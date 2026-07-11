//! Finite actual local TLS provider, with fresh synthetic CA/key material only.
use super::*;
use rustls::pki_types::pem::PemObject;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::AtomicBool,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) enum Reply {
    Bytes(Vec<u8>),
    Stall,
}
pub(super) struct Fixture {
    pub address: std::net::SocketAddr,
    pub root: Vec<u8>,
    pub requests: Arc<AtomicUsize>,
    pub valid_requests: Arc<AtomicBool>,
    stopping: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn openssl(path: &Path, args: &[&str]) {
    let child = Command::new("openssl")
        .args(args)
        .current_dir(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("local OpenSSL fixture process");
    let mut child = Reap(child);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().expect("fixture process status") {
            assert!(status.success(), "synthetic TLS fixture generation");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fixture generation deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
impl Fixture {
    pub async fn new(replies: Vec<Reply>, certificate_ip: &str, days: &str) -> Self {
        assert!(replies.len() <= 64);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        openssl(
            path,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                "root.key",
                "-out",
                "root.pem",
                "-days",
                "1",
                "-subj",
                "/CN=synthetic-signal-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        openssl(
            path,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                "leaf.key",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=synthetic-idp",
            ],
        );
        std::fs::write(path.join("leaf.ext"),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:{certificate_ip}\n")).unwrap();
        openssl(
            path,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "root.pem",
                "-CAkey",
                "root.key",
                "-CAcreateserial",
                "-out",
                "leaf.pem",
                "-days",
                days,
                "-extfile",
                "leaf.ext",
            ],
        );
        let leaf = rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(path.join("leaf.pem")).unwrap(),
        )
        .unwrap();
        let root = rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(path.join("root.pem")).unwrap(),
        )
        .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
            &std::fs::read(path.join("leaf.key")).unwrap(),
        )
        .unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stopping = CancellationToken::new();
        let stop = stopping.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = requests.clone();
        let valid_requests = Arc::new(AtomicBool::new(true));
        let valid = valid_requests.clone();
        let task = tokio::spawn(async move {
            for reply in replies {
                let accepted = tokio::select! {biased;_=stop.cancelled()=>break,result=listener.accept()=>result};
                let (socket, _) = accepted.unwrap();
                let exchange = async {
                    let Ok(mut socket) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 1024];
                    let end = loop {
                        let count = socket.read(&mut buffer).await.unwrap_or(0);
                        if count == 0 {
                            return;
                        }
                        assert!(
                            bytes.len() + count <= 32 * 1024,
                            "finite client request fixture"
                        );
                        bytes.extend_from_slice(&buffer[..count]);
                        if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let headers = std::str::from_utf8(&bytes[..end])
                        .unwrap()
                        .to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap();
                    assert!(length <= 16 * 1024);
                    while bytes.len() < end + length {
                        let count = socket.read(&mut buffer).await.unwrap_or(0);
                        if count == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                        assert!(bytes.len() <= 32 * 1024);
                    }
                    let expected = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        b"synthetic-client:synthetic-secret",
                    );
                    let raw_headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let body = std::str::from_utf8(&bytes[end..end + length]).unwrap();
                    let good = raw_headers.starts_with("POST /introspect HTTP/1.1\r\n")
                        && raw_headers
                            .to_ascii_lowercase()
                            .contains(&format!("host: {address}\r\n"))
                        && raw_headers.contains(&format!("Basic {expected}\r\n"))
                        && headers.contains("content-type: application/x-www-form-urlencoded\r\n")
                        && headers.contains("connection: close\r\n")
                        && body == "token=opaque&token_type_hint=access_token";
                    if !good {
                        valid.store(false, Ordering::Release);
                    }
                    seen.fetch_add(1, Ordering::AcqRel);
                    match reply {
                        Reply::Bytes(reply) => {
                            assert!(reply.len() <= 64 * 1024);
                            let _ = socket.write_all(&reply).await;
                            let _ = socket.shutdown().await;
                        }
                        Reply::Stall => {
                            let mut extra = [0u8; 1];
                            let _ = socket.read(&mut extra).await;
                        }
                    }
                };
                tokio::select! {biased;_=stop.cancelled()=>break,_=tokio::time::timeout(Duration::from_secs(5),exchange)=>{}}
            }
        });
        Self {
            address,
            root: root.to_vec(),
            requests,
            valid_requests,
            stopping,
            task: Some(task),
        }
    }
    pub fn config(&self) -> IdentityConfig {
        let mut value = super::config();
        value.endpoint = format!("https://{}/introspect", self.address);
        value.extra_roots = vec![self.root.clone()];
        value
    }
    pub async fn wait_requests(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.requests.load(Ordering::Acquire) < count {
            assert!(Instant::now() < deadline, "provider request milestone");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    pub async fn finish(mut self) {
        self.stopping.cancel();
        self.task.as_mut().unwrap().await.unwrap();
        self.task.take();
        assert!(
            self.valid_requests.load(Ordering::Acquire),
            "fixed authenticated form/origin request"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopping.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
pub(super) fn valid_body() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    serde_json::to_vec(&serde_json::json!({"active":true,"iss":"https://identity.example.test","aud":"synthetic-signal","sub":"reader","exp":now+60,"token_type":"Bearer"})).unwrap()
}
pub(super) fn json_reply(body: &[u8]) -> Reply {
    let mut bytes=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    bytes.extend_from_slice(body);
    Reply::Bytes(bytes)
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::future::Future;

    #[tokio::test]
    async fn cancelled_finish_retains_provider_task_for_fixture_drop() {
        struct MarkExit(Arc<tokio::sync::Notify>);
        impl Drop for MarkExit {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let exited = Arc::new(tokio::sync::Notify::new());
        let started = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let exited = exited.clone();
            let started = started.clone();
            async move {
                let _exit = MarkExit(exited);
                started.notify_one();
                std::future::pending::<()>().await;
            }
        });
        started.notified().await;
        let fixture = Fixture {
            root: Vec::new(),
            address: "127.0.0.1:1".parse().unwrap(),
            requests: Arc::new(AtomicUsize::new(0)),
            valid_requests: Arc::new(AtomicBool::new(true)),
            stopping: CancellationToken::new(),
            task: Some(task),
        };
        let mut finishing = Box::pin(fixture.finish());
        // Poll once so finish is suspended specifically inside the JoinHandle.
        std::future::poll_fn(|context| {
            assert!(finishing.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(finishing);
        tokio::time::timeout(Duration::from_secs(1), exited.notified())
            .await
            .unwrap();
    }
}
