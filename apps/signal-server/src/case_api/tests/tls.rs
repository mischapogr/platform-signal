//! Actual finite TLS introspection fixture. All CA/keys/subjects are synthetic.
use super::*;
use rustls::pki_types::pem::PemObject;
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

pub(super) struct Provider {
    pub address: std::net::SocketAddr,
    pub root: Vec<u8>,
    pub subject: Arc<Mutex<Option<String>>>,
    pub calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn openssl(path: &std::path::Path, args: &[&str]) -> TestResult {
    let mut child = Reap(
        Command::new("openssl")
            .args(args)
            .current_dir(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(status.success());
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("TLS fixture OpenSSL deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
impl Provider {
    pub(super) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
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
                "/CN=synthetic-soc-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
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
                "/CN=synthetic-soc-idp",
            ],
        )?;
        std::fs::write(
            path.join("leaf.ext"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
        )?;
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
                "-set_serial",
                "2",
                "-out",
                "leaf.pem",
                "-days",
                "1",
                "-extfile",
                "leaf.ext",
            ],
        )?;
        let leaf = rustls::pki_types::CertificateDer::from_pem_slice(&std::fs::read(
            path.join("leaf.pem"),
        )?)?;
        let root = rustls::pki_types::CertificateDer::from_pem_slice(&std::fs::read(
            path.join("root.pem"),
        )?)?
        .to_vec();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&std::fs::read(
            path.join("leaf.key"),
        )?)?;
        let server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)?,
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let subject = Arc::new(Mutex::new(Some("writer".to_owned())));
        let selected = subject.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let thread = std::thread::spawn(move || {
            let lifetime = std::time::Instant::now() + Duration::from_secs(60);
            while !stopping.load(Ordering::Acquire) && std::time::Instant::now() < lifetime {
                let (socket, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                socket
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut tls = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server.clone()).unwrap(),
                    socket,
                );
                let exchange = (|| -> std::io::Result<()> {
                    let mut bytes = Vec::new();
                    let mut buffer = [0; 1024];
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    let end = loop {
                        if bytes.len() >= 32 * 1024 || std::time::Instant::now() >= deadline {
                            return Err(std::io::Error::other("fixture request bound"));
                        }
                        let n = tls.read(&mut buffer)?;
                        if n == 0 {
                            return Ok(());
                        }
                        bytes.extend_from_slice(&buffer[..n]);
                        if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let headers =
                        std::str::from_utf8(&bytes[..end]).map_err(std::io::Error::other)?;
                    assert!(headers.starts_with("POST /introspect HTTP/1.1\r\n"));
                    let basic = STANDARD.encode(b"synthetic-client:synthetic-secret");
                    assert!(headers.contains(&format!("Basic {basic}\r\n")));
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .ok_or_else(|| std::io::Error::other("length"))?
                        .parse()
                        .map_err(std::io::Error::other)?;
                    assert!(length <= 16 * 1024);
                    while bytes.len() < end + length {
                        if std::time::Instant::now() >= deadline {
                            return Err(std::io::Error::other("fixture body deadline"));
                        }
                        let n = tls.read(&mut buffer)?;
                        if n == 0 {
                            return Ok(());
                        }
                        bytes.extend_from_slice(&buffer[..n]);
                        assert!(bytes.len() <= 32 * 1024);
                    }
                    assert_eq!(
                        &bytes[end..end + length],
                        b"token=opaque&token_type_hint=access_token"
                    );
                    assert!(seen.fetch_add(1, Ordering::AcqRel) < 192);
                    let subject = selected.lock().unwrap().clone();
                    let body = serde_json::to_vec(&json!({"active":subject.is_some(),"iss":"https://soc-idp.example.test","sub":subject.unwrap_or_default(),"aud":"signal","exp":crate::access::now().unwrap()+60,"token_type":"Bearer"})).unwrap();
                    write!(
                        tls,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )?;
                    tls.write_all(&body)?;
                    tls.flush()?;
                    Ok(())
                })();
                let _ = exchange; // Cancelled clients may close before the fixed response.
            }
        });
        Ok(Self {
            address,
            root,
            subject,
            calls,
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().is_ok(), "owned TLS fixture thread");
        }
    }
}
