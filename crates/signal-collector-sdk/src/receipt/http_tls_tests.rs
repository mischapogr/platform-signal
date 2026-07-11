//! Actual mTLS transport; the tiny HTTP peer simulates admission, not durable WAL.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn openssl(root: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Reap(
        Command::new("openssl")
            .args(args)
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err("synthetic TLS generation failed".into());
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("synthetic TLS generation deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn pki(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for ca in ["original", "foreign"] {
        openssl(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                &format!("{ca}.key"),
                "-out",
                &format!("{ca}.pem"),
                "-days",
                "1",
                "-subj",
                &format!("/CN=synthetic-{ca}"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
    }
    for (name, ca, usage, serial) in [
        ("server", "original", "serverAuth", "10"),
        ("client", "original", "clientAuth", "11"),
        ("foreign-client", "foreign", "clientAuth", "12"),
    ] {
        openssl(
            root,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN=synthetic-{name}"),
            ],
        )?;
        fs::write(
            root.join(format!("{name}.ext")),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n"
            ),
        )?;
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-set_serial",
                serial,
                "-days",
                "1",
                "-extfile",
                &format!("{name}.ext"),
                "-out",
                &format!("{name}.pem"),
            ],
        )?;
    }
    Ok(())
}
fn client_config(
    root: &Path,
    identity: &str,
    trust: &str,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    let cert = CertificateDer::from_pem_file(root.join(format!("{identity}.pem")))?;
    let key = PrivateKeyDer::from_pem_file(root.join(format!("{identity}.key")))?;
    let ca = CertificateDer::from_pem_file(root.join(format!("{trust}.pem")))?;
    let wire = serde_json::to_vec(&json!({"schema_version":1,
        "certificate_chain_der_base64":[STANDARD.encode(cert.as_ref())],
        "private_key_der_base64":STANDARD.encode(key.secret_der()),
        "peer_roots_der_base64":[STANDARD.encode(ca.as_ref())]}))?;
    Ok(crate::transport::tls::from_private_json(&wire)?)
}
struct Task<T>(Option<JoinHandle<T>>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

#[tokio::test]
async fn actual_mutual_tls_denials_hold_receipt_ids_and_valid_reply_commits_prefix() -> TestResult {
    let certificates = tempfile::tempdir()?;
    pki(certificates.path())?;
    let ca = CertificateDer::from_pem_file(certificates.path().join("original.pem"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_file(
                certificates.path().join("server.pem"),
            )?],
            PrivateKeyDer::from_pem_file(certificates.path().join("server.key"))?,
        )?;
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server_config.send_tls13_tickets = 0;
    for mode in ["wrong-root", "foreign-client", "missing-client", "valid"] {
        let directory = root()?;
        let (wire, binding) = vector("prepared")?;
        let store = ReceiptStore::open(config(&directory)?, owner(), 1, ctx()).await?;
        store.publish(wire, binding.clone(), ctx()).await?;
        let replay = store
            .replay(binding.clone(), ctx())
            .await?
            .ok_or("replay")?;
        let batch = replay
            .batch(ReceiptBatchLimits::default())?
            .ok_or("batch")?;
        let expected = batch.body().to_vec();
        let ids = batch.event_ids().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = requests.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config.clone()));
        let mut peer = Task(Some(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), async move {
                let (stream, _) = listener.accept().await?;
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return Ok(());
                };
                let (headers, body) = http_publisher_tests::request(&mut stream).await?;
                seen.fetch_add(1, Ordering::Relaxed);
                assert!(headers.starts_with("POST /v1/events/batch HTTP/1.1"));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("authorization: bearer fixture-token\r\n")
                );
                assert_eq!(body, expected);
                let response = serde_json::to_vec(
                    &json!({"schema_version":1,"accepted":2,"rejected":0,"event_ids":ids}),
                )?;
                let headers = format!(
                    "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                stream.write_all(headers.as_bytes()).await?;
                stream.write_all(&response).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await?
        })));
        let tls = if mode == "missing-client" {
            let mut trust = rustls::RootCertStore::empty();
            trust.add(CertificateDer::from_pem_file(
                certificates.path().join("original.pem"),
            )?)?;
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(trust)
            .with_no_client_auth()
        } else {
            client_config(
                certificates.path(),
                if mode == "foreign-client" {
                    "foreign-client"
                } else {
                    "client"
                },
                if mode == "wrong-root" {
                    "foreign"
                } else {
                    "original"
                },
            )?
        };
        assert!(matches!(
            HttpReceiptPublisher::with_tls(
                "http://127.0.0.1",
                None,
                Duration::from_secs(1),
                Some(tls.clone())
            ),
            Err(ReceiptError::Configuration)
        ));
        let publisher = HttpReceiptPublisher::with_tls(
            &format!("https://localhost:{}", address.port()),
            Some("fixture-token"),
            Duration::from_secs(1),
            Some(tls),
        )?;
        let step = publish_receipt_batch(
            &store,
            binding.clone(),
            &publisher,
            ReceiptBatchLimits::default(),
            ctx(),
        )
        .await?;
        let accepted = if mode == "valid" { 2 } else { 0 };
        assert!(
            matches!(step, PublishStep::Attempt { accepted: count, remaining, .. } if count == accepted && remaining == 2 - accepted),
            "wrong TLS receipt progress: {mode}"
        );
        peer.0
            .as_mut()
            .ok_or("peer")?
            .await?
            .map_err(|e| e as Box<dyn std::error::Error>)?;
        peer.0.take();
        assert_eq!(
            requests.load(Ordering::Relaxed),
            usize::from(mode == "valid")
        );
        let current = store
            .replay(binding.clone(), ctx())
            .await?
            .ok_or("current replay")?;
        assert_eq!(current.progress.verified_prefix(), accepted);
        assert_eq!(
            current
                .batch(ReceiptBatchLimits::default())?
                .map(|b| b.event_ids().to_vec()),
            if accepted == 0 {
                Some(batch.event_ids().to_vec())
            } else {
                None
            }
        );
        store.close(ctx()).await?;
        let reopened = ReceiptStore::open(config(&directory)?, owner(), 1, ctx()).await?;
        assert_eq!(
            reopened
                .replay(binding, ctx())
                .await?
                .ok_or("reopened replay")?
                .progress
                .verified_prefix(),
            accepted
        );
        reopened.close(ctx()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ready_tls_receipt_response_after_original_deadline_is_uncertain() -> TestResult {
    use std::{
        cell::Cell,
        future::Future,
        task::{Context, Poll, Waker},
    };
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(50))?;
    let ready = Cell::new(false);
    let polls = Cell::new(0);
    let response = std::future::poll_fn(|_| {
        polls.set(polls.get() + 1);
        if ready.get() {
            Poll::Ready(Ok(AdmissionReply {
                status: 202,
                body: b"synthetic-ready".to_vec(),
            }))
        } else {
            Poll::Pending
        }
    });
    let future = super::super::http_publisher::reply_before_deadline(&context, response);
    tokio::pin!(future);
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    ready.set(true);
    std::thread::sleep(
        context
            .deadline()
            .saturating_duration_since(tokio::time::Instant::now())
            + Duration::from_millis(10),
    );
    assert!(matches!(future.await, Err(PublishFailure::Uncertain)));
    assert_eq!(polls.get(), 1);
    Ok(())
}
