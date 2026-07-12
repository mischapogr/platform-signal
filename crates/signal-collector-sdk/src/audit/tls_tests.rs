//! Actual client/server certificate verification; semantic ACKs are not fsync proof.
use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use signal_protocol::audit::AuditAcknowledgement;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub(super) async fn qualify_mutual_tls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    crate::test_tls::pki(directory.path())
        .map_err(|_| "synthetic TLS fixture generation failed")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(
        directory.path().join("original.pem"),
    )?)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_file(
                directory.path().join("server.pem"),
            )?],
            PrivateKeyDer::from_pem_file(directory.path().join("server.key"))?,
        )?;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    for mode in ["wrong-root", "foreign-client", "wrong-credential", "valid"] {
        let record = super::tests::record()?;
        let expected = record.body().to_vec();
        let ack = AuditAcknowledgement::for_prepared(&record).to_json()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("https://127.0.0.1:{}", listener.local_addr()?.port());
        let seen = Arc::new(AtomicUsize::new(0));
        let observed = seen.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server.clone()));
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), async move {
                let (stream, _) = listener.accept().await?;
                let Ok(mut stream) = acceptor.accept(stream).await else { return Ok(()); };
                let mut bytes = Vec::new(); let mut block = [0u8; 1024];
                let (headers, offset, length) = loop {
                    let n = stream.read(&mut block).await?;
                    if n == 0 || n > 8192 - bytes.len() { return Err("audit TLS request missing".into()); }
                    bytes.extend_from_slice(&block[..n]);
                    if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end])?.to_ascii_lowercase();
                        let length = headers.lines().find_map(|l| l.strip_prefix("content-length: ")).ok_or("length")?.parse::<usize>()?;
                        if length > signal_protocol::audit::RECORD_BYTES { return Err("audit TLS body oversized".into()); }
                        break (headers, end + 4, length);
                    }
                };
                while bytes.len() < offset + length {
                    let n = stream.read(&mut block).await?;
                    if n == 0 || n > 8192 - bytes.len() { return Err("audit TLS body missing".into()); }
                    bytes.extend_from_slice(&block[..n]);
                }
                assert!(headers.starts_with("post /v1/audit/records http/1.1\r\n"));
                assert_eq!(&bytes[offset..offset+length], expected);
                let credential_valid = headers.contains("authorization: bearer synthetic-audit-only");
                assert_eq!(credential_valid, mode != "wrong-credential");
                if credential_valid { observed.fetch_add(1, Ordering::Relaxed); }
                let status = if credential_valid { 200 } else { 403 };
                let mut reply = format!("HTTP/1.1 {status} Synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",ack.len()).into_bytes();
                reply.extend_from_slice(&ack);
                stream.write_all(&reply).await.map_err(|e| format!("{mode}: TLS fixture reply write: {e}"))?;
                super::tests::close_after_reply(&mut stream).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }).await?
        });
        let mut task = super::tests::Task(Some(task));
        let material = crate::test_tls::material(
            directory.path(),
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
        )
        .map_err(|_| "synthetic TLS material failed")?;
        let sink = HttpAuditSink::from_private_tls(
            &endpoint,
            if mode == "wrong-credential" {
                "synthetic-denied"
            } else {
                "synthetic-audit-only"
            },
            Duration::from_secs(1),
            &material,
        )?;
        let result = sink
            .append(&record, std::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert_eq!(
            result,
            if mode == "valid" {
                Ok(())
            } else {
                Err(AppendError::Uncertain)
            },
            "TLS outcome: {mode}"
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            task.0.as_mut().ok_or("missing TLS peer")?,
        )
        .await???;
        task.0.take();
        super::tests::retire().await?;
        assert_eq!(seen.load(Ordering::Relaxed), usize::from(mode == "valid"));
    }
    Ok(())
}
