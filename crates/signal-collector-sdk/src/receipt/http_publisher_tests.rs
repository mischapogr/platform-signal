use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn setup(
    d: &tempfile::TempDir,
) -> Result<(ReceiptStore, ReceiptBinding), Box<dyn std::error::Error>> {
    let (wire, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(d)?, owner(), 1, ctx()).await?;
    s.publish(wire, b.clone(), ctx()).await?;
    Ok((s, b))
}
pub(super) async fn request(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let mut all = Vec::new();
    let mut chunk = [0u8; 4096];
    let boundary = loop {
        if all.len() > 65536 {
            return Err("header cap".into());
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err("request EOF".into());
        }
        all.extend_from_slice(&chunk[..n]);
        if let Some(at) = all.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let headers = std::str::from_utf8(&all[..boundary])?.to_owned();
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.trim().parse::<usize>())
        })
        .unwrap_or(Ok(0))?;
    if length > 1024 * 1024 {
        return Err("request cap".into());
    }
    while all.len() < boundary + length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err("body EOF".into());
        }
        all.extend_from_slice(&chunk[..n]);
    }
    Ok((headers, all[boundary..boundary + length].to_vec()))
}
fn reply(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 202 Accepted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn actual_tcp_request_preserves_pinned_batch_and_authentication_then_commits_prefix()
-> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let replay = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let batch = replay
        .batch(ReceiptBatchLimits::default())?
        .ok_or("batch")?;
    let expected = batch.body().to_vec();
    let ids = batch.event_ids().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let (headers, body) = request(&mut stream).await?;
        assert!(headers.starts_with("POST /v1/events/batch HTTP/1.1"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-token\r\n")
        );
        assert_eq!(body, expected);
        let response = serde_json::to_vec(
            &json!({"schema_version":1,"accepted":2,"rejected":0,"event_ids":ids,"error":null}),
        )?;
        stream.write_all(&reply(&response)).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let publisher = HttpReceiptPublisher::new(
        &format!("http://{address}"),
        Some("fixture-token"),
        Duration::from_secs(1),
    )?;
    assert!(matches!(
        publish_receipt_batch(
            &s,
            b.clone(),
            &publisher,
            ReceiptBatchLimits::default(),
            ctx()
        )
        .await?,
        PublishStep::Attempt {
            accepted: 2,
            remaining: 0,
            ..
        }
    ));
    server.await?.map_err(|e| e as Box<dyn std::error::Error>)?;
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert_eq!(s.replay(b, ctx()).await?.ok_or("reopen")?.remaining(), 0);
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn oversized_declared_and_chunked_responses_hold_the_exact_suffix() -> TestResult {
    for chunked in [false, true] {
        let d = root()?;
        let (s, b) = setup(&d).await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _ = request(&mut stream).await?;
            let response = if chunked {
                let mut bytes=b"HTTP/1.1 202 Accepted\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n".to_vec();
                bytes.extend_from_slice(&vec![b'x'; 65537]);
                bytes.extend_from_slice(b"\r\n0\r\n\r\n");
                bytes
            } else {
                b"HTTP/1.1 202 Accepted\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n"
                    .to_vec()
            };
            let _ = stream.write_all(&response).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let publisher =
            HttpReceiptPublisher::new(&format!("http://{address}"), None, Duration::from_secs(1))?;
        assert!(matches!(
            publish_receipt_batch(
                &s,
                b.clone(),
                &publisher,
                ReceiptBatchLimits::default(),
                ctx()
            )
            .await?,
            PublishStep::Attempt {
                accepted: 0,
                remaining: 2,
                ..
            }
        ));
        server.await?.map_err(|e| e as Box<dyn std::error::Error>)?;
        assert_eq!(
            s.replay(b, ctx())
                .await?
                .ok_or("r")?
                .progress
                .verified_prefix(),
            0
        );
        s.close(ctx()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn redirect_never_forwards_body_or_token_and_stalled_read_cancels() -> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let destination = TcpListener::bind("127.0.0.1:0").await?;
    let target = destination.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = request(&mut stream).await?;
        stream.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target}/v1/events/batch\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let publisher = HttpReceiptPublisher::new(
        &format!("http://{address}"),
        Some("fixture-token"),
        Duration::from_secs(1),
    )?;
    assert!(matches!(
        publish_receipt_batch(
            &s,
            b.clone(),
            &publisher,
            ReceiptBatchLimits::default(),
            ctx()
        )
        .await,
        Err(ReceiptError::InvalidResponse)
    ));
    server.await?.map_err(|e| e as Box<dyn std::error::Error>)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), destination.accept())
            .await
            .is_err()
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = request(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 32\r\n\r\n")
            .await?;
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await??;
        assert_eq!(closed, 0);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let publisher =
        HttpReceiptPublisher::new(&format!("http://{address}"), None, Duration::from_secs(1))?;
    let token = CancellationToken::new();
    let context = ExtensionContext::new(token.clone(), Duration::from_secs(5))?;
    let result = tokio::join!(
        publish_receipt_batch(
            &s,
            b.clone(),
            &publisher,
            ReceiptBatchLimits::default(),
            context
        ),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token.cancel();
        }
    );
    assert!(matches!(result.0, Err(ReceiptError::Cancelled)));
    server.await?.map_err(|e| e as Box<dyn std::error::Error>)?;
    assert_eq!(
        s.replay(b, ctx())
            .await?
            .ok_or("r")?
            .progress
            .verified_prefix(),
        0
    );
    s.close(ctx()).await?;
    Ok(())
}

#[test]
fn endpoint_and_header_configuration_rejects_injection_and_foreign_paths() -> TestResult {
    for endpoint in [
        "",
        "file:///secret",
        "https://user:secret@example.invalid",
        "https://example.invalid/wrong",
        "https://example.invalid/?secret=value",
        "https://example.invalid/#fragment",
    ] {
        assert!(matches!(
            HttpReceiptPublisher::new(endpoint, None, Duration::from_secs(1)),
            Err(ReceiptError::Configuration)
        ));
    }
    for token in ["", "secret\r\nInjected: true"] {
        assert!(matches!(
            HttpReceiptPublisher::new(
                "https://example.invalid",
                Some(token),
                Duration::from_secs(1)
            ),
            Err(ReceiptError::Configuration)
        ));
    }
    assert!(matches!(
        HttpReceiptPublisher::new("https://example.invalid", None, Duration::ZERO),
        Err(ReceiptError::Configuration)
    ));
    Ok(())
}
