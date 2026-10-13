use super::*;
use chrono::Utc;
use signal_protocol::object_custody::{ObjectReference, Scope};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
fn description() -> Description {
    Description {
        schema_version: 1,
        id: Uuid::from_u128(9),
        scope: Scope {
            schema_version: 1,
            store_id: Uuid::from_u128(1),
            generation: Uuid::from_u128(2),
            tenant: "synthetic".into(),
            stream: Uuid::from_u128(3),
            partition_id: Uuid::from_u128(4),
        },
        object: ObjectReference {
            schema_version: 1,
            backend_id: Uuid::from_u128(5),
            key: "original/body".into(),
            version: "v1".into(),
        },
        bytes: 4,
        sha256: sha2::Sha256::digest(b"body").into(),
        retain_until: Utc::now() + chrono::Duration::hours(1),
    }
}
use sha2::Digest;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn client_requires_selected_endpoint_bearer_and_secure_transport() {
    for endpoint in [
        "http://localhost/v1/custody/confirm",
        "http://192.0.2.1/v1/custody/confirm",
        "https://example.invalid/v1/events",
        "https://example.invalid/v1/custody/confirm?query=1",
        "https://user:pass@example.invalid/v1/custody/confirm",
    ] {
        assert!(
            ObjectCustodyClient::new(endpoint, "synthetic", Duration::from_secs(1), None, true)
                .is_err()
        );
    }
    assert!(
        ObjectCustodyClient::new(
            "http://127.0.0.1/v1/custody/confirm",
            "synthetic",
            Duration::from_secs(1),
            None,
            false
        )
        .is_err()
    );
    assert!(
        ObjectCustodyClient::new(
            "https://example.invalid/v1/custody/confirm",
            "",
            Duration::from_secs(1),
            None,
            false
        )
        .is_err()
    );
}
#[tokio::test]
async fn fresh_nonce_expiry_uncertainty_and_cancellation_retain_original() -> Result {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}{CONFIRM_PATH}", listener.local_addr()?);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut entered = Some(entered);
        let mut nonces = Vec::new();
        let mut first = None;
        for mode in 0..5 {
            let (mut socket, _) = listener.accept().await?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() > 8192 {
                    return Err(std::io::Error::other("headers full"));
                }
                head.push(socket.read_u8().await?);
            }
            let text = std::str::from_utf8(&head).map_err(std::io::Error::other)?;
            let lower = text.to_ascii_lowercase();
            assert!(lower.contains("authorization: bearer synthetic"));
            let len = lower
                .lines()
                .find_map(|s| {
                    s.strip_prefix("content-length:")
                        .and_then(|s| s.trim().parse::<usize>().ok())
                })
                .ok_or_else(|| std::io::Error::other("body length"))?;
            if len > WIRE_BYTES {
                return Err(std::io::Error::other("body full"));
            }
            let mut body = vec![0; len];
            socket.read_exact(&mut body).await?;
            let request: ConfirmRequest =
                serde_json::from_slice(&body).map_err(std::io::Error::other)?;
            assert!(!nonces.contains(&request.request_nonce));
            nonces.push(request.request_nonce);
            let now = Utc::now();
            let mut reply = Confirmation {
                schema_version: 1,
                request_nonce: request.request_nonce,
                description: request.description.clone(),
                description_sha256: request
                    .description
                    .digest()
                    .map_err(std::io::Error::other)?,
                confirmed_at: now,
                valid_until: now + chrono::Duration::seconds(3),
                valid_for_ms: 3000,
                server_elapsed_ms: 0,
            };
            if mode == 1 {
                reply = first
                    .clone()
                    .ok_or_else(|| std::io::Error::other("missing first reply"))?;
            }
            if mode == 2 {
                reply.confirmed_at = now - chrono::Duration::seconds(2);
                reply.valid_until = now - chrono::Duration::seconds(1);
                reply.valid_for_ms = 1000;
            }
            if mode == 3 {
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                }
                let mut one = [0];
                assert_eq!(socket.read(&mut one).await?, 0);
                continue;
            }
            if mode == 4 {
                // A peer clock ahead of ours cannot restart the original
                // monotonic lease budget after the RTT has already spent it.
                reply.confirmed_at = now + chrono::Duration::seconds(60);
                reply.valid_until = reply.confirmed_at + chrono::Duration::milliseconds(100);
                reply.valid_for_ms = 100;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let bytes = serde_json::to_vec(&reply).map_err(std::io::Error::other)?;
            if mode == 0 {
                first = Some(reply);
            }
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    )
                    .as_bytes(),
                )
                .await?;
            socket.write_all(&bytes).await?;
            socket.shutdown().await?;
        }
        Ok::<(), std::io::Error>(())
    });
    let original = tempfile::tempdir()?;
    let path = original.path().join("original");
    std::fs::write(&path, b"body")?;
    let client = Arc::new(ObjectCustodyClient::new(
        &endpoint,
        "synthetic",
        Duration::from_secs(1),
        None,
        true,
    )?);
    let d = description();
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?;
    let permit = client.confirm(&d, &context).await?;
    assert_eq!(permit.checked_confirmation()?.description, d);
    context.cancellation().cancel();
    assert!(matches!(
        permit.checked_confirmation(),
        Err(CustodyError::Cancelled)
    ));
    for _ in 0..2 {
        let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?;
        assert!(client.confirm(&d, &ctx).await.is_err());
        assert_eq!(std::fs::read(&path)?, b"body");
    }
    let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?;
    let cancel = ctx.cancellation().clone();
    let front = client.clone();
    let original_description = d.clone();
    let request = tokio::spawn(async move { front.confirm(&original_description, &ctx).await });
    tokio::time::timeout(Duration::from_secs(3), observed).await??;
    cancel.cancel();
    assert!(matches!(request.await?, Err(CustodyError::Cancelled)));
    assert_eq!(std::fs::read(&path)?, b"body");
    tokio::time::timeout(Duration::from_secs(3), async {
        while client.metrics().depth != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?;
    assert!(matches!(
        client.confirm(&d, &ctx).await,
        Err(CustodyError::Timeout)
    ));
    assert_eq!(std::fs::read(&path)?, b"body");
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    assert_eq!(client.metrics().depth, 0);
    Ok(())
}
