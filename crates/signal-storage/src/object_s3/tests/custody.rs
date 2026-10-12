use super::*;
use crate::object_manifest::{QueryObjectRef, sha256};
use chrono::{Duration as ChronoDuration, Utc};

fn reference(body: &[u8]) -> QueryObjectRef {
    QueryObjectRef {
        key: "custody/original binary".into(),
        version: Some("pinned+/v1".into()),
        etag: Some("\"exact\"".into()),
        bytes: body.len() as u64,
        sha256: sha256(body),
    }
}
fn headers(horizon: chrono::DateTime<Utc>) -> String {
    format!(
        "ETag: \"exact\"\r\nx-amz-version-id: pinned+/v1\r\nx-amz-object-lock-mode: COMPLIANCE\r\nx-amz-object-lock-retain-until-date: {}\r\n",
        horizon.to_rfc3339()
    )
}
fn retained_io(endpoint: &str) -> Result<(ObjectIo, S3HttpObserver)> {
    let cfg = config(endpoint);
    let (store, _) = build(&cfg, &credentials())?;
    let (reader, observer) = build_custody_reader(&cfg, &credentials(), "123456789012")?;
    Ok((
        ObjectIo::remote_retained(
            Arc::new(store),
            reader,
            tokio::runtime::Handle::current(),
            ObjectIoLimits {
                bytes: cfg.max_object_bytes,
                ..Default::default()
            },
        )?,
        observer,
    ))
}
#[tokio::test]
async fn exact_signed_full_version_observes_compliance_and_expected_owner() -> Result {
    let body = b"independent original";
    let horizon = Utc::now() + ChronoDuration::hours(2);
    let mut endpoint = Endpoint::start(vec![reply(200, &headers(horizon), body)]).await?;
    let (io, observer) = retained_io(&endpoint.url)?;
    let observed = io
        .verify_retained(
            &reference(body),
            horizon - ChronoDuration::minutes(1),
            OperationContext::new(Duration::from_secs(2)),
        )
        .await?;
    assert_eq!(observed, horizon);
    let wires = endpoint.finish().await?;
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].method, "GET");
    let url = Url::parse(&format!("{}{}", endpoint.url, wires[0].target))?;
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![("versionId".into(), "pinned+/v1".into())]
    );
    assert!(wires[0].target.contains("original%20binary"));
    assert_eq!(
        wires[0]
            .headers
            .get("x-amz-expected-bucket-owner")
            .map(String::as_str),
        Some("123456789012")
    );
    assert!(
        wires[0]
            .headers
            .get("authorization")
            .is_some_and(|s| s.contains("x-amz-expected-bucket-owner"))
    );
    assert_eq!(observer.metrics().requests, 1);
    io.shutdown(OperationContext::new(Duration::from_secs(2)))
        .await?;
    Ok(())
}
#[tokio::test]
async fn missing_bypassable_shortened_or_substituted_evidence_never_confirms() -> Result {
    let body = b"retained bytes";
    let horizon = Utc::now() + ChronoDuration::hours(2);
    let good = headers(horizon);
    let variants = [
        good.replace("COMPLIANCE", "GOVERNANCE"),
        good.replace("x-amz-object-lock-mode: COMPLIANCE\r\n", ""),
        good.replace("pinned+/v1", "different-version"),
        good.replace("\"exact\"", "\"changed\""),
        headers(Utc::now() + ChronoDuration::minutes(1)),
        format!("{good}x-amz-object-lock-mode: COMPLIANCE\r\n"),
        format!(
            "{good}x-amz-object-lock-retain-until-date: {}\r\n",
            horizon.to_rfc3339()
        ),
        format!("{good}x-amz-version-id: pinned+/v1\r\n"),
        format!("{good}x-amz-delete-marker: true\r\n"),
        format!("{good}Content-Range: bytes 0-13/14\r\n"),
        good.replace(&horizon.to_rfc3339(), "invalid-date"),
    ];
    for h in variants {
        let mut endpoint = Endpoint::start(vec![reply(200, &h, body)]).await?;
        let (io, _) = retained_io(&endpoint.url)?;
        assert!(
            io.verify_retained(
                &reference(body),
                horizon,
                OperationContext::new(Duration::from_secs(2))
            )
            .await
            .is_err()
        );
        assert_eq!(endpoint.finish().await?.len(), 1);
        io.shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
    }
    for (status, returned) in [(200, b"changed digest".as_slice()), (403, body.as_slice())] {
        let mut endpoint = Endpoint::start(vec![reply(status, &good, returned)]).await?;
        let (io, _) = retained_io(&endpoint.url)?;
        assert!(
            io.verify_retained(
                &reference(body),
                horizon,
                OperationContext::new(Duration::from_secs(2))
            )
            .await
            .is_err()
        );
        endpoint.finish().await?;
        io.shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
    }
    Ok(())
}
#[tokio::test]
async fn default_io_and_invalid_reference_never_send_retention_request() -> Result {
    let endpoint = Endpoint::start(vec![]).await?;
    let (normal, observer) = io(&endpoint.url)?;
    let horizon = Utc::now() + ChronoDuration::hours(1);
    assert_eq!(
        normal
            .verify_retained(
                &reference(b"body"),
                horizon,
                OperationContext::new(Duration::from_secs(2))
            )
            .await,
        Err(ObjectIoError::Config)
    );
    assert_eq!(observer.metrics().requests, 0);
    normal
        .shutdown(OperationContext::new(Duration::from_secs(2)))
        .await?;
    let (retained, observer) = retained_io(&endpoint.url)?;
    for version in [None, Some("null".into()), Some("*".into())] {
        let mut r = reference(b"body");
        r.version = version;
        assert!(
            retained
                .verify_retained(&r, horizon, OperationContext::new(Duration::from_secs(2)))
                .await
                .is_err()
        );
    }
    assert_eq!(observer.metrics().requests, 0);
    retained
        .shutdown(OperationContext::new(Duration::from_secs(2)))
        .await?;
    Ok(())
}

#[tokio::test]
async fn caller_abort_and_deadline_close_owned_socket_and_drain_worker() -> Result {
    for abort in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (entered, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (mut socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
                let wire = read_wire(&mut socket).await?;
                let _ = entered.send(());
                let mut one = [0];
                if socket.read(&mut one).await.map_err(|e| e.to_string())? != 0 {
                    return Err("owned cancelled connection sent unexpected bytes".into());
                }
                Ok(vec![wire])
            })
            .await
            .map_err(|_| "fixture disconnect deadline".to_owned())?
        });
        let mut endpoint = Endpoint {
            url,
            task: Some(task),
        };
        let (io, observer) = retained_io(&endpoint.url)?;
        let io = Arc::new(io);
        let front = io.clone();
        let request = tokio::spawn(async move {
            front
                .verify_retained(
                    &reference(b"body"),
                    Utc::now() + ChronoDuration::hours(1),
                    OperationContext::new(Duration::from_millis(500)),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), observed).await??;
        assert_eq!(observer.metrics().depth, 1);
        if abort {
            request.abort();
            assert!(request.await.is_err());
        } else {
            assert_eq!(request.await?, Err(ObjectIoError::Timeout));
        }
        assert_eq!(endpoint.finish().await?.len(), 1);
        io.shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
        assert_eq!(observer.metrics().depth, 0);
        assert_eq!(io.metrics().running, 0);
        assert_eq!(io.metrics().depth, 0);
    }
    Ok(())
}
