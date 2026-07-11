#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
mod fixture;
use signal_protocol::access::{Operation, ScopeFacts};
use std::time::Duration;
pub(super) struct LookupPause {
    entered: std::sync::atomic::AtomicBool,
    released: Mutex<bool>,
    condition: std::sync::Condvar,
}
impl LookupPause {
    pub(super) fn wait(&self) -> Result<(), IdentityError> {
        let mut released = self
            .released
            .lock()
            .map_err(|_| IdentityError::Unavailable)?;
        self.entered.store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !*released {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(IdentityError::Unavailable);
            }
            released = self
                .condition
                .wait_timeout(released, remaining)
                .map_err(|_| IdentityError::Unavailable)?
                .0;
        }
        Ok(())
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
}

fn policy() -> Arc<CompiledPolicy> {
    signal_protocol::access::AccessPolicy::from_json(
        br#"{"schema_version":1,"roles":[],"bindings":[]}"#,
    )
    .unwrap()
    .compile()
    .unwrap()
}
fn config() -> IdentityConfig {
    IdentityConfig {
        endpoint: "https://127.0.0.1:1/introspect".into(),
        client_id: "synthetic-client".into(),
        client_secret: "synthetic-secret".into(),
        extra_roots: vec![],
        workers: 1,
        max_request_duration: std::time::Duration::from_secs(1),
    }
}
fn profile() -> IntrospectionProfile {
    IntrospectionProfile::new(
        "https://identity.example.test".into(),
        "synthetic-signal".into(),
        60,
    )
    .unwrap()
}
#[tokio::test]
async fn token_rejections_do_not_open_connections_and_shutdown_joins_workers() {
    let backend = IdentityBackend::new(
        config(),
        profile(),
        policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    for token in ["", "bad credential", "\n"] {
        let context = IdentityContext {
            deadline: Instant::now() + std::time::Duration::from_secs(1),
            cancellation: CancellationToken::new(),
        };
        assert!(matches!(
            backend.authenticate(token, context).await,
            Err(IdentityError::InvalidCredential)
        ));
    }
    let metrics = backend.metrics();
    assert_eq!(metrics.depth, 0);
    assert_eq!(metrics.queue_depth, 0);
    assert_eq!(metrics.rejected, 3);
    backend
        .shutdown(Instant::now() + std::time::Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(backend.metrics().workers_alive, 0);
}
#[tokio::test]
async fn origin_configuration_rejects_http_userinfo_query_and_fragment() {
    for endpoint in [
        "http://127.0.0.1/introspect",
        "https://user@127.0.0.1/introspect",
        "https://127.0.0.1/introspect?secret=1",
        "https://127.0.0.1/introspect#secret",
    ] {
        let mut input = config();
        input.endpoint = endpoint.into();
        assert!(matches!(
            IdentityBackend::new(
                input,
                profile(),
                policy(),
                tokio::runtime::Handle::current()
            ),
            Err(IdentityError::Configuration)
        ));
    }
}

fn reader_policy() -> Arc<CompiledPolicy> {
    signal_protocol::access::AccessPolicy::from_json(br#"{"schema_version":1,"roles":[{"id":"read","permissions":[{"operation":"query_events","scope":{"sources":{"mode":"all"},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"all"}}}]}],"bindings":[{"issuer":"https://identity.example.test","subject":"reader","roles":["read"]}]}"#).unwrap().compile().unwrap()
}
fn context() -> IdentityContext {
    IdentityContext {
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation: CancellationToken::new(),
    }
}
async fn idle(backend: &IdentityBackend) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while backend.metrics().depth != 0 {
        assert!(Instant::now() < deadline, "physical completion");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn actual_https_introspection_rechecks_revocation_and_never_caches_grants() {
    let provider = fixture::Fixture::new(
        vec![
            fixture::json_reply(&fixture::valid_body()),
            fixture::json_reply(br#"{"active":false}"#),
            fixture::json_reply(&fixture::valid_body()),
        ],
        "127.0.0.1",
        "1",
    )
    .await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        reader_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let grant = backend.authenticate("opaque", context()).await.unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(grant.allows(
        Operation::QueryEvents,
        ScopeFacts {
            source: None,
            account: Some("a"),
            resource: None
        },
        now
    ));
    assert!(!grant.allows(
        Operation::QueryEvents,
        ScopeFacts {
            source: None,
            account: Some("b"),
            resource: None
        },
        now
    ));
    assert!(matches!(
        backend.authenticate("opaque", context()).await,
        Err(IdentityError::Denied)
    ));
    assert!(backend.authenticate("opaque", context()).await.is_ok());
    assert_eq!(provider.requests.load(Ordering::Acquire), 3);
    assert_eq!(backend.metrics().denied, 1);
    assert_eq!(backend.metrics().rejected, 1);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

#[tokio::test]
async fn provider_status_headers_shapes_and_body_limits_fail_closed() {
    let mut chunked=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4001\r\n".to_vec();
    chunked.extend(vec![b'x'; 16 * 1024 + 1]);
    chunked.extend(b"\r\n0\r\n\r\n");
    let rows=vec![
        (fixture::Reply::Bytes(b"HTTP/1.1 302 Found\r\nLocation: https://other.example.test/\r\nContent-Length: 0\r\n\r\n".to_vec()),IdentityError::Unavailable),
        (fixture::Reply::Bytes(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n".to_vec()),IdentityError::Unavailable),
        (fixture::Reply::Bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}".to_vec()),IdentityError::InvalidResponse),
        (fixture::Reply::Bytes(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}".to_vec()),IdentityError::InvalidResponse),
        (fixture::Reply::Bytes(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}".to_vec()),IdentityError::InvalidResponse),
        (fixture::Reply::Bytes(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16385\r\n\r\n".to_vec()),IdentityError::InvalidResponse),
        (fixture::Reply::Bytes(chunked),IdentityError::InvalidResponse),
        (fixture::json_reply(br#"{"active":true,"active":false}"#),IdentityError::InvalidResponse),
        (fixture::json_reply(br#"[true,"https://identity.example.test","reader","synthetic-signal",9999999999,"Bearer",null,null]"#),IdentityError::InvalidResponse),
    ];
    for (reply, expected) in rows {
        let provider = fixture::Fixture::new(vec![reply], "127.0.0.1", "1").await;
        let backend = IdentityBackend::new(
            provider.config(),
            profile(),
            reader_policy(),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        assert!(
            matches!(backend.authenticate("opaque",context()).await,Err(error) if error==expected)
        );
        assert_eq!(provider.requests.load(Ordering::Acquire), 1);
        assert_eq!(backend.metrics().depth, 0);
        backend
            .shutdown(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        provider.finish().await;
    }
}

#[tokio::test]
async fn authenticated_provider_cannot_override_profile_or_private_subject_binding() {
    let mut replies = Vec::new();
    for (field, value) in [
        ("iss", serde_json::json!("https://other.example.test")),
        ("aud", serde_json::json!("other-audience")),
        ("exp", serde_json::json!(1)),
        ("sub", serde_json::json!("unbound-subject")),
    ] {
        let mut body: serde_json::Value = serde_json::from_slice(&fixture::valid_body()).unwrap();
        body[field] = value;
        // These extensions are never role authority, even over verified TLS.
        body["roles"] = serde_json::json!(["administrator"]);
        body["scope"] = serde_json::json!("configure query_events");
        replies.push(fixture::json_reply(&serde_json::to_vec(&body).unwrap()));
    }
    replies.push(fixture::json_reply(&fixture::valid_body()));
    let provider = fixture::Fixture::new(replies, "127.0.0.1", "1").await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        reader_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    for expected in [
        IdentityError::Denied,
        IdentityError::Denied,
        IdentityError::Denied,
        IdentityError::Denied,
    ] {
        assert!(matches!(
            backend.authenticate("opaque", context()).await,
            Err(error) if error == expected
        ));
        idle(&backend).await;
    }
    let grant = backend.authenticate("opaque", context()).await.unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(!grant.allows(
        Operation::Configure,
        ScopeFacts {
            source: None,
            account: None,
            resource: None
        },
        now
    ));
    assert_eq!(provider.requests.load(Ordering::Acquire), 5);
    assert_eq!(backend.metrics().rejected, 4);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

#[tokio::test]
async fn wrong_root_wrong_host_and_expired_certificate_never_send_credentials() {
    for (certificate_ip, days, extra_root) in [
        ("127.0.0.1", "1", false),
        ("127.0.0.2", "1", true),
        ("127.0.0.1", "-1", true),
    ] {
        let provider = fixture::Fixture::new(
            vec![fixture::json_reply(&fixture::valid_body())],
            certificate_ip,
            days,
        )
        .await;
        let mut config = provider.config();
        if !extra_root {
            config.extra_roots.clear();
        }
        let backend = IdentityBackend::new(
            config,
            profile(),
            reader_policy(),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        assert!(matches!(
            backend.authenticate("opaque", context()).await,
            Err(IdentityError::Unavailable)
        ));
        assert_eq!(provider.requests.load(Ordering::Acquire), 0);
        backend
            .shutdown(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        provider.finish().await;
    }
}

#[tokio::test]
async fn finite_worker_capacity_cancellation_and_timeout_recover_for_fresh_request() {
    let provider = fixture::Fixture::new(
        vec![
            fixture::Reply::Stall,
            fixture::Reply::Stall,
            fixture::json_reply(&fixture::valid_body()),
        ],
        "127.0.0.1",
        "1",
    )
    .await;
    let mut config = provider.config();
    config.max_request_duration = Duration::from_millis(300);
    let backend = IdentityBackend::new(
        config,
        profile(),
        reader_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let request = backend.clone();
    let context = context();
    let cancellation = context.cancellation.clone();
    let pending = tokio::spawn(async move { request.authenticate("opaque", context).await });
    provider.wait_requests(1).await;
    assert_eq!(backend.metrics().depth, 1);
    assert_eq!(backend.metrics().running, 1);
    assert!(matches!(
        backend
            .authenticate("opaque", super::tests::context())
            .await,
        Err(IdentityError::Busy)
    ));
    cancellation.cancel();
    assert!(matches!(
        pending.await.unwrap(),
        Err(IdentityError::Cancelled)
    ));
    idle(&backend).await;
    assert!(matches!(
        backend
            .authenticate("opaque", super::tests::context())
            .await,
        Err(IdentityError::Timeout)
    ));
    idle(&backend).await;
    assert!(
        backend
            .authenticate("opaque", super::tests::context())
            .await
            .is_ok()
    );
    assert_eq!(provider.requests.load(Ordering::Acquire), 3);
    assert_eq!(backend.metrics().requests, 4);
    assert_eq!(backend.metrics().rejected, 3);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

#[tokio::test]
async fn paused_physical_lookup_retains_lease_after_frontend_timeout_and_close() {
    let provider = fixture::Fixture::new(
        vec![fixture::json_reply(&fixture::valid_body())],
        "127.0.0.1",
        "1",
    )
    .await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        reader_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let pause = Arc::new(LookupPause {
        entered: std::sync::atomic::AtomicBool::new(false),
        released: Mutex::new(false),
        condition: std::sync::Condvar::new(),
    });
    *backend.inner.transport.before_lookup.lock().unwrap() = Some(pause.clone());
    let request = backend.clone();
    let pending = tokio::spawn(async move {
        request
            .authenticate(
                "opaque",
                IdentityContext {
                    deadline: Instant::now() + Duration::from_millis(100),
                    cancellation: CancellationToken::new(),
                },
            )
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !pause.entered.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(matches!(
        pending.await.unwrap(),
        Err(IdentityError::Timeout)
    ));
    assert_eq!(backend.metrics().depth, 1);
    assert_eq!(backend.metrics().running, 1);
    assert!(matches!(
        backend.authenticate("opaque", context()).await,
        Err(IdentityError::Busy)
    ));
    assert!(matches!(
        backend
            .shutdown(Instant::now() + Duration::from_millis(20))
            .await,
        Err(IdentityError::Timeout)
    ));
    assert_eq!(backend.metrics().depth, 1);
    assert_eq!(backend.metrics().workers_alive, 1);
    assert!(matches!(
        backend.authenticate("opaque", context()).await,
        Err(IdentityError::Stopped)
    ));
    pause.release();
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(backend.metrics().depth, 0);
    assert_eq!(backend.metrics().workers_alive, 0);
    assert_eq!(provider.requests.load(Ordering::Acquire), 0);
    provider.finish().await;
}

#[tokio::test]
async fn aborted_caller_is_counted_and_releases_only_completed_physical_work() {
    let provider = fixture::Fixture::new(
        vec![
            fixture::Reply::Stall,
            fixture::json_reply(&fixture::valid_body()),
        ],
        "127.0.0.1",
        "1",
    )
    .await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        reader_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let request = backend.clone();
    let pending = tokio::spawn(async move { request.authenticate("opaque", context()).await });
    provider.wait_requests(1).await;
    pending.abort();
    assert!(matches!(pending.await, Err(error) if error.is_cancelled()));
    idle(&backend).await;
    assert_eq!(backend.metrics().rejected, 1);
    assert!(backend.authenticate("opaque", context()).await.is_ok());
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}
