// Synthetic loopback API and ephemeral PKI only.
#![allow(clippy::unwrap_used)]
use super::super::{Kind, Limits};
use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::{Value, json};
use std::sync::{Mutex, atomic::AtomicUsize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

struct Tokens {
    calls: AtomicUsize,
    delay: Duration,
}
#[async_trait]
impl TokenProvider for Tokens {
    async fn token(&self, _: &ExtensionContext) -> Result<AccessToken, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(self.delay).await;
        AccessToken::new("synthetic-k8s-token".into())
    }
}
fn tokens() -> Tokens {
    Tokens {
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
    }
}
fn context(ms: u64) -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_millis(ms)).unwrap()
}
fn profile(limits: Limits) -> Profile {
    Profile::new("cluster", Kind::Pod, Some("team"), Some("node-a"), limits).unwrap()
}
fn pod(uid: &str, rv: &str) -> Value {
    json!({"apiVersion":"v1","kind":"Pod","metadata":{"uid":uid,"name":uid,"namespace":"team","resourceVersion":rv},"spec":{"nodeName":"node-a","containers":[{"name":"main"}]}})
}
fn page(items: Vec<Value>, next: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"list-opaque","continue":next},"items":items})).unwrap()
}
fn event(action: &str, object: Value) -> Vec<u8> {
    let mut raw = serde_json::to_vec(&json!({"type":action,"object":object})).unwrap();
    raw.push(b'\n');
    raw
}
struct Reply {
    status: u16,
    chunks: Vec<(Vec<u8>, u64)>,
    header_delay: u64,
    extra: &'static str,
    chunked: bool,
}
impl Reply {
    fn body(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            chunks: vec![(body, 0)],
            header_delay: 0,
            extra: "",
            chunked: false,
        }
    }
}
struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    reply: Reply,
    seen: &Arc<Mutex<Vec<String>>>,
) {
    let work = async {
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).await?;
            if n == 0 || request.len() + n > 8192 {
                return Err(std::io::Error::other("fixture request bound"));
            }
            request.extend_from_slice(&buf[..n]);
        }
        seen.lock()
            .unwrap()
            .push(String::from_utf8(request).unwrap());
        tokio::time::sleep(Duration::from_millis(reply.header_delay)).await;
        let length: usize = reply.chunks.iter().map(|(bytes, _)| bytes.len()).sum();
        let framing = if reply.chunked {
            "Transfer-Encoding: chunked\r\n".to_owned()
        } else {
            format!("Content-Length: {length}\r\n")
        };
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {} Fixture\r\n{framing}Connection: close\r\n{}\r\n",
                    reply.status, reply.extra
                )
                .as_bytes(),
            )
            .await?;
        for (bytes, delay) in reply.chunks {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            if reply.chunked {
                stream
                    .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
                    .await?;
            }
            stream.write_all(&bytes).await?;
            if reply.chunked {
                stream.write_all(b"\r\n").await?;
            }
            stream.flush().await?;
        }
        if reply.chunked {
            stream.write_all(b"0\r\n\r\n").await?;
        }
        stream.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(4), work).await;
}
async fn server(replies: Vec<Reply>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let task = tokio::spawn(async move {
        for reply in replies {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_secs(4), listener.accept()).await
            else {
                return;
            };
            respond(stream, reply, &seen).await;
        }
    });
    Server {
        origin,
        requests,
        task,
    }
}
fn local(server: &Server, limits: Limits) -> Collector {
    Collector::local_fixture(&server.origin, profile(limits)).unwrap()
}
#[tokio::test]
async fn scoped_paginated_list_uses_exact_opaque_queries_and_bearer_then_atomic_snapshot() {
    let s = server(vec![
        Reply::body(page(vec![pod("a", "a-rv")], "opaque+/=?&x")),
        Reply::body(page(vec![pod("b", "b-rv")], "")),
    ])
    .await;
    let mut c = local(&s, Limits::default());
    let tokens = tokens();
    c.list(&tokens, &context(2000)).await.unwrap();
    assert_eq!(tokens.calls.load(Ordering::Relaxed), 2);
    let view = c.snapshot();
    assert!(view.collection.authoritative);
    assert_eq!(view.collection.objects.len(), 2);
    let requests = s.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert!(request.starts_with("GET /api/v1/namespaces/team/pods?"));
        assert!(request.contains("authorization: Bearer synthetic-k8s-token\r\n"));
        let path = request.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&format!("http://fixture{path}")).unwrap();
        let pairs: std::collections::BTreeMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(pairs["fieldSelector"], "spec.nodeName=node-a");
    }
    assert!(requests[1].contains("continue=opaque%2B%2F%3D%3F%26x"));
    assert_eq!(c.metrics().snapshot().active, 0);
}
#[test]
fn origin_route_and_selector_scope_refuse_before_any_token_can_be_acquired() {
    for origin in [
        "http://example.invalid",
        "https://127.0.0.1",
        "http://user@127.0.0.1",
        "http://127.0.0.1/path",
        "http://127.0.0.1?secret=x",
        "http://127.0.0.1#fragment",
        "http://127.0.0.1\\evil",
    ] {
        assert!(
            Collector::local_fixture(origin, profile(Limits::default())).is_err(),
            "{origin}"
        );
    }
    for name in [
        "../foreign",
        "a/b",
        "a%2fb",
        "UPPER",
        "a.b",
        "a,metadata.name=secret",
        "-bad",
    ] {
        let p = Profile::new("cluster", Kind::Pod, Some(name), None, Limits::default()).unwrap();
        assert!(Collector::local_fixture("http://127.0.0.1", p).is_err());
    }
    for node in ["node,metadata.name=x", "node=foreign", "../node", "UPPER"] {
        let p = Profile::new("cluster", Kind::Pod, None, Some(node), Limits::default()).unwrap();
        assert!(Collector::local_fixture("http://127.0.0.1", p).is_err());
    }
    let a = Collector::local_fixture("http://127.0.0.1:1", profile(Limits::default())).unwrap();
    let b = Collector::local_fixture("http://127.0.0.1:2", profile(Limits::default())).unwrap();
    assert_ne!(a.source_binding(), b.source_binding());
}
#[tokio::test]
async fn watch_retains_split_frame_and_snapshot_only_while_session_connected() {
    let mut changed = pod("a", "changed");
    changed["metadata"]["annotations"] = json!({"note":"snow☃"});
    let change = event("MODIFIED", changed);
    let split = change.windows(3).position(|w| w == "☃".as_bytes()).unwrap() + 1;
    let reply = Reply {
        chunks: vec![
            (change[..split].to_vec(), 0),
            (change[split..].to_vec(), 15),
        ],
        ..Reply::body(vec![])
    };
    let s = server(vec![Reply::body(page(vec![pod("a", "rv")], "")), reply]).await;
    let mut c = local(&s, Limits::default());
    let tokens = tokens();
    let ctx = context(2000);
    c.list(&tokens, &ctx).await.unwrap();
    let metrics = c.metrics();
    let binding = c.source_binding().to_owned();
    let mut watch = c.watch(&tokens, &ctx).await.unwrap();
    assert!(watch.next_frame().await.unwrap());
    let snapshot = watch.snapshot();
    assert!(snapshot.collection.authoritative);
    assert_eq!(snapshot.source_binding, binding);
    assert_eq!(snapshot.collection.objects[0].resource_version(), "changed");
    assert!(!watch.next_frame().await.unwrap());
    assert!(!watch.snapshot().collection.authoritative);
    assert_eq!(watch.next_frame().await, Err(Error::Closed));
    drop(watch);
    assert!(!c.snapshot().collection.authoritative);
    assert_eq!(metrics.snapshot().active, 0);
    assert_eq!(metrics.snapshot().invalidated_operations, 1);
}
#[tokio::test]
async fn dropped_watch_session_or_frame_read_invalidates_and_relist_restores() {
    let mut delayed = Reply::body(event(
        "BOOKMARK",
        json!({"metadata":{"resourceVersion":"b"}}),
    ));
    delayed.chunks[0].1 = 200;
    let s = server(vec![
        Reply::body(page(vec![pod("a", "rv")], "")),
        delayed,
        Reply::body(page(vec![], "")),
    ])
    .await;
    let mut c = local(&s, Limits::default());
    let tokens = tokens();
    let ctx = context(2000);
    c.list(&tokens, &ctx).await.unwrap();
    let mut watch = c.watch(&tokens, &ctx).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), watch.next_frame())
            .await
            .is_err()
    );
    assert!(!watch.snapshot().collection.authoritative);
    drop(watch);
    assert!(matches!(
        c.watch(&tokens, &ctx).await,
        Err(Error::Reconcile(super::super::Error::Stale))
    ));
    c.list(&tokens, &ctx).await.unwrap();
    assert!(c.snapshot().collection.authoritative);
}
#[tokio::test]
async fn http_permission_expiry_redirect_and_encoding_never_retry_or_refresh() {
    for (status, expected) in [
        (401, Error::Permission),
        (403, Error::Permission),
        (410, Error::Expired),
        (302, Error::Response),
        (500, Error::Response),
    ] {
        let mut reply = Reply::body(vec![]);
        reply.status = status;
        reply.extra = "Location: http://example.invalid/\r\n";
        let s = server(vec![reply]).await;
        let mut c = local(&s, Limits::default());
        let tokens = tokens();
        assert_eq!(c.list(&tokens, &context(1000)).await, Err(expected));
        assert_eq!(tokens.calls.load(Ordering::Relaxed), 1);
        assert_eq!(s.requests.lock().unwrap().len(), 1);
        assert!(!c.snapshot().collection.authoritative);
        assert_eq!(c.metrics().snapshot().invalidated_operations, 1);
    }
    let mut encoded = Reply::body(page(vec![], ""));
    encoded.extra = "Content-Encoding: gzip\r\n";
    let s = server(vec![encoded]).await;
    let mut c = local(&s, Limits::default());
    assert_eq!(
        c.list(&tokens(), &context(1000)).await,
        Err(Error::Response)
    );
}
#[tokio::test]
async fn original_deadline_bounds_token_headers_chunks_and_precancelled_work() {
    let s = server(vec![]).await;
    let mut c = local(&s, Limits::default());
    let slow = Tokens {
        calls: AtomicUsize::new(0),
        delay: Duration::from_millis(200),
    };
    assert_eq!(c.list(&slow, &context(20)).await, Err(Error::Timeout));
    assert!(s.requests.lock().unwrap().is_empty());
    let mut reply = Reply::body(page(vec![], ""));
    reply.header_delay = 200;
    let s = server(vec![reply]).await;
    let mut c = local(&s, Limits::default());
    assert_eq!(c.list(&tokens(), &context(20)).await, Err(Error::Timeout));
    let mut reply = Reply::body(page(vec![], ""));
    reply.chunks[0].1 = 200;
    let s = server(vec![reply]).await;
    let mut c = local(&s, Limits::default());
    assert_eq!(c.list(&tokens(), &context(20)).await, Err(Error::Timeout));
    let ctx = context(1000);
    ctx.cancellation().cancel();
    let token = tokens();
    assert_eq!(c.list(&token, &ctx).await, Err(Error::Cancelled));
    assert_eq!(token.calls.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn watch_original_deadline_partial_eof_error_and_received_whitespace_limits_refuse() {
    let cases = vec![
        (
            Reply {
                chunks: vec![(
                    event("BOOKMARK", json!({"metadata":{"resourceVersion":"b"}})),
                    200,
                )],
                ..Reply::body(vec![])
            },
            Error::Timeout,
        ),
        (Reply::body(b"{\"type\":".to_vec()), Error::Response),
        (
            Reply::body(event("ERROR", json!({"code":410}))),
            Error::Reconcile(super::super::Error::Continuity),
        ),
    ];
    for (reply, expected) in cases {
        let s = server(vec![Reply::body(page(vec![], "")), reply]).await;
        let mut c = local(
            &s,
            Limits {
                max_watch_bytes: 256,
                ..Limits::default()
            },
        );
        let tokens = tokens();
        c.list(&tokens, &context(1000)).await.unwrap();
        let ctx = context(if expected == Error::Timeout { 30 } else { 1000 });
        let mut watch = c.watch(&tokens, &ctx).await.unwrap();
        assert_eq!(watch.next_frame().await, Err(expected));
        assert!(!watch.snapshot().collection.authoritative);
    }
}
#[tokio::test]
async fn list_and_watch_native_byte_caps_and_inconsistent_list_never_publish_prefix() {
    let s = server(vec![Reply::body(vec![b' '; 257])]).await;
    let mut c = local(
        &s,
        Limits {
            max_page_bytes: 256,
            ..Limits::default()
        },
    );
    assert_eq!(c.list(&tokens(), &context(1000)).await, Err(Error::Limit));
    let mut wrong: Value = serde_json::from_slice(&page(vec![], "")).unwrap();
    wrong["metadata"]["resourceVersion"] = json!("foreign");
    let s = server(vec![
        Reply::body(page(vec![pod("a", "rv")], "next")),
        Reply::body(serde_json::to_vec(&wrong).unwrap()),
    ])
    .await;
    let mut c = local(&s, Limits::default());
    assert!(c.list(&tokens(), &context(1000)).await.is_err());
    assert!(c.snapshot().collection.objects.is_empty());
}
#[tokio::test]
async fn bearer_only_tls_checks_original_ca_foreign_ca_and_hostname() {
    let dir = tempfile::tempdir().unwrap();
    crate::test_tls::pki(dir.path()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_file(dir.path().join("server.pem")).unwrap()],
            PrivateKeyDer::from_pem_file(dir.path().join("server.key")).unwrap(),
        )
        .unwrap();
    for (address, trust, success) in [
        ("127.0.0.1", "original", true),
        ("127.0.0.1", "foreign", false),
        ("127.0.0.2", "original", false),
    ] {
        let listener = TcpListener::bind(format!("{address}:0")).await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server.clone()));
        let task = tokio::spawn(async move {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_secs(2), listener.accept()).await
            else {
                return;
            };
            if let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream)).await
            {
                respond(stream, Reply::body(page(vec![], "")), &seen).await;
            }
        });
        let server_owner = Server {
            origin: origin.clone(),
            requests,
            task,
        };
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(dir.path().join(format!("{trust}.pem"))).unwrap())
            .unwrap();
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let other =
            Collector::new(&origin, profile(Limits::default()), config.clone(), [2; 32]).unwrap();
        let mut c = Collector::new(&origin, profile(Limits::default()), config, [1; 32]).unwrap();
        assert_ne!(other.source_binding(), c.source_binding());
        assert_eq!(c.list(&tokens(), &context(1500)).await.is_ok(), success);
        assert_eq!(
            server_owner.requests.lock().unwrap().len(),
            usize::from(success)
        );
    }
}

#[test]
fn all_selected_kind_routes_and_explicit_cluster_scope_are_fixed() {
    for kind in [
        Kind::Pod,
        Kind::Node,
        Kind::Namespace,
        Kind::Role,
        Kind::ClusterRole,
        Kind::RoleBinding,
        Kind::ClusterRoleBinding,
    ] {
        let p = Profile::new(
            "cluster",
            kind,
            kind.namespaced().then_some("team"),
            None,
            Limits::default(),
        )
        .unwrap();
        let base = Url::parse("https://api.invalid:6443").unwrap();
        let request = url(&base, &p, Some("https://foreign.invalid/private"), None).unwrap();
        assert_eq!(request.host_str(), Some("api.invalid"));
        assert_eq!(request.port(), Some(6443));
        let prefix = if matches!(kind, Kind::Pod | Kind::Node | Kind::Namespace) {
            "/api/v1"
        } else {
            "/apis/rbac.authorization.k8s.io/v1"
        };
        let expected = if kind.namespaced() {
            format!("{prefix}/namespaces/team/{}", resource(kind))
        } else {
            format!("{prefix}/{}", resource(kind))
        };
        assert_eq!(request.path(), expected);
        assert!(request.query_pairs().any(|(key,value)|key=="continue" && value=="https://foreign.invalid/private"));
    }
    let p = Profile::new("cluster", Kind::Pod, None, None, Limits::default()).unwrap();
    assert_eq!(
        url(&Url::parse("http://127.0.0.1").unwrap(), &p, None, None)
            .unwrap()
            .path(),
        "/api/v1/pods"
    );
}
#[tokio::test]
async fn dropped_session_without_frame_read_and_cancelled_watch_invalidate() {
    for cancelled in [false, true] {
        let mut delayed = Reply::body(event(
            "BOOKMARK",
            json!({"metadata":{"resourceVersion":"b"}}),
        ));
        delayed.chunks[0].1 = 200;
        let s = server(vec![Reply::body(page(vec![], "")), delayed]).await;
        let mut c = local(&s, Limits::default());
        let token = tokens();
        let ctx = context(1000);
        c.list(&token, &ctx).await.unwrap();
        let metrics = c.metrics();
        let mut watch = c.watch(&token, &ctx).await.unwrap();
        if cancelled {
            ctx.cancellation().cancel();
            assert_eq!(watch.next_frame().await, Err(Error::Cancelled));
            assert!(!watch.snapshot().collection.authoritative);
        }
        drop(watch);
        assert!(!c.snapshot().collection.authoritative);
        assert_eq!(metrics.snapshot().active, 0);
    }
}
#[tokio::test]
async fn dropped_refresh_keeps_old_inventory_stale_instead_of_publishing_prefix() {
    struct Pages(AtomicUsize);
    #[async_trait]
    impl TokenProvider for Pages {
        async fn token(&self, _: &ExtensionContext) -> Result<AccessToken, Error> {
            if self.0.fetch_add(1, Ordering::Relaxed) >= 2 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            AccessToken::new("synthetic-k8s-token".into())
        }
    }
    let s = server(vec![
        Reply::body(page(vec![pod("old", "rv")], "")),
        Reply::body(page(vec![pod("new", "new-rv")], "next")),
    ])
    .await;
    let mut c = local(&s, Limits::default());
    let token = Pages(AtomicUsize::new(0));
    let ctx = context(2000);
    c.list(&token, &ctx).await.unwrap();
    let generation = c.snapshot().collection.generation;
    let metrics = c.metrics();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), c.list(&token, &ctx))
            .await
            .is_err()
    );
    let snapshot = c.snapshot();
    assert!(!snapshot.collection.authoritative);
    assert_eq!(snapshot.collection.generation, generation);
    assert_eq!(snapshot.collection.objects[0].uid(), "old");
    assert_eq!(metrics.snapshot().active, 0);
    assert_eq!(metrics.snapshot().invalidated_operations, 1);
}
#[tokio::test]
async fn watch_header_byte_limit_and_metadata_age_are_rechecked_after_authentication() {
    let s = server(vec![
        Reply::body(page(vec![], "")),
        Reply::body(vec![b'\n'; 257]),
    ])
    .await;
    let mut c = local(
        &s,
        Limits {
            max_watch_bytes: 256,
            ..Limits::default()
        },
    );
    let token = tokens();
    let ctx = context(1000);
    c.list(&token, &ctx).await.unwrap();
    assert!(matches!(c.watch(&token, &ctx).await, Err(Error::Limit)));
    assert!(!c.snapshot().collection.authoritative);
    let s = server(vec![Reply::body(page(vec![], "")), Reply::body(vec![])]).await;
    let mut c = local(
        &s,
        Limits {
            max_age_seconds: 1,
            ..Limits::default()
        },
    );
    c.list(&tokens(), &context(2000)).await.unwrap();
    let slow = Tokens {
        calls: AtomicUsize::new(0),
        delay: Duration::from_millis(1100),
    };
    assert!(matches!(
        c.watch(&slow, &context(2000)).await,
        Err(Error::Reconcile(super::super::Error::Stale))
    ));
}

#[tokio::test]
async fn idle_watch_snapshot_invalidates_on_cancellation_or_original_deadline() {
    for cancellation in [false, true] {
        let mut reply = Reply::body(event(
            "BOOKMARK",
            json!({"metadata":{"resourceVersion":"b"}}),
        ));
        reply.chunks[0].1 = 1000;
        let s = server(vec![Reply::body(page(vec![], "")), reply]).await;
        let mut c = local(&s, Limits::default());
        let token = tokens();
        c.list(&token, &context(2000)).await.unwrap();
        let ctx = context(300);
        let mut watch = c.watch(&token, &ctx).await.unwrap();
        if cancellation {
            ctx.cancellation().cancel();
        } else {
            tokio::time::sleep(Duration::from_millis(310)).await;
        }
        // Snapshot is deliberately the FIRST operation after cancel/expiry. A
        // next_frame call here would hide the original idle-snapshot defect.
        assert!(!watch.snapshot().collection.authoritative);
        assert_eq!(watch.next_frame().await, Err(Error::Closed));
        drop(watch);
        assert!(!c.snapshot().collection.authoritative);
    }
}
#[tokio::test]
async fn chunked_body_whitespace_and_pending_frame_caps_charge_every_received_byte() {
    let reply = Reply {
        chunked: true,
        chunks: vec![(vec![b'\n'; 80], 0); 4],
        ..Reply::body(vec![])
    };
    let s = server(vec![Reply::body(page(vec![], "")), reply]).await;
    let mut c = local(
        &s,
        Limits {
            max_watch_bytes: 256,
            ..Limits::default()
        },
    );
    let token = tokens();
    let ctx = context(2000);
    c.list(&token, &ctx).await.unwrap();
    let mut watch = c.watch(&token, &ctx).await.unwrap();
    assert_eq!(watch.next_frame().await, Err(Error::Limit));
    assert!(watch.received_bytes() > 256);
    assert!(!watch.snapshot().collection.authoritative);
    let reply = Reply {
        chunked: true,
        chunks: vec![(vec![b' '; 257], 0)],
        ..Reply::body(vec![])
    };
    let s = server(vec![Reply::body(page(vec![], "")), reply]).await;
    let mut c = local(
        &s,
        Limits {
            max_page_bytes: 256,
            max_watch_bytes: 1024,
            ..Limits::default()
        },
    );
    let token = tokens();
    let ctx = context(2000);
    c.list(&token, &ctx).await.unwrap();
    let mut watch = c.watch(&token, &ctx).await.unwrap();
    assert_eq!(watch.next_frame().await, Err(Error::Limit));
    assert_eq!(watch.received_bytes(), 257);
}
