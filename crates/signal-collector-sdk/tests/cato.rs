#![allow(clippy::unwrap_used, clippy::expect_used)]
use async_trait::async_trait;
use chrono::Utc;
use signal_collector_sdk::{ExtensionContext, cato::*};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;
#[derive(Default)]
struct Keys(std::sync::atomic::AtomicUsize);
#[async_trait]
impl KeyProvider for Keys {
    async fn key(&self, _: &ExtensionContext) -> Result<ApiKey, Error> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ApiKey::new("synthetic-key".into())
    }
}
fn ctx() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(3)).unwrap()
}
async fn server(
    replies: Vec<String>,
) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let worker = tokio::spawn(async move {
        for reply in replies {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            let mut block = [0; 1024];
            loop {
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
                let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut block))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && bytes.len() + n <= 16384);
                bytes.extend_from_slice(&block[..n]);
            }
            captured
                .lock()
                .unwrap()
                .push(String::from_utf8(bytes).unwrap());
            // A bounded client may close before an oversized entity is sent.
            let _ = socket.write_all(reply.as_bytes()).await;
        }
    });
    (origin, requests, worker)
}
fn response(code: u16, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {code} fixture\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}
#[tokio::test]
async fn bounded_post_retries_preserve_marker_account_filter_and_exact_bytes() {
    let body =
        " {\"data\":{\"eventsFeed\":{\"marker\":\"next\",\"fetchedCount\":0,\"accounts\":[]}}} ";
    let (origin, requests, worker) = server(vec![
        response(429, "Retry-After: 0\r\n", ""),
        response(503, "", ""),
        response(200, "", body),
    ])
    .await;
    let c = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    let keys = Keys::default();
    let marker = "opaque\"\\marker";
    let p = Position::Resume {
        marker: marker.into(),
        committed_at: Utc::now(),
    };
    let got = c.capture(&p, &keys, &ctx()).await.unwrap();
    assert_eq!(got.original_bytes, body.as_bytes());
    worker.await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    for r in requests.iter() {
        assert!(r.starts_with("POST /api/v1/graphql2 HTTP/1.1"));
        assert!(r.to_lowercase().contains("x-api-key: synthetic-key"));
        let request: serde_json::Value =
            serde_json::from_str(r.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(request["query"], QUERY);
        assert_eq!(request["variables"]["marker"], marker);
        assert_eq!(
            request["variables"]["accountIDs"],
            serde_json::json!(["123"])
        );
    }
    assert_eq!(keys.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(c.metrics(), (0, 1, 0));
}
#[tokio::test]
async fn expired_future_and_invalid_marker_refuse_before_key_or_network() {
    let c = EventsClient::local_fixture("http://127.0.0.1:9", "123".into()).unwrap();
    let keys = Keys::default();
    for (marker, at, error) in [
        (
            "old".into(),
            Utc::now() - chrono::Duration::days(3),
            Error::Expired,
        ),
        (
            "future".into(),
            Utc::now() + chrono::Duration::hours(1),
            Error::Expired,
        ),
        (String::new(), Utc::now(), Error::Scope),
        ("x".repeat(MAX_MARKER_BYTES + 1), Utc::now(), Error::Scope),
        ("bad\nmarker".into(), Utc::now(), Error::Scope),
    ] {
        assert!(
            matches!(c.capture(&Position::Resume{marker,committed_at:at},&keys,&ctx()).await,Err(e) if e==error)
        );
    }
    assert_eq!(keys.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    for origin in [
        "http://example.invalid",
        "http://user@127.0.0.1:9",
        "http://127.0.0.1:9/?query",
        "http://127.0.0.1:9/path",
    ] {
        assert!(EventsClient::local_fixture(origin, "123".into()).is_err());
    }
    for account in ["0", "0123", "1\"bad", ""] {
        assert!(EventsClient::local_fixture("http://127.0.0.1:9", account.into()).is_err());
    }
}
#[tokio::test]
async fn auth_redirect_expiry_exhaustion_and_body_limit_do_not_return_capture() {
    for (code, expected, count) in [
        (401, Error::Authentication, 1),
        (403, Error::Authentication, 1),
        (302, Error::Response, 1),
        (410, Error::Expired, 1),
        (503, Error::Unavailable, MAX_ATTEMPTS),
    ] {
        let (origin, _, worker) = server(vec![
            response(
                code,
                "Retry-After: 0\r\nLocation: https://attacker.invalid/\r\n",
                ""
            );
            count
        ])
        .await;
        let c = EventsClient::local_fixture(&origin, "123".into()).unwrap();
        assert!(
            matches!(c.capture(&Position::Latest,&Keys::default(),&ctx()).await,Err(e) if e==expected)
        );
        worker.await.unwrap();
        assert_eq!(c.metrics(), (0, 1, 1));
    }
    let (origin, _, worker) = server(vec![format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_BODY_BYTES + 1
    )])
    .await;
    let c = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    assert!(matches!(
        c.capture(&Position::Latest, &Keys::default(), &ctx()).await,
        Err(Error::Limit)
    ));
    worker.await.unwrap();
}
#[tokio::test]
async fn retry_wait_uses_original_deadline_and_cancellation() {
    for cancel in [false, true] {
        let (origin, _, worker) = server(vec![response(429, "Retry-After: 60\r\n", "")]).await;
        let c = EventsClient::local_fixture(&origin, "123".into()).unwrap();
        let context =
            ExtensionContext::new(CancellationToken::new(), Duration::from_millis(80)).unwrap();
        let token = context.cancellation().clone();
        let keys = Keys::default();
        let future = c.capture(&Position::Latest, &keys, &context);
        tokio::pin!(future);
        let result = if cancel {
            tokio::select! {r=&mut future=>r,_=tokio::time::sleep(Duration::from_millis(20))=>{token.cancel();future.await}}
        } else {
            future.await
        };
        assert!(matches!(result,Err(e) if e==if cancel{Error::Cancelled}else{Error::Timeout}));
        worker.await.unwrap();
        assert_eq!(c.metrics(), (0, 1, 1));
    }
}

use page::{Epoch, PageJournal, Pager, State};
struct Disk {
    path: std::path::PathBuf,
    lose_reply: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl PageJournal for Disk {
    async fn load(&self, _: &ExtensionContext) -> Result<Option<State>, Error> {
        match std::fs::read(&self.path) {
            Ok(bytes) if bytes.len() <= page::MAX_STATE_BYTES => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| Error::Journal),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(Error::Journal),
        }
    }
    async fn commit(
        &self,
        revision: u64,
        next: &State,
        context: &ExtensionContext,
    ) -> Result<(), Error> {
        use std::io::Write;
        if self
            .load(context)
            .await?
            .as_ref()
            .map_or(0, State::revision)
            != revision
        {
            return Err(Error::Conflict);
        }
        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|_| Error::Journal)?;
        file.write_all(&serde_json::to_vec(next).map_err(|_| Error::Journal)?)
            .map_err(|_| Error::Journal)?;
        file.sync_all().map_err(|_| Error::Journal)?;
        std::fs::rename(tmp, &self.path).map_err(|_| Error::Journal)?;
        std::fs::File::open(self.path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Journal)?;
        if self
            .lose_reply
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            Err(Error::Journal)
        } else {
            Ok(())
        }
    }
}
fn security(next: &str, records: serde_json::Value) -> String {
    serde_json::json!({"data":{"eventsFeed":{"marker":next,"fetchedCount":records.as_array().unwrap().len(),"accounts":[{"id":"123","errorString":null,"records":records}]}}}).to_string()
}
fn record() -> serde_json::Value {
    serde_json::json!({"time":"2026-10-14T10:00:00Z","fieldsMap":{"event_type":"Security","event_sub_type":"Internet Firewall","action":"Block","account_id":"123","internalId":"native-assertion","custom":{"nested":[1,true]}}})
}
#[tokio::test]
async fn fsync_lost_commit_reply_reload_exact_events_and_marker_without_repeat_request() {
    let first = security("marker-one", serde_json::json!([record()]));
    let second = security("marker-two", serde_json::json!([]));
    let (origin, requests, worker) =
        server(vec![response(200, "", &first), response(200, "", &second)]).await;
    let c = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let disk = Disk {
        path: directory.path().join("page.json"),
        lose_reply: std::sync::atomic::AtomicBool::new(true),
    };
    let epoch = Epoch::new("test-source", uuid::Uuid::from_u128(1), Position::Latest).unwrap();
    let keys = Keys::default();
    let mut pager = Pager::new(&c, &disk, &keys, epoch.clone());
    assert!(matches!(pager.advance(&ctx()).await, Err(Error::Journal)));
    let before = disk.load(&ctx()).await.unwrap().unwrap();
    assert_eq!(before.revision(), 1);
    assert_eq!(before.pages()[0].original(), first.as_bytes());
    let original_event = before.events().next().unwrap().clone();
    assert_eq!(
        original_event.attributes["cato"]["fields"]["custom"]["nested"],
        serde_json::json!([1, true])
    );
    assert_eq!(
        original_event.attributes["coverage"]["completeness"],
        "not_assessed"
    );
    drop(pager);
    let mut fresh = Pager::new(&c, &disk, &keys, epoch.clone());
    let after = fresh.advance(&ctx()).await.unwrap();
    assert_eq!(after.revision(), 2);
    assert_eq!(after.events().next().unwrap(), &original_event);
    worker.await.unwrap();
    {
        let requests = requests.lock().unwrap();
        let second_request: serde_json::Value =
            serde_json::from_str(requests[1].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(second_request["variables"]["marker"], "marker-one");
    }
    let mut corrupted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&disk.path).unwrap()).unwrap();
    corrupted["pages"][0]["prepared"][0]["message"] = serde_json::json!("tampered");
    std::fs::write(&disk.path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
    assert!(matches!(fresh.load(&ctx()).await, Err(Error::Conflict)));
}
#[tokio::test]
async fn malformed_partial_scope_conflict_and_graphql_errors_preserve_original_checkpoint() {
    let first = security("one", serde_json::json!([record()]));
    let mut foreign = record();
    foreign["fieldsMap"]["account_id"] = serde_json::json!("999");
    let mut malformed = record();
    malformed["time"] = serde_json::json!("not-time");
    let mut other_type = record();
    other_type["fieldsMap"]["event_type"] = serde_json::json!("Connectivity");
    let mut account_error: serde_json::Value =
        serde_json::from_str(&security("two", serde_json::json!([]))).unwrap();
    account_error["data"]["eventsFeed"]["accounts"][0]["errorString"] = serde_json::json!("denied");
    let invalid = vec![
        security("two", serde_json::json!([record(), malformed])),
        security("two", serde_json::json!([foreign])),
        security("two", serde_json::json!([other_type])),
        security("one", serde_json::json!([record()])),
        account_error.to_string(),
        "{\"errors\":[{\"message\":\"expired marker\"}],\"data\":null}".into(),
    ];
    for bad in invalid {
        let (origin, _, worker) =
            server(vec![response(200, "", &first), response(200, "", &bad)]).await;
        let c = EventsClient::local_fixture(&origin, "123".into()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let disk = Disk {
            path: directory.path().join("page.json"),
            lose_reply: std::sync::atomic::AtomicBool::new(false),
        };
        let epoch = Epoch::new("test", uuid::Uuid::from_u128(2), Position::Latest).unwrap();
        let keys = Keys::default();
        let mut pager = Pager::new(&c, &disk, &keys, epoch);
        pager.advance(&ctx()).await.unwrap();
        let before = std::fs::read(&disk.path).unwrap();
        assert!(pager.advance(&ctx()).await.is_err());
        assert_eq!(std::fs::read(&disk.path).unwrap(), before);
        worker.await.unwrap();
    }
}
struct HeldKey;
#[async_trait]
impl KeyProvider for HeldKey {
    async fn key(&self, _: &ExtensionContext) -> Result<ApiKey, Error> {
        std::future::pending().await
    }
}
#[tokio::test]
async fn concurrent_request_rejects_and_abandoned_key_future_counts_failure() {
    let client = EventsClient::local_fixture("http://127.0.0.1:9", "123".into()).unwrap();
    let context = ctx();
    let mut active = Box::pin(client.capture(&Position::Latest, &HeldKey, &context));
    tokio::select! {r=&mut active=>panic!("unexpected result {}",r.is_ok()),_=tokio::time::sleep(Duration::from_millis(20))=>{}}
    assert_eq!(client.metrics(), (1, 1, 0));
    assert!(matches!(
        client
            .capture(&Position::Latest, &Keys::default(), &ctx())
            .await,
        Err(Error::Busy)
    ));
    drop(active);
    assert_eq!(client.metrics(), (0, 1, 2));
}
#[tokio::test]
async fn cato_disk_receipt_child_process() {
    let Some(config) = std::env::var_os("SIGNAL_OWNED_CATO_CHILD_CONFIG") else {
        return;
    };
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(config).unwrap()).unwrap();
    let client = EventsClient::local_fixture(v["origin"].as_str().unwrap(), "123".into()).unwrap();
    let disk = Disk {
        path: v["state"].as_str().unwrap().into(),
        lose_reply: std::sync::atomic::AtomicBool::new(false),
    };
    let keys = Keys::default();
    let epoch = Epoch::new("crash-test", uuid::Uuid::from_u128(42), Position::Latest).unwrap();
    let mut pager = Pager::new(&client, &disk, &keys, epoch);
    assert_eq!(pager.advance(&ctx()).await.unwrap().revision(), 1);
    std::fs::write(v["ready"].as_str().unwrap(), b"committed").unwrap();
    std::future::pending::<()>().await;
}
struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
async fn physical_child_sigkill_preserves_fsynced_page_and_resumes_exact_cursor() {
    use std::os::unix::process::ExitStatusExt;
    let first = security("crash-one", serde_json::json!([record()]));
    let second = security("crash-two", serde_json::json!([]));
    let (origin, requests, worker) =
        server(vec![response(200, "", &first), response(200, "", &second)]).await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let ready = dir.path().join("ready");
    let config = dir.path().join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({"origin":origin,"state":state,"ready":ready}))
            .unwrap(),
    )
    .unwrap();
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cato_disk_receipt_child_process", "--nocapture"])
            .env("SIGNAL_OWNED_CATO_CHILD_CONFIG", &config)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "child did not commit"
        );
        assert!(child.0.try_wait().unwrap().is_none(), "child exited early");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let disk = Disk {
        path: state,
        lose_reply: std::sync::atomic::AtomicBool::new(false),
    };
    let before = disk.load(&ctx()).await.unwrap().unwrap();
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    let client = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    let keys = Keys::default();
    let mut fresh = Pager::new(
        &client,
        &disk,
        &keys,
        Epoch::new("crash-test", uuid::Uuid::from_u128(42), Position::Latest).unwrap(),
    );
    let after = fresh.advance(&ctx()).await.unwrap();
    assert_eq!(after.revision(), 2);
    assert_eq!(after.pages()[0].original(), before.pages()[0].original());
    assert_eq!(after.events().next(), before.events().next());
    worker.await.unwrap();
    let requests = requests.lock().unwrap();
    let body: serde_json::Value =
        serde_json::from_str(requests[1].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["variables"]["marker"], "crash-one");
}
#[tokio::test]
async fn finite_page_capacity_and_expired_resume_preserve_custody_before_key_access() {
    let body = security("idle", serde_json::json!([]));
    let (origin, _, worker) = server(vec![response(200, "", &body); page::MAX_PAGES]).await;
    let client = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let disk = Disk {
        path: dir.path().join("state.json"),
        lose_reply: std::sync::atomic::AtomicBool::new(false),
    };
    let epoch = Epoch::new("finite", uuid::Uuid::from_u128(3), Position::Latest).unwrap();
    let keys = Keys::default();
    let mut pager = Pager::new(&client, &disk, &keys, epoch);
    for i in 0..page::MAX_PAGES {
        assert_eq!(
            pager.advance(&ctx()).await.unwrap().revision(),
            i as u64 + 1
        );
    }
    let before = std::fs::read(&disk.path).unwrap();
    assert!(matches!(pager.advance(&ctx()).await, Err(Error::Limit)));
    assert_eq!(before, std::fs::read(&disk.path).unwrap());
    assert_eq!(
        keys.0.load(std::sync::atomic::Ordering::Relaxed),
        page::MAX_PAGES
    );
    worker.await.unwrap();
    // Simulated historical trusted journal: retained empty-page receipt remains
    // readable, while its old last cursor cannot trigger another provider call.
    let mut old: serde_json::Value = serde_json::from_slice(&before).unwrap();
    old["pages"].as_array_mut().unwrap().truncate(1);
    old["pages"][0]["observed_at"] = serde_json::json!(Utc::now() - chrono::Duration::days(3));
    std::fs::write(&disk.path, serde_json::to_vec(&old).unwrap()).unwrap();
    let old_bytes = std::fs::read(&disk.path).unwrap();
    assert_eq!(pager.load(&ctx()).await.unwrap().revision(), 1);
    assert!(matches!(pager.advance(&ctx()).await, Err(Error::Expired)));
    assert_eq!(old_bytes, std::fs::read(&disk.path).unwrap());
    assert_eq!(
        keys.0.load(std::sync::atomic::Ordering::Relaxed),
        page::MAX_PAGES
    );
}
#[tokio::test]
async fn chunked_entity_limit_and_return_to_initial_cursor_refuse_without_advancement() {
    let chunk = "x".repeat(MAX_BODY_BYTES / 2);
    let mut response =
        "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned();
    for _ in 0..3 {
        response.push_str(&format!("{:x}\r\n{}\r\n", chunk.len(), chunk));
    }
    response.push_str("0\r\n\r\n");
    let (origin, _, worker) = server(vec![response]).await;
    let client = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    assert!(matches!(
        client
            .capture(&Position::Latest, &Keys::default(), &ctx())
            .await,
        Err(Error::Limit)
    ));
    worker.await.unwrap();
    let (origin, _, worker) = server(vec![
        self::response(200, "", &security("next", serde_json::json!([record()]))),
        self::response(200, "", &security("initial", serde_json::json!([]))),
    ])
    .await;
    let client = EventsClient::local_fixture(&origin, "123".into()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let disk = Disk {
        path: dir.path().join("state.json"),
        lose_reply: std::sync::atomic::AtomicBool::new(false),
    };
    let epoch = Epoch::new(
        "cycle",
        uuid::Uuid::from_u128(4),
        Position::Resume {
            marker: "initial".into(),
            committed_at: Utc::now(),
        },
    )
    .unwrap();
    let keys = Keys::default();
    let mut pager = Pager::new(&client, &disk, &keys, epoch);
    pager.advance(&ctx()).await.unwrap();
    let before = std::fs::read(&disk.path).unwrap();
    assert!(matches!(pager.advance(&ctx()).await, Err(Error::Conflict)));
    assert_eq!(before, std::fs::read(&disk.path).unwrap());
    worker.await.unwrap();
}
