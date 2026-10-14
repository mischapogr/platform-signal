#![allow(clippy::unwrap_used, clippy::expect_used)]
use async_trait::async_trait;
use signal_collector_sdk::{ExtensionContext, m365::*};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
#[derive(Default)]
struct Tokens(Mutex<Vec<bool>>);
#[async_trait]
impl TokenProvider for Tokens {
    async fn token(&self, refresh: bool, _: &ExtensionContext) -> Result<AccessToken, Error> {
        self.0.lock().unwrap().push(refresh);
        AccessToken::new(
            if refresh {
                "synthetic-new-token"
            } else {
                "synthetic-old-token"
            }
            .into(),
        )
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
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
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
            socket.write_all(reply.as_bytes()).await.unwrap();
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
fn listing(client: &ActivityClient) -> String {
    format!(
        "{}subscriptions/content?contentType={FEED}&startTime=2026-10-14T00%3A00%3A00Z&endTime=2026-10-14T01%3A00%3A00Z",
        client.root()
    )
}
#[tokio::test]
async fn native_http_refresh_throttle_outage_and_exact_response_capture() {
    let (origin, requests, worker) = server(vec![
        response(401, "", ""),
        response(429, "Retry-After: 0\r\n", ""),
        response(503, "", ""),
        response(200, "", "[ {\"opaque\":true} ]"),
    ])
    .await;
    let client = ActivityClient::local_fixture(&origin, Uuid::from_u128(1)).unwrap();
    let tokens = Tokens::default();
    let result = client
        .capture(&listing(&client), &tokens, &ctx())
        .await
        .unwrap();
    assert_eq!(result.original_bytes, b"[ {\"opaque\":true} ]");
    assert!(result.next_page_uri.is_none());
    worker.await.unwrap();
    assert_eq!(*tokens.0.lock().unwrap(), vec![false, true]);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].contains("Bearer synthetic-old-token"));
    assert!(
        requests[1..]
            .iter()
            .all(|r| r.contains("Bearer synthetic-new-token"))
    );
}
#[tokio::test]
async fn malicious_uri_refuses_before_token_or_network_and_feed_is_pinned() {
    let c = ActivityClient::local_fixture("http://127.0.0.1:9", Uuid::from_u128(1)).unwrap();
    let t = Tokens::default();
    for url in [
        "https://attacker.invalid/".to_owned(),
        format!(
            "{}subscriptions/content?contentType=Audit.Exchange",
            c.root()
        ),
        format!("{}../audit/id", c.root()),
        format!("{}audit/%2e%2e/id", c.root()),
        format!("{}audit/id#fragment", c.root()),
    ] {
        assert!(matches!(
            c.capture(&url, &t, &ctx()).await,
            Err(Error::Scope)
        ));
    }
    assert!(t.0.lock().unwrap().is_empty());
    assert!(ActivityClient::local_fixture("http://example.invalid", Uuid::from_u128(1)).is_err());
    assert!(ActivityClient::local_fixture("http://127.0.0.1:9", Uuid::nil()).is_err());
}
#[tokio::test]
async fn exhaustion_and_authentication_and_expired_content_never_return_success() {
    for (code, expected, count) in [
        (401, Error::Authentication, 2),
        (403, Error::Authentication, 1),
        (410, Error::Expired, 1),
        (429, Error::Unavailable, MAX_ATTEMPTS),
        (503, Error::Unavailable, MAX_ATTEMPTS),
    ] {
        let (origin, _, worker) =
            server(vec![response(code, "Retry-After: 0\r\n", ""); count]).await;
        let client = ActivityClient::local_fixture(&origin, Uuid::from_u128(1)).unwrap();
        assert!(
            matches!(client.capture(&listing(&client),&Tokens::default(),&ctx()).await,Err(e) if e==expected)
        );
        worker.await.unwrap();
    }
}
#[tokio::test]
async fn cancellation_and_original_deadline_stop_retry_without_token_leak() {
    let (origin, _, worker) = server(vec![response(429, "Retry-After: 60\r\n", "")]).await;
    let client = ActivityClient::local_fixture(&origin, Uuid::from_u128(1)).unwrap();
    let budget =
        ExtensionContext::new(CancellationToken::new(), Duration::from_millis(100)).unwrap();
    assert!(matches!(
        client
            .capture(&listing(&client), &Tokens::default(), &budget)
            .await,
        Err(Error::Timeout)
    ));
    worker.await.unwrap();
    let token = CancellationToken::new();
    token.cancel();
    let budget = ExtensionContext::new(token, Duration::from_secs(1)).unwrap();
    let tokens = Tokens::default();
    assert!(matches!(
        client.capture(&listing(&client), &tokens, &budget).await,
        Err(Error::Cancelled)
    ));
    assert!(tokens.0.lock().unwrap().is_empty());
    assert!(
        !Error::Authentication
            .to_string()
            .contains("synthetic-old-token")
    );
}
#[tokio::test]
async fn declared_body_limit_and_malicious_continuation_refuse_whole_response() {
    for headers in [
        format!("Content-Length: {}\r\n", MAX_BODY_BYTES + 1),
        "NextPageUri: https://attacker.invalid/page\r\n".into(),
    ] {
        let (origin, _, worker) = server(vec![format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\n"
        )])
        .await;
        let client = ActivityClient::local_fixture(&origin, Uuid::from_u128(1)).unwrap();
        assert!(
            client
                .capture(&listing(&client), &Tokens::default(), &ctx())
                .await
                .is_err()
        );
        worker.await.unwrap();
    }
}

use signal_collector_sdk::m365::page::{PageJournal, State, Window};
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
struct DiskJournal {
    path: PathBuf,
    lost_reply: AtomicBool,
    lock: Mutex<()>,
}
impl DiskJournal {
    fn read(&self) -> Result<Option<State>, Error> {
        match std::fs::read(&self.path) {
            Ok(raw) => {
                if raw.len() > 16 * 1024 * 1024 {
                    return Err(Error::Limit);
                }
                serde_json::from_slice(&raw)
                    .map(Some)
                    .map_err(|_| Error::Journal)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Journal),
        }
    }
}
#[async_trait]
impl PageJournal for DiskJournal {
    async fn load(&self, _: &ExtensionContext) -> Result<Option<State>, Error> {
        self.read()
    }
    async fn commit(&self, expected: u64, next: &State, _: &ExtensionContext) -> Result<(), Error> {
        let _guard = self.lock.lock().map_err(|_| Error::Journal)?;
        if self.read()?.as_ref().map_or(0, State::revision) != expected {
            return Err(Error::Conflict);
        }
        let temporary = self.path.with_extension("pending");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| Error::Journal)?;
        let raw = serde_json::to_vec(next).map_err(|_| Error::Journal)?;
        if raw.len() > 16 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        file.write_all(&raw).map_err(|_| Error::Journal)?;
        file.sync_all().map_err(|_| Error::Journal)?;
        std::fs::rename(temporary, &self.path).map_err(|_| Error::Journal)?;
        std::fs::File::open(self.path.parent().ok_or(Error::Journal)?)
            .map_err(|_| Error::Journal)?
            .sync_all()
            .map_err(|_| Error::Journal)?;
        if self.lost_reply.swap(false, Ordering::Relaxed) {
            return Err(Error::Journal);
        }
        Ok(())
    }
}
fn audit(id: u128, tenant: Uuid) -> serde_json::Value {
    serde_json::json!({"Id":Uuid::from_u128(id),"OrganizationId":tenant,"CreationTime":"2026-10-14T12:00:00",
        "RecordType":15,"Operation":"UserLoggedIn","UserType":0,"UserId":"synthetic-user","UserKey":"synthetic-key",
        "Workload":"AzureActiveDirectory","ClientIP":null,"ResultStatus":"Succeeded","LogonError":"synthetic-native-assertion"})
}
#[tokio::test]
async fn durable_paged_receipts_lost_commit_reply_restart_and_exact_dedup() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.json");
    let journal = DiskJournal {
        path: path.clone(),
        lost_reply: AtomicBool::new(true),
        lock: Mutex::new(()),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let tenant = Uuid::from_u128(1);
    let mut client = ActivityClient::local_fixture(&origin, tenant).unwrap();
    let now = chrono::Utc::now();
    let window = Window::new(
        "fixture-aad",
        now - chrono::Duration::hours(1),
        now + chrono::Duration::hours(1),
        Uuid::from_u128(2),
    )
    .unwrap();
    let mut first =
        reqwest::Url::parse(&format!("{}subscriptions/content", client.root())).unwrap();
    first
        .query_pairs_mut()
        .append_pair("contentType", FEED)
        .append_pair(
            "startTime",
            &(now - chrono::Duration::hours(1)).to_rfc3339(),
        )
        .append_pair("endTime", &(now + chrono::Duration::hours(1)).to_rfc3339())
        .append_pair("PublisherIdentifier", &Uuid::from_u128(2).to_string());
    let mut next = first.clone();
    next.query_pairs_mut()
        .append_pair("nextPage", "opaque-page-2");
    let metadata = |id: &str| serde_json::json!({"contentType":FEED,"contentId":id,"contentUri":format!("{}audit/{id}",client.root()),"contentCreated":now,"contentExpiration":now+chrono::Duration::hours(8)});
    let listing1 = serde_json::json!([metadata("first")]).to_string();
    let listing2 = serde_json::json!([metadata("first"), metadata("second")]).to_string();
    let body1 = serde_json::json!([audit(100, tenant)]).to_string();
    let body2 = serde_json::json!([audit(101, tenant)]).to_string();
    let replies = vec![
        response(401, "", ""),
        response(429, "Retry-After: 0\r\n", ""),
        response(200, &format!("NextPageUri: {next}\r\n"), &listing1),
        response(503, "", ""),
        response(200, "", &body1),
        response(200, "", &listing2),
        response(200, "", &body1),
        response(200, "", &body2),
    ];
    let worker = tokio::spawn(async move {
        for reply in replies {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            let mut block = [0; 1024];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut block))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && bytes.len() + n <= 16384);
                bytes.extend_from_slice(&block[..n]);
            }
            socket.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let tokens = Tokens::default();
    assert!(matches!(
        client.advance(&window, &tokens, &journal, &ctx()).await,
        Err(Error::Journal)
    ));
    let pinned = journal.read().unwrap().unwrap();
    assert_eq!(pinned.revision(), 1);
    assert_eq!(pinned.cursor(), Some(next.as_str()));
    let first_event = pinned.events().next().unwrap().clone();
    assert_eq!(pinned.pages()[0].original_listing(), listing1.as_bytes());
    assert_eq!(
        pinned.pages()[0].original_contents().next().unwrap().1,
        body1.as_bytes()
    );
    // A fresh journal object reloads only durable disk state; no in-memory cache.
    let restarted = DiskJournal {
        path: path.clone(),
        lost_reply: AtomicBool::new(false),
        lock: Mutex::new(()),
    };
    let complete = client
        .advance(&window, &tokens, &restarted, &ctx())
        .await
        .unwrap();
    worker.await.unwrap();
    assert!(complete.complete());
    assert_eq!(complete.depth(), (2, 2, 2));
    assert_eq!(
        complete.events().find(|e| e.id == first_event.id).unwrap(),
        &first_event
    );
    assert_eq!(complete.events().count(), 2);
    assert_eq!(
        *tokens.0.lock().unwrap(),
        vec![false, true, false, false, false, false]
    );
    let before = std::fs::read(&path).unwrap();
    let noop = client
        .advance(&window, &tokens, &restarted, &ctx())
        .await
        .unwrap();
    assert!(noop.complete());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let changed = Window::new(
        "other-route",
        now - chrono::Duration::hours(1),
        now + chrono::Duration::hours(1),
        Uuid::from_u128(2),
    )
    .unwrap();
    assert!(matches!(
        client.advance(&changed, &tokens, &restarted, &ctx()).await,
        Err(Error::Scope)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut corrupted: serde_json::Value = serde_json::from_slice(&before).unwrap();
    corrupted["events"][Uuid::from_u128(100).to_string()]["event"]["message"] =
        serde_json::json!("changed");
    std::fs::write(&path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
    assert!(matches!(
        client.advance(&window, &tokens, &restarted, &ctx()).await,
        Err(Error::Conflict)
    ));
}

async fn bounded_replies(listener: TcpListener, replies: Vec<String>) {
    for reply in replies {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        let mut block = [0; 1024];
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut block))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0 && bytes.len() + n <= 16384);
            bytes.extend_from_slice(&block[..n]);
        }
        tokio::time::timeout(Duration::from_secs(2), socket.write_all(reply.as_bytes()))
            .await
            .unwrap()
            .unwrap();
    }
}
fn page_url(client: &ActivityClient, now: chrono::DateTime<chrono::Utc>) -> reqwest::Url {
    let mut url = reqwest::Url::parse(&format!("{}subscriptions/content", client.root())).unwrap();
    url.query_pairs_mut()
        .append_pair("contentType", FEED)
        .append_pair(
            "startTime",
            &(now - chrono::Duration::hours(1)).to_rfc3339(),
        )
        .append_pair("endTime", &(now + chrono::Duration::hours(1)).to_rfc3339())
        .append_pair("PublisherIdentifier", &Uuid::from_u128(2).to_string());
    url
}
#[tokio::test]
async fn malformed_late_content_cycle_and_conflicting_ids_preserve_durable_cursor() {
    for scenario in [
        "cycle",
        "malformed",
        "content_conflict",
        "event_conflict",
        "tenant_conflict",
        "changed_window",
        "expired",
        "outside_window",
        "list_limit",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let journal = DiskJournal {
            path: temp.path().join("state.json"),
            lost_reply: AtomicBool::new(false),
            lock: Mutex::new(()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let tenant = Uuid::from_u128(1);
        let mut client = ActivityClient::local_fixture(&origin, tenant).unwrap();
        let now = chrono::Utc::now();
        let window = Window::new(
            "fixture-aad",
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(1),
            Uuid::from_u128(2),
        )
        .unwrap();
        let first = page_url(&client, now);
        let mut next = first.clone();
        next.query_pairs_mut().append_pair("nextPage", "second");
        let metadata = |id: &str| serde_json::json!({"contentType":FEED,"contentId":id,"contentUri":format!("{}audit/{id}",client.root()),"contentCreated":now,"contentExpiration":now+chrono::Duration::hours(8)});
        let list1 = serde_json::json!([metadata("first")]).to_string();
        let body1 = serde_json::json!([audit(100, tenant)]).to_string();
        let mut replies = vec![
            response(200, &format!("NextPageUri: {next}\r\n"), &list1),
            response(200, "", &body1),
        ];
        match scenario {
            "cycle" => replies.push(response(200, &format!("NextPageUri: {first}\r\n"), "[]")),
            "changed_window" => {
                let mut changed = next.clone();
                changed
                    .query_pairs_mut()
                    .append_pair("startTime", "2000-01-01T00:00:00Z");
                replies.push(response(200, &format!("NextPageUri: {changed}\r\n"), "[]"));
            }
            "expired" | "outside_window" | "list_limit" => {
                let mut meta = metadata("new");
                if scenario == "expired" {
                    meta["contentExpiration"] =
                        serde_json::json!(now - chrono::Duration::minutes(1));
                    meta["contentCreated"] = serde_json::json!(now - chrono::Duration::minutes(2));
                }
                if scenario == "outside_window" {
                    meta["contentCreated"] = serde_json::json!(now - chrono::Duration::hours(2));
                }
                let count = if scenario == "list_limit" { 65 } else { 1 };
                replies.push(response(
                    200,
                    "",
                    &serde_json::to_string(&vec![meta; count]).unwrap(),
                ));
            }
            _ => {
                let id = if scenario == "content_conflict" {
                    "first"
                } else {
                    "new"
                };
                replies.push(response(
                    200,
                    "",
                    &serde_json::json!([metadata(id)]).to_string(),
                ));
                let mut row = audit(100, tenant);
                row["Operation"] = serde_json::json!("changed");
                if scenario == "tenant_conflict" {
                    row["OrganizationId"] = serde_json::json!(Uuid::from_u128(99));
                }
                let body = if scenario == "malformed" {
                    format!("[{},{{]", audit(101, tenant))
                } else {
                    serde_json::json!([row]).to_string()
                };
                replies.push(response(200, "", &body));
            }
        }
        let worker = tokio::spawn(bounded_replies(listener, replies));
        client
            .advance(&window, &Tokens::default(), &journal, &ctx())
            .await
            .unwrap();
        let before = std::fs::read(&journal.path).unwrap();
        assert!(
            client
                .advance(&window, &Tokens::default(), &journal, &ctx())
                .await
                .is_err(),
            "{scenario}"
        );
        worker.await.unwrap();
        assert_eq!(std::fs::read(&journal.path).unwrap(), before, "{scenario}");
        assert_eq!(journal.read().unwrap().unwrap().revision(), 1);
    }
}
#[tokio::test]
async fn m365_disk_receipt_child_process() {
    let Some(config) = std::env::var_os("SIGNAL_OWNED_M365_CHILD_CONFIG") else {
        return;
    };
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(config).unwrap()).unwrap();
    let now: chrono::DateTime<chrono::Utc> = data["now"].as_str().unwrap().parse().unwrap();
    let mut client =
        ActivityClient::local_fixture(data["origin"].as_str().unwrap(), Uuid::from_u128(1))
            .unwrap();
    let window = Window::new(
        "fixture-aad",
        now - chrono::Duration::hours(1),
        now + chrono::Duration::hours(1),
        Uuid::from_u128(2),
    )
    .unwrap();
    let journal = DiskJournal {
        path: PathBuf::from(data["state"].as_str().unwrap()),
        lost_reply: AtomicBool::new(false),
        lock: Mutex::new(()),
    };
    let state = client
        .advance(&window, &Tokens::default(), &journal, &ctx())
        .await
        .unwrap();
    assert_eq!(state.revision(), 1);
    std::fs::write(
        data["ready"].as_str().unwrap(),
        b"durable receipt committed",
    )
    .unwrap();
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
async fn physical_child_sigkill_reloads_receipt_before_following_next_page() {
    use std::os::unix::process::ExitStatusExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.json");
    let ready = temp.path().join("ready");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut client = ActivityClient::local_fixture(&origin, Uuid::from_u128(1)).unwrap();
    let now = chrono::Utc::now();
    let window = Window::new(
        "fixture-aad",
        now - chrono::Duration::hours(1),
        now + chrono::Duration::hours(1),
        Uuid::from_u128(2),
    )
    .unwrap();
    let mut next = page_url(&client, now);
    next.query_pairs_mut()
        .append_pair("nextPage", "after-crash");
    let metadata = serde_json::json!({"contentType":FEED,"contentId":"first","contentUri":format!("{}audit/first",client.root()),"contentCreated":now,"contentExpiration":now+chrono::Duration::hours(8)});
    let worker = tokio::spawn(bounded_replies(
        listener,
        vec![
            response(
                200,
                &format!("NextPageUri: {next}\r\n"),
                &serde_json::json!([metadata]).to_string(),
            ),
            response(
                200,
                "",
                &serde_json::json!([audit(100, Uuid::from_u128(1))]).to_string(),
            ),
            response(200, "", "[]"),
        ],
    ));
    let config = temp.path().join("child.json");
    std::fs::write(
        &config,
        serde_json::to_vec(
            &serde_json::json!({"origin":origin,"now":now,"state":path,"ready":ready}),
        )
        .unwrap(),
    )
    .unwrap();
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "m365_disk_receipt_child_process", "--nocapture"])
            .env("SIGNAL_OWNED_M365_CHILD_CONFIG", &config)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !ready.is_file() {
        if child.0.try_wait().unwrap().is_some() || tokio::time::Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            panic!("owned child failed before durable receipt marker");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(child.0.try_wait().unwrap().is_none());
    let journal = DiskJournal {
        path,
        lost_reply: AtomicBool::new(false),
        lock: Mutex::new(()),
    };
    let original = journal
        .read()
        .unwrap()
        .unwrap()
        .events()
        .next()
        .unwrap()
        .clone();
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    let complete = client
        .advance(&window, &Tokens::default(), &journal, &ctx())
        .await
        .unwrap();
    worker.await.unwrap();
    assert!(complete.complete());
    assert_eq!(complete.events().next().unwrap(), &original);
    assert_eq!(complete.pages().len(), 2);
}

#[tokio::test]
async fn request_admission_is_single_slot_and_dropped_capture_is_counted() {
    struct Held;
    #[async_trait]
    impl TokenProvider for Held {
        async fn token(&self, _: bool, _: &ExtensionContext) -> Result<AccessToken, Error> {
            std::future::pending().await
        }
    }
    let client = ActivityClient::local_fixture("http://127.0.0.1:9", Uuid::from_u128(1)).unwrap();
    let uri = listing(&client);
    let budget = ctx();
    let mut pending = Box::pin(client.capture(&uri, &Held, &budget));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(client.metrics(), (1, 1, 0));
    assert!(matches!(
        client.capture(&uri, &Tokens::default(), &ctx()).await,
        Err(Error::Busy)
    ));
    assert_eq!(client.metrics(), (1, 1, 1));
    drop(pending);
    assert_eq!(client.metrics(), (0, 1, 2));
}

#[tokio::test]
async fn documented_v1_continuation_without_publisher_preserves_cursor_and_private_request_binding()
{
    let temp = tempfile::tempdir().unwrap();
    let journal = DiskJournal {
        path: temp.path().join("state.json"),
        lost_reply: AtomicBool::new(false),
        lock: Mutex::new(()),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let mut client = ActivityClient::local_fixture(&origin, Uuid::from_u128(1)).unwrap();
    let day = chrono::Utc::now().date_naive();
    let start = day.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end = start + chrono::Duration::days(1);
    let window = Window::new("fixture-aad", start, end, Uuid::from_u128(2)).unwrap();
    let next = format!(
        "{origin}/api/v1/{}/activity/feed/subscriptions/content?contentType={FEED}&startTime={}&endTime={}&nextPage=opaque",
        Uuid::from_u128(1),
        day,
        end.date_naive()
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let requests = captured.clone();
    let link = next.clone();
    let worker = tokio::spawn(async move {
        for reply in [
            response(200, &format!("NextPageUri: {link}\r\n"), "[]"),
            response(200, "", "[]"),
        ] {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            let mut block = [0; 1024];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut block))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && bytes.len() + n <= 16384);
                bytes.extend_from_slice(&block[..n]);
            }
            requests
                .lock()
                .unwrap()
                .push(String::from_utf8(bytes).unwrap());
            tokio::time::timeout(Duration::from_secs(2), socket.write_all(reply.as_bytes()))
                .await
                .unwrap()
                .unwrap();
        }
    });
    let first = client
        .advance(&window, &Tokens::default(), &journal, &ctx())
        .await
        .unwrap();
    assert_eq!(first.cursor(), Some(next.as_str()));
    let complete = client
        .advance(&window, &Tokens::default(), &journal, &ctx())
        .await
        .unwrap();
    worker.await.unwrap();
    assert!(complete.complete());
    assert_eq!(complete.pages()[1].request_uri(), next);
    assert!(
        complete.pages()[1]
            .actual_request_uri()
            .contains("PublisherIdentifier=00000000-0000-0000-0000-000000000002")
    );
    assert!(captured.lock().unwrap()[1].starts_with("GET /api/v1/"));
    assert!(
        captured.lock().unwrap()[1]
            .contains("PublisherIdentifier=00000000-0000-0000-0000-000000000002")
    );
    assert!(
        client
            .validate_uri(&format!(
                "{origin}/api/v1/{}/activity/feed/audit/id",
                Uuid::from_u128(1)
            ))
            .is_err()
    );
    assert!(
        client
            .validate_uri(&format!(
                "{origin}/api/v1/{}/activity/feed/subscriptions/content?contentType={FEED}",
                Uuid::from_u128(99)
            ))
            .is_err()
    );
}
