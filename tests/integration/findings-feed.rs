//! Actual monolith append feed, SIGKILL/reopen, late records and divergent restore.
use serde_json::{Value, json};
use signal_protocol::findings_feed::FindingsCursor;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TOKEN: &str = "synthetic-findings-feed-token";
fn client() -> TestResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(0)
        .build()?)
}
async fn body(mut response: reqwest::Response) -> TestResult<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > 65536usize.saturating_sub(out.len()) {
            return Err("reply cap".into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
struct Server {
    root: PathBuf,
    url: String,
    child: Option<Child>,
    generation: usize,
    budget: usize,
}
impl Server {
    fn new(root: &Path) -> TestResult<Self> {
        std::fs::create_dir_all(root.join("rules"))?;
        std::fs::write(
            root.join("rules/generic.yaml"),
            "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: fixture.feed\n  name: Synthetic feed finding\nspec:\n  severity: high\n  match:\n    all:\n      - field: source.type\n        eq: generic\n  finding:\n    title: Synthetic feed finding\n",
        )?;
        Ok(Self {
            root: root.into(),
            url: String::new(),
            child: None,
            generation: 0,
            budget: 8 * 1024 * 1024,
        })
    }
    async fn start(&mut self) -> TestResult {
        if self.child.is_some() {
            return Err("already running".into());
        }
        self.generation += 1;
        let log = self
            .root
            .join(format!("feed-server-{}.log", self.generation));
        let output = std::fs::File::create(&log)?;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_signal-server"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SIGNAL_") {
                cmd.env_remove(key);
            }
        }
        cmd.env("SIGNAL_LISTEN", "127.0.0.1:0")
            .env("SIGNAL_API_TOKEN", TOKEN)
            .env("SIGNAL_WAL_DIR", self.root.join("wal"))
            .env("SIGNAL_STORAGE_DIR", self.root.join("events"))
            .env("SIGNAL_FINDINGS_DIR", self.root.join("findings"))
            .env("SIGNAL_RULE_DIRS", self.root.join("rules"))
            .env("SIGNAL_STORAGE_FLUSH_MS", "10")
            .env("SIGNAL_FINDINGS_QUERY_BYTES", self.budget.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(output);
        self.child = Some(cmd.spawn()?);
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.child.as_mut().ok_or("child")?.try_wait()?.is_some() {
                return Err("server rejected startup".into());
            }
            let mut data = Vec::new();
            std::fs::File::open(&log)?
                .take(1_048_577)
                .read_to_end(&mut data)?;
            if data.len() > 1_048_576 {
                return Err("log cap".into());
            }
            for line in String::from_utf8_lossy(&data).lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line)
                    && let Some(address) = v["fields"]["listen"].as_str()
                {
                    self.url = format!("http://{address}");
                    if client()?
                        .get(format!("{}/readyz", self.url))
                        .send()
                        .await?
                        .status()
                        == 200
                    {
                        return Ok(());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("startup deadline".into())
    }
    fn crash(&mut self) -> TestResult {
        let mut child = self.child.take().ok_or("child")?;
        child.kill()?;
        child.wait()?;
        Ok(())
    }
    async fn request(&self, path: &str) -> TestResult<(u16, Value)> {
        let response = client()?
            .get(format!("{}{path}", self.url))
            .bearer_auth(TOKEN)
            .send()
            .await?;
        if path.starts_with("/v1/findings/feed") {
            assert_eq!(
                response
                    .headers()
                    .get("cache-control")
                    .and_then(|h| h.to_str().ok()),
                Some("no-store")
            );
        }
        let status = response.status().as_u16();
        Ok((status, serde_json::from_slice(&body(response).await?)?))
    }
    async fn page(&self, after: &str, limit: usize) -> TestResult<Value> {
        let (status, v) = self
            .request(&format!("/v1/findings/feed?after={after}&limit={limit}"))
            .await?;
        assert_eq!(status, 200);
        Ok(v)
    }
    async fn append(&self, n: u128, old: bool) -> TestResult {
        let event = json!({"schema_version":1,"id":Uuid::from_u128(n),"timestamp":"2026-10-08T12:00:00Z","observed_at":if old {"2020-01-01T00:00:00Z"} else {"2026-10-08T12:00:00Z"},"source":{"type":"generic"},"message":"synthetic feed evidence"});
        let response = client()?
            .post(format!("{}/v1/events", self.url))
            .bearer_auth(TOKEN)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&event)?)
            .send()
            .await?;
        assert_eq!(response.status().as_u16(), 202);
        let _ = body(response).await?;
        Ok(())
    }
    async fn wait_tail(&self, n: u64) -> TestResult<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let p = self.page("begin", 100).await?;
            if FindingsCursor::decode(cursor(&p)?)?.position() == n {
                return Ok(p);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("finding persistence deadline".into())
    }
    fn redacted(&self) -> TestResult {
        for n in 1..=self.generation {
            let mut data = Vec::new();
            std::fs::File::open(self.root.join(format!("feed-server-{n}.log")))?
                .take(1_048_577)
                .read_to_end(&mut data)?;
            assert!(data.len() <= 1_048_576);
            assert!(!String::from_utf8_lossy(&data).contains(TOKEN));
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn cursor(page: &Value) -> TestResult<&str> {
    Ok(page["next_cursor"].as_str().ok_or("cursor")?)
}
fn copy_tree(from: &Path, to: &Path, files: &mut usize, bytes: &mut u64) -> TestResult {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let m = entry.metadata()?;
        if entry.file_type()?.is_symlink() {
            return Err("backup symlink".into());
        }
        if m.is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()), files, bytes)?;
        } else if m.is_file() {
            *files += 1;
            *bytes += m.len();
            if *files > 64 || *bytes > 8 * 1024 * 1024 {
                return Err("backup fixture cap".into());
            }
            std::fs::copy(entry.path(), to.join(entry.file_name()))?;
        } else {
            return Err("backup file type".into());
        }
    }
    Ok(())
}
#[tokio::test]
async fn monolith_feed_cursor_survives_restart_and_rejects_divergent_restore() -> TestResult {
    let temp = tempfile::tempdir()?;
    let backup = tempfile::tempdir()?;
    let mut server = Server::new(temp.path())?;
    server.start().await?;
    let initial = server.page("begin", 1).await?;
    assert_eq!(initial["findings"], json!([]));
    server.append(1, false).await?;
    let first = server.wait_tail(1).await?;
    assert_eq!(server.page(cursor(&initial)?, 1).await?, first);
    server.crash()?;
    let mut count = 0;
    let mut bytes = 0;
    for path in ["wal", "events", "findings"] {
        copy_tree(
            &temp.path().join(path),
            &backup.path().join(path),
            &mut count,
            &mut bytes,
        )?;
    }
    server.start().await?;
    server.append(2, false).await?;
    let all = server.wait_tail(2).await?;
    let second = server.page(cursor(&first)?, 1).await?;
    assert_eq!(
        second["findings"][0]["event_ids"][0],
        Uuid::from_u128(2).to_string()
    );
    assert_eq!(cursor(&all)?, cursor(&second)?);
    // A lost page response is simply retried from the same saved prefix.
    assert_eq!(server.page(cursor(&first)?, 1).await?, second);
    server.crash()?;
    server.start().await?;
    assert_eq!(server.page(cursor(&first)?, 1).await?, second);
    server.append(3, true).await?;
    server.wait_tail(3).await?;
    let late = server.page(cursor(&second)?, 1).await?;
    assert_eq!(late["findings"][0]["created_at"], "2020-01-01T00:00:00Z");
    server.append(3, true).await?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let checkpoint = std::fs::read(temp.path().join("wal/checkpoint"))?;
        if checkpoint.len() == 28 && u64::from_le_bytes(checkpoint[8..16].try_into()?) == 4 {
            break;
        }
        if Instant::now() >= deadline {
            return Err("duplicate checkpoint deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(cursor(&server.wait_tail(3).await?)?, cursor(&late)?);
    let (_, list) = server.request("/v1/findings?limit=10").await?;
    assert_eq!(
        list["findings"][0]["event_ids"][0],
        Uuid::from_u128(3).to_string()
    );
    server.crash()?;
    // Restore the complete first-prefix backup, preserving the WAL/store stream.
    for path in ["wal", "events", "findings"] {
        std::fs::remove_dir_all(temp.path().join(path))?;
        copy_tree(
            &backup.path().join(path),
            &temp.path().join(path),
            &mut 0,
            &mut 0,
        )?;
    }
    server.start().await?;
    let (status, unavailable) = server
        .request(&format!("/v1/findings/feed?after={}", cursor(&second)?))
        .await?;
    assert_eq!(status, 409);
    assert_eq!(unavailable["error"]["code"], "cursor_position_unavailable");
    assert!(unavailable.get("next_cursor").is_none());
    server.append(4, false).await?;
    server.wait_tail(2).await?;
    let (status, divergent) = server
        .request(&format!("/v1/findings/feed?after={}", cursor(&second)?))
        .await?;
    assert_eq!(status, 409);
    assert_eq!(divergent["error"]["code"], "cursor_history_mismatch");
    assert!(divergent.get("next_cursor").is_none());
    let new = server.page(cursor(&first)?, 1).await?;
    assert_eq!(
        new["findings"][0]["event_ids"][0],
        Uuid::from_u128(4).to_string()
    );
    server.crash()?;
    server.redacted()?;
    Ok(())
}
#[tokio::test]
async fn monolith_rejects_unrepresentable_empty_feed_budget_before_ready() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut server = Server::new(temp.path())?;
    server.budget = 287;
    assert!(server.start().await.is_err());
    assert!(server.child.as_mut().ok_or("child")?.try_wait()?.is_some());
    server.redacted()?;
    Ok(())
}
