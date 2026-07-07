//! Owned real-server lifecycle, finite polling and cleanup on any failure.
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub struct Server {
    pub root: PathBuf,
    pub url: String,
    child: Option<Child>,
    generation: u64,
}
impl Server {
    pub fn new(root: &Path) -> TestResult<Self> {
        fs::create_dir_all(root.join("rules"))?;
        fs::write(
            root.join("rules/root.yaml"),
            "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: fixture.root-activity\n  name: Synthetic root activity\nspec:\n  severity: high\n  match:\n    all:\n      - field: source.type\n        eq: cloudtrail\n      - field: attributes.security.actor_kind\n        eq: Root\n  finding:\n    title: Synthetic root activity\n",
        )?;
        Ok(Self {
            root: root.into(),
            url: String::new(),
            child: None,
            generation: 0,
        })
    }
    pub async fn start(&mut self) -> TestResult<()> {
        if self.child.is_some() {
            return Err("already running".into());
        }
        self.generation += 1;
        let log = self.root.join(format!("server-{}.log", self.generation));
        let output = fs::File::create(&log)?;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_signal-server"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SIGNAL_") {
                cmd.env_remove(key);
            }
        }
        cmd.env("SIGNAL_LISTEN", "127.0.0.1:0")
            .env("SIGNAL_API_TOKEN", INGEST_TOKEN)
            .env("SIGNAL_WAL_DIR", self.root.join("wal"))
            .env("SIGNAL_STORAGE_DIR", self.root.join("events"))
            .env("SIGNAL_FINDINGS_DIR", self.root.join("findings"))
            .env("SIGNAL_RULE_DIRS", self.root.join("rules"))
            .env("SIGNAL_STORAGE_BATCH_EVENTS", "10")
            .env("SIGNAL_STORAGE_FLUSH_MS", "500")
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output);
        self.child = Some(cmd.spawn()?);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            if self.child.as_mut().ok_or("child")?.try_wait()?.is_some() {
                return Err("server startup failed".into());
            }
            let data = fs::read(&log)?;
            if data.len() > 1024 * 1024 {
                return Err("startup log cap".into());
            }
            for line in String::from_utf8_lossy(&data).lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line)
                    && let Some(address) = v["fields"]["listen"].as_str()
                {
                    self.url = format!("http://{address}");
                    if source::client()?
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
        Err("server startup deadline".into())
    }
    pub async fn wait_failed(&mut self) -> TestResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            if let Some(status) = self.child.as_mut().ok_or("child")?.try_wait()? {
                self.child.take();
                if status.success() {
                    return Err("expected consumer failure".into());
                }
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("server failure deadline".into())
    }
    pub fn crash(&mut self) -> TestResult<()> {
        let mut child = self.child.take().ok_or("child")?;
        child.kill()?;
        child.wait()?;
        Ok(())
    }
    pub fn checkpoint(&self) -> TestResult<u64> {
        let raw = std::fs::read(self.root.join("wal/checkpoint"))?;
        if raw.len() != 28 || &raw[..8] != b"SIGACK01" {
            return Err("checkpoint shape".into());
        }
        Ok(u64::from_le_bytes(raw[8..16].try_into()?))
    }
    pub async fn rows(&self, name: &str) -> TestResult<Vec<Value>> {
        let r = source::client()?
            .get(format!("{}/v1/{name}", self.url))
            .bearer_auth(INGEST_TOKEN)
            .send()
            .await?;
        if r.status() != 200 {
            return Err("query unavailable".into());
        }
        let v: Value = serde_json::from_slice(&source::body(r, 1024 * 1024).await?)?;
        Ok(v[name].as_array().ok_or("rows")?.clone())
    }
    pub async fn persisted(&self, event_count: usize, checkpoint: u64) -> TestResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            if self.rows("events").await?.len() == event_count
                && self.rows("findings").await?.len() == 1
                && self.checkpoint()? == checkpoint
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err("persistence deadline".into())
    }
    pub fn assert_redacted(&self) -> TestResult<()> {
        for n in 1..=self.generation {
            let s = std::fs::read_to_string(self.root.join(format!("server-{n}.log")))?;
            assert!(!s.contains(INGEST_TOKEN));
            assert!(!s.contains("ephemeral-private-handle"));
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
