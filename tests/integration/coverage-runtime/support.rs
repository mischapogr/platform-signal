//! Owned local process and finite HTTP helpers. No external source/production credentials.
use super::*;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
pub const TOKEN: &str = "synthetic-coverage-supervision-token";
pub struct Server {
    pub root: PathBuf,
    pub url: String,
    child: Option<Child>,
    generation: usize,
}
impl Server {
    pub async fn new(root: &Path) -> TestResult<Self> {
        std::fs::create_dir_all(root)?;
        let f = fixture()?;
        let c = signal_coverage::CoverageConfig::default();
        let config = json!({"schema_version":1,"directory":root.join("coverage").to_str().ok_or("path")?,
            "limits":{"max_payloads":c.max_payloads,"max_identities":c.max_identities,"max_bindings":c.max_bindings,"max_ledger_bytes":c.max_ledger_bytes,
                "max_database_pages":c.max_database_pages,"max_journal_bytes":c.max_journal_bytes,"operation_capacity":c.operation_capacity,
                "transient_memory_bytes":c.transient_memory_bytes,"worker_memory_bytes":c.worker_memory_bytes,"max_vm_steps":c.max_vm_steps,"operation_timeout_ms":1000},
            "scopes":[{"binding_json":serde_json::to_string(&f["bindings"][0]["input"])?,"profile_json":serde_json::to_string(&f["profiles"][0]["input"])?,
                "authority_revision":"synthetic-runtime-authority","token_env":"COVERAGE_SIM_TOKEN","max_report_age_seconds":60,"max_clock_skew_seconds":2,
                "payload_retention_seconds":300,"identity_retention_seconds":600}]});
        std::fs::write(root.join("coverage.json"), serde_json::to_vec(&config)?)?;
        let mut s = Self {
            root: root.into(),
            url: String::new(),
            child: None,
            generation: 0,
        };
        let log = root.join("runtime-bootstrap.log");
        let output = std::fs::File::create(&log)?;
        s.child = Some(
            s.command()
                .arg("--initialize-coverage")
                .stdin(Stdio::null())
                .stdout(output.try_clone()?)
                .stderr(output)
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = s.child.as_mut().ok_or("bootstrap child")?.try_wait()? {
                s.child.take();
                if !status.success() {
                    return Err("coverage bootstrap failed".into());
                }
                break;
            }
            if std::fs::metadata(&log)?.len() > 65_536 {
                return Err("bootstrap log capacity".into());
            }
            if Instant::now() >= deadline {
                return Err("coverage bootstrap deadline; owner kills and reaps child".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut bytes = Vec::new();
        std::fs::File::open(log)?
            .take(65_537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err("bootstrap log capacity".into());
        }
        assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
        Ok(s)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_signal-server"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SIGNAL_") {
                cmd.env_remove(key);
            }
        }
        cmd.env("SIGNAL_LISTEN", "127.0.0.1:0")
            .env("SIGNAL_API_TOKEN", "separate-synthetic-event-token")
            .env("SIGNAL_COVERAGE_CONFIG", self.root.join("coverage.json"))
            .env("COVERAGE_SIM_TOKEN", TOKEN)
            .env("SIGNAL_WAL_DIR", self.root.join("wal"))
            .env("SIGNAL_STORAGE_DIR", self.root.join("events"))
            .env("SIGNAL_FINDINGS_DIR", self.root.join("findings"))
            .env("SIGNAL_STORAGE_FLUSH_MS", "10");
        cmd
    }
    pub async fn start(&mut self) -> TestResult {
        if self.child.is_some() {
            return Err("already running".into());
        }
        self.generation += 1;
        let log = self
            .root
            .join(format!("runtime-server-{}.log", self.generation));
        let output = std::fs::File::create(&log)?;
        self.child = Some(
            self.command()
                .stdout(Stdio::null())
                .stderr(output)
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.child.as_mut().ok_or("child")?.try_wait()?.is_some() {
                return Err("server startup failed".into());
            }
            let mut data = Vec::new();
            std::fs::File::open(&log)?
                .take(1_048_577)
                .read_to_end(&mut data)?;
            if data.len() > 1_048_576 {
                return Err("log capacity".into());
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
    pub fn crash(&mut self) -> TestResult {
        let mut child = self.child.take().ok_or("child")?;
        child.kill()?;
        child.wait()?;
        Ok(())
    }
    pub async fn record(&self, id: &str) -> TestResult<Value> {
        self.get(&format!("/v1/coverage/records/{id}")).await
    }
    pub async fn get(&self, path: &str) -> TestResult<Value> {
        let reply = client()?
            .get(format!("{}{path}", self.url))
            .bearer_auth(TOKEN)
            .send()
            .await?;
        if reply.status() != 200 {
            return Err("history read failed".into());
        }
        Ok(serde_json::from_slice(&body(reply, 524_288).await?)?)
    }
    pub fn redacted(&self) -> TestResult {
        for n in 1..=self.generation {
            let log = std::fs::read_to_string(self.root.join(format!("runtime-server-{n}.log")))?;
            assert!(!log.contains(TOKEN));
            assert!(!log.contains("source-probe-private-token"));
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
pub fn client() -> TestResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_millis(500))
        .pool_max_idle_per_host(0)
        .build()?)
}
pub async fn body(mut response: reqwest::Response, limit: usize) -> TestResult<Vec<u8>> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err("body capacity".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err("body capacity".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
