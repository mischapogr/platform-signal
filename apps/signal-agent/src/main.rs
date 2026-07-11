//! Edge collector executable.
use signal_agent::{config::AgentConfig, runtime};
use std::{io::Write, process::ExitCode, time::Duration};
use tokio_util::sync::CancellationToken;

const HELP: &str = "signal-agent --server URL [--stdin | --file PATH ...] [--once]\n\
  --healthcheck | --readycheck  Quiet local probe; SIGNAL_HEALTHCHECK_ADDR and SIGNAL_PROBE_TLS_CONFIG\n\
  --spool-dir PATH          Dedicated durable spool (default data/agent-spool)\n\
  --format auto|plain|json  JSON objects become attributes; plain lines become messages\n\
  --source-type TYPE        Source type (default log)\n\
  --source-name NAME        Optional source name\n\
  --batch-events N          Maximum batch events (default 100)\n\
  --batch-bytes N           Maximum HTTP body bytes (default 1048576)\n\
  --flush-ms N              Batch coalescing interval (default 1000)\n\
  --request-timeout-ms N    HTTP deadline (default 5000)\n\
  --retry-base-ms N         Initial jittered retry delay (default 100)\n\
  --retry-max-ms N          Retry delay cap (default 5000)\n\
  --shutdown-timeout-ms N   Drain deadline (default 10000)\n\
  --max-spool-bytes N       Spool disk limit (default 67108864)\n\
  --max-spool-events N      Spool record limit (default 10000)\n\
  --max-line-bytes N        Input line limit (default 65536)\n\
  --max-event-bytes N       Canonical event JSON limit (default 65536)\n\
  --metrics-listen ADDRESS  Optional bounded metrics listener\n\
API token: SIGNAL_AGENT_API_TOKEN only. Optional private mTLS: SIGNAL_AGENT_TLS_CONFIG.\n\
Flags override matching SIGNAL_AGENT_*\n\
environment settings. Files follow until SIGTERM unless --once.\n";

fn bounded_stderr(message: String) {
    // One bounded final record; a stalled sink never blocks Tokio or exit.
    let (done, wait) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("signal-agent-log".into())
        .spawn(move || {
            let _ = std::io::stderr().write_all(message.as_bytes());
            let _ = done.send(());
        })
        .is_ok()
    {
        let _ = wait.recv_timeout(Duration::from_millis(250));
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version") {
        println!("signal-agent {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args
        .iter()
        .any(|a| matches!(a.as_str(), "--healthcheck" | "--readycheck"))
    {
        if args.len() != 1 {
            return ExitCode::FAILURE;
        }
        return if signal_agent::probe::from_env(args[0] == "--readycheck").is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    let config = match AgentConfig::parse(args) {
        Ok(config) => config,
        Err(error) => {
            bounded_stderr(format!("{{\"level\":\"error\",\"message\":\"{error}\"}}\n"));
            return ExitCode::FAILURE;
        }
    };
    let executor = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            bounded_stderr(
                "{\"level\":\"error\",\"message\":\"runtime initialization failed\"}\n".into(),
            );
            return ExitCode::FAILURE;
        }
    };
    let result = executor.block_on(async {
        let stopping = CancellationToken::new();
        let signal_stop = stopping.clone();
        let signals = tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut term) => {
                    tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
            signal_stop.cancel();
        });
        let result = runtime::run(config, stopping).await;
        signals.abort();
        result
    });
    drop(executor);
    match result {
        Ok(report) => {
            bounded_stderr(format!(
                "{{\"level\":\"info\",\"accepted\":{},\"rejected\":{},\"retries\":{},\"pending\":{}}}\n",
                report.accepted, report.rejected, report.retries, report.pending
            ));
            ExitCode::SUCCESS
        }
        Err(error) => {
            bounded_stderr(format!("{{\"level\":\"error\",\"message\":\"{error}\"}}\n"));
            ExitCode::FAILURE
        }
    }
}
