//! Replace this process with the bounded shared HTTP/mTLS probe; no shell or child.
use std::{
    os::unix::process::CommandExt,
    process::{Command, ExitCode, Stdio},
};

fn main() -> ExitCode {
    let _error = Command::new("/usr/local/bin/signal-agent")
        .arg("--healthcheck")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec();
    ExitCode::FAILURE
}
