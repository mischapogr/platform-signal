//! Shell-free HTTP health probe with one absolute two-second I/O deadline.
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    process::ExitCode,
    time::{Duration, Instant},
};

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe deadline expired"))
}

fn probe(address: SocketAddr, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut connection = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let mut written = 0;
    while written < request.len() {
        connection.set_write_timeout(Some(remaining(deadline)?))?;
        let count = connection.write(&request[written..])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "probe write failed",
            ));
        }
        written += count;
    }
    let mut response = [0u8; 128];
    let mut used = 0;
    while used < response.len() {
        connection.set_read_timeout(Some(remaining(deadline)?))?;
        let count = connection.read(&mut response[used..])?;
        if count == 0 {
            break;
        }
        used += count;
        if let Some(end) = response[..used].iter().position(|byte| *byte == b'\n') {
            let line = &response[..=end];
            if line.ends_with(b"\r\n")
                && (line.starts_with(b"HTTP/1.1 200 ") || line.starts_with(b"HTTP/1.0 200 "))
            {
                return Ok(());
            }
            break;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unhealthy response",
    ))
}

fn main() -> ExitCode {
    // Numeric addresses avoid unbounded DNS lookup. Never print endpoint values,
    // response bytes or environment diagnostics into Docker healthcheck logs.
    let selected = match std::env::var("SIGNAL_HEALTHCHECK_ADDR") {
        Ok(address) => address,
        Err(std::env::VarError::NotPresent) => "127.0.0.1:8080".into(),
        Err(_) => return ExitCode::FAILURE,
    };
    if selected.len() > 128 {
        return ExitCode::FAILURE;
    }
    match selected.parse::<SocketAddr>() {
        Ok(address) if probe(address, Duration::from_secs(2)).is_ok() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn healthy_and_malformed_status_are_distinguished() -> io::Result<()> {
        for (response, healthy) in [
            (&b"HTTP/1.1 200 OK\r\n\r\n"[..], true),
            (&b"HTTP/1.1 503 Unavailable\r\n\r\n"[..], false),
            (&b"HTTP/1.1 200 OK\n"[..], false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let server = std::thread::spawn(move || -> io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                let mut request = [0u8; 128];
                stream.read(&mut request)?;
                stream.write_all(response)
            });
            assert_eq!(probe(address, Duration::from_secs(1)).is_ok(), healthy);
            server
                .join()
                .map_err(|_| io::Error::other("test worker failed"))??;
        }
        Ok(())
    }

    #[test]
    fn trickled_response_cannot_extend_absolute_deadline() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
            stream.set_write_timeout(Some(Duration::from_secs(1)))?;
            let mut request = [0u8; 128];
            stream.read(&mut request)?;
            for byte in b"HTTP/1.1 200 OK\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Ok(())
        });
        let started = Instant::now();
        assert!(probe(address, Duration::from_millis(100)).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server
            .join()
            .map_err(|_| io::Error::other("test worker failed"))??;
        Ok(())
    }
}
