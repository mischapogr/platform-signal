//! Finite permission probe: never reads secret bytes or writes through an opened handle.
use std::{fs::{self, File, OpenOptions}, os::unix::fs::MetadataExt, process::{Command, Stdio}, time::{Duration, Instant}};
unsafe extern "C" { fn kill(pid: i32, signal: i32) -> i32; }
fn print_identity(status: &str) {
    for (n, field) in ["Uid", "Gid", "Groups", "CapEff", "NoNewPrivs"].iter().enumerate() {
        let value = status.lines().find_map(|line| line.strip_prefix(&format!("{field}:"))).unwrap().trim();
        if n != 0 { print!(","); }
        if *field == "CapEff" { print!("\"{field}\":\"{value}\""); }
        else { print!("\"{field}\":[{}]", value.split_whitespace().collect::<Vec<_>>().join(",")); }
    }
}
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "hold" { std::thread::sleep(Duration::from_secs(170)); return; }
    let mut server = if mode == "receiver-process" {
        let mut child = Command::new("/server").args(["--audit-receiver", "--config", "/restricted/config"])
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        if child.try_wait().unwrap().is_some() { std::process::exit(2); }
        Some(child)
    } else { None };
    let status = fs::read_to_string(server.as_ref().map_or_else(|| "/proc/self/status".to_owned(), |child| format!("/proc/{}/status", child.id()))).unwrap();
    print!("{{\"identity\":{{");
    print_identity(&status);
    print!("}},\"pid1_identity\":{{");
    print_identity(&fs::read_to_string("/proc/1/status").unwrap());
    print!("}},\"results\":[");
    let root = fs::metadata("/restricted/root").unwrap();
    let files = [("control", "/restricted/root/control"), ("journal", "/restricted/root/journal"), ("config", "/restricted/config"), ("key", "/restricted/key"), ("secret", "/restricted/secret")];
    let errno = |result: std::io::Result<()>| result.err().map_or(0, |e| e.raw_os_error().unwrap_or(-1));
    print!("{{\"name\":\"root-list\",\"errno\":{}}}", errno(fs::read_dir("/restricted/root").map(|_| ())));
    for (name, path) in files {
        let read = errno(File::open(path).map(|_| ()));
        let write = errno(OpenOptions::new().write(true).append(true).open(path).map(|_| ()));
        print!(",{{\"name\":\"{name}-read\",\"errno\":{read}}},{{\"name\":\"{name}-write\",\"errno\":{write}}}");
    }
    if mode == "deny" {
        let result = OpenOptions::new().write(true).create_new(true).open("/restricted/root/permission-probe-unused");
        print!(",{{\"name\":\"root-create\",\"errno\":{}}}", errno(result.map(|_| ())));
    }
    println!("],\"root_owner\":{},\"root_mode\":{},\"root_inode\":{}}}", root.uid(), root.mode() & 0o777, root.ino());
    if let Some(child) = server.as_mut() {
        // This one explicitly owned child has no subprocess descendants.
        unsafe { kill(child.id() as i32, 15); }
        let deadline = Instant::now() + Duration::from_secs(2);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline { std::thread::sleep(Duration::from_millis(10)); }
        if child.try_wait().unwrap().is_none() { child.kill().unwrap(); child.wait().unwrap(); std::process::exit(3); }
    }
}
