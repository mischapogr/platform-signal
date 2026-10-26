#!/usr/bin/env python3
"""Qualify the bounded owned-process native metadata source, not full D14."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "apps/signal-agent/native/runtime-metadata.c"
FIXTURE = ROOT / "tests/integration/runtime-read-fixture.c"
PROFILE = "linux-owned-syscall-metadata/v1"
SENTINEL = b"SYNTHETIC-CREDENTIAL-PAYLOAD-NEVER-CAPTURE-8347"
SOCKET_SENTINEL = b"SYNTHETIC-SOCKET-PAYLOAD-NEVER-CAPTURE-1926"
BASE = {"schema_version", "profile", "capture_id", "config_sha256", "host", "boot_id",
        "sequence", "timestamp_ns", "pid", "tid", "start_ticks", "clock_ticks",
        "mount_ns", "audit_arch", "execution_generation", "kind"}
OBJECT = {"fd", "object_type", "dev_major", "dev_minor", "inode", "mount_id",
          "ctime_sec", "ctime_nsec", "result", "error", "syscall_entry_ns", "syscall_exit_ns"}
FIELDS = {"exec": set(), "read": OBJECT | {"requested"},
          "connect": OBJECT | {"family", "address", "port", "scope_id"},
          "end": {"reason", "stops"}, "gap": {"reason", "stops"}}


def validate_records(raw, capture_id, config_hash):
    """Strict shape validation; these records do not authenticate themselves."""
    if len(raw) > 1024 * 1024 or not raw.endswith(b"\n"):
        raise ValueError("truncated or oversized capture")
    records = [json.loads(line) for line in raw.splitlines()]
    if not records or len(records) > 4096:
        raise ValueError("record bound")
    identity = None
    generation = 0
    for sequence, r in enumerate(records, 1):
        kind = r.get("kind")
        if kind not in FIELDS or set(r) != BASE | FIELDS[kind]:
            raise ValueError("unrecognized metadata fields")
        if r["schema_version"] != 1 or r["profile"] != PROFILE:
            raise ValueError("unsupported profile")
        if r["capture_id"] != capture_id or r["config_sha256"] != config_hash:
            raise ValueError("capture binding")
        if r["sequence"] != sequence:
            raise ValueError("source ordinal")
        current = tuple(r[x] for x in ("host", "boot_id", "pid", "tid", "start_ticks", "clock_ticks", "mount_ns", "audit_arch"))
        uuid.UUID(r["boot_id"])
        if identity is None:
            identity = current
        if current != identity or r["pid"] != r["tid"]:
            raise ValueError("process continuity")
        if kind == "exec":
            generation += 1
        if r["execution_generation"] != generation:
            raise ValueError("execution continuity")
        if kind in ("read", "connect") and generation == 0:
            raise ValueError("operation before execution")
        if kind in ("read", "connect"):
            if not 0 < r["syscall_entry_ns"] <= r["syscall_exit_ns"] <= r["timestamp_ns"]:
                raise ValueError("operation time interval")
            if type(r["error"]) is not bool or type(r["result"]) is not int:
                raise ValueError("result type")
            if r["error"] != (r["result"] < 0):
                raise ValueError("result/error conflict")
        if kind == "read" and not r["error"] and r["result"] > r["requested"]:
            raise ValueError("impossible read length")
        if kind in ("gap", "end") and sequence != len(records):
            raise ValueError("record after terminal")
    if records[-1]["kind"] not in ("gap", "end"):
        raise ValueError("missing terminal record")
    for forbidden in (SENTINEL, SOCKET_SENTINEL, b"SYNTHETIC-STDOUT-PAYLOAD", b"SYNTHETIC-STDERR-PAYLOAD"):
        if forbidden in raw:
            raise ValueError("payload entered metadata")
    return records


def file_reads(records, inode):
    return [r for r in records if r["kind"] == "read" and r["inode"] == inode
            and r["object_type"] == stat.S_IFREG]


def capture_case(binary, fixture, path, mode, config_hash, timeout=10000, cancel=False, evidence=None):
    family = socket.AF_INET6 if mode == "ipv6" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        port = server.getsockname()[1]
        if mode != "badconnect":
            server.listen(1)
        server.settimeout(0.1)
        done = threading.Event()
        errors = []

        def serve():
            while not done.is_set():
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with connection:
                    if mode == "socket":
                        try:
                            connection.sendall(SOCKET_SENTINEL)
                        except OSError as exc:
                            errors.append(str(exc))
                return

        thread = threading.Thread(target=serve)
        if mode != "badconnect":
            thread.start()
        capture_id = str(uuid.uuid4())
        command = [str(binary), capture_id, config_hash, "synthetic-owned-host", str(timeout),
                   "--", str(fixture), mode, str(path), str(port)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        try:
            if cancel:
                time.sleep(0.3)
                process.send_signal(signal.SIGTERM)
            raw, stderr = process.communicate(timeout=15)
        except BaseException:
            process.kill()
            process.communicate()
            raise
        finally:
            done.set()
            if thread.is_alive():
                thread.join(timeout=1)
            if thread.is_alive():
                raise AssertionError("fixture server thread not reaped")
        if evidence is not None:
            evidence.with_suffix(".raw.jsonl").write_bytes(raw)
            evidence.with_suffix(".process.json").write_text(json.dumps({
                "exit_code": process.returncode, "capture_id": capture_id,
                "config_sha256": config_hash, "stderr": stderr.decode(errors="replace"),
                "listener_errors": errors}, indent=2) + "\n")
        if stderr or errors:
            raise AssertionError((stderr, errors))
        records = validate_records(raw, capture_id, config_hash)
        # The collector has waitpid-reaped its exact PID before exit. Linux PID
        # reuse is checked via the recorded start time rather than PID alone.
        pid = records[-1]["pid"]
        proc = Path(f"/proc/{pid}/stat")
        if proc.exists():
            fields = proc.read_text().rsplit(")", 1)[1].split()
            if int(fields[19]) == records[-1]["start_ticks"]:
                raise AssertionError("owned tracee remains after collector exit")
        return process.returncode, records


def qualify(output):
    output.mkdir(parents=True, exist_ok=True)
    sources = (COLLECTOR, FIXTURE, Path(__file__).resolve(),
               ROOT / "scripts/test-runtime-read.py", ROOT / "docs/82-runtime-read-metadata.md")

    def source_hashes():
        return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}

    frozen = source_hashes()
    compiler_commands = []

    def compile_source(command, data=None):
        compiler_commands.append({"argv": command, "stdin_sha256": hashlib.sha256(data).hexdigest() if data else None})
        subprocess.run(command, input=data, check=True, timeout=30)

    binary = output / "runtime-metadata"
    fixture = output / "runtime-read-fixture"
    for source, destination in ((COLLECTOR, binary), (FIXTURE, fixture)):
        static = ["-static"] if source == FIXTURE else []
        compile_source(["cc", *static, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                        str(source), "-o", str(destination)])
    dynamic = output / "runtime-read-fixture-dynamic"
    compile_source(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                    str(FIXTURE), "-o", str(dynamic)])
    compat = None
    if os.uname().machine == "x86_64":
        # An actual Linux i386 ABI transition, without a 32-bit libc dependency.
        compat = output / "runtime-read-fixture-i386"
        compile_source(["cc", "-m32", "-nostdlib", "-static", "-x", "assembler", "-o", str(compat), "-"],
                       b".global _start\n_start:\nmov $1,%eax\nxor %ebx,%ebx\nint $0x80\n")
    binaries = [binary, fixture, dynamic, *([compat] if compat else [])]
    elf_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries}
    if source_hashes() != frozen:
        raise AssertionError("source drift during compilation")
    results = []
    with tempfile.TemporaryDirectory(prefix="signal-owned-read-") as folder:
        path = Path(folder) / "synthetic-input"
        path.write_bytes(SENTINEL)
        other = Path(str(path) + ".other")
        other.write_bytes(b"SYNTHETIC-UNPROTECTED-OTHER-FILE")
        inode, other_inode = path.stat().st_ino, other.stat().st_ino
        cases = ["read", "eof", "error", "fault", "open", "reuse", "rename", "execfail", "exec",
                 "socket", "badconnect", "ipv6", "output", "clone", "pread", "mmap",
                 "signal", "hang", "cancel", "dynamic"]
        if compat is not None:
            cases.append("compat")
        for mode in cases:
            executable = dynamic if mode == "dynamic" else compat if mode == "compat" else fixture
            code, records = capture_case(binary, executable, path, "hang" if mode == "cancel" else mode,
                                         frozen[str(COLLECTOR.relative_to(ROOT))],
                                         timeout=500 if mode == "hang" else 10000,
                                         cancel=mode == "cancel", evidence=output / mode)
            (output / f"{mode}.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
            reads = file_reads(records, inode)
            connects = [r for r in records if r["kind"] == "connect"]
            if mode in ("clone", "pread", "mmap", "signal", "hang", "cancel", "dynamic", "compat"):
                assert code == 2 and records[-1]["kind"] == "gap", (mode, code, records)
                reason = {"clone": "unsupported_syscall", "pread": "unsupported_syscall",
                          "mmap": "unsupported_syscall", "signal": "signal_or_event",
                          "hang": "timeout", "cancel": "cancelled", "dynamic": "unsupported_syscall",
                          "compat": "syscall_abi"}[mode]
                assert records[-1]["reason"] == reason, (mode, records[-1])
            else:
                assert code == 0 and records[-1]["kind"] == "end", (mode, code, records[-1])
                assert connects, mode
                if mode == "badconnect":
                    assert connects[-1]["error"] and connects[-1]["result"] < 0
                else:
                    assert connects[-1]["result"] == 0 and not connects[-1]["error"]
                if mode in ("read", "execfail", "exec", "output", "rename"):
                    assert len(reads) == 1 and reads[0]["result"] == len(SENTINEL), (mode, reads)
                elif mode == "eof":
                    assert len(reads) == 1 and reads[0]["result"] == 0 and not reads[0]["error"]
                elif mode == "fault":
                    assert len(reads) == 1 and reads[0]["error"] and reads[0]["result"] == -14
                elif mode == "error":
                    assert not reads and any(r["kind"] == "read" and r["error"] and r["result"] == -9 for r in records)
                elif mode == "reuse":
                    assert not reads and len(file_reads(records, other_inode)) == 1
                elif mode == "socket":
                    assert not reads and any(r["kind"] == "read" and r["object_type"] == stat.S_IFSOCK and r["result"] > 0 for r in records)
                else:
                    assert not reads, (mode, reads)
                if mode == "exec":
                    assert reads[0]["execution_generation"] == 1 and connects[-1]["execution_generation"] == 2
                if mode == "execfail":
                    assert reads[0]["execution_generation"] == connects[-1]["execution_generation"] == 1
                if mode == "ipv6":
                    assert connects[-1]["family"] == 6 and connects[-1]["address"] == "::1"
            results.append({"case": mode, "exit_code": code, "records": len(records), "passed": True})
    if source_hashes() != frozen or any(hashlib.sha256(Path(p).read_bytes()).hexdigest() != h for p, h in elf_hashes.items()):
        raise AssertionError("source or executable drift during qualification")
    report = {"schema_version": 1, "scope": "owned synthetic native metadata capture only; not D14 acceptance",
              "architecture": os.uname().machine,
              "source_sha256": frozen, "source_unchanged": True,
              "executable_sha256": elf_hashes, "compiler_commands": compiler_commands,
              "cases": results, "passed": True}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = qualify(arguments.output.resolve())
    print(json.dumps({"passed": report["passed"], "cases": len(report["cases"]), "output": str(arguments.output)}))
