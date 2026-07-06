#!/usr/bin/env python3
"""Check ADR-015 encodings and optional local SQLite mechanics.

This is an offline reference, not the Rust coverage store or an intake service.
The SQLite projection omits authorization, SDK validation and history policy.
"""

import argparse
from contextlib import closing
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import selectors
import shutil
import sqlite3
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
DOMAINS = {kind: ("SIGNAL-COVERAGE-" + kind + "-V1\0").encode("ascii")
           for kind in ("PROFILE", "BINDING", "HISTORY", "COMMIT", "PREFIX", "STATE")}
COMPONENTS = {"configuration": 1, "scope": 2, "continuity": 4, "source_integrity": 8}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(4_194_305)
    require(len(raw) <= 4_194_304, "fixture byte cap")
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON constant")))


def uint(value, width):
    require(type(value) is int and 0 <= value < 1 << (width * 8), "unsigned integer")
    return value.to_bytes(width, "big")


def blob(value):
    return uint(len(value), 4) + value


def text(value):
    require(isinstance(value, str), "text type")
    data = value.encode("utf-8")
    require(1 <= len(data) <= 1024, "text byte cap")
    return blob(data)


def identifier(value):
    parsed = uuid.UUID(value)
    require(str(parsed) == value and parsed.int != 0, "canonical non-nil UUID")
    return parsed.bytes


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "digest syntax")
    return bytes.fromhex(value)


def sha(data):
    return hashlib.sha256(data).digest()


def timestamp(value):
    require(isinstance(value, str), "time type")
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z", value)
    require(match is not None, "UTC timestamp syntax")
    datetime.datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S")
    return (match[1] + "." + (match[2] or "").ljust(9, "0") + "Z").encode("ascii")


def profile_bytes(profile):
    fields = {"schema_version", "id", "revision", "required_components", "requires_checkpoint",
              "max_interval_seconds", "max_verification_age_seconds", "max_clock_skew_seconds"}
    require(set(profile) == fields and type(profile["schema_version"]) is int
            and profile["schema_version"] == 1, "profile fields/version")
    components = profile["required_components"]
    require(isinstance(components, list) and all(isinstance(c, str) for c in components)
            and 3 <= len(components) <= 4 and len(set(components)) == len(components)
            and set(components) <= COMPONENTS.keys(), "profile components")
    mask = sum(COMPONENTS[c] for c in components)
    require(mask & 7 == 7 and type(profile["requires_checkpoint"]) is bool, "profile baseline")
    for field in ("max_interval_seconds", "max_verification_age_seconds"):
        require(type(profile[field]) is int and 1 <= profile[field] <= 86400, "profile duration")
    require(type(profile["max_clock_skew_seconds"]) is int
            and 0 <= profile["max_clock_skew_seconds"] <= 300, "profile skew")
    return (DOMAINS["PROFILE"] + uint(1, 4) + text(profile["id"]) + text(profile["revision"])
            + uint(mask, 1) + uint(int(profile["requires_checkpoint"]), 1)
            + b"".join(uint(profile[f], 4) for f in
                       ("max_interval_seconds", "max_verification_age_seconds", "max_clock_skew_seconds")))


def binding_bytes(binding):
    require(set(binding) == {"source_id", "collector_id", "resource_scope", "expected_stream",
                             "coverage_profile", "collection_config_revision", "observer_id"}, "binding fields")
    scope = binding["resource_scope"]
    require(set(scope) in ({"kind", "id"}, {"kind", "id", "attributes"}), "scope fields")
    attrs = scope.get("attributes", {})
    require(isinstance(attrs, dict) and len(attrs) <= 16, "scope attribute count")
    require(all(isinstance(k, str) for k in attrs), "scope key type")
    profile = binding["coverage_profile"]
    require(set(profile) == {"id", "revision"}, "binding profile fields")
    result = (DOMAINS["BINDING"] + text(binding["source_id"]) + text(binding["collector_id"])
              + text(scope["kind"]) + text(scope["id"]) + uint(len(attrs), 4)
              + b"".join(text(k) + text(attrs[k]) for k in sorted(attrs, key=lambda k: k.encode("utf-8")))
              + text(binding["expected_stream"]) + text(profile["id"]) + text(profile["revision"])
              + text(binding["collection_config_revision"]) + text(binding["observer_id"]))
    require(len(result) <= 65536, "binding byte cap")
    return result


def commit_bytes(commit, profiles, bindings):
    require(set(commit) == {"history_id", "sequence", "record_id", "raw_utf8", "profile", "binding",
                            "authority_revision", "accepted_at", "replay_until", "identity_until",
                            "correction_of"}, "commit fields")
    seq = commit["sequence"]
    require(isinstance(seq, str) and re.fullmatch(r"[1-9][0-9]{0,19}", seq), "sequence syntax")
    raw = commit["raw_utf8"].encode("utf-8")
    require(1 <= len(raw) <= 65536, "record byte cap")
    record = json.loads(raw, object_pairs_hook=pairs)
    require(record["record_id"] == commit["record_id"], "raw record identity")
    p = profiles[commit["profile"]]
    b = bindings[commit["binding"]]
    require(b["coverage_profile"] == {"id": p["id"], "revision": p["revision"]}, "profile binding")
    require(all(record[k] == b[k] for k in ("source_id", "collector_id", "expected_stream",
                "coverage_profile", "collection_config_revision"))
            and record["provenance"]["observer_id"] == b["observer_id"], "raw record binding")
    scope = dict(record["resource_scope"])
    scope.setdefault("attributes", {})
    expected_scope = dict(b["resource_scope"])
    expected_scope.setdefault("attributes", {})
    require(scope == expected_scope, "raw record scope")
    times = [timestamp(commit[k]) for k in ("accepted_at", "replay_until", "identity_until")]
    require(times[0] < times[1] <= times[2], "receipt deadlines")
    correction = commit["correction_of"]
    return (DOMAINS["COMMIT"] + identifier(commit["history_id"]) + uint(int(seq), 8)
            + identifier(commit["record_id"]) + uint(len(raw), 4) + sha(raw) + blob(binding_bytes(b))
            + sha(profile_bytes(p)) + text(commit["authority_revision"])
            + timestamp(commit["accepted_at"]) + timestamp(commit["replay_until"])
            + timestamp(commit["identity_until"])
            + (b"\0" if correction is None else b"\1" + identifier(correction)))


def state_bytes(state):
    fields = {"history_id", "committed_sequence", "committed_prefix", "payload_pruned_through",
              "payload_anchor", "identity_pruned_through", "identity_anchor", "clock_floor",
              "payload_count", "identity_count", "binding_count", "profile_count", "ledger_charge"}
    require(set(state) == fields, "state fields")
    positions = [int(state[k]) for k in
                 ("identity_pruned_through", "payload_pruned_through", "committed_sequence")]
    require(positions == sorted(positions), "state pruning order")
    require(state["payload_count"] == positions[2] - positions[1]
            and state["identity_count"] == positions[2] - positions[0], "state counts")
    require(all(type(state[k]) is int and 0 <= state[k] < 2**63 for k in
                ("payload_count", "identity_count", "binding_count", "profile_count", "ledger_charge"))
            and state["ledger_charge"] >= 16384, "state counter/charge range")
    anchors = {}
    result = DOMAINS["STATE"] + uint(1, 4) + identifier(state["history_id"])
    for position, witness in (("committed_sequence", "committed_prefix"),
                              ("payload_pruned_through", "payload_anchor"),
                              ("identity_pruned_through", "identity_anchor")):
        value = state[position]
        require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "state sequence")
        seq = int(value)
        anchor = digest(state[witness])
        require(seq not in anchors or anchors[seq] == anchor, "equal-position anchors")
        require(seq != 0 or anchor == sha(DOMAINS["HISTORY"] + identifier(state["history_id"])), "zero anchor")
        anchors[seq] = anchor
        result += uint(seq, 8) + anchor
    return result + timestamp(state["clock_floor"]) + b"".join(uint(state[k], 8) for k in
        ("payload_count", "identity_count", "binding_count", "profile_count", "ledger_charge"))


def identity_bytes(history_id):
    header = b"SIGCOV01" + identifier(history_id)
    return header + sha(header)


def check_vectors(fixture):
    require(set(fixture) == {"schema_version", "contract_id", "runtime_status", "profiles", "bindings",
                            "chains", "standalone_commits", "times", "states", "identities"}, "fixture fields")
    require(fixture["schema_version"] == 1 and fixture["contract_id"] == "source-coverage-backend-v1"
            and fixture["runtime_status"] == "reference-only", "fixture identity/evidence scope")
    require(1 <= len(fixture["profiles"]) <= 16 and 1 <= len(fixture["bindings"]) <= 16
            and 1 <= len(fixture["chains"]) <= 8 and 1 <= len(fixture["standalone_commits"]) <= 8
            and 1 <= len(fixture["states"]) <= 16 and 1 <= len(fixture["times"]) <= 16
            and 1 <= len(fixture["identities"]) <= 8, "vector counts")
    profiles, bindings = {}, {}
    for kind, target, encoder in (("profiles", profiles, profile_bytes), ("bindings", bindings, binding_bytes)):
        for item in fixture[kind]:
            require(set(item) == {"id", "input", "encoded_hex", "sha256"} and item["id"] not in target,
                    "vector fields/duplicate ID")
            data = encoder(item["input"])
            require(data.hex() == item["encoded_hex"] and sha(data).hex() == item["sha256"], kind + " golden mismatch")
            target[item["id"]] = item["input"]
    committed = 0
    names = set()
    for chain in fixture["chains"]:
        require(set(chain) == {"id", "history_id", "initial_prefix", "commits"}
                and chain["id"] not in names and 1 <= len(chain["commits"]) <= 16, "chain fields/count")
        names.add(chain["id"])
        prefix = sha(DOMAINS["HISTORY"] + identifier(chain["history_id"]))
        require(prefix.hex() == chain["initial_prefix"], "history genesis mismatch")
        for seq, item in enumerate(chain["commits"], 1):
            require(set(item) == {"input", "encoded_hex", "commit_sha256", "prefix_digest"}, "commit vector fields")
            commit = item["input"]
            require(commit["history_id"] == chain["history_id"] and commit["sequence"] == str(seq), "chain order")
            data = commit_bytes(commit, profiles, bindings)
            prefix = sha(DOMAINS["PREFIX"] + prefix + sha(data))
            require(data.hex() == item["encoded_hex"] and sha(data).hex() == item["commit_sha256"]
                    and prefix.hex() == item["prefix_digest"], "commit/prefix golden mismatch")
            committed += 1
    for item in fixture["standalone_commits"]:
        require(set(item) == {"input", "encoded_hex", "commit_sha256"}, "standalone fields")
        data = commit_bytes(item["input"], profiles, bindings)
        require(data.hex() == item["encoded_hex"] and sha(data).hex() == item["commit_sha256"], "standalone mismatch")
    for item in fixture["times"]:
        require(set(item) == {"input", "encoded_ascii"} and timestamp(item["input"]).decode() == item["encoded_ascii"], "time golden mismatch")
    for item in fixture["states"]:
        require(set(item) == {"input", "encoded_hex", "sha256"}, "state vector fields")
        data = state_bytes(item["input"])
        require(data.hex() == item["encoded_hex"] and sha(data).hex() == item["sha256"], "state golden mismatch")
        state = item["input"]
        chain = next((c for c in fixture["chains"] if c["id"] == "original"
                      and c["history_id"] == state["history_id"]), None)
        require(chain is not None, "state chain reference")
        tail = int(state["committed_sequence"])
        require(tail <= len(chain["commits"]), "state frontier unavailable")
        identity_floor = int(state["identity_pruned_through"])
        payload_floor = int(state["payload_pruned_through"])
        for position, witness in ((tail, "committed_prefix"), (payload_floor, "payload_anchor"),
                                  (identity_floor, "identity_anchor")):
            expected = chain["initial_prefix"] if position == 0 else chain["commits"][position-1]["prefix_digest"]
            require(state[witness] == expected, "state chain witness")
        identities = chain["commits"][identity_floor:tail]
        keys = {binding_bytes(bindings[c["input"]["binding"]]) for c in identities}
        pins = {profile_bytes(profiles[c["input"]["profile"]]) for c in identities}
        charge = (16384 + sum(len(bytes.fromhex(c["encoded_hex"])) + 8192 for c in identities)
                  + sum(len(c["input"]["raw_utf8"].encode()) + 256 for c in chain["commits"][payload_floor:tail])
                  + sum(len(k) + 4096 for k in keys) + sum(len(p) + 4096 for p in pins))
        require(state["binding_count"] == len(keys) and state["profile_count"] == len(pins)
                and state["ledger_charge"] == charge, "state registry/ledger accounting")
    for item in fixture["identities"]:
        require(set(item) == {"history_id", "encoded_hex"}
                and identity_bytes(item["history_id"]).hex() == item["encoded_hex"], "identity golden mismatch")
    return {"profiles": len(profiles), "bindings": len(bindings), "chains": len(names),
            "chained_commits": committed, "standalone_commits": len(fixture["standalone_commits"]),
            "times": len(fixture["times"]), "states": len(fixture["states"]), "identities": len(fixture["identities"])}


def check_guards(fixture):
    mutations = [
        ("evidence scope", ("runtime_status",), "implemented"),
        ("fixture version", ("schema_version",), 2),
        ("profile version", ("profiles", 0, "input", "schema_version"), True),
        ("profile duplicate component", ("profiles", 0, "input", "required_components"), ["configuration"] * 3),
        ("profile missing baseline", ("profiles", 0, "input", "required_components"), ["configuration", "scope", "source_integrity"]),
        ("profile boolean", ("profiles", 0, "input", "requires_checkpoint"), 1),
        ("profile zero duration", ("profiles", 0, "input", "max_interval_seconds"), 0),
        ("profile skew", ("profiles", 0, "input", "max_clock_skew_seconds"), 301),
        ("profile bytes", ("profiles", 0, "encoded_hex"), "00"),
        ("profile fingerprint", ("profiles", 0, "sha256"), "0" * 64),
        ("binding empty text", ("bindings", 0, "input", "source_id"), ""),
        ("binding byte bound", ("bindings", 0, "input", "source_id"), "é" * 513),
        ("binding nonstring attribute", ("bindings", 0, "input", "resource_scope", "attributes"), {"key": 1}),
        ("binding excessive attributes", ("bindings", 0, "input", "resource_scope", "attributes"), {str(i): "v" for i in range(17)}),
        ("binding additional scope field", ("bindings", 0, "input", "resource_scope"), {"kind": "k", "id": "i", "extra": "x"}),
        ("chain nil identity", ("chains", 0, "history_id"), "00000000-0000-0000-0000-000000000000"),
        ("chain genesis", ("chains", 0, "initial_prefix"), "0" * 64),
        ("chain noncontiguous sequence", ("chains", 0, "commits", 1, "input", "sequence"), "3"),
        ("commit raw content", ("chains", 0, "commits", 0, "input", "raw_utf8"), fixture["chains"][0]["commits"][0]["input"]["raw_utf8"] + " "),
        ("commit correction", ("chains", 0, "commits", 0, "input", "correction_of"), fixture["chains"][0]["commits"][1]["input"]["record_id"]),
        ("commit prefix", ("chains", 0, "commits", 0, "prefix_digest"), "0" * 64),
        ("u64 overflow", ("standalone_commits", 0, "input", "sequence"), str(2**64)),
        ("sequence noncanonical", ("standalone_commits", 0, "input", "sequence"), "01"),
        ("time offset", ("times", 0, "input"), "0001-01-01T00:00:00+00:00"),
        ("time calendar", ("times", 0, "input"), "2026-02-30T00:00:00Z"),
        ("time leap second", ("times", 0, "input"), "2026-10-07T00:00:60Z"),
        ("time precision", ("times", 0, "input"), "2026-10-07T00:00:00.1234567890Z"),
        ("state pruning order", ("states", 0, "input", "identity_pruned_through"), "1"),
        ("state counter", ("states", 1, "input", "identity_count"), 2),
        ("state equal-position anchor", ("states", 0, "input", "payload_anchor"), "0" * 64),
        ("state signed byte counter", ("states", 1, "input", "ledger_charge"), 2**63),
        ("state checksum", ("states", 0, "sha256"), "0" * 64),
        ("identity header", ("identities", 0, "encoded_hex"), "00" * 56),
    ]
    for name, path, value in mutations:
        mutated = copy.deepcopy(fixture)
        parent = mutated
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = value
        try:
            check_vectors(mutated)
        except ValueError:
            continue
        raise ValueError("rejection guard accepted: " + name)
    profiles = {v["id"]: v for v in fixture["profiles"]}
    bindings = {v["id"]: v for v in fixture["bindings"]}
    require(profiles["basic"]["sha256"] == profiles["basic_reordered"]["sha256"], "profile set order")
    require(bindings["basic"]["encoded_hex"] == bindings["omitted_attributes"]["encoded_hex"], "empty attributes")
    require(bindings["unicode"]["encoded_hex"] == bindings["unicode_reordered"]["encoded_hex"]
            != bindings["unicode_decomposed"]["encoded_hex"], "UTF8 order/no normalization")
    chains = {v["id"]: v for v in fixture["chains"]}
    require(len({chains[k]["commits"][0]["prefix_digest"] for k in
                 ("original", "reserialized", "other_history")}) == 3, "raw/store prefix domains")
    return {"rejection_guards": len(mutations), "relationship_checks": 4}


def projection_open(path):
    connection = sqlite3.connect(path, timeout=0, isolation_level=None)
    connection.execute("PRAGMA page_size=4096")
    require(connection.execute("PRAGMA page_size").fetchone()[0] == 4096, "page size")
    require(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete", "journal mode")
    connection.execute("PRAGMA synchronous=EXTRA")
    require(connection.execute("PRAGMA synchronous").fetchone()[0] == 3, "sync mode")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA mmap_size=0")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-1024")
    return connection


def projection_apply(connection, fixture, stage):
    chain = fixture["chains"][0]
    connection.execute("BEGIN IMMEDIATE")
    if stage.startswith("append"):
        item = chain["commits"][1]
        c = item["input"]
        connection.execute("INSERT INTO entries VALUES (?,?,?,?,?)", (uint(2, 8), identifier(c["record_id"]),
            bytes.fromhex(item["encoded_hex"]), digest(item["prefix_digest"]), c["raw_utf8"].encode()))
        if stage != "append_partial":
            connection.execute("UPDATE state SET sequence=?,prefix=?", (uint(2, 8), digest(item["prefix_digest"])))
    elif stage.startswith("payload"):
        connection.execute("UPDATE entries SET raw=NULL WHERE sequence=?", (uint(1, 8),))
        connection.execute("UPDATE state SET payload_floor=?,payload_anchor=?", (uint(1, 8), digest(chain["commits"][0]["prefix_digest"])))
    elif stage.startswith("identity"):
        connection.execute("DELETE FROM entries WHERE sequence=?", (uint(1, 8),))
        connection.execute("UPDATE state SET identity_floor=?,identity_anchor=?", (uint(1, 8), digest(chain["commits"][0]["prefix_digest"])))
    else:
        raise ValueError("unknown probe stage")
    if stage.endswith("committed"):
        connection.execute("COMMIT")


def worker(args):
    # Private subprocess hook for the explicitly requested mechanics probe.
    fixture = load(args.fixture)
    with closing(projection_open(args.worker_db)) as connection:
        projection_apply(connection, fixture, args.worker_stage)
        print("READY", flush=True)
        sys.stdin.read(1)


def kill_at(path, fixture_path, stage):
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--fixture", str(fixture_path),
        "--worker-db", str(path), "--worker-stage", stage], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(10)), "probe worker deadline")
        require(process.stdout.readline() == b"READY\n", "probe worker failed before kill point")
        process.kill()
        process.wait(timeout=10)
        require(process.returncode == -9, "SIGKILL result")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def probe(directory, fixture_path, fixture):
    require(not directory.exists(), "probe directory must be new; preserve previous evidence")
    directory.mkdir(parents=True)
    path = directory / "coverage.sqlite3"
    chain = fixture["chains"][0]
    first = chain["commits"][0]
    checks = []
    with closing(projection_open(path)) as connection:
        connection.executescript("""CREATE TABLE state(sequence BLOB,prefix BLOB,payload_floor BLOB,
            payload_anchor BLOB,identity_floor BLOB,identity_anchor BLOB);
            CREATE TABLE entries(sequence BLOB PRIMARY KEY,record_id BLOB UNIQUE NOT NULL,
                metadata BLOB NOT NULL,prefix BLOB NOT NULL,raw BLOB) WITHOUT ROWID;""")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO state VALUES (?,?,?,?,?,?)", (uint(1, 8), digest(first["prefix_digest"]),
            uint(0, 8), digest(chain["initial_prefix"]), uint(0, 8), digest(chain["initial_prefix"])))
        connection.execute("INSERT INTO entries VALUES (?,?,?,?,?)", (uint(1, 8), identifier(first["input"]["record_id"]),
            bytes.fromhex(first["encoded_hex"]), digest(first["prefix_digest"]), first["input"]["raw_utf8"].encode()))
        connection.execute("COMMIT")
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "initial integrity")
        checks.append("verified_DELETE_EXTRA_and_initial_commit")

    def snapshot():
        with closing(projection_open(path)) as connection:
            require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "recovery integrity")
            return (connection.execute("SELECT * FROM state").fetchall(),
                    connection.execute("SELECT * FROM entries ORDER BY sequence").fetchall())

    baseline = snapshot()
    for stage in ("append_partial", "append_prepared"):
        kill_at(path, fixture_path, stage)
        require(snapshot() == baseline, "uncommitted transaction leaked")
        checks.append("SIGKILL_" + stage + "_rolls_back_projection")
    kill_at(path, fixture_path, "append_committed")
    committed = snapshot()
    require(len(committed[1]) == 2 and committed[0][0][0] == uint(2, 8), "lost-response commit missing")
    checks.append("SIGKILL_after_commit_preserves_row_and_frontier")
    kill_at(path, fixture_path, "payload_prepared")
    require(snapshot() == committed, "uncommitted payload pruning leaked")
    checks.append("SIGKILL_payload_prune_rolls_back_payload_and_marker")
    kill_at(path, fixture_path, "payload_committed")
    pruned = snapshot()
    require(pruned[1][0][-1] is None and pruned[0][0][2] == uint(1, 8), "payload pruning not atomic")
    checks.append("payload_prune_preserves_identity_and_anchor")
    kill_at(path, fixture_path, "identity_prepared")
    require(snapshot() == pruned, "uncommitted identity pruning leaked")
    checks.append("SIGKILL_identity_prune_rolls_back_identity_and_marker")
    kill_at(path, fixture_path, "identity_committed")
    retained = snapshot()
    require(len(retained[1]) == 1 and retained[0][0][4] == uint(1, 8)
            and retained[0][0][:2] == committed[0][0][:2], "identity prune lost frontier")
    prefix = sha(DOMAINS["PREFIX"] + retained[0][0][5] + sha(retained[1][0][2]))
    require(prefix == retained[1][0][3] == retained[0][0][1], "retained chain from anchor")
    checks.append("identity_prune_recovery_reconstructs_retained_prefix")

    with closing(projection_open(path)) as connection:
        second = projection_open(path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                second.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                require(error.sqlite_errorcode == sqlite3.SQLITE_BUSY, "unexpected contention error")
            else:
                raise ValueError("second writer acquired transaction")
            connection.execute("ROLLBACK")
        finally:
            second.close()
        checks.append("second_SQLite_writer_is_busy")
        connection.execute("PRAGMA max_page_count=32")
        require(connection.execute("PRAGMA max_page_count").fetchone()[0] == 32, "page cap")
        connection.execute("BEGIN IMMEDIATE")
        try:
            for seq in range(3, 100):
                connection.execute("INSERT INTO entries VALUES (?,?,?,?,?)", (uint(seq, 8), uuid.UUID(int=seq).bytes,
                    b"probe", b"p" * 32, b"x" * 65536))
        except sqlite3.DatabaseError as error:
            require(error.sqlite_errorcode == sqlite3.SQLITE_FULL, "database cap failed differently")
        else:
            raise ValueError("database cap did not reject")
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        require(path.stat().st_size <= 32 * 4096, "database file exceeded page cap")
    require(snapshot() == retained, "page cap failure changed acknowledged baseline")
    checks.append("SQLITE_FULL_preserves_committed_projection")
    copy_path = directory / "relocated.sqlite3"
    shutil.copyfile(path, copy_path)
    with closing(projection_open(copy_path)) as connection:
        require(connection.execute("SELECT * FROM state").fetchall() == retained[0]
                and connection.execute("SELECT * FROM entries ORDER BY sequence").fetchall() == retained[1], "offline relocation changed history")
    checks.append("closed_database_offline_relocation_preserves_rows")
    require(sorted([uint(n, 8) for n in (2**64-1, 1, 2**63, 2**63-1)])
            == [uint(n, 8) for n in (1, 2**63-1, 2**63, 2**64-1)], "u64 BLOB ordering")
    checks.append("u64_blob_encoding_orders_across_signed_boundary")
    import fcntl
    lock_path = directory / ".lock"
    with lock_path.open("wb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_lock = """import fcntl,sys
with open(sys.argv[1], 'rb') as lock:
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: sys.exit(0)
    sys.exit(1)
"""
        result = subprocess.run([sys.executable, "-c", check_lock, str(lock_path)], timeout=10, check=False)
        require(result.returncode == 0, "second process acquired advisory lock")
    checks.append("OS_advisory_lock_excludes_second_process")
    return {"sqlite_version": sqlite3.sqlite_version, "scope": "Python/system-SQLite projection; not Rust store qualification",
            "passed": len(checks), "checks": checks, "missing": ["Rust integration", "authorization/semantic intake",
            "56 history outcomes", "Rust worker lifetime ownership", "VFS fault injection and power loss",
            "active journal reserve qualification", "memory/cancellation/clock budgets", "native ARM64"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=ROOT / "tests/fixtures/source-coverage/backend-vectors.json")
    parser.add_argument("--probe-dir", type=Path, help="new directory for bounded local SQLite mechanics evidence")
    parser.add_argument("--self-test", action="store_true", help="also execute frozen-vector rejection and relationship guards")
    parser.add_argument("--worker-db", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-stage", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_db:
        worker(args)
        return
    fixture = load(args.fixture)
    require(sha(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 known answer")
    result = {"schema_version": 1, "status": "passed", "scope": "ADR-015 reference encodings", "vectors": check_vectors(fixture)}
    if args.self_test:
        result["guards"] = check_guards(fixture)
    if args.probe_dir:
        result["mechanics"] = probe(args.probe_dir, args.fixture.resolve(), fixture)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, UnicodeError, OSError, RecursionError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
