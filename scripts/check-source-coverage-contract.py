#!/usr/bin/env python3
"""Check the offline SourceCoverage schemas and fixture inventory.

This checker supports only the structural keywords used in the two owned schemas.
It rejects unknown schema keywords and remote references. It does not assert
format annotations, execute semantic assessments or qualify production coverage.
"""

import argparse
import copy
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
KEYWORDS = {"$schema", "$id", "$comment", "$defs", "$ref", "title", "description",
            "type", "const", "enum", "required", "properties", "additionalProperties",
            "propertyNames", "maxProperties", "items", "maxItems", "minItems", "uniqueItems",
            "minimum", "maximum", "minLength", "maxLength", "pattern", "format"}
STATES = {"verified", "partial", "unknown", "failed", "unsupported"}
COMPONENTS = {"configuration", "scope", "continuity", "source_integrity"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("non-finite JSON constant")


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(4_194_305)
    require(len(raw) <= 4_194_304, "contract input exceeds 4 MiB")
    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant), raw


def resolve(ref, root):
    require(ref.startswith("#/$defs/") and ref.count("/") == 2,
            "only direct local definition references are supported")
    return root["$defs"][ref.removeprefix("#/$defs/")]


def inspect_schema(schema, root, depth=0):
    require(depth <= 16 and isinstance(schema, dict), "invalid/recursive schema")
    require(schema.keys() <= KEYWORDS, "unsupported schema keyword")
    if "$ref" in schema:
        inspect_schema(resolve(schema["$ref"], root), root, depth + 1)
    for name in ("$defs", "properties"):
        for child in schema.get(name, {}).values():
            inspect_schema(child, root, depth + 1)
    for name in ("items", "propertyNames", "additionalProperties"):
        if name in schema and isinstance(schema[name], dict):
            inspect_schema(schema[name], root, depth + 1)
    if "pattern" in schema:
        re.compile(schema["pattern"])
    require(schema.get("format") in (None, "date-time", "uuid"), "unknown format annotation")


def is_type(value, kind):
    return {"object": lambda: isinstance(value, dict), "array": lambda: isinstance(value, list),
            "string": lambda: isinstance(value, str), "null": lambda: value is None,
            "boolean": lambda: isinstance(value, bool),
            "integer": lambda: (not isinstance(value, bool) and isinstance(value, (int, float))
                                and (isinstance(value, int) or (math.isfinite(value) and value.is_integer())))}[kind]()


def validate(value, schema, root, path="$", depth=0):
    require(depth <= 16, "structural depth exceeded")
    if "$ref" in schema:
        validate(value, resolve(schema["$ref"], root), root, path, depth + 1)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        require(any(is_type(value, kind) for kind in types), path + ": type")
    if "const" in schema:
        require(value == schema["const"], path + ": const")
    if "enum" in schema:
        require(value in schema["enum"], path + ": enum")
    if isinstance(value, dict):
        require(set(schema.get("required", [])) <= value.keys(), path + ": required")
        require(len(value) <= schema.get("maxProperties", len(value)), path + ": maxProperties")
        props = schema.get("properties", {})
        for key, child in value.items():
            if "propertyNames" in schema:
                validate(key, schema["propertyNames"], root, path + ".<key>", depth + 1)
            if key in props:
                validate(child, props[key], root, path + "." + key, depth + 1)
            else:
                extra = schema.get("additionalProperties", True)
                require(extra is not False, path + ": additionalProperties")
                if isinstance(extra, dict):
                    validate(child, extra, root, path + ".<value>", depth + 1)
    if isinstance(value, list):
        require(schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)),
                path + ": item count")
        if schema.get("uniqueItems"):
            # The owned schemas use uniqueness only for string arrays.
            require(all(isinstance(item, str) for item in value), "unsupported uniqueItems input")
            require(len(set(value)) == len(value), path + ": uniqueItems")
        for item in value:
            if "items" in schema:
                validate(item, schema["items"], root, path + "[]", depth + 1)
    if isinstance(value, str):
        require(schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)),
                path + ": character count")
        if "pattern" in schema:
            require(re.search(schema["pattern"], value) is not None, path + ": pattern")
    if not isinstance(value, bool) and isinstance(value, (int, float)):
        require(schema.get("minimum", value) <= value <= schema.get("maximum", value), path + ": range")


def check(root):
    record_path = root / "schemas/source-coverage.schema.json"
    profile_path = root / "schemas/source-coverage-profile.schema.json"
    fixture_path = root / "tests/fixtures/source-coverage/contract.json"
    record_schema, record_raw = load(record_path)
    profile_schema, profile_raw = load(profile_path)
    fixture, fixture_raw = load(fixture_path)
    for schema in (record_schema, profile_schema):
        require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
                "unexpected schema dialect")
        inspect_schema(schema, schema)
    require(fixture["schema_version"] == 1, "unsupported fixture version")
    profiles = fixture["profiles"]
    require(1 <= len(profiles) <= 16, "profile fixture count")
    profile_keys = set()
    for p in profiles:
        validate(p, profile_schema, profile_schema)
        require(set(p["required_components"]) <= COMPONENTS and
                COMPONENTS - {"source_integrity"} <= set(p["required_components"]),
                "profile fixture missing baseline components")
        require((p["id"], p["revision"]) not in profile_keys, "duplicate profile fixture")
        profile_keys.add((p["id"], p["revision"]))
    records = fixture["record_cases"]
    require(1 <= len(records) <= 128, "record fixture count")
    ids = {f["id"] for f in records}
    require(len(ids) == len(records), "duplicate record fixture")
    accepted = rejected = deferred = 0
    outcomes = []
    for f in records:
        error = None
        try:
            validate(f["record"], record_schema, record_schema)
        except ValueError as failure:
            error = str(failure)
        require(isinstance(f["expected_structure"], bool), "structure expectation must be boolean")
        require((error is None) == f["expected_structure"], f["id"] + ": structural expectation differs")
        semantics = f["expected_semantics"]
        if error:
            require(semantics == "not_evaluated", "invalid structure reached semantics")
            rejected += 1
        else:
            require(semantics in ("valid", "reject"), "missing semantic expectation")
            require((f["expected_semantic_error"] is not None) == (semantics == "reject"),
                    "semantic rejection reason missing/inconsistent")
            deferred += int(semantics == "reject")
            accepted += 1
        outcomes.append({"id": f["id"], "structure": "rejected" if error else "accepted",
                         "structural_error": error, "semantic_execution": "not run"})
    assessments = fixture["assessment_cases"]
    require(1 <= len(assessments) <= 128, "assessment fixture count")
    a_ids = {a["id"] for a in assessments}
    require(len(a_ids) == len(assessments), "duplicate assessment fixture")
    def closed(properties):
        return {"type": "object", "additionalProperties": False,
                "required": list(properties), "properties": properties}
    binding = closed({k: record_schema["properties"][k] for k in
                      ("source_id", "collector_id", "resource_scope", "expected_stream",
                       "coverage_profile", "collection_config_revision")})
    context = closed({"at": {"$ref": "#/$defs/timestamp"},
                      "mode": {"type": "string", "enum": ["current", "historical"]},
                      "observer_status": {"type": "string", "enum": ["healthy", "unhealthy", "unknown"]},
                      "observer_id": {"$ref": "#/$defs/identifier"}, "binding": binding,
                      "interval": closed({k: {"$ref": "#/$defs/timestamp"} for k in ("start", "end")})})
    for a in assessments:
        validate(a["context"], context, record_schema)
        require(a["record_fixture"] in ids and a["expected"]["status"] in STATES,
                "invalid assessment reference/status")
        require(a["context"]["mode"] in {"current", "historical"}, "assessment mode")
        require(a["context"]["observer_status"] in {"healthy", "unhealthy", "unknown"}, "observer status")
        require(a["runtime_status"] == "planned", "design-time assessment marker changed")
        reasons = a["expected"]["reason_codes"]
        require(isinstance(reasons, list) and len(reasons) <= 1 and
                all(isinstance(reason, str) and 0 < len(reason) <= 128 for reason in reasons),
                "invalid primary assessment reason")
    transitions = fixture["transition_cases"]
    require(1 <= len(transitions) <= 32, "transition fixture count")
    require(len({t["id"] for t in transitions}) == len(transitions), "duplicate transition fixture")
    for t in transitions:
        require(2 <= len(t["steps"]) <= 16 and set(t["steps"]) <= a_ids, "transition step references")
        require(len(t["retained_records"]) <= 16 and set(t["retained_records"]) <= ids,
                "transition history references")
        require(set(t["historical_assertions"]) <= a_ids, "historical assessment references")
    require(fixture["limits"] == {"max_record_bytes": 65536, "max_string_bytes": 1024,
                                  "max_fixture_bytes": 4194304, "max_gap_entries": 128,
                                  "max_proof_refs": 32, "max_scope_attributes": 16}, "contract limit drift")
    history = check_history(root, fixture, record_schema)
    return {"schema_version": 1, "status": "passed-offline-structural-contract",
            "profiles": len(profiles), "record_cases": len(records), "structural_accepts": accepted,
            "structural_rejects": rejected, "deferred_semantic_rejection_cases": deferred,
            "assessment_cases": len(assessments), "transition_sequences": len(transitions),
            "semantic_assessments_executed": 0, "format_assertions_executed": 0,
            "schema_scope": "Owned structural keyword subset; not a general Draft 2020-12 implementation",
            "hashes": {"record_schema": hashlib.sha256(record_raw).hexdigest(),
                       "profile_schema": hashlib.sha256(profile_raw).hexdigest(),
                       "fixtures": hashlib.sha256(fixture_raw).hexdigest(),
                       "checker": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            "record_outcomes": outcomes, "history_contract": history}


def closed_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + ": fields")


def fixture_text(value, label, maximum=1024):
    require(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= maximum,
            label + ": text bound")


def check_history(root, contract, record_schema):
    """Inventory/byte relationships only; no history-state-machine execution."""
    path = root / "tests/fixtures/source-coverage/history.json"
    fixture, raw = load(path)
    closed_keys(fixture, ("schema_version", "status", "contract_id", "limits", "requirements",
                         "candidates", "receipt_example", "cases"), "history fixture")
    require(type(fixture["schema_version"]) is int and fixture["schema_version"] == 1,
            "history fixture version")
    require(fixture["status"] == "proposed-contract" and
            fixture["contract_id"] == "source-coverage-history-v1", "history status/identity")
    limits = fixture["limits"]
    limit_keys = ("max_fixture_bytes", "max_record_bytes", "max_binding_metadata_bytes",
                  "max_receipt_metadata_bytes", "max_entry_bytes", "max_retained_payloads",
                  "max_retained_identities", "max_binding_keys", "max_ledger_bytes",
                  "max_transient_bytes", "max_page_records", "max_page_bytes", "max_scan_records",
                  "max_scan_bytes", "max_inflight_operations", "payload_retention_seconds",
                  "identity_retention_seconds", "max_report_admission_age_seconds",
                  "max_clock_skew_seconds", "operation_timeout_millis")
    closed_keys(limits, limit_keys, "history limits")
    for key, value in limits.items():
        minimum = 0 if key == "max_clock_skew_seconds" else 1
        require(type(value) is int and minimum <= value <= (1 << 53) - 1,
                "history limit must be finite/bounded integer")
    for key in ("payload_retention_seconds", "identity_retention_seconds", "max_report_admission_age_seconds"):
        require(limits[key] <= (1 << 32) - 1, "history duration ceiling")
    require(limits["max_fixture_bytes"] == 4_194_304 and limits["max_record_bytes"] == 65_536,
            "history input bound drift")
    require(limits["max_retained_identities"] >= limits["max_retained_payloads"], "identity capacity below payload capacity")
    require(limits["identity_retention_seconds"] >= limits["payload_retention_seconds"] >
            limits["max_report_admission_age_seconds"] + limits["max_clock_skew_seconds"],
            "history retention/admission windows inconsistent")
    require(limits["max_clock_skew_seconds"] <= 300, "history skew bound")
    require(limits["max_page_bytes"] >= limits["max_record_bytes"] + limits["max_receipt_metadata_bytes"],
            "history page cannot hold one maximum row")
    require(limits["max_scan_records"] >= limits["max_page_records"] and
            limits["max_scan_bytes"] >= limits["max_entry_bytes"], "history scan budget")
    require(limits["max_entry_bytes"] >= 6 * limits["max_record_bytes"] + limits["max_receipt_metadata_bytes"] and
            limits["max_ledger_bytes"] >= limits["max_entry_bytes"] + limits["max_binding_metadata_bytes"] and
            limits["max_transient_bytes"] >= limits["max_entry_bytes"], "history byte reservation")
    requirements = fixture["requirements"]
    require(isinstance(requirements, list) and len(requirements) == 16, "history requirement inventory")
    required = {f"H{i:02}" for i in range(1, 17)}
    seen = set()
    for item in requirements:
        closed_keys(item, ("id", "name"), "history requirement")
        require(item["id"] in required and item["id"] not in seen, "history requirement identity")
        fixture_text(item["name"], "history requirement", 256)
        seen.add(item["id"])
    records = {item["id"]: item for item in contract["record_cases"]}
    candidates = fixture["candidates"]
    require(isinstance(candidates, list) and 1 <= len(candidates) <= 32, "history candidate inventory")
    candidate_map = {}
    payloads = {}
    values = {}
    for item in candidates:
        closed_keys(item, ("id", "record_fixture", "encoding", "edits", "expected_structure"), "history candidate")
        fixture_text(item["id"], "history candidate id", 128)
        require(item["id"] not in candidate_map and item["record_fixture"] in records, "history candidate reference")
        require(item["encoding"] in {"compact", "pretty", "trailing_space"}, "history candidate encoding")
        require(isinstance(item["edits"], dict) and len(item["edits"]) <= 8, "history candidate edits")
        value = copy.deepcopy(records[item["record_fixture"]]["record"])
        for pointer, replacement in item["edits"].items():
            require(pointer in {"/record_id", "/coverage_start", "/coverage_end"}, "history edit path")
            fixture_text(replacement, "history candidate edit")
            value[pointer[1:]] = replacement
        require(type(item["expected_structure"]) is bool, "history candidate structural expectation")
        valid = True
        try:
            validate(value, record_schema, record_schema)
        except ValueError:
            valid = False
        require(valid == item["expected_structure"], "history candidate structural outcome")
        if item["encoding"] == "pretty":
            encoded = json.dumps(value, ensure_ascii=False, indent=2).encode()
        else:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
            if item["encoding"] == "trailing_space":
                encoded += b" "
        require(len(encoded) <= limits["max_record_bytes"], "history candidate raw byte limit")
        candidate_map[item["id"]] = item
        payloads[item["id"]] = encoded
        values[item["id"]] = value
    # These fixtures exercise the distinction between logical and exact wire identity.
    require({"quiet", "quiet_pretty", "quiet_spaced", "changed_same_id"} <= candidate_map.keys(),
            "missing exact-byte history examples")
    for name in ("quiet_pretty", "quiet_spaced", "changed_same_id"):
        require(values[name]["record_id"] == values["quiet"]["record_id"] and
                payloads[name] != payloads["quiet"], "history conflict example lacks same-id/different-bytes")
    require(values["quiet_pretty"] == values["quiet_spaced"] == values["quiet"],
            "history reserialization examples changed logical content")
    example = fixture["receipt_example"]
    closed_keys(example, ("candidate", "receipt", "prefix_digest_status"), "history receipt example")
    require(example["candidate"] in candidate_map and
            example["prefix_digest_status"] == "placeholder-not-a-golden-vector", "history prefix evidence claim")
    receipt = example["receipt"]
    closed_keys(receipt, ("schema_version", "history_id", "sequence", "record_id", "content_sha256",
                         "prefix_digest", "accepted_at", "replay_until", "identity_until",
                         "profile_fingerprint", "authority_revision", "correction_of"), "history receipt")
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1, "history receipt version")
    uuid_pattern = record_schema["properties"]["record_id"]["pattern"]
    for name in ("history_id", "record_id"):
        require(isinstance(receipt[name], str) and re.fullmatch(uuid_pattern, receipt[name]) and
                receipt[name] != "00000000-0000-0000-0000-000000000000", "history receipt UUID")
    require(isinstance(receipt["sequence"], str) and re.fullmatch(r"[1-9][0-9]{0,19}", receipt["sequence"]) and
            int(receipt["sequence"]) <= (1 << 64) - 1, "history receipt sequence")
    for name in ("content_sha256", "prefix_digest", "profile_fingerprint"):
        require(isinstance(receipt[name], str) and re.fullmatch(r"[0-9a-f]{64}", receipt[name]), "history receipt digest")
    require(receipt["prefix_digest"] == "0" * 64, "history placeholder must not imply token acceptance")
    chosen = example["candidate"]
    require(receipt["record_id"] == values[chosen]["record_id"] and
            receipt["content_sha256"] == hashlib.sha256(payloads[chosen]).hexdigest(), "history receipt raw identity")
    selected_profiles = [p for p in contract["profiles"] if
                         (p["id"], p["revision"]) == (values[chosen]["coverage_profile"]["id"],
                                                       values[chosen]["coverage_profile"]["revision"])]
    require(len(selected_profiles) == 1 and receipt["profile_fingerprint"] == hashlib.sha256(
        json.dumps(selected_profiles[0], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest(),
        "history receipt pinned profile")
    for name in ("accepted_at", "replay_until", "identity_until"):
        validate(receipt[name], record_schema["$defs"]["timestamp"], record_schema)
        require(len(receipt[name]) == 20, "owned receipt example must use whole seconds")
    example_times = {name: datetime.datetime.fromisoformat(receipt[name].replace("Z", "+00:00"))
                     for name in ("accepted_at", "replay_until", "identity_until")}
    require(example_times["replay_until"] - example_times["accepted_at"] ==
            datetime.timedelta(seconds=limits["payload_retention_seconds"]) and
            example_times["identity_until"] - example_times["accepted_at"] ==
            datetime.timedelta(seconds=limits["identity_retention_seconds"]), "history receipt retention deadlines")
    fixture_text(receipt["authority_revision"], "history receipt authority")
    require(receipt["correction_of"] is None, "history baseline receipt is not a correction")
    require(len(json.dumps(receipt, ensure_ascii=False, separators=(",", ":")).encode()) <=
            limits["max_receipt_metadata_bytes"], "history receipt metadata byte limit")
    cases = fixture["cases"]
    require(isinstance(cases, list) and 1 <= len(cases) <= 128, "history case inventory")
    case_ids = set()
    covered = set()
    outcomes = {"committed", "replayed", "id_content_conflict", "not_authorized", "binding_mismatch",
                "invalid_record", "profile_unavailable", "profile_revision_conflict", "record_in_future", "report_too_old",
                "quota_rejected", "replay_window_expired", "identity_pruned", "pruned", "prune_blocked",
                "clock_regression", "correction_target_unavailable", "correction_binding_mismatch",
                "no_health_aggregation", "page_continuation", "history_pruned", "response_limit",
                "record_unavailable", "history_page", "not_committed", "outcome_unknown",
                "complete_prefix_recovered", "readiness_failed", "consistent_pruned_prefix", "same_history",
                "history_unavailable", "prefix_mismatch", "independent_reconciliation_required",
                "ownership_lost", "unsupported_ownership", "sequence_exhausted"}
    for item in cases:
        closed_keys(item, ("id", "kind", "candidates", "requirements", "preconditions", "expected", "runtime_status"),
                    "history case")
        fixture_text(item["id"], "history case id", 128)
        require(item["id"] not in case_ids, "duplicate history case")
        case_ids.add(item["id"])
        require(item["kind"] in {"submit", "retry", "get", "scan", "recovery", "prune", "supervision"}, "history case kind")
        require(isinstance(item["candidates"], list) and len(item["candidates"]) <= 4 and
                all(name in candidate_map for name in item["candidates"]), "history case candidate reference")
        require(isinstance(item["requirements"], list) and 1 <= len(item["requirements"]) <= 16 and
                len(set(item["requirements"])) == len(item["requirements"]) and
                set(item["requirements"]) <= required, "history case requirement reference")
        covered.update(item["requirements"])
        require(isinstance(item["preconditions"], list) and 1 <= len(item["preconditions"]) <= 8, "history preconditions")
        for statement in item["preconditions"]:
            fixture_text(statement, "history precondition", 512)
        require(item["runtime_status"] == "planned", "history runtime cannot be claimed by fixture inventory")
        expected = item["expected"]
        closed_keys(expected, ("outcome", "sequence_effect", "history_effect", "health_effect", "reason_codes"), "history expectation")
        require(expected["outcome"] in outcomes and
                expected["sequence_effect"] in {"none", "one", "original", "boundary", "uncertain"} and
                expected["history_effect"] in {"unchanged", "append", "prune_eligible_prefix", "may_commit"} and
                expected["health_effect"] in {"no_claim", "no_renewal", "external_unknown"}, "history expectation vocabulary")
        reasons = expected["reason_codes"]
        require(isinstance(reasons, list) and len(reasons) <= 1, "history primary reason bound")
        for reason in reasons:
            fixture_text(reason, "history reason", 128)
        if expected["outcome"] == "replayed":
            require((expected["sequence_effect"], expected["history_effect"], expected["health_effect"]) ==
                    ("original", "unchanged", "no_renewal"), "history replay incorrectly renews state")
        elif expected["outcome"] == "committed":
            require((expected["sequence_effect"], expected["history_effect"], expected["health_effect"]) ==
                    ("one", "append", "no_claim"), "history admission incorrectly claims health")
        elif expected["outcome"] == "outcome_unknown":
            require((expected["sequence_effect"], expected["history_effect"]) ==
                    ("uncertain", "may_commit"), "history uncertainty incorrectly claims rollback")
        elif expected["outcome"] == "pruned":
            require((expected["sequence_effect"], expected["history_effect"]) ==
                    ("boundary", "prune_eligible_prefix"), "history pruning expectation")
        else:
            require((expected["sequence_effect"], expected["history_effect"]) ==
                    ("none", "unchanged"), "history rejection/read changes admitted history")
    require(covered == required, "history requirements lack fixture coverage")
    require({"identical_retry", "pretty_json_conflict", "trailing_whitespace_conflict", "changed_content_same_id",
             "replay_at_deadline", "identity_pruned_old_receipt", "backfill_append", "page_pruned_between_reads",
             "sync_uncertainty", "restore_divergent_prefix", "ownership_lost_during_commit"} <= case_ids,
            "missing core history failure fixtures")
    return {"status": "passed-offline-history-inventory", "requirements": len(required),
            "candidate_cases": len(candidates), "planned_cases": len(cases), "runtime_cases_executed": 0,
            "prefix_vectors_executed": 0, "raw_byte_relationships_checked": 3,
            "fixture_sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Contract root for isolated rejection checks")
    parser.add_argument("--report", type=Path, help="New retained report path; existing files refused")
    args = parser.parse_args()
    report = check(args.root)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(f"Coverage contract passed: {report['profiles']} profiles, {report['record_cases']} record cases "
          f"({report['structural_accepts']} accepted / {report['structural_rejects']} rejected), "
          f"{report['assessment_cases']} assessment fixtures, {report['transition_sequences']} transition sequences")
    print("Structural checks only; Rust semantic/assessment tests are separate; this checker verifies no source proofs")
    history = report["history_contract"]
    print(f"History inventory: {history['requirements']} requirements, {history['candidate_cases']} candidates, "
          f"{history['planned_cases']} planned cases; no history runtime or prefix-vector execution")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        print(f"Coverage contract check failed: {error}", file=sys.stderr)
        sys.exit(1)
