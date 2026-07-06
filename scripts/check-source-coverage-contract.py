#!/usr/bin/env python3
"""Check the offline SourceCoverage schemas and fixture inventory.

This checker supports only the structural keywords used in the two owned schemas.
It rejects unknown schema keywords and remote references. It does not assert
format annotations, execute semantic assessments or qualify production coverage.
"""

import argparse
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
        require(a["runtime_status"] == "planned", "assessment incorrectly marked implemented")
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
            "record_outcomes": outcomes}


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
          f"{report['assessment_cases']} planned assessments, {report['transition_sequences']} transition sequences")
    print("Structural keyword checks only; semantic/current-health transitions and source proof validation remain planned")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        print(f"Coverage contract check failed: {error}", file=sys.stderr)
        sys.exit(1)
