#!/usr/bin/env python3
"""Check offline synthetic design witnesses, never normalize arbitrary source data.

Only the ACK witness describes an implemented runtime contract. Native projection,
identity and custody cases specify the next Rust task; this is not a collector,
normalizer, receipt engine, cloud qualification or source-health assessment.
"""
import argparse
from datetime import datetime
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cloudtrail-source/contract.json"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 16
LIMITS = {
    "max_compressed_object_bytes": 8 * 1024 * 1024,
    "max_decoded_object_bytes": 32 * 1024 * 1024,
    "max_native_records": 1024,
    "max_native_record_bytes": 256 * 1024,
    "max_json_depth": 16,
    "max_normalized_event_bytes": 64 * 1024,
    "max_prepared_bytes": 16 * 1024 * 1024,
    "max_binary_receipt_bytes": 32 * 1024 * 1024,
    "max_pending_receipts": 1,
    "minimum_working_disk_bytes": 64 * 1024 * 1024,
    "transient_reserve_bytes": 128 * 1024 * 1024,
    "max_metadata_bytes": 1024 * 1024,
    "max_framing_bytes": 64 * 1024,
    "max_control_bytes": 8 * 1024 * 1024,
    "max_control_replacement_bytes": 8 * 1024 * 1024,
    "root_index_allowance_bytes": 4 * 1024 * 1024,
    "parser_http_scratch_bytes": 16 * 1024 * 1024,
    "transient_index_bytes": 1024 * 1024,
    "max_ack_bytes": 64 * 1024,
    "allocation_allowance_bytes": 16 * 1024 * 1024,
    "max_notification_bytes": 256 * 1024,
    "max_notification_object_refs": 16,
}
REQUIRED_PATHS = ["eventVersion", "eventID", "eventTime", "eventSource", "eventName",
                  "awsRegion", "eventType", "recipientAccountId", "managementEvent"]
MAPPINGS = [
    {"event_source": "ec2.amazonaws.com", "event_name": "DescribeInstances", "condition": None,
     "action": "resource.activity", "control": None},
    {"event_source": "cloudtrail.amazonaws.com", "event_name": "StopLogging", "condition": None,
     "action": "audit.stop", "control": None},
    {"event_source": "cloudtrail.amazonaws.com", "event_name": "DeleteTrail", "condition": None,
     "action": "audit.delete", "control": None},
    {"event_source": "signin.amazonaws.com", "event_name": "ConsoleLogin", "condition": None,
     "action": "identity.console_login", "control": None},
    {"event_source": "guardduty.amazonaws.com", "event_name": "UpdateDetector",
     "condition": {"path": "requestParameters.enable", "equals": False},
     "action": "control.disable", "control": "guardduty"},
    {"event_source": "guardduty.amazonaws.com", "event_name": "DeleteDetector", "condition": None,
     "action": "control.disable", "control": "guardduty"},
    {"event_source": "securityhub.amazonaws.com", "event_name": "DisableSecurityHub", "condition": None,
     "action": "control.disable", "control": "securityhub"},
    {"event_source": "config.amazonaws.com", "event_name": "StopConfigurationRecorder", "condition": None,
     "action": "control.disable", "control": "config"},
]
NATIVE_IDS = {
    "root-activity", "iam-activity", "root-stop-logging", "delete-trail", "stop-logging-failed",
    "console-iam-no-mfa", "console-root-no-mfa", "console-iam-mfa", "console-failed",
    "console-missing-mfa", "console-federated-no-mfa", "console-conflicting-error",
    "guardduty-update-disable", "guardduty-delete", "securityhub-disable", "config-stop",
    "guardduty-update-enable", "guardduty-update-missing-enable", "guardduty-update-string-false",
    "disable-failed", "wrong-service-stop-logging", "missing-actor", "missing-response",
    "message-without-error-code", "nested-error-code", "malformed-response", "unsupported-action",
    "missing-event-id", "invalid-timestamp", "unsupported-major", "unsupported-old-minor",
    "additive-new-minor", "non-management", "wrong-category", "missing-recipient",
    "recipient-scope-denied", "actor-cross-account", "duplicate-root-copy", "distinct-identical-message",
    "same-id-changed-bytes",
    "wrong-event-kind",
}
CUSTODY_IDS = {
    "pinned-before-send", "ack-partial-prefix", "lost-response", "crash-before-receipt-commit",
    "crash-after-receipt-before-progress", "duplicate-sqs-delivery", "parser-upgrade-pending",
    "divergent-restore", "expired-original", "restore-pending", "receipt-quota",
    "decompression-limit", "late-out-of-order", "cross-account-route", "poison-explicit-disposition",
    "coverage-independent",
    "local-m1-not-host-loss", "m2-not-strong-custody", "multi-reference-all-owned",
}
ACK_IDS = {
    "full-202", "partial-429", "unavailable-503", "timeout-408", "reduce-413", "unauthorized-401",
    "invalid-event-400", "partial-202-invalid", "reordered-ids-invalid", "prefix-overrun-invalid",
    "partial-permanent-invalid", "missing-error-invalid", "wrong-status-invalid",
    "wrong-schema-invalid", "counts-invalid", "error-index-invalid", "lost-response-zero",
    "cancelled-zero", "response-limit-zero",
}
SCOPE = {
    "synthetic_only": True, "runtime_normalizer_implemented": False,
    "runtime_receipts_implemented": False, "cloud_qualified": False,
    "checker_kind": "offline_design_witness_checker",
    "ack_kind": "implemented_rust_ack_witness_model",
    "native_kind": "planned_rust_profile_projection_witnesses",
    "custody_kind": "planned_unexecuted_scenarios",
}
CUSTODY_EXPECTATIONS = {
    "pinned-before-send": "Durably pin exact original/hash/version, normalized bytes, event IDs, observed_at and profile revision before any send; planned crash acceptance remains required.",
    "ack-partial-prefix": "Only a verified M2 prefix can advance local accepted progress; retain exact remaining pinned bytes; this persistence behavior is planned.",
    "lost-response": "Advance zero; replay the pinned batch IDs and bytes after reconciling receipt state. Downstream replay may duplicate already admitted events.",
    "crash-before-receipt-commit": "No send before preparation commit; restart must retain only complete committed receipt state. Actual crash qualification is planned.",
    "crash-after-receipt-before-progress": "Recover immutable prepared IDs/bytes and replay uncertain suffix; do not regenerate normalizer output or assume exactly once.",
    "duplicate-sqs-delivery": "Delivery handle and SQS message ID do not replace stable native/source identity; retain duplicate disposition and custody obligations.",
    "parser-upgrade-pending": "Replay stored prepared bytes under the originally pinned revision; never renormalize pending input with a new parser.",
    "divergent-restore": "History or source witness mismatch rejects progress; absence from a backup does not authorize a new source acceptance.",
    "expired-original": "Do not claim rehydratable evidence; report unavailable original and recovery uncertainty, not no-match or healthy coverage.",
    "restore-pending": "Pending receipt continues to hold its slot and custody obligation until authoritative source evidence can be reconciled.",
    "receipt-quota": "Backpressure before allocation or source acknowledgement; preserve unexpired receipt and original; no eviction.",
    "decompression-limit": "Stop before decoded/native/depth limits; retain explicit poison or oversized disposition and source reference; planned gzip acceptance is not executed here.",
    "late-out-of-order": "Native event time is preserved and never replaced by preparation observed_at; delivery order does not establish coverage continuity.",
    "cross-account-route": "Trusted recipient scope authorizes routing; actor account may differ and must not be used as recipient authority.",
    "poison-explicit-disposition": "Retain source custody and typed poison disposition; no silent successful delete or fresh health assertion.",
    "coverage-independent": "M2 proves synced WAL admission only; selectors, delivery continuity, source digest and observer freshness require independent evidence.",
    "local-m1-not-host-loss": "Local M1 may transfer process-recovery responsibility only under explicit owner acceptance; it does not prove host, AZ or account loss recovery.",
    "m2-not-strong-custody": "Verified M2 alone cannot authorize source deletion under a host-loss or protected-original custody requirement; require the selected independent witness.",
    "multi-reference-all-owned": "The first local adapter supports one reference per message; 16 is only a parser/work cap. Hold multi-reference messages unsupported with source ACK blocked until separately qualified bounded control and handoff own every original, replay and pending-work obligation; never evict an unexpired receipt to advance.",
}


def same_json(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), f"{label}: unexpected keys")


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, f"{label}: invalid integer")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def depth_before_parse(raw):
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            require(depth <= MAX_DEPTH, "JSON exceeds depth 16")
        elif byte in (125, 93):
            depth -= 1
            require(depth >= 0, "unbalanced JSON")
    require(depth == 0 and not quoted, "incomplete JSON")


def strict_json(raw, limit=MAX_FILE_BYTES):
    require(type(raw) is bytes and len(raw) <= limit, "JSON byte limit exceeded")
    depth_before_parse(raw)
    def nonfinite(_):
        raise ValueError("nonfinite JSON number")
    def finite_float(value):
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite JSON number")
        return parsed
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=nonfinite, parse_float=finite_float)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_uuid(value):
    require(type(value) is str, "UUID must be a string")
    parsed = uuid.UUID(value)
    require(parsed.int != 0 and str(parsed) == value, "noncanonical or nil UUID")
    return value


def utc(value):
    require(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value),
            "timestamp must be explicit UTC")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def path_value(value, path):
    for part in path.split("."):
        if type(value) is not dict or part not in value:
            return None
        value = value[part]
    return value


@lru_cache(maxsize=1)
def current_catalog():
    with (ROOT / "tests/fixtures/security-requirements/catalog.json").open("rb") as stream:
        return strict_json(stream.read(MAX_FILE_BYTES + 1))


def catalog_matches(security, legacy=True):
    # Preserve the design's legacy action-filter witness alongside the selected
    # D01 profile. This models predicates; Rust tests qualify native normalization.
    catalog = current_catalog()
    result = []
    for detection in catalog["detections"]:
        if detection["id"] not in {"SIG-D01", "SIG-D02", "SIG-D03", "SIG-D05"}:
            continue
        match = detection["native_rule"]["spec"]["match"]
        event = {"source": {"type": "cloudtrail"}, "attributes": {"security": security}}
        def witness(term):
            return set(term) == {"field", "eq"} and type(path_value(event, term["field"])) is type(term["eq"]) and path_value(event, term["field"]) == term["eq"]
        if legacy and detection["id"] == "SIG-D01" and security.get("action") != "resource.activity":
            continue
        if all(witness(t) for t in match.get("all", [])) and ("any" not in match or any(witness(t) for t in match["any"])):
            result.append(detection["id"])
    return result


def projection_witness(native, route, raw_sha, ordinal):
    """Literal design expectations for bounded synthetic cases; no canonical event or ID generation."""
    empty = {"disposition": "quarantine_record", "reason_codes": [], "security": {},
             "cloudtrail": {}, "catalog_matches": [], "proposed_matches": []}
    def quarantined(reason):
        return dict(empty, reason_codes=[reason])
    if type(native) is not dict or any(k not in native for k in REQUIRED_PATHS):
        return quarantined("missing_required_native")
    if any(type(native[k]) is not str or not native[k] for k in REQUIRED_PATHS[:-1]):
        return quarantined("malformed_required_native")
    try:
        canonical_uuid(native["eventID"])
        utc(native["eventTime"])
    except (ValueError, TypeError):
        return quarantined("malformed_required_native")
    version = re.fullmatch(r"(\d+)\.(\d+)", native["eventVersion"])
    if not version or int(version[1]) != 1 or int(version[2]) < 6:
        return quarantined("unsupported_native_version")
    if native["managementEvent"] is not True or native.get("eventCategory", "Management") != "Management":
        return quarantined("unsupported_event_category")
    if native["eventType"] not in {"AwsApiCall", "AwsConsoleSignIn"} or not re.fullmatch(r"\d{12}", native["recipientAccountId"]):
        return quarantined("malformed_required_native")
    if native["recipientAccountId"] not in route["allowed_recipient_accounts"] or native["awsRegion"] not in route["allowed_regions"]:
        return quarantined("recipient_route_not_authorized")
    cloud = {"event_id": native["eventID"], "event_source": native["eventSource"],
             "event_name": native["eventName"], "event_version": native["eventVersion"],
             "event_type": native["eventType"], "recipient_account_id": native["recipientAccountId"],
             "region": native["awsRegion"], "record_ordinal": ordinal, "record_sha256": raw_sha}
    identity = native.get("userIdentity")
    security, reasons = {}, []
    if type(identity) is dict and type(identity.get("type")) is str and identity["type"]:
        security["actor_kind"] = identity["type"]
        if type(identity.get("accountId")) is str:
            cloud["actor_account_id"] = identity["accountId"]
    else:
        reasons.append("missing_actor")
    if type(native.get("sourceIPAddress")) is str:
        cloud["source_ip_address"] = native["sourceIPAddress"]
    mapping = next((m for m in MAPPINGS if m["event_source"] == native["eventSource"] and m["event_name"] == native["eventName"]), None)
    if mapping and native["eventType"] != ("AwsConsoleSignIn" if mapping["action"] == "identity.console_login" else "AwsApiCall"):
        mapping = None
    if mapping and mapping["condition"] and path_value(native, mapping["condition"]["path"]) is not False:
        mapping = None
    if mapping is None:
        reasons.append("unsupported_operation")
    else:
        security["action"] = mapping["action"]
        if mapping["control"]:
            security["control"] = mapping["control"]
        errors = [native.get("errorCode"), path_value(native, "responseElements.errorCode")]
        messages = [native.get("errorMessage"), path_value(native, "responseElements.errorMessage")]
        fields_present = [k in native for k in ("errorCode", "errorMessage")]
        response = native.get("responseElements")
        fields_present += [type(response) is dict and k in response for k in ("errorCode", "errorMessage")]
        malformed = any(present and (type(value) is not str or not value) for present, value in zip(fields_present, [errors[0], messages[0], errors[1], messages[1]]))
        has_code = any(type(v) is str and v for v in errors)
        has_message = any(type(v) is str and v for v in messages)
        outcome = None
        if mapping["action"] == "identity.console_login":
            login = path_value(native, "responseElements.ConsoleLogin")
            if login == "Success" and not has_code and not has_message and not malformed:
                outcome = "success"
            elif login == "Failure" and not malformed:
                outcome = "failure"
            mfa = path_value(native, "additionalEventData.MFAUsed")
            if security.get("actor_kind") in {"IAMUser", "Root"}:
                if mfa in ("Yes", "No"):
                    security["mfa_used"] = mfa == "Yes"
                else:
                    reasons.append("missing_or_unsupported_mfa")
            else:
                reasons.append("unsupported_actor_mfa")
        elif not malformed and has_code:
            outcome = "failure"
        elif not malformed and not has_message and "responseElements" in native and (response is None or type(response) is dict):
            outcome = "success"
        if outcome is None:
            reasons.append("unknown_operation_outcome")
        else:
            security["outcome"] = outcome
    current = catalog_matches(security)
    future = catalog_matches(security, legacy=False)
    return {"disposition": "emit_indeterminate" if reasons else "emit", "reason_codes": reasons,
            "security": security, "cloudtrail": cloud, "catalog_matches": current, "proposed_matches": future}


def ack_witness(status, response, batch_ids):
    """Pure witness for the current Rust HTTP verify function, not transport or progress persistence."""
    invalid = {"accepted": 0, "disposition": "error", "error": "InvalidResponse"}
    if type(response) is not dict or type(status) is not int:
        return invalid
    if response.get("schema_version") != 1 or type(response.get("schema_version")) is not int:
        return invalid
    accepted, rejected = response.get("accepted"), response.get("rejected")
    ids = response.get("event_ids")
    if type(accepted) is not int or type(rejected) is not int or accepted < 0 or rejected < 0 or accepted > len(batch_ids) or type(ids) is not list or len(ids) != accepted or ids != batch_ids[:accepted]:
        return invalid
    error = response.get("error")
    if status == 202:
        if accepted != len(batch_ids) or rejected != 0 or error is not None:
            return invalid
        return {"accepted": accepted, "disposition": "Complete", "error": None}
    if type(error) is not dict:
        return invalid
    code, index = error.get("code"), error.get("index")
    if type(code) is not str or type(error.get("message")) is not str:
        return invalid
    if index is not None and (type(index) is not int or index < 0):
        return invalid
    retry = {(429, "full"), (408, "request_timeout"), (503, "unavailable"), (503, "stopping")}
    reduce = {(413, "batch_too_large"), (413, "payload_too_large")}
    permanent = {(401, "unauthorized"), (400, "invalid_json"), (400, "invalid_event"),
                 (400, "unsupported_version"), (400, "empty_batch"), (404, "not_found"),
                 (405, "method_not_allowed"), (415, "unsupported_media_type")}
    pair = (status, code)
    disposition = "Retry" if pair in retry else "ReduceBatch" if pair in reduce else "Permanent" if pair in permanent else None
    if disposition is None or (accepted + rejected != len(batch_ids) and not (accepted == 0 and rejected == 0 and index is None)):
        return invalid
    if accepted and (disposition != "Retry" or accepted == len(batch_ids) or index != accepted):
        return invalid
    if not accepted and index is not None and (index >= len(batch_ids) or (disposition == "Retry" and code != "request_timeout" and index != 0)):
        return invalid
    return {"accepted": accepted, "disposition": disposition, "error": None}


def inventory(cases, expected, label):
    require(type(cases) is list and 0 < len(cases) <= 128, f"{label}: unbounded inventory")
    identifiers = [c.get("id") if type(c) is dict else None for c in cases]
    require(all(type(i) is str for i in identifiers) and len(set(identifiers)) == len(identifiers) and set(identifiers) == expected, f"{label}: missing or duplicate scenario IDs")


def validate_contract(contract):
    keys(contract, {"schema_version", "status", "scope", "profile", "limits", "native_cases", "source_identity_contract", "source_identity_cases", "object_identity_contract", "object_identity_cases", "prepared_cases", "ack_contract", "ack_cases", "custody_cases"}, "contract")
    require(type(contract["schema_version"]) is int and contract["schema_version"] == 1 and contract["status"] == "design_contract_only", "unsupported fixture schema/status")
    require(same_json(contract["scope"], SCOPE), "qualification or phase scope changed")
    keys(contract["limits"], LIMITS, "limits")
    for name, value in LIMITS.items():
        integer(contract["limits"][name], 1, 128 * 1024 * 1024, name)
        require(contract["limits"][name] == value, f"{name}: frozen laboratory design limit changed")
    require(sum(LIMITS[k] for k in ("max_compressed_object_bytes", "max_prepared_bytes", "max_metadata_bytes", "max_framing_bytes")) <= LIMITS["max_binary_receipt_bytes"], "one receipt reserve")
    require(sum(LIMITS[k] for k in ("max_binary_receipt_bytes", "max_compressed_object_bytes", "max_control_bytes", "max_control_replacement_bytes", "root_index_allowance_bytes")) <= LIMITS["minimum_working_disk_bytes"], "working disk reserve")
    require(sum(LIMITS[k] for k in ("max_compressed_object_bytes", "max_decoded_object_bytes", "max_prepared_bytes", "max_binary_receipt_bytes", "parser_http_scratch_bytes", "max_metadata_bytes", "transient_index_bytes", "max_ack_bytes", "allocation_allowance_bytes")) <= LIMITS["transient_reserve_bytes"], "transient reserve")
    keys(contract["profile"], {"id", "revision", "source_type", "native_version", "required_native_paths", "action_mappings", "future_d01_change"}, "profile")
    require(same_json(contract["profile"], {"id": "cloudtrail-management", "revision": "v1", "source_type": "cloudtrail", "native_version": {"major": 1, "minimum_minor": 6, "accept_additive_minor": True}, "required_native_paths": REQUIRED_PATHS, "action_mappings": MAPPINGS, "future_d01_change": "remove_resource_activity_action_constraint_in_next_rust_task"}), "profile mapping contract changed")
    inventory(contract["native_cases"], NATIVE_IDS, "native")
    cases = {}
    for case in contract["native_cases"]:
        keys(case, {"id", "raw_utf8", "raw_sha256", "record_ordinal", "trusted_route", "expected"}, case["id"])
        require(type(case["raw_utf8"]) is str, "native bytes must be literal UTF-8")
        raw = case["raw_utf8"].encode()
        require(case["raw_sha256"] == sha(raw), "native original hash mismatch")
        integer(case["record_ordinal"], 0, 1023, "record ordinal")
        route = case["trusted_route"]
        keys(route, {"route_id", "allowed_recipient_accounts", "allowed_regions"}, "trusted route")
        require(same_json(route, {"route_id": "fixture-cloudtrail-route", "allowed_recipient_accounts": ["111122223333"], "allowed_regions": ["us-east-1"]}), "trusted scope changed")
        native = strict_json(raw, LIMITS["max_native_record_bytes"])
        expected = projection_witness(native, route, case["raw_sha256"], case["record_ordinal"])
        keys(case["expected"], expected, "expected projection")
        require(same_json(case["expected"], expected), f"{case['id']}: native mapping witness mismatch")
        cases[case["id"]] = (case, native)
    seen_native = {}
    for case, native in cases.values():
        if "eventID" in native:
            seen_native.setdefault(native["eventID"], set()).add(case["id"])
    for names in seen_native.values():
        require(len(names) == 1 or names == {"root-activity", "duplicate-root-copy", "same-id-changed-bytes"}, "undeclared duplicate native event identity")
    identity = contract["source_identity_contract"]
    require(same_json(identity, {"runtime_status": "planned", "identity_scope": "observational_native_identity_comparison_only", "no_global_dedupe": True, "key_fields": ["trusted_route.route_id", "recipientAccountId", "awsRegion", "eventID"], "excluded_delivery_fields": ["sqs_receipt_handle", "etag", "object_last_modified"], "hash_policy": "sha256_original_bytes_not_etag"}), "source identity scope changed")
    inventory(contract["source_identity_cases"], {"duplicate-native-event", "distinct-identical-messages", "same-native-id-content-conflict"}, "source identity")
    for case in contract["source_identity_cases"]:
        keys(case, {"id", "left_case", "right_case", "expected_relation", "runtime_status"}, "identity case")
        require(case["runtime_status"] == "planned", "identity runtime claim")
        left, right = cases[case["left_case"]], cases[case["right_case"]]
        def identity_key(pair):
            c, native = pair
            return (c["trusted_route"]["route_id"], native["recipientAccountId"], native["awsRegion"], native["eventID"])
        same_key = identity_key(left) == identity_key(right)
        relation = "duplicate_same_native_identity" if same_key and left[0]["raw_utf8"] == right[0]["raw_utf8"] else "same_id_changed_bytes_conflict" if same_key else "distinct_native_identity"
        require(case["expected_relation"] == relation, "source identity relation mismatch")
        if case["id"] == "distinct-identical-messages":
            require(same_json(left[0]["expected"]["security"], right[0]["expected"]["security"]) and not same_key, "distinct identical-message witness")
    require(same_json(contract["object_identity_contract"], {"runtime_status": "planned", "identity_scope": "retained_receipt_only", "key_fields": ["trusted_scope", "bucket", "key", "version_id"], "compare_exact_original_bytes": True, "sha256_is_witness_only": True, "no_global_native_dedupe": True}), "object replay identity contract changed")
    inventory(contract["object_identity_cases"], {"same-object-new-delivery", "same-version-changed-bytes", "new-version-identical-bytes", "changed-scope"}, "object identity")
    for case in contract["object_identity_cases"]:
        keys(case, {"id", "left", "right", "left_delivery_handle", "right_delivery_handle", "expected_relation", "runtime_status"}, "object identity witness")
        require(case["runtime_status"] == "planned", "object receipt runtime claim")
        for name in ("left_delivery_handle", "right_delivery_handle"):
            require(type(case[name]) is str and case[name].startswith("fixture-handle-") and len(case[name]) <= 128, "synthetic delivery handle")
        original_bytes = []
        for obj in (case["left"], case["right"]):
            keys(obj, {"trusted_scope", "bucket", "key", "version_id", "original_hex", "original_sha256"}, "object reference")
            scope = obj["trusted_scope"]
            keys(scope, {"route_id", "account_id", "region", "configuration_revision"}, "object trusted scope")
            require(scope["route_id"] == "fixture-cloudtrail-route" and scope["account_id"] == "111122223333" and scope["region"] == "us-east-1" and scope["configuration_revision"] in {"fixture-config-v1", "fixture-config-v2"}, "object authority scope")
            require(obj["bucket"] == "fixture-cloudtrail-originals" and obj["key"] == "fixture/cloudtrail/management.json.gz" and obj["version_id"] in {"fixture-version-1", "fixture-version-2"}, "object version reference")
            require(type(obj["original_hex"]) is str and len(obj["original_hex"]) <= 2 * LIMITS["max_compressed_object_bytes"] and re.fullmatch(r"(?:[0-9a-f]{2})+", obj["original_hex"]), "original bytes encoding")
            raw = bytes.fromhex(obj["original_hex"])
            require(obj["original_sha256"] == sha(raw), "object original hash mismatch")
            original_bytes.append(raw)
        left, right = case["left"], case["right"]
        if not same_json(left["trusted_scope"], right["trusted_scope"]):
            relation = "scope_change_requires_fresh_authority"
        elif any(left[k] != right[k] for k in ("bucket", "key", "version_id")):
            relation = "distinct_object_version"
        elif original_bytes[0] != original_bytes[1]:
            relation = "changed_original_bytes_conflict"
        else:
            relation = "same_retained_object_replay_key"
        require(case["expected_relation"] == relation, "object identity witness mismatch")
        if case["id"] == "same-object-new-delivery":
            require(case["left_delivery_handle"] != case["right_delivery_handle"] and relation == "same_retained_object_replay_key", "delivery handle used as object identity")
    inventory(contract["prepared_cases"], {"pinned-root-activity", "pinned-iam-activity"}, "prepared")
    for pin in contract["prepared_cases"]:
        keys(pin, {"id", "native_case", "runtime_status", "prepared_uuid", "prepared_observed_at", "raw_utf8", "sha256", "normalizer_id", "normalizer_revision", "original_ref"}, "prepared pin")
        require(pin["runtime_status"] == "planned" and pin["normalizer_id"] == "cloudtrail-management" and pin["normalizer_revision"] == "v1", "prepared version pin")
        canonical_uuid(pin["prepared_uuid"])
        utc(pin["prepared_observed_at"])
        witnesses = {"pinned-root-activity": ("root-activity", "20000000-0000-4000-8000-000000000001", 0), "pinned-iam-activity": ("iam-activity", "20000000-0000-4000-8000-000000000002", 1)}
        native_case, prepared_id, ordinal = witnesses[pin["id"]]
        require(pin["native_case"] == native_case and pin["prepared_uuid"] == prepared_id and pin["prepared_observed_at"] == "2026-10-07T12:00:01Z", "fixed preparation witness changed")
        require(type(pin["raw_utf8"]) is str and sha(pin["raw_utf8"].encode()) == pin["sha256"], "pinned prepared bytes hash mismatch")
        event = strict_json(pin["raw_utf8"].encode(), LIMITS["max_normalized_event_bytes"])
        keys(event, {"schema_version", "id", "timestamp", "observed_at", "source", "severity", "message", "attributes", "tags", "resource"}, "prepared event")
        require(event["schema_version"] == 1 and type(event["schema_version"]) is int and event["id"] == pin["prepared_uuid"] and event["observed_at"] == pin["prepared_observed_at"], "prepared identity/time mismatch")
        c, native = cases[pin["native_case"]]
        require(event["timestamp"] == native["eventTime"] and same_json(event["source"], {"type": "cloudtrail", "name": "cloudtrail-management"}), "prepared source/time mismatch")
        require(event["severity"] == "info" and event["message"] == f"CloudTrail {native['eventSource']}/{native['eventName']}" and same_json(event["tags"], []), "prepared severity/message/tags mismatch")
        require(same_json(event["resource"], {"kind": "aws_account", "id": "111122223333", "account_id": "111122223333", "region": "us-east-1"}), "prepared trusted resource mismatch")
        require(c["record_ordinal"] == ordinal, "prepared ordinal witness")
        require(same_json(event["attributes"], {"security": c["expected"]["security"], "aws": {"cloudtrail": c["expected"]["cloudtrail"]}, "evidence_ref": f"receipt://30000000-0000-4000-8000-000000000001/record/{ordinal}", "normalizer": {"id": "cloudtrail-management", "revision": "v1"}}), "prepared mapping/provenance mismatch")
        keys(pin["original_ref"], {"uri", "version_id", "record_sha256", "record_ordinal", "etag_is_content_hash"}, "original reference")
        require(same_json(pin["original_ref"], {"uri": "fixture://cloudtrail/management-original", "version_id": "fixture-version-1", "record_sha256": c["raw_sha256"], "record_ordinal": c["record_ordinal"], "etag_is_content_hash": False}), "source original version/hash pin mismatch")
    require(same_json(contract["ack_contract"], {"runtime_status": "implemented_witness_only", "implementation": "apps/signal-agent/src/http.rs::verify", "milestone": "M2_synced_WAL_admission_only", "prepared_before_send": True, "uncertain_response_advances_zero": True}), "ACK contract scope changed")
    inventory(contract["ack_cases"], ACK_IDS, "ACK")
    for case in contract["ack_cases"]:
        keys(case, {"id", "batch_ids", "status", "response", "transport_error", "expected"}, "ACK case")
        require(type(case["batch_ids"]) is list and 1 <= len(case["batch_ids"]) <= 1024, "ACK batch bound")
        require(len(set(case["batch_ids"])) == len(case["batch_ids"]), "duplicate prepared batch ID")
        for value in case["batch_ids"]:
            canonical_uuid(value)
        require(case["batch_ids"] == [p["prepared_uuid"] for p in contract["prepared_cases"]], "ACK detached from pinned ordered IDs")
        transport = case["transport_error"]
        if transport is not None:
            require(transport in {"Transport", "Cancelled", "ResponseLimit"} and case["status"] is None and case["response"] is None, "invalid transport witness")
            expected = {"accepted": 0, "disposition": "error", "error": transport}
        else:
            integer(case["status"], 100, 599, "HTTP status")
            keys(case["response"], {"schema_version", "accepted", "rejected", "event_ids", "error"}, "ACK envelope")
            error = case["response"]["error"]
            if error is not None:
                keys(error, {"code", "message", "index"}, "ACK error")
                require(type(error["code"]) is str and type(error["message"]) is str, "ACK error fields")
            expected = ack_witness(case["status"], case["response"], case["batch_ids"])
        keys(case["expected"], expected, "ACK expectation")
        require(same_json(case["expected"], expected), f"{case['id']}: ACK/progress witness mismatch")
    inventory(contract["custody_cases"], CUSTODY_IDS, "custody")
    for case in contract["custody_cases"]:
        keys(case, {"id", "runtime_status", "expected", "proof_kind"}, "custody case")
        require(case["runtime_status"] == "planned" and case["proof_kind"] == "declarative_unexecuted", "custody runtime qualification claim")
        require(case["expected"] == CUSTODY_EXPECTATIONS[case["id"]], "custody safety expectation changed")
    return {"native_cases": len(cases), "source_identity_cases": len(contract["source_identity_cases"]), "object_identity_cases": len(contract["object_identity_cases"]), "prepared_cases": len(contract["prepared_cases"]), "ack_witnesses": len(contract["ack_cases"]), "planned_custody_cases": len(contract["custody_cases"])}


def load_contract(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    contract = strict_json(raw)
    validate_contract(contract)
    return contract, sha(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        contract, digest = load_contract(args.fixture)
        stats = validate_contract(contract)
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError, OverflowError) as error:
        print(f"CloudTrail contract rejected: {error}", file=sys.stderr)
        return 1
    report = {"status": "passed", **stats, "sha256": digest, "scope": "offline_design_and_ACK_witnesses_only"}
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"CloudTrail contract: {stats['native_cases']} native, {stats['source_identity_cases']} identity, {stats['prepared_cases']} prepared, {stats['ack_witnesses']} ACK witnesses, {stats['planned_custody_cases']} planned custody; {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
