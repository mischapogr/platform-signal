#!/usr/bin/env python3
"""Independent tampering checks for offline CloudTrail design witnesses only."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check-cloudtrail-source-contract.py")
FIXTURE = CHECKER.parent.parent / "tests/fixtures/cloudtrail-source/contract.json"
SPEC = importlib.util.spec_from_file_location("cloudtrail_design_checker", CHECKER)
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def case(document, inventory, identifier):
    return next(value for value in document[inventory] if value["id"] == identifier)


def rewrite_prepared(document, change):
    pin = document["prepared_cases"][0]
    event = json.loads(pin["raw_utf8"])
    change(event)
    pin["raw_utf8"] = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
    pin["sha256"] = sha(pin["raw_utf8"].encode())


class DesignTampering(unittest.TestCase):
    rejection_checks = 0

    @classmethod
    def setUpClass(cls):
        cls.original, cls.digest = c.load_contract(FIXTURE)

    def reject(self, change):
        document = copy.deepcopy(self.original)
        change(document)
        with self.assertRaises(ValueError):
            c.validate_contract(document)
        type(self).rejection_checks += 1

    def reject_file(self, raw):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mutated.json"
            path.write_bytes(raw)
            result = subprocess.run(
                [sys.executable, str(CHECKER), "--fixture", str(path), "--json"],
                capture_output=True, text=True, timeout=15, check=False,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CloudTrail contract rejected:", result.stderr)
        self.assertNotIn('"status": "passed"', result.stdout)
        type(self).rejection_checks += 1

    def test_original_document_and_cli_are_accepted(self):
        self.assertEqual(self.digest, sha(FIXTURE.read_bytes()))
        result = subprocess.run(
            [sys.executable, str(CHECKER), "--fixture", str(FIXTURE), "--json"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["sha256"], self.digest)
        self.assertEqual(report["scope"], "offline_design_and_ACK_witnesses_only")
        self.assertEqual(report["native_cases"], len(self.original["native_cases"]))
        self.assertEqual(report["ack_witnesses"], len(self.original["ack_cases"]))

    def test_missing_required_sections_and_empty_inventories_reject(self):
        for field in self.original:
            with self.subTest(missing=field):
                self.reject(lambda d, field=field: d.pop(field))
        for field in (key for key in self.original if key.endswith("_cases")):
            with self.subTest(empty=field):
                self.reject(lambda d, field=field: d.__setitem__(field, []))

    def test_removed_duplicate_or_renamed_scenarios_reject(self):
        for field in (key for key in self.original if key.endswith("_cases")):
            for mode in ("remove", "duplicate", "rename"):
                with self.subTest(inventory=field, mode=mode):
                    def change(d, field=field, mode=mode):
                        if mode == "remove":
                            d[field].pop()
                        elif mode == "duplicate":
                            d[field].append(copy.deepcopy(d[field][0]))
                        else:
                            d[field][0]["id"] = "unreviewed-scenario"
                    self.reject(change)

    def test_scope_cannot_be_upgraded_or_retyped(self):
        mutations = {"synthetic_only": False, "runtime_normalizer_implemented": True,
                     "runtime_receipts_implemented": True, "cloud_qualified": True,
                     "checker_kind": "qualified_collector", "custody_kind": "executed"}
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.reject(lambda d, field=field, value=value: d["scope"].__setitem__(field, value))
        for field in ("synthetic_only", "cloud_qualified"):
            with self.subTest(type_alias=field):
                self.reject(lambda d, field=field: d["scope"].__setitem__(field, int(d["scope"][field])))
        self.reject(lambda d: d.__setitem__("status", "runtime_accepted"))

    def test_every_frozen_limit_is_required_positive_typed_and_exact(self):
        for field in self.original["limits"]:
            for value in (0, True, float(self.original["limits"][field]),
                          self.original["limits"][field] + 1):
                with self.subTest(field=field, value=value):
                    self.reject(lambda d, field=field, value=value: d["limits"].__setitem__(field, value))
            with self.subTest(missing=field):
                self.reject(lambda d, field=field: d["limits"].pop(field))

    def test_profile_required_paths_and_service_qualification_are_frozen(self):
        self.reject(lambda d: d["profile"]["required_native_paths"].remove("recipientAccountId"))
        self.reject(lambda d: d["profile"]["action_mappings"][1].__setitem__("event_source", "unrelated.amazonaws.com"))
        self.reject(lambda d: d["profile"]["action_mappings"][4]["condition"].__setitem__("equals", 0))
        self.reject(lambda d: d["profile"]["native_version"].__setitem__("major", True))
        self.reject(lambda d: d["profile"].__setitem__("revision", "current-catalog"))

    def test_native_expected_security_fields_are_checked(self):
        for field, wrong in (("actor_kind", "IAMUser"), ("action", "audit.stop"), ("outcome", "failure")):
            with self.subTest(field=field):
                self.reject(lambda d, field=field, wrong=wrong: case(d, "native_cases", "root-activity")["expected"]["security"].__setitem__(field, wrong))
        self.reject(lambda d: case(d, "native_cases", "console-iam-no-mfa")["expected"]["security"].__setitem__("mfa_used", True))
        self.reject(lambda d: case(d, "native_cases", "console-federated-no-mfa")["expected"]["security"].__setitem__("mfa_used", False))
        self.reject(lambda d: case(d, "native_cases", "console-iam-no-mfa")["expected"]["security"].__setitem__("mfa_used", 0))

    def test_api_event_cannot_claim_supported_action_as_console_signin(self):
        def change(d):
            value = case(d, "native_cases", "root-stop-logging")
            native = json.loads(value["raw_utf8"])
            native["eventType"] = "AwsConsoleSignIn"
            value["raw_utf8"] = json.dumps(native, separators=(",", ":"))
            value["raw_sha256"] = sha(value["raw_utf8"].encode())
            value["expected"]["cloudtrail"]["record_sha256"] = value["raw_sha256"]
            value["expected"]["cloudtrail"]["event_type"] = "AwsConsoleSignIn"
            # Preserving the previous successful audit.stop oracle must be rejected.
        self.reject(change)

    def test_native_expected_provenance_and_disposition_are_checked(self):
        for field, wrong in (("event_id", "10000000-0000-4000-8000-000000000099"),
                             ("recipient_account_id", "444455556666"), ("region", "us-west-2"),
                             ("record_sha256", "0" * 64), ("record_ordinal", 1)):
            with self.subTest(field=field):
                self.reject(lambda d, field=field, wrong=wrong: case(d, "native_cases", "root-activity")["expected"]["cloudtrail"].__setitem__(field, wrong))
        self.reject(lambda d: case(d, "native_cases", "missing-event-id")["expected"].__setitem__("disposition", "emit"))
        self.reject(lambda d: case(d, "native_cases", "missing-actor")["expected"].__setitem__("reason_codes", []))

    def test_current_and_planned_predicate_oracles_are_distinct(self):
        value = case(self.original, "native_cases", "root-stop-logging")["expected"]
        self.assertEqual(value["catalog_matches"], ["SIG-D02"])
        self.assertEqual(value["proposed_matches"], ["SIG-D01", "SIG-D02"])
        self.reject(lambda d: case(d, "native_cases", "root-stop-logging")["expected"].__setitem__("catalog_matches", ["SIG-D01", "SIG-D02"]))
        self.reject(lambda d: case(d, "native_cases", "root-stop-logging")["expected"].__setitem__("proposed_matches", ["SIG-D02"]))

    def test_native_hash_and_trusted_route_cannot_be_substituted(self):
        self.reject(lambda d: case(d, "native_cases", "root-activity").__setitem__("raw_sha256", "0" * 64))
        self.reject(lambda d: case(d, "native_cases", "root-activity")["trusted_route"].__setitem__("allowed_recipient_accounts", ["222233334444"]))
        self.reject(lambda d: case(d, "native_cases", "root-activity")["trusted_route"].__setitem__("route_id", "another-authority"))

    def test_prepared_hash_identity_times_revision_and_source_are_pinned(self):
        self.reject(lambda d: d["prepared_cases"][0].__setitem__("sha256", "0" * 64))
        self.reject(lambda d: d["prepared_cases"][0].__setitem__("prepared_uuid", "20000000-0000-4000-8000-000000000099"))
        self.reject(lambda d: d["prepared_cases"][0].__setitem__("prepared_observed_at", "2026-10-07T12:01:01Z"))
        self.reject(lambda d: d["prepared_cases"][0].__setitem__("normalizer_revision", "v2"))
        for field, wrong in (("timestamp", "2026-10-07T12:01:00Z"), ("observed_at", "2026-10-07T12:01:01Z"),
                             ("source", {"type": "cloudtrail", "name": "another-profile"}),
                             ("id", "20000000-0000-4000-8000-000000000099")):
            with self.subTest(field=field):
                self.reject(lambda d, field=field, wrong=wrong: rewrite_prepared(d, lambda e: e.__setitem__(field, wrong)))

    def test_prepared_base_fields_reject_even_with_recomputed_hash(self):
        for field, wrong in (("severity", "critical"), ("message", "tampered text"),
                             ("tags", ["private-policy"]), ("resource", {"account_id": "444455556666", "region": "us-west-2"})):
            with self.subTest(field=field):
                self.reject(lambda d, field=field, wrong=wrong: rewrite_prepared(d, lambda e: e.__setitem__(field, wrong)))
        self.reject(lambda d: rewrite_prepared(d, lambda e: e["attributes"].__setitem__("evidence_ref", "receipt://wrong/record/0")))
        self.reject(lambda d: rewrite_prepared(d, lambda e: e["attributes"]["security"].__setitem__("outcome", "failure")))

    def test_original_version_hash_and_etag_role_are_checked(self):
        for field, wrong in (("version_id", "null"), ("record_sha256", "0" * 64),
                             ("record_ordinal", 1), ("etag_is_content_hash", True)):
            with self.subTest(field=field):
                self.reject(lambda d, field=field, wrong=wrong: d["prepared_cases"][0]["original_ref"].__setitem__(field, wrong))

    def test_ack_scope_never_promotes_m2_to_processing_or_archive(self):
        for field, wrong in (("milestone", "M4_completed"), ("prepared_before_send", False),
                             ("uncertain_response_advances_zero", False), ("runtime_status", "source_ACK_implemented")):
            with self.subTest(field=field):
                self.reject(lambda d, field=field, wrong=wrong: d["ack_contract"].__setitem__(field, wrong))

    def test_ack_order_counts_and_prefix_boundary_match_submitted_ids(self):
        self.reject(lambda d: case(d, "ack_cases", "full-202")["response"]["event_ids"].reverse())
        self.reject(lambda d: case(d, "ack_cases", "partial-429")["response"].__setitem__("event_ids", ["20000000-0000-4000-8000-000000000002"]))
        self.reject(lambda d: case(d, "ack_cases", "partial-429")["response"]["error"].__setitem__("index", 0))
        self.reject(lambda d: case(d, "ack_cases", "partial-429")["response"].__setitem__("rejected", 0))
        self.reject(lambda d: case(d, "ack_cases", "full-202")["response"].__setitem__("accepted", 3))
        self.reject(lambda d: case(d, "ack_cases", "full-202")["batch_ids"].__setitem__(0, "20000000-0000-4000-8000-000000000099"))
        def unpinned_second_id(d):
            value = case(d, "ack_cases", "full-202")
            value["batch_ids"][1] = "20000000-0000-4000-8000-000000000099"
            value["response"]["event_ids"][1] = value["batch_ids"][1]
            # The ACK is internally consistent, but its second ID has no pinned bytes.
        self.reject(unpinned_second_id)

    def test_ack_status_error_shape_and_partial_permanent_are_rejected(self):
        self.reject(lambda d: case(d, "ack_cases", "partial-429").__setitem__("status", 202))
        self.reject(lambda d: case(d, "ack_cases", "partial-429")["response"].__setitem__("error", None))
        self.reject(lambda d: case(d, "ack_cases", "full-202")["response"].__setitem__("schema_version", 2))
        def permanent(d):
            value = case(d, "ack_cases", "partial-429")
            value["status"] = 401
            value["response"]["error"]["code"] = "unauthorized"
        self.reject(permanent)

    def test_invalid_and_uncertain_ack_cannot_claim_progress(self):
        for identifier in ("lost-response-zero", "cancelled-zero", "response-limit-zero",
                           "reordered-ids-invalid", "partial-202-invalid", "prefix-overrun-invalid"):
            with self.subTest(identifier=identifier):
                self.reject(lambda d, identifier=identifier: case(d, "ack_cases", identifier)["expected"].__setitem__("accepted", 1))
        self.reject(lambda d: case(d, "ack_cases", "partial-429")["expected"].__setitem__("accepted", True))

    def test_source_identity_conflict_and_distinct_event_expectations_are_checked(self):
        self.reject(lambda d: d["source_identity_contract"]["key_fields"].remove("recipientAccountId"))
        self.reject(lambda d: d["source_identity_contract"].__setitem__("hash_policy", "etag_as_hash"))
        for identifier in ("duplicate-native-event", "distinct-identical-messages", "same-native-id-content-conflict"):
            with self.subTest(identifier=identifier):
                self.reject(lambda d, identifier=identifier: case(d, "source_identity_cases", identifier).__setitem__("expected_relation", "source_deleted_safe"))

    def test_retained_object_replay_is_bound_to_full_scope_and_object_version(self):
        def replay(d):
            return next(value for value in d["object_identity_cases"]
                        if value["expected_relation"] == "same_retained_object_replay_key")
        for field, wrong in (("bucket", "different-fixture-bucket"), ("key", "different/object.json.gz"),
                             ("version_id", "fixture-version-2")):
            with self.subTest(object_field=field):
                self.reject(lambda d, field=field, wrong=wrong: replay(d)["right"].__setitem__(field, wrong))
        for field, wrong in (("route_id", "different-authority"), ("account_id", "444455556666"),
                             ("region", "us-west-2"), ("configuration_revision", "fixture-config-v2")):
            with self.subTest(scope_field=field):
                self.reject(lambda d, field=field, wrong=wrong: replay(d)["right"]["trusted_scope"].__setitem__(field, wrong))
        for missing_version in (None, "", "null"):
            with self.subTest(version=missing_version):
                def change(d, version=missing_version):
                    for side in ("left", "right"):
                        replay(d)[side]["version_id"] = version
                self.reject(change)

    def test_object_replay_compares_original_bytes_not_delivery_handle_or_hash_only(self):
        def replay(d):
            return next(value for value in d["object_identity_cases"]
                        if value["expected_relation"] == "same_retained_object_replay_key")
        self.reject(lambda d: replay(d)["right"].__setitem__("original_sha256", "0" * 64))
        def changed_bytes(d):
            value = replay(d)["right"]
            original = bytes.fromhex(value["original_hex"]) + b"changed"
            value["original_hex"] = original.hex()
            value["original_sha256"] = sha(original)
        self.reject(changed_bytes)
        self.reject(lambda d: d["object_identity_contract"].__setitem__("compare_exact_original_bytes", False))
        self.reject(lambda d: d["object_identity_contract"].__setitem__("no_global_native_dedupe", False))

    def test_planned_custody_expectations_cannot_silently_change_to_safe_deletion(self):
        for identifier in ("lost-response", "receipt-quota", "expired-original", "poison-explicit-disposition", "coverage-independent"):
            with self.subTest(identifier=identifier):
                self.reject(lambda d, identifier=identifier: case(d, "custody_cases", identifier).__setitem__("expected", "Delete source immediately; M2 proves M3/M4 and healthy complete coverage."))
        self.reject(lambda d: case(d, "custody_cases", "lost-response").__setitem__("runtime_status", "qualified"))

    def test_duplicate_json_keys_reject_outer_and_native_inputs(self):
        raw = FIXTURE.read_bytes().strip()
        self.reject_file(b'{"schema_version":1,' + raw[1:])
        def change(d):
            value = case(d, "native_cases", "unsupported-action")
            value["raw_utf8"] = '{"eventName":"changed",' + value["raw_utf8"][1:]
            value["raw_sha256"] = sha(value["raw_utf8"].encode())
        self.reject(change)

    def test_nonfinite_literals_and_exponent_overflow_reject(self):
        for number in (b"NaN", b"Infinity", b"-Infinity", b"9e999", b"-9e999"):
            with self.subTest(number=number):
                self.reject_file(b'{"unused":' + number + b',' + FIXTURE.read_bytes().lstrip()[1:])
                def change(d, number=number):
                    value = case(d, "native_cases", "unsupported-action")
                    value["raw_utf8"] = value["raw_utf8"][:-1] + ',"unused":' + number.decode() + '}'
                    value["raw_sha256"] = sha(value["raw_utf8"].encode())
                    value["expected"]["cloudtrail"]["record_sha256"] = value["raw_sha256"]
                self.reject(change)
        # Direct parser check isolates overflow from unknown-field rejection.
        with self.assertRaises(ValueError):
            c.strict_json(b'{"unused":9e999}')
        type(self).rejection_checks += 1

    def test_json_depth_and_quoted_brackets_have_exact_boundaries(self):
        self.assertIsInstance(c.strict_json(b"[" * 16 + b"0" + b"]" * 16), list)
        with self.assertRaises(ValueError):
            c.strict_json(b"[" * 17 + b"0" + b"]" * 17)
        type(self).rejection_checks += 1
        self.assertEqual(c.strict_json(b'{"s":"[[[\\\"{{{{]]]"}')["s"], '[[["{{{{]]]')

    def test_checker_input_byte_cap_and_invalid_utf8_fail_closed(self):
        self.reject_file(b" " * (4 * 1024 * 1024 + 1))
        self.reject_file(b'{"value":"\xff"}')


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DesignTampering)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({"schema_version": 1, "status": "passed" if result.wasSuccessful() else "failed",
                      "tests": result.testsRun, "rejection_checks": DesignTampering.rejection_checks,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "fixture_sha256": sha(FIXTURE.read_bytes()), "checker_sha256": sha(CHECKER.read_bytes()),
                      "scope": "independent_offline_design_tampering_only"}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
