#!/usr/bin/env python3
"""Fail-closed validation regressions for native metadata qualification evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("runtime_read", Path(__file__).with_name("check-runtime-read.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MetadataEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.capture = "11111111-1111-4111-8111-111111111111"
        self.config = "a" * 64
        common = dict(schema_version=1, profile=module.PROFILE, capture_id=self.capture,
                      config_sha256=self.config, host="synthetic", boot_id=self.capture,
                      timestamp_ns=1792990000000000000, pid=123, tid=123, start_ticks=100,
                      clock_ticks=100, mount_ns=1, audit_arch=0xc000003e, execution_generation=1)
        self.records = [dict(common, sequence=1, kind="exec"),
                        dict(common, sequence=2, kind="end", reason="exited", stops=10)]

    def validate(self, records):
        return module.validate_records(b"".join(json.dumps(x).encode() + b"\n" for x in records),
                                       self.capture, self.config)

    def test_terminal_and_identity_proof_are_required(self):
        self.validate(self.records)
        for field, value in (("pid", 124), ("start_ticks", 101), ("mount_ns", 2),
                             ("sequence", 3), ("execution_generation", 2),
                             ("capture_id", "22222222-2222-4222-8222-222222222222"),
                             ("config_sha256", "b" * 64), ("profile", "unknown")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.records)
                changed[-1][field] = value
                with self.assertRaises(ValueError):
                    self.validate(changed)
        with self.assertRaises(ValueError):
            self.validate(self.records[:1])

    def test_payload_fields_and_source_after_terminal_refused(self):
        changed = copy.deepcopy(self.records)
        changed[0]["buffer"] = module.SENTINEL.decode()
        with self.assertRaises(ValueError):
            self.validate(changed)
        changed = copy.deepcopy(self.records)
        changed.append(dict(changed[0], sequence=3))
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_impossible_success_and_error_pair_refused(self):
        read = dict(self.records[0], kind="read", sequence=2, fd=3, object_type=32768,
                    dev_major=1, dev_minor=1, inode=9, mount_id=1, ctime_sec=1,
                    ctime_nsec=0, requested=16, result=17, error=False,
                    syscall_entry_ns=1792989999999000000, syscall_exit_ns=1792990000000000000)
        end = dict(self.records[-1], sequence=3)
        for result, error in ((17, False), (-14, False), (1, True)):
            with self.subTest(result=result, error=error), self.assertRaises(ValueError):
                self.validate([self.records[0], dict(read, result=result, error=error), end])


if __name__ == "__main__":
    unittest.main()
