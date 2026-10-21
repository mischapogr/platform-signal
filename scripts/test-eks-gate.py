#!/usr/bin/env python3
"""Local regressions for the EKS qualification harness; no AWS access or billing."""

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("check_eks", Path(__file__).with_name("check-eks.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

BASE = ["--account-id", "123456789012", "--region", "eu-central-1", "--run-id", "t1"]


class DryRunTests(unittest.TestCase):
    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(MODULE.subprocess, "run") as run, \
                mock.patch.object(MODULE.shutil, "which", return_value="/bin/x"):
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            code = MODULE.main(list(argv))
        return code, out.getvalue(), run

    def test_teardown_dry_run_executes_nothing_and_orders_cluster_before_bucket(self):
        code, out, run = self.run_main("teardown", *BASE)
        self.assertEqual(code, 0)
        run.assert_not_called()
        self.assertLess(out.index("eksctl delete cluster"), out.index("delete-bucket"))

    def test_execute_refuses_foreign_account(self):
        fake = mock.Mock(returncode=0, stdout='{"Account": "999999999999"}', stderr="")
        with mock.patch.object(MODULE.subprocess, "run", return_value=fake), \
                mock.patch.object(MODULE.shutil, "which", return_value="/bin/x"), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = MODULE.main(["preflight", *BASE, "--execute"])
        self.assertEqual(code, 1)
        self.assertIn("does not match the authorized", err.getvalue())

    def test_ttl_is_capped(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = MODULE.main(["preflight", *BASE, "--ttl-hours", "24"])
        self.assertEqual(code, 1)
        self.assertIn("capped at 8", err.getvalue())

    def test_resources_are_tagged_and_object_lock_never_compliance(self):
        source = Path(MODULE.__file__).read_text()
        self.assertIn("signal-qual", source)
        self.assertNotIn('"Mode": "COMPLIANCE"', source)


if __name__ == "__main__":
    unittest.main()
