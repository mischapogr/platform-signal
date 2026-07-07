#!/usr/bin/env python3
"""Local regressions for cleanup of exclusively owned Kubernetes gate resources."""

import argparse
import importlib.util
from pathlib import Path
import subprocess
import unittest

SPEC = importlib.util.spec_from_file_location(
    "kubernetes_gate", Path(__file__).with_name("check-kubernetes.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Forward:
    def __init__(self, timeout=False, kill_failure=False):
        self.timeout = timeout
        self.kill_failure = kill_failure
        self.calls = []

    def terminate(self):
        self.calls.append("terminate")

    def wait(self, timeout):
        self.calls.append("wait")
        if self.timeout and self.calls.count("wait") == 1:
            raise subprocess.TimeoutExpired("owned-forward", timeout)

    def kill(self):
        self.calls.append("kill")
        if self.kill_failure:
            raise OSError("owned-process kill failure")


class CleanupTests(unittest.TestCase):
    def gate(self, forward):
        gate = MODULE.Gate(argparse.Namespace(kind="kind"), "/tmp/cleanup-test")
        gate.forward = forward
        gate.cluster_attempted = True
        commands = []
        gate.run = lambda args, **kwargs: commands.append(args)
        return gate, commands

    def test_timeout_kills_process_and_deletes_owned_cluster(self):
        forward = Forward(timeout=True)
        gate, commands = self.gate(forward)
        gate.cleanup()
        self.assertEqual(forward.calls, ["terminate", "wait", "kill", "wait"])
        self.assertEqual(commands, [["kind", "delete", "cluster", "--name", gate.name]])
        self.assertIsNone(gate.forward)

    def test_process_cleanup_failure_still_deletes_owned_cluster(self):
        gate, commands = self.gate(Forward(timeout=True, kill_failure=True))
        with self.assertRaises(OSError):
            gate.cleanup()
        self.assertEqual(commands, [["kind", "delete", "cluster", "--name", gate.name]])

    def test_unattempted_cluster_is_never_deleted(self):
        gate, commands = self.gate(Forward())
        gate.cluster_attempted = False
        gate.cleanup()
        self.assertEqual(commands, [])


if __name__ == "__main__":
    unittest.main()
