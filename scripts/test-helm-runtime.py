#!/usr/bin/env python3
"""Render the real chart to guard Standard selection and credential references."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELM = "helm"


class RuntimeTests(unittest.TestCase):
    def render(self, runtime):
        with tempfile.TemporaryDirectory(prefix="signal-helm-runtime-") as directory:
            values = Path(directory) / "values.json"
            values.write_text(json.dumps({"runtime": runtime}))
            return subprocess.run(
                [HELM, "template", "proof", str(ROOT / "deploy/helm/signal"),
                 "--show-only", "templates/deployment.yaml", "--values", str(values)],
                capture_output=True, text=True, timeout=20, check=False)

    def test_standard_selects_s3_and_identity_secret_without_literals(self):
        result = self.render({"existingSecret": "runtime-config", "files": {
            "SIGNAL_SHARED_CONFIG": "shared.json", "SIGNAL_ACCESS_CONFIG": "access.json"},
            "secretEnv": [{"name": "SIGNAL_IDENTITY_CLIENT_SECRET",
                           "secret": "runtime-credentials", "key": "identity-client-secret"}]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("- name: SIGNAL_STORAGE_TYPE\n              value: s3", result.stdout)
        self.assertIn("value: /var/lib/signal/query-cache", result.stdout)
        self.assertIn('- name: SIGNAL_IDENTITY_CLIENT_SECRET\n              valueFrom:\n'
                      '                secretKeyRef:\n                  name: "runtime-credentials"\n'
                      '                  key: "identity-client-secret"', result.stdout)
        for selector in ("SIGNAL_SHARED_CONFIG", "SIGNAL_ACCESS_CONFIG"):
            self.assertIn(f'mountPath: "/etc/signal/{selector}.json"\n'
                          f'              subPath: "{selector}.json"\n'
                          '              readOnly: true', result.stdout)
        self.assertIn("replicas: 1", result.stdout)
        self.assertIn("type: Recreate", result.stdout)
        self.assertIn("readOnlyRootFilesystem: true", result.stdout)

    def test_default_and_access_only_keep_filesystem_storage_selection(self):
        for runtime in ({}, {"existingSecret": "runtime-config",
                             "files": {"SIGNAL_ACCESS_CONFIG": "access.json"}}):
            with self.subTest(runtime=runtime):
                result = self.render(runtime)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("name: SIGNAL_STORAGE_TYPE", result.stdout)
                self.assertNotIn("name: SIGNAL_S3_CACHE_DIR", result.stdout)

    def test_storage_and_other_owned_settings_cannot_be_overridden(self):
        for name in ("SIGNAL_STORAGE_TYPE", "SIGNAL_API_TOKEN", "SIGNAL_SHARED_CONFIG",
                     "SIGNAL_S3_CACHE_DIR", "SIGNAL_LISTEN", "LD_PRELOAD"):
            with self.subTest(name=name):
                result = self.render({"secretEnv": [
                    {"name": name, "secret": "credentials", "key": "value"}]})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("runtime.secretEnv cannot override", result.stderr)

    def test_duplicate_identity_secret_is_rejected(self):
        entry = {"name": "SIGNAL_IDENTITY_CLIENT_SECRET", "secret": "credentials", "key": "value"}
        result = self.render({"secretEnv": [entry, entry]})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate environment name", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helm", default="helm")
    args, remaining = parser.parse_known_args()
    HELM = args.helm
    unittest.main(argv=[__file__, *remaining])
