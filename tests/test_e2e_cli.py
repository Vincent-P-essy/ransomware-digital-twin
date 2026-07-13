from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from .helpers import BUNDLE, ROOT


class CliEndToEndTests(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "ransomware_twin",
                "--bundle",
                str(BUNDLE),
                *arguments,
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )

    def test_validate_and_compare_export(self) -> None:
        validation = self._run("validate")
        self.assertEqual(0, validation.returncode, validation.stderr)
        self.assertTrue(json.loads(validation.stdout)["valid"])
        with tempfile.TemporaryDirectory() as directory:
            comparison = self._run(
                "compare",
                "--profiles",
                "flat-baseline",
                "resilient-reference",
                "--output-dir",
                directory,
            )
            self.assertEqual(0, comparison.returncode, comparison.stderr)
            payload = json.loads(comparison.stdout)
            self.assertEqual(
                "resilient-reference", payload["best_resilience_profile_id"]
            )
            self.assertEqual(4, len(payload["artifacts"]))

    def test_unknown_profile_is_a_structured_failure(self) -> None:
        result = self._run("simulate", "--profile", "unknown-profile")
        self.assertEqual(2, result.returncode)
        error = json.loads(result.stderr)
        self.assertEqual("ValidationError", error["error"])


if __name__ == "__main__":
    unittest.main()
