from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from ransomware_twin.bundle import load_bundle
from ransomware_twin.exporters import (
    events_jsonl,
    markdown_report,
    metrics_csv,
    write_comparison_bundle,
)
from ransomware_twin.simulator import run_comparison

from .helpers import BUNDLE


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        bundle = load_bundle(BUNDLE)
        cls.comparison = run_comparison(bundle, [item.id for item in bundle.profiles])

    def test_csv_has_one_row_per_profile(self) -> None:
        rows = list(csv.DictReader(metrics_csv(self.comparison).splitlines()))
        self.assertEqual(5, len(rows))
        self.assertEqual("15", rows[0]["machines_touched"])
        self.assertEqual("2", rows[-1]["machines_touched"])

    def test_jsonl_is_a_replayable_golden_event_corpus(self) -> None:
        events = [
            json.loads(line) for line in events_jsonl(self.comparison).splitlines()
        ]
        expected = sum(len(report["events"]) for report in self.comparison["reports"])
        self.assertEqual(expected, len(events))
        self.assertTrue(all(event["event_hash"] for event in events))

    def test_markdown_states_safety_and_measurement_limits(self) -> None:
        report = markdown_report(self.comparison)
        self.assertIn("No host file is encrypted", report)
        self.assertIn("Wall-clock", report)
        self.assertIn("15/16", report)
        self.assertIn("2/16", report)

    def test_export_bundle_contains_json_csv_markdown_and_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_comparison_bundle(self.comparison, Path(directory))
            self.assertEqual({"json", "csv", "markdown", "events"}, set(paths))
            self.assertTrue(all(Path(path).is_file() for path in paths.values()))


if __name__ == "__main__":
    unittest.main()
