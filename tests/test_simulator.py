from __future__ import annotations

import copy
import unittest

from ransomware_twin.audit import verify_event_chain
from ransomware_twin.bundle import load_bundle
from ransomware_twin.errors import IntegrityError, ValidationError
from ransomware_twin.simulator import functional_view, run_comparison, run_simulation

from .helpers import BUNDLE


class SimulatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_bundle(BUNDLE)

    def test_flat_baseline_reaches_catastrophic_impact(self) -> None:
        metrics = run_simulation(self.bundle, "flat-baseline")["metrics"]
        self.assertEqual(15, metrics["machines_touched"])
        self.assertEqual(15, metrics["encrypted_assets"])
        self.assertEqual(50, metrics["time_to_critical_compromise_seconds"])
        self.assertEqual(100.0, metrics["exfiltrated_data_gb"])
        self.assertEqual(100.0, metrics["data_lost_percent"])
        self.assertEqual(825, metrics["rto_minutes"])
        self.assertEqual(480, metrics["rpo_minutes"])
        self.assertFalse(metrics["backup_available"])

    def test_layered_reference_contains_before_critical_assets(self) -> None:
        report = run_simulation(self.bundle, "resilient-reference")
        metrics = report["metrics"]
        self.assertEqual(2, metrics["machines_touched"])
        self.assertEqual(39, metrics["time_to_detection_seconds"])
        self.assertEqual(47, metrics["time_to_confinement_seconds"])
        self.assertIsNone(metrics["time_to_critical_compromise_seconds"])
        self.assertEqual(0, metrics["encrypted_assets"])
        self.assertEqual(0.0, metrics["data_lost_percent"])
        self.assertEqual(38, metrics["rto_minutes"])
        self.assertEqual(0, metrics["rpo_minutes"])
        self.assertEqual(
            {"automated-containment": 17}, metrics["blocked_events_by_control"]
        )

    def test_control_ablation_exposes_distinct_tradeoffs(self) -> None:
        segmented = run_simulation(self.bundle, "segmented-only")["metrics"]
        privilege = run_simulation(self.bundle, "least-privilege-only")["metrics"]
        immutable = run_simulation(self.bundle, "immutable-backup-only")["metrics"]
        self.assertEqual(2, segmented["machines_touched"])
        self.assertEqual(3, privilege["machines_touched"])
        self.assertEqual(40.0, privilege["exfiltrated_data_gb"])
        self.assertEqual(15, immutable["machines_touched"])
        self.assertEqual(0.0, immutable["data_lost_percent"])
        self.assertEqual(195, immutable["rto_minutes"])
        self.assertIn("segmentation-policy", segmented["blocked_events_by_control"])
        self.assertIn("least-privilege-policy", privilege["blocked_events_by_control"])

    def test_functional_evidence_is_deterministic(self) -> None:
        first = run_simulation(self.bundle, "flat-baseline")
        second = run_simulation(self.bundle, "flat-baseline")
        self.assertEqual(first["functional_sha256"], second["functional_sha256"])
        self.assertEqual(functional_view(first), functional_view(second))
        self.assertNotIn("measurement", functional_view(first))

    def test_every_event_chain_is_valid_and_simulation_only(self) -> None:
        for profile in self.bundle.profiles:
            report = run_simulation(self.bundle, profile.id)
            with self.subTest(profile=profile.id):
                self.assertTrue(verify_event_chain(report["events"]))
                self.assertTrue(
                    all(item["simulation_only"] for item in report["events"])
                )
                self.assertFalse(report["safety"]["payload_execution"])
                self.assertFalse(report["safety"]["network_egress"])
                self.assertFalse(report["safety"]["host_file_encryption"])

    def test_event_chain_detects_tampering(self) -> None:
        report = run_simulation(self.bundle, "flat-baseline")
        tampered = copy.deepcopy(report["events"])
        tampered[2]["outcome"] = "prevented"
        with self.assertRaises(IntegrityError):
            verify_event_chain(tampered)

    def test_comparison_measures_improvement_from_baseline(self) -> None:
        comparison = run_comparison(
            self.bundle, ["flat-baseline", "resilient-reference"]
        )
        self.assertEqual(
            "resilient-reference", comparison["best_resilience_profile_id"]
        )
        delta = comparison["deltas_vs_baseline"]["resilient-reference"]
        self.assertEqual(-13.0, delta["machines_touched"])
        self.assertEqual(-100.0, delta["data_lost_percent"])
        self.assertEqual(-787.0, delta["rto_minutes"])
        self.assertGreater(delta["resilience_score"], 80)

    def test_comparison_requires_unique_profiles(self) -> None:
        with self.assertRaises(ValidationError):
            run_comparison(self.bundle, ["flat-baseline", "flat-baseline"])


if __name__ == "__main__":
    unittest.main()
