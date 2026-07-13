#!/usr/bin/env python3
"""Reproducibility, safety, ablation, and measured-outcome policy gate."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ransomware_twin.audit import verify_event_chain  # noqa: E402
from ransomware_twin.bundle import load_bundle  # noqa: E402
from ransomware_twin.simulator import (  # noqa: E402
    comparison_functional_view,
    run_comparison,
)


def main() -> int:
    bundle = load_bundle()
    profile_ids = [item.id for item in bundle.profiles]
    first = run_comparison(bundle, profile_ids)
    second = run_comparison(bundle, profile_ids)
    reports = {item["profile"]["id"]: item for item in first["reports"]}
    baseline = reports["flat-baseline"]["metrics"]
    resilient = reports["resilient-reference"]["metrics"]
    immutable = reports["immutable-backup-only"]["metrics"]
    checks = {
        "functional_determinism": comparison_functional_view(first)
        == comparison_functional_view(second),
        "functional_digest_stable": first["functional_sha256"]
        == second["functional_sha256"],
        "all_event_chains_valid": all(
            verify_event_chain(report["events"]) for report in first["reports"]
        ),
        "flat_baseline_reaches_15_assets": baseline["machines_touched"] == 15,
        "flat_baseline_loses_primary_data": baseline["data_lost_percent"] == 100.0,
        "layered_reference_contains_at_47s": resilient["time_to_confinement_seconds"]
        == 47,
        "layered_reference_limits_blast": resilient["machines_touched"] == 2,
        "layered_reference_prevents_encryption": resilient["encrypted_assets"] == 0,
        "layered_reference_has_zero_data_loss": resilient["data_lost_percent"] == 0.0,
        "immutable_backup_preserves_data": immutable["machines_touched"] == 15
        and immutable["data_lost_percent"] == 0.0,
        "best_profile_is_layered_reference": first["best_resilience_profile_id"]
        == "resilient-reference",
        "all_reports_have_no_external_effects": all(
            report["safety"]["network_egress"] is False
            and report["safety"]["payload_execution"] is False
            and report["safety"]["host_file_encryption"] is False
            for report in first["reports"]
        ),
    }
    passed = all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "functional_sha256": first["functional_sha256"],
                "baseline": baseline,
                "resilient_reference": resilient,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
