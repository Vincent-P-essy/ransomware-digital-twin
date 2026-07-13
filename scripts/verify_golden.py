#!/usr/bin/env python3
"""Verify committed evidence and reproduce its deterministic functional digest."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ransomware_twin.audit import verify_event_chain  # noqa: E402
from ransomware_twin.bundle import load_bundle  # noqa: E402
from ransomware_twin.errors import ValidationError  # noqa: E402
from ransomware_twin.jsonutil import load_json  # noqa: E402
from ransomware_twin.serialization import digest, file_sha256  # noqa: E402
from ransomware_twin.simulator import (  # noqa: E402
    comparison_functional_view,
    run_comparison,
)


GOLDEN = ROOT / "golden" / "2026-07-13"
EXPECTED_FILES = {"comparison.json", "events.jsonl", "metrics.csv", "report.md"}


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{label} must be an object")
    return value


def main() -> int:
    manifest = _mapping(load_json(GOLDEN / "manifest.json"), "golden manifest")
    if set(manifest) != {
        "contract_version",
        "functional_sha256",
        "files",
        "measurement_note",
    }:
        raise ValidationError("unsupported golden manifest shape")
    if manifest["contract_version"] != "1.0":
        raise ValidationError("unsupported golden contract version")
    files = _mapping(manifest["files"], "golden files")
    if set(files) != EXPECTED_FILES:
        raise ValidationError("golden manifest has an unexpected file set")
    file_checks = {
        name: file_sha256(GOLDEN / name) == expected for name, expected in files.items()
    }
    committed = _mapping(load_json(GOLDEN / "comparison.json"), "comparison")
    committed_digest = digest(comparison_functional_view(committed))
    bundle = load_bundle()
    reproduced = run_comparison(bundle, [item.id for item in bundle.profiles])
    checks = {
        "files_unchanged": all(file_checks.values()),
        "committed_digest_valid": committed_digest
        == committed.get("functional_sha256"),
        "manifest_digest_matches": manifest["functional_sha256"]
        == committed.get("functional_sha256"),
        "functional_digest_reproduced": reproduced["functional_sha256"]
        == manifest["functional_sha256"],
        "all_committed_event_chains_valid": all(
            verify_event_chain(report["events"]) for report in committed["reports"]
        ),
    }
    passed = all(file_checks.values()) and all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "file_checks": file_checks,
                "functional_sha256": reproduced["functional_sha256"],
                "wall_clock_recompared": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
