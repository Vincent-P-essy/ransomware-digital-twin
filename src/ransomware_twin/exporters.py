"""Machine-readable and human-readable simulation evidence exports."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Dict, Mapping

from .serialization import canonical_json, pretty_json


def metrics_csv(comparison: Mapping[str, Any]) -> str:
    output = io.StringIO(newline="")
    fields = [
        "profile_id",
        "network_mode",
        "least_privilege",
        "immutable_backup",
        "detection_enabled",
        "machines_touched",
        "encrypted_assets",
        "time_to_critical_compromise_seconds",
        "time_to_confinement_seconds",
        "exfiltrated_data_gb",
        "data_lost_percent",
        "rto_minutes",
        "rpo_minutes",
        "blast_radius_percent",
        "weighted_blast_radius_percent",
        "resilience_score",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for report in comparison["reports"]:
        profile = report["profile"]
        metrics = report["metrics"]
        writer.writerow(
            {
                "profile_id": profile["id"],
                "network_mode": profile["network_mode"],
                "least_privilege": profile["least_privilege"],
                "immutable_backup": profile["immutable_backup"],
                "detection_enabled": profile["detection_enabled"],
                **{field: metrics[field] for field in fields if field in metrics},
            }
        )
    return output.getvalue()


def events_jsonl(comparison: Mapping[str, Any]) -> str:
    return "".join(
        canonical_json(event) + "\n"
        for report in comparison["reports"]
        for event in report["events"]
    )


def markdown_report(comparison: Mapping[str, Any]) -> str:
    lines = [
        "# Enterprise ransomware resilience comparison",
        "",
        f"- Scenario: `{comparison['scenario_id']}`",
        f"- Functional SHA-256: `{comparison['functional_sha256']}`",
        f"- Baseline: `{comparison['baseline_profile_id']}`",
        f"- Highest resilience score: `{comparison['best_resilience_profile_id']}`",
        "",
        "| Profile | Touched | Encrypted | Confinement | Exfiltrated | Data lost | RTO | RPO | Blast radius | Score |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for report in comparison["reports"]:
        metrics = report["metrics"]
        confinement = (
            "n/a"
            if metrics["time_to_confinement_seconds"] is None
            else f"{metrics['time_to_confinement_seconds']} s"
        )
        lines.append(
            f"| `{report['profile']['id']}` | {metrics['machines_touched']}/{metrics['total_assets']} | "
            f"{metrics['encrypted_assets']} | {confinement} | {metrics['exfiltrated_data_gb']:.1f} GB | "
            f"{metrics['data_lost_percent']:.1f}% | {metrics['rto_minutes']} min | "
            f"{metrics['rpo_minutes']} min | {metrics['blast_radius_percent']:.1f}% | "
            f"{metrics['resilience_score']:.1f} |"
        )
    lines.extend(
        [
            "",
            "All actions are deterministic in-memory state transitions. No host file is encrypted, no payload is executed, and no data leaves the process.",
            "",
            "Timings in the metrics are simulated incident time. Wall-clock execution measurements are environment-dependent and excluded from the functional digest.",
            "",
        ]
    )
    return "\n".join(lines)


def write_comparison_bundle(
    comparison: Mapping[str, Any], output_dir: Path
) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": output_dir / "comparison.json",
        "csv": output_dir / "metrics.csv",
        "markdown": output_dir / "report.md",
        "events": output_dir / "events.jsonl",
    }
    paths["json"].write_text(pretty_json(comparison), encoding="utf-8")
    paths["csv"].write_text(metrics_csv(comparison), encoding="utf-8")
    paths["markdown"].write_text(markdown_report(comparison), encoding="utf-8")
    paths["events"].write_text(events_jsonl(comparison), encoding="utf-8")
    return {name: str(path) for name, path in paths.items()}
