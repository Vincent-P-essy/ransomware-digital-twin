"""CLI for validation, simulation, comparison, export, and local serving."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .api import serve
from .audit import verify_event_chain
from .bundle import default_bundle_root, load_bundle, profile_by_id
from .errors import DigitalTwinError
from .exporters import write_comparison_bundle
from .models import to_jsonable
from .serialization import pretty_json
from .simulator import run_comparison, run_simulation


DEFAULT_PROFILES = [
    "flat-baseline",
    "segmented-only",
    "least-privilege-only",
    "immutable-backup-only",
    "resilient-reference",
]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ransomware-twin",
        description="Safe deterministic enterprise ransomware resilience simulator",
    )
    parser.add_argument("--bundle", type=Path, default=default_bundle_root())
    commands = parser.add_subparsers(dest="subcommand", required=True)
    commands.add_parser(
        "validate", help="validate the integrity-pinned experiment bundle"
    )
    commands.add_parser("profiles", help="list defense configurations")

    simulate = commands.add_parser("simulate", help="run one safe simulation profile")
    simulate.add_argument("--profile", required=True)
    simulate.add_argument("--full", action="store_true")

    compare = commands.add_parser("compare", help="compare two or more profiles")
    compare.add_argument("--profiles", nargs="+", default=DEFAULT_PROFILES)
    compare.add_argument("--output-dir", type=Path)
    compare.add_argument("--full", action="store_true")

    server = commands.add_parser("serve", help="serve the local API and dashboard")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    return parser


def _execute(args: argparse.Namespace) -> int:
    root = args.bundle.resolve()
    if args.subcommand == "serve":
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        serve(args.host, args.port, root)
        return 0
    bundle = load_bundle(root)
    if args.subcommand == "validate":
        reports = [run_simulation(bundle, profile.id) for profile in bundle.profiles]
        print(
            pretty_json(
                {
                    "valid": True,
                    "assets": len(bundle.topology.assets),
                    "zones": len({item.zone for item in bundle.topology.assets}),
                    "paths": len(bundle.topology.paths),
                    "actions": len(bundle.scenario.actions),
                    "profiles": len(bundle.profiles),
                    "integrity_files": len(bundle.integrity),
                    "all_event_chains_valid": all(
                        verify_event_chain(report["events"]) for report in reports
                    ),
                    "safety": reports[0]["safety"],
                }
            ),
            end="",
        )
        return 0
    if args.subcommand == "profiles":
        print(
            pretty_json({"profiles": [to_jsonable(item) for item in bundle.profiles]}),
            end="",
        )
        return 0
    if args.subcommand == "simulate":
        profile_by_id(bundle, args.profile)
        report = run_simulation(bundle, args.profile)
        output = (
            report
            if args.full
            else {
                "profile_id": report["profile"]["id"],
                "functional_sha256": report["functional_sha256"],
                "metrics": report["metrics"],
                "safety": report["safety"],
                "event_chain_valid": verify_event_chain(report["events"]),
            }
        )
        print(pretty_json(output), end="")
        return 0
    comparison = run_comparison(bundle, args.profiles)
    artifacts = (
        write_comparison_bundle(comparison, args.output_dir) if args.output_dir else {}
    )
    output = (
        comparison
        if args.full
        else {
            "functional_sha256": comparison["functional_sha256"],
            "baseline_profile_id": comparison["baseline_profile_id"],
            "best_resilience_profile_id": comparison["best_resilience_profile_id"],
            "metrics": {
                report["profile"]["id"]: report["metrics"]
                for report in comparison["reports"]
            },
            "deltas_vs_baseline": comparison["deltas_vs_baseline"],
            "artifacts": artifacts,
            "external_effects": "none",
        }
    )
    print(pretty_json(output), end="")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _execute(args)
    except (DigitalTwinError, ValueError) as exc:
        print(
            json.dumps(
                {"error": type(exc).__name__, "detail": str(exc)}, sort_keys=True
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
