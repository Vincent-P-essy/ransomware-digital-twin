#!/usr/bin/env python3
"""Reject offensive execution, destructive I/O, nondeterminism, and egress surfaces."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, List, Mapping, Tuple


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "ransomware_twin"
sys.path.insert(0, str(ROOT / "src"))

from ransomware_twin.bundle import default_bundle_root, load_bundle  # noqa: E402
from ransomware_twin.models import Primitive  # noqa: E402


FORBIDDEN_MODULES = {
    "ctypes",
    "ftplib",
    "http.client",
    "paramiko",
    "requests",
    "socket",
    "subprocess",
    "telnetlib",
    "urllib.request",
}
FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "os.popen",
    "os.spawnv",
    "os.spawnl",
    "time.sleep",
    "random.random",
    "random.randint",
    "uuid.uuid4",
}
FORBIDDEN_METHODS = {"unlink", "rmdir", "rename", "replace"}
FORBIDDEN_SCENARIO_KEYS = {
    "argv",
    "command",
    "executable",
    "payload",
    "script",
    "shell",
}


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def inspect_file(path: Path) -> List[Tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: List[Tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(
                    alias.name == item or alias.name.startswith(item + ".")
                    for item in FORBIDDEN_MODULES
                ):
                    findings.append((node.lineno, f"forbidden import: {alias.name}"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            if any(
                node.module == item or node.module.startswith(item + ".")
                for item in FORBIDDEN_MODULES
            ):
                findings.append((node.lineno, f"forbidden import: {node.module}"))
        elif isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name in FORBIDDEN_CALLS or name.rsplit(".", 1)[-1] in FORBIDDEN_METHODS:
                findings.append((node.lineno, f"forbidden call: {name}"))
    return findings


def inspect_keys(value: Any, path: str = "$") -> List[str]:
    findings: List[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_SCENARIO_KEYS:
                findings.append(f"{path}.{key}")
            findings.extend(inspect_keys(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(inspect_keys(item, f"{path}[{index}]"))
    return findings


def main() -> int:
    source_findings = [
        {"file": str(path.relative_to(ROOT)), "line": line, "detail": detail}
        for path in sorted(SOURCE.rglob("*.py"))
        for line, detail in inspect_file(path)
    ]
    raw_scenario = json.loads(
        (default_bundle_root() / "scenario.json").read_text(encoding="utf-8")
    )
    scenario_key_findings = inspect_keys(raw_scenario)
    bundle = load_bundle()
    primitive_allowlist = {item.value for item in Primitive}
    actual_primitives = {item.primitive.value for item in bundle.scenario.actions}
    checks = {
        "runtime_source_surface": not source_findings,
        "scenario_has_no_execution_fields": not scenario_key_findings,
        "only_allowlisted_primitives": actual_primitives <= primitive_allowlist,
        "all_actions_are_declared": len(bundle.scenario.actions) == 20,
    }
    passed = all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "source_findings": source_findings,
                "scenario_key_findings": scenario_key_findings,
                "primitives": sorted(actual_primitives),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
