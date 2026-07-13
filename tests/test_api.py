from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Tuple

from ransomware_twin.api import create_server

from .helpers import BUNDLE


@contextmanager
def running_server() -> Iterator[Tuple[str, Any]]:
    server = create_server("127.0.0.1", 0, BUNDLE)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def read_json(url: str) -> Tuple[int, Dict[str, Any], Any]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, json.load(response), response.headers


class ApiTests(unittest.TestCase):
    def test_health_topology_profiles_and_dashboard(self) -> None:
        with running_server() as (base, _):
            status, health, headers = read_json(base + "/api/v1/health")
            self.assertEqual(200, status)
            self.assertEqual("simulation-only", health["execution_mode"])
            self.assertEqual("none", health["external_effects"])
            self.assertEqual("nosniff", headers["X-Content-Type-Options"])
            _, topology, _ = read_json(base + "/api/v1/topology")
            self.assertEqual(16, len(topology["topology"]["assets"]))
            _, profiles, _ = read_json(base + "/api/v1/profiles")
            self.assertEqual(5, len(profiles["profiles"]))
            with urllib.request.urlopen(base + "/", timeout=5) as response:
                html = response.read().decode("utf-8")
                self.assertIn("Enterprise Resilience Digital Twin", html)
                self.assertIn(
                    "default-src 'self'", response.headers["Content-Security-Policy"]
                )

    def test_compare_endpoint_runs_controlled_profiles(self) -> None:
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/compare",
                data=json.dumps(
                    {"profile_ids": ["flat-baseline", "resilient-reference"]}
                ).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                comparison = json.load(response)
            self.assertEqual(
                "resilient-reference", comparison["best_resilience_profile_id"]
            )
            self.assertEqual(64, len(comparison["functional_sha256"]))

    def test_api_rejects_extra_fields(self) -> None:
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/simulate",
                data=json.dumps(
                    {"profile_id": "flat-baseline", "command": "no"}
                ).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as captured:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(400, captured.exception.code)

    def test_api_rejects_duplicate_json_keys(self) -> None:
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/simulate",
                data=b'{"profile_id":"flat-baseline","profile_id":"resilient-reference"}',
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as captured:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(400, captured.exception.code)


if __name__ == "__main__":
    unittest.main()
