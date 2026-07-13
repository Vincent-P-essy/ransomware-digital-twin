from __future__ import annotations

import json
import unittest

from ransomware_twin.bundle import load_bundle
from ransomware_twin.errors import IntegrityError, ValidationError

from .helpers import BUNDLE, BundleCopy


class BundleTests(unittest.TestCase):
    def test_integrity_pinned_bundle_is_complete(self) -> None:
        bundle = load_bundle(BUNDLE)
        self.assertEqual(16, len(bundle.topology.assets))
        self.assertEqual(14, len(bundle.topology.paths))
        self.assertEqual(20, len(bundle.scenario.actions))
        self.assertEqual(5, len(bundle.profiles))
        self.assertEqual(8, len(bundle.integrity))
        self.assertEqual(11, len({item.zone for item in bundle.topology.assets}))

    def test_mutated_profile_is_rejected_before_parsing(self) -> None:
        copied = BundleCopy()
        try:
            profile = copied.path / "profiles" / "flat-baseline.json"
            profile.write_text(
                profile.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(IntegrityError, "hash mismatch"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()

    def test_duplicate_json_key_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            profile = copied.path / "profiles" / "flat-baseline.json"
            text = profile.read_text(encoding="utf-8").replace(
                '  "version": "1.0",', '  "version": "1.0",\n  "version": "2.0",'
            )
            profile.write_text(text, encoding="utf-8")
            copied.repin("profiles/flat-baseline.json")
            with self.assertRaisesRegex(ValidationError, "duplicate JSON key"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()

    def test_unknown_profile_field_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            profile = copied.path / "profiles" / "flat-baseline.json"
            raw = json.loads(profile.read_text(encoding="utf-8"))
            raw["unreviewed_control"] = True
            profile.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            copied.repin("profiles/flat-baseline.json")
            with self.assertRaisesRegex(ValidationError, "unsupported fields"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()

    def test_manifest_path_traversal_is_rejected(self) -> None:
        copied = BundleCopy()
        try:
            manifest_path = copied.path / "manifest.json"
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            raw["files"]["../outside.json"] = raw["files"].pop("catalog.json")
            manifest_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "traversal-free"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()

    def test_unknown_primitive_fails_closed(self) -> None:
        copied = BundleCopy()
        try:
            scenario = copied.path / "scenario.json"
            text = scenario.read_text(encoding="utf-8").replace(
                '"primitive": "initial_access"', '"primitive": "unbounded_action"', 1
            )
            scenario.write_text(text, encoding="utf-8")
            copied.repin("scenario.json")
            with self.assertRaisesRegex(ValidationError, "unsupported safe primitive"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()

    def test_scenario_cannot_embed_extra_command_fields(self) -> None:
        copied = BundleCopy()
        try:
            scenario = copied.path / "scenario.json"
            raw = json.loads(scenario.read_text(encoding="utf-8"))
            raw["actions"][0]["command"] = "not accepted"
            scenario.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            copied.repin("scenario.json")
            with self.assertRaisesRegex(ValidationError, "unsupported fields"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()

    def test_scenario_references_require_scalar_identifiers(self) -> None:
        copied = BundleCopy()
        try:
            scenario = copied.path / "scenario.json"
            raw = json.loads(scenario.read_text(encoding="utf-8"))
            raw["actions"][1]["source_asset"] = ["ws-finance-01"]
            scenario.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            copied.repin("scenario.json")
            with self.assertRaisesRegex(ValidationError, "string or null"):
                load_bundle(copied.path)
        finally:
            copied.cleanup()


if __name__ == "__main__":
    unittest.main()
