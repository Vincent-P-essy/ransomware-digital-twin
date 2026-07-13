from __future__ import annotations

import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from ransomware_twin.serialization import file_sha256


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "src" / "ransomware_twin" / "bundle"


class BundleCopy:
    def __init__(self) -> None:
        self._temporary = TemporaryDirectory()
        self.path = Path(self._temporary.name) / "bundle"
        shutil.copytree(BUNDLE, self.path)

    def repin(self, relative: str) -> None:
        manifest_path = self.path / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][relative] = file_sha256(self.path / relative)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def cleanup(self) -> None:
        self._temporary.cleanup()
