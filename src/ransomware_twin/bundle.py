"""Strict, integrity-pinned loading of the packaged experiment bundle."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Mapping, Set

from .errors import IntegrityError, ValidationError
from .jsonutil import load_json
from .models import (
    AccessPath,
    Asset,
    AssetKind,
    DataClass,
    Dependency,
    ExperimentBundle,
    NetworkMode,
    Primitive,
    Scenario,
    ScenarioAction,
    SimulationProfile,
    Topology,
)
from .serialization import file_sha256


_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_ROLES = {"user", "service", "admin"}
_STAGE_ORDER = {
    "initial-access": 0,
    "credential-access": 1,
    "lateral-movement": 2,
    "exfiltration": 3,
    "impact": 4,
    "recovery-inhibition": 5,
}


def default_bundle_root() -> Path:
    return Path(__file__).with_name("bundle")


def resolve_inside(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValidationError(
            f"bundle path must be relative and traversal-free: {relative}"
        )
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ValidationError(f"bundle path escapes root: {relative}")
    return resolved


def _object(
    value: Any, path: str, required: Set[str], optional: Set[str] = set()
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise ValidationError(f"{path} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(
            f"{path} has unsupported fields: {', '.join(sorted(unknown))}"
        )
    return value


def _string(value: Any, path: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _identifier(value: Any, path: str) -> str:
    parsed = _string(value, path, 96)
    if not _ID.fullmatch(parsed):
        raise ValidationError(f"{path} has an invalid identifier")
    return parsed


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValidationError(
            f"{path} must be an integer between {minimum} and {maximum}"
        )
    return int(value)


def _number(value: Any, path: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{path} must be numeric")
    parsed = float(value)
    if not minimum <= parsed <= maximum:
        raise ValidationError(f"{path} must be between {minimum} and {maximum}")
    return parsed


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{path} must be boolean")
    return value


def verify_bundle(root: Path) -> Dict[str, str]:
    manifest = _object(
        load_json(root / "manifest.json"), "$", {"contract_version", "files"}
    )
    if manifest["contract_version"] != "1.0":
        raise ValidationError("unsupported bundle integrity contract")
    files = manifest["files"]
    if not isinstance(files, Mapping) or not files:
        raise ValidationError("bundle manifest files must be a non-empty object")
    checks: Dict[str, str] = {}
    for raw_path, raw_hash in sorted(files.items()):
        relative = _string(raw_path, "$.files key", 240)
        expected = _string(raw_hash, f"$.files.{relative}", 64)
        if not _SHA256.fullmatch(expected):
            raise ValidationError(f"invalid SHA-256 for {relative}")
        target = resolve_inside(root, relative)
        if not target.is_file():
            raise IntegrityError(f"bundle file is missing: {relative}")
        actual = file_sha256(target)
        if actual != expected:
            raise IntegrityError(f"bundle hash mismatch: {relative}")
        checks[relative] = actual
    return checks


def _topology(path: Path) -> Topology:
    raw = _object(
        load_json(path),
        "$",
        {"version", "name", "description", "assets", "paths", "dependencies"},
    )
    if raw["version"] != "1.0":
        raise ValidationError("unsupported topology version")
    if not isinstance(raw["assets"], list) or not raw["assets"]:
        raise ValidationError("topology assets must be a non-empty list")
    assets = []
    for index, item in enumerate(raw["assets"]):
        item_path = f"$.assets[{index}]"
        data = _object(
            item,
            item_path,
            {
                "id",
                "name",
                "kind",
                "zone",
                "criticality",
                "data_gb",
                "data_class",
                "restore_minutes",
                "rebuild_minutes",
                "encryptable",
                "exfiltratable",
            },
        )
        try:
            kind = AssetKind(_string(data["kind"], f"{item_path}.kind", 32))
            data_class = DataClass(
                _string(data["data_class"], f"{item_path}.data_class", 16)
            )
        except ValueError as exc:
            raise ValidationError(f"invalid asset enum at {item_path}: {exc}") from exc
        assets.append(
            Asset(
                id=_identifier(data["id"], f"{item_path}.id"),
                name=_string(data["name"], f"{item_path}.name", 120),
                kind=kind,
                zone=_identifier(data["zone"], f"{item_path}.zone"),
                criticality=_integer(
                    data["criticality"], f"{item_path}.criticality", 1, 5
                ),
                data_gb=_number(data["data_gb"], f"{item_path}.data_gb", 0, 1_000_000),
                data_class=data_class,
                restore_minutes=_integer(
                    data["restore_minutes"], f"{item_path}.restore_minutes", 0, 100_000
                ),
                rebuild_minutes=_integer(
                    data["rebuild_minutes"], f"{item_path}.rebuild_minutes", 0, 100_000
                ),
                encryptable=_boolean(data["encryptable"], f"{item_path}.encryptable"),
                exfiltratable=_boolean(
                    data["exfiltratable"], f"{item_path}.exfiltratable"
                ),
            )
        )
    asset_ids = [item.id for item in assets]
    if len(set(asset_ids)) != len(asset_ids):
        raise ValidationError("asset identifiers must be unique")
    known_assets = set(asset_ids)

    if not isinstance(raw["paths"], list) or not raw["paths"]:
        raise ValidationError("topology paths must be a non-empty list")
    paths = []
    for index, item in enumerate(raw["paths"]):
        item_path = f"$.paths[{index}]"
        data = _object(
            item,
            item_path,
            {"id", "source", "target", "required_role", "segmented_allowed"},
        )
        source = _identifier(data["source"], f"{item_path}.source")
        target = _identifier(data["target"], f"{item_path}.target")
        role = _string(data["required_role"], f"{item_path}.required_role", 16)
        if source not in known_assets or target not in known_assets:
            raise ValidationError(f"path references an unknown asset at {item_path}")
        if source == target or role not in _ROLES:
            raise ValidationError(f"invalid access path at {item_path}")
        paths.append(
            AccessPath(
                id=_identifier(data["id"], f"{item_path}.id"),
                source=source,
                target=target,
                required_role=role,
                segmented_allowed=_boolean(
                    data["segmented_allowed"], f"{item_path}.segmented_allowed"
                ),
            )
        )
    path_ids = [item.id for item in paths]
    if len(set(path_ids)) != len(path_ids):
        raise ValidationError("access path identifiers must be unique")

    if not isinstance(raw["dependencies"], list):
        raise ValidationError("topology dependencies must be a list")
    dependencies = []
    for index, item in enumerate(raw["dependencies"]):
        item_path = f"$.dependencies[{index}]"
        data = _object(item, item_path, {"service", "depends_on"})
        service = _identifier(data["service"], f"{item_path}.service")
        depends_on = _identifier(data["depends_on"], f"{item_path}.depends_on")
        if (
            service not in known_assets
            or depends_on not in known_assets
            or service == depends_on
        ):
            raise ValidationError(f"invalid dependency at {item_path}")
        dependencies.append(Dependency(service=service, depends_on=depends_on))
    return Topology(
        version="1.0",
        name=_string(raw["name"], "$.name", 120),
        description=_string(raw["description"], "$.description", 800),
        assets=tuple(assets),
        paths=tuple(paths),
        dependencies=tuple(dependencies),
    )


def _scenario(path: Path, topology: Topology) -> Scenario:
    raw = _object(
        load_json(path),
        "$",
        {"version", "id", "title", "description", "safety_invariant", "actions"},
    )
    if raw["version"] != "1.0":
        raise ValidationError("unsupported scenario version")
    if not isinstance(raw["actions"], list) or not raw["actions"]:
        raise ValidationError("scenario actions must be a non-empty list")
    known_assets = {item.id for item in topology.assets}
    known_paths = {item.id for item in topology.paths}
    actions = []
    for index, item in enumerate(raw["actions"]):
        item_path = f"$.actions[{index}]"
        data = _object(
            item,
            item_path,
            {
                "id",
                "at_seconds",
                "stage",
                "primitive",
                "source_asset",
                "target_asset",
                "path_id",
                "volume_gb",
                "signal_score",
            },
        )
        try:
            primitive = Primitive(
                _string(data["primitive"], f"{item_path}.primitive", 48)
            )
        except ValueError as exc:
            raise ValidationError(f"unsupported safe primitive at {item_path}") from exc
        stage = _string(data["stage"], f"{item_path}.stage", 32)
        if stage not in _STAGE_ORDER:
            raise ValidationError(f"unsupported stage at {item_path}")
        source = data["source_asset"]
        target = data["target_asset"]
        path_id = data["path_id"]
        for value, label in ((source, "source_asset"), (target, "target_asset")):
            if value is not None:
                if not isinstance(value, str):
                    raise ValidationError(
                        f"{label} must be a string or null at {item_path}"
                    )
                if value not in known_assets and value != "compromised-assets":
                    raise ValidationError(f"unknown {label} at {item_path}")
        if path_id is not None:
            if not isinstance(path_id, str):
                raise ValidationError(
                    f"path_id must be a string or null at {item_path}"
                )
            if path_id not in known_paths:
                raise ValidationError(f"unknown path_id at {item_path}")
        action = ScenarioAction(
            id=_identifier(data["id"], f"{item_path}.id"),
            at_seconds=_integer(
                data["at_seconds"], f"{item_path}.at_seconds", 0, 86_400
            ),
            stage=stage,
            primitive=primitive,
            source_asset=source,
            target_asset=target,
            path_id=path_id,
            volume_gb=_number(
                data["volume_gb"], f"{item_path}.volume_gb", 0, 1_000_000
            ),
            signal_score=_integer(
                data["signal_score"], f"{item_path}.signal_score", 0, 100
            ),
        )
        _validate_action_shape(action, item_path)
        actions.append(action)
    if len({item.id for item in actions}) != len(actions):
        raise ValidationError("scenario action identifiers must be unique")
    ordered = sorted(actions, key=lambda item: (item.at_seconds, item.id))
    if actions != ordered:
        raise ValidationError("scenario actions must be deterministically ordered")
    stage_ranks = [_STAGE_ORDER[item.stage] for item in actions]
    if stage_ranks != sorted(stage_ranks):
        raise ValidationError("scenario stages must follow the controlled progression")
    return Scenario(
        version="1.0",
        id=_identifier(raw["id"], "$.id"),
        title=_string(raw["title"], "$.title", 160),
        description=_string(raw["description"], "$.description", 1000),
        safety_invariant=_string(raw["safety_invariant"], "$.safety_invariant", 500),
        actions=tuple(actions),
    )


def _validate_action_shape(action: ScenarioAction, path: str) -> None:
    shapes = {
        Primitive.INITIAL_ACCESS: (False, True, False, False),
        Primitive.CREDENTIAL_ACCESS: (True, False, False, False),
        Primitive.LATERAL_MOVE: (False, False, True, False),
        Primitive.EXFILTRATION_ATTEMPT: (False, True, False, True),
        Primitive.ENCRYPT_IMPACTED_ASSETS: (False, True, False, False),
        Primitive.DESTROY_RECOVERY_POINTS: (True, True, False, False),
    }
    source_required, target_required, path_required, volume_required = shapes[
        action.primitive
    ]
    if (action.source_asset is not None) is not source_required:
        raise ValidationError(f"invalid source_asset shape at {path}")
    if (action.target_asset is not None) is not target_required:
        raise ValidationError(f"invalid target_asset shape at {path}")
    if (action.path_id is not None) is not path_required:
        raise ValidationError(f"invalid path_id shape at {path}")
    if (action.volume_gb > 0) is not volume_required:
        raise ValidationError(f"invalid volume_gb shape at {path}")
    if (
        action.primitive is Primitive.ENCRYPT_IMPACTED_ASSETS
        and action.target_asset != "compromised-assets"
    ):
        raise ValidationError("encryption selector must be compromised-assets")


def _profile(path: Path) -> SimulationProfile:
    raw = _object(
        load_json(path),
        "$",
        {
            "version",
            "id",
            "label",
            "description",
            "network_mode",
            "least_privilege",
            "immutable_backup",
            "detection_enabled",
            "detection_threshold",
            "sensor_delay_seconds",
            "response_delay_seconds",
            "backup_interval_minutes",
            "unrecoverable_rpo_minutes",
        },
    )
    if raw["version"] != "1.0":
        raise ValidationError("unsupported profile version")
    try:
        network_mode = NetworkMode(_string(raw["network_mode"], "$.network_mode", 16))
    except ValueError as exc:
        raise ValidationError("network_mode must be flat or segmented") from exc
    detection_enabled = _boolean(raw["detection_enabled"], "$.detection_enabled")
    threshold = _integer(raw["detection_threshold"], "$.detection_threshold", 1, 10_000)
    sensor_delay = _integer(
        raw["sensor_delay_seconds"], "$.sensor_delay_seconds", 0, 86_400
    )
    response_delay = _integer(
        raw["response_delay_seconds"], "$.response_delay_seconds", 0, 86_400
    )
    if detection_enabled and (sensor_delay == 0 or response_delay == 0):
        raise ValidationError("enabled detection requires non-zero delays")
    return SimulationProfile(
        version="1.0",
        id=_identifier(raw["id"], "$.id"),
        label=_string(raw["label"], "$.label", 120),
        description=_string(raw["description"], "$.description", 800),
        network_mode=network_mode,
        least_privilege=_boolean(raw["least_privilege"], "$.least_privilege"),
        immutable_backup=_boolean(raw["immutable_backup"], "$.immutable_backup"),
        detection_enabled=detection_enabled,
        detection_threshold=threshold,
        sensor_delay_seconds=sensor_delay,
        response_delay_seconds=response_delay,
        backup_interval_minutes=_integer(
            raw["backup_interval_minutes"], "$.backup_interval_minutes", 1, 10_080
        ),
        unrecoverable_rpo_minutes=_integer(
            raw["unrecoverable_rpo_minutes"], "$.unrecoverable_rpo_minutes", 1, 525_600
        ),
    )


def load_bundle(root: Path | None = None) -> ExperimentBundle:
    bundle_root = (root or default_bundle_root()).resolve()
    integrity = verify_bundle(bundle_root)
    catalog = _object(
        load_json(bundle_root / "catalog.json"),
        "$",
        {"version", "topology", "scenario", "profiles"},
    )
    if catalog["version"] != "1.0":
        raise ValidationError("unsupported bundle catalog version")
    topology_ref = _string(catalog["topology"], "$.topology", 240)
    scenario_ref = _string(catalog["scenario"], "$.scenario", 240)
    profile_refs = catalog["profiles"]
    if not isinstance(profile_refs, list) or len(profile_refs) < 2:
        raise ValidationError("catalog must declare at least two profiles")
    parsed_refs = tuple(
        _string(item, f"$.profiles[{index}]", 240)
        for index, item in enumerate(profile_refs)
    )
    expected_files = {"catalog.json", topology_ref, scenario_ref, *parsed_refs}
    if set(integrity) != expected_files:
        raise IntegrityError("bundle manifest and catalog file sets differ")
    topology = _topology(resolve_inside(bundle_root, topology_ref))
    scenario = _scenario(resolve_inside(bundle_root, scenario_ref), topology)
    profiles = tuple(
        _profile(resolve_inside(bundle_root, item)) for item in parsed_refs
    )
    if len({item.id for item in profiles}) != len(profiles):
        raise ValidationError("profile identifiers must be unique")
    return ExperimentBundle(
        root=bundle_root,
        topology=topology,
        scenario=scenario,
        profiles=profiles,
        integrity=integrity,
    )


def profile_by_id(bundle: ExperimentBundle, profile_id: str) -> SimulationProfile:
    for profile in bundle.profiles:
        if profile.id == profile_id:
            return profile
    raise ValidationError(f"unknown profile: {profile_id}")
