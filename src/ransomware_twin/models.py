"""Immutable domain models for the enterprise twin and safe scenario."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Tuple


class AssetKind(str, Enum):
    WORKSTATION = "workstation"
    IDENTITY = "identity"
    FILE_SHARE = "file-share"
    BUSINESS_SERVICE = "business-service"
    BACKUP_CONTROL = "backup-control"
    BACKUP_VAULT = "backup-vault"
    SECURITY_SERVICE = "security-service"


class DataClass(str, Enum):
    PRIMARY = "primary"
    SYSTEM = "system"
    BACKUP = "backup"
    NONE = "none"


class NetworkMode(str, Enum):
    FLAT = "flat"
    SEGMENTED = "segmented"


class Primitive(str, Enum):
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVE = "lateral_move"
    EXFILTRATION_ATTEMPT = "exfiltration_attempt"
    ENCRYPT_IMPACTED_ASSETS = "encrypt_impacted_assets"
    DESTROY_RECOVERY_POINTS = "destroy_recovery_points"


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    kind: AssetKind
    zone: str
    criticality: int
    data_gb: float
    data_class: DataClass
    restore_minutes: int
    rebuild_minutes: int
    encryptable: bool
    exfiltratable: bool


@dataclass(frozen=True)
class AccessPath:
    id: str
    source: str
    target: str
    required_role: str
    segmented_allowed: bool


@dataclass(frozen=True)
class Dependency:
    service: str
    depends_on: str


@dataclass(frozen=True)
class Topology:
    version: str
    name: str
    description: str
    assets: Tuple[Asset, ...]
    paths: Tuple[AccessPath, ...]
    dependencies: Tuple[Dependency, ...]


@dataclass(frozen=True)
class ScenarioAction:
    id: str
    at_seconds: int
    stage: str
    primitive: Primitive
    source_asset: str | None
    target_asset: str | None
    path_id: str | None
    volume_gb: float
    signal_score: int


@dataclass(frozen=True)
class Scenario:
    version: str
    id: str
    title: str
    description: str
    safety_invariant: str
    actions: Tuple[ScenarioAction, ...]


@dataclass(frozen=True)
class SimulationProfile:
    version: str
    id: str
    label: str
    description: str
    network_mode: NetworkMode
    least_privilege: bool
    immutable_backup: bool
    detection_enabled: bool
    detection_threshold: int
    sensor_delay_seconds: int
    response_delay_seconds: int
    backup_interval_minutes: int
    unrecoverable_rpo_minutes: int


@dataclass(frozen=True)
class ExperimentBundle:
    root: Path
    topology: Topology
    scenario: Scenario
    profiles: Tuple[SimulationProfile, ...]
    integrity: Mapping[str, str]


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [to_jsonable(item) for item in value]
    return value
