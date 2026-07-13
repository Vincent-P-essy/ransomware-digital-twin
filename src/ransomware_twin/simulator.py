"""Safe discrete-event simulation and resilience comparison engine.

Every scenario primitive is a state transition over immutable input models. The
engine never executes a command, encrypts a file, or opens an outbound connection.
"""

from __future__ import annotations

import heapq
import platform
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Sequence, Set, Tuple

from . import __version__
from .audit import chain_events, verify_event_chain
from .bundle import load_bundle, profile_by_id
from .errors import ValidationError
from .models import (
    AccessPath,
    Asset,
    AssetKind,
    DataClass,
    ExperimentBundle,
    NetworkMode,
    Primitive,
    ScenarioAction,
    SimulationProfile,
    to_jsonable,
)
from .serialization import digest


ROLE_RANK = {"none": 0, "user": 1, "service": 2, "admin": 3}


@dataclass
class _State:
    compromised: Set[str] = field(default_factory=set)
    encrypted: Set[str] = field(default_factory=set)
    credential_role: str = "none"
    backup_available: bool = True
    cumulative_signal: int = 0
    detection_at: int | None = None
    containment_at: int | None = None
    contained: bool = False
    exfiltrated_gb: float = 0.0


def _snapshot(state: _State) -> Dict[str, Any]:
    return {
        "compromised_assets": sorted(state.compromised),
        "encrypted_assets": sorted(state.encrypted),
        "credential_role": state.credential_role,
        "backup_available": state.backup_available,
        "cumulative_signal": state.cumulative_signal,
        "detection_at_seconds": state.detection_at,
        "containment_at_seconds": state.containment_at,
        "contained": state.contained,
        "exfiltrated_gb": round(state.exfiltrated_gb, 3),
    }


def _event(
    profile: SimulationProfile,
    event_id: str,
    at_seconds: int,
    stage: str,
    primitive: str,
    source_asset: str | None,
    target_asset: str | None,
    outcome: str,
    reason: str,
    signal_score: int,
    affected_assets: Sequence[str],
    exfiltrated_gb: float,
) -> Dict[str, Any]:
    return {
        "event_id": f"{profile.id}:{event_id}",
        "profile_id": profile.id,
        "at_seconds": at_seconds,
        "stage": stage,
        "primitive": primitive,
        "source_asset": source_asset,
        "target_asset": target_asset,
        "outcome": outcome,
        "reason": reason,
        "signal_score": signal_score,
        "affected_assets": sorted(affected_assets),
        "exfiltrated_gb": round(exfiltrated_gb, 3),
        "simulation_only": True,
    }


def _process_action(
    action: ScenarioAction,
    profile: SimulationProfile,
    state: _State,
    assets: Mapping[str, Asset],
    paths: Mapping[str, AccessPath],
) -> Dict[str, Any]:
    source = action.source_asset
    target = action.target_asset
    affected: List[str] = []
    exfiltrated = 0.0
    outcome = "blocked"
    reason = "precondition-not-met"
    blocked_by_containment = state.contained and action.primitive in {
        Primitive.LATERAL_MOVE,
        Primitive.EXFILTRATION_ATTEMPT,
        Primitive.ENCRYPT_IMPACTED_ASSETS,
        Primitive.DESTROY_RECOVERY_POINTS,
    }
    if blocked_by_containment:
        outcome = "prevented"
        reason = "automated-containment"
    elif action.primitive is Primitive.INITIAL_ACCESS:
        assert target is not None
        state.compromised.add(target)
        affected.append(target)
        outcome = "success"
        reason = "controlled-initial-state-transition"
    elif action.primitive is Primitive.CREDENTIAL_ACCESS:
        assert source is not None
        if source in state.compromised:
            state.credential_role = "user" if profile.least_privilege else "admin"
            outcome = "limited" if profile.least_privilege else "success"
            reason = (
                "least-privilege-scope"
                if profile.least_privilege
                else "broad-credential-scope"
            )
    elif action.primitive is Primitive.LATERAL_MOVE:
        assert action.path_id is not None
        path = paths[action.path_id]
        source, target = path.source, path.target
        if source not in state.compromised:
            reason = "source-not-compromised"
        elif (
            profile.network_mode is NetworkMode.SEGMENTED and not path.segmented_allowed
        ):
            outcome = "prevented"
            reason = "segmentation-policy"
        elif ROLE_RANK[state.credential_role] < ROLE_RANK[path.required_role]:
            outcome = "prevented"
            reason = "least-privilege-policy"
        elif target in state.compromised:
            outcome = "no-op"
            reason = "target-already-compromised"
        else:
            state.compromised.add(target)
            affected.append(target)
            outcome = "success"
            reason = "simulated-access-path"
    elif action.primitive is Primitive.EXFILTRATION_ATTEMPT:
        assert target is not None
        asset = assets[target]
        if target in state.compromised and asset.exfiltratable:
            exfiltrated = min(action.volume_gb, asset.data_gb)
            state.exfiltrated_gb += exfiltrated
            outcome = "success"
            reason = "simulated-data-counter-only"
        elif not asset.exfiltratable:
            outcome = "prevented"
            reason = "data-egress-policy"
    elif action.primitive is Primitive.ENCRYPT_IMPACTED_ASSETS:
        affected = sorted(
            asset_id for asset_id in state.compromised if assets[asset_id].encryptable
        )
        if affected:
            state.encrypted.update(affected)
            outcome = "success"
            reason = "state-flags-only-no-file-operations"
        else:
            outcome = "no-op"
            reason = "no-encryptable-simulated-assets"
    elif action.primitive is Primitive.DESTROY_RECOVERY_POINTS:
        assert source is not None and target is not None
        if source not in state.compromised:
            reason = "backup-control-not-compromised"
        elif profile.immutable_backup:
            outcome = "prevented"
            reason = "immutable-recovery-policy"
        else:
            state.backup_available = False
            outcome = "success"
            reason = "simulated-recovery-point-state-change"
    else:  # pragma: no cover - enum exhaustiveness guard
        raise AssertionError(f"unhandled primitive: {action.primitive}")
    return _event(
        profile=profile,
        event_id=action.id,
        at_seconds=action.at_seconds,
        stage=action.stage,
        primitive=action.primitive.value,
        source_asset=source,
        target_asset=target,
        outcome=outcome,
        reason=reason,
        signal_score=action.signal_score,
        affected_assets=affected,
        exfiltrated_gb=exfiltrated,
    )


def _metrics(
    bundle: ExperimentBundle,
    profile: SimulationProfile,
    state: _State,
    events: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    assets = {item.id: item for item in bundle.topology.assets}
    total_assets = len(assets)
    critical_compromise_times = [
        int(event["at_seconds"])
        for event in events
        if event["primitive"]
        in {Primitive.INITIAL_ACCESS.value, Primitive.LATERAL_MOVE.value}
        and event["outcome"] == "success"
        and any(assets[item].criticality >= 4 for item in event["affected_assets"])
    ]
    compromise_times = [
        int(event["at_seconds"])
        for event in events
        if event["primitive"]
        in {Primitive.INITIAL_ACCESS.value, Primitive.LATERAL_MOVE.value}
        and event["outcome"] == "success"
        and event["affected_assets"]
    ]
    primary_assets = [
        item for item in assets.values() if item.data_class is DataClass.PRIMARY
    ]
    total_primary_data = sum(item.data_gb for item in primary_assets)
    encrypted_primary_data = sum(
        assets[item].data_gb
        for item in state.encrypted
        if assets[item].data_class is DataClass.PRIMARY
    )
    irrecoverable_data = encrypted_primary_data if not state.backup_available else 0.0
    data_lost_percent = (
        irrecoverable_data / total_primary_data * 100 if total_primary_data else 0.0
    )
    if state.encrypted:
        recovery_times = [
            (
                assets[item].restore_minutes
                if state.backup_available
                else assets[item].rebuild_minutes
            )
            for item in state.encrypted
        ]
        rto_minutes = max(recovery_times, default=0) + 30 + len(state.encrypted) * 5
    elif state.contained:
        rto_minutes = 30 + len(state.compromised) * 4
    elif state.compromised:
        rto_minutes = 15 + len(state.compromised) * 2
    else:
        rto_minutes = 0
    rpo_minutes = (
        0
        if encrypted_primary_data == 0
        else (
            profile.backup_interval_minutes
            if state.backup_available
            else profile.unrecoverable_rpo_minutes
        )
    )
    total_weight = sum(item.criticality for item in assets.values())
    affected_weight = sum(assets[item].criticality for item in state.compromised)
    blast = len(state.compromised) / total_assets * 100
    weighted_blast = affected_weight / total_weight * 100
    exfil_percent = (
        state.exfiltrated_gb / total_primary_data * 100 if total_primary_data else 0.0
    )
    rto_penalty = min(rto_minutes / 1_000 * 100, 100)
    resilience_score = max(
        0.0,
        100
        - weighted_blast * 0.35
        - data_lost_percent * 0.35
        - min(exfil_percent, 100) * 0.15
        - rto_penalty * 0.15,
    )
    service_kinds = {
        AssetKind.IDENTITY,
        AssetKind.FILE_SHARE,
        AssetKind.BUSINESS_SERVICE,
    }
    zone_counts: Dict[str, int] = {}
    for item in state.compromised:
        zone = assets[item].zone
        zone_counts[zone] = zone_counts.get(zone, 0) + 1
    blocked_reasons: Dict[str, int] = {}
    for event in events:
        if event["outcome"] in {"blocked", "prevented"}:
            reason = str(event["reason"])
            blocked_reasons[reason] = blocked_reasons.get(reason, 0) + 1
    completed_stages = sorted(
        {
            str(event["stage"])
            for event in events
            if event["stage"] != "defense" and event["outcome"] == "success"
        }
    )
    return {
        "total_assets": total_assets,
        "machines_touched": len(state.compromised),
        "compromised_assets": sorted(state.compromised),
        "critical_assets_compromised": sorted(
            item for item in state.compromised if assets[item].criticality >= 4
        ),
        "encrypted_assets": len(state.encrypted),
        "encrypted_asset_ids": sorted(state.encrypted),
        "service_outage_count": sum(
            assets[item].kind in service_kinds for item in state.encrypted
        ),
        "time_to_critical_compromise_seconds": (
            min(critical_compromise_times) if critical_compromise_times else None
        ),
        "time_to_last_compromise_seconds": max(compromise_times)
        if compromise_times
        else None,
        "time_to_detection_seconds": state.detection_at,
        "time_to_confinement_seconds": state.containment_at,
        "blast_radius_percent": round(blast, 3),
        "weighted_blast_radius_percent": round(weighted_blast, 3),
        "blast_radius_by_zone": dict(sorted(zone_counts.items())),
        "primary_data_gb": round(total_primary_data, 3),
        "encrypted_primary_data_gb": round(encrypted_primary_data, 3),
        "exfiltrated_data_gb": round(state.exfiltrated_gb, 3),
        "irrecoverable_data_gb": round(irrecoverable_data, 3),
        "data_lost_percent": round(data_lost_percent, 3),
        "backup_available": state.backup_available,
        "rto_minutes": rto_minutes,
        "rpo_minutes": rpo_minutes,
        "scenario_duration_seconds": max(
            item.at_seconds for item in bundle.scenario.actions
        ),
        "completed_attack_stages": completed_stages,
        "blocked_events_by_control": dict(sorted(blocked_reasons.items())),
        "resilience_score": round(resilience_score, 1),
    }


def _functional_view(report: Mapping[str, Any]) -> Dict[str, Any]:
    engine = dict(report["engine"])
    engine.pop("python", None)
    return {
        "report_version": report["report_version"],
        "engine": engine,
        "scenario": report["scenario"],
        "profile": report["profile"],
        "topology": report["topology"],
        "bundle_integrity": report["bundle_integrity"],
        "safety": report["safety"],
        "metrics": report["metrics"],
        "events": report["events"],
    }


def run_simulation(
    bundle: ExperimentBundle | None = None, profile_id: str = "flat-baseline"
) -> Dict[str, Any]:
    started = time.perf_counter_ns()
    experiment = bundle or load_bundle()
    profile = profile_by_id(experiment, profile_id)
    assets = {item.id: item for item in experiment.topology.assets}
    paths = {item.id: item for item in experiment.topology.paths}
    state = _State()
    queue: List[Tuple[int, int, str, str, Any]] = []
    for action in experiment.scenario.actions:
        heapq.heappush(queue, (action.at_seconds, 20, action.id, "action", action))
    raw_events: List[Dict[str, Any]] = []
    while queue:
        at_seconds, _, event_id, event_kind, payload = heapq.heappop(queue)
        if event_kind == "detection":
            event = _event(
                profile,
                event_id,
                at_seconds,
                "defense",
                "detection_signal",
                "siem",
                "response-orchestrator",
                "success",
                "deterministic-signal-threshold",
                0,
                [],
                0.0,
            )
        elif event_kind == "containment":
            state.contained = True
            event = _event(
                profile,
                event_id,
                at_seconds,
                "defense",
                "automated_containment",
                "response-orchestrator",
                "compromised-assets",
                "success",
                "simulated-isolation-state-change",
                0,
                sorted(state.compromised),
                0.0,
            )
        else:
            action = payload
            if not isinstance(action, ScenarioAction):
                raise AssertionError("invalid internal event payload")
            event = _process_action(action, profile, state, assets, paths)
            state.cumulative_signal += action.signal_score
            if (
                profile.detection_enabled
                and state.detection_at is None
                and state.cumulative_signal >= profile.detection_threshold
            ):
                state.detection_at = action.at_seconds + profile.sensor_delay_seconds
                state.containment_at = (
                    state.detection_at + profile.response_delay_seconds
                )
                heapq.heappush(
                    queue,
                    (
                        state.detection_at,
                        10,
                        "defense-detection",
                        "detection",
                        None,
                    ),
                )
                heapq.heappush(
                    queue,
                    (
                        state.containment_at,
                        10,
                        "defense-containment",
                        "containment",
                        None,
                    ),
                )
        event["state_after"] = _snapshot(state)
        raw_events.append(event)
    events = chain_events(raw_events)
    verify_event_chain(events)
    report: Dict[str, Any] = {
        "report_version": "1.0",
        "engine": {
            "name": "ransomware-digital-twin",
            "version": __version__,
            "python": platform.python_version(),
            "execution_model": "deterministic-discrete-event/v1",
        },
        "scenario": to_jsonable(experiment.scenario),
        "profile": to_jsonable(profile),
        "topology": {
            "name": experiment.topology.name,
            "asset_count": len(experiment.topology.assets),
            "path_count": len(experiment.topology.paths),
            "dependency_count": len(experiment.topology.dependencies),
            "zones": sorted({item.zone for item in experiment.topology.assets}),
        },
        "bundle_integrity": dict(sorted(experiment.integrity.items())),
        "safety": {
            "simulation_only": True,
            "state_transitions_only": True,
            "host_file_encryption": False,
            "payload_execution": False,
            "network_egress": False,
            "free_form_commands": False,
        },
        "metrics": _metrics(experiment, profile, state, events),
        "events": events,
        "measurement": {
            "wall_clock_ms": round((time.perf_counter_ns() - started) / 1_000_000, 6),
            "environment_dependent": True,
        },
    }
    report["functional_sha256"] = digest(_functional_view(report))
    return report


def functional_view(report: Mapping[str, Any]) -> Dict[str, Any]:
    return _functional_view(report)


def run_comparison(
    bundle: ExperimentBundle | None = None,
    profile_ids: Sequence[str] = ("flat-baseline", "resilient-reference"),
) -> Dict[str, Any]:
    started = time.perf_counter_ns()
    experiment = bundle or load_bundle()
    if len(profile_ids) < 2 or len(set(profile_ids)) != len(profile_ids):
        raise ValidationError("comparison requires at least two unique profiles")
    reports = [run_simulation(experiment, profile_id) for profile_id in profile_ids]
    baseline = reports[0]
    deltas: Dict[str, Dict[str, Any]] = {}
    metric_names = (
        "machines_touched",
        "encrypted_assets",
        "exfiltrated_data_gb",
        "data_lost_percent",
        "rto_minutes",
        "rpo_minutes",
        "blast_radius_percent",
        "weighted_blast_radius_percent",
        "resilience_score",
    )
    for report in reports[1:]:
        profile_id = str(report["profile"]["id"])
        deltas[profile_id] = {
            name: round(
                float(report["metrics"][name]) - float(baseline["metrics"][name]), 3
            )
            for name in metric_names
        }
    best = max(reports, key=lambda item: item["metrics"]["resilience_score"])
    comparison: Dict[str, Any] = {
        "comparison_version": "1.0",
        "scenario_id": experiment.scenario.id,
        "baseline_profile_id": baseline["profile"]["id"],
        "profile_ids": list(profile_ids),
        "best_resilience_profile_id": best["profile"]["id"],
        "reports": reports,
        "deltas_vs_baseline": deltas,
        "safety": {
            "simulation_only": True,
            "external_effects": "none",
        },
        "measurement": {
            "wall_clock_ms": round((time.perf_counter_ns() - started) / 1_000_000, 6),
            "environment_dependent": True,
        },
    }
    comparison["functional_sha256"] = digest(comparison_functional_view(comparison))
    return comparison


def comparison_functional_view(comparison: Mapping[str, Any]) -> Dict[str, Any]:
    functional = {
        key: value
        for key, value in comparison.items()
        if key not in {"measurement", "functional_sha256"}
    }
    functional["reports"] = [
        functional_view(report) for report in comparison["reports"]
    ]
    return functional
