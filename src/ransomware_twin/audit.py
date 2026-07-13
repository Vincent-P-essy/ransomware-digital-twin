"""Tamper-evident event chaining for deterministic simulation timelines."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

from .errors import IntegrityError
from .serialization import digest


GENESIS_HASH = "0" * 64


def chain_events(events: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    previous = GENESIS_HASH
    result: List[Dict[str, Any]] = []
    for sequence, raw in enumerate(events, start=1):
        event = {"sequence": sequence, "previous_hash": previous, **dict(raw)}
        event["event_hash"] = digest(event)
        previous = event["event_hash"]
        result.append(event)
    return result


def verify_event_chain(events: Iterable[Mapping[str, Any]]) -> bool:
    previous = GENESIS_HASH
    expected_sequence = 1
    for event in events:
        if event.get("sequence") != expected_sequence:
            raise IntegrityError("event sequence is not contiguous")
        if event.get("previous_hash") != previous:
            raise IntegrityError("event previous-hash link is invalid")
        claimed = event.get("event_hash")
        unsigned = {key: value for key, value in event.items() if key != "event_hash"}
        actual = digest(unsigned)
        if claimed != actual:
            raise IntegrityError("event hash is invalid")
        previous = actual
        expected_sequence += 1
    if expected_sequence == 1:
        raise IntegrityError("event chain must not be empty")
    return True
