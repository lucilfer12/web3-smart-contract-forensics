from __future__ import annotations

from importlib.metadata import entry_points
from typing import Iterable

from .detectors.base import Detector


ENTRY_POINT_GROUP = "scf_engine.detectors"


def discover_detectors() -> list[Detector]:
    discovered: list[Detector] = []
    try:
        groups = entry_points()
        selected = groups.select(group=ENTRY_POINT_GROUP) if hasattr(groups, "select") else groups.get(ENTRY_POINT_GROUP, [])
    except Exception:
        selected = []
    for entry in selected:
        try:
            loaded = entry.load()
            detector = loaded() if isinstance(loaded, type) else loaded
            if isinstance(detector, Detector):
                discovered.append(detector)
        except Exception:
            continue
    return discovered


def all_detectors(builtins: Iterable[Detector]) -> list[Detector]:
    result = list(builtins)
    result.extend(discover_detectors())
    seen: set[str] = set()
    unique: list[Detector] = []
    for detector in result:
        if detector.rule_id in seen:
            continue
        seen.add(detector.rule_id)
        unique.append(detector)
    return unique
