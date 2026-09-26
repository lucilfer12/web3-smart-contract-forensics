from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentObservation:
    agent: str
    finding_id: str
    status: str
    confidence: float
    evidence: list[str]


@dataclass(frozen=True)
class CrossValidationResult:
    finding_id: str
    consensus: str
    confidence: float
    agreeing_agents: list[str]
    dissenting_agents: list[str]
    evidence: list[str]


def cross_validate(observations: list[AgentObservation]) -> list[CrossValidationResult]:
    grouped: dict[str, list[AgentObservation]] = {}
    for item in observations:
        grouped.setdefault(item.finding_id, []).append(item)
    results: list[CrossValidationResult] = []
    for finding_id, group in sorted(grouped.items()):
        positive = [x for x in group if x.status == "CONFIRMED"]
        negative = [x for x in group if x.status == "REJECTED"]
        if positive and not negative:
            consensus = "CONFIRMED"
        elif negative and not positive:
            consensus = "REJECTED"
        else:
            consensus = "CONFLICT"
        confidence = sum(x.confidence for x in group) / len(group)
        evidence = sorted({e for x in group for e in x.evidence})
        results.append(CrossValidationResult(
            finding_id=finding_id,
            consensus=consensus,
            confidence=round(confidence, 4),
            agreeing_agents=[x.agent for x in group if x.status == ("CONFIRMED" if positive else "REJECTED")],
            dissenting_agents=[x.agent for x in group if x.status != ("CONFIRMED" if positive else "REJECTED")],
            evidence=evidence,
        ))
    return results


def validation_report(observations: list[AgentObservation]) -> dict[str, Any]:
    results = cross_validate(observations)
    return {
        "schema_version": "0.5.0",
        "findings": [item.__dict__ for item in results],
        "summary": {
            "total": len(results),
            "confirmed": sum(x.consensus == "CONFIRMED" for x in results),
            "rejected": sum(x.consensus == "REJECTED" for x in results),
            "conflict": sum(x.consensus == "CONFLICT" for x in results),
        },
        "limitations": [
            "Consensus is an evidence aggregation mechanism, not proof of exploitability.",
            "Agent observations must point to independently inspectable evidence.",
        ],
    }
