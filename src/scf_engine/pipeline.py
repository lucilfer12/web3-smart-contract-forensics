from __future__ import annotations

from typing import Any

from .cross_validate import AgentObservation, validation_report
from .invariants import evaluate_invariants, invariant_summary


def build_validation_pipeline(
    case: dict[str, Any],
    observations: list[AgentObservation] | None = None,
) -> dict[str, Any]:
    invariant_results = evaluate_invariants(case)
    report = validation_report(observations or [])
    return {
        "schema_version": "0.5.0",
        "invariants": {
            "results": [item.__dict__ for item in invariant_results],
            "summary": invariant_summary(invariant_results),
        },
        "cross_validation": report,
        "promotion_gate": {
            "eligible": (
                all(item.status == "PASS" for item in invariant_results)
                and report["summary"]["conflict"] == 0
            ),
            "reason": "Requires all deterministic invariants to pass and no cross-agent conflicts.",
        },
    }
