from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class InvariantResult:
    name: str
    status: str
    detail: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class Invariant:
    name: str
    check: Callable[[dict[str, Any]], bool]
    description: str


def no_unexpected_external_value_flow(case: dict[str, Any]) -> bool:
    root = case.get("execution", {}).get("root", {})
    return int(root.get("value", 0)) >= 0


def no_unpriced_profit_claim(case: dict[str, Any]) -> bool:
    return case.get("economic", {}).get("profit_claim") is None


BUILTIN_INVARIANTS = [
    Invariant(
        "nonnegative-native-root-value",
        no_unexpected_external_value_flow,
        "Root execution value must be represented as a non-negative amount.",
    ),
    Invariant(
        "no-unpriced-profit-claim",
        no_unpriced_profit_claim,
        "The engine must not claim profit without valuation evidence.",
    ),
]


def evaluate_invariants(case: dict[str, Any], invariants: list[Invariant] | None = None) -> list[InvariantResult]:
    results: list[InvariantResult] = []
    for invariant in invariants or BUILTIN_INVARIANTS:
        try:
            passed = bool(invariant.check(case))
            results.append(InvariantResult(
                invariant.name,
                "PASS" if passed else "FAIL",
                invariant.description,
                {"source": "deterministic-invariant"},
            ))
        except Exception as exc:
            results.append(InvariantResult(
                invariant.name,
                "ERROR",
                str(exc),
                {"source": "deterministic-invariant"},
            ))
    return results


def invariant_summary(results: list[InvariantResult]) -> dict[str, Any]:
    counts = {key: sum(item.status == key for item in results) for key in ("PASS", "FAIL", "ERROR")}
    return {"total": len(results), **counts}
