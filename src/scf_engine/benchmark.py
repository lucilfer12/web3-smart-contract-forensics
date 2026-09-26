from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import analyze


@dataclass
class BenchmarkCase:
    name: str
    target: str
    expect: set[str]
    forbid: set[str]


@dataclass
class BenchmarkResult:
    case: str
    passed: bool
    expected_missing: list[str]
    forbidden_present: list[str]
    finding_count: int


def run_case(case: BenchmarkCase) -> BenchmarkResult:
    result = analyze(case.target)
    observed = {finding.rule_id for finding in result.findings}
    missing = sorted(case.expect - observed)
    present = sorted(case.forbid & observed)
    return BenchmarkResult(case.name, not missing and not present, missing, present, len(result.findings))


def run_benchmark(root: str) -> list[BenchmarkResult]:
    base = Path(root)
    cases = [
        BenchmarkCase(
            "mixed-vulnerable",
            str(base / "fixtures" / "contracts" / "vulnerable"),
            {"SCF-REENTRANCY-001", "SCF-AUTH-001", "SCF-UPGRADE-001", "SCF-DESTRUCT-001"},
            set(),
        ),
        BenchmarkCase(
            "guarded-clean",
            str(base / "fixtures" / "contracts" / "clean"),
            set(),
            {"SCF-REENTRANCY-001", "SCF-ACCESS-001", "SCF-AUTH-001", "SCF-UPGRADE-002"},
        ),
    ]
    return [run_case(case) for case in cases]


def benchmark_dict(results: list[BenchmarkResult]) -> dict[str, Any]:
    return {
        "passed": all(item.passed for item in results),
        "cases": [
            {
                "case": item.case,
                "passed": item.passed,
                "expected_missing": item.expected_missing,
                "forbidden_present": item.forbidden_present,
                "finding_count": item.finding_count,
            }
            for item in results
        ],
    }
