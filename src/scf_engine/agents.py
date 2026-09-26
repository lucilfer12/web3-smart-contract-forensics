from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable

from .engine import analyze
from .evm import analyze_bytecode
from .pipeline import build_validation_pipeline
from .cross_validate import AgentObservation
from .analysis_adapters import adapter_inventory, run_hevm_symbolic, run_echidna, run_forge_fuzz

@dataclass(frozen=True)
class AgentResult:
    agent: str
    status: str
    confidence: float
    evidence: list[dict[str, Any]]
    data: dict[str, Any]

@dataclass(frozen=True)
class AgentSpec:
    name: str
    purpose: str

AGENTS = [
    AgentSpec("static-analyzer", "AST detectors, taint and source evidence"),
    AgentSpec("bytecode-analyzer", "EVM opcode and proxy heuristics"),
    AgentSpec("symbolic-agent", "Optional HEVM symbolic execution"),
    AgentSpec("fuzzing-agent", "Optional Echidna/Foundry fuzzing"),
    AgentSpec("validation-agent", "Deterministic invariants and conflict gate"),
]


def _static(target: str) -> AgentResult:
    result = analyze(target)
    findings = [item.__dict__ for item in result.findings]
    return AgentResult("static-analyzer", "COMPLETED",
        sum(f.get("confidence", 0.0) for f in findings) / len(findings) if findings else 1.0,
        [{"kind": "source-location", "reference": str(f.get("evidence", []))} for f in findings],
        {"summary": result.summary(), "findings": findings})


def _bytecode(value: str) -> AgentResult:
    result = analyze_bytecode(value)
    return AgentResult("bytecode-analyzer", "COMPLETED", 0.75,
        [{"kind": "bytecode", "reference": "operator-supplied bytecode"}], result)


def _optional(project: str, tool: str) -> AgentResult:
    inventory = adapter_inventory()
    if tool == "symbolic":
        result = run_hevm_symbolic(project)
    elif tool == "echidna":
        result = run_echidna(project)
    else:
        result = run_forge_fuzz(project)
    return AgentResult(tool + "-agent", result.status, 1.0 if result.status == "PASSED" else 0.0,
        [{"kind": "tool-run", "reference": tool}], {"inventory": inventory, "result": result.__dict__})
def run_agent_team(target: str, *, bytecode: str | None = None,
                   project: str | None = None, fuzz_tool: str = "forge") -> dict[str, Any]:
    """Run the local evidence agents and gate their combined observations.

    External agents are never represented as successful when their executable is absent.
    The returned observations are suitable for the existing promotion pipeline.
    """
    results = [_static(target)]
    if bytecode:
        results.append(_bytecode(bytecode))
    if project:
        results.append(_optional(project, "symbolic"))
        results.append(_optional(project, fuzz_tool))

    observations: list[AgentObservation] = []
    for result in results:
        for finding in result.data.get("findings", []):
            rule = finding.get("rule_id", finding.get("id", "unknown"))
            observations.append(AgentObservation(
                agent=result.agent,
                finding_id=str(rule),
                status="CONFIRMED" if result.status == "COMPLETED" else "UNAVAILABLE",
                confidence=float(result.confidence),
                evidence=[str(item) for item in result.evidence],
            ))
    validation_case = {"findings": results[0].data.get("findings", [])}
    gate = build_validation_pipeline(validation_case, observations)
    return {
        "schema_version": "1.0.0",
        "agents": [asdict(item) for item in results],
        "validation": gate,
        "capabilities": adapter_inventory(),
    }


def agent_inventory() -> list[dict[str, str]]:
    return [asdict(item) for item in AGENTS]
