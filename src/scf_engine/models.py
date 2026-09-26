from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int
    column: int = 1
    end_line: int | None = None
    end_column: int | None = None


@dataclass
class CallSite:
    kind: str
    callee: str
    location: SourceLocation
    text: str = ""
    external: bool = False
    value_transfer: bool = False
    low_level: bool = False


@dataclass
class StateVariable:
    name: str
    type_name: str
    visibility: str | None
    location: SourceLocation
    constant: bool = False
    immutable: bool = False


@dataclass
class FunctionModel:
    contract: str
    name: str
    signature: str
    visibility: str | None
    mutability: str | None
    modifiers: list[str]
    location: SourceLocation
    body_text: str
    calls: list[CallSite] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    loops: int = 0
    branches: int = 0
    inline_assembly: bool = False
    uses_msg_sender: bool = False
    uses_msg_value: bool = False
    uses_tx_origin: bool = False
    uses_timestamp: bool = False
    uses_blockhash: bool = False
    has_require: bool = False
    cfg_nodes: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ContractModel:
    name: str
    kind: str
    bases: list[str]
    location: SourceLocation
    state_variables: dict[str, StateVariable] = field(default_factory=dict)
    functions: dict[str, FunctionModel] = field(default_factory=dict)
    modifiers: set[str] = field(default_factory=set)
    events: set[str] = field(default_factory=set)


@dataclass
class SourceUnit:
    file: str
    source_hash: str
    pragma: str | None
    imports: list[str]
    contracts: dict[str, ContractModel]
    parse_errors: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    source: SourceLocation
    snippet: str
    reason: str
    rule: str
    confidence: float


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    description: str
    recommendation: str
    evidence: list[Evidence]
    contract: str
    function: str | None = None
    cwe: str | None = None
    swc: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    tool_version: str
    target: str
    sources: list[SourceUnit]
    findings: list[Finding]
    metrics: dict[str, Any]
    graph: dict[str, list[dict[str, Any]]]

    def to_dict(self) -> dict[str, Any]:
        def jsonable(value: Any) -> Any:
            if hasattr(value, "__dataclass_fields__"):
                return {name: jsonable(getattr(value, name)) for name in value.__dataclass_fields__}
            if isinstance(value, dict):
                return {str(key): jsonable(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [jsonable(item) for item in value]
            if isinstance(value, set):
                return sorted(jsonable(item) for item in value)
            return value
        return jsonable(self)

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for item in self.findings:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return {
            "target": self.target,
            "sources": len(self.sources),
            "contracts": sum(len(s.contracts) for s in self.sources),
            "functions": sum(
                len(c.functions) for s in self.sources for c in s.contracts.values()
            ),
            "findings": len(self.findings),
            "severity_counts": counts,
            "metrics": self.metrics,
        }


SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
