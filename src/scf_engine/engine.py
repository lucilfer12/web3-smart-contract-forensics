from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from .detectors import DEFAULT_DETECTORS
from .models import AnalysisResult, ContractModel, Finding, SourceUnit
from .parser import parse_path
from .taint import analyze_taint_source, findings_from_taint
from .registry import all_detectors

TOOL_VERSION = "0.4.0"


def _node_id(kind: str, *parts: str) -> str:
    return kind + ":" + ":".join(parts)


def build_graph(units: list[SourceUnit]) -> dict[str, list[dict[str, object]]]:
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    for unit in units:
        for contract in unit.contracts.values():
            cid = _node_id("contract", unit.file, contract.name)
            nodes.append({"id": cid, "type": "contract", "name": contract.name, "file": unit.file})
            for base in contract.bases:
                edges.append({"from": cid, "to": _node_id("contract", "*", base), "type": "inherits"})
            for var in contract.state_variables.values():
                vid = _node_id("state", unit.file, contract.name, var.name)
                nodes.append({"id": vid, "type": "state", "name": var.name, "file": unit.file, "line": var.location.line})
                edges.append({"from": cid, "to": vid, "type": "contains"})
            for fn in contract.functions.values():
                fid = _node_id("function", unit.file, contract.name, fn.signature)
                nodes.append({"id": fid, "type": "function", "name": fn.signature, "file": unit.file, "line": fn.location.line})
                edges.append({"from": cid, "to": fid, "type": "contains"})
                for call in fn.calls:
                    edges.append({"from": fid, "to": _node_id("external" if call.external else "function", call.callee), "type": "calls", "line": call.location.line})
                for name in fn.reads:
                    edges.append({"from": fid, "to": _node_id("state", unit.file, contract.name, name), "type": "reads"})
                for name in fn.writes:
                    edges.append({"from": fid, "to": _node_id("state", unit.file, contract.name, name), "type": "writes"})
                for cfg in fn.cfg_nodes:
                    node_id = _node_id("cfg", unit.file, contract.name, fn.signature, str(cfg["id"]))
                    nodes.append({"id": node_id, "type": "cfg", "kind": cfg["kind"], "line": cfg["line"], "branch": cfg["branch"], "loop": cfg["loop"]})
                    if "next" in cfg:
                        edges.append({"from": node_id, "to": _node_id("cfg", unit.file, contract.name, fn.signature, str(cfg["next"])), "type": "flow"})
                cfg_ids = {str(item["id"]): _node_id("cfg", unit.file, contract.name, fn.signature, str(item["id"])) for item in fn.cfg_nodes}
                for index, cfg in enumerate(fn.cfg_nodes):
                    current = cfg_ids.get(str(cfg["id"]))
                    if not current:
                        continue
                    if cfg.get("branch") and "next" in cfg:
                        edges.append({"from": current, "to": cfg_ids[str(cfg["next"])], "type": "branch_true"})
                        if index + 2 < len(fn.cfg_nodes):
                            edges.append({"from": current, "to": cfg_ids[str(fn.cfg_nodes[index + 2]["id"])], "type": "branch_false"})
                    if cfg.get("loop") and "next" in cfg:
                        edges.append({"from": cfg_ids[str(cfg["next"])], "to": current, "type": "loop_back"})
                        if index + 2 < len(fn.cfg_nodes):
                            edges.append({"from": current, "to": cfg_ids[str(fn.cfg_nodes[index + 2]["id"])], "type": "loop_exit"})
    lookup = {
        (unit.file, contract.name, fn.name): _node_id("function", unit.file, contract.name, fn.signature)
        for unit in units for contract in unit.contracts.values() for fn in contract.functions.values()
    }
    for unit in units:
        for contract in unit.contracts.values():
            for fn in contract.functions.values():
                source_id = lookup.get((unit.file, contract.name, fn.name))
                if not source_id:
                    continue
                for call in fn.calls:
                    if not call.external:
                        target_id = lookup.get((unit.file, contract.name, call.callee))
                        if target_id:
                            edges.append({"from": source_id, "to": target_id, "type": "calls", "resolved": True, "line": call.location.line})
    return {"nodes": nodes, "edges": edges}


def _run_detectors(units: list[SourceUnit], detectors: Iterable) -> list[Finding]:
    findings: list[Finding] = []
    for unit in units:
        for contract in unit.contracts.values():
            for function in contract.functions.values():
                for detector in detectors:
                    findings.extend(detector.run(unit, contract, function))
    unique: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        first = finding.evidence[0].source if finding.evidence else None
        key = (finding.rule_id, finding.contract, finding.function, first.file if first else "", first.line if first else 0)
        unique[key] = finding
    severity_order = {name: index for index, name in enumerate(("Informational", "Low", "Medium", "High", "Critical"))}
    return sorted(unique.values(), key=lambda x: (-severity_order.get(x.severity, 0), -x.confidence, x.rule_id, x.function or ""))


def _metrics(units: list[SourceUnit], findings: list[Finding], graph: dict[str, list[dict[str, object]]]) -> dict[str, object]:
    contracts = [c for u in units for c in u.contracts.values()]
    functions = [f for c in contracts for f in c.functions.values()]
    calls = [call for f in functions for call in f.calls]
    return {
        "files": len(units),
        "contracts": len(contracts),
        "functions": len(functions),
        "state_variables": sum(len(c.state_variables) for c in contracts),
        "external_calls": sum(1 for c in calls if c.external),
        "low_level_calls": sum(1 for c in calls if c.low_level),
        "value_transfers": sum(1 for c in calls if c.value_transfer),
        "loops": sum(f.loops for f in functions),
        "branches": sum(f.branches for f in functions),
        "cfg_nodes": sum(len(f.cfg_nodes) for f in functions),
        "parse_errors": sum(len(u.parse_errors) for u in units),
        "findings_by_rule": dict(Counter(f.rule_id for f in findings)),
        "graph_nodes": len(graph["nodes"]),
        "graph_edges": len(graph["edges"]),
        "source_roots": sorted({str(Path(u.file).parent) for u in units}),
    }


def analyze(target: str, detectors: Iterable | None = None) -> AnalysisResult:
    units = parse_path(target)
    active = all_detectors(detectors or DEFAULT_DETECTORS)
    findings = _run_detectors(units, active)
    for unit in units:
        path = Path(unit.file)
        if path.is_file():
            try:
                findings.extend(findings_from_taint(analyze_taint_source(path.read_text(encoding="utf-8"), unit.file)))
            except (OSError, UnicodeDecodeError):
                pass
    dedup: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        location = finding.evidence[0].source if finding.evidence else None
        key = (finding.rule_id, location.file if location else "", location.line if location else 0, finding.function)
        dedup[key] = finding
    findings = list(dedup.values())
    severity_order = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    findings.sort(key=lambda item: (-severity_order.get(item.severity, 0), -item.confidence, item.rule_id, item.function or ""))
    graph = build_graph(units)
    return AnalysisResult(
        tool_version=TOOL_VERSION,
        target=str(Path(target)),
        sources=units,
        findings=findings,
        metrics=_metrics(units, findings, graph),
        graph=graph,
    )
