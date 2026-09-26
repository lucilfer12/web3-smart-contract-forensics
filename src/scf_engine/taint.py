from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import Evidence, Finding, SourceLocation
from .parser import _language, _text, walk
from tree_sitter import Parser, Node


@dataclass
class TaintPath:
    contract: str
    function: str
    sources: list[str]
    sink: str
    variable: str
    location: SourceLocation
    snippet: str


def _lhs_name(node: Node) -> str:
    left = node.child_by_field_name("left")
    if left is None:
        return ""
    text = _text(left).strip()
    match = re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", text)
    return match.group(0) if match else ""


def _rhs_text(node: Node) -> str:
    right = node.child_by_field_name("right") or node.child_by_field_name("value")
    return _text(right)


def _parameters(fn: Node) -> set[str]:
    names: set[str] = set()
    for node in fn.named_children:
        if node.type != "parameter":
            continue
        name_node = node.child_by_field_name("name")
        name = _text(name_node)
        if not name:
            identifiers = [child for child in node.named_children if child.type == "identifier"]
            if identifiers:
                name = _text(identifiers[-1])
        if name:
            names.add(name)
    return names


def analyze_taint_source(source: str, filename: str) -> list[TaintPath]:
    parser = Parser(_language())
    tree = parser.parse(source.encode("utf-8"))
    findings: list[TaintPath] = []
    for fn in [n for n in walk(tree.root_node) if n.type == "function_definition"]:
        name_node = fn.child_by_field_name("name")
        contract_name = "unknown"
        parent = fn.parent
        while parent is not None:
            if parent.type in {"contract_declaration", "interface_declaration", "library_declaration"}:
                contract_name = _text(parent.child_by_field_name("name")) or "unknown"
                break
            parent = parent.parent
        name = _text(name_node) or "fallback"
        tainted = {"msg.sender", "msg.value", "tx.origin", "msg.data"} | _parameters(fn)
        assignments = [n for n in walk(fn) if n.type in {"assignment_expression", "augmented_assignment_expression"}]
        changed = True
        while changed:
            changed = False
            for assignment in assignments:
                lhs = _lhs_name(assignment)
                rhs = _rhs_text(assignment)
                if lhs and lhs not in tainted and any(re.search(rf"\b{re.escape(token)}\b", rhs) for token in tainted):
                    tainted.add(lhs)
                    changed = True
        for call in [n for n in walk(fn) if n.type == "call_expression"]:
            callee = _text(call.child_by_field_name("function"))
            if not callee:
                continue
            low = callee.rsplit(".", 1)[-1]
            if low not in {"call", "delegatecall", "staticcall", "send", "transfer"}:
                continue
            root = callee.split(".", 1)[0]
            if root in tainted:
                findings.append(TaintPath(contract_name, name, sorted(_parameters(fn) & tainted | {root} & tainted), callee, root, SourceLocation(filename, call.start_point[0] + 1, call.start_point[1] + 1), _text(call)))
    return findings


def findings_from_taint(paths: Iterable[TaintPath]) -> list[Finding]:
    out: list[Finding] = []
    for path in paths:
        evidence = Evidence(path.location, path.snippet, "Untrusted parameter or transaction context reaches an external call target.", "SCF-TAINT-001", 0.86)
        out.append(Finding(
            rule_id="SCF-TAINT-001",
            title="Tainted input reaches an external call target",
            severity="High" if path.sink.endswith("delegatecall") else "Medium",
            confidence=0.86,
            description="AST-based def-use propagation connected a user/transaction-controlled value to a dynamic external interaction target.",
            recommendation="Validate and constrain call targets against an explicit trust policy; avoid using raw user-controlled addresses as execution targets.",
            evidence=[evidence],
            contract=path.contract,
            function=path.function,
            cwe="CWE-20",
            tags=["taint", "data-flow", "external-call"],
        ))
    return out
