from __future__ import annotations

from typing import Any


def _esc(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def to_dot(graph: dict[str, list[dict[str, Any]]]) -> str:
    lines = ["digraph SCF {", "  rankdir=LR;"]
    for node in graph.get("nodes", []):
        label = node.get("name", node.get("kind", node["id"]))
        shape = {"contract": "box", "state": "cylinder", "function": "ellipse", "cfg": "note"}.get(str(node.get("type")), "ellipse")
        lines.append(f'  "{_esc(node["id"])}" [label="{_esc(label)}", shape={shape}];')
    for edge in graph.get("edges", []):
        label = edge.get("type", "")
        lines.append(f'  "{_esc(edge["from"])}" -> "{_esc(edge["to"])}" [label="{_esc(label)}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_mermaid(graph: dict[str, list[dict[str, Any]]]) -> str:
    lines = ["flowchart LR"]
    ids = {}
    for index, node in enumerate(graph.get("nodes", [])):
        alias = f"N{index}"
        ids[node["id"]] = alias
        label = _esc(node.get("name", node.get("kind", node["id"])))
        lines.append(f'  {alias}["{label}"]')
    for edge in graph.get("edges", []):
        left = ids.get(edge.get("from")); right = ids.get(edge.get("to"))
        if left and right:
            label = _esc(edge.get("type", ""))
            lines.append(f"  {left} -->|{label}| {right}")
    return "\n".join(lines) + "\n"
