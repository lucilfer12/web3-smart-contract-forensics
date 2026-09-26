from __future__ import annotations

import ctypes
import hashlib
import re
from pathlib import Path
from typing import Iterator

from tree_sitter import Language, Node, Parser
import tree_sitter_solidity

from .models import CallSite, ContractModel, FunctionModel, SourceLocation, SourceUnit, StateVariable


def _language() -> Language:
    # tree-sitter-solidity 1.2.x exposes a raw pointer; ABI 15 needs a capsule
    # when used with modern py-tree-sitter releases.
    make_capsule = ctypes.pythonapi.PyCapsule_New
    make_capsule.restype = ctypes.py_object
    make_capsule.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
    capsule = make_capsule(
        ctypes.c_void_p(tree_sitter_solidity.language()),
        b"tree_sitter.Language",
        None,
    )
    return Language(capsule)


def _text(node: Node | None) -> str:
    return "" if node is None else node.text.decode("utf-8", errors="replace")


def _loc(path: str, node: Node) -> SourceLocation:
    return SourceLocation(
        file=path,
        line=node.start_point[0] + 1,
        column=node.start_point[1] + 1,
        end_line=node.end_point[0] + 1,
        end_column=node.end_point[1] + 1,
    )


def walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.named_children:
        yield from walk(child)


def _children_of_type(node: Node, kind: str) -> list[Node]:
    return [c for c in node.named_children if c.type == kind]


def _field_text(node: Node, name: str) -> str:
    return _text(node.child_by_field_name(name))


def _identifier(node: Node) -> str:
    field = node.child_by_field_name("name")
    if field is not None:
        return _text(field)
    for child in node.named_children:
        if child.type == "identifier":
            return _text(child)
    return ""


def _direct_descendants(node: Node, kinds: set[str]) -> list[Node]:
    out: list[Node] = []
    stack = list(reversed(node.named_children))
    while stack:
        cur = stack.pop()
        if cur.type in kinds:
            out.append(cur)
            continue
        stack.extend(reversed(cur.named_children))
    return out


def _split_base_names(node: Node) -> list[str]:
    text = _field_text(node, "base") or _text(node)
    if " is " not in text:
        return []
    tail = text.split(" is ", 1)[1].split("{", 1)[0]
    return [part.strip().split("(", 1)[0].strip() for part in tail.split(",") if part.strip()]


def _signature(node: Node) -> str:
    name = _identifier(node) or "fallback"
    params = _field_text(node, "parameters")
    return f"{name}{params}"


def _modifiers(node: Node) -> list[str]:
    names: list[str] = []
    for child in node.named_children:
        if child.type == "modifier_invocation":
            value = _text(child).strip().split("(", 1)[0]
            if value:
                names.append(value)
    return names


def _visibility(node: Node) -> str | None:
    for child in node.named_children:
        if child.type == "visibility":
            return _text(child).strip()
    return None


def _mutability(node: Node) -> str | None:
    for child in node.named_children:
        if child.type == "state_mutability":
            return _text(child).strip()
    return None


def _state_vars(contract_node: Node, path: str) -> dict[str, StateVariable]:
    result: dict[str, StateVariable] = {}
    body = contract_node.child_by_field_name("body")
    if body is None:
        return result
    for member in body.named_children:
        if member.type != "state_variable_declaration":
            continue
        name = _identifier(member)
        type_name = _field_text(member, "type")
        visibility = _field_text(member, "visibility") or None
        raw = _text(member)
        result[name] = StateVariable(
            name=name,
            type_name=type_name,
            visibility=visibility,
            location=_loc(path, member),
            constant=" constant" in raw,
            immutable="immutable" in raw,
        )
    return result


def _events(contract_node: Node) -> set[str]:
    body = contract_node.child_by_field_name("body")
    if body is None:
        return set()
    return {_identifier(n) for n in body.named_children if n.type == "event_definition"}


def _modifiers_defined(contract_node: Node) -> set[str]:
    body = contract_node.child_by_field_name("body")
    if body is None:
        return set()
    return {_identifier(n) for n in body.named_children if n.type == "modifier_definition"}


def _call_sites(fn: Node, path: str) -> list[CallSite]:
    calls: list[CallSite] = []
    for call in _direct_descendants(fn, {"call_expression"}):
        callee_node = call.child_by_field_name("function")
        callee = _text(callee_node).strip()
        raw = _text(call)
        dotted = "." in callee
        member_name = callee.rsplit(".", 1)[-1]
        low = member_name in {"call", "delegatecall", "staticcall", "callcode", "send", "transfer"}
        calls.append(
            CallSite(
                kind="external" if dotted or low else "internal",
                callee=callee,
                location=_loc(path, call),
                text=raw,
                external=dotted or low,
                value_transfer="{value:" in raw.replace(" ", ""),
                low_level=low,
            )
        )
    return calls


def _cfg_nodes(node: Node, path: str) -> list[dict[str, object]]:
    body = node.child_by_field_name("body")
    if body is None:
        return []
    kinds = {
        "variable_declaration_statement", "expression_statement", "if_statement",
        "for_statement", "while_statement", "do_while_statement", "return_statement",
        "revert_statement", "emit_statement", "try_statement", "assembly_statement",
    }
    statements = sorted(
        _direct_descendants(body, kinds),
        key=lambda item: (item.start_point[0], item.start_point[1], item.end_point[1]),
    )
    out: list[dict[str, object]] = []
    for index, statement in enumerate(statements):
        kind = statement.type
        out.append({
            "id": f"n{index}",
            "kind": kind,
            "line": statement.start_point[0] + 1,
            "text": _text(statement)[:240],
            "branch": kind in {"if_statement", "try_statement"},
            "loop": kind in {"for_statement", "while_statement", "do_while_statement"},
        })
    for index in range(len(out) - 1):
        out[index]["next"] = f"n{index + 1}"
    return out


def _function_model(contract: str, node: Node, path: str, state_names: set[str]) -> FunctionModel:
    body = node.child_by_field_name("body")
    body_text = _text(body)
    calls = _call_sites(node, path)
    writes: list[str] = []
    for assignment in _direct_descendants(node, {"assignment_expression", "augmented_assignment_expression"}):
        lhs = _field_text(assignment, "left") or _text(assignment).split("=", 1)[0]
        for name in state_names:
            if re.search(rf"\b{re.escape(name)}\b", lhs):
                writes.append(name)
    reads: list[str] = []
    write_set = set(writes)
    for name in state_names:
        if re.search(rf"\b{re.escape(name)}\b", body_text) and name not in write_set:
            reads.append(name)
    return FunctionModel(
        contract=contract,
        name=_identifier(node) or "fallback",
        signature=_signature(node),
        visibility=_visibility(node),
        mutability=_mutability(node),
        modifiers=_modifiers(node),
        location=_loc(path, node),
        body_text=body_text,
        calls=calls,
        writes=sorted(set(writes)),
        reads=sorted(set(reads)),
        loops=len(_direct_descendants(node, {"for_statement", "while_statement", "do_while_statement"})),
        branches=len(_direct_descendants(node, {"if_statement", "ternary_expression", "try_statement"})),
        inline_assembly=bool(_direct_descendants(node, {"assembly_statement"})),
        uses_msg_sender="msg.sender" in body_text,
        uses_msg_value="msg.value" in body_text,
        uses_tx_origin="tx.origin" in body_text,
        uses_timestamp=bool(re.search(r"\bblock\.timestamp\b|\btimestamp\b", body_text)),
        uses_blockhash="blockhash(" in body_text,
        has_require=bool(re.search(r"\brequire\s*\(", body_text)),
        cfg_nodes=_cfg_nodes(node, path),
    )


def parse_source(path: str, source: str) -> SourceUnit:
    parser = Parser(_language())
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    contracts: dict[str, ContractModel] = {}
    imports: list[str] = []
    pragma: str | None = None
    parse_errors: list[str] = []

    if root.has_error:
        for node in walk(root):
            if node.type == "ERROR":
                parse_errors.append(f"syntax error at line {node.start_point[0] + 1}")

    for node in root.named_children:
        if node.type == "import_directive":
            value = _text(node)
            imports.append(value.strip())
        elif node.type == "pragma_directive" and pragma is None:
            pragma = _text(node).strip()

    contract_nodes = _direct_descendants(
        root,
        {"contract_declaration", "interface_declaration", "library_declaration"},
    )
    for contract_node in contract_nodes:
        name = _identifier(contract_node)
        if not name:
            continue
        kind = contract_node.type.removesuffix("_declaration")
        model = ContractModel(
            name=name,
            kind=kind,
            bases=_split_base_names(contract_node),
            location=_loc(path, contract_node),
            state_variables=_state_vars(contract_node, path),
            modifiers=_modifiers_defined(contract_node),
            events=_events(contract_node),
        )
        body = contract_node.child_by_field_name("body")
        if body is not None:
            for member in body.named_children:
                if member.type == "function_definition":
                    fn = _function_model(name, member, path, set(model.state_variables))
                    model.functions[fn.signature] = fn
                elif member.type in {"constructor_definition", "fallback_receive_definition"}:
                    raw_name = "constructor" if member.type == "constructor_definition" else "fallback"
                    fn = FunctionModel(
                        contract=name,
                        name=raw_name,
                        signature=raw_name,
                        visibility=_visibility(member),
                        mutability=_mutability(member),
                        modifiers=_modifiers(member),
                        location=_loc(path, member),
                        body_text=_text(member.child_by_field_name("body")),
                    )
                    fn.calls = _call_sites(member, path)
                    fn.inline_assembly = bool(_direct_descendants(member, {"assembly_statement"}))
                    model.functions[fn.signature] = fn
        contracts[name] = model

    return SourceUnit(
        file=path,
        source_hash=source_hash,
        pragma=pragma,
        imports=imports,
        contracts=contracts,
        parse_errors=sorted(set(parse_errors)),
    )


def parse_path(target: str) -> list[SourceUnit]:
    path = Path(target)
    files = [path] if path.is_file() else sorted(path.rglob("*.sol"))
    units: list[SourceUnit] = []
    for file in files:
        try:
            units.append(parse_source(file.as_posix(), file.read_text(encoding="utf-8")))
        except UnicodeDecodeError:
            units.append(SourceUnit(str(file), "", None, [], {}, ["non-UTF8 source file"]))
        except Exception as exc:
            units.append(SourceUnit(str(file), "", None, [], {}, [f"parser failure: {exc}"]))
    return units
