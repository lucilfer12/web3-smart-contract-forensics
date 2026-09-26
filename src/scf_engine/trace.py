from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

TRANSFER_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@dataclass
class TraceFrame:
    depth: int
    call_type: str
    sender: str
    target: str
    value: int
    input_data: str
    path: str
    children: list["TraceFrame"] = field(default_factory=list)


@dataclass
class TokenTransfer:
    token: str
    sender: str
    receiver: str
    amount: int
    log_index: int | None = None


def _hex_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not value:
        return 0
    text = str(value)
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0


def _walk_frames(raw: dict[str, Any], depth: int = 0, path: str = "0") -> TraceFrame:
    frame = TraceFrame(
        depth=depth,
        call_type=str(raw.get("type", raw.get("callType", "CALL"))).upper(),
        sender=str(raw.get("from", raw.get("sender", ""))),
        target=str(raw.get("to", raw.get("target", ""))),
        value=_hex_int(raw.get("value")),
        input_data=str(raw.get("input", raw.get("data", ""))),
        path=path,
    )
    children = raw.get("calls", raw.get("children", [])) or []
    frame.children = [_walk_frames(child, depth + 1, f"{path}.{i}") for i, child in enumerate(children)]
    return frame


def iter_frames(frame: TraceFrame) -> Iterator[TraceFrame]:
    yield frame
    for child in frame.children:
        yield from iter_frames(child)


def _transfer_from_log(log: dict[str, Any]) -> TokenTransfer | None:
    topics = [str(item).lower().removeprefix("0x") for item in log.get("topics", [])]
    if not topics or topics[0] != TRANSFER_TOPIC or len(topics) < 3:
        return None
    try:
        sender = "0x" + topics[1][-40:]
        receiver = "0x" + topics[2][-40:]
        data = str(log.get("data", "0x0"))
        amount = int(data, 16) if data.startswith("0x") else int(data, 16)
    except (ValueError, TypeError):
        return None
    return TokenTransfer(
        token=str(log.get("address", "")),
        sender=sender,
        receiver=receiver,
        amount=amount,
        log_index=_hex_int(log.get("logIndex")) if log.get("logIndex") is not None else None,
    )


def parse_trace(payload: dict[str, Any]) -> tuple[TraceFrame, list[TokenTransfer]]:
    raw = payload.get("result", payload.get("trace", payload))
    if isinstance(raw, dict) and "calls" in raw:
        root = _walk_frames(raw)
    elif isinstance(raw, list):
        root = _walk_frames({"type": "ROOT", "calls": raw})
    else:
        root = _walk_frames(raw if isinstance(raw, dict) else {})
    logs = payload.get("logs", [])
    transfers = [item for item in (_transfer_from_log(log) for log in logs) if item]
    return root, transfers


def summarize_trace(payload: dict[str, Any]) -> dict[str, Any]:
    root, transfers = parse_trace(payload)
    frames = list(iter_frames(root))
    net_token_flows: dict[str, dict[str, int]] = {}
    for transfer in transfers:
        flows = net_token_flows.setdefault(transfer.token, {})
        flows[transfer.sender] = flows.get(transfer.sender, 0) - transfer.amount
        flows[transfer.receiver] = flows.get(transfer.receiver, 0) + transfer.amount
    external = [f for f in frames if f.call_type in {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}]
    delegate = [f for f in frames if f.call_type == "DELEGATECALL"]
    value_calls = [f for f in frames if f.value]
    selectors: dict[str, int] = {}
    for frame in frames:
        selector = frame.input_data[:10] if frame.input_data.startswith("0x") else frame.input_data[:8]
        if len(selector) >= 8:
            selectors[selector] = selectors.get(selector, 0) + 1
    return {
        "root_sender": root.sender,
        "root_target": root.target,
        "frame_count": len(frames),
        "max_depth": max((f.depth for f in frames), default=0),
        "external_interactions": len(external),
        "delegatecalls": len(delegate),
        "native_value_transfers": sum(f.value for f in value_calls),
        "unique_callers": sorted({f.sender for f in frames if f.sender}),
        "unique_targets": sorted({f.target for f in frames if f.target}),
        "selectors": selectors,
        "erc20_transfers": [
            {"token": t.token, "from": t.sender, "to": t.receiver, "amount": t.amount, "log_index": t.log_index}
            for t in transfers
        ],
        "net_token_flows": net_token_flows,
    }


def forensic_flags(payload: dict[str, Any]) -> list[dict[str, Any]]:
    root, transfers = parse_trace(payload)
    frames = list(iter_frames(root))
    flags: list[dict[str, Any]] = []
    for frame in frames:
        if frame.call_type == "DELEGATECALL":
            flags.append({"type": "delegatecall", "path": frame.path, "target": frame.target, "depth": frame.depth})
        if frame.value and frame.depth >= 1:
            flags.append({"type": "nested-value-transfer", "path": frame.path, "target": frame.target, "value": frame.value})
    token_out = {}
    for transfer in transfers:
        token_out.setdefault(transfer.sender, 0)
        token_out[transfer.sender] += transfer.amount
    for sender, amount in sorted(token_out.items(), key=lambda item: -item[1]):
        flags.append({"type": "token-outflow", "sender": sender, "amount": amount})
    return flags


def load_trace(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def analyze_trace(path: str) -> dict[str, Any]:
    payload = load_trace(path)
    summary = summarize_trace(payload)
    return {"trace": summary, "flags": forensic_flags(payload)}
