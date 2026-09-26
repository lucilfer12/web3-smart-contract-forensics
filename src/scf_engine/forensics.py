from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .trace import TraceFrame, iter_frames, parse_trace, summarize_trace


def _int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    text = str(value)
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0


def _selector(data: str | None) -> str | None:
    if not data:
        return None
    value = str(data)
    if value.startswith("0x"):
        value = value[2:]
    return "0x" + value[:8] if len(value) >= 8 else None


@dataclass
class FlowAccount:
    address: str
    incoming: int = 0
    outgoing: int = 0

    @property
    def net(self) -> int:
        return self.incoming - self.outgoing


def _flow_accounts(summary: dict[str, Any]) -> list[dict[str, Any]]:
    accounts: dict[str, FlowAccount] = {}
    for transfer in summary.get("erc20_transfers", []):
        sender = str(transfer.get("from", ""))
        receiver = str(transfer.get("to", ""))
        amount = int(transfer.get("amount", 0))
        if sender:
            accounts.setdefault(sender, FlowAccount(sender)).outgoing += amount
        if receiver:
            accounts.setdefault(receiver, FlowAccount(receiver)).incoming += amount
    return [
        {"address": a.address, "incoming": a.incoming, "outgoing": a.outgoing, "net": a.net}
        for a in sorted(accounts.values(), key=lambda x: (-abs(x.net), x.address))
    ]
def _native_flows(root: TraceFrame) -> list[dict[str, Any]]:
    flows: dict[str, FlowAccount] = {}
    for frame in iter_frames(root):
        if frame.value <= 0:
            continue
        sender = frame.sender
        receiver = frame.target
        if sender:
            flows.setdefault(sender, FlowAccount(sender)).outgoing += frame.value
        if receiver:
            flows.setdefault(receiver, FlowAccount(receiver)).incoming += frame.value
    return [
        {"address": a.address, "incoming": a.incoming, "outgoing": a.outgoing, "net": a.net}
        for a in sorted(flows.values(), key=lambda x: (-abs(x.net), x.address))
    ]


def _evidence(summary: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = [
        {"kind": "transaction-trace", "reference": "trace", "note": "Call tree supplied by the RPC trace provider."},
        {"kind": "receipt-logs", "reference": "receipt.logs", "note": "ERC-20 Transfer events are decoded when their topic matches the standard signature."},
    ]
    if summary.get("trace_provider"):
        evidence.append({
            "kind": "trace-provider",
            "reference": str(summary["trace_provider"]),
            "note": "Provider mode used to obtain the execution trace.",
        })
    return evidence


def build_forensic_case(payload: dict[str, Any]) -> dict[str, Any]:
    transaction = payload.get("transaction", {})
    receipt = payload.get("receipt", {})
    block = payload.get("block", {}) or {}
    trace_payload = payload.get("trace")
    if not trace_payload:
        raise ValueError("transaction payload has no execution trace")
    trace_payload = dict(trace_payload)
    trace_payload.setdefault("logs", receipt.get("logs", []))
    root, _ = parse_trace(trace_payload)
    summary = summarize_trace(trace_payload)
    summary["trace_provider"] = trace_payload.get("provider_mode")
    entry_selector = _selector(transaction.get("input"))
    block_number = transaction.get("blockNumber")
    timestamp = block.get("timestamp")
    return {
        "schema_version": "0.5.0",
        "transaction": {
            "hash": transaction.get("hash"),
            "block_number": block_number,
            "block_hash": transaction.get("blockHash"),
            "timestamp": timestamp,
            "from": transaction.get("from"),
            "to": transaction.get("to"),
            "value": transaction.get("value", "0x0"),
            "nonce": transaction.get("nonce"),
            "entry_selector": entry_selector,
            "status": receipt.get("status"),
            "gas_used": receipt.get("gasUsed"),
            "effective_gas_price": receipt.get("effectiveGasPrice"),
            "contract_address": receipt.get("contractAddress"),
        },
        "execution": {
            "root": {"from": root.sender, "to": root.target, "value": root.value, "selector": _selector(root.input_data)},
            "summary": summary,
            "erc20_flows": _flow_accounts(summary),
            "native_value_flows": _native_flows(root),
        },
        "economic": {
            "status": "FLOW_ONLY",
            "gross_token_outflow": sum(int(x["outgoing"]) for x in _flow_accounts(summary)),
            "gross_token_inflow": sum(int(x["incoming"]) for x in _flow_accounts(summary)),
            "native_value_moved": summary.get("native_value_transfers", 0),
            "profit_claim": None,
            "limitations": [
                "Token amounts are raw units and are not valued in fiat or a base asset.",
                "Flow deltas are not proof of attacker identity or realized profit.",
                "Gas and price impact require additional market and state evidence.",
            ],
        },
        "flags": summary.get("forensic_flags", []),
        "evidence": _evidence(summary, payload),
    }


def build_forensic_case_without_trace(payload: dict[str, Any]) -> dict[str, Any]:
    transaction = payload.get("transaction", {})
    receipt = payload.get("receipt", {})
    block = payload.get("block", {}) or {}
    return {
        "schema_version": "0.5.0",
        "transaction": {
            "hash": transaction.get("hash"),
            "block_number": transaction.get("blockNumber"),
            "timestamp": block.get("timestamp"),
            "from": transaction.get("from"),
            "to": transaction.get("to"),
            "value": transaction.get("value", "0x0"),
            "entry_selector": _selector(transaction.get("input")),
            "status": receipt.get("status"),
        },
        "execution": {"summary": None, "erc20_flows": [], "native_value_flows": []},
        "economic": {
            "status": "TRACE_REQUIRED",
            "gross_token_outflow": 0,
            "gross_token_inflow": 0,
            "native_value_moved": 0,
            "profit_claim": None,
        },
        "flags": [],
        "evidence": [{"kind": "transaction-receipt", "reference": "receipt", "note": "No execution trace was requested."}],
    }
def enrich_with_code(payload: dict[str, Any], code_by_address: dict[str, str]) -> dict[str, Any]:
    """Attach code-presence evidence without interpreting bytecode as exploit proof."""
    result = dict(payload)
    execution = dict(result.get("execution", {}))
    addresses = set()
    summary = execution.get("summary") or {}
    addresses.update(summary.get("unique_targets", []))
    addresses.update(summary.get("unique_callers", []))
    contracts = []
    for address in sorted(a for a in addresses if a):
        code = code_by_address.get(address, "0x")
        contracts.append({
            "address": address,
            "code_present": bool(code and code != "0x"),
            "bytecode_size": max(0, (len(code) - 2) // 2) if code.startswith("0x") else len(code) // 2,
        })
    result["contracts"] = contracts
    result.setdefault("evidence", []).append({
        "kind": "historical-code",
        "reference": "eth_getCode",
        "note": "Code presence was read at the requested block tag.",
    })
    return result
