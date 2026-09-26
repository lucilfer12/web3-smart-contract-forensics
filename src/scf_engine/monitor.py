from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rpc import RpcClient


@dataclass(frozen=True)
class MonitorEvent:
    kind: str
    block_number: str
    tx_hash: str | None
    address: str | None
    detail: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "block_number": self.block_number,
            "tx_hash": self.tx_hash,
            "address": self.address,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def _hex_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    try:
        text = str(value or "0")
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0


def latest_block(client: RpcClient) -> int:
    return _hex_int(client.call("eth_blockNumber", []))


def scan_block(client: RpcClient, block_number: int, watched: set[str]) -> list[MonitorEvent]:
    tag = hex(block_number)
    block = client.block(tag) or {}
    events: list[MonitorEvent] = []
    for tx in block.get("transactions", []):
        target = str(tx.get("to") or "").lower()
        sender = str(tx.get("from") or "").lower()
        if watched and target not in watched and sender not in watched:
            continue
        address = target if target in watched else sender
        events.append(MonitorEvent(
            kind="watched-transaction",
            block_number=tag,
            tx_hash=tx.get("hash"),
            address=address,
            detail="Transaction touched a watched address.",
            evidence={"method": "eth_getBlockByNumber", "block": tag, "to": tx.get("to"), "from": tx.get("from")},
        ))
    return events
def scan_blocks(
    client: RpcClient,
    start_block: int,
    end_block: int,
    watched: set[str] | None = None,
) -> list[MonitorEvent]:
    watched = {item.lower() for item in (watched or set())}
    if end_block < start_block:
        raise ValueError("end_block must be >= start_block")
    events: list[MonitorEvent] = []
    for number in range(start_block, end_block + 1):
        events.extend(scan_block(client, number, watched))
    return events


def privileged_change_event(
    block_number: str,
    tx_hash: str,
    address: str,
    detail: str,
    evidence: dict[str, Any],
) -> MonitorEvent:
    return MonitorEvent(
        kind="privileged-change",
        block_number=block_number,
        tx_hash=tx_hash,
        address=address,
        detail=detail,
        evidence=evidence,
    )


def monitoring_contract(
    client: RpcClient,
    address: str,
    block: str = "latest",
) -> dict[str, Any]:
    code = client.code(address, block)
    return {
        "address": address,
        "block": block,
        "code_present": code != "0x",
        "bytecode_size": max(0, (len(code) - 2) // 2) if code.startswith("0x") else len(code) // 2,
        "evidence": {"method": "eth_getCode", "block": block, "mutating": False},
    }
