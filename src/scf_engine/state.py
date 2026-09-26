from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rpc import RpcClient


@dataclass
class StateSnapshot:
    address: str
    block_tag: str
    code: str
    balance: str
    storage: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "block_tag": self.block_tag,
            "code": self.code,
            "balance": self.balance,
            "storage": dict(self.storage),
            "code_present": self.code != "0x",
            "bytecode_size": max(0, (len(self.code) - 2) // 2) if self.code.startswith("0x") else len(self.code) // 2,
        }


def _balance(client: RpcClient, address: str, block: str) -> str:
    return str(client.call("eth_getBalance", [address, block]) or "0x0")


def snapshot_address(
    client: RpcClient,
    address: str,
    block: str = "latest",
    slots: list[str] | None = None,
) -> StateSnapshot:
    code = client.code(address, block)
    balance = _balance(client, address, block)
    storage = {slot: client.storage_at(address, slot, block) for slot in (slots or [])}
    return StateSnapshot(address, block, code, balance, storage)


def collect_state_snapshot(
    client: RpcClient,
    addresses: list[str],
    block: str = "latest",
    slots_by_address: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    slots_by_address = slots_by_address or {}
    snapshots = [
        snapshot_address(client, address, block, slots_by_address.get(address, []))
        for address in sorted(set(addresses))
    ]
    return {
        "schema_version": "0.5.0",
        "block_tag": block,
        "addresses": [item.as_dict() for item in snapshots],
        "evidence": {
            "kind": "historical-state",
            "provider": "EVM JSON-RPC",
            "methods": ["eth_getCode", "eth_getBalance", "eth_getStorageAt"],
            "mutating": False,
        },
        "limitations": [
            "Only requested storage slots are captured; a complete state dump requires a state-diff provider.",
            "Storage slot values have no semantic meaning without ABI/layout mapping.",
            "Historical availability depends on the RPC provider's archive/state retention.",
        ],
    }


def addresses_from_forensic_case(case: dict[str, Any]) -> list[str]:
    execution = case.get("execution", {})
    summary = execution.get("summary") or {}
    addresses = set(summary.get("unique_callers", [])) | set(summary.get("unique_targets", []))
    tx = case.get("transaction", {})
    for key in ("from", "to"):
        if tx.get(key):
            addresses.add(tx[key])
    return sorted(a for a in addresses if a)
