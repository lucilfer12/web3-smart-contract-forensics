from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class RpcClient:
    url: str
    timeout: int = 30

    def call(self, method: str, params: list[Any]) -> Any:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        request = urllib.request.Request(self.url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            value = json.loads(response.read().decode("utf-8"))
        if value.get("error"):
            raise RuntimeError(f"RPC {method} failed: {value['error']}")
        return value.get("result")

    def transaction(self, tx_hash: str) -> dict[str, Any] | None:
        return self.call("eth_getTransactionByHash", [tx_hash])

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def block(self, block_number: str) -> dict[str, Any] | None:
        return self.call("eth_getBlockByNumber", [block_number, True])

    def code(self, address: str, block: str = "latest") -> str:
        return str(self.call("eth_getCode", [address, block]) or "0x")

    def storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return str(self.call("eth_getStorageAt", [address, slot, block]) or "0x")

    def trace(self, tx_hash: str) -> dict[str, Any]:
        try:
            result = self.call("debug_traceTransaction", [tx_hash, {"tracer": "callTracer", "timeout": "20s"}])
            return {"result": result, "provider_mode": "debug_callTracer"}
        except Exception as debug_error:
            try:
                result = self.call("trace_transaction", [tx_hash])
                return {"result": result, "provider_mode": "parity_trace", "debug_error": str(debug_error)}
            except Exception as parity_error:
                raise RuntimeError(f"No supported trace method: debug={debug_error}; parity={parity_error}") from parity_error


def collect_transaction(client: RpcClient, tx_hash: str, include_trace: bool = True) -> dict[str, Any]:
    tx = client.transaction(tx_hash)
    receipt = client.receipt(tx_hash)
    if not tx:
        raise ValueError(f"transaction not found: {tx_hash}")
    if not receipt:
        raise ValueError(f"receipt not found: {tx_hash}")
    result: dict[str, Any] = {"transaction": tx, "receipt": receipt}
    block_number = tx.get("blockNumber")
    if block_number:
        result["block"] = client.block(block_number)
    if include_trace:
        result["trace"] = client.trace(tx_hash)
    return result


def normalize_transaction(payload: dict[str, Any]) -> dict[str, Any]:
    tx = payload.get("transaction", {})
    receipt = payload.get("receipt", {})
    block = payload.get("block", {}) or {}
    return {
        "hash": tx.get("hash"),
        "block_number": tx.get("blockNumber"),
        "block_hash": tx.get("blockHash"),
        "timestamp": block.get("timestamp"),
        "from": tx.get("from"),
        "to": tx.get("to"),
        "value": tx.get("value", "0x0"),
        "input": tx.get("input", "0x"),
        "nonce": tx.get("nonce"),
        "status": receipt.get("status"),
        "gas_used": receipt.get("gasUsed"),
        "effective_gas_price": receipt.get("effectiveGasPrice"),
        "contract_address": receipt.get("contractAddress"),
        "logs": receipt.get("logs", []),
        "trace_provider": (payload.get("trace") or {}).get("provider_mode"),
    }
