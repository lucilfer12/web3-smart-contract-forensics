# SCF Transaction Forensics

The transaction forensics layer converts an EVM transaction, receipt, execution trace and optional historical state into a deterministic, reviewable case object.

## Evidence chain

transaction -> receipt + block -> execution trace -> optional historical state -> flow analysis.

The trace stage extracts a call tree, selectors, native value flows, ERC-20 Transfer events and forensic flags. The state stage can capture code, native balance and explicitly requested storage slots at an historical block tag.

## Economic semantics

The engine deliberately reports FLOW_ONLY rather than calling a flow "profit". Raw token units do not provide a common valuation, and a transfer does not prove attacker identity or realized gain. A future economic adapter can add prices, pool reserves, slippage, gas cost and balance-delta evidence.

## Historical state

state.py uses read-only JSON-RPC methods and accepts an explicit block tag. This supports archive-node state reconstruction without writing to a live chain. Storage slots are captured only when requested; semantic decoding requires ABI/storage-layout evidence.

## Reproduction

Foundry integration has explicit outcomes:
- REPRODUCED: controlled test completed successfully and evidence can be recorded.
- NOT_REPRODUCED: the tool is unavailable or the controlled test failed.
- ERROR: reserved for adapter-level failures.

A successful static finding never becomes a reproduction claim automatically.

## CLI

    python tools/scf.py forensics https://rpc.example <tx-hash> --json case.json
    python tools/scf.py forensics https://rpc.example <tx-hash> --state-block 0x123456
    python tools/scf.py state https://rpc.example <address> --block 0x123456 --slot 0x0
    python tools/scf.py reproduce path/to/foundry-project

## API

The local FastAPI service exposes POST /forensics/transaction and POST /forensics/state. The default server binds to 127.0.0.1. RPC URLs are operator-supplied and should only be pointed at trusted/read-only endpoints.

## Boundaries

This component is forensic and defensive. It does not submit transactions, mutate remote state, generate private keys, or claim exploit success from heuristics alone.

## Read-only monitoring

monitor.py provides deterministic block scanning for watched addresses. It emits transaction-touch events from eth_getBlockByNumber without submitting transactions or mutating state. This is a foundation for future upgrade, privileged-role, oracle and liquidity anomaly detectors; those higher-level detectors should attach concrete event/state evidence before creating an alert.
