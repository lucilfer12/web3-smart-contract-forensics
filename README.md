# Web3 Smart Contract Forensics

Evidence-first Web3 security research evolving into a verification-driven forensic platform.

## What exists today

- 226 preserved Critical security records in the legacy corpus.
- 226 original case files retained under `cases/`.
- A new additive audit layer under `audit-reports/`.
- Structured audit records in `datasets/audit_reports.json`.
- Evidence/provenance-aware validation and source reachability tooling.
- A deterministic taxonomy classifier that never promotes a finding from severity alone.

## Audit report model

Every generated report follows:

1. Summary
2. Root Cause
3. Attack Path
4. Preconditions
5. Impact
6. Proof of Concept status
7. Recommendation
8. Fix Verification
9. Evidence
10. Verification and limitations

Missing evidence is represented as unknown/pending rather than invented.
## Verification lifecycle

`candidate -> source_verified -> analyst_verified -> reproduced -> corroborated`

Confidence measures evidence quality, not severity. The LLM/AI layer is intended to reason over evidence, never to manufacture it.

## Analysis engine

The repository now ships a runnable defensive analysis engine under `src/scf_engine/`.

Current engine capabilities:

- Solidity parsing with tree-sitter and a canonical source IR.
- Function/state/call modeling plus a control-flow node graph.
- Cross-contract knowledge graph edges for inheritance, calls, reads and writes.
- Built-in detectors for reentrancy, authorization, tx.origin, unchecked calls, delegatecall, destruction, randomness, token-transfer handling, oracle-sensitive paths, signature replay, initializer safety and loop-based DoS.
- Evidence-bearing findings with source locations, snippets, rule IDs, CWE/SWC mappings and confidence.
- JSON and SARIF output for automation and code-scanning pipelines.
- Local transaction-trace forensics with nested call reconstruction, delegatecall/value-flow flags and ERC-20 Transfer extraction.
- Deterministic forensic case objects with address-level token/native flows and explicit FLOW_ONLY economic semantics.
- Optional evidence-backed economic valuation of observed flows; no automatic profit claims.
- Deterministic invariants and cross-agent evidence validation with conflict-aware promotion gates.
- Historical EVM state snapshots for code, balance and selected storage slots at a block tag.
- FastAPI service for source analysis, knowledge graph queries and transaction/state forensics without exposing arbitrary server filesystem paths.
- Positive/negative benchmark fixtures and regression tests.

The engine is intentionally evidence-first: a detector reports a reviewable hypothesis with provenance rather than pretending a static heuristic is proof of exploitability.

## CLI

```bash
python -m pip install -r requirements.txt
python tools/scf.py analyze path/to/contracts --json result.json --sarif result.sarif
python tools/scf.py rules
python tools/scf.py trace path/to/trace.json
python tools/scf.py bytecode 0x6001600055 --json
python tools/scf.py index path/to/contracts --db .scf/scf.db
python tools/scf.py compile path/to/Contract.sol
python tools/scf.py slither path/to/contracts
python tools/scf.py reproduce path/to/foundry-project
python tools/scf.py tx https://rpc.example <tx-hash> --json tx.json
python tools/scf.py forensics https://rpc.example <tx-hash> --json case.json
python tools/scf.py forensics https://rpc.example <tx-hash> --state-block 0x123456
python tools/scf.py forensics https://rpc.example <tx-hash> --valuation-json valuations.json
python tools/scf.py state https://rpc.example <address> --block 0x123456 --slot 0x0
python tools/scf.py monitor https://rpc.example --address 0x... --from-block 123 --to-block 130 --json alerts.json
python tools/scf.py validate-case case.json --observations-json observations.json
python tools/scf.py serve --host 127.0.0.1 --port 8000
```

For CI, use `--fail-on High` or `--fail-on Critical` to gate merges on findings.

## Platform architecture

The architecture is organized around corpus, knowledge, analysis, forensics, verification, intelligence and product planes. See `docs/ARCHITECTURE.md` and `docs/ENGINE.md`.

The next layers are deliberately designed as replaceable adapters: optional Slither integration, compiler/fork execution, richer bytecode/ABI ingestion, persistent knowledge-graph storage, historical transaction providers, economic simulation, and IDE components can sit on top of the canonical IR without changing the legacy corpus.

## Compatibility and preservation

The original `datasets/reports.json`, `datasets/reports.csv`, `cases/`, existing methodology and validators are preserved. New tooling is additive and does not delete or silently rewrite legacy research.

## Validation

~~~bash
python tools/validate_dataset.py
python tools/generate_audit_reports.py
python tools/validate_audit_reports.py
~~~

## Safety

Public evidence only. No secrets, private keys, confidential reports, embargoed vulnerabilities or live-target exploit instructions.
