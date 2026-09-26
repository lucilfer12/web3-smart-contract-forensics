# SCF 1.0 completion contract

SCF 1.0 is the repository-level implementation target. It is not a claim that every external security tool or chain is installed on every machine.

## Implemented in-repository

- Evidence-preserving legacy corpus and generated audit layer.
- Solidity AST parsing, source IR, call/control-flow modeling and taint analysis.
- Static detectors with CWE/SWC metadata, source evidence and SARIF.
- EVM bytecode inspection and proxy heuristics.
- SQLite knowledge graph with findings, entities and relationships.
- Compiler, Slither, Foundry, HEVM, Echidna and Forge adapter contracts.
- Transaction, trace, state and historical block evidence collection through read-only JSON-RPC.
- Deterministic forensic cases and explicit FLOW_ONLY economics.
- Invariant checks, cross-agent conflict detection and promotion gates.
- Named local agent team that orchestrates static, bytecode, symbolic, fuzzing and validation stages.
- Controlled historical-fork runner using Anvil + Forge when those binaries are present.
- FastAPI endpoints for analysis, forensics, knowledge, capabilities and agent execution.
- CLI coverage for every implemented workflow.
- Positive/negative fixtures, regression tests and CI SARIF upload.

## Evidence states

`UNVERIFIED -> SOURCE_VERIFIED -> ANALYST_VERIFIED -> REPRODUCED -> INDEPENDENTLY_REPRODUCED`

A missing executable, archive RPC, analyst review or independent reproduction is reported as unavailable/pending; it is never converted into proof.

## External prerequisites

The repository can run its deterministic core with Python dependencies alone. Deep symbolic execution, fuzzing and historical fork execution require their respective operator-installed tools and, for historical state, an RPC provider that retains the requested block state.
## Agent orchestration

`scf agents` executes the local team and feeds observations into the existing validation gate. Agents do not invent evidence and unavailable external tools remain unavailable.

The API exposes `GET /capabilities` and `POST /agents/run` so an IDE or automation layer can discover capabilities before dispatching work.

## Historical fork

`scf fork <project> <rpc> --block <number>` starts a local Anvil fork and runs the selected Foundry tests. A passing run yields `REPRODUCED` evidence; failures, missing binaries and unavailable RPC state do not.

## Security model

All RPC functionality is read-only. The fork runner is local and test-driven. The repository does not contain private keys, live-target exploit transactions, secret material or automatic transaction submission.

## 1.0 acceptance checks

Run:

```text
python -m pytest -q
python tools/benchmark_engine.py
python tools/validate_dataset.py
python tools/validate_audit_reports.py
python tools/scf.py adapters
python tools/scf.py agents fixtures/contracts/vulnerable
```

CI additionally validates generated audit state and uploads SARIF findings.
