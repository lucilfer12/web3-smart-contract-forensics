# SCF Engine

SCF Engine is the executable analysis layer of Web3 Smart Contract Forensics. It turns source and trace evidence into reviewable findings without treating heuristics as proof.

## Pipeline

~~~text
Solidity files
   |
   +-- tree-sitter parser
   |     +-- contracts / inheritance
   |     +-- functions / modifiers
   |     +-- state variables
   |     +-- calls / control-flow nodes
   |
   +-- canonical IR
   |     +-- source locations
   |     +-- reads / writes
   |     +-- call sites
   |
   +-- detectors
   |     +-- control-flow/security
   |     +-- access control
   |     +-- upgradeability
   |     +-- randomness / oracle
   |     +-- DoS / token handling
   |
   +-- AST taint/data-flow
   |
   +-- knowledge graph
   |
   +-- reports
         +-- JSON
         +-- SARIF
         +-- Graphviz DOT
         +-- Mermaid
~~~

## Forensic pipeline

Local EVM trace JSON is normalized into nested call frames. The forensic layer extracts depth, call type, caller/target, native value, selectors, delegatecall use, ERC-20 Transfer events and net token flows.

The trace analyzer does not claim attacker identity or profit merely from one transfer event. Those conclusions require transaction context and independent corroboration.

## Verification lifecycle

UNVERIFIED -> SOURCE_VERIFIED -> ANALYST_VERIFIED -> REPRODUCED -> INDEPENDENTLY_REPRODUCED

A promotion is blocked unless the required evidence classes are present. This prevents a static detector from silently becoming a reproduced exploit claim.

## External adapters

- compiler.py uses Solidity standard-json when solc is installed.
- external.py can invoke Slither when the executable is installed; it is optional.
- foundry.py runs local Foundry tests and can record controlled reproduction evidence.

## Validation and multi-agent evidence

The engine now has a deterministic validation layer before a finding is promoted:

1. Built-in invariants evaluate machine-checkable safety properties.
2. Independent agent observations can be submitted with explicit evidence references.
3. Cross-validation marks each finding as CONFIRMED, REJECTED, or CONFLICT.
4. Promotion is blocked when deterministic invariants fail or agent evidence conflicts.
5. Verification state remains separate from confidence; neither static detection nor consensus alone proves exploitability.

CLI:

    python tools/scf.py validate-case case.json
    python tools/scf.py validate-case case.json --observations-json observations.json

This is an orchestration layer, not a claim that the repository already contains every future symbolic/fuzzing agent.

## Symbolic execution and fuzzing adapters

Optional adapters now expose existing operator-controlled analysis projects to HEVM symbolic tests, Echidna property fuzzing, and Foundry fuzz tests.

The adapters never synthesize or submit exploit transactions. They execute an existing local test target and preserve tool availability, return status, stdout/stderr and command evidence. Missing tools are reported as UNAVAILABLE, not treated as a clean security result.

CLI:

    python tools/scf.py adapters
    python tools/scf.py symbolic path/to/project
    python tools/scf.py fuzz path/to/project --tool echidna
    python tools/scf.py fuzz path/to/foundry --tool forge --test invariantName

## Security model

The HTTP service accepts source text, not arbitrary server filesystem paths. The default CLI server binds to loopback. Reproduction is designed around controlled projects and synthetic or isolated environments.

## Known limitations

Detectors combine AST-derived facts with conservative source heuristics. They do not replace compiler semantic analysis, symbolic execution, invariant testing, bytecode verification, protocol-specific economic modeling, or human review.

## Extension contract

A detector implements Detector.run(unit, contract, function) and returns evidence-bearing Finding objects. New detectors should ship with positive and negative fixtures, stable rule IDs, explicit mappings, and regression tests.
