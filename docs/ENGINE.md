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

## Security model

The HTTP service accepts source text, not arbitrary server filesystem paths. The default CLI server binds to loopback. Reproduction is designed around controlled projects and synthetic or isolated environments.

## Known limitations

Detectors combine AST-derived facts with conservative source heuristics. They do not replace compiler semantic analysis, symbolic execution, invariant testing, bytecode verification, protocol-specific economic modeling, or human review.

## Extension contract

A detector implements Detector.run(unit, contract, function) and returns evidence-bearing Finding objects. New detectors should ship with positive and negative fixtures, stable rule IDs, explicit mappings, and regression tests.
