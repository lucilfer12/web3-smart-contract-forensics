# SCF Platform Architecture

SCF is evolving from a research catalog into an evidence-first Web3 security platform.
The legacy corpus remains immutable input; new layers are additive.

## Core planes

1. **Corpus plane** — raw reports, normalized records, provenance and source reachability.
2. **Knowledge plane** — vulnerability taxonomy, entities, relationships and historical patterns.
3. **Analysis plane** — static analysis, dynamic execution, symbolic reasoning, fuzzing and economic checks.
4. **Forensics plane** — transaction traces, state diffs, fund flow, timelines and incident reconstruction.
5. **Verification plane** — evidence scoring, reproduction state, independent checks and regression tests.
6. **Intelligence plane** — retrieval, agent orchestration and human-readable security reasoning.
7. **Product plane** — CLI, API, IDE, reports, monitoring and integrations.

## Non-negotiable evidence rule

The language model is a reasoning layer, not a source of truth.
A finding may only advance its verification state when an explicit evidence transition is recorded.

~~~
candidate -> source_verified -> analyst_verified -> reproduced -> corroborated
~~~

A higher severity never increases confidence.

## Case lifecycle

~~~
public source
    -> ingestion
    -> normalization
    -> provenance
    -> audit report
    -> evidence extraction
    -> controlled reproduction
    -> regression test
    -> knowledge graph
    -> future detection
~~~
## Data contracts

Every finding should eventually be addressable by:

- case ID
- canonical vulnerability class
- affected project/protocol
- source URLs
- evidence items
- affected contract/function when known
- root cause
- attack path
- preconditions
- impact
- remediation
- fix verification
- reproduction state
- confidence
- provenance history

Unknown values remain unknown. Derived values must identify their derivation rule.

## Safety boundaries

Reproduction is limited to synthetic assets, local forks, isolated deployments and defensive analysis.
No credentials, private keys, embargoed material or live-target exploit instructions belong in the corpus.

## Compatibility

The original `datasets/reports.json`, `datasets/reports.csv`, `cases/`, and existing validators remain supported.
The audit layer writes to `audit-reports/` and `datasets/audit_reports.json` rather than replacing the legacy corpus.
