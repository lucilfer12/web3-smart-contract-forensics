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

## Platform direction

The long-term architecture is organized around corpus, knowledge, analysis, forensics, verification, intelligence and product planes. See `docs/ARCHITECTURE.md`.

Planned capabilities include static analysis, dynamic/fork analysis, transaction reconstruction, economic-security analysis, knowledge graphs, regression corpora, detector SDKs, CLI/API and a security IDE.

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
