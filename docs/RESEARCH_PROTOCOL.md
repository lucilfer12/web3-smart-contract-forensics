# Evidence-First Research Protocol

This protocol is the quality gate for turning public security material into durable SCF knowledge.

## 1. Discovery

Capture the original URL, publication context, source organization, title and retrieval timestamp. Do not paraphrase beyond what is supported by the source.

## 2. Normalization

Map the record into the SCF taxonomy. Keep unknown values null. Never infer severity, exploitability, asset loss or bounty value from unrelated fields.

## 3. Evidence extraction

Store bounded excerpts that allow a reviewer to locate the source claim. Excerpts are discovery aids, not replacements for the original report.

## 4. Technical review

A reviewer establishes the root cause, affected component, preconditions, attack path and impact from primary evidence. If source code is available, link the relevant function/file/commit.

## 5. Reproduction

Use only a local fork, synthetic assets or an isolated deployment. Record the environment, state assumptions, test/invariant and observed result.
## 6. Fix verification

Prefer explicit public evidence: audit update, remediation commit, regression test, release note or independent review. A source saying “fixed” is evidence of a claimed remediation, not by itself proof that the current deployed code is safe.

## 7. Corroboration

Independent sources may strengthen confidence when they establish the same technical fact. Duplicate copies of the same report do not count as independent corroboration.

## 8. Regression

Every reproduced finding should become a deterministic regression test. Every detector should have positive and negative fixtures. Historical cases must remain immutable inputs to the benchmark.

## 9. Promotion states

- `candidate`: imported lead; insufficient direct evidence.
- `source_verified`: primary public evidence located and matched.
- `analyst_verified`: technical interpretation reviewed.
- `reproduced`: behavior reproduced in a controlled environment.
- `corroborated`: independently supported by public evidence.

Promotion is monotonic and auditable. Never downgrade evidence quality merely to increase coverage.

## 10. Audit report standard

Every mature case should contain Summary, Root Cause, Attack Path, Preconditions, Impact, PoC status, Recommendation, Fix Verification, Evidence, Confidence, Limitations and Provenance.
