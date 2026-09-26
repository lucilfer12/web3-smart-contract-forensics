# Methodology

## Inclusion
Keep a record in the Critical collection only when the source itself marks it Critical or provides direct evidence supporting that severity.

## Evidence tiers
primary = original public report or bug-fix review
corroborated = primary evidence plus independent public corroboration
secondary = reputable public description with incomplete primary evidence
candidate = lead requiring review

## Rewards
reward_amount means only a case-specific public reward. Program maximums are never substituted.

## Smart-contract focus
Exclude ordinary Web2, frontend-only, and infrastructure-only issues unless the root cause is smart-contract or blockchain code.

## Reproduction
Use synthetic assets, local forks, or isolated test deployments.

## Validation
Stable case ID, public source URL, explicit evidence level, normalized class, duplicate check, and provenance note.
## Audit report promotion

Generated audit reports are evidence containers, not proof. A case remains `candidate` until a reviewer confirms the primary source. `source_verified` requires direct source evidence; `analyst_verified` requires a technical review; `reproduced` requires controlled reproduction; `corroborated` requires independent public corroboration.

### Required report fields

Summary -> Root Cause -> Attack Path -> Preconditions -> Impact -> PoC status -> Recommendation -> Fix Verification -> Evidence -> Limitations.

### Evidence discipline

- Never infer exploitability from severity alone.
- Never invent a PoC, affected address, function, asset amount, or remediation.
- Preserve source URLs and record extraction provenance.
- Reachable URLs are not proof of correctness.
- Reproduction must use synthetic assets, local forks, or isolated deployments.
- Fix verification must cite a commit, test, audit update, or other public evidence when available.
