import json, pathlib, re
ROOT=pathlib.Path(__file__).resolve().parents[1]
records=json.loads((ROOT/"datasets/reports.json").read_text(encoding="utf-8-sig"))
cases=ROOT/"cases"
for p in cases.glob("*.md"):
    p.unlink()
for r in records:
    case=r["case_id"]
    sources="\n".join(f"- {u}" for u in r.get("sources",[]))
    reward="Not publicly documented in this source" if r.get("reward_amount") is None else f"{r['reward_amount']} {r.get('reward_currency') or ''}".strip()
    cvss="Unknown" if r.get("cvss") is None else str(r["cvss"])
    md=f"""# {case} — {r.get('title','Untitled')}

## Classification
- Severity: Critical
- Record type: {r.get('record_type')}
- Status: {r.get('status')}
- Evidence level: {r.get('evidence_level')}

## Project / Source
- Project: {r.get('project') or 'Unknown'}
- Source: {r.get('source_name') or 'Unknown'}

## Technical normalization
- Vulnerability class: {r.get('vulnerability_class') or 'Pending normalization'}
- Impact: {r.get('impact') or 'Pending primary-source review'}
- CVSS: {cvss}

## Reward
- Case-specific reward: {reward}

## Provenance
{sources}

## Research note
This record is a structured public-security finding. A final verified case should preserve the original report's wording only as a concise summary, record remediation evidence where available, and distinguish documented facts from analyst interpretation.

## Safety
No secrets or operational live-target exploitation material are included.
"""
    (cases/f"{case}.md").write_text(md,encoding="utf-8")
print("case files:",len(records))