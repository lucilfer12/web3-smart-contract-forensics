"""Strict validation for the evidence-first audit layer."""
from __future__ import annotations
import json
import re
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets" / "audit_reports.json"
CASES = ROOT / "audit-reports"
ID_RE = re.compile(r"^SCF-\d{4}$")

def main() -> int:
    reports = json.loads(DATA.read_text(encoding="utf-8"))
    errors = []
    ids = set()
    for report in reports:
        cid = report.get("case_id")
        if not isinstance(cid, str) or not ID_RE.fullmatch(cid):
            errors.append(f"{cid}: invalid case id")
        if cid in ids:
            errors.append(f"{cid}: duplicate")
        ids.add(cid)
        for key in ("summary","classification","analysis","evidence","verification"):
            if key not in report:
                errors.append(f"{cid}: missing {key}")
        evidence = report.get("evidence", {})
        sources = set(evidence.get("sources", []))
        for url in sources:
            parsed = urlparse(url)
            if parsed.scheme not in {"http","https"} or not parsed.netloc:
                errors.append(f"{cid}: invalid source URL {url}")
        for item in evidence.get("public_excerpts", []):
            if item.get("source") not in sources:
                errors.append(f"{cid}: excerpt source not in provenance")
            if len(item.get("excerpt", "")) > 10000:
                errors.append(f"{cid}: excerpt too large")
        confidence = report.get("verification", {}).get("confidence")
        if not isinstance(confidence, (int,float)) or not 0 <= confidence <= 1:
            errors.append(f"{cid}: invalid confidence")
        if not (CASES / f"{cid}.md").exists():
            errors.append(f"{cid}: missing markdown report")
    source_count = len(json.loads((ROOT/"datasets/reports.json").read_text(encoding="utf-8-sig")))
    if len(reports) != source_count:
        errors.append(f"count mismatch: source={source_count}, audits={len(reports)}")
    print(f"audit_reports={len(reports)}")
    print(f"legacy_case_files={len(list((ROOT/'cases').glob('SCF-*.md')))}")
    if errors:
        print("\n".join(errors[:200]))
        return 1
    print("AUDIT REPORTS VALID")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
