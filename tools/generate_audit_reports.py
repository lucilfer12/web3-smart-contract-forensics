"""Generate evidence-first audit reports without mutating legacy cases."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from scf.audit import build_report, to_markdown, normalize_source

SOURCE = ROOT / "datasets" / "reports.json"
OUT_DIR = ROOT / "audit-reports"
OUT_JSON = ROOT / "datasets" / "audit_reports.json"

def main() -> int:
    records = json.loads(SOURCE.read_text(encoding="utf-8-sig"))
    evidence_path = ROOT / "datasets" / "public_evidence.json"
    evidence = {x["case_id"]: x for x in json.loads(evidence_path.read_text(encoding="utf-8"))} if evidence_path.exists() else {}
    reports = []
    OUT_DIR.mkdir(exist_ok=True)
    for record in records:
        report = build_report(record)
        match = evidence.get(record["case_id"], {})
        report["evidence"]["public_excerpts"] = [
            {**item, "source": normalize_source(item.get("source", "")),
             "excerpt": item.get("excerpt", "")[:6000]}
            for item in match.get("source_matches", [])[:3]
        ]
        if report["evidence"]["public_excerpts"]:
            report["verification"]["checks"].append("public-source-excerpt-found")
            excerpt_text = " ".join(x.get("excerpt", "") for x in report["evidence"]["public_excerpts"]).lower()
            if "fixed" in excerpt_text or "remediated" in excerpt_text:
                report["evidence"]["fix_verification"] = "The public-source excerpt contains a fix/remediation marker; verify the exact remediation and deployed state before promotion."
        reports.append(report)
        (OUT_DIR / f"{record['case_id']}.md").write_text(
            to_markdown(report), encoding="utf-8"
        )
    OUT_JSON.write_text(json.dumps(reports, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    print(f"generated={len(reports)}")
    print(f"markdown_dir={OUT_DIR}")
    print(f"json={OUT_JSON}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
