"""Build a transparent manual-review queue; priority is not a security verdict."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
reports = json.loads((ROOT / "datasets" / "audit_reports.json").read_text(encoding="utf-8"))
reach = {x["url"]: x for x in json.loads((ROOT / "datasets" / "source_verification.json").read_text(encoding="utf-8"))["results"]}
queue = []
for r in reports:
    sources = r["evidence"]["sources"]
    reachable = sum(1 for u in sources if reach.get(u, {}).get("reachable"))
    score = reachable * 2 + len(r["classification"]["taxonomy"])
    queue.append({"case_id": r["case_id"], "review_priority": score,
                  "source_count": len(sources), "reachable_sources": reachable,
                  "taxonomy": r["classification"]["taxonomy"],
                  "status": r["classification"]["status"],
                  "reason": "Prioritize human primary-source review; this score is workflow metadata, not severity or confidence."})
queue.sort(key=lambda x: (-x["review_priority"], x["case_id"]))
(ROOT / "datasets" / "review_queue.json").write_text(json.dumps(queue, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"queue={len(queue)}")
