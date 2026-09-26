"""Portable, deterministic VulnDB ingestion with case-ID preservation."""
import argparse, csv, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["case_id","title","severity","record_type","status","source_name","project","vulnerability_class","impact","cvss","reward_amount","reward_currency","disclosed","evidence_level","sources","notes"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=Path, help="Directory containing vulns-*.json files")
    ap.add_argument("--write", action="store_true", help="Write normalized datasets")
    args = ap.parse_args()
    existing = {r["title"] + "|" + "|".join(r.get("sources", [])): r["case_id"]
                for r in json.loads((ROOT/"datasets/reports.json").read_text(encoding="utf-8-sig"))}
    rows=[]
    for f in sorted(args.source.glob("vulns-*.json")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if not line.strip(): continue
            try: obj=json.loads(line)
            except json.JSONDecodeError: continue
            if str(obj.get("severity","")).lower() != "critical": continue
            ds=obj.get("dataSource") or {}; title=str(obj.get("title","")).strip(); repo=str(ds.get("repo","")).strip()
            key=title+"|"+repo; cid=existing.get(key)
            if not cid:
                digest=hashlib.sha1(key.encode()).hexdigest()[:12]
                cid="NEW-"+digest
            rows.append({"case_id":cid,"title":title,"severity":"Critical","record_type":"audit_finding","status":"candidate","source_name":"Smart Contract VulnDB","project":str(ds.get("name","")).strip() or None,"vulnerability_class":None,"impact":None,"cvss":None,"reward_amount":None,"reward_currency":None,"disclosed":None,"evidence_level":"secondary","sources":[repo] if repo else [],"notes":"Critical finding imported as metadata; review original source before promotion."})
    rows=list({(r["title"], tuple(r["sources"])):r for r in rows}.values())
    print(f"Prepared {len(rows)} Critical audit findings from {args.source}")
    if not args.write: return
    if any(r["case_id"].startswith("NEW-") for r in rows):
        raise SystemExit("Refusing to write: new IDs require explicit migration design; review the prepared set first.")
    (ROOT/"datasets/reports.json").write_text(json.dumps(rows,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    with (ROOT/"datasets/reports.csv").open("w",encoding="utf-8",newline="") as fh:
        w=csv.DictWriter(fh,fieldnames=FIELDS); w.writeheader()
        for r in rows:
            rr=dict(r); rr["sources"]=" | ".join(rr.get("sources",[])); w.writerow({k:rr.get(k) for k in FIELDS})

if __name__ == "__main__": main()
