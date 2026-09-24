import csv, pathlib, re, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
rows=list(csv.DictReader((ROOT/"datasets/reports.csv").open(encoding="utf-8-sig",newline="")))
errors=[]
ids=set()
for n,row in enumerate(rows,2):
    cid=row.get("case_id","")
    if not re.fullmatch(r"SCF-\d{4}",cid): errors.append(f"line {n}: invalid case_id")
    if cid in ids: errors.append(f"line {n}: duplicate case_id {cid}")
    ids.add(cid)
    if row.get("severity")!="Critical": errors.append(f"line {n}: non-Critical record")
    if row.get("record_type") not in {"audit_finding","bugfix_review","incident"}: errors.append(f"line {n}: invalid record_type")
    if not row.get("title"): errors.append(f"line {n}: missing title")
    if not row.get("sources"): errors.append(f"line {n}: missing sources")
print(f"records={len(rows)}")
if errors:
    print("\n".join(errors[:100]))
    sys.exit(1)
print("VALID")