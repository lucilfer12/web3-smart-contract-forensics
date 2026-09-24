import json,csv,pathlib,hashlib

ROOT=pathlib.Path(__file__).resolve().parents[1]
SRC=pathlib.Path(r"C:\Users\pc\AppData\Local\Temp\smart-contract-vulndb\dataset")
rows=[]
for f in SRC.glob("vulns-*.json"):
    with f.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip(): continue
            try: obj=json.loads(line)
            except Exception: continue
            if str(obj.get("severity","")).lower()!="critical": continue
            ds=obj.get("dataSource") or {}
            title=str(obj.get("title","")).strip()
            name=str(ds.get("name","")).strip()
            repo=str(ds.get("repo","")).strip()
            key=hashlib.sha1((title+"|"+repo).encode()).hexdigest()[:12]
            rows.append({"key":key,"title":title,"severity":"Critical","record_type":"audit_finding","status":"candidate","source_name":"Smart Contract VulnDB","project":name or None,"vulnerability_class":None,"impact":None,"cvss":None,"reward_amount":None,"reward_currency":None,"disclosed":None,"evidence_level":"secondary","sources":[repo] if repo else [],"notes":"Critical finding imported as metadata; review original source before promotion."})
rows=list({r["key"]:r for r in rows}.values())
for i,r in enumerate(rows,1):
    r["case_id"]=f"SCF-{i:04d}"
    del r["key"]
(ROOT/"datasets/reports.json").write_text(json.dumps(rows,indent=2,ensure_ascii=False),encoding="utf-8")
fields=["case_id","title","severity","record_type","status","source_name","project","vulnerability_class","impact","cvss","reward_amount","reward_currency","disclosed","evidence_level","sources","notes"]
with (ROOT/"datasets/reports.csv").open("w",encoding="utf-8",newline="") as fh:
    w=csv.DictWriter(fh,fieldnames=fields); w.writeheader()
    for r in rows:
        rr=dict(r); rr["sources"]=" | ".join(rr.get("sources",[])); w.writerow({k:rr.get(k) for k in fields})
print(f"Imported {len(rows)} Critical audit findings.")