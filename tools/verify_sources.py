"""Verify reachability of public provenance URLs; never promotes findings."""
from __future__ import annotations
import json, time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "datasets" / "reports.json"
OUTPUT = ROOT / "datasets" / "source_verification.json"

def check(url: str) -> dict:
    req = Request(url, headers={"User-Agent": "SCF-SourceVerifier/1.0"})
    started = time.time()
    try:
        with urlopen(req, timeout=12) as response:
            return {"url": url, "reachable": True, "status": response.status,
                    "final_url": response.geturl(), "elapsed_ms": round((time.time()-started)*1000)}
    except HTTPError as exc:
        return {"url": url, "reachable": False, "status": exc.code,
                "error": str(exc), "elapsed_ms": round((time.time()-started)*1000)}
    except (URLError, TimeoutError, OSError) as exc:
        return {"url": url, "reachable": False, "status": None,
                "error": str(exc), "elapsed_ms": round((time.time()-started)*1000)}

def main() -> int:
    records = json.loads(INPUT.read_text(encoding="utf-8-sig"))
    urls = sorted({u for r in records for u in r.get("sources", [])})
    results = [check(url) for url in urls]
    OUTPUT.write_text(json.dumps({
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy": "Reachability is not evidence of correctness and never changes case status.",
        "results": results,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ok = sum(1 for x in results if x["reachable"])
    print(f"urls={len(results)} reachable={ok} unreachable={len(results)-ok}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
