"""Extract bounded public evidence excerpts without promoting findings."""
from __future__ import annotations
import json, re
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "datasets" / "reports.json"
OUTPUT = ROOT / "datasets" / "public_evidence.json"

class TextParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts=[]; self.skip=0; self.in_title=False
    def handle_starttag(self, tag, attrs):
        if tag in {"script","style","noscript","svg"}: self.skip += 1
        if tag == "title": self.in_title = True
    def handle_endtag(self, tag):
        if tag in {"script","style","noscript","svg"} and self.skip: self.skip -= 1
        if tag == "title": self.in_title = False
    def handle_data(self, data):
        if self.skip: return
        value = re.sub(r"\s+", " ", data).strip()
        if value: self.parts.append(value)

def fetch(url):
    req = Request(url, headers={"User-Agent":"SCF-EvidenceExtractor/1.0"})
    try:
        with urlopen(req, timeout=15) as r:
            raw = r.read(3_000_000)
            return r.status, r.geturl(), raw.decode("utf-8","replace")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return None, url, str(exc)

def words(text):
    return [w for w in re.findall(r"[a-zA-Z0-9'-]{4,}", text.lower())
            if w not in {"function","critical","issue","allows","might","should"}]

def extract(title, text):
    compact = re.sub(r"\s+", " ", text)
    target = words(title)
    if not target: return None
    lower = compact.lower()
    needle = " ".join(target)
    positions = [m.start() for m in re.finditer(re.escape(needle), lower)]
    if positions:
        def richness(pos):
            window = lower[max(0,pos-300):min(len(lower),pos+2600)]
            markers = ("description", "impact", "recommendation", "update", "fixed", "severity", "root cause")
            return sum(window.count(m) for m in markers)
        pos = max(positions, key=richness)
        return compact[max(0,pos-1200):min(len(compact),pos+9000)]
    anchors = [lower.find(w) for w in target[:8] if lower.find(w) >= 0]
    if not anchors: return None
    pos = min(anchors)
    return compact[max(0,pos-700):min(len(compact),pos+1800)]
def main():
    records = json.loads(INPUT.read_text(encoding="utf-8-sig"))
    urls = sorted({u for r in records for u in r.get("sources", [])})
    pages = {}
    for i, url in enumerate(urls, 1):
        status, final_url, raw = fetch(url)
        parser = TextParser()
        if status and raw.lstrip().startswith("<"):
            try: parser.feed(raw)
            except Exception: pass
        pages[url] = {"status": status, "final_url": final_url,
                      "page_title": parser.parts[0] if parser.parts else None,
                      "text": " ".join(parser.parts)[:500_000]}
        print(f"{i}/{len(urls)} status={status} url={url}")
    evidence = []
    for r in records:
        matches = []
        for url in r.get("sources", []):
            page = pages.get(url, {})
            excerpt = extract(r.get("title",""), page.get("text",""))
            if excerpt:
                matches.append({"source": url, "status": page.get("status"),
                                "final_url": page.get("final_url"), "excerpt": excerpt})
        evidence.append({"case_id": r["case_id"], "title": r["title"],
                         "source_matches": matches, "match_count": len(matches),
                         "promotion_policy": "Excerpt discovery never changes verification state."})
    OUTPUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(f"cases={len(evidence)} matched={sum(bool(x['match_count']) for x in evidence)}")

if __name__ == "__main__": main()
