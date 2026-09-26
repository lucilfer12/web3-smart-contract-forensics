"""Evidence-first audit report primitives for SCF."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
import re
from urllib.parse import urlparse

STATUS_ORDER = {"candidate": 0, "source_verified": 1, "analyst_verified": 2,
                "reproduced": 3, "corroborated": 4}

KEYWORDS = {
    "reentrancy": ("reentr", "callback", "re-entr"),
    "access-control": ("access control", "access-control", "no access", "non owner", "unauthorized"),
    "initialization": ("initialize", "initializ", "uninitialized", "initializer"),
    "oracle": ("oracle", "price", "twap", "stale price", "manipulat"),
    "accounting": ("rewarddebt", "accounting", "share", "rounding", "calculation", "balance"),
    "validation": ("validation", "check", "sanitiz", "incorrect input", "missing check"),
    "upgradeability": ("upgrade", "proxy", "implementation"),
    "signature": ("signature", "permit", "eip-712", "ecdsa", "replay"),
    "token": ("erc20", "erc721", "erc777", "approval", "allowance", "transfer"),
    "governance": ("governance", "vote", "proposal", "timelock"),
    "cross-chain": ("cross-chain", "bridge", "xchain", "message"),
    "dos": ("denial", "dos", "grief", "gas limit", "out of gas"),
}

def classify_title(title: str) -> list[str]:
    text = title.lower()
    return [name for name, terms in KEYWORDS.items()
            if any(term in text for term in terms)]

def normalize_source(url: str) -> str:
    value = re.sub(r"/{2,}", "/", url.replace("https://", "https://").replace("http://", "http://"))
    value = value.replace("https:/", "https://").replace("http:/", "http://")
    return value.rstrip("/")

def source_is_public_http(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

def initial_confidence(record: dict[str, Any]) -> float:
    """Conservative score: evidence quality, never severity."""
    level = record.get("evidence_level")
    base = {"candidate": 0.20, "secondary": 0.45,
            "primary": 0.70, "corroborated": 0.90}.get(level, 0.10)
    if record.get("status") == "verified":
        base += 0.05
    if record.get("impact"):
        base += 0.02
    if record.get("vulnerability_class"):
        base += 0.02
    return min(base, 0.99)

def build_report(record: dict[str, Any]) -> dict[str, Any]:
    title = record.get("title", "Untitled")
    classes = classify_title(title)
    sources = [normalize_source(x) for x in record.get("sources", [])]
    return {
        "schema_version": "1.0",
        "case_id": record["case_id"],
        "summary": {
            "title": title,
            "executive_summary": (
                "Structured audit record generated from the public corpus. "
                "Technical claims remain unverified until primary evidence is reviewed."
            ),
        },
        "classification": {
            "severity": record.get("severity"),
            "record_type": record.get("record_type"),
            "status": "candidate" if record.get("status") == "candidate" else "source_verified",
            "evidence_level": record.get("evidence_level"),
            "vulnerability_class": record.get("vulnerability_class"),
            "taxonomy": classes,
        },
        "analysis": {
            "root_cause": "Not established from the imported metadata; requires primary-source review.",
            "attack_path": [],
            "preconditions": [],
            "impact": record.get("impact") or "Not established from the imported metadata.",
            "recommendation": "Review the original public report, implement the documented remediation, and verify the fix in an isolated environment.",
            "affected_components": [],
            "assumptions": ["No technical fact is inferred solely from the Critical severity label."],
        },
        "evidence": {
            "sources": sources,
            "evidence_items": [
                {"type": "public_source", "value": u, "verified": False}
                for u in sources
            ],
            "poc": None,
            "poc_status": "not_available",
            "fix_verification": None,
        },
        "verification": {
            "confidence": initial_confidence(record),
            "verification_state": "candidate",
            "checks": ["source-preserved", "no-severity-inference"],
            "limitations": ["Primary report not yet reviewed", "No reproducible PoC generated from metadata"],
        },
        "provenance": {
            "source_name": record.get("source_name"),
            "project": record.get("project"),
            "disclosed": record.get("disclosed"),
            "import_note": record.get("notes"),
        },
        "history": {
            "generated_from": "datasets/reports.json",
            "promotion_rule": "Only evidence-backed review may advance verification_state.",
        },
    }

def to_markdown(report: dict[str, Any]) -> str:
    c = report["classification"]; a = report["analysis"]; e = report["evidence"]
    lines = [
        f"# {report['case_id']} — {report['summary']['title']}", "",
        "## Summary", report["summary"]["executive_summary"], "",
        "## Classification",
        f"- Severity: {c['severity']}",
        f"- Record type: {c['record_type']}",
        f"- Status: {c['status']}",
        f"- Evidence level: {c['evidence_level']}",
        f"- Vulnerability class: {c['vulnerability_class'] or 'Pending primary-source review'}",
        f"- Taxonomy: {', '.join(c['taxonomy']) or 'Pending normalization'}", "",
        "## Root Cause", a["root_cause"], "",
        "## Attack Path", *([f"{i}. {x}" for i, x in enumerate(a["attack_path"], 1)] or ["Not established."]), "",
        "## Preconditions", *([f"- {x}" for x in a["preconditions"]] or ["- Not established."]), "",
        "## Impact", a["impact"], "",
        "## Proof of Concept", e["poc"] or "Not available from imported metadata; do not infer or invent a PoC.", "",
        "## Recommendation", a["recommendation"], "",
        "## Fix Verification", e["fix_verification"] or "Pending documented remediation and isolated verification.", "",
        "## Evidence",
    ]
    lines += [f"- {u}" for u in e["sources"]] or ["- No public source supplied."]
    excerpts = e.get("public_excerpts", [])
    if excerpts:
        lines += ["", "### Public-source excerpts"]
        for item in excerpts:
            excerpt = re.sub(r"\\s+", " ", item.get("excerpt", ""))[:1400]
            lines += [f"- Source: {item.get('source')}", f"  - Excerpt: {excerpt}"]
    lines += ["", "## Verification",
              f"- Confidence: {report['verification']['confidence']:.2f}",
              f"- State: {report['verification']['verification_state']}",
              "- Checks: " + ", ".join(report["verification"]["checks"]),
              "- Limitations: " + "; ".join(report["verification"]["limitations"])]
    return "\n".join(lines) + "\n"
