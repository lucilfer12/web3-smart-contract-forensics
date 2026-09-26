import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from scf.audit import build_report, classify_title, normalize_source


def test_taxonomy_is_deterministic():
    tags = classify_title("Reentrancy and oracle price manipulation")
    assert "reentrancy" in tags
    assert "oracle" in tags


def test_source_normalization_preserves_scheme():
    assert normalize_source("https://example.com//audit/") == "https://example.com/audit"


def test_report_never_promotes_candidate():
    report = build_report({
        "case_id": "SCF-0001", "title": "Critical issue", "severity": "Critical",
        "record_type": "audit_finding", "status": "candidate",
        "evidence_level": "secondary", "sources": ["https://example.com/a"]
    })
    assert report["classification"]["status"] == "candidate"
    assert report["verification"]["confidence"] < 0.5
