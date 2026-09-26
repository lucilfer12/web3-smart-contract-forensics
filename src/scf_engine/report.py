from __future__ import annotations

import json
from typing import Any

from .models import AnalysisResult, Finding


def _level(severity: str) -> str:
    return {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Informational": "note"}.get(severity, "warning")


def finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "contract": finding.contract,
        "function": finding.function,
        "cwe": finding.cwe,
        "swc": finding.swc,
        "tags": finding.tags,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "evidence": [
            {
                "file": e.source.file,
                "line": e.source.line,
                "column": e.source.column,
                "snippet": e.snippet,
                "reason": e.reason,
                "confidence": e.confidence,
            }
            for e in finding.evidence
        ],
    }


def json_report(result: AnalysisResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload["findings"] = [finding_dict(f) for f in result.findings]
    payload["summary"] = result.summary()
    return payload


def sarif_report(result: AnalysisResult) -> dict[str, Any]:
    rules = {}
    results = []
    for finding in result.findings:
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.recommendation},
            "properties": {"severity": finding.severity, "cwe": finding.cwe, "swc": finding.swc},
        })
        location = finding.evidence[0].source if finding.evidence else None
        result_item = {
            "ruleId": finding.rule_id,
            "level": _level(finding.severity),
            "message": {"text": finding.description},
            "properties": {"confidence": finding.confidence, "severity": finding.severity},
        }
        if location:
            result_item["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": location.file}, "region": {"startLine": location.line, "startColumn": location.column}}}]
        results.append(result_item)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "SCF Engine", "version": result.tool_version, "rules": list(rules.values())}}, "results": results}]}


def write_json(result: AnalysisResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(json_report(result), handle, indent=2, ensure_ascii=False)


def write_sarif(result: AnalysisResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sarif_report(result), handle, indent=2, ensure_ascii=False)
