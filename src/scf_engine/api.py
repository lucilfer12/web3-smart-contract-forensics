from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .knowledge import KnowledgeStore
from .engine import TOOL_VERSION, _metrics, _run_detectors, build_graph
from .detectors import DEFAULT_DETECTORS
from .report import finding_dict
from .parser import parse_source
from .taint import analyze_taint_source, findings_from_taint


class SourceRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    source: str = Field(min_length=1)


class AnalysisRequest(BaseModel):
    sources: list[SourceRequest] = Field(min_length=1)


def _analyze_sources(request: AnalysisRequest):
    units = [parse_source(item.filename, item.source) for item in request.sources]
    findings = _run_detectors(units, DEFAULT_DETECTORS)
    for item in request.sources:
        findings.extend(findings_from_taint(analyze_taint_source(item.source, item.filename)))
    graph = build_graph(units)
    return {
        "tool_version": TOOL_VERSION,
        "summary": {
            "sources": len(units),
            "contracts": sum(len(u.contracts) for u in units),
            "findings": len(findings),
            "metrics": _metrics(units, findings, graph),
        },
        "findings": [finding_dict(f) for f in findings],
        "graph": graph,
        "parse_errors": {u.file: u.parse_errors for u in units if u.parse_errors},
    }


def create_app() -> FastAPI:
    app = FastAPI(title="SCF Engine", version="0.4.0", description="Defensive Solidity static and forensic analysis")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "tool": "scf-engine", "version": "0.4.0"}

    @app.get("/rules")
    def rules():
        from .detectors import DEFAULT_DETECTORS
        return [{"id": d.rule_id, "title": d.title, "severity": d.severity, "cwe": d.cwe, "swc": d.swc, "tags": list(d.tags)} for d in DEFAULT_DETECTORS]

    @app.get("/knowledge/stats")
    def knowledge_stats(db: str = ".scf/scf.db"):
        store = KnowledgeStore(db)
        try:
            return store.stats()
        finally:
            store.close()

    @app.get("/knowledge/findings")
    def knowledge_findings(rule_id: str | None = None, severity: str | None = None, db: str = ".scf/scf.db"):
        store = KnowledgeStore(db)
        try:
            return store.findings(rule_id=rule_id, severity=severity)
        finally:
            store.close()

    @app.get("/knowledge/graph")
    def knowledge_graph(db: str = ".scf/scf.db"):
        store = KnowledgeStore(db)
        try:
            return store.graph()
        finally:
            store.close()

    @app.post("/analyze")
    def analyze_sources(request: AnalysisRequest):
        return _analyze_sources(request)

    @app.post("/analyze/source")
    def analyze_single(request: SourceRequest):
        return _analyze_sources(AnalysisRequest(sources=[request]))

    return app
