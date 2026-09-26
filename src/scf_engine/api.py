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
from .rpc import RpcClient, collect_transaction
from .forensics import build_forensic_case, build_forensic_case_without_trace
from .state import collect_state_snapshot, addresses_from_forensic_case


class SourceRequest(BaseModel):
    filename: str = Field(default="Contract.sol", min_length=1)
    source: str = Field(min_length=1)


class AnalysisRequest(BaseModel):
    sources: list[SourceRequest] = Field(min_length=1)


class TransactionRequest(BaseModel):
    rpc_url: str = Field(min_length=1)
    tx_hash: str = Field(min_length=1)
    include_trace: bool = True
    state_block: str | None = None


class StateRequest(BaseModel):
    rpc_url: str = Field(min_length=1)
    address: str = Field(min_length=1)
    block: str = "latest"
    slots: list[str] = Field(default_factory=list)


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

    @app.post("/forensics/transaction")
    def forensic_transaction(request: TransactionRequest):
        client = RpcClient(request.rpc_url)
        payload = collect_transaction(client, request.tx_hash, include_trace=request.include_trace)
        case = build_forensic_case(payload) if request.include_trace else build_forensic_case_without_trace(payload)
        if request.state_block:
            case["state_snapshot"] = collect_state_snapshot(client, addresses_from_forensic_case(case), request.state_block)
        return case

    @app.post("/forensics/state")
    def forensic_state(request: StateRequest):
        return collect_state_snapshot(client=RpcClient(request.rpc_url), addresses=[request.address], block=request.block, slots_by_address={request.address: request.slots})

    return app
