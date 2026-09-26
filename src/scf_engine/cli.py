from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detectors import DEFAULT_DETECTORS
from .engine import analyze
from .report import finding_dict, json_report, write_json, write_sarif
from .graph import to_dot, to_mermaid
from .trace import analyze_trace, summarize_trace
from .evm import analyze_bytecode
from .knowledge import KnowledgeStore
from .compiler import compile_source
from .external import run_slither, slither_available
from .foundry import available as foundry_available, run_tests, record_reproduction
from .verification import EvidenceRecord
from .rpc import RpcClient, collect_transaction, normalize_transaction
from .forensics import build_forensic_case, build_forensic_case_without_trace
from .state import collect_state_snapshot, addresses_from_forensic_case


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scf", description="Web3 Smart Contract Forensics analysis engine")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze Solidity source files")
    a.add_argument("target", help="Solidity file or directory")
    a.add_argument("--json", dest="json_path", help="Write full JSON result")
    a.add_argument("--sarif", dest="sarif_path", help="Write SARIF result")
    a.add_argument("--only", action="append", help="Restrict to one detector rule id; repeatable")
    a.add_argument("--fail-on", choices=["Informational", "Low", "Medium", "High", "Critical"], help="Fail when a finding meets/exceeds this severity")
    a.add_argument("--dot", dest="dot_path", help="Write knowledge/call graph as Graphviz DOT")
    a.add_argument("--mermaid", dest="mermaid_path", help="Write knowledge/call graph as Mermaid")

    t = sub.add_parser("trace", help="Analyze a local EVM call-trace JSON")
    t.add_argument("path", help="Trace JSON file")
    t.add_argument("--json", dest="json_path", help="Write JSON result")

    r = sub.add_parser("rules", help="List built-in detector rules")
    r.add_argument("--json", dest="json_path", help="Write rules as JSON")

    s = sub.add_parser("serve", help="Run the local FastAPI service")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", default=8000, type=int)

    b = sub.add_parser("bytecode", help="Disassemble and summarize EVM bytecode")
    b.add_argument("value", help="0x-prefixed bytecode or a file containing it")
    b.add_argument("--json", dest="json_path", nargs="?", const="-", help="Write JSON result; omit path to print JSON")

    i = sub.add_parser("index", help="Analyze and ingest findings/graph into SQLite")
    i.add_argument("target")
    i.add_argument("--db", default=".scf/scf.db")

    c = sub.add_parser("compile", help="Compile Solidity with solc when installed")
    c.add_argument("path")
    c.add_argument("--json", dest="json_path")

    l = sub.add_parser("slither", help="Run optional Slither adapter")
    l.add_argument("target")
    l.add_argument("--json", dest="json_path")

    f = sub.add_parser("reproduce", help="Run controlled Foundry tests")
    f.add_argument("project")
    f.add_argument("--test", dest="test_filter")
    f.add_argument("--reference", default="local-controlled-reproduction")

    x = sub.add_parser("tx", help="Collect one transaction from an EVM JSON-RPC endpoint")
    x.add_argument("rpc_url")
    x.add_argument("tx_hash")
    x.add_argument("--no-trace", action="store_true")
    x.add_argument("--json", dest="json_path")

    fs = sub.add_parser("forensics", help="Build a defensive forensic case from a transaction")
    fs.add_argument("rpc_url")
    fs.add_argument("tx_hash")
    fs.add_argument("--no-trace", action="store_true")
    fs.add_argument("--state-block", help="Optional historical block tag for state evidence")
    fs.add_argument("--json", dest="json_path")

    st = sub.add_parser("state", help="Read historical EVM code, balance and selected storage")
    st.add_argument("rpc_url")
    st.add_argument("address")
    st.add_argument("--block", default="latest")
    st.add_argument("--slot", action="append", default=[])
    st.add_argument("--json", dest="json_path")
    return parser


def _selected(ids: list[str] | None):
    if not ids:
        return DEFAULT_DETECTORS
    wanted = set(ids)
    return [detector for detector in DEFAULT_DETECTORS if detector.rule_id in wanted]


def _fail_threshold(findings, threshold: str | None) -> bool:
    if not threshold:
        return False
    order = {name: index for index, name in enumerate(("Informational", "Low", "Medium", "High", "Critical"))}
    return any(order.get(item.severity, 0) >= order[threshold] for item in findings)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        rows = [{"id": d.rule_id, "title": d.title, "severity": d.severity, "cwe": d.cwe, "swc": d.swc, "tags": list(d.tags)} for d in DEFAULT_DETECTORS]
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        else:
            for row in rows:
                print(f"{row['id']}\t{row['severity']}\t{row['title']}")
        return 0

    if args.command == "trace":
        result = analyze_trace(args.path)
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
        else:
            print(json.dumps(result, indent=2))
        return 0

    if args.command == "serve":
        import uvicorn
        uvicorn.run("scf_engine.api:create_app", host=args.host, port=args.port, factory=True)
        return 0

    if args.command == "bytecode":
        value = Path(args.value).read_text(encoding="utf-8").strip() if Path(args.value).is_file() else args.value
        result = analyze_bytecode(value)
        if args.json_path and args.json_path != "-":
            Path(args.json_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
        else:
            print(json.dumps(result, indent=2))
        return 0

    if args.command == "index":
        result = analyze(args.target)
        store = KnowledgeStore(args.db)
        store.ingest(result)
        print(json.dumps(store.stats(), indent=2))
        store.close()
        return 0

    if args.command == "compile":
        source_path = Path(args.path)
        payload = compile_source(source_path.name, source_path.read_text(encoding="utf-8"))
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            print(json.dumps(payload, indent=2))
        return 0 if payload.get("available") else 2

    if args.command == "slither":
        payload = run_slither(args.target)
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            print(json.dumps(payload, indent=2))
        return 0 if payload.get("available") else 2

    if args.command == "reproduce":
        status = foundry_available()
        if not status.get("forge"):
            print(json.dumps({"available": False, "status": status, "error": "forge executable not found"}, indent=2))
            return 2
        run = run_tests(args.project, args.test_filter)
        outcome = record_reproduction(run, args.reference)
        print(json.dumps({"run": run.__dict__, "outcome": outcome.status, "reason": outcome.reason, "verification": {"state": outcome.verification.state.value, "evidence": [item.__dict__ for item in outcome.verification.evidence]}}, indent=2))
        return 0 if outcome.status == "REPRODUCED" else 1

    if args.command == "forensics":
        client = RpcClient(args.rpc_url)
        payload = collect_transaction(client, args.tx_hash, include_trace=not args.no_trace)
        case = build_forensic_case(payload) if not args.no_trace else build_forensic_case_without_trace(payload)
        if args.state_block:
            addresses = addresses_from_forensic_case(case)
            case["state_snapshot"] = collect_state_snapshot(client, addresses, args.state_block)
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(case, indent=2), encoding="utf-8")
        else:
            print(json.dumps(case, indent=2))
        return 0

    if args.command == "state":
        payload = collect_state_snapshot(RpcClient(args.rpc_url), [args.address], args.block, {args.address: args.slot})
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if args.command == "tx":
        payload = collect_transaction(RpcClient(args.rpc_url), args.tx_hash, include_trace=not args.no_trace)
        normalized = normalize_transaction(payload)
        if payload.get("trace"):
            normalized["trace_summary"] = summarize_trace(payload["trace"])
        if args.json_path:
            Path(args.json_path).write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        else:
            print(json.dumps(normalized, indent=2))
        return 0

    result = analyze(args.target, _selected(args.only))
    print(json.dumps(result.summary(), indent=2))
    for finding in result.findings:
        location = finding.evidence[0].source if finding.evidence else None
        where = f"{location.file}:{location.line}" if location else finding.contract
        print(f"[{finding.severity}] {finding.rule_id} {where} {finding.title} (confidence={finding.confidence:.2f})")
    if args.json_path:
        write_json(result, args.json_path)
    if args.sarif_path:
        write_sarif(result, args.sarif_path)
    if args.dot_path:
        Path(args.dot_path).write_text(to_dot(result.graph), encoding="utf-8")
    if args.mermaid_path:
        Path(args.mermaid_path).write_text(to_mermaid(result.graph), encoding="utf-8")
    return 1 if _fail_threshold(result.findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
