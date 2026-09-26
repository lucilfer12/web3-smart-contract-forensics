from pathlib import Path

from scf_engine.engine import analyze
from scf_engine.parser import parse_source
from scf_engine.report import json_report, sarif_report
from scf_engine.trace import summarize_trace, forensic_flags

ROOT = Path(__file__).parents[2]
VULN = ROOT / "fixtures" / "contracts" / "vulnerable"
CLEAN = ROOT / "fixtures" / "contracts" / "clean"


def test_parser_builds_contract_and_function_ir():
    unit = parse_source("sample.sol", "pragma solidity ^0.8.0; contract A { uint x; function f() external { x = 1; } }")
    assert set(unit.contracts) == {"A"}
    fn = next(iter(unit.contracts["A"].functions.values()))
    assert fn.writes == ["x"]
    assert fn.cfg_nodes


def test_vulnerable_fixture_has_expected_rules():
    result = analyze(str(VULN))
    ids = {finding.rule_id for finding in result.findings}
    assert "SCF-REENTRANCY-001" in ids
    assert "SCF-AUTH-001" in ids
    assert "SCF-DESTRUCT-001" in ids
    assert "SCF-UPGRADE-001" in ids
    assert result.metrics["contracts"] == 1
    assert result.metrics["graph_nodes"] > 0


def test_clean_fixture_suppresses_guarded_patterns():
    result = analyze(str(CLEAN))
    ids = {finding.rule_id for finding in result.findings}
    assert "SCF-REENTRANCY-001" not in ids
    assert "SCF-ACCESS-001" not in ids


def test_reports_are_machine_readable():
    result = analyze(str(VULN))
    payload = json_report(result)
    sarif = sarif_report(result)
    assert payload["summary"]["findings"] == len(result.findings)
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SCF Engine"


def test_trace_forensics():
    payload = {
        "result": {"from": "0xaaa", "to": "0xbbb", "value": "0x10", "input": "0x12345678", "calls": [
            {"type": "DELEGATECALL", "from": "0xbbb", "to": "0xccc", "input": "0xabcdef12"}
        ]},
        "logs": [{"address": "0xtoken", "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x0000000000000000000000000000000000000aaa", "0x0000000000000000000000000000000000000bbb"], "data": "0x64", "logIndex": "0x1"}]
    }
    summary = summarize_trace(payload)
    assert summary["delegatecalls"] == 1
    assert summary["erc20_transfers"][0]["amount"] == 100
    assert any(flag["type"] == "delegatecall" for flag in forensic_flags(payload))


def test_ast_taint_reaches_delegatecall_target():
    result = analyze(str(VULN))
    taint = [finding for finding in result.findings if finding.rule_id == "SCF-TAINT-001"]
    assert taint
    assert any(finding.function == "execute" for finding in taint)
