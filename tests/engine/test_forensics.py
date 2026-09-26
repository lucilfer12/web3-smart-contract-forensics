from scf_engine.forensics import build_forensic_case, build_forensic_case_without_trace
from scf_engine.state import StateSnapshot


def _payload():
    return {
        "transaction": {
            "hash": "0xtx",
            "blockNumber": "0x2a",
            "blockHash": "0xblock",
            "from": "0xaaa",
            "to": "0xbbb",
            "value": "0x10",
            "input": "0x12345678deadbeef",
            "nonce": "0x1",
        },
        "receipt": {
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3b9aca00",
            "logs": [{
                "address": "0xtoken",
                "topics": [
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    "0x0000000000000000000000000000000000000bbb",
                    "0x0000000000000000000000000000000000000aaa",
                ],
                "data": "0x64",
                "logIndex": "0x0",
            }],
        },
        "block": {"timestamp": "0x100"},
        "trace": {
            "provider_mode": "debug_callTracer",
            "result": {
                "from": "0xaaa",
                "to": "0xbbb",
                "value": "0x10",
                "input": "0x12345678deadbeef",
                "calls": [{"type": "CALL", "from": "0xbbb", "to": "0xccc", "value": "0x5", "input": "0xabcdef12"}],
            },
        },
    }
def test_build_forensic_case_is_flow_first():
    case = build_forensic_case(_payload())
    assert case["transaction"]["entry_selector"] == "0x12345678"
    assert case["execution"]["summary"]["frame_count"] == 2
    assert case["execution"]["erc20_flows"][0]["address"].endswith(("aaa", "bbb"))
    assert case["economic"]["status"] == "FLOW_ONLY"
    assert case["economic"]["profit_claim"] is None
    assert any(item["kind"] == "transaction-trace" for item in case["evidence"])


def test_no_trace_is_explicitly_not_an_economic_claim():
    payload = dict(_payload())
    payload.pop("trace")
    case = build_forensic_case_without_trace(payload)
    assert case["economic"]["status"] == "TRACE_REQUIRED"
    assert case["execution"]["summary"] is None
    assert case["economic"]["profit_claim"] is None


def test_state_snapshot_serialization():
    snapshot = StateSnapshot("0xabc", "0x2a", "0x6000", "0x10", {"0x0": "0x01"})
    result = snapshot.as_dict()
    assert result["code_present"] is True
    assert result["bytecode_size"] == 2
    assert result["storage"]["0x0"] == "0x01"
