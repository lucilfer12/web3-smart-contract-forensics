from scf_engine.rpc import normalize_transaction


def test_transaction_normalization_preserves_forensic_context():
    payload = {
        "transaction": {
            "hash": "0xabc", "blockNumber": "0x10", "blockHash": "0xdef",
            "from": "0xaaa", "to": "0xbbb", "value": "0x20", "input": "0x1234", "nonce": "0x4"
        },
        "receipt": {
            "status": "0x1", "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00",
            "contractAddress": None, "logs": [{"address": "0xtoken"}]
        },
        "block": {"timestamp": "0x64"},
        "trace": {"provider_mode": "debug_callTracer"}
    }
    result = normalize_transaction(payload)
    assert result["hash"] == "0xabc"
    assert result["block_number"] == "0x10"
    assert result["from"] == "0xaaa"
    assert result["to"] == "0xbbb"
    assert result["logs"][0]["address"] == "0xtoken"
    assert result["trace_provider"] == "debug_callTracer"
