from scf_engine.economic import value_forensics


def test_valuation_is_explicit_and_not_profit_claim():
    case = {"transaction": {"gas_used": "0x5208", "effective_gas_price": "0x3b9aca00"}, "execution": {"erc20_flows": [{"address": "0xtoken", "incoming": 100, "outgoing": 40, "net": 60}]}}
    result = value_forensics(case, {"0xtoken": {"usd_per_raw_unit": "2", "evidence": "operator-price-source"}, "NATIVE": {"usd_per_raw_unit": "1", "evidence": "native-price-source"}})
    assert result["status"] == "VALUED_FLOW"
    assert result["token_breakdown"][0]["net_usd"] == "120"
    assert result["profit_claim"] is None
