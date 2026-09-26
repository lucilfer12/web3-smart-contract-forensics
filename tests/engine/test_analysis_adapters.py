from scf_engine.analysis_adapters import adapter_inventory, run_hevm_symbolic


def test_adapter_inventory_is_structured():
    result = adapter_inventory()
    assert "symbolic" in result
    assert "fuzzing" in result


def test_missing_symbolic_tool_is_explicit():
    result = run_hevm_symbolic("fixtures/contracts/vulnerable")
    assert result.status in {"UNAVAILABLE", "PASSED", "FAILED", "TIMEOUT"}
    assert "command" in result.evidence
