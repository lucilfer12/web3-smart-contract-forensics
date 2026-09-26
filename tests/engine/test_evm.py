from scf_engine.evm import analyze_bytecode, disassemble


def test_evm_disassembly_and_security_metrics():
    code = "0x63deadbeef60005260016000f4ff"
    instructions = disassemble(code)
    assert any(item.mnemonic == "PUSH4" for item in instructions)
    metrics = analyze_bytecode(code)
    assert metrics["delegatecalls"] == 1
    assert metrics["selfdestructs"] == 1
    assert metrics["candidate_selectors"]
