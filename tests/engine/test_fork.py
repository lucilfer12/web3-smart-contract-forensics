from scf_engine.fork import ForkRun, build_anvil_command, reproduction_evidence


def test_fork_command_supports_historical_block():
    assert build_anvil_command("http://rpc", "123")[-2:] == ["--fork-block-number", "123"]


def test_fork_requires_success_for_reproduction():
    failed = ForkRun(True, ["anvil"], "FAILED", 1, "", "error")
    assert reproduction_evidence(failed, "x")["state"] == "UNVERIFIED"
    passed = ForkRun(True, ["anvil"], "PASSED", 0, "ok", "", "123")
    assert reproduction_evidence(passed, "x")["state"] == "REPRODUCED"
