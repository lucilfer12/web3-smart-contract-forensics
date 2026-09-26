from scf_engine.agents import agent_inventory, run_agent_team


def test_agent_inventory_is_explicit():
    names = {item["name"] for item in agent_inventory()}
    assert "static-analyzer" in names
    assert "validation-agent" in names
    assert "fuzzing-agent" in names


def test_agent_team_produces_validation_gate():
    payload = run_agent_team("fixtures/contracts/vulnerable")
    assert payload["schema_version"] == "1.0.0"
    assert payload["agents"]
    assert "promotion_gate" in payload["validation"]
