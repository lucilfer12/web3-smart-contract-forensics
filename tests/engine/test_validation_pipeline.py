from scf_engine.cross_validate import AgentObservation, cross_validate
from scf_engine.invariants import evaluate_invariants
from scf_engine.pipeline import build_validation_pipeline


def _case():
    return {"execution": {"root": {"value": 1}}, "economic": {"profit_claim": None}}


def test_invariants_pass_on_safe_case():
    result = evaluate_invariants(_case())
    assert all(item.status == "PASS" for item in result)


def test_cross_validation_conflict_is_visible():
    observations = [
        AgentObservation("static", "F1", "CONFIRMED", 0.8, ["source"]),
        AgentObservation("symbolic", "F1", "REJECTED", 0.7, ["trace"]),
    ]
    result = cross_validate(observations)
    assert result[0].consensus == "CONFLICT"
    assert result[0].dissenting_agents


def test_pipeline_blocks_conflicting_promotion():
    observations = [
        AgentObservation("static", "F1", "CONFIRMED", 0.8, ["source"]),
        AgentObservation("symbolic", "F1", "REJECTED", 0.7, ["trace"]),
    ]
    result = build_validation_pipeline(_case(), observations)
    assert result["promotion_gate"]["eligible"] is False
    assert result["cross_validation"]["summary"]["conflict"] == 1
