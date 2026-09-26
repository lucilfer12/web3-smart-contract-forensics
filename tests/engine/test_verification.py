from scf_engine.verification import EvidenceRecord, Verification, VerificationState


def test_verification_requires_evidence_chain():
    v = Verification()
    primary = EvidenceRecord("primary-source", "source:1")
    review = EvidenceRecord("analyst-review", "review:1")
    reproduction = EvidenceRecord("controlled-reproduction", "run:1")
    independent = EvidenceRecord("independent-reproduction", "run:2")
    assert not v.can_promote(VerificationState.SOURCE_VERIFIED)
    v.promote(VerificationState.SOURCE_VERIFIED, [primary])
    assert not v.can_promote(VerificationState.REPRODUCED)
    v.promote(VerificationState.ANALYST_VERIFIED, [review])
    v.promote(VerificationState.REPRODUCED, [reproduction])
    v.promote(VerificationState.INDEPENDENTLY_REPRODUCED, [independent])
    assert v.state is VerificationState.INDEPENDENTLY_REPRODUCED


def test_verification_rolls_back_on_failed_promotion():
    v = Verification()
    try:
        v.promote(VerificationState.REPRODUCED, [EvidenceRecord("primary-source", "source:1")])
    except ValueError:
        pass
    else:
        raise AssertionError("promotion should require all evidence classes")
    assert v.state is VerificationState.UNVERIFIED
    assert v.evidence == []
