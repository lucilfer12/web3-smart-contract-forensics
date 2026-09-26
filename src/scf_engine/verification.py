from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class VerificationState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SOURCE_VERIFIED = "SOURCE_VERIFIED"
    ANALYST_VERIFIED = "ANALYST_VERIFIED"
    REPRODUCED = "REPRODUCED"
    INDEPENDENTLY_REPRODUCED = "INDEPENDENTLY_REPRODUCED"


ORDER = {state: index for index, state in enumerate(VerificationState)}


@dataclass(frozen=True)
class EvidenceRecord:
    kind: str
    reference: str
    note: str = ""


@dataclass
class Verification:
    state: VerificationState = VerificationState.UNVERIFIED
    evidence: list[EvidenceRecord] | None = None

    def __post_init__(self) -> None:
        self.evidence = list(self.evidence or [])

    def can_promote(self, target: VerificationState) -> bool:
        current = ORDER[self.state]
        wanted = ORDER[target]
        if wanted <= current:
            return True
        required = {
            VerificationState.SOURCE_VERIFIED: {"primary-source"},
            VerificationState.ANALYST_VERIFIED: {"primary-source", "analyst-review"},
            VerificationState.REPRODUCED: {"primary-source", "analyst-review", "controlled-reproduction"},
            VerificationState.INDEPENDENTLY_REPRODUCED: {"primary-source", "analyst-review", "controlled-reproduction", "independent-reproduction"},
        }[target]
        kinds = {item.kind for item in self.evidence}
        return required.issubset(kinds)

    def promote(self, target: VerificationState, evidence: Iterable[EvidenceRecord]) -> None:
        new_evidence = list(evidence)
        combined = self.evidence + new_evidence
        old = self.evidence
        self.evidence = combined
        if not self.can_promote(target):
            self.evidence = old
            raise ValueError(f"insufficient evidence to promote {self.state.value} -> {target.value}")
        self.state = target
