from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..models import ContractModel, Finding, FunctionModel, SourceUnit


class Detector(ABC):
    rule_id: str
    title: str
    severity: str
    cwe: str | None = None
    swc: str | None = None
    tags: tuple[str, ...] = ()

    @abstractmethod
    def run(self, unit: SourceUnit, contract: ContractModel, function: FunctionModel) -> Iterable[Finding]:
        raise NotImplementedError

    def make_finding(
        self,
        *,
        function: FunctionModel,
        description: str,
        recommendation: str,
        evidence,
        confidence: float,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            confidence=max(0.0, min(1.0, confidence)),
            description=description,
            recommendation=recommendation,
            evidence=list(evidence),
            contract=function.contract,
            function=function.signature,
            cwe=self.cwe,
            swc=self.swc,
            tags=list(self.tags),
        )
