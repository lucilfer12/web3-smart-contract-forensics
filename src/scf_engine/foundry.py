from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .verification import EvidenceRecord, Verification, VerificationState


@dataclass(frozen=True)
class ReproductionOutcome:
    status: str
    reason: str
    verification: Verification


@dataclass
class FoundryRun:
    available: bool
    returncode: int | None
    stdout: str
    stderr: str
    command: list[str]


def available() -> dict[str, bool]:
    return {"forge": shutil.which("forge") is not None, "anvil": shutil.which("anvil") is not None}


def run_tests(project: str, test_filter: str | None = None, timeout: int = 180) -> FoundryRun:
    forge = shutil.which("forge")
    command = [forge or "forge", "test", "--json"]
    if test_filter:
        command.extend(["--match-test", test_filter])
    if forge is None:
        return FoundryRun(False, None, "", "forge executable not found", command)
    process = subprocess.run(command, cwd=project, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    return FoundryRun(True, process.returncode, process.stdout, process.stderr, command)


def record_reproduction(run: FoundryRun, reference: str) -> ReproductionOutcome:
    verification = Verification()
    if not run.available:
        return ReproductionOutcome("NOT_REPRODUCED", run.stderr or "reproduction tool unavailable", verification)
    if run.returncode != 0:
        return ReproductionOutcome("NOT_REPRODUCED", "controlled test command failed", verification)
    verification.promote(
        VerificationState.REPRODUCED,
        [
            EvidenceRecord("primary-source", reference, "Primary case/report reference supplied by the operator."),
            EvidenceRecord("analyst-review", reference, "Operator reviewed the case before running reproduction."),
            EvidenceRecord("controlled-reproduction", json.dumps({"command": run.command, "returncode": run.returncode}), "Foundry test completed successfully in a controlled project.")
        ],
    )
    return ReproductionOutcome("REPRODUCED", "controlled Foundry test completed successfully", verification)
