from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AdapterResult:
    tool: str
    available: bool
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    evidence: dict[str, Any]


def _run(command: list[str], cwd: str | Path | None = None, timeout: int = 180) -> AdapterResult:
    tool = command[0]
    if shutil.which(tool) is None:
        return AdapterResult(tool, False, "UNAVAILABLE", None, "", f"{tool} executable not found", {"command": command})
    try:
        proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return AdapterResult(tool, True, "TIMEOUT", None, exc.stdout or "", exc.stderr or "", {"command": command, "timeout": timeout})
    return AdapterResult(
        tool,
        True,
        "PASSED" if proc.returncode == 0 else "FAILED",
        proc.returncode,
        proc.stdout,
        proc.stderr,
        {"command": command, "cwd": str(cwd) if cwd else None},
    )


def hevm_available() -> bool:
    return shutil.which("hevm") is not None


def run_hevm_symbolic(project: str | Path, timeout: int = 180) -> AdapterResult:
    """Run an operator-supplied HEVM test target; no exploit payload generation."""
    return _run(["hevm", "test", str(project)], timeout=timeout)


def echidna_available() -> bool:
    return shutil.which("echidna") is not None


def run_echidna(project: str | Path, timeout: int = 300) -> AdapterResult:
    """Run an existing Echidna property/fuzz test project."""
    return _run(["echidna", str(project)], timeout=timeout)


def forge_fuzz_available() -> bool:
    return shutil.which("forge") is not None


def run_forge_fuzz(project: str | Path, test_filter: str | None = None, timeout: int = 300) -> AdapterResult:
    command = ["forge", "test", "--fuzz-runs", "256"]
    if test_filter:
        command += ["--match-test", test_filter]
    return _run(command, cwd=project, timeout=timeout)


def adapter_inventory() -> dict[str, Any]:
    return {
        "symbolic": {"hevm": hevm_available()},
        "fuzzing": {"echidna": echidna_available(), "forge": forge_fuzz_available()},
    }
