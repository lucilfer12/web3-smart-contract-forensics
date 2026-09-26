from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class ForkRun:
    available: bool
    command: list[str]
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    block: str | None = None


def inventory() -> dict[str, bool]:
    return {name: shutil.which(name) is not None for name in ("anvil", "forge")}


def build_anvil_command(rpc_url: str, block: str | None = None, port: int = 8545) -> list[str]:
    command = ["anvil", "--fork-url", rpc_url, "--port", str(port)]
    if block:
        command.extend(["--fork-block-number", str(int(block, 0) if block.startswith("0x") else int(block))])
    return command


def run_forked_tests(project: str, rpc_url: str, *, block: str | None = None,
                     test_filter: str | None = None, timeout: int = 300) -> ForkRun:
    tools = inventory()
    if not (tools["anvil"] and tools["forge"]):
        return ForkRun(False, build_anvil_command(rpc_url, block), "UNAVAILABLE", None, "", "anvil and forge are required")
    anvil_cmd = build_anvil_command(rpc_url, block)
    forge_cmd = ["forge", "test", "--root", project]
    if test_filter:
        forge_cmd += ["--match-test", test_filter]
    server = subprocess.Popen(anvil_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        completed = subprocess.run(forge_cmd, capture_output=True, text=True, timeout=timeout)
        return ForkRun(True, anvil_cmd + [";", *forge_cmd],
                       "PASSED" if completed.returncode == 0 else "FAILED",
                       completed.returncode, completed.stdout, completed.stderr, block)
    except subprocess.TimeoutExpired as exc:
        return ForkRun(True, anvil_cmd + [";", *forge_cmd], "TIMEOUT", None, exc.stdout or "", exc.stderr or "", block)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


def reproduction_evidence(run: ForkRun, reference: str) -> dict[str, Any]:
    if run.status != "PASSED":
        return {"state": "UNVERIFIED", "reason": "fork test did not pass", "evidence": []}
    return {"state": "REPRODUCED", "reason": "controlled local fork test passed",
            "evidence": [{"kind": "controlled-reproduction", "reference": reference,
                          "block": run.block, "returncode": run.returncode}]}
