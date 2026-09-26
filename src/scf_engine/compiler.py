from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


def solc_path() -> str | None:
    return shutil.which("solc")


def standard_json_input(source_name: str, source: str, optimizer_runs: int = 200) -> dict[str, Any]:
    return {
        "language": "Solidity",
        "sources": {source_name: {"content": source}},
        "settings": {
            "optimizer": {"enabled": True, "runs": optimizer_runs},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object", "storageLayout", "metadata"]}},
        },
    }


def compile_source(source_name: str, source: str, optimizer_runs: int = 200) -> dict[str, Any]:
    executable = solc_path()
    if executable is None:
        return {"available": False, "error": "solc executable not found"}
    process = subprocess.run(
        [executable, "--standard-json"],
        input=json.dumps(standard_json_input(source_name, source)).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    try:
        result = json.loads(process.stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        result = {"errors": [{"severity": "error", "formattedMessage": process.stderr.decode("utf-8", errors="replace")}]}
    result["available"] = True
    result["returncode"] = process.returncode
    return result
