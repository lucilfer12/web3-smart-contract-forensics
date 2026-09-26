from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def tool_path(name: str) -> str | None:
    return shutil.which(name)


def slither_available() -> bool:
    return tool_path("slither") is not None


def run_slither(target: str, timeout: int = 180) -> dict[str, Any]:
    executable = tool_path("slither")
    if executable is None:
        return {"available": False, "error": "slither executable not found"}
    with tempfile.TemporaryDirectory(prefix="scf-slither-") as tmp:
        output = Path(tmp) / "slither.json"
        process = subprocess.run(
            [executable, target, "--json", str(output)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        payload: dict[str, Any] = {"available": True, "returncode": process.returncode, "stderr": process.stderr[-4000:]}
        if output.exists():
            try:
                payload["results"] = json.loads(output.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload["results_error"] = "slither output was not valid JSON"
        return payload
