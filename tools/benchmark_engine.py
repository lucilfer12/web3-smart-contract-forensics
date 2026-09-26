from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scf_engine.benchmark import benchmark_dict, run_benchmark


if __name__ == "__main__":
    result = benchmark_dict(run_benchmark(str(ROOT)))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
