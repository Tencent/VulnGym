# -*- coding: utf-8 -*-
"""One-shot: lint → verify → build deliverables."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script: str, *args: str) -> int:
    cmd = [sys.executable, str(HERE / script), *args]
    print("+", " ".join(cmd))
    return subprocess.call(cmd)


def main() -> int:
    for script in ("lint_semantics.py", "run_verify_batch.py", "build_deliverables.py"):
        rc = run(script, *sys.argv[1:] if script == "run_verify_batch.py" else ())
        if rc != 0:
            return rc
    # refresh main dataset rows (verify stays 0 per VERIFY_POLICY)
    rc = run("apply_fixed.py", "--write")
    if rc != 0:
        return rc
    print("ALL OK (entries.jsonl updated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
