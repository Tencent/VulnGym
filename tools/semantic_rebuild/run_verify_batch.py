# -*- coding: utf-8 -*-
"""Verify AFTER.json nodes against the entry's vuln commit."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
N8N = ROOT / ".cache" / "repos" / "n8n"
VERIFY = ROOT / "tools" / "semantic_rebuild" / "verify_nodes.py"

COMMITS = {
    "entry-00099": "8ab4492e8c0b743455e51fc111441d8d5010a6ad",
    "entry-00100": "8ab4492e8c0b743455e51fc111441d8d5010a6ad",
    "entry-00103": "57d6015f2ea0442c24e0449105325b7e36f066df",
    "entry-00176": "3af9095245be3aaad6bc16622f379f79c6c6068f",
    "entry-00511": "09e2c2b5547b49a824a8265d312583f5d1f5c79f",
    "entry-00512": "09e2c2b5547b49a824a8265d312583f5d1f5c79f",
}

FILES_BY_ENTRY = {
    "entry-00099": [
        "packages/workflow/src/expression-sandboxing.ts",
        "packages/workflow/src/expression-evaluator-proxy.ts",
        "packages/workflow/src/expression.ts",
        "packages/cli/src/workflows/workflows.controller.ts",
    ],
    "entry-00100": [
        "packages/workflow/src/expression-sandboxing.ts",
        "packages/workflow/src/expression-evaluator-proxy.ts",
        "packages/workflow/src/expression.ts",
    ],
    "entry-00103": [
        "packages/cli/src/webhooks/webhook-helpers.ts",
        "packages/cli/src/webhooks/webhook-request-handler.ts",
        "packages/core/src/html-sandbox.ts",
    ],
    "entry-00176": [
        "packages/nodes-base/nodes/Code/Code.node.ts",
        "packages/@n8n/task-runner-python/src/task_analyzer.py",
        "packages/@n8n/task-runner-python/src/constants.py",
    ],
    "entry-00511": [
        "packages/workflow/src/expression.ts",
        "packages/@n8n/expression-runtime/src/extensions/extend.ts",
    ],
    "entry-00512": [
        "packages/workflow/src/expression.ts",
        "packages/@n8n/expression-runtime/src/runtime/reset.ts",
        "packages/workflow/src/expression-sandboxing.ts",
    ],
}

DEFAULT = [
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00511",
    "entry-00512",
]


def materialize(commit: str, files: list[str]) -> None:
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
        raise ValueError(f"refusing non-hex commit: {commit!r}")
    for f in files:
        rel = f.replace("\\", "/")
        if ".." in rel.split("/") or rel.startswith("/") or re.match(r"^[A-Za-z]:/", rel):
            raise ValueError(f"refusing unsafe repo path: {f!r}")
    subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=N8N, check=False, capture_output=True)
    subprocess.check_call(["git", "checkout", "--detach", commit], cwd=N8N)
    for f in files:
        data = subprocess.check_output(["git", "show", f"HEAD:{f}"], cwd=N8N)
        path = N8N / f
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main() -> int:
    entries = sys.argv[1:] or DEFAULT
    rc = 0
    for eid in entries:
        commit = COMMITS[eid]
        print(f"=== {eid} @ {commit[:12]} ===")
        materialize(commit, FILES_BY_ENTRY[eid])
        after = ROOT / "tools" / "semantic_rebuild" / eid / "AFTER.json"
        p = subprocess.run(
            [sys.executable, str(VERIFY), "--repo", str(N8N), "--nodes", str(after)],
            cwd=ROOT,
        )
        if p.returncode != 0:
            rc = p.returncode
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
