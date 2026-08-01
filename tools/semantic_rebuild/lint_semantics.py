# -*- coding: utf-8 -*-
"""Issue #6 semantic lint for AFTER.json packs (not a substitute for human judgment)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "tools" / "semantic_rebuild"
IDS = [
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00511",
    "entry-00512",
]

LINE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def node_key(n: dict) -> tuple:
    return (n.get("file"), str(n.get("line")), (n.get("code") or "").strip())


def is_brace_only(code: str) -> bool:
    return bool(re.fullmatch(r"[}\s;]+", (code or "").strip()))


def check_node_schema(eid: str, label: str, node: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(node, dict):
        return [f"{eid}: {label} not an object"]
    for req in ("file", "line", "code"):
        if req not in node or node[req] in (None, ""):
            errs.append(f"{eid}: {label} missing {req}")
    f = node.get("file")
    if isinstance(f, str):
        if f.startswith("/") or "\\" in f[:2] or f.startswith("http") or ".." in f.replace("\\", "/").split("/"):
            errs.append(f"{eid}: {label} file should be repo-relative, got {f!r}")
    line = node.get("line")
    if isinstance(line, int):
        if line < 1:
            errs.append(f"{eid}: {label} line must be >= 1")
    elif isinstance(line, str):
        m = LINE_RE.fullmatch(line.strip())
        if not m:
            errs.append(f"{eid}: {label} bad line form {line!r}")
        else:
            a = int(m.group(1))
            b = int(m.group(2) or m.group(1))
            if a < 1 or b < a:
                errs.append(f"{eid}: {label} invalid line range {line!r}")
    elif line is not None:
        errs.append(f"{eid}: {label} line must be int or 'start-end' string")
    return errs


def lint_entry(eid: str) -> list[str]:
    errs: list[str] = []
    after_path = BASE / eid / "AFTER.json"
    cand_path = BASE / eid / "CANDIDATES.md"
    patch_path = BASE / eid / "PATCH_NOTES.md"
    if not after_path.is_file():
        return [f"{eid}: missing AFTER.json"]
    if not cand_path.is_file():
        errs.append(f"{eid}: missing CANDIDATES.md (Issue asks for candidate loci)")
    if not patch_path.is_file():
        errs.append(f"{eid}: missing PATCH_NOTES.md (Issue encourages patch evidence)")

    data = json.loads(after_path.read_text(encoding="utf-8"))
    if data.get("verify", 0) != 0:
        errs.append(f"{eid}: verify must stay 0 for this PR scope")

    ep = data.get("entry_point") or {}
    cr = data.get("critical_operation") or {}
    trace = data.get("trace") or []

    errs.extend(check_node_schema(eid, "entry_point", ep))
    errs.extend(check_node_schema(eid, "critical_operation", cr))
    for i, t in enumerate(trace):
        errs.extend(check_node_schema(eid, f"trace[{i}]", t))

    if is_brace_only(ep.get("code") or ""):
        errs.append(f"{eid}: entry_point looks brace-only (Issue rejects `}}` style nodes)")

    if not (ep.get("desc") and cr.get("desc")):
        errs.append(f"{eid}: entry/critical missing desc")

    keys = [node_key(ep), node_key(cr)] + [node_key(t) for t in trace]
    seen = {}
    for i, k in enumerate(keys):
        label = ["entry_point", "critical_operation"][i] if i < 2 else f"trace[{i-2}]"
        if k in seen:
            errs.append(f"{eid}: duplicate node {label} == {seen[k]} ({k[0]}:{k[1]})")
        else:
            seen[k] = label

    staticish = re.compile(r"^\s*(const|let|var|export const)?\s*\w+\s*=\s*\{?\s*$")
    if staticish.search((cr.get("code") or "").split("\n")[0]) and "BLOCKED" in (cr.get("code") or ""):
        errs.append(f"{eid}: critical looks like static BLOCKED_* declaration")

    return errs


def main() -> int:
    all_errs: list[str] = []
    for req in ("CRITICAL_RULE.md", "VERIFY_POLICY.md", "README.md"):
        if not (BASE / req).is_file():
            all_errs.append(f"missing {req}")
    for eid in IDS:
        all_errs.extend(lint_entry(eid))
    if all_errs:
        print("SEMANTIC LINT FAIL")
        for e in all_errs:
            print(" -", e)
        return 1
    print("SEMANTIC LINT PASS", len(IDS), "entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
