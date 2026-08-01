# -*- coding: utf-8 -*-
"""Verify VulnGym node {file,line,code} against a local checkout."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def normalize_code(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # compare by stripped lines to tolerate leading tabs in annotations
    lines = [ln.rstrip() for ln in s.split("\n")]
    return "\n".join(lines).strip()


def parse_line(line) -> tuple[int, int]:
    if isinstance(line, int):
        return line, line
    m = re.fullmatch(r"(\d+)-(\d+)", str(line).strip())
    if not m:
        raise ValueError(f"bad line: {line!r}")
    a, b = int(m.group(1)), int(m.group(2))
    return a, b


def resolve_repo_file(repo: Path, rel: str) -> Path:
    """Join a repo-relative path and reject traversal / absolute escapes."""
    rel = (rel or "").replace("\\", "/").strip()
    if not rel or rel.startswith("/") or re.match(r"^[A-Za-z]:/", rel):
        raise ValueError(f"file must be repo-relative, got {rel!r}")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"path traversal refused: {rel!r}")
    repo_r = repo.resolve()
    path = (repo_r.joinpath(*parts)).resolve()
    try:
        path.relative_to(repo_r)
    except ValueError as exc:
        raise ValueError(f"path escapes repo root: {rel!r}") from exc
    return path

def slice_file(path: Path, start: int, end: int) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    # 1-based inclusive
    chunk = lines[start - 1 : end]
    return "\n".join(chunk)


def check_node(repo: Path, node: dict, label: str) -> dict:
    rel = node["file"].replace("\\", "/")
    try:
        path = resolve_repo_file(repo, rel)
    except ValueError as exc:
        return {"label": label, "ok": False, "error": str(exc)}
    start, end = parse_line(node["line"])
    if not path.is_file():
        return {"label": label, "ok": False, "error": f"missing file {rel}"}
    got = normalize_code(slice_file(path, start, end))
    exp = normalize_code(node["code"])
    ok = got == exp
    return {
        "label": label,
        "ok": ok,
        "file": rel,
        "line": node["line"],
        "expected_head": exp[:120],
        "got_head": got[:120],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--nodes", type=Path, required=True, help="JSON with entry_point/critical_operation/trace")
    args = ap.parse_args()
    data = json.loads(args.nodes.read_text(encoding="utf-8"))
    # allow full entry or {nodes: ...}
    if "entry_point" in data:
        entry = data
    else:
        entry = data["entry"]
    results = []
    results.append(check_node(args.repo, entry["entry_point"], "entry_point"))
    results.append(check_node(args.repo, entry["critical_operation"], "critical_operation"))
    for i, t in enumerate(entry.get("trace") or []):
        results.append(check_node(args.repo, t, f"trace[{i}]"))
    bad = [r for r in results if not r["ok"]]
    print(json.dumps({"pass": not bad, "results": results}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if not bad else 1)


if __name__ == "__main__":
    main()
