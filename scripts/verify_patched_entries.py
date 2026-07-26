#!/usr/bin/env python3
"""Verify the rebuilt entries and basic JSONL/schema constraints."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ENTRIES_PATH = Path(__file__).resolve().parent.parent / "data" / "entries.jsonl"
TARGETED = ("entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as src:
        for line_no, raw in enumerate(src, start=1):
            if not raw.strip():
                raise ValueError(f"{path}: blank JSONL row at line {line_no}")
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON at line {line_no}: {exc}") from exc
    return rows


def check_line(value: Any) -> str | None:
    if isinstance(value, int):
        return None if value >= 1 else "line < 1"
    if isinstance(value, str) and re.fullmatch(r"\d+-\d+", value):
        start, end = (int(part) for part in value.split("-", 1))
        if start < 1:
            return "line range start < 1"
        if start > end:
            return "line range start > end"
        return None
    return "line must be positive int or 'start-end'"


def check_node(entry_id: str, label: str, node: Any, require_desc: bool) -> list[str]:
    errors: list[str] = []
    if not isinstance(node, dict):
        return [f"{entry_id}: {label} is not an object"]

    for key in ("file", "line", "code"):
        if key not in node:
            errors.append(f"{entry_id}: {label} missing {key}")
    if "file" in node and not isinstance(node["file"], str):
        errors.append(f"{entry_id}: {label}.file is not a string")
    if "code" in node and not isinstance(node["code"], str):
        errors.append(f"{entry_id}: {label}.code is not a string")
    if "line" in node:
        line_error = check_line(node["line"])
        if line_error:
            errors.append(f"{entry_id}: {label} {line_error}")
    if require_desc and not (node.get("desc") or "").strip():
        errors.append(f"{entry_id}: {label} missing desc")
    return errors


def main() -> int:
    try:
        rows = load_jsonl(ENTRIES_PATH)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    failures: list[str] = []
    found: dict[str, dict[str, Any]] = {}

    for row_no, entry in enumerate(rows, start=1):
        entry_id = entry.get("entry_id", f"<line {row_no}>")
        for key in ("entry_point", "critical_operation"):
            failures.extend(check_node(entry_id, key, entry.get(key), require_desc=False))
        trace = entry.get("trace")
        if not isinstance(trace, list):
            failures.append(f"{entry_id}: trace is not a list")
        else:
            for idx, node in enumerate(trace):
                failures.extend(check_node(entry_id, f"trace[{idx}]", node, require_desc=False))
        if entry.get("verify") not in (0, 1):
            failures.append(f"{entry_id}: verify must be 0 or 1")
        if entry_id in TARGETED:
            found[entry_id] = entry

    missing = [entry_id for entry_id in TARGETED if entry_id not in found]
    if missing:
        failures.append(f"missing target entries: {missing}")

    for entry_id in TARGETED:
        entry = found.get(entry_id)
        if not entry:
            continue
        failures.extend(check_node(entry_id, "entry_point", entry.get("entry_point"), require_desc=True))
        failures.extend(
            check_node(entry_id, "critical_operation", entry.get("critical_operation"), require_desc=True)
        )
        trace = entry.get("trace")
        if not trace:
            failures.append(f"{entry_id}: empty trace")
            continue
        for idx, node in enumerate(trace):
            failures.extend(check_node(entry_id, f"trace[{idx}]", node, require_desc=True))

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print(f"{len(failures)} schema failure(s)", file=sys.stderr)
        return 1

    for entry_id in TARGETED:
        entry = found[entry_id]
        print(
            f"ok {entry_id} commit={entry.get('commit')[:8]} "
            f"entry_point={entry['entry_point']['file']}:{entry['entry_point']['line']} "
            f"critical={entry['critical_operation']['file']}:{entry['critical_operation']['line']} "
            f"trace_nodes={len(entry['trace'])} verify={entry.get('verify')}"
        )
    print(f"all {len(rows)} rows are valid JSONL; all 5 target entries match schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
