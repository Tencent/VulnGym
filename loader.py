"""JSONL loading / saving and line-number normalization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load a JSONL file into a list of dicts."""
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"{path}:{i}: invalid JSON: {e}") from None
    return rows


def save_jsonl(entries: list[dict[str, Any]], path: Path) -> None:
    """Write a list of dicts as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def normalize_line(line: int | str) -> tuple[int, int]:
    """Normalize a line field to (start, end) tuple.

    int 97        → (97, 97)
    str "348-352" → (348, 352)
    str "97-97"   → (97, 97)
    """
    if isinstance(line, int):
        if line < 1:
            raise ValueError(f"line must be >= 1, got {line}")
        return (line, line)
    s = str(line).strip()
    if "-" in s:
        parts = s.split("-", 1)
        start, end = int(parts[0]), int(parts[1])
        if start < 1 or end < start:
            raise ValueError(f"invalid line range: {line}")
        return (start, end)
    val = int(s)
    if val < 1:
        raise ValueError(f"line must be >= 1, got {line}")
    return (val, val)


def format_line(start: int, end: int) -> int | str:
    """Restore line to original type: single-line returns int, multi-line returns str."""
    if start == end:
        return start
    return f"{start}-{end}"


def get_node_key(node: dict) -> tuple:
    """Get (file, line_start, line_end) key for comparing node locations."""
    file = node.get("file", "")
    start, end = normalize_line(node.get("line", 1))
    return (file, start, end)


def collect_all_nodes(entry: dict[str, Any]) -> list[tuple[str, dict]]:
    """Yield all nodes from an entry as (node_path, node_dict) pairs."""
    nodes: list[tuple[str, dict]] = []
    nodes.append(("entry_point", entry.get("entry_point", {})))
    nodes.append(("critical_operation", entry.get("critical_operation", {})))
    for i, trace_node in enumerate(entry.get("trace", [])):
        nodes.append((f"trace[{i}]", trace_node))
    return nodes
