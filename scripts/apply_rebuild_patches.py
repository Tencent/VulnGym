#!/usr/bin/env python3
"""Apply issue #7 rebuilt-chain patches to the full VulnGym entries file."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE = ROOT / "data" / "entries.jsonl"
DEFAULT_PATCH = ROOT / "data" / "entries.rebuilt_chains.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "entries.fixed.jsonl"
DEFAULT_DIFF = ROOT / "reports" / "rebuild_fix_diff.csv"

DIFF_FIELDS = [
    "entry_id",
    "field_path",
    "old_file",
    "old_line",
    "old_code",
    "old_desc",
    "new_file",
    "new_line",
    "new_code",
    "new_desc",
    "reason",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from None
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_no}: row must be an object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def iter_nodes(entry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("entry_point", "critical_operation"):
        node = entry.get(key)
        if isinstance(node, dict):
            yield key, node
    trace = entry.get("trace")
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            if isinstance(node, dict):
                yield f"trace[{index}]", node


def apply_patches(
    base_entries: list[dict[str, Any]],
    patch_entries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    patches = {entry["entry_id"]: entry for entry in patch_entries}
    missing = sorted(set(patches) - {entry.get("entry_id") for entry in base_entries})
    if missing:
        raise SystemExit(f"patch entries not found in base data: {', '.join(missing)}")

    fixed_entries: list[dict[str, Any]] = []
    diff_rows: list[dict[str, Any]] = []
    for entry in base_entries:
        entry_id = entry.get("entry_id")
        replacement = patches.get(entry_id)
        if replacement is None:
            fixed_entries.append(entry)
            continue
        diff_rows.extend(make_diff_rows(entry, replacement))
        fixed_entries.append(replacement)
    return fixed_entries, diff_rows


def make_diff_rows(old_entry: dict[str, Any], new_entry: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    entry_id = str(new_entry.get("entry_id", old_entry.get("entry_id", "")))
    old_nodes = dict(iter_nodes(old_entry))
    new_nodes = dict(iter_nodes(new_entry))

    for field_path, new_node in new_nodes.items():
        old_node = old_nodes.get(field_path, {})
        if old_node != new_node:
            rows.append(diff_row(entry_id, field_path, old_node, new_node, "rebuilt semantic chain from advisory, original annotation, and source code"))
    for field_path, old_node in old_nodes.items():
        if field_path not in new_nodes:
            rows.append(diff_row(entry_id, field_path, old_node, {}, "removed stale or irrelevant trace node during chain rebuild"))
    return rows


def diff_row(
    entry_id: str,
    field_path: str,
    old_node: dict[str, Any],
    new_node: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "field_path": field_path,
        "old_file": old_node.get("file", ""),
        "old_line": old_node.get("line", ""),
        "old_code": old_node.get("code", ""),
        "old_desc": old_node.get("desc", ""),
        "new_file": new_node.get("file", ""),
        "new_line": new_node.get("line", ""),
        "new_code": new_node.get("code", ""),
        "new_desc": new_node.get("desc", ""),
        "reason": reason,
    }


def write_diff(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DIFF_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--diff-out", type=Path, default=DEFAULT_DIFF)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_entries = read_jsonl(args.base)
    patch_entries = read_jsonl(args.patch)
    fixed_entries, diff_rows = apply_patches(base_entries, patch_entries)
    write_jsonl(args.output, fixed_entries)
    write_diff(args.diff_out, diff_rows)
    print(f"base entries: {len(base_entries)}")
    print(f"patch entries: {len(patch_entries)}")
    print(f"fixed entries: {len(fixed_entries)}")
    print(f"diff rows: {len(diff_rows)}")
    print(f"wrote fixed jsonl: {args.output}")
    print(f"wrote diff csv: {args.diff_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
