#!/usr/bin/env python3
"""Apply the curated rebuild entries to data/entries.jsonl.

The fixed entries live in data/entries.fixed.jsonl. This script copies the
five target objects from that snapshot into the canonical data/entries.jsonl,
then refreshes fix_diff.csv and examples/report.json. It validates every JSONL
row while reading so malformed rows cannot be silently skipped.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRIES_PATH = REPO_ROOT / "data" / "entries.jsonl"
FIXED_PATH = REPO_ROOT / "data" / "entries.fixed.jsonl"
OUT_DIFF = REPO_ROOT / "fix_diff.csv"
OUT_REPORT = REPO_ROOT / "examples" / "report.json"

TARGETED = ("entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [row for row, _raw in load_jsonl_with_raw(path)]


def load_jsonl_with_raw(path: Path) -> list[tuple[dict[str, Any], str]]:
    rows: list[tuple[dict[str, Any], str]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            if not raw.strip():
                raise ValueError(f"{path}: blank JSONL row at line {line_no}")
            try:
                rows.append((json.loads(raw), raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON at line {line_no}: {exc}") from exc
    return rows


def render_location(value: Any) -> str:
    if isinstance(value, list):
        return f"[{len(value)} trace node(s)]"
    if isinstance(value, dict):
        return f"{value.get('file')}::{value.get('line')}"
    return str(value)


def main() -> int:
    if not ENTRIES_PATH.is_file():
        print(f"entries file not found: {ENTRIES_PATH}", file=sys.stderr)
        return 1
    if not FIXED_PATH.is_file():
        print(f"fixed snapshot not found: {FIXED_PATH}", file=sys.stderr)
        return 1

    try:
        entries = load_jsonl_with_raw(ENTRIES_PATH)
        fixed_rows = load_jsonl(FIXED_PATH)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    fixed_by_id = {row.get("entry_id"): row for row in fixed_rows}
    missing = [entry_id for entry_id in TARGETED if entry_id not in fixed_by_id]
    if missing:
        print(f"fixed snapshot missing target entries: {missing}", file=sys.stderr)
        return 1

    targeted = set(TARGETED)
    rewritten = 0
    diff_rows: list[dict[str, Any]] = []
    fixes_report: list[dict[str, Any]] = []
    out_lines: list[str] = []

    for entry, raw in entries:
        entry_id = entry.get("entry_id")
        if entry_id not in targeted:
            out_lines.append(raw if raw.endswith("\n") else raw + "\n")
            continue

        patch = fixed_by_id[entry_id]
        updated = dict(entry)
        for field in ("entry_point", "critical_operation", "trace"):
            after = patch[field]
            updated[field] = after
            diff_rows.append(
                {
                    "entry_id": entry_id,
                    "field": field,
                    "before": "(replaced)",
                    "after": render_location(after),
                    "verify": patch.get("verify", ""),
                }
            )

        updated["verify"] = patch.get("verify", entry.get("verify"))
        out_lines.append(json.dumps(updated, ensure_ascii=False, separators=(",", ":")) + "\n")
        rewritten += 1
        fixes_report.append(
            {
                "entry_id": entry_id,
                "commit": updated.get("commit"),
                "report_id": updated.get("report_id"),
                "verify": updated.get("verify"),
                "node_counts": {
                    "trace_nodes": len(updated.get("trace", [])),
                    "entry_point_file": updated["entry_point"]["file"],
                    "entry_point_line": updated["entry_point"]["line"],
                    "critical_operation_file": updated["critical_operation"]["file"],
                    "critical_operation_line": updated["critical_operation"]["line"],
                },
            }
        )

    if rewritten != len(TARGETED):
        found = sorted(row.get("entry_id") for row, _raw in entries if row.get("entry_id") in targeted)
        print(f"expected {len(TARGETED)} rewrites, got {rewritten}: {found}", file=sys.stderr)
        return 1

    with ENTRIES_PATH.open("w", encoding="utf-8", newline="\n") as dst:
        dst.writelines(out_lines)

    with OUT_DIFF.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["entry_id", "field", "before", "after", "verify"]
        )
        writer.writeheader()
        writer.writerows(diff_rows)

    OUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    with OUT_REPORT.open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "generated_by": "scripts/apply_entry_patches.py",
                "schema": "VulnGym entries.jsonl (SCHEMA.md)",
                "source_snapshot": str(FIXED_PATH.relative_to(REPO_ROOT)),
                "fixes": fixes_report,
            },
            fh,
            ensure_ascii=False,
            indent=2,
        )
        fh.write("\n")

    print(f"rewrote {rewritten} entries")
    print(f"diff csv -> {OUT_DIFF}")
    print(f"report  -> {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
