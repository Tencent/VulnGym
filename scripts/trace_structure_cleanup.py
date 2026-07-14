#!/usr/bin/env python3
"""Detect and conservatively repair structural problems in VulnGym traces."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path


LOG_FIELDS = (
    "entry_id", "field_path", "issue", "action", "reason", "old_node",
    "new_node", "reference_path", "reference_line",
)


def line_span(value: object) -> tuple[int, int]:
    if type(value) is int and value > 0:
        return value, value
    if isinstance(value, str):
        match = re.fullmatch(r"([1-9]\d*)-([1-9]\d*)", value)
        if match and int(match[1]) <= int(match[2]):
            return int(match[1]), int(match[2])
    raise ValueError(f"invalid line value: {value!r}")


def node_key(node: dict) -> tuple[object, object, object]:
    return node.get("file"), node.get("line"), node.get("code")


def event(entry: dict, index: int, issue: str, action: str, reason: str,
          old_node: dict, new_node: dict | None = None,
          reference_path: str = "", reference_line: object = "") -> dict:
    return {
        "entry_id": entry.get("entry_id", ""),
        "field_path": f"trace[{index}]",
        "issue": issue,
        "action": action,
        "reason": reason,
        "old_node": json.dumps(old_node, ensure_ascii=False, sort_keys=True),
        "new_node": "" if new_node is None else json.dumps(new_node, ensure_ascii=False, sort_keys=True),
        "reference_path": reference_path,
        "reference_line": reference_line,
    }


def process_entry(entry: dict, mode: str, fix_verify: str) -> tuple[dict, list[dict], Counter]:
    trace = entry.get("trace", [])
    if not isinstance(trace, list):
        raise ValueError(f"{entry.get('entry_id')}: trace must be a list")
    can_fix = mode == "fix" and (fix_verify == "all" or str(entry.get("verify")) == fix_verify)
    logs: list[dict] = []
    stats = Counter(trace_nodes=len(trace))
    kept: list[dict] = []
    seen: dict[tuple[object, object, object], dict] = {}
    entry_point = entry.get("entry_point", {})
    critical = entry.get("critical_operation", {})

    for index, node in enumerate(trace):
        if not isinstance(node, dict):
            raise ValueError(f"{entry.get('entry_id')}: trace[{index}] must be an object")
        duplicate = seen.get(node_key(node))
        if duplicate is not None:
            stats["duplicates"] += 1
            same_desc = duplicate.get("desc") == node.get("desc")
            if can_fix and same_desc:
                logs.append(event(entry, index, "duplicate", "removed", "identical trace node and description", node))
                stats["removed_duplicates"] += 1
                continue
            reason = "duplicate location has a conflicting description" if not same_desc else "conservative mode"
            logs.append(event(entry, index, "duplicate", "review", reason, node, node))
            stats["review"] += 1
        else:
            seen[node_key(node)] = node

        out_of_bounds: tuple[str, str, dict] | None = None
        node_file = node.get("file")
        try:
            node_start, node_end = line_span(node.get("line"))
            if node_file == entry_point.get("file"):
                ep_start, _ = line_span(entry_point.get("line"))
                if node_end < ep_start:
                    out_of_bounds = ("before_entry", "trace node ends before entry point starts", entry_point)
            if out_of_bounds is None and node_file == critical.get("file"):
                _, critical_end = line_span(critical.get("line"))
                if node_start > critical_end:
                    out_of_bounds = ("after_critical", "trace node starts after critical operation ends", critical)
        except ValueError as exc:
            logs.append(event(entry, index, "invalid_line", "review", str(exc), node, node))
            stats["review"] += 1

        if out_of_bounds:
            issue, reason, reference = out_of_bounds
            stats[issue] += 1
            if can_fix:
                logs.append(event(entry, index, issue, "removed", reason, node,
                                  reference_path=reference.get("file", ""),
                                  reference_line=reference.get("line", "")))
                stats["removed_out_of_bounds"] += 1
                continue
            logs.append(event(entry, index, issue, "review", reason, node, node,
                              reference.get("file", ""), reference.get("line", "")))
            stats["review"] += 1
        elif node_file not in {entry_point.get("file"), critical.get("file")}:
            stats["cross_file_skipped"] += 1

        kept.append(node)

    result = dict(entry)
    result["trace"] = kept
    if kept != trace:
        stats["changed_entries"] = 1
    return result, logs, stats


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number}: expected object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_log(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOG_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_report(path: Path, mode: str, stats: Counter, log_count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Trace structure report", "", f"- Mode: `{mode}`",
        f"- Entries scanned: {stats['entries']}",
        f"- Trace nodes scanned: {stats['trace_nodes']}",
        f"- Duplicate candidates: {stats['duplicates']}",
        f"- Before-entry anomalies: {stats['before_entry']}",
        f"- After-critical anomalies: {stats['after_critical']}",
        f"- Cross-file nodes not compared: {stats['cross_file_skipped']}",
        f"- Removed duplicate nodes: {stats['removed_duplicates']}",
        f"- Removed out-of-bounds nodes: {stats['removed_out_of_bounds']}",
        f"- Entries changed: {stats['changed_entries']}",
        f"- Human-review events: {stats['review']}",
        f"- Log rows: {log_count}", "",
        "Cross-file nodes retain their original order and are never compared by line number.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/entries.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("data/entries.trace_fixed.jsonl"))
    parser.add_argument("--log", type=Path, default=Path("reports/trace_fix_log.csv"))
    parser.add_argument("--report", type=Path, default=Path("reports/trace_structure_report.md"))
    parser.add_argument("--mode", choices=("check", "fix"), default="check")
    parser.add_argument("--fix-verify", choices=("0", "1", "all"), default="0")
    args = parser.parse_args(argv)

    output, logs, totals = [], [], Counter()
    rows = load_jsonl(args.input)
    for entry in rows:
        fixed, entry_logs, stats = process_entry(entry, args.mode, args.fix_verify)
        output.append(fixed)
        logs.extend(entry_logs)
        totals.update(stats)
    totals["entries"] = len(rows)
    write_jsonl(args.output, output)
    write_log(args.log, logs)
    write_report(args.report, args.mode, totals, len(logs))
    print(f"scanned={len(rows)} changed={totals['changed_entries']} logs={len(logs)} review={totals['review']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
