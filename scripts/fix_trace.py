#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any


FOCUS_ENTRY_IDS = ("entry-00103", "entry-00320", "entry-00511", "entry-00185")
LOG_FIELDS = (
    "entry_id",
    "trace_index",
    "field_path",
    "action",
    "reason",
    "before",
    "after",
    "mode",
    "need_manual_review",
)


class ValidationError(ValueError):
    pass


def parse_line_range(line: Any) -> tuple[int, int]:
    """Normalize a positive int or a 'start-end' string into (start, end)."""
    if isinstance(line, bool):
        raise ValidationError(f"invalid bool line: {line!r}")
    if isinstance(line, int):
        if line < 1:
            raise ValidationError(f"line must be >= 1: {line!r}")
        return line, line
    if isinstance(line, str):
        match = re.fullmatch(r"([1-9]\d*)-([1-9]\d*)", line)
        if not match:
            raise ValidationError(f"invalid line range: {line!r}")
        start, end = int(match.group(1)), int(match.group(2))
        if start > end:
            raise ValidationError(f"line range start > end: {line!r}")
        return start, end
    raise ValidationError(f"line must be int or 'start-end': {line!r}")


def validate_node(node: Any, path: str) -> None:
    if not isinstance(node, dict):
        raise ValidationError(f"{path} must be an object")
    for field in ("file", "line", "code"):
        if field not in node:
            raise ValidationError(f"{path}.{field} is required")
    if not isinstance(node["file"], str):
        raise ValidationError(f"{path}.file must be a string")
    if not isinstance(node["code"], str):
        raise ValidationError(f"{path}.code must be a string")
    parse_line_range(node["line"])


def validate_entry(entry: Any, line_no: int) -> None:
    if not isinstance(entry, dict):
        raise ValidationError(f"line {line_no}: entry must be an object")
    entry_id = entry.get("entry_id", f"line {line_no}")
    verify = entry.get("verify")
    if type(verify) is not int or verify not in (0, 1):
        raise ValidationError(f"{entry_id}.verify must be 0 or 1")
    validate_node(entry.get("entry_point"), f"{entry_id}.entry_point")
    validate_node(entry.get("critical_operation"), f"{entry_id}.critical_operation")
    trace = entry.get("trace")
    if not isinstance(trace, list):
        raise ValidationError(f"{entry_id}.trace must be a list")
    for index, node in enumerate(trace):
        validate_node(node, f"{entry_id}.trace[{index}]")


def load_entries(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            entry = json.loads(line)
            validate_entry(entry, line_no)
            entries.append(entry)
    return entries


def node_identity(node: dict[str, Any]) -> tuple[str, Any, str]:
    return node["file"], node["line"], node["code"]


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def make_log(
    entry_id: str,
    trace_index: int,
    action: str,
    reason: str,
    before: Any,
    after: Any,
    mode: str,
    need_manual_review: bool = False,
) -> dict[str, str]:
    return {
        "entry_id": entry_id,
        "trace_index": str(trace_index),
        "field_path": f"trace[{trace_index}]",
        "action": action,
        "reason": reason,
        "before": compact_json(before),
        "after": compact_json(after) if after is not None else "",
        "mode": mode,
        "need_manual_review": "true" if need_manual_review else "false",
    }


def empty_focus_stats() -> dict[str, dict[str, int | bool]]:
    return {
        entry_id: {
            "total_trace_nodes": 0,
            "duplicate_trace_nodes": 0,
            "duplicate_trace_nodes_removed": 0,
            "before_entry_point_nodes": 0,
            "after_critical_operation_nodes": 0,
            "order_anomaly_nodes_removed": 0,
            "cross_file_trace_nodes_skipped": 0,
            "need_manual_review": False,
        }
        for entry_id in FOCUS_ENTRY_IDS
    }


def new_report() -> dict[str, Any]:
    return {
        "total_entries": 0,
        "total_trace_nodes": 0,
        "duplicate_trace_nodes": 0,
        "duplicate_trace_nodes_removed": 0,
        "before_entry_point_nodes": 0,
        "after_critical_operation_nodes": 0,
        "order_anomaly_nodes_removed": 0,
        "cross_file_trace_nodes_skipped": 0,
        "manual_review_entries": [],
        "focus_entries": empty_focus_stats(),
    }


def inc_focus(report: dict[str, Any], entry_id: str, key: str, amount: int = 1) -> None:
    if entry_id in report["focus_entries"]:
        report["focus_entries"][entry_id][key] += amount


def mark_manual_review(
    report: dict[str, Any], manual_review_entries: set[str], entry_id: str
) -> None:
    manual_review_entries.add(entry_id)
    if entry_id in report["focus_entries"]:
        report["focus_entries"][entry_id]["need_manual_review"] = True


def analyze_entry(
    entry: dict[str, Any],
    mode: str,
    report: dict[str, Any],
    manual_review_entries: set[str],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    entry_id = entry.get("entry_id", "")
    fixed_entry = deepcopy(entry)
    logs: list[dict[str, str]] = []
    trace = entry["trace"]

    entry_start, _ = parse_line_range(entry["entry_point"]["line"])
    critical_start, critical_end = parse_line_range(entry["critical_operation"]["line"])
    entry_file = entry["entry_point"]["file"]
    critical_file = entry["critical_operation"]["file"]

    report["total_trace_nodes"] += len(trace)
    inc_focus(report, entry_id, "total_trace_nodes", len(trace))

    seen: dict[tuple[str, Any, str], dict[str, Any]] = {}
    indexes_to_remove: set[int] = set()
    order_anomaly_indexes: set[int] = set()

    for index, node in enumerate(trace):
        identity = node_identity(node)
        if identity in seen:
            first_node = seen[identity]["node"]
            need_manual_review = first_node.get("desc") != node.get("desc")
            action = "remove" if mode == "fix" else "would_remove"
            report["duplicate_trace_nodes"] += 1
            inc_focus(report, entry_id, "duplicate_trace_nodes")
            if mode == "fix":
                report["duplicate_trace_nodes_removed"] += 1
                inc_focus(report, entry_id, "duplicate_trace_nodes_removed")
                indexes_to_remove.add(index)
            if need_manual_review:
                mark_manual_review(report, manual_review_entries, entry_id)
            logs.append(
                make_log(
                    entry_id,
                    index,
                    action,
                    "duplicate_trace_node",
                    node,
                    None if mode == "fix" else node,
                    mode,
                    need_manual_review,
                )
            )
        else:
            seen[identity] = {"index": index, "node": node}

        trace_start, trace_end = parse_line_range(node["line"])
        compared = False
        if node["file"] == entry_file:
            compared = True
            if trace_end < entry_start:
                report["before_entry_point_nodes"] += 1
                inc_focus(report, entry_id, "before_entry_point_nodes")
                order_anomaly_indexes.add(index)
                logs.append(
                    make_log(
                        entry_id,
                        index,
                        "remove" if mode == "fix" else "would_remove",
                        "trace_before_entry_point",
                        node,
                        None if mode == "fix" else node,
                        mode,
                    )
                )
        if node["file"] == critical_file:
            compared = True
            if trace_start > critical_end:
                report["after_critical_operation_nodes"] += 1
                inc_focus(report, entry_id, "after_critical_operation_nodes")
                order_anomaly_indexes.add(index)
                logs.append(
                    make_log(
                        entry_id,
                        index,
                        "remove" if mode == "fix" else "would_remove",
                        "trace_after_critical_operation",
                        node,
                        None if mode == "fix" else node,
                        mode,
                    )
                )
        if not compared:
            report["cross_file_trace_nodes_skipped"] += 1
            inc_focus(report, entry_id, "cross_file_trace_nodes_skipped")
            logs.append(
                make_log(
                    entry_id,
                    index,
                    "skip",
                    "cross_file_skip_line_compare",
                    node,
                    node,
                    mode,
                )
            )

    if mode == "fix":
        indexes_to_remove.update(order_anomaly_indexes)
        report["order_anomaly_nodes_removed"] += len(order_anomaly_indexes)
        inc_focus(report, entry_id, "order_anomaly_nodes_removed", len(order_anomaly_indexes))
        fixed_entry["trace"] = [
            node for index, node in enumerate(fixed_entry["trace"]) if index not in indexes_to_remove
        ]

    return fixed_entry, logs


def write_jsonl(entries: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for line_no, entry in enumerate(entries, 1):
            validate_entry(entry, line_no)
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(logs: list[dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOG_FIELDS)
        writer.writeheader()
        writer.writerows(logs)


def write_report(report: dict[str, Any], path: Path, manual_review_entries: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    report["manual_review_entries"] = sorted(manual_review_entries)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect and optionally fix deterministic trace anomalies in entries.jsonl."
    )
    parser.add_argument("--input", default="data/entries.jsonl", help="input JSONL path")
    parser.add_argument(
        "--output", default="outputs/entries.trace_fixed.jsonl", help="output JSONL path"
    )
    parser.add_argument("--log", default="outputs/trace_fix_log.csv", help="CSV log path")
    parser.add_argument(
        "--report", default="outputs/trace_fix_report.json", help="JSON report path"
    )
    parser.add_argument("--mode", choices=("check", "fix"), default="check")
    return parser.parse_args()


def validate_output_paths(input_path: Path, output_paths: dict[str, Path]) -> None:
    input_resolved = input_path.resolve()
    seen: dict[Path, str] = {}
    for label, path in output_paths.items():
        resolved = path.resolve()
        if resolved == input_resolved:
            raise ValidationError(f"--{label} must not overwrite --input: {path}")
        if resolved in seen:
            raise ValidationError(
                f"--{label} and --{seen[resolved]} must use different paths: {path}"
            )
        seen[resolved] = label


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_paths = {
        "output": Path(args.output),
        "log": Path(args.log),
        "report": Path(args.report),
    }
    validate_output_paths(input_path, output_paths)
    entries = load_entries(input_path)
    report = new_report()
    report["total_entries"] = len(entries)
    manual_review_entries: set[str] = set()
    fixed_entries: list[dict[str, Any]] = []
    logs: list[dict[str, str]] = []

    for entry in entries:
        fixed_entry, entry_logs = analyze_entry(entry, args.mode, report, manual_review_entries)
        fixed_entries.append(fixed_entry)
        logs.extend(entry_logs)

    write_jsonl(fixed_entries, output_paths["output"])
    write_csv(logs, output_paths["log"])
    write_report(report, output_paths["report"], manual_review_entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
