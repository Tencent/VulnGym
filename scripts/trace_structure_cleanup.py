#!/usr/bin/env python3
"""Detect and optionally clean structural issues in VulnGym trace chains.

The checker is deliberately conservative: it never reorders trace nodes, and
it compares line numbers only when a trace node is in the same file as the
entry point or critical operation being checked.
"""
from __future__ import annotations

import argparse
import csv
import copy
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "entries.trace_fixed.jsonl"
DEFAULT_LOG_CSV = REPO_ROOT / "reports" / "trace_structure_fix_log.csv"
DEFAULT_LOG_JSONL = REPO_ROOT / "reports" / "trace_structure_fix_log.jsonl"
DEFAULT_REPORT = REPO_ROOT / "reports" / "trace_structure_report.md"

LINE_INT_RE = re.compile(r"^[1-9]\d*$")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
LEADING_DOT_SLASH_RE = re.compile(r"^(?:\./)+")
MULTI_SLASH_RE = re.compile(r"/+")

REQUIRED_ENTRY_FIELDS = {
    "commit",
    "critical_operation",
    "entry_id",
    "entry_point",
    "origin",
    "project",
    "repo_url",
    "report_id",
    "source_link",
    "trace",
    "verify",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_ids",
    "vuln_title",
}
REQUIRED_NODE_FIELDS = {"file", "line", "code"}


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int


@dataclass
class TraceItem:
    node: dict[str, Any]
    index: int
    dropped: bool = False


def normalize_path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = value.replace("\\", "/")
    value = LEADING_DOT_SLASH_RE.sub("", value)
    return MULTI_SLASH_RE.sub("/", value)


def parse_line_span(value: Any) -> LineSpan | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return LineSpan(value, value) if value >= 1 else None
    if isinstance(value, str):
        if LINE_INT_RE.fullmatch(value):
            line = int(value)
            return LineSpan(line, line)
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return LineSpan(start, end)
    return None


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from None
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_no}: row must be a JSON object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def short_path(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def node_desc(node: dict[str, Any]) -> str:
    desc = node.get("desc")
    return desc.strip() if isinstance(desc, str) else ""


def fix_applies(entry: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.mode != "fix":
        return False
    if args.fix_verify == "all":
        return True
    return str(entry.get("verify")) == args.fix_verify


def add_log(
    logs: list[dict[str, Any]],
    stats: Counter[str],
    *,
    entry: dict[str, Any],
    field_path: str,
    issue_type: str,
    action: str,
    reason: str,
    before: Any,
    after: Any,
    details: dict[str, Any] | None = None,
) -> None:
    logs.append(
        {
            "entry_id": entry.get("entry_id"),
            "verify": entry.get("verify"),
            "field_path": field_path,
            "issue_type": issue_type,
            "action": action,
            "reason": reason,
            "before": before,
            "after": after,
            "details": details or {},
        }
    )
    stats[f"issue.{issue_type}"] += 1
    stats[f"action.{action}"] += 1


def validate_node(node: Any, path: str, errors: list[str]) -> None:
    if not isinstance(node, dict):
        errors.append(f"{path}: expected object")
        return
    missing = REQUIRED_NODE_FIELDS - set(node)
    if missing:
        errors.append(f"{path}: missing {sorted(missing)}")
    if not isinstance(node.get("file"), str) or not node.get("file"):
        errors.append(f"{path}.file: expected non-empty string")
    if parse_line_span(node.get("line")) is None:
        errors.append(f"{path}.line: expected positive int or start-end range")
    if not isinstance(node.get("code"), str):
        errors.append(f"{path}.code: expected string")
    if "desc" in node and not isinstance(node["desc"], str):
        errors.append(f"{path}.desc: expected string when present")


def validate_entries(rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    entry_ids: set[str] = set()
    for row_no, entry in enumerate(rows, 1):
        prefix = f"row[{row_no}]"
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        if missing:
            errors.append(f"{prefix}: missing {sorted(missing)}")
        entry_id = entry.get("entry_id")
        if isinstance(entry_id, str):
            if entry_id in entry_ids:
                errors.append(f"{prefix}: duplicate entry_id {entry_id}")
            entry_ids.add(entry_id)
        else:
            errors.append(f"{prefix}.entry_id: expected string")
        if entry.get("verify") not in (0, 1):
            errors.append(f"{prefix}.verify: expected 0 or 1")
        if not isinstance(entry.get("trace"), list):
            errors.append(f"{prefix}.trace: expected list")
            continue
        validate_node(entry.get("entry_point"), f"{prefix}.entry_point", errors)
        validate_node(entry.get("critical_operation"), f"{prefix}.critical_operation", errors)
        for idx, node in enumerate(entry["trace"]):
            validate_node(node, f"{prefix}.trace[{idx}]", errors)
    return errors


def handle_duplicates(
    entry: dict[str, Any],
    items: list[TraceItem],
    logs: list[dict[str, Any]],
    stats: Counter[str],
    args: argparse.Namespace,
) -> None:
    seen: dict[tuple[Any, Any, Any], TraceItem] = {}
    can_fix = fix_applies(entry, args)

    for item in items:
        key = (item.node.get("file"), item.node.get("line"), item.node.get("code"))
        first = seen.get(key)
        if first is None:
            seen[key] = item
            continue

        stats["duplicate_nodes"] += 1
        first_desc = node_desc(first.node)
        item_desc = node_desc(item.node)
        desc_conflict = bool(first_desc and item_desc and first_desc != item_desc)

        if desc_conflict:
            stats["duplicate_desc_conflicts"] += 1

        if can_fix and args.duplicate_policy == "drop-all":
            action = "removed"
            item.dropped = True
            after: Any = None
        elif can_fix and args.duplicate_policy == "safe" and not desc_conflict:
            action = "removed"
            item.dropped = True
            after = None
            if item_desc and not first_desc:
                before_first = copy.deepcopy(first.node)
                first.node["desc"] = item_desc
                stats["duplicate_desc_synced"] += 1
                add_log(
                    logs,
                    stats,
                    entry=entry,
                    field_path=f"trace[{first.index}].desc",
                    issue_type="duplicate_desc_sync",
                    action="updated",
                    reason="first duplicate node had no desc; copied desc from later duplicate",
                    before=before_first,
                    after=copy.deepcopy(first.node),
                    details={"duplicate_index": item.index},
                )
        else:
            action = "manual_review" if args.mode == "check" or can_fix else "skipped_not_fix_target"
            after = copy.deepcopy(item.node)

        add_log(
            logs,
            stats,
            entry=entry,
            field_path=f"trace[{item.index}]",
            issue_type="duplicate_node",
            action=action,
            reason="same {file, line, code} appears earlier in trace",
            before=copy.deepcopy(item.node),
            after=after,
            details={
                "first_index": first.index,
                "duplicate_index": item.index,
                "desc_conflict": desc_conflict,
                "duplicate_policy": args.duplicate_policy,
            },
        )


def compare_order(
    entry: dict[str, Any],
    items: list[TraceItem],
    logs: list[dict[str, Any]],
    stats: Counter[str],
    args: argparse.Namespace,
) -> None:
    entry_node = entry.get("entry_point", {})
    critical_node = entry.get("critical_operation", {})
    entry_file = normalize_path(entry_node.get("file"))
    critical_file = normalize_path(critical_node.get("file"))
    entry_span = parse_line_span(entry_node.get("line"))
    critical_span = parse_line_span(critical_node.get("line"))
    can_fix = fix_applies(entry, args)

    for item in items:
        if item.dropped:
            continue
        trace_file = normalize_path(item.node.get("file"))
        trace_span = parse_line_span(item.node.get("line"))
        if trace_span is None:
            add_log(
                logs,
                stats,
                entry=entry,
                field_path=f"trace[{item.index}].line",
                issue_type="invalid_trace_line",
                action="manual_review",
                reason="trace line is not a positive integer or start-end range",
                before=item.node.get("line"),
                after=item.node.get("line"),
            )
            continue

        if entry_span is not None and trace_file == entry_file:
            if trace_span.end < entry_span.start:
                stats["order_before_entry_whole"] += 1
                action = "removed" if can_fix else ("manual_review" if args.mode == "check" else "skipped_not_fix_target")
                if action == "removed":
                    item.dropped = True
                add_log(
                    logs,
                    stats,
                    entry=entry,
                    field_path=f"trace[{item.index}]",
                    issue_type="order_before_entry",
                    action=action,
                    reason="same-file trace node ends before entry_point starts",
                    before=copy.deepcopy(item.node),
                    after=None if action == "removed" else copy.deepcopy(item.node),
                    details={"entry_point_line": entry_node.get("line"), "trace_line": item.node.get("line")},
                )
                continue
            if trace_span.start < entry_span.start <= trace_span.end:
                stats["order_before_entry_overlap"] += 1
                add_log(
                    logs,
                    stats,
                    entry=entry,
                    field_path=f"trace[{item.index}]",
                    issue_type="order_before_entry_overlap",
                    action="manual_review",
                    reason="same-file trace node overlaps entry_point boundary",
                    before=copy.deepcopy(item.node),
                    after=copy.deepcopy(item.node),
                    details={"entry_point_line": entry_node.get("line"), "trace_line": item.node.get("line")},
                )
        elif args.log_cross_file and entry_span is not None:
            stats["cross_file_entry_comparisons_skipped"] += 1
            add_log(
                logs,
                stats,
                entry=entry,
                field_path=f"trace[{item.index}]",
                issue_type="cross_file_entry_skip",
                action="kept",
                reason="trace node is in a different file from entry_point; line order not compared",
                before=copy.deepcopy(item.node),
                after=copy.deepcopy(item.node),
            )
        elif entry_span is not None:
            stats["cross_file_entry_comparisons_skipped"] += 1

        if item.dropped:
            continue

        if critical_span is not None and trace_file == critical_file:
            if trace_span.start > critical_span.end:
                stats["order_after_critical_whole"] += 1
                removable = can_fix and args.order_policy == "bounds"
                action = "removed" if removable else ("manual_review" if args.mode == "check" or can_fix else "skipped_not_fix_target")
                if action == "removed":
                    item.dropped = True
                add_log(
                    logs,
                    stats,
                    entry=entry,
                    field_path=f"trace[{item.index}]",
                    issue_type="order_after_critical",
                    action=action,
                    reason="same-file trace node starts after critical_operation ends",
                    before=copy.deepcopy(item.node),
                    after=None if action == "removed" else copy.deepcopy(item.node),
                    details={
                        "critical_operation_line": critical_node.get("line"),
                        "trace_line": item.node.get("line"),
                        "order_policy": args.order_policy,
                    },
                )
            elif trace_span.start <= critical_span.end < trace_span.end:
                stats["order_after_critical_overlap"] += 1
                add_log(
                    logs,
                    stats,
                    entry=entry,
                    field_path=f"trace[{item.index}]",
                    issue_type="order_after_critical_overlap",
                    action="manual_review",
                    reason="same-file trace node overlaps critical_operation boundary",
                    before=copy.deepcopy(item.node),
                    after=copy.deepcopy(item.node),
                    details={"critical_operation_line": critical_node.get("line"), "trace_line": item.node.get("line")},
                )
        elif args.log_cross_file and critical_span is not None:
            stats["cross_file_critical_comparisons_skipped"] += 1
            add_log(
                logs,
                stats,
                entry=entry,
                field_path=f"trace[{item.index}]",
                issue_type="cross_file_critical_skip",
                action="kept",
                reason="trace node is in a different file from critical_operation; line order not compared",
                before=copy.deepcopy(item.node),
                after=copy.deepcopy(item.node),
            )
        elif critical_span is not None:
            stats["cross_file_critical_comparisons_skipped"] += 1


def process_entry(
    entry: dict[str, Any],
    logs: list[dict[str, Any]],
    stats: Counter[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    fixed = copy.deepcopy(entry)
    trace = fixed.get("trace")
    if not isinstance(trace, list):
        return fixed

    stats["entries_scanned"] += 1
    stats["trace_nodes_scanned"] += len(trace)
    items = [TraceItem(node=node, index=index) for index, node in enumerate(trace) if isinstance(node, dict)]

    handle_duplicates(fixed, items, logs, stats, args)
    compare_order(fixed, items, logs, stats, args)
    fixed["trace"] = [item.node for item in items if not item.dropped]
    if fixed["trace"] != entry.get("trace"):
        stats["entries_changed"] += 1
    return fixed


def build_report(
    *,
    input_path: Path,
    output_path: Path | None,
    logs: list[dict[str, Any]],
    stats: Counter[str],
    input_errors: list[str],
    output_errors: list[str],
    changed_entries: list[str],
    args: argparse.Namespace,
) -> str:
    issue_counts = {k.removeprefix("issue."): v for k, v in sorted(stats.items()) if k.startswith("issue.")}
    action_counts = {k.removeprefix("action."): v for k, v in sorted(stats.items()) if k.startswith("action.")}
    manual_entries = sorted({log["entry_id"] for log in logs if log["action"] == "manual_review"})

    lines = [
        "# Trace structure cleanup report",
        "",
        "## Config",
        "",
        f"- mode: `{args.mode}`",
        f"- input: `{short_path(input_path)}`",
        f"- output: `{short_path(output_path) if output_path else ''}`",
        f"- fix_verify: `{args.fix_verify}`",
        f"- order_policy: `{args.order_policy}`",
        f"- duplicate_policy: `{args.duplicate_policy}`",
        f"- log_cross_file: `{args.log_cross_file}`",
        "",
        "## Totals",
        "",
        f"- entries scanned: {stats['entries_scanned']}",
        f"- trace nodes scanned: {stats['trace_nodes_scanned']}",
        f"- changed entries: {len(changed_entries)}",
        f"- log events: {len(logs)}",
        f"- manual-review entries: {len(manual_entries)}",
        f"- input schema errors: {len(input_errors)}",
        f"- output schema errors: {len(output_errors)}",
        "",
        "## Issue Counts",
        "",
    ]
    lines.extend([f"- {name}: {count}" for name, count in issue_counts.items()] or ["- none"])
    lines.extend(["", "## Action Counts", ""])
    lines.extend([f"- {name}: {count}" for name, count in action_counts.items()] or ["- none"])
    lines.extend(["", "## Changed Entries", ""])
    lines.extend([f"- {entry_id}" for entry_id in changed_entries] or ["- none"])
    lines.extend(["", "## Manual Review Entries", ""])
    lines.extend([f"- {entry_id}" for entry_id in manual_entries] or ["- none"])

    if input_errors or output_errors:
        lines.extend(["", "## Schema Errors", ""])
        for err in input_errors[:20]:
            lines.append(f"- input: {err}")
        for err in output_errors[:20]:
            lines.append(f"- output: {err}")
    return "\n".join(lines) + "\n"


def write_logs(csv_path: Path, jsonl_path: Path, logs: list[dict[str, Any]]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "entry_id",
        "verify",
        "field_path",
        "issue_type",
        "action",
        "reason",
        "before",
        "after",
        "details",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for log in logs:
            row = dict(log)
            row["before"] = json_text(row.get("before"))
            row["after"] = json_text(row.get("after"))
            row["details"] = json_text(row.get("details"))
            writer.writerow({field: row.get(field, "") for field in fields})
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as handle:
        for log in logs:
            handle.write(json_text(log))
            handle.write("\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect and optionally clean VulnGym trace structural issues.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--log-csv", type=Path, default=DEFAULT_LOG_CSV)
    parser.add_argument("--log-jsonl", type=Path, default=DEFAULT_LOG_JSONL)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--mode", choices=("check", "fix"), default="check")
    parser.add_argument("--fix-verify", choices=("0", "1", "all"), default="0")
    parser.add_argument(
        "--order-policy",
        choices=("entry-before-only", "bounds"),
        default="entry-before-only",
        help="fix mode policy for same-file order issues",
    )
    parser.add_argument(
        "--duplicate-policy",
        choices=("safe", "drop-all", "none"),
        default="safe",
        help="fix mode policy for duplicate trace nodes",
    )
    parser.add_argument(
        "--log-cross-file",
        action="store_true",
        help="write per-node logs for skipped cross-file comparisons",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rows = load_jsonl(args.input)
    input_errors = validate_entries(rows)

    logs: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    fixed_rows = [process_entry(entry, logs, stats, args) for entry in rows]
    output_errors = validate_entries(fixed_rows)
    changed_entries = [
        after.get("entry_id", "")
        for before, after in zip(rows, fixed_rows)
        if before.get("trace") != after.get("trace")
    ]

    if args.mode == "fix":
        write_jsonl(args.output, fixed_rows)
    write_logs(args.log_csv, args.log_jsonl, logs)

    report = build_report(
        input_path=args.input,
        output_path=args.output if args.mode == "fix" else None,
        logs=logs,
        stats=stats,
        input_errors=input_errors,
        output_errors=output_errors,
        changed_entries=changed_entries,
        args=args,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8", newline="\n")

    print(report.rstrip())
    if input_errors or output_errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
