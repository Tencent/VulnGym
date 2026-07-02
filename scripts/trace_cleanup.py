#!/usr/bin/env python3
"""Detect and optionally clean structural trace-chain issues in entries.jsonl.

The script is intentionally conservative:

* It never reorders trace nodes.
* It only compares line numbers when a trace node is in the same file as the
  entry point or critical operation being checked.
* In fix mode, it removes duplicate trace nodes and clearly pre-entry nodes
  for the selected verify bucket by default. Same-file nodes after the critical
  operation are reported for review unless --order-fix-policy bounds is used.
"""
from __future__ import annotations

import argparse
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
DEFAULT_LOG = REPO_ROOT / "reports" / "trace_fix_log.json"
DEFAULT_REPORT_JSON = REPO_ROOT / "reports" / "trace_fix_report.json"
DEFAULT_REPORT_MD = REPO_ROOT / "reports" / "trace_fix_report.md"

LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
NUMERIC_LINE_RE = re.compile(r"^[1-9]\d*$")
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
    original_index: int
    dropped: bool = False


def normalize_path(path: Any) -> str:
    if not isinstance(path, str):
        return ""
    path = path.replace("\\", "/")
    path = LEADING_DOT_SLASH_RE.sub("", path)
    return MULTI_SLASH_RE.sub("/", path)


def parse_line_span(value: Any) -> LineSpan | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return LineSpan(value, value) if value >= 1 else None
    if isinstance(value, str):
        if NUMERIC_LINE_RE.fullmatch(value):
            line = int(value)
            return LineSpan(line, line)
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return LineSpan(start, end)
    return None


def span_to_dict(span: LineSpan | None) -> dict[str, int] | None:
    if span is None:
        return None
    return {"start": span.start, "end": span.end}


def desc_value(node: dict[str, Any]) -> str:
    value = node.get("desc")
    return value.strip() if isinstance(value, str) else ""


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


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def display_path(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def add_log(
    logs: list[dict[str, Any]],
    stats: Counter[str],
    *,
    entry: dict[str, Any],
    event_type: str,
    field_path: str,
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
            "event_type": event_type,
            "action": action,
            "reason": reason,
            "before": before,
            "after": after,
            "details": details or {},
        }
    )
    stats[f"event.{event_type}"] += 1
    stats[f"action.{action}"] += 1


def entry_is_fix_target(entry: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.mode != "fix":
        return False
    if args.fix_verify == "all":
        return True
    return str(entry.get("verify")) == args.fix_verify


def candidate_action(*, can_fix: bool, mode: str, fixed_action: str, check_action: str) -> str:
    if can_fix:
        return fixed_action
    if mode == "check":
        return check_action
    return "skipped_not_fix_target"


def handle_duplicate_nodes(
    *,
    entry: dict[str, Any],
    items: list[TraceItem],
    logs: list[dict[str, Any]],
    stats: Counter[str],
    can_fix: bool,
    args: argparse.Namespace,
) -> None:
    seen: dict[tuple[Any, Any, Any], TraceItem] = {}

    for item in items:
        node = item.node
        key = (node.get("file"), node.get("line"), node.get("code"))
        first = seen.get(key)
        if first is None:
            seen[key] = item
            continue

        stats["duplicate_nodes"] += 1
        first_desc = desc_value(first.node)
        duplicate_desc = desc_value(node)

        desc_status = "same_or_absent"
        if duplicate_desc and not first_desc:
            desc_status = "sync_first_from_duplicate"
            stats["duplicate_desc_sync_needed"] += 1
            before_first = copy.deepcopy(first.node)
            after_first = copy.deepcopy(first.node)
            after_first["desc"] = duplicate_desc
            if can_fix and args.duplicate_fix_policy != "none":
                first.node["desc"] = duplicate_desc
            if args.duplicate_fix_policy == "none":
                action = "manual_review"
                after_sync = before_first
            else:
                action = candidate_action(
                    can_fix=can_fix,
                    mode=args.mode,
                    fixed_action="desc_synced",
                    check_action="would_sync_desc",
                )
                after_sync = after_first
            add_log(
                logs,
                stats,
                entry=entry,
                event_type="duplicate_desc_sync",
                field_path=f"trace[{first.original_index}].desc",
                action=action,
                reason=(
                    "duplicate trace node has the same file/line/code and a "
                    "non-empty desc while the first occurrence has no desc"
                ),
                before=before_first,
                after=after_sync,
                details={
                    "duplicate_path": f"trace[{item.original_index}]",
                    "kept_path": f"trace[{first.original_index}]",
                    "duplicate_fix_policy": args.duplicate_fix_policy,
                },
            )
        elif first_desc and duplicate_desc and first_desc != duplicate_desc:
            desc_status = "conflict_review"
            stats["duplicate_desc_conflicts"] += 1
            add_log(
                logs,
                stats,
                entry=entry,
                event_type="duplicate_desc_conflict",
                field_path=f"trace[{item.original_index}].desc",
                action="manual_review",
                reason=(
                    "duplicate trace node has the same file/line/code but a "
                    "different desc from the first occurrence"
                ),
                before=node,
                after=first.node,
                details={
                    "duplicate_path": f"trace[{item.original_index}]",
                    "kept_path": f"trace[{first.original_index}]",
                },
            )

        policy = args.duplicate_fix_policy
        should_drop = False
        if policy == "drop-all":
            should_drop = can_fix
        elif policy == "safe":
            should_drop = can_fix and desc_status != "conflict_review"

        if should_drop:
            item.dropped = True
            action = "removed"
            after = None
            reason = (
                "duplicate trace node with identical file, line, and code; "
                "the first occurrence is retained"
            )
        elif desc_status == "conflict_review" and policy == "safe":
            action = "manual_review"
            after = node
            reason = (
                "duplicate trace node has identical file, line, and code but a "
                "different desc; kept by the safe duplicate policy for manual review"
            )
        elif policy == "none":
            action = "manual_review"
            after = node
            reason = "duplicate trace node detected; kept because duplicate fixing is disabled"
        else:
            action = candidate_action(
                can_fix=can_fix,
                mode=args.mode,
                fixed_action="removed",
                check_action="would_remove",
            )
            after = node
            reason = (
                "duplicate trace node with identical file, line, and code; "
                "the first occurrence would be retained in fix mode"
            )
        add_log(
            logs,
            stats,
            entry=entry,
            event_type="duplicate_node",
            field_path=f"trace[{item.original_index}]",
            action=action,
            reason=reason,
            before=node,
            after=after,
            details={
                "kept_path": f"trace[{first.original_index}]",
                "desc_status": desc_status,
                "duplicate_fix_policy": policy,
            },
        )


def compare_trace_bounds(
    *,
    entry: dict[str, Any],
    item: TraceItem,
    logs: list[dict[str, Any]],
    stats: Counter[str],
    can_fix: bool,
    args: argparse.Namespace,
) -> None:
    node = item.node
    trace_span = parse_line_span(node.get("line"))
    entry_span = parse_line_span(entry.get("entry_point", {}).get("line"))
    critical_span = parse_line_span(entry.get("critical_operation", {}).get("line"))

    trace_path = f"trace[{item.original_index}]"
    trace_file = normalize_path(node.get("file"))
    entry_file = normalize_path(entry.get("entry_point", {}).get("file"))
    critical_file = normalize_path(entry.get("critical_operation", {}).get("file"))

    if trace_span is None:
        stats["invalid_trace_lines"] += 1
        add_log(
            logs,
            stats,
            entry=entry,
            event_type="invalid_trace_line",
            field_path=f"{trace_path}.line",
            action="manual_review",
            reason="trace node line is neither a positive integer nor a valid start-end range",
            before=node.get("line"),
            after=node.get("line"),
            details={"trace_node": node},
        )
        return

    if entry_span is None:
        stats["invalid_entry_point_lines"] += 1
    elif trace_file == entry_file:
        if trace_span.end < entry_span.start:
            stats["order_before_entry_whole"] += 1
            policy_drops = args.order_fix_policy in {"entry-before-only", "bounds"}
            should_drop = can_fix and policy_drops
            if should_drop:
                item.dropped = True
            action = (
                candidate_action(
                    can_fix=can_fix,
                    mode=args.mode,
                    fixed_action="removed",
                    check_action="would_remove",
                )
                if policy_drops
                else "manual_review"
            )
            add_log(
                logs,
                stats,
                entry=entry,
                event_type="order_before_entry",
                field_path=trace_path,
                action=action,
                reason="same-file trace node is wholly before entry_point",
                before=node,
                after=None if should_drop else node,
                details={
                    "trace_span": span_to_dict(trace_span),
                    "entry_point_span": span_to_dict(entry_span),
                    "classification": "whole_before_entry",
                },
            )
        elif trace_span.start < entry_span.start:
            stats["order_before_entry_overlap"] += 1
            add_log(
                logs,
                stats,
                entry=entry,
                event_type="order_before_entry_overlap",
                field_path=trace_path,
                action="manual_review",
                reason="same-file trace range starts before entry_point but overlaps the entry boundary",
                before=node,
                after=node,
                details={
                    "trace_span": span_to_dict(trace_span),
                    "entry_point_span": span_to_dict(entry_span),
                    "classification": "boundary_overlap",
                },
            )
    elif args.log_cross_file:
        stats["cross_file_entry_comparisons_skipped"] += 1
        add_log(
            logs,
            stats,
            entry=entry,
            event_type="cross_file_skip",
            field_path=trace_path,
            action="kept_cross_file",
            reason="cross-file trace node is not compared with entry_point line numbers",
            before=node,
            after=node,
            details={
                "comparison": "trace_vs_entry_point",
                "trace_file": node.get("file"),
                "entry_point_file": entry.get("entry_point", {}).get("file"),
            },
        )

    if critical_span is None:
        stats["invalid_critical_operation_lines"] += 1
    elif trace_file == critical_file:
        if trace_span.start > critical_span.end:
            stats["order_after_critical_whole"] += 1
            policy_drops = args.order_fix_policy == "bounds"
            should_drop = can_fix and policy_drops
            if should_drop:
                item.dropped = True
            action = (
                candidate_action(
                    can_fix=can_fix,
                    mode=args.mode,
                    fixed_action="removed",
                    check_action="would_remove",
                )
                if policy_drops
                else "manual_review"
            )
            add_log(
                logs,
                stats,
                entry=entry,
                event_type="order_after_critical",
                field_path=trace_path,
                action=action,
                reason=(
                    "same-file trace node is wholly after critical_operation; "
                    "kept for review unless --order-fix-policy bounds is used"
                ),
                before=node,
                after=None if should_drop else node,
                details={
                    "trace_span": span_to_dict(trace_span),
                    "critical_operation_span": span_to_dict(critical_span),
                    "classification": "whole_after_critical",
                },
            )
        elif trace_span.end > critical_span.end:
            stats["order_after_critical_overlap"] += 1
            add_log(
                logs,
                stats,
                entry=entry,
                event_type="order_after_critical_overlap",
                field_path=trace_path,
                action="manual_review",
                reason=(
                    "same-file trace range extends beyond critical_operation "
                    "but overlaps the critical boundary"
                ),
                before=node,
                after=node,
                details={
                    "trace_span": span_to_dict(trace_span),
                    "critical_operation_span": span_to_dict(critical_span),
                    "classification": "boundary_overlap",
                },
            )
    elif args.log_cross_file:
        stats["cross_file_critical_comparisons_skipped"] += 1
        add_log(
            logs,
            stats,
            entry=entry,
            event_type="cross_file_skip",
            field_path=trace_path,
            action="kept_cross_file",
            reason="cross-file trace node is not compared with critical_operation line numbers",
            before=node,
            after=node,
            details={
                "comparison": "trace_vs_critical_operation",
                "trace_file": node.get("file"),
                "critical_operation_file": entry.get("critical_operation", {}).get("file"),
            },
        )


def process_entry(
    entry: dict[str, Any],
    logs: list[dict[str, Any]],
    stats: Counter[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    can_fix = entry_is_fix_target(entry, args)
    fixed_entry = copy.deepcopy(entry)
    original_trace = fixed_entry.get("trace", [])

    if not isinstance(original_trace, list):
        stats["invalid_trace_shapes"] += 1
        add_log(
            logs,
            stats,
            entry=entry,
            event_type="invalid_trace_shape",
            field_path="trace",
            action="manual_review",
            reason="trace must be a list",
            before=original_trace,
            after=original_trace,
        )
        return fixed_entry

    items = [
        TraceItem(node=copy.deepcopy(node), original_index=index)
        for index, node in enumerate(original_trace)
        if isinstance(node, dict)
    ]
    if len(items) != len(original_trace):
        stats["invalid_trace_node_shapes"] += len(original_trace) - len(items)

    handle_duplicate_nodes(
        entry=entry,
        items=items,
        logs=logs,
        stats=stats,
        can_fix=can_fix,
        args=args,
    )

    for item in items:
        if item.dropped:
            continue
        compare_trace_bounds(
            entry=entry,
            item=item,
            logs=logs,
            stats=stats,
            can_fix=can_fix,
            args=args,
        )

    if args.mode == "fix":
        fixed_entry["trace"] = [item.node for item in items if not item.dropped]
    return fixed_entry


def validate_node(node: Any, path: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(node, dict):
        return [f"{path}: must be an object"]
    missing = REQUIRED_NODE_FIELDS - set(node)
    if missing:
        errors.append(f"{path}: missing required node fields {sorted(missing)}")
    if "line" in node and parse_line_span(node.get("line")) is None:
        errors.append(f"{path}.line: invalid line {node.get('line')!r}")
    if "file" in node and not isinstance(node.get("file"), str):
        errors.append(f"{path}.file: must be a string")
    if "code" in node and not isinstance(node.get("code"), str):
        errors.append(f"{path}.code: must be a string")
    if "desc" in node and not isinstance(node.get("desc"), str):
        errors.append(f"{path}.desc: must be a string when present")
    return errors


def validate_entries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    validation_errors: list[dict[str, Any]] = []
    for row_index, entry in enumerate(rows, 1):
        entry_id = entry.get("entry_id", f"row-{row_index}")
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        errors: list[str] = []
        if missing:
            errors.append(f"missing top-level fields {sorted(missing)}")
        if entry.get("verify") not in {0, 1}:
            errors.append("verify must be exactly 0 or 1")
        if not isinstance(entry.get("trace"), list):
            errors.append("trace must be a list")
        errors.extend(validate_node(entry.get("entry_point"), "entry_point"))
        errors.extend(validate_node(entry.get("critical_operation"), "critical_operation"))
        for index, node in enumerate(entry.get("trace", []) if isinstance(entry.get("trace"), list) else []):
            errors.extend(validate_node(node, f"trace[{index}]"))
        if errors:
            validation_errors.append(
                {
                    "entry_id": entry_id,
                    "row_index": row_index,
                    "errors": errors,
                }
            )
    return validation_errors


def build_report(
    *,
    input_path: Path,
    output_path: Path | None,
    original_rows: list[dict[str, Any]],
    fixed_rows: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    stats: Counter[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    changed_entries = [
        row.get("entry_id")
        for original, row in zip(original_rows, fixed_rows)
        if original != row
    ]
    event_counts = Counter(log["event_type"] for log in logs)
    action_counts = Counter(log["action"] for log in logs)
    manual_review_entries = sorted(
        {
            log.get("entry_id")
            for log in logs
            if log.get("action") == "manual_review" and log.get("entry_id")
        }
    )

    input_validation = validate_entries(original_rows)
    output_validation = validate_entries(fixed_rows)

    return {
        "config": {
            "mode": args.mode,
            "input": display_path(input_path),
            "output": display_path(output_path),
            "fix_verify": args.fix_verify,
            "order_fix_policy": args.order_fix_policy,
            "duplicate_fix_policy": args.duplicate_fix_policy,
            "log_cross_file": args.log_cross_file,
        },
        "totals": {
            "entries_scanned": len(original_rows),
            "trace_nodes_scanned": sum(
                len(row.get("trace", []))
                for row in original_rows
                if isinstance(row.get("trace"), list)
            ),
            "log_events": len(logs),
            "changed_entries": len(changed_entries),
            "manual_review_entries": len(manual_review_entries),
            "input_schema_errors": len(input_validation),
            "output_schema_errors": len(output_validation),
        },
        "issue_counts": {
            "duplicate_nodes": stats.get("duplicate_nodes", 0),
            "duplicate_desc_sync_needed": stats.get("duplicate_desc_sync_needed", 0),
            "duplicate_desc_conflicts": stats.get("duplicate_desc_conflicts", 0),
            "order_before_entry_whole": stats.get("order_before_entry_whole", 0),
            "order_before_entry_overlap": stats.get("order_before_entry_overlap", 0),
            "order_after_critical_whole": stats.get("order_after_critical_whole", 0),
            "order_after_critical_overlap": stats.get("order_after_critical_overlap", 0),
            "cross_file_entry_comparisons_skipped": stats.get("cross_file_entry_comparisons_skipped", 0),
            "cross_file_critical_comparisons_skipped": stats.get("cross_file_critical_comparisons_skipped", 0),
            "invalid_trace_lines": stats.get("invalid_trace_lines", 0),
        },
        "action_counts": dict(sorted(action_counts.items())),
        "event_counts": dict(sorted(event_counts.items())),
        "changed_entry_ids": sorted(changed_entries),
        "manual_review_entry_ids": manual_review_entries,
        "schema_validation": {
            "input_errors": input_validation,
            "output_errors": output_validation,
        },
    }


def write_report_markdown(path: Path, report: dict[str, Any]) -> None:
    cfg = report["config"]
    totals = report["totals"]
    issue_counts = report["issue_counts"]
    action_counts = report["action_counts"]

    lines = [
        "# Trace cleanup report",
        "",
        "## Config",
        "",
        f"- mode: `{cfg['mode']}`",
        f"- input: `{cfg['input']}`",
        f"- output: `{cfg['output']}`",
        f"- fix_verify: `{cfg['fix_verify']}`",
        f"- order_fix_policy: `{cfg['order_fix_policy']}`",
        f"- duplicate_fix_policy: `{cfg['duplicate_fix_policy']}`",
        f"- log_cross_file: `{cfg['log_cross_file']}`",
        "",
        "## Totals",
        "",
        f"- entries scanned: {totals['entries_scanned']}",
        f"- trace nodes scanned: {totals['trace_nodes_scanned']}",
        f"- changed entries: {totals['changed_entries']}",
        f"- log events: {totals['log_events']}",
        f"- manual-review entries: {totals['manual_review_entries']}",
        f"- input schema errors: {totals['input_schema_errors']}",
        f"- output schema errors: {totals['output_schema_errors']}",
        "",
        "## Issues",
        "",
    ]
    for key in [
        "duplicate_nodes",
        "duplicate_desc_sync_needed",
        "duplicate_desc_conflicts",
        "order_before_entry_whole",
        "order_before_entry_overlap",
        "order_after_critical_whole",
        "order_after_critical_overlap",
        "cross_file_entry_comparisons_skipped",
        "cross_file_critical_comparisons_skipped",
        "invalid_trace_lines",
    ]:
        lines.append(f"- {key}: {issue_counts.get(key, 0)}")

    lines.extend(["", "## Actions", ""])
    for key, value in action_counts.items():
        lines.append(f"- {key}: {value}")

    if report["changed_entry_ids"]:
        lines.extend(["", "## Changed Entries", ""])
        for entry_id in report["changed_entry_ids"]:
            lines.append(f"- {entry_id}")

    if report["manual_review_entry_ids"]:
        lines.extend(["", "## Manual Review Entries", ""])
        for entry_id in report["manual_review_entry_ids"]:
            lines.append(f"- {entry_id}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_summary(report: dict[str, Any], log_path: Path, report_path: Path, md_path: Path) -> None:
    totals = report["totals"]
    issues = report["issue_counts"]
    actions = report["action_counts"]

    print("Trace cleanup scan complete")
    print("===========================")
    print(f"entries scanned: {totals['entries_scanned']}")
    print(f"trace nodes scanned: {totals['trace_nodes_scanned']}")
    print(f"duplicate nodes: {issues['duplicate_nodes']}")
    print(
        "order anomalies: "
        f"before-entry={issues['order_before_entry_whole']} "
        f"(overlap={issues['order_before_entry_overlap']}), "
        f"after-critical={issues['order_after_critical_whole']} "
        f"(overlap={issues['order_after_critical_overlap']})"
    )
    print(f"actions: {dict(sorted(actions.items()))}")
    print(f"changed entries: {totals['changed_entries']}")
    print(f"manual-review entries: {totals['manual_review_entries']}")
    print(f"schema errors after processing: {totals['output_schema_errors']}")
    print()
    print(f"log: {log_path}")
    print(f"json report: {report_path}")
    print(f"markdown report: {md_path}")
    if report["config"]["output"]:
        print(f"fixed jsonl: {report['config']['output']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect and optionally clean structural trace-chain issues.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="entries JSONL to scan")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="fixed JSONL output; defaults to data/entries.trace_fixed.jsonl in fix mode",
    )
    parser.add_argument("--log-out", type=Path, default=DEFAULT_LOG, help="JSON event log output")
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT_JSON, help="JSON report output")
    parser.add_argument("--report-md-out", type=Path, default=DEFAULT_REPORT_MD, help="Markdown report output")
    parser.add_argument(
        "--mode",
        choices=("check", "fix"),
        default="check",
        help="check only or write a fixed JSONL",
    )
    parser.add_argument(
        "--fix-verify",
        choices=("0", "1", "all"),
        default="0",
        help="which verify bucket can be changed in fix mode",
    )
    parser.add_argument(
        "--order-fix-policy",
        choices=("none", "entry-before-only", "bounds"),
        default="entry-before-only",
        help=(
            "order cleanup in fix mode: none keeps order anomalies, "
            "entry-before-only drops wholly pre-entry nodes, bounds also drops "
            "wholly post-critical nodes"
        ),
    )
    parser.add_argument(
        "--duplicate-fix-policy",
        choices=("safe", "drop-all", "none"),
        default="safe",
        help=(
            "duplicate cleanup in fix mode: safe drops only duplicates without "
            "conflicting desc text, drop-all drops every duplicate candidate, "
            "none only reports duplicates"
        ),
    )
    parser.add_argument(
        "--log-cross-file",
        dest="log_cross_file",
        action="store_true",
        default=True,
        help="log skipped cross-file line comparisons",
    )
    parser.add_argument(
        "--no-log-cross-file",
        dest="log_cross_file",
        action="store_false",
        help="omit per-node cross-file skip events from the log",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_path = args.input
    output_path = args.output if args.output is not None else (DEFAULT_OUTPUT if args.mode == "fix" else None)

    rows = load_jsonl(input_path)
    logs: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    fixed_rows = [process_entry(entry, logs, stats, args) for entry in rows]

    if output_path is not None:
        write_jsonl(output_path, fixed_rows)

    report = build_report(
        input_path=input_path,
        output_path=output_path,
        original_rows=rows,
        fixed_rows=fixed_rows,
        logs=logs,
        stats=stats,
        args=args,
    )
    write_json(args.log_out, logs)
    write_json(args.report_out, report)
    write_report_markdown(args.report_md_out, report)
    print_summary(report, args.log_out, args.report_out, args.report_md_out)

    return 1 if report["totals"]["output_schema_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
