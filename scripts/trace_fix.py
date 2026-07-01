#!/usr/bin/env python3
"""Detect and conservatively fix structural trace issues in VulnGym entries."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
# Default paths are kept stable so the script can be run directly from the repo root.
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "entries.trace_fixed.jsonl"
DEFAULT_LOG = REPO_ROOT / "reports" / "trace_fix_log.json"
DEFAULT_REPORT = REPO_ROOT / "reports" / "trace_fix_report.json"
# Same-file nodes near the anchor are left for manual review in fix mode.
DEFAULT_AUTO_FIX_MIN_GAP = 20

# These issue types mirror the structural cases called out in the issue description.
ISSUE_TYPE_DUPLICATE = "duplicate"
ISSUE_TYPE_CONTAINS_ENTRY = "contains_entry_point"
ISSUE_TYPE_CONTAINS_CRITICAL = "contains_critical_operation"
ISSUE_TYPE_ORDER_BEFORE_ENTRY = "order_before_entry"
ISSUE_TYPE_ORDER_AFTER_CRITICAL = "order_after_critical"
ISSUE_TYPE_CROSS_FILE = "cross_file_skipped"

# Actions describe what the current mode decided to do with a detected issue.
ACTION_SKIPPED = "skipped"
ACTION_REMOVED = "removed"
ACTION_RECORDED = "recorded"

# Only the schema subset required by this issue is enforced here.
REQUIRED_TOP_LEVEL_FIELDS = (
    "entry_id",
    "report_id",
    "source_link",
    "vuln_ids",
    "origin",
    "project",
    "repo_url",
    "commit",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "entry_point",
    "critical_operation",
    "trace",
    "verify",
)
REQUIRED_NODE_FIELDS = ("file", "line", "code")

_MULTI_SLASH = re.compile(r"/+")
_LEADING_DOT_SLASH = re.compile(r"^(?:\./)+")


@dataclass
class TraceIssue:
    entry_id: str
    field_path: str
    issue_type: str
    trace_index: int
    file: str
    line: Any
    code: str
    before: dict
    after: Optional[dict]
    action: str
    reason: str
    gap: Optional[int] = None
    first_trace_index: Optional[int] = None
    desc_conflict: bool = False

    def to_dict(self) -> dict:
        data = asdict(self)
        if self.gap is None:
            data.pop("gap")
        if self.first_trace_index is None:
            data.pop("first_trace_index")
        if not self.desc_conflict:
            data.pop("desc_conflict")
        return data


def normalize_path(path: Any) -> str:
    # Path normalization keeps signature comparison stable across slash styles.
    if not isinstance(path, str):
        return ""
    path = path.replace("\\", "/")
    path = _LEADING_DOT_SLASH.sub("", path)
    return _MULTI_SLASH.sub("/", path)


def parse_line(value: Any) -> tuple[int, int]:
    # Normalize int / "start-end" into a comparable closed interval.
    if isinstance(value, int):
        return (value, value) if value >= 1 else (0, 0)
    if isinstance(value, str):
        value = value.strip()
        if "-" in value:
            start, _, end = value.partition("-")
            try:
                start_num = int(start)
                end_num = int(end)
            except ValueError:
                return (0, 0)
            return (start_num, end_num) if start_num >= 1 and end_num >= start_num else (0, 0)
        try:
            num = int(value)
        except ValueError:
            return (0, 0)
        return (num, num) if num >= 1 else (0, 0)
    return (0, 0)


def node_signature(node: dict) -> tuple[str, int, int, str]:
    # Duplicate detection intentionally ignores desc and compares structural identity only.
    start, end = parse_line(node.get("line"))
    return (
        normalize_path(node.get("file", "")),
        start,
        end,
        node.get("code", ""),
    )


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                rows.append(json.loads(text))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from None
    return rows


def save_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            # Stable key ordering makes later diff review much easier.
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def _node_snapshot(node: dict) -> dict:
    # Logs only need the fields relevant to this cleanup task.
    data = {
        "file": node.get("file", ""),
        "line": node.get("line"),
        "code": node.get("code", ""),
    }
    if "desc" in node:
        data["desc"] = node.get("desc")
    return data


def _node_label(node: dict) -> str:
    return f"{normalize_path(node.get('file', ''))}:{node.get('line')}"


def detect_endpoint_in_trace(entry: dict, trace: list[dict]) -> list[TraceIssue]:
    issues: list[TraceIssue] = []
    entry_id = entry.get("entry_id", "<unknown>")
    entry_sig = node_signature(entry.get("entry_point", {}))
    critical_sig = node_signature(entry.get("critical_operation", {}))

    for idx, node in enumerate(trace):
        sig = node_signature(node)
        snap = _node_snapshot(node)
        # Trace is allowed to repeat the entry/critical node as an anchor.
        if sig == entry_sig:
            issues.append(
                TraceIssue(
                    entry_id=entry_id,
                    field_path=f"trace[{idx}]",
                    issue_type=ISSUE_TYPE_CONTAINS_ENTRY,
                    trace_index=idx,
                    file=node.get("file", ""),
                    line=node.get("line"),
                    code=node.get("code", ""),
                    before=snap,
                    after=snap,
                    action=ACTION_SKIPPED,
                    reason=f"trace node matches entry_point anchor ({_node_label(node)}); kept as valid anchor reference",
                )
            )
        elif sig == critical_sig:
            issues.append(
                TraceIssue(
                    entry_id=entry_id,
                    field_path=f"trace[{idx}]",
                    issue_type=ISSUE_TYPE_CONTAINS_CRITICAL,
                    trace_index=idx,
                    file=node.get("file", ""),
                    line=node.get("line"),
                    code=node.get("code", ""),
                    before=snap,
                    after=snap,
                    action=ACTION_SKIPPED,
                    reason=f"trace node matches critical_operation anchor ({_node_label(node)}); kept as valid anchor reference",
                )
            )
    return issues


def detect_duplicates(entry: dict, trace: list[dict]) -> list[TraceIssue]:
    issues: list[TraceIssue] = []
    # Remember the first structural occurrence so later duplicates can point back to it.
    seen: dict[tuple[str, int, int, str], tuple[int, dict]] = {}
    entry_id = entry.get("entry_id", "<unknown>")

    for idx, node in enumerate(trace):
        sig = node_signature(node)
        if sig in seen:
            first_idx, first_node = seen[sig]
            first_desc = first_node.get("desc")
            current_desc = node.get("desc")
            desc_conflict = first_desc != current_desc
            reason = f"duplicate trace node; same {{file, line, code}} as trace[{first_idx}]"
            if desc_conflict:
                reason += "; desc differs from first occurrence and was not merged"
            issues.append(
                TraceIssue(
                    entry_id=entry_id,
                    field_path=f"trace[{idx}]",
                    issue_type=ISSUE_TYPE_DUPLICATE,
                    trace_index=idx,
                    file=node.get("file", ""),
                    line=node.get("line"),
                    code=node.get("code", ""),
                    before=_node_snapshot(node),
                    after=None,
                    action=ACTION_RECORDED,
                    reason=reason,
                    first_trace_index=first_idx,
                    desc_conflict=desc_conflict,
                )
            )
        else:
            # The first occurrence is always kept as the canonical node.
            seen[sig] = (idx, node)
    return issues


def detect_order_issues(entry: dict, trace: list[dict]) -> list[TraceIssue]:
    issues: list[TraceIssue] = []
    entry_id = entry.get("entry_id", "<unknown>")
    entry_point = entry.get("entry_point", {})
    critical_op = entry.get("critical_operation", {})
    entry_file = normalize_path(entry_point.get("file", ""))
    critical_file = normalize_path(critical_op.get("file", ""))
    entry_start, _ = parse_line(entry_point.get("line"))
    _, critical_end = parse_line(critical_op.get("line"))

    for idx, node in enumerate(trace):
        node_file = normalize_path(node.get("file", ""))
        node_start, node_end = parse_line(node.get("line"))
        # Invalid line values are schema problems and are handled by validation, not issue logging.
        if node_start == 0 or node_end == 0:
            continue

        same_as_entry = bool(entry_file) and node_file == entry_file
        same_as_critical = bool(critical_file) and node_file == critical_file

        # Cross-file hops are preserved as-is and only logged.
        if not same_as_entry and not same_as_critical:
            snap = _node_snapshot(node)
            issues.append(
                TraceIssue(
                    entry_id=entry_id,
                    field_path=f"trace[{idx}]",
                    issue_type=ISSUE_TYPE_CROSS_FILE,
                    trace_index=idx,
                    file=node.get("file", ""),
                    line=node.get("line"),
                    code=node.get("code", ""),
                    before=snap,
                    after=snap,
                    action=ACTION_SKIPPED,
                    reason=(
                        f"cross-file trace node in {node_file or '<empty>'}; "
                        "same-file line comparison skipped and original order preserved"
                    ),
                )
            )
            continue

        # For same-file nodes, compare against the nearest anchor boundary only.
        if same_as_entry and node_end < entry_start:
            issues.append(
                TraceIssue(
                    entry_id=entry_id,
                    field_path=f"trace[{idx}]",
                    issue_type=ISSUE_TYPE_ORDER_BEFORE_ENTRY,
                    trace_index=idx,
                    file=node.get("file", ""),
                    line=node.get("line"),
                    code=node.get("code", ""),
                    before=_node_snapshot(node),
                    after=None,
                    action=ACTION_RECORDED,
                    reason=(
                        f"same-file order issue: trace line.end={node_end} is before "
                        f"entry_point.line={entry_start} ({_node_label(entry_point)})"
                    ),
                    gap=entry_start - node_end,
                )
            )
            continue

        if same_as_critical and node_start > critical_end:
            issues.append(
                TraceIssue(
                    entry_id=entry_id,
                    field_path=f"trace[{idx}]",
                    issue_type=ISSUE_TYPE_ORDER_AFTER_CRITICAL,
                    trace_index=idx,
                    file=node.get("file", ""),
                    line=node.get("line"),
                    code=node.get("code", ""),
                    before=_node_snapshot(node),
                    after=None,
                    action=ACTION_RECORDED,
                    reason=(
                        f"same-file order issue: trace line.start={node_start} is after "
                        f"critical_operation.line.end={critical_end} ({_node_label(critical_op)})"
                    ),
                    gap=node_start - critical_end,
                )
            )

    return issues


def apply_fixes(entry: dict, issues: list[TraceIssue]) -> tuple[list[dict], list[TraceIssue]]:
    trace = entry.get("trace", [])
    if not trace:
        return trace, issues

    # Removal is collected first so trace order can be preserved for the remaining nodes.
    remove_indices: set[int] = set()

    # Fix mode only removes deterministic structural problems.
    for issue in issues:
        if issue.issue_type == ISSUE_TYPE_DUPLICATE:
            remove_indices.add(issue.trace_index)
            issue.action = ACTION_REMOVED
            issue.after = None
            continue

        if issue.issue_type in (ISSUE_TYPE_ORDER_BEFORE_ENTRY, ISSUE_TYPE_ORDER_AFTER_CRITICAL):
            # The issue asks for conservative fixing, so nearby nodes stay for review.
            if issue.gap is not None and issue.gap > DEFAULT_AUTO_FIX_MIN_GAP:
                remove_indices.add(issue.trace_index)
                issue.action = ACTION_REMOVED
                issue.after = None
                issue.reason = (
                    f"{issue.reason}; fix mode: gap {issue.gap} exceeds review window "
                    f"{DEFAULT_AUTO_FIX_MIN_GAP}, node removed"
                )
            else:
                # Nearby same-file nodes are ambiguous, so fix mode only records them.
                issue.after = issue.before
                issue.reason = (
                    f"{issue.reason}; fix mode: gap {issue.gap} stays within review window "
                    f"{DEFAULT_AUTO_FIX_MIN_GAP}, kept for manual review"
                )
            continue

        if issue.action == ACTION_RECORDED:
            issue.after = issue.before

    new_trace: list[dict] = []
    for idx, node in enumerate(trace):
        if idx in remove_indices:
            continue
        # Remaining nodes keep their original relative order.
        new_trace.append(node)
    return new_trace, issues


def analyze_entry(entry: dict) -> list[TraceIssue]:
    trace = entry.get("trace", [])
    if not trace:
        return []

    issues: list[TraceIssue] = []
    endpoint_issues = detect_endpoint_in_trace(entry, trace)
    issues.extend(endpoint_issues)
    endpoint_indices = {issue.trace_index for issue in endpoint_issues}

    # Anchor nodes are allowed in trace and should not be re-flagged.
    for issue in detect_duplicates(entry, trace):
        if issue.trace_index not in endpoint_indices:
            issues.append(issue)

    # Order checks run after anchor filtering for the same reason.
    for issue in detect_order_issues(entry, trace):
        if issue.trace_index not in endpoint_indices:
            issues.append(issue)

    return issues


def validate_entry_schema(entry: dict, entry_offset: int) -> None:
    if not isinstance(entry, dict):
        raise SystemExit(f"schema validation failed for entry[{entry_offset}]: top-level row must be an object")

    missing_fields = [field for field in REQUIRED_TOP_LEVEL_FIELDS if field not in entry]
    if missing_fields:
        raise SystemExit(
            f"schema validation failed for entry[{entry_offset}] {entry.get('entry_id', '<unknown>')}: "
            f"missing top-level fields: {', '.join(missing_fields)}"
        )

    if entry.get("verify") not in (0, 1):
        raise SystemExit(
            f"schema validation failed for entry[{entry_offset}] {entry.get('entry_id', '<unknown>')}: "
            "verify must be 0 or 1"
        )

    if not isinstance(entry.get("trace"), list):
        raise SystemExit(
            f"schema validation failed for entry[{entry_offset}] {entry.get('entry_id', '<unknown>')}: "
            "trace must be a list"
        )

    # Only validate the subset of SCHEMA.md constraints required by this issue.
    validate_node_schema(entry["entry_point"], entry_offset, "entry_point")
    validate_node_schema(entry["critical_operation"], entry_offset, "critical_operation")

    for idx, node in enumerate(entry["trace"]):
        validate_node_schema(node, entry_offset, f"trace[{idx}]")


def validate_node_schema(node: dict, entry_offset: int, field_path: str) -> None:
    if not isinstance(node, dict):
        raise SystemExit(f"schema validation failed for entry[{entry_offset}] {field_path}: node must be an object")

    missing_fields = [field for field in REQUIRED_NODE_FIELDS if field not in node]
    if missing_fields:
        raise SystemExit(
            f"schema validation failed for entry[{entry_offset}] {field_path}: "
            f"missing node fields: {', '.join(missing_fields)}"
        )

    if parse_line(node.get("line")) == (0, 0):
        raise SystemExit(
            f"schema validation failed for entry[{entry_offset}] {field_path}: "
            "line must be a positive integer or start-end string"
        )


def validate_entries_schema(entries: list[dict]) -> None:
    # Validation is reused for both input sanity checks and post-fix output checks.
    for idx, entry in enumerate(entries):
        validate_entry_schema(entry, idx)


def validate_jsonl_file(path: Path) -> None:
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.rstrip("\n")
            if not text.strip():
                continue
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON after write: {exc}") from None


def build_report(
    input_path: Path,
    output_path: Path,
    log_path: Path,
    mode: str,
    entries_total: int,
    all_issues: list[TraceIssue],
) -> dict:
    # Report statistics intentionally separate full detection from auto-fix decisions.
    structural_entries: set[str] = set()
    duplicate_node_count = 0
    order_issue_node_count = 0
    auto_fixed_count = 0
    review_required_count = 0

    for issue in all_issues:
        if issue.issue_type == ISSUE_TYPE_DUPLICATE:
            duplicate_node_count += 1
            structural_entries.add(issue.entry_id)
        if issue.issue_type in (ISSUE_TYPE_ORDER_BEFORE_ENTRY, ISSUE_TYPE_ORDER_AFTER_CRITICAL):
            order_issue_node_count += 1
            structural_entries.add(issue.entry_id)

        if issue.action == ACTION_REMOVED:
            auto_fixed_count += 1
        elif issue.action == ACTION_RECORDED:
            if issue.issue_type in (ISSUE_TYPE_ORDER_BEFORE_ENTRY, ISSUE_TYPE_ORDER_AFTER_CRITICAL):
                review_required_count += 1

    return {
        "metadata": {
            "input_file": str(input_path),
            "output_file": str(output_path),
            "log_file": str(log_path),
            "mode": mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_entries": entries_total,
            "entries_with_structural_issues": len(structural_entries),
        },
        "statistics": {
            "duplicate_node_count": duplicate_node_count,
            "order_issue_node_count": order_issue_node_count,
            "auto_fixed_count": auto_fixed_count,
            "review_required_count": review_required_count,
        },
    }


def _write_log(log_path: Path, input_path: Path, output_path: Path, mode: str, entries_total: int, issues: list[TraceIssue]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Dry-run keeps logs compact; fix mode keeps before/after details.
    if mode == "dry-run":
        logged_issues = [
            {
                "entry_id": issue.entry_id,
                "field_path": issue.field_path,
                "issue_type": issue.issue_type,
                "reason": issue.reason,
                "action": issue.action,
            }
            for issue in issues
            if issue.issue_type in (ISSUE_TYPE_DUPLICATE, ISSUE_TYPE_ORDER_BEFORE_ENTRY, ISSUE_TYPE_ORDER_AFTER_CRITICAL)
        ]
    else:
        # Fix logs keep both removed nodes and review-only nodes for later audit.
        logged_issues = [
            {
                "entry_id": issue.entry_id,
                "field_path": issue.field_path,
                "action": issue.action,
                "before": issue.before,
                "after": issue.after,
                "reason": issue.reason,
            }
            for issue in issues
            if issue.action in (ACTION_REMOVED, ACTION_RECORDED)
        ]

    with log_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "metadata": {
                    "input_file": str(input_path),
                    "output_file": str(output_path) if mode == "fix" else None,
                    "mode": mode,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "total_entries": entries_total,
                    "total_issues": len(logged_issues),
                },
                "issues": logged_issues,
            },
            handle,
            ensure_ascii=False,
            indent=2,
        )


def _print_summary(report: dict) -> None:
    metadata = report["metadata"]
    stats = report["statistics"]
    print()
    print("Trace-fix summary")
    print("=================")
    print(f"  mode:           {metadata['mode']}")
    print(f"  total entries:  {metadata['total_entries']}")
    print(f"  entries with structural issues: {metadata['entries_with_structural_issues']}")
    print()
    print(f"  duplicate_node_count:           {stats['duplicate_node_count']}")
    print(f"  order_issue_node_count:         {stats['order_issue_node_count']}")
    print(f"  auto_fixed_count:               {stats['auto_fixed_count']}")
    print(f"  review_required_count:          {stats['review_required_count']}")
    print()


def run(args: argparse.Namespace) -> int:
    input_path: Path = args.input
    output_path: Path = args.output
    log_path: Path = args.log
    report_path: Path = args.report
    mode: str = args.mode

    if not input_path.exists():
        print(f"ERROR: input file not found: {input_path}", file=sys.stderr)
        return 1

    print(f"[trace_fix] loading {input_path}")
    entries = load_jsonl(input_path)
    print(f"[trace_fix] {len(entries)} entries loaded")
    # Fail fast on malformed rows before any detection or write happens.
    validate_entries_schema(entries)

    all_issues: list[TraceIssue] = []
    output_entries: list[dict] = []

    # Detection is always full-scan; fix mode only changes deterministic cases.
    for entry in entries:
        issues = analyze_entry(entry)
        if mode == "fix" and issues:
            new_trace, issues = apply_fixes(entry, issues)
            new_entry = dict(entry)
            new_entry["trace"] = new_trace
            output_entries.append(new_entry)
        else:
            output_entries.append(entry)
        all_issues.extend(issues)

    _write_log(log_path, input_path, output_path, mode, len(entries), all_issues)

    if mode == "fix":
        print(f"[trace_fix] writing fixed dataset to {output_path}")
        save_jsonl(output_path, output_entries)
        # Re-validate persisted output so the generated JSONL stays safe to consume.
        validate_jsonl_file(output_path)
        validate_entries_schema(output_entries)

    print(f"[trace_fix] writing log to {log_path}")
    validate_jsonl_file(log_path) if log_path.suffix == ".jsonl" else None

    report = build_report(
        input_path=input_path,
        output_path=output_path if mode == "fix" else Path("(none - dry run)"),
        log_path=log_path,
        mode=mode,
        entries_total=len(entries),
        all_issues=all_issues,
    )
    print(f"[trace_fix] writing report to {report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)

    _print_summary(report)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect and optionally fix structural issues in VulnGym trace arrays.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--mode", choices=("dry-run", "fix"), default="dry-run")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    return run(build_arg_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
