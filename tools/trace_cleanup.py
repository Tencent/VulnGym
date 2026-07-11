#!/usr/bin/env python3
"""Detect and optionally repair structural problems in VulnGym traces."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
ENTRY_ID_RE = re.compile(r"^entry-\d{5}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class DataValidationError(ValueError):
    """Raised when input or generated data violates a required invariant."""


def parse_line(value: Any, field_path: str = "line") -> tuple[int, int]:
    """Normalize an integer or ``start-end`` line value to an interval."""
    if isinstance(value, bool):
        raise DataValidationError(f"{field_path}: boolean is not a valid line")
    if isinstance(value, int):
        if value < 1:
            raise DataValidationError(f"{field_path}: line must be positive")
        return value, value
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return start, end
    raise DataValidationError(
        f"{field_path}: expected a positive integer or 'start-end', got {value!r}"
    )


def validate_node(node: Any, field_path: str) -> None:
    if not isinstance(node, dict):
        raise DataValidationError(f"{field_path}: expected an object")
    for key in ("file", "line", "code"):
        if key not in node:
            raise DataValidationError(f"{field_path}: missing required key {key!r}")
    if not isinstance(node["file"], str) or not node["file"]:
        raise DataValidationError(f"{field_path}.file: expected a non-empty string")
    if not isinstance(node["code"], str):
        raise DataValidationError(f"{field_path}.code: expected a string")
    if "desc" in node and not isinstance(node["desc"], str):
        raise DataValidationError(f"{field_path}.desc: expected a string")
    parse_line(node["line"], f"{field_path}.line")


def validate_dataset(entries: Iterable[dict[str, Any]]) -> None:
    seen_ids: set[str] = set()
    for row_number, entry in enumerate(entries, 1):
        prefix = f"row {row_number}"
        if not isinstance(entry, dict):
            raise DataValidationError(f"{prefix}: expected an object")
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or not ENTRY_ID_RE.fullmatch(entry_id):
            raise DataValidationError(f"{prefix}.entry_id: invalid entry id {entry_id!r}")
        if entry_id in seen_ids:
            raise DataValidationError(f"{prefix}.entry_id: duplicate id {entry_id!r}")
        seen_ids.add(entry_id)
        if not isinstance(entry.get("commit"), str) or not COMMIT_RE.fullmatch(entry["commit"]):
            raise DataValidationError(f"{entry_id}.commit: expected 40 lowercase hex characters")
        if not isinstance(entry.get("repo_url"), str) or not entry["repo_url"].startswith(
            "https://github.com/"
        ):
            raise DataValidationError(f"{entry_id}.repo_url: expected a GitHub HTTPS URL")
        if entry.get("verify") not in (0, 1) or isinstance(entry.get("verify"), bool):
            raise DataValidationError(f"{entry_id}.verify: expected 0 or 1")
        validate_node(entry.get("entry_point"), f"{entry_id}.entry_point")
        validate_node(entry.get("critical_operation"), f"{entry_id}.critical_operation")
        trace = entry.get("trace")
        if not isinstance(trace, list):
            raise DataValidationError(f"{entry_id}.trace: expected an array")
        for index, node in enumerate(trace):
            validate_node(node, f"{entry_id}.trace[{index}]")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            if not raw_line.strip():
                continue
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise DataValidationError(f"{path}:{line_number}: invalid JSON: {error}") from None
            entries.append(value)
    validate_dataset(entries)
    return entries


def node_key(node: dict[str, Any]) -> tuple[Any, Any, Any]:
    return node["file"], node["line"], node["code"]


def make_event(
    entry_id: str,
    field_path: str,
    kind: str,
    action: str,
    reason: str,
    before: Any,
    after: Any,
    **details: Any,
) -> dict[str, Any]:
    event = {
        "entry_id": entry_id,
        "field_path": field_path,
        "kind": kind,
        "action": action,
        "reason": reason,
        "before": before,
        "after": after,
    }
    if details:
        event["details"] = details
    return event


def process_entry(
    entry: dict[str, Any],
    *,
    mode: str,
    dedupe_desc_conflicts: bool = False,
    fix_verified: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], set[int], set[int]]:
    """Return a processed entry, audit events, removed indexes, and review indexes."""
    entry_id = entry["entry_id"]
    trace = entry["trace"]
    events: list[dict[str, Any]] = []
    removals: set[int] = set()
    manual_review: set[int] = set()
    can_fix = mode == "fix" and (entry["verify"] == 0 or fix_verified)

    def repair_action(repair: str) -> str:
        if mode == "report":
            return "reported"
        return repair if can_fix else "kept_for_review"

    groups: dict[tuple[Any, Any, Any], list[int]] = defaultdict(list)
    for index, node in enumerate(trace):
        groups[node_key(node)].append(index)

    desc_updates: dict[int, str] = {}
    for indexes in groups.values():
        if len(indexes) < 2:
            continue
        first_index = indexes[0]
        nonempty_descs = {
            trace[index].get("desc") for index in indexes if trace[index].get("desc")
        }
        has_desc_conflict = len(nonempty_descs) > 1
        if has_desc_conflict and not (dedupe_desc_conflicts and can_fix):
            manual_review.update(indexes)
            for index in indexes[1:]:
                events.append(
                    make_event(
                        entry_id,
                        f"trace[{index}]",
                        "duplicate_desc_conflict",
                        "kept_for_review",
                        "duplicate candidate has a different non-empty desc",
                        trace[index],
                        trace[index],
                        first_index=first_index,
                    )
                )
            continue

        canonical_desc = trace[first_index].get("desc")
        if not canonical_desc and nonempty_descs:
            canonical_desc = next(iter(nonempty_descs))
            if can_fix:
                desc_updates[first_index] = canonical_desc
            elif mode == "fix":
                manual_review.add(first_index)
            events.append(
                make_event(
                    entry_id,
                    f"trace[{first_index}].desc",
                    "desc_sync",
                    repair_action("updated"),
                    "copied the only non-empty desc from a duplicate node",
                    trace[first_index].get("desc"),
                    canonical_desc if can_fix else trace[first_index].get("desc"),
                )
            )

        for index in indexes[1:]:
            if can_fix:
                removals.add(index)
            elif mode == "fix":
                manual_review.add(index)
            reason = (
                "duplicate candidate forced to keep the first desc"
                if has_desc_conflict
                else "duplicate node; the first occurrence is retained"
            )
            events.append(
                make_event(
                    entry_id,
                    f"trace[{index}]",
                    "duplicate",
                    repair_action("removed"),
                    reason,
                    trace[index],
                    None if can_fix else trace[index],
                    first_index=first_index,
                )
            )

    entry_point = entry["entry_point"]
    critical_operation = entry["critical_operation"]
    entry_start, _ = parse_line(entry_point["line"])
    _, critical_end = parse_line(critical_operation["line"])

    for index, node in enumerate(trace):
        node_start, node_end = parse_line(node["line"])
        path = f"trace[{index}]"
        skipped_boundaries: list[str] = []
        if node["file"] == entry_point["file"]:
            if node_end < entry_start:
                if can_fix:
                    removals.add(index)
                elif mode == "fix":
                    manual_review.add(index)
                events.append(
                    make_event(
                        entry_id,
                        path,
                        "before_entry_point",
                        repair_action("removed"),
                        "trace interval ends before the entry-point interval starts",
                        node,
                        None if can_fix else node,
                        trace_interval=[node_start, node_end],
                        boundary_interval=list(parse_line(entry_point["line"])),
                    )
                )
        else:
            skipped_boundaries.append("entry_point")

        if node["file"] == critical_operation["file"]:
            if node_start > critical_end:
                if can_fix:
                    removals.add(index)
                elif mode == "fix":
                    manual_review.add(index)
                events.append(
                    make_event(
                        entry_id,
                        path,
                        "after_critical_operation",
                        repair_action("removed"),
                        "trace interval starts after the critical-operation interval ends",
                        node,
                        None if can_fix else node,
                        trace_interval=[node_start, node_end],
                        boundary_interval=list(parse_line(critical_operation["line"])),
                    )
                )
        else:
            skipped_boundaries.append("critical_operation")

        if skipped_boundaries:
            events.append(
                make_event(
                    entry_id,
                    path,
                    "cross_file_skipped",
                    "skipped",
                    "cross-file node is not compared by line number",
                    node,
                    node,
                    boundaries=skipped_boundaries,
                )
            )

    output_entry = dict(entry)
    output_trace: list[dict[str, Any]] = []
    for index, node in enumerate(trace):
        if can_fix and index in removals:
            continue
        output_node = dict(node)
        if can_fix and index in desc_updates:
            output_node["desc"] = desc_updates[index]
        output_trace.append(output_node)
    output_entry["trace"] = output_trace
    return output_entry, events, removals, manual_review


def process_entries(
    entries: list[dict[str, Any]],
    *,
    mode: str,
    dedupe_desc_conflicts: bool = False,
    fix_verified: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    output: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    removed_nodes = 0
    review_nodes: set[tuple[str, int]] = set()
    duplicate_groups = 0
    duplicate_nodes = 0
    duplicate_desc_conflict_groups = 0

    for entry in entries:
        groups: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)
        for node in entry["trace"]:
            groups[node_key(node)].append(node)
        for nodes in groups.values():
            if len(nodes) < 2:
                continue
            duplicate_groups += 1
            duplicate_nodes += len(nodes) - 1
            nonempty_descs = {node.get("desc") for node in nodes if node.get("desc")}
            if len(nonempty_descs) > 1:
                duplicate_desc_conflict_groups += 1

    for entry in entries:
        processed, entry_events, removals, manual_review = process_entry(
            entry,
            mode=mode,
            dedupe_desc_conflicts=dedupe_desc_conflicts,
            fix_verified=fix_verified,
        )
        output.append(processed)
        events.extend(entry_events)
        removed_nodes += len(removals)
        review_nodes.update((entry["entry_id"], index) for index in manual_review)

    validate_dataset(output)
    event_counts = Counter(event["kind"] for event in events)
    action_counts = Counter(event["action"] for event in events)
    structural_kinds = {
        "after_critical_operation",
        "before_entry_point",
        "duplicate",
        "duplicate_desc_conflict",
    }
    anomaly_entries = {
        event["entry_id"] for event in events if event["kind"] in structural_kinds
    }
    modified_entries = sum(
        original["trace"] != processed["trace"]
        for original, processed in zip(entries, output)
    )
    report = {
        "mode": mode,
        "entries_scanned": len(entries),
        "entries_with_anomalies": len(anomaly_entries),
        "entries_modified": modified_entries,
        "trace_nodes_scanned": sum(len(entry["trace"]) for entry in entries),
        "trace_nodes_written": sum(len(entry["trace"]) for entry in output),
        "duplicate_candidate_groups": duplicate_groups,
        "duplicate_candidate_nodes": duplicate_nodes,
        "duplicate_desc_conflict_groups": duplicate_desc_conflict_groups,
        "order_anomalies": event_counts["before_entry_point"]
        + event_counts["after_critical_operation"],
        "cross_file_comparisons_skipped": sum(
            len(event.get("details", {}).get("boundaries", ()))
            for event in events
            if event["kind"] == "cross_file_skipped"
        ),
        "removed_nodes": removed_nodes,
        "manual_review_nodes": len(review_nodes),
        "verified_entries_protected": mode == "fix" and not fix_verified,
        "event_counts": dict(sorted(event_counts.items())),
        "action_counts": dict(sorted(action_counts.items())),
    }
    return output, events, report


def _atomic_write(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        temporary_path = Path(stream.name)
        try:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    def writer(stream: Any) -> None:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    _atomic_write(path, writer)


def write_json(path: Path, value: dict[str, Any]) -> None:
    def writer(stream: Any) -> None:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")

    _atomic_write(path, writer)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT)
    parser.add_argument(
        "--mode",
        choices=("report", "fix"),
        default="report",
        help="report only (default), or remove deterministic anomalies",
    )
    parser.add_argument("--output", type=Path, help="fixed JSONL output; required in fix mode")
    parser.add_argument(
        "--log-output", type=Path, default=Path("trace_fix_log.jsonl")
    )
    parser.add_argument(
        "--report-output", type=Path, default=Path("trace_fix_report.json")
    )
    parser.add_argument(
        "--dedupe-desc-conflicts",
        action="store_true",
        help="in fix mode, remove duplicate keys even when their desc values differ",
    )
    parser.add_argument(
        "--fix-verified",
        action="store_true",
        help="allow fix mode to modify human-reviewed entries (verify=1)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.mode == "fix" and args.output is None:
        parser.error("--output is required in fix mode")
    if args.dedupe_desc_conflicts and args.mode != "fix":
        parser.error("--dedupe-desc-conflicts requires --mode fix")
    if args.fix_verified and args.mode != "fix":
        parser.error("--fix-verified requires --mode fix")
    output_paths = [args.log_output.resolve(), args.report_output.resolve()]
    if args.output:
        output_paths.append(args.output.resolve())
    if args.input.resolve() in output_paths:
        parser.error("refusing to overwrite the input file")
    if len(output_paths) != len(set(output_paths)):
        parser.error("output, log, and report paths must be different")

    try:
        entries = load_jsonl(args.input)
        output, events, report = process_entries(
            entries,
            mode=args.mode,
            dedupe_desc_conflicts=args.dedupe_desc_conflicts,
            fix_verified=args.fix_verified,
        )
        if args.output:
            write_jsonl(args.output, output)
        write_jsonl(args.log_output, events)
        write_json(args.report_output, report)
    except (OSError, DataValidationError) as error:
        parser.exit(1, f"error: {error}\n")

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"audit log: {args.log_output}")
    print(f"report: {args.report_output}")
    if args.output:
        print(f"data: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
