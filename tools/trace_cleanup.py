#!/usr/bin/env python3
"""Detect and conservatively repair structural problems in VulnGym traces.

The default mode only reports findings. ``--mode fix`` removes exact trace
duplicates and nodes that are wholly outside a same-file boundary. Human-
verified entries are still report-only unless ``--include-verified`` is used.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import re
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


ENTRY_ID_RE = re.compile(r"^entry-\d{5}$")
GHSA_RE = re.compile(r"^GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")

ENTRY_REQUIRED_FIELDS = {
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
INTERNAL_FIELDS = {
    "annotated_by",
    "created_at",
    "description",
    "detection_type",
    "generality",
    "ground_truth",
    "human_remark",
    "is_active",
    "pipeline_id",
    "taint_sink",
    "taint_source",
    "vuln_category_l3",
}
NODE_REQUIRED_FIELDS = {"file", "line", "code"}
LOG_FIELDS = [
    "entry_id",
    "field_path",
    "finding",
    "action",
    "before",
    "after",
    "reason",
    "comparison",
]
SUMMARY_KEYS = {
    "auto_fixes",
    "boundary_inversions",
    "critical_boundary_overlaps",
    "cross_file_comparisons_skipped",
    "cross_file_log_records",
    "cross_file_nodes",
    "description_conflicts",
    "description_sync_candidates",
    "descriptions_synced",
    "duplicate_candidates",
    "duplicate_nodes_removed",
    "entries_modified",
    "entries_scanned",
    "entries_that_would_change",
    "entries_with_cross_file_skips",
    "entries_with_structural_findings",
    "entry_before_boundary",
    "entry_before_boundary_obvious",
    "entry_boundary_overlaps",
    "log_records",
    "manual_review_findings",
    "out_of_bounds_nodes_removed",
    "output_entries",
    "reported_findings",
    "trace_after_critical_operation",
    "trace_after_critical_operation_obvious",
    "trace_nodes_removed",
    "trace_nodes_scanned",
    "unverified_entries",
    "verified_entries",
}


class SchemaError(ValueError):
    """Raised when an input or generated entry violates SCHEMA.md basics."""


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int


@dataclass(frozen=True)
class Finding:
    entry_id: str
    field_path: str
    finding: str
    action: str
    before: Any
    after: Any
    reason: str
    comparison: str = ""

    def as_csv_row(self) -> dict[str, str]:
        return {
            "entry_id": self.entry_id,
            "field_path": self.field_path,
            "finding": self.finding,
            "action": self.action,
            "before": json.dumps(
                self.before, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
            "after": json.dumps(
                self.after, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
            "reason": self.reason,
            "comparison": self.comparison,
        }


@dataclass
class EntryScanResult:
    entry: dict[str, Any]
    findings: list[Finding]
    stats: Counter[str]
    structural_finding: bool
    cross_file_skip: bool
    would_modify: bool
    modified: bool


def parse_line_span(value: Any, field_path: str = "line") -> LineSpan:
    """Normalize a SCHEMA.md line value into an inclusive span."""
    if isinstance(value, bool):
        raise SchemaError(f"{field_path}: boolean is not a valid line number")
    if isinstance(value, int):
        if value < 1:
            raise SchemaError(f"{field_path}: line must be >= 1, got {value}")
        return LineSpan(value, value)
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if not match:
            raise SchemaError(
                f"{field_path}: expected a positive integer or 'start-end', got {value!r}"
            )
        start, end = (int(part) for part in match.groups())
        if start > end:
            raise SchemaError(f"{field_path}: range start {start} exceeds end {end}")
        return LineSpan(start, end)
    raise SchemaError(
        f"{field_path}: expected a positive integer or range string, got {type(value).__name__}"
    )


def _require_string(value: Any, field_path: str) -> None:
    if not isinstance(value, str):
        raise SchemaError(f"{field_path}: expected string, got {type(value).__name__}")


def validate_node(node: Any, field_path: str) -> None:
    if not isinstance(node, dict):
        raise SchemaError(f"{field_path}: expected object, got {type(node).__name__}")
    missing = NODE_REQUIRED_FIELDS - node.keys()
    if missing:
        raise SchemaError(f"{field_path}: missing required fields {sorted(missing)}")
    _require_string(node["file"], f"{field_path}.file")
    _require_string(node["code"], f"{field_path}.code")
    parse_line_span(node["line"], f"{field_path}.line")
    if "desc" in node:
        _require_string(node["desc"], f"{field_path}.desc")


def validate_entries(entries: Sequence[dict[str, Any]]) -> None:
    """Validate the entry-level SCHEMA.md invariants affected by this tool."""
    seen_ids: set[str] = set()
    ordered_ids: list[str] = []
    scalar_string_fields = [
        "origin",
        "project",
        "repo_url",
        "report_id",
        "source_link",
        "vuln_category_l1",
        "vuln_category_l2",
        "vuln_title",
    ]

    for row_number, entry in enumerate(entries, start=1):
        prefix = f"entries[{row_number}]"
        if not isinstance(entry, dict):
            raise SchemaError(f"{prefix}: expected object")
        missing = ENTRY_REQUIRED_FIELDS - entry.keys()
        if missing:
            raise SchemaError(f"{prefix}: missing required fields {sorted(missing)}")
        internal = INTERNAL_FIELDS & entry.keys()
        if internal:
            raise SchemaError(f"{prefix}: contains internal fields {sorted(internal)}")

        for field in scalar_string_fields:
            _require_string(entry[field], f"{prefix}.{field}")

        entry_id = entry["entry_id"]
        _require_string(entry_id, f"{prefix}.entry_id")
        if not ENTRY_ID_RE.fullmatch(entry_id):
            raise SchemaError(f"{prefix}.entry_id: invalid value {entry_id!r}")
        if entry_id in seen_ids:
            raise SchemaError(f"{prefix}.entry_id: duplicate value {entry_id!r}")
        seen_ids.add(entry_id)
        ordered_ids.append(entry_id)

        report_id = entry["report_id"]
        if not GHSA_RE.fullmatch(report_id):
            raise SchemaError(f"{prefix}.report_id: invalid GHSA id {report_id!r}")
        source_link = entry["source_link"]
        if "github.com/advisories/" not in source_link.lower():
            raise SchemaError(f"{prefix}.source_link: not a GitHub advisory URL")
        if source_link.rstrip("/").rsplit("/", 1)[-1].upper() != report_id:
            raise SchemaError(f"{prefix}.source_link: GHSA id does not match report_id")
        if entry["origin"] != "GitHub Advisory Database (reviewed)":
            raise SchemaError(f"{prefix}.origin: unexpected value {entry['origin']!r}")
        if not entry["repo_url"].startswith("https://github.com/"):
            raise SchemaError(f"{prefix}.repo_url: expected https://github.com/ URL")
        if not isinstance(entry["commit"], str) or not COMMIT_RE.fullmatch(entry["commit"]):
            raise SchemaError(f"{prefix}.commit: expected 40 lowercase hexadecimal characters")

        verify = entry["verify"]
        if isinstance(verify, bool) or not isinstance(verify, int) or verify not in {0, 1}:
            raise SchemaError(f"{prefix}.verify: expected integer 0 or 1")
        vuln_ids = entry["vuln_ids"]
        if not isinstance(vuln_ids, list) or not all(
            isinstance(item, str) for item in vuln_ids
        ):
            raise SchemaError(f"{prefix}.vuln_ids: expected string array")

        validate_node(entry["entry_point"], f"{prefix}.entry_point")
        validate_node(entry["critical_operation"], f"{prefix}.critical_operation")
        trace = entry["trace"]
        if not isinstance(trace, list):
            raise SchemaError(f"{prefix}.trace: expected array")
        for trace_index, node in enumerate(trace):
            validate_node(node, f"{prefix}.trace[{trace_index}]")

    if ordered_ids != sorted(ordered_ids):
        raise SchemaError("entries are not sorted by entry_id")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SchemaError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(value, dict):
                raise SchemaError(f"{path}:{line_number}: expected a JSON object")
            entries.append(value)
    return entries


def write_jsonl(path: Path, entries: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def write_log(path: Path, findings: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOG_FIELDS, lineterminator="\n")
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.as_csv_row())


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _node_key(node: dict[str, Any]) -> tuple[str, Any, str]:
    return node["file"], node["line"], node["code"]


def _meaningful_desc(node: dict[str, Any]) -> str | None:
    desc = node.get("desc")
    if isinstance(desc, str) and desc.strip():
        return desc
    return None


def _comparison(node_span: LineSpan, boundary_span: LineSpan) -> str:
    return (
        f"trace={node_span.start}-{node_span.end};"
        f" boundary={boundary_span.start}-{boundary_span.end}"
    )


def scan_entry(
    source_entry: dict[str, Any], mode: str, include_verified: bool
) -> EntryScanResult:
    entry = copy.deepcopy(source_entry)
    entry_id = entry["entry_id"]
    trace: list[dict[str, Any]] = entry["trace"]
    entry_point = entry["entry_point"]
    critical_operation = entry["critical_operation"]
    entry_span = parse_line_span(entry_point["line"], f"{entry_id}.entry_point.line")
    critical_span = parse_line_span(
        critical_operation["line"], f"{entry_id}.critical_operation.line"
    )
    eligible_for_fix = mode == "fix" and (
        entry["verify"] == 0 or include_verified
    )

    findings: list[Finding] = []
    stats: Counter[str] = Counter()
    duplicate_indices: set[int] = set()
    obvious_out_of_bounds: set[int] = set()
    planned_desc: dict[int, str] = {}
    structural_finding = False
    cross_file_skip = False
    cross_file_details: list[dict[str, Any]] = []
    would_modify = False

    first_by_key: dict[tuple[str, Any, str], int] = {}
    for index, node in enumerate(trace):
        key = _node_key(node)
        first_index = first_by_key.get(key)
        if first_index is None:
            first_by_key[key] = index
            continue

        structural_finding = True
        would_modify = True
        stats["duplicate_candidates"] += 1
        duplicate_indices.add(index)
        first_node = trace[first_index]
        kept_desc = planned_desc.get(first_index) or _meaningful_desc(first_node)
        duplicate_desc = _meaningful_desc(node)

        if eligible_for_fix:
            duplicate_action = "remove"
            duplicate_reason = (
                f"exact trace duplicate of trace[{first_index}]; keep first occurrence"
            )
        elif mode == "fix" and entry["verify"] == 1:
            duplicate_action = "manual_review"
            duplicate_reason = (
                f"exact trace duplicate of trace[{first_index}], but verify=1 entries are report-only"
            )
        else:
            duplicate_action = "report_only"
            duplicate_reason = (
                f"exact trace duplicate of trace[{first_index}]; conservative mode makes no changes"
            )

        findings.append(
            Finding(
                entry_id=entry_id,
                field_path=f"trace[{index}]",
                finding="duplicate_node",
                action=duplicate_action,
                before=node,
                after=None if eligible_for_fix else node,
                reason=duplicate_reason,
                comparison=f"same_as=trace[{first_index}]",
            )
        )

        if kept_desc is None and duplicate_desc is not None:
            planned_desc[first_index] = duplicate_desc
            stats["description_sync_candidates"] += 1
            updated = copy.deepcopy(first_node)
            updated["desc"] = duplicate_desc
            if eligible_for_fix:
                action = "sync_description"
                reason = f"kept trace[{first_index}] had no description; copied it from duplicate trace[{index}]"
            elif mode == "fix" and entry["verify"] == 1:
                action = "manual_review"
                reason = "description could be synchronized, but verify=1 entries are report-only"
            else:
                action = "report_only"
                reason = "description could be synchronized; conservative mode makes no changes"
            findings.append(
                Finding(
                    entry_id=entry_id,
                    field_path=f"trace[{first_index}].desc",
                    finding="duplicate_description_sync",
                    action=action,
                    before=first_node,
                    after=updated if eligible_for_fix else first_node,
                    reason=reason,
                    comparison=f"description_from=trace[{index}]",
                )
            )
        elif kept_desc is not None and duplicate_desc is not None and kept_desc != duplicate_desc:
            stats["description_conflicts"] += 1
            findings.append(
                Finding(
                    entry_id=entry_id,
                    field_path=f"trace[{first_index}].desc",
                    finding="duplicate_description_conflict",
                    action="manual_review",
                    before=first_node,
                    after=first_node,
                    reason=(
                        f"trace[{first_index}] and duplicate trace[{index}] have different non-empty descriptions; "
                        "the first description is retained"
                    ),
                    comparison=f"conflicts_with=trace[{index}]",
                )
            )

    boundary_inverted = (
        entry_point["file"] == critical_operation["file"]
        and entry_span.start > critical_span.end
    )
    if boundary_inverted:
        structural_finding = True
        stats["boundary_inversions"] += 1
        findings.append(
            Finding(
                entry_id=entry_id,
                field_path="entry_point.line,critical_operation.line",
                finding="boundary_inversion",
                action="manual_review",
                before={
                    "entry_point": entry_point,
                    "critical_operation": critical_operation,
                },
                after={
                    "entry_point": entry_point,
                    "critical_operation": critical_operation,
                },
                reason=(
                    "entry_point starts after critical_operation in the same file; "
                    "trace nodes in this file are not auto-removed"
                ),
                comparison=(
                    f"entry_point={entry_span.start}-{entry_span.end};"
                    f" critical_operation={critical_span.start}-{critical_span.end}"
                ),
            )
        )

    for index, node in enumerate(trace):
        node_span = parse_line_span(node["line"], f"{entry_id}.trace[{index}].line")
        skipped_boundaries: list[str] = []
        compared_boundaries: list[str] = []

        if node["file"] == entry_point["file"]:
            if not boundary_inverted:
                compared_boundaries.append("entry_point")
            if not boundary_inverted and node_span.start < entry_span.start:
                structural_finding = True
                stats["entry_before_boundary"] += 1
                wholly_before = node_span.end < entry_span.start
                if wholly_before:
                    stats["entry_before_boundary_obvious"] += 1
                    obvious_out_of_bounds.add(index)
                    would_modify = True
                else:
                    stats["entry_boundary_overlaps"] += 1

                if wholly_before and eligible_for_fix:
                    if index in duplicate_indices:
                        action = "already_removed_duplicate"
                    else:
                        action = "remove"
                    after: Any = None
                    reason = "trace span is wholly before the same-file entry_point boundary"
                elif wholly_before and mode == "fix" and entry["verify"] == 1:
                    action = "manual_review"
                    after = node
                    reason = "trace span is wholly before entry_point, but verify=1 entries are report-only"
                elif wholly_before:
                    action = "report_only"
                    after = node
                    reason = "trace span is wholly before entry_point; conservative mode makes no changes"
                else:
                    action = "manual_review"
                    after = node
                    reason = (
                        "trace range starts before entry_point but overlaps its boundary; "
                        "not safe to auto-remove"
                    )

                findings.append(
                    Finding(
                        entry_id=entry_id,
                        field_path=f"trace[{index}]",
                        finding="trace_before_entry_point",
                        action=action,
                        before=node,
                        after=after,
                        reason=reason,
                        comparison=_comparison(node_span, entry_span),
                    )
                )
        elif node["file"] != entry_point["file"]:
            skipped_boundaries.append("entry_point")

        if node["file"] == critical_operation["file"]:
            if not boundary_inverted:
                compared_boundaries.append("critical_operation")
            if not boundary_inverted and node_span.end > critical_span.end:
                structural_finding = True
                stats["trace_after_critical_operation"] += 1
                wholly_after = node_span.start > critical_span.end
                if wholly_after:
                    stats["trace_after_critical_operation_obvious"] += 1
                    obvious_out_of_bounds.add(index)
                    would_modify = True
                else:
                    stats["critical_boundary_overlaps"] += 1

                if wholly_after and eligible_for_fix:
                    if index in duplicate_indices:
                        action = "already_removed_duplicate"
                    else:
                        action = "remove"
                    after = None
                    reason = "trace span is wholly after the same-file critical_operation boundary"
                elif wholly_after and mode == "fix" and entry["verify"] == 1:
                    action = "manual_review"
                    after = node
                    reason = (
                        "trace span is wholly after critical_operation, but verify=1 entries are report-only"
                    )
                elif wholly_after:
                    action = "report_only"
                    after = node
                    reason = (
                        "trace span is wholly after critical_operation; conservative mode makes no changes"
                    )
                else:
                    action = "manual_review"
                    after = node
                    reason = (
                        "trace range ends after critical_operation but overlaps its boundary; "
                        "not safe to auto-remove"
                    )

                findings.append(
                    Finding(
                        entry_id=entry_id,
                        field_path=f"trace[{index}]",
                        finding="trace_after_critical_operation",
                        action=action,
                        before=node,
                        after=after,
                        reason=reason,
                        comparison=_comparison(node_span, critical_span),
                    )
                )
        elif node["file"] != critical_operation["file"]:
            skipped_boundaries.append("critical_operation")

        if skipped_boundaries:
            cross_file_skip = True
            stats["cross_file_nodes"] += 1
            stats["cross_file_comparisons_skipped"] += len(skipped_boundaries)
            cross_file_details.append(
                {
                    "compared": compared_boundaries,
                    "node_file": node["file"],
                    "skipped": skipped_boundaries,
                    "trace_index": index,
                }
            )

    if cross_file_details:
        stats["cross_file_log_records"] += 1
        findings.append(
            Finding(
                entry_id=entry_id,
                field_path="trace",
                finding="cross_file_comparison_skipped",
                action="skip",
                before=None,
                after=None,
                reason="跨文件，不参与行号比较；原始 trace 顺序保持不变（按 entry 聚合）",
                comparison=json.dumps(
                    cross_file_details,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        )

    modified = False
    if eligible_for_fix:
        for first_index, description in planned_desc.items():
            if _meaningful_desc(trace[first_index]) is None:
                trace[first_index]["desc"] = description
                stats["descriptions_synced"] += 1
                modified = True

        remove_indices = duplicate_indices | obvious_out_of_bounds
        if remove_indices:
            entry["trace"] = [
                node for index, node in enumerate(trace) if index not in remove_indices
            ]
            stats["duplicate_nodes_removed"] += len(duplicate_indices)
            stats["out_of_bounds_nodes_removed"] += len(
                obvious_out_of_bounds - duplicate_indices
            )
            stats["trace_nodes_removed"] += len(remove_indices)
            modified = True

    stats["manual_review_findings"] += sum(
        finding.action == "manual_review" for finding in findings
    )
    stats["reported_findings"] += sum(
        finding.action == "report_only" for finding in findings
    )
    stats["log_records"] += len(findings)
    if modified:
        stats["entries_modified"] += 1

    return EntryScanResult(
        entry=entry,
        findings=findings,
        stats=stats,
        structural_finding=structural_finding,
        cross_file_skip=cross_file_skip,
        would_modify=would_modify,
        modified=modified,
    )


def process_entries(
    entries: Sequence[dict[str, Any]], mode: str, include_verified: bool = False
) -> tuple[list[dict[str, Any]], list[Finding], dict[str, int]]:
    if mode not in {"report", "fix"}:
        raise ValueError(f"unsupported mode: {mode}")

    output: list[dict[str, Any]] = []
    findings: list[Finding] = []
    totals: Counter[str] = Counter()
    entries_with_structural_findings = 0
    entries_with_cross_file_skips = 0
    entries_that_would_change = 0

    for entry in entries:
        result = scan_entry(entry, mode=mode, include_verified=include_verified)
        output.append(result.entry)
        findings.extend(result.findings)
        totals.update(result.stats)
        totals["entries_scanned"] += 1
        totals["trace_nodes_scanned"] += len(entry["trace"])
        totals["verified_entries"] += entry["verify"] == 1
        totals["unverified_entries"] += entry["verify"] == 0
        entries_with_structural_findings += result.structural_finding
        entries_with_cross_file_skips += result.cross_file_skip
        entries_that_would_change += result.would_modify

    totals["entries_with_structural_findings"] = entries_with_structural_findings
    totals["entries_with_cross_file_skips"] = entries_with_cross_file_skips
    totals["entries_that_would_change"] = entries_that_would_change
    totals["output_entries"] = len(output)
    totals["auto_fixes"] = (
        totals["trace_nodes_removed"] + totals["descriptions_synced"]
    )
    for key in SUMMARY_KEYS:
        totals.setdefault(key, 0)
    return output, findings, dict(sorted(totals.items()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Detect duplicate and same-file boundary anomalies in VulnGym trace arrays. "
            "The default report mode does not modify any entry."
        )
    )
    parser.add_argument("--input", type=Path, default=Path("data/entries.jsonl"))
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "output JSONL (default: data/entries.trace_reported.jsonl in report mode, "
            "data/entries.trace_fixed.jsonl in fix mode)"
        ),
    )
    parser.add_argument(
        "--log",
        type=Path,
        help=(
            "CSV log (default: trace_report_log.csv in report mode, "
            "trace_fix_log.csv in fix mode)"
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        help=(
            "JSON report (default: trace_report.json in report mode, "
            "trace_cleanup_report.json in fix mode)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("report", "fix"),
        default="report",
        help="report only (default), or apply deterministic fixes",
    )
    parser.add_argument(
        "--include-verified",
        action="store_true",
        help="allow fix mode to modify verify=1 entries (disabled by default)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_path = args.output or Path(
        "data/entries.trace_fixed.jsonl"
        if args.mode == "fix"
        else "data/entries.trace_reported.jsonl"
    )
    log_path = args.log or Path(
        "trace_fix_log.csv" if args.mode == "fix" else "trace_report_log.csv"
    )
    report_path = args.report or Path(
        "trace_cleanup_report.json" if args.mode == "fix" else "trace_report.json"
    )
    entries = load_jsonl(args.input)
    validate_entries(entries)
    output, findings, summary = process_entries(
        entries, mode=args.mode, include_verified=args.include_verified
    )
    validate_entries(output)

    if args.mode == "report":
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.resolve() != args.input.resolve():
            shutil.copyfile(args.input, output_path)
    else:
        write_jsonl(output_path, output)
    write_log(log_path, findings)
    report = {
        "include_verified": args.include_verified,
        "input": args.input.as_posix(),
        "input_sha256": _sha256(args.input),
        "log": log_path.as_posix(),
        "mode": args.mode,
        "output": output_path.as_posix(),
        "schema_validation": {
            "entries": len(output),
            "passed": True,
            "scope": "SCHEMA.md entry-level basic invariants",
        },
        "summary": summary,
    }
    report["output_sha256"] = _sha256(output_path)
    write_report(report_path, report)

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
