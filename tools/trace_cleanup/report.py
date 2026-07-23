from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from .io import atomic_write_text
from .models import ApplyResult, Decision, DetectionResult


CSV_FIELDS = [
    "entry_id",
    "report_id",
    "verify",
    "rule_id",
    "status",
    "field_path",
    "trace_index",
    "file",
    "raw_line",
    "boundary_role",
    "boundary_file",
    "boundary_raw_line",
    "relation",
    "before",
    "after",
    "kept_index",
    "reason",
]
_RULE_ORDER = {
    "duplicate_trace_node": 0,
    "before_entry_definite": 1,
    "after_critical_definite": 2,
    "overlap_entry": 3,
    "overlap_critical": 4,
    "cross_file_skipped": 5,
}


def _json_cell(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _sort_key(decision: Decision) -> tuple:
    finding = decision.finding
    return (
        finding.entry_id,
        finding.trace_index,
        _RULE_ORDER.get(finding.rule_id, 99),
        finding.field_path,
    )


def _row(decision: Decision) -> dict[str, Any]:
    finding = decision.finding
    return {
        "entry_id": finding.entry_id,
        "report_id": finding.report_id,
        "verify": finding.verify,
        "rule_id": finding.rule_id,
        "status": decision.status,
        "field_path": finding.field_path,
        "trace_index": finding.trace_index,
        "file": finding.file,
        "raw_line": _json_cell(finding.raw_line),
        "boundary_role": finding.boundary_role,
        "boundary_file": finding.boundary_file,
        "boundary_raw_line": _json_cell(finding.boundary_raw_line),
        "relation": finding.relation,
        "before": _json_cell(finding.before),
        "after": _json_cell(finding.after),
        "kept_index": "" if finding.kept_index is None else finding.kept_index,
        "reason": finding.reason,
    }


def _csv_text(decisions: list[Decision]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=CSV_FIELDS,
        lineterminator="\n",
    )
    writer.writeheader()
    for decision in sorted(decisions, key=_sort_key):
        writer.writerow(_row(decision))
    return stream.getvalue()


def build_summary(
    detection: DetectionResult,
    decisions: list[Decision],
    application: ApplyResult,
    *,
    mode: str,
    duplicate_action: str,
    order_action: str,
    input_sha256: str,
    output_sha256: str | None = None,
) -> dict[str, Any]:
    rules = [decision.finding.rule_id for decision in decisions]
    statuses = [decision.status for decision in decisions]
    summary: dict[str, Any] = {
        "entries_scanned": detection.entries_scanned,
        "trace_nodes_scanned": detection.trace_nodes_scanned,
        "duplicate_groups": detection.duplicate_groups,
        "duplicate_extra_nodes": detection.duplicate_extra_nodes,
        "before_entry_findings": rules.count("before_entry_definite"),
        "after_critical_findings": rules.count("after_critical_definite"),
        "overlap_findings": sum(rule.startswith("overlap_") for rule in rules),
        "cross_file_skipped": statuses.count("skipped_cross_file"),
        "auto_fixed": statuses.count("auto_fixed"),
        "manual_review": statuses.count("manual_review"),
        "protected_verified": statuses.count("protected_verified"),
        "changed_entries": application.changed_entries,
        "input_sha256": input_sha256,
    }
    if output_sha256 is not None:
        summary["output_sha256"] = output_sha256
    summary.update(
        {
            "mode": mode,
            "duplicate_action": duplicate_action,
            "order_action": order_action,
        }
    )
    return summary


def write_reports(
    reports_dir: Path,
    decisions: list[Decision],
    summary: dict[str, Any],
    *,
    include_fix_log: bool,
) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        reports_dir / "trace_findings.csv",
        _csv_text(decisions),
    )
    needs_human = [
        decision for decision in decisions
        if decision.status in {
            "reported",
            "manual_review",
            "protected_verified",
        }
    ]
    atomic_write_text(
        reports_dir / "trace_needs_human.csv",
        _csv_text(needs_human),
    )
    atomic_write_text(
        reports_dir / "trace_summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
    )
    if include_fix_log:
        fixed = [
            decision for decision in decisions
            if decision.status == "auto_fixed"
        ]
        atomic_write_text(
            reports_dir / "trace_fix_log.csv",
            _csv_text(fixed),
        )
