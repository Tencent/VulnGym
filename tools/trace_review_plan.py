#!/usr/bin/env python3
"""Create and apply stale-safe human decisions for trace cleanup candidates."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import io
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "entries.jsonl"
DEFAULT_PLAN = ROOT / "reports" / "trace_review_plan.csv"
DEFAULT_REPORT = ROOT / "reports" / "trace_review_plan_report.json"
DEFAULT_OUTPUT = ROOT / "data" / "entries.trace_reviewed.jsonl"
DEFAULT_DIFF = ROOT / "reports" / "trace_review_diff.csv"
DEFAULT_AUDIT = ROOT / "reports" / "trace_review_audit.csv"

LINE_RANGE_RE = re.compile(r"([1-9]\d*)-([1-9]\d*)")
DECISIONS = {"", "keep", "remove"}

PLAN_FIELDS = (
    "event_id",
    "dataset_sha256",
    "entry_id",
    "entry_verify",
    "entry_sha256",
    "trace_index",
    "candidate_types",
    "node_sha256",
    "expected_node_json",
    "references_json",
    "suggested_decision",
    "reason",
    "decision",
    "reviewer",
    "rationale",
)

IMMUTABLE_PLAN_FIELDS = PLAN_FIELDS[:12]

DIFF_FIELDS = (
    "event_id",
    "entry_id",
    "original_trace_index",
    "candidate_types",
    "old_node_json",
    "reviewer",
    "rationale",
)

AUDIT_FIELDS = (
    "event_id",
    "entry_id",
    "original_trace_index",
    "candidate_types",
    "decision",
    "status",
    "reviewer",
    "rationale",
    "node_sha256",
    "entry_sha256",
)


class ReviewPlanError(ValueError):
    """Raised when a plan cannot be trusted or applied safely."""


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def line_span(value: object) -> tuple[int, int]:
    if type(value) is int and value > 0:
        return value, value
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value.strip())
        if match:
            start, end = int(match[1]), int(match[2])
            if start <= end:
                return start, end
    raise ReviewPlanError(f"invalid line value: {value!r}")


def normalize_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ReviewPlanError(f"invalid repository path: {value!r}")
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return re.sub(r"/+", "/", normalized)


def validate_node(node: object, label: str) -> dict:
    if not isinstance(node, dict):
        raise ReviewPlanError(f"{label} must be an object")
    missing = [key for key in ("file", "line", "code") if key not in node]
    if missing:
        raise ReviewPlanError(f"{label} is missing: {', '.join(missing)}")
    normalize_path(node["file"])
    line_span(node["line"])
    if not isinstance(node["code"], str):
        raise ReviewPlanError(f"{label}.code must be a string")
    if "desc" in node and not isinstance(node["desc"], str):
        raise ReviewPlanError(f"{label}.desc must be a string when present")
    return node


def validate_entry(entry: object, row_number: int) -> dict:
    if not isinstance(entry, dict):
        raise ReviewPlanError(f"entry row {row_number} must be an object")
    entry_id = entry.get("entry_id")
    if not isinstance(entry_id, str) or not entry_id:
        raise ReviewPlanError(f"entry row {row_number} has an invalid entry_id")
    if entry.get("verify") not in (0, 1):
        raise ReviewPlanError(f"{entry_id}.verify must be 0 or 1")
    validate_node(entry.get("entry_point"), f"{entry_id}.entry_point")
    validate_node(
        entry.get("critical_operation"),
        f"{entry_id}.critical_operation",
    )
    trace = entry.get("trace")
    if not isinstance(trace, list):
        raise ReviewPlanError(f"{entry_id}.trace must be a list")
    for index, node in enumerate(trace):
        validate_node(node, f"{entry_id}.trace[{index}]")
    return entry


def load_entries(path: Path) -> list[dict]:
    entries: list[dict] = []
    seen_ids: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for row_number, line in enumerate(handle, 1):
            if not line.strip():
                raise ReviewPlanError(f"{path}:{row_number}: blank JSONL row")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReviewPlanError(f"{path}:{row_number}: {exc}") from exc
            validate_entry(entry, row_number)
            entry_id = entry["entry_id"]
            if entry_id in seen_ids:
                raise ReviewPlanError(f"duplicate entry_id: {entry_id}")
            seen_ids.add(entry_id)
            entries.append(entry)
    return entries


def duplicate_key(node: dict) -> tuple[object, object, object]:
    return node["file"], node["line"], node["code"]


def _event_id(
    entry_id: str,
    entry_sha256: str,
    trace_index: int,
    candidate_types: str,
    node_sha256: str,
    references_json: str,
) -> str:
    payload = canonical_json(
        {
            "entry_id": entry_id,
            "entry_sha256": entry_sha256,
            "trace_index": trace_index,
            "candidate_types": candidate_types,
            "node_sha256": node_sha256,
            "references_json": references_json,
        }
    )
    return "tr-" + sha256_text(payload)[:16]


def detect_candidates(
    entries: Iterable[dict],
    dataset_sha256: str,
) -> tuple[list[dict[str, str]], dict[str, object]]:
    candidates: list[dict[str, str]] = []
    counts: Counter[str] = Counter()

    for entry in entries:
        counts["entries_scanned"] += 1
        entry_id = entry["entry_id"]
        entry_digest = sha256_text(canonical_json(entry))
        entry_point = entry["entry_point"]
        critical = entry["critical_operation"]
        entry_file = normalize_path(entry_point["file"])
        critical_file = normalize_path(critical["file"])
        entry_start, _ = line_span(entry_point["line"])
        _, critical_end = line_span(critical["line"])
        seen: dict[tuple[object, object, object], tuple[int, dict]] = {}

        for index, node in enumerate(entry["trace"]):
            counts["trace_nodes_scanned"] += 1
            issues: list[str] = []
            reasons: list[str] = []
            references: dict[str, object] = {}

            key = duplicate_key(node)
            if key in seen:
                first_index, first_node = seen[key]
                counts["duplicate_candidates"] += 1
                references["duplicate"] = {
                    "first_trace_index": first_index,
                    "first_node": first_node,
                }
                if first_node == node:
                    issues.append("duplicate_exact")
                    counts["duplicate_exact"] += 1
                    reasons.append(
                        "same {file,line,code,desc} as "
                        f"trace[{first_index}]"
                    )
                else:
                    issues.append("duplicate_desc_conflict")
                    counts["duplicate_desc_conflicts"] += 1
                    reasons.append(
                        "same {file,line,code} as "
                        f"trace[{first_index}], but desc differs"
                    )
            else:
                seen[key] = (index, node)

            node_file = normalize_path(node["file"])
            node_start, node_end = line_span(node["line"])
            same_as_entry = node_file == entry_file
            same_as_critical = node_file == critical_file

            if same_as_entry and node_end < entry_start:
                issues.append("before_entry")
                counts["before_entry"] += 1
                references["entry_point"] = entry_point
                reasons.append(
                    f"trace range ends at {node_end} before entry point "
                    f"starts at {entry_start} in the same file"
                )

            if same_as_critical and node_start > critical_end:
                issues.append("after_critical")
                counts["after_critical"] += 1
                references["critical_operation"] = critical
                reasons.append(
                    f"trace range starts at {node_start} after critical "
                    f"operation ends at {critical_end} in the same file"
                )

            if not same_as_entry and not same_as_critical:
                counts["cross_file_skipped"] += 1

            if not issues:
                continue

            type_order = {
                "duplicate_exact": 0,
                "duplicate_desc_conflict": 1,
                "before_entry": 2,
                "after_critical": 3,
            }
            issues.sort(key=type_order.__getitem__)
            candidate_types = "|".join(issues)
            expected_node_json = canonical_json(node)
            references_json = canonical_json(references)
            node_digest = sha256_text(expected_node_json)
            suggested = "remove" if "duplicate_exact" in issues else "keep"
            event_id = _event_id(
                entry_id,
                entry_digest,
                index,
                candidate_types,
                node_digest,
                references_json,
            )
            candidates.append(
                {
                    "event_id": event_id,
                    "dataset_sha256": dataset_sha256,
                    "entry_id": entry_id,
                    "entry_verify": str(entry["verify"]),
                    "entry_sha256": entry_digest,
                    "trace_index": str(index),
                    "candidate_types": candidate_types,
                    "node_sha256": node_digest,
                    "expected_node_json": expected_node_json,
                    "references_json": references_json,
                    "suggested_decision": suggested,
                    "reason": "; ".join(reasons),
                    "decision": "",
                    "reviewer": "",
                    "rationale": "",
                }
            )
            counts["candidate_rows"] += 1
            counts[f"suggested_{suggested}"] += 1
            counts[f"verify_{entry['verify']}_candidates"] += 1

    report: dict[str, object] = {
        "schema_version": 1,
        "dataset_sha256": dataset_sha256,
        "entries_scanned": counts["entries_scanned"],
        "trace_nodes_scanned": counts["trace_nodes_scanned"],
        "candidate_rows": counts["candidate_rows"],
        "duplicate_candidates": counts["duplicate_candidates"],
        "duplicate_exact": counts["duplicate_exact"],
        "duplicate_desc_conflicts": counts["duplicate_desc_conflicts"],
        "before_entry": counts["before_entry"],
        "after_critical": counts["after_critical"],
        "cross_file_skipped": counts["cross_file_skipped"],
        "suggested_remove": counts["suggested_remove"],
        "suggested_keep": counts["suggested_keep"],
        "verified_candidates": counts["verify_1_candidates"],
        "unverified_candidates": counts["verify_0_candidates"],
    }
    return candidates, report


def _render_csv(fields: tuple[str, ...], rows: Iterable[dict[str, object]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def jsonl_newline(path: Path) -> str:
    with path.open("rb") as handle:
        sample = handle.read(1024 * 1024)
    return "\r\n" if b"\r\n" in sample else "\n"


def _render_jsonl(entries: Iterable[dict], newline: str = "\n") -> str:
    return "".join(
        json.dumps(entry, ensure_ascii=False, sort_keys=True) + newline
        for entry in entries
    )


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def ensure_distinct_paths(*paths: Path) -> None:
    resolved = [path.resolve() for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ReviewPlanError("input and output paths must all be distinct")


def create_plan(
    input_path: Path,
    plan_path: Path,
    report_path: Path,
) -> dict[str, object]:
    ensure_distinct_paths(input_path, plan_path, report_path)
    entries = load_entries(input_path)
    dataset_digest = file_sha256(input_path)
    candidates, report = detect_candidates(entries, dataset_digest)
    report = {
        **report,
        "input": str(input_path),
        "plan": str(plan_path),
    }
    atomic_write_text(plan_path, _render_csv(PLAN_FIELDS, candidates))
    atomic_write_text(
        report_path,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return report


def read_plan(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = [field for field in PLAN_FIELDS if field not in fields]
        if missing:
            raise ReviewPlanError(
                f"plan is missing columns: {', '.join(missing)}"
            )
        rows = [dict(row) for row in reader]
    if not rows:
        raise ReviewPlanError("plan has no candidate rows")
    return rows


def _validate_plan_rows(
    rows: list[dict[str, str]],
    expected: list[dict[str, str]],
    dataset_sha256: str,
    allow_pending: bool,
    include_verified: bool,
) -> dict[str, dict[str, str]]:
    expected_by_id = {row["event_id"]: row for row in expected}
    rows_by_id: dict[str, dict[str, str]] = {}

    for row_number, row in enumerate(rows, 2):
        event_id = row.get("event_id", "")
        if not event_id:
            raise ReviewPlanError(f"plan row {row_number} has no event_id")
        if event_id in rows_by_id:
            raise ReviewPlanError(f"duplicate event_id in plan: {event_id}")
        rows_by_id[event_id] = row

    expected_ids = set(expected_by_id)
    actual_ids = set(rows_by_id)
    if actual_ids != expected_ids:
        missing = sorted(expected_ids - actual_ids)
        unknown = sorted(actual_ids - expected_ids)
        details = []
        if missing:
            details.append(f"missing current events: {', '.join(missing[:5])}")
        if unknown:
            details.append(f"unknown or stale events: {', '.join(unknown[:5])}")
        raise ReviewPlanError("plan is incomplete or stale; " + "; ".join(details))

    for event_id, row in rows_by_id.items():
        expected_row = expected_by_id[event_id]
        for field in IMMUTABLE_PLAN_FIELDS:
            if row.get(field, "") != expected_row[field]:
                raise ReviewPlanError(
                    f"{event_id}: immutable field {field} does not match input"
                )
        if row["dataset_sha256"] != dataset_sha256:
            raise ReviewPlanError(
                f"{event_id}: plan was created for a different dataset"
            )

        decision = row.get("decision", "").strip().lower()
        row["decision"] = decision
        if decision not in DECISIONS:
            raise ReviewPlanError(
                f"{event_id}: decision must be remove, keep, or blank"
            )
        if not decision:
            if not allow_pending:
                raise ReviewPlanError(
                    f"{event_id}: pending decision; use --allow-pending to continue"
                )
            continue

        if not row.get("reviewer", "").strip():
            raise ReviewPlanError(f"{event_id}: reviewer is required")
        if not row.get("rationale", "").strip():
            raise ReviewPlanError(f"{event_id}: rationale is required")
        if (
            decision == "remove"
            and row["entry_verify"] == "1"
            and not include_verified
        ):
            raise ReviewPlanError(
                f"{event_id}: refusing to remove a verify=1 node; "
                "use --include-verified after explicit review"
            )

    return rows_by_id


def apply_plan(
    input_path: Path,
    plan_path: Path,
    output_path: Path,
    diff_path: Path,
    audit_path: Path,
    *,
    allow_pending: bool = False,
    include_verified: bool = False,
) -> dict[str, int]:
    ensure_distinct_paths(
        input_path,
        plan_path,
        output_path,
        diff_path,
        audit_path,
    )
    entries = load_entries(input_path)
    dataset_digest = file_sha256(input_path)
    expected, _ = detect_candidates(entries, dataset_digest)
    rows = read_plan(plan_path)
    rows_by_id = _validate_plan_rows(
        rows,
        expected,
        dataset_digest,
        allow_pending,
        include_verified,
    )

    remove_by_entry: dict[str, set[int]] = {}
    for candidate in expected:
        decision = rows_by_id[candidate["event_id"]]["decision"]
        if decision == "remove":
            remove_by_entry.setdefault(candidate["entry_id"], set()).add(
                int(candidate["trace_index"])
            )

    output_entries = copy.deepcopy(entries)
    entry_by_id = {entry["entry_id"]: entry for entry in output_entries}
    for entry_id, indices in remove_by_entry.items():
        trace = entry_by_id[entry_id]["trace"]
        entry_by_id[entry_id]["trace"] = [
            node for index, node in enumerate(trace) if index not in indices
        ]

    diff_rows: list[dict[str, str]] = []
    audit_rows: list[dict[str, str]] = []
    status_counts: Counter[str] = Counter()
    for candidate in expected:
        decision_row = rows_by_id[candidate["event_id"]]
        decision = decision_row["decision"]
        status = {
            "": "pending",
            "keep": "kept",
            "remove": "removed",
        }[decision]
        status_counts[status] += 1
        audit_rows.append(
            {
                "event_id": candidate["event_id"],
                "entry_id": candidate["entry_id"],
                "original_trace_index": candidate["trace_index"],
                "candidate_types": candidate["candidate_types"],
                "decision": decision,
                "status": status,
                "reviewer": decision_row.get("reviewer", "").strip(),
                "rationale": decision_row.get("rationale", "").strip(),
                "node_sha256": candidate["node_sha256"],
                "entry_sha256": candidate["entry_sha256"],
            }
        )
        if decision == "remove":
            diff_rows.append(
                {
                    "event_id": candidate["event_id"],
                    "entry_id": candidate["entry_id"],
                    "original_trace_index": candidate["trace_index"],
                    "candidate_types": candidate["candidate_types"],
                    "old_node_json": candidate["expected_node_json"],
                    "reviewer": decision_row["reviewer"].strip(),
                    "rationale": decision_row["rationale"].strip(),
                }
            )

    # All validation is complete before any externally visible output is replaced.
    atomic_write_text(
        output_path,
        _render_jsonl(output_entries, jsonl_newline(input_path)),
    )
    atomic_write_text(diff_path, _render_csv(DIFF_FIELDS, diff_rows))
    atomic_write_text(audit_path, _render_csv(AUDIT_FIELDS, audit_rows))
    return {
        "entries": len(output_entries),
        "removed": status_counts["removed"],
        "kept": status_counts["kept"],
        "pending": status_counts["pending"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser(
        "plan",
        help="detect candidates and create a fingerprinted decision sheet",
    )
    plan_parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    plan_parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    plan_parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)

    apply_parser = subparsers.add_parser(
        "apply",
        help="validate reviewed decisions and create trace cleanup outputs",
    )
    apply_parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    apply_parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    apply_parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    apply_parser.add_argument("--diff", type=Path, default=DEFAULT_DIFF)
    apply_parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    apply_parser.add_argument("--allow-pending", action="store_true")
    apply_parser.add_argument("--include-verified", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "plan":
            report = create_plan(args.input, args.plan, args.report)
            print(
                " ".join(
                    [
                        f"entries={report['entries_scanned']}",
                        f"trace_nodes={report['trace_nodes_scanned']}",
                        f"candidates={report['candidate_rows']}",
                        f"duplicates={report['duplicate_candidates']}",
                        f"desc_conflicts={report['duplicate_desc_conflicts']}",
                        f"before_entry={report['before_entry']}",
                        f"after_critical={report['after_critical']}",
                        f"cross_file_skipped={report['cross_file_skipped']}",
                    ]
                )
            )
        else:
            result = apply_plan(
                args.input,
                args.plan,
                args.output,
                args.diff,
                args.audit,
                allow_pending=args.allow_pending,
                include_verified=args.include_verified,
            )
            print(" ".join(f"{key}={value}" for key, value in result.items()))
    except (OSError, ReviewPlanError) as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
