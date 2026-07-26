#!/usr/bin/env python3
"""Verify that committed trace-cleanup artifacts are fresh and conservative."""

from __future__ import annotations

import csv
import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import trace_cleanup as cleanup

ROOT = Path(__file__).resolve().parent.parent
FIXED_PATH = ROOT / "data" / "entries.trace_fixed.jsonl"
REPORT_JSON = ROOT / "reports" / "trace_fix_report.json"
REPORT_MD = ROOT / "reports" / "trace_fix_report.md"
DIFF_CSV = ROOT / "reports" / "trace_fix_diff.csv"
REVIEW_CSV = ROOT / "reports" / "trace_review_queue.csv"
DAMAGED_TEXT_RE = re.compile(r"\?{4,}|\ufffd|绗\?|锛|鈥")
EXPECTED_CHANGED_IDS = {"entry-00103", "entry-00320"}
EXPECTED_REVIEW_IDS = {"entry-00185", "entry-00511"}


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def regenerate() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    args = cleanup.parse_args(["--mode", "fix"])
    source_rows = cleanup.load_jsonl(cleanup.DEFAULT_INPUT)
    logs: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    fixed_rows = [cleanup.process_entry(row, logs, stats, args) for row in source_rows]
    report = cleanup.build_report(
        input_path=cleanup.DEFAULT_INPUT,
        output_path=cleanup.DEFAULT_OUTPUT,
        original_rows=source_rows,
        fixed_rows=fixed_rows,
        logs=logs,
        stats=stats,
        args=args,
    )
    return source_rows, fixed_rows, logs, report


def assert_trace_subsequence(
    entry_id: str,
    original: list[dict[str, Any]],
    fixed: list[dict[str, Any]],
) -> None:
    cursor = 0
    for node in fixed:
        while cursor < len(original) and original[cursor] != node:
            cursor += 1
        if cursor == len(original):
            raise AssertionError(f"{entry_id} trace was reordered or gained a node")
        cursor += 1


def check_row_invariants(
    source_rows: list[dict[str, Any]], fixed_rows: list[dict[str, Any]]
) -> set[str]:
    if len(source_rows) != len(fixed_rows):
        raise AssertionError("fixed JSONL row count changed")
    if [row["entry_id"] for row in source_rows] != [
        row["entry_id"] for row in fixed_rows
    ]:
        raise AssertionError("fixed JSONL entry order changed")

    changed_ids = set()
    for before, after in zip(source_rows, fixed_rows, strict=True):
        before_metadata = {key: value for key, value in before.items() if key != "trace"}
        after_metadata = {key: value for key, value in after.items() if key != "trace"}
        if before_metadata != after_metadata:
            raise AssertionError(f"{before['entry_id']} changed a non-trace field")
        assert_trace_subsequence(before["entry_id"], before["trace"], after["trace"])
        if before != after:
            changed_ids.add(before["entry_id"])
    return changed_ids


def compare_generated_files(
    fixed_rows: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    report: dict[str, Any],
) -> None:
    if FIXED_PATH.read_bytes() != cleanup.rows_jsonl_bytes(fixed_rows):
        raise AssertionError("fixed JSONL is stale")
    if json.loads(REPORT_JSON.read_text(encoding="utf-8")) != report:
        raise AssertionError("JSON report is stale")

    with tempfile.TemporaryDirectory() as directory:
        temp_root = Path(directory)
        markdown = temp_root / "report.md"
        diff = temp_root / "diff.csv"
        review = temp_root / "review.csv"
        cleanup.write_report_markdown(markdown, report)
        cleanup.write_change_diff_csv(diff, logs)
        cleanup.write_review_queue_csv(review, logs)
        for expected, actual in (
            (REPORT_MD, markdown),
            (DIFF_CSV, diff),
            (REVIEW_CSV, review),
        ):
            if expected.read_bytes() != actual.read_bytes():
                raise AssertionError(f"{expected.name} is stale")


def check_audit_artifacts(
    changed_ids: set[str], logs: list[dict[str, Any]], report: dict[str, Any]
) -> tuple[int, int]:
    diff_rows = load_csv(DIFF_CSV)
    review_rows = load_csv(REVIEW_CSV)
    diff_ids = {row["entry_id"] for row in diff_rows}
    review_ids = {row["entry_id"] for row in review_rows}

    if changed_ids != EXPECTED_CHANGED_IDS:
        raise AssertionError(f"unexpected changed entries: {sorted(changed_ids)}")
    if diff_ids != changed_ids:
        raise AssertionError("compact diff does not match changed entries")
    if len(diff_rows) != len(cleanup.change_events(logs)):
        raise AssertionError("compact diff row count does not match applied events")
    if not EXPECTED_REVIEW_IDS <= review_ids:
        raise AssertionError("priority manual-review entries are missing")
    if report["changed_entry_ids"] != sorted(changed_ids):
        raise AssertionError("report changed-entry list is inconsistent")
    if report["artifacts"]["change_log_rows"] != len(diff_rows):
        raise AssertionError("report change-log count is inconsistent")
    if report["artifacts"]["review_queue_rows"] != len(review_rows):
        raise AssertionError("report review-queue count is inconsistent")
    return len(diff_rows), len(review_rows)


def check_text_integrity() -> None:
    for path in (REPORT_JSON, REPORT_MD, DIFF_CSV, REVIEW_CSV):
        text = path.read_text(encoding="utf-8")
        if DAMAGED_TEXT_RE.search(text):
            raise AssertionError(f"encoding damage pattern found in {path}")


def main() -> None:
    source_rows, fixed_rows, logs, report = regenerate()
    schema_errors = cleanup.validate_entries(fixed_rows)
    if schema_errors:
        raise AssertionError(f"fixed JSONL has schema errors: {schema_errors[:3]}")
    changed_ids = check_row_invariants(source_rows, fixed_rows)
    compare_generated_files(fixed_rows, logs, report)
    diff_rows, review_rows = check_audit_artifacts(changed_ids, logs, report)
    check_text_integrity()

    print("Trace cleanup artifacts verified")
    print("==============================")
    print(f"full rows: {len(fixed_rows)}")
    print(f"changed entries: {len(changed_ids)} ({', '.join(sorted(changed_ids))})")
    print(f"compact diff rows: {diff_rows}")
    print(f"aggregated review rows: {review_rows}")
    print("non-trace fields and entry order: unchanged")
    print("trace subsequence invariant: ok")
    print("artifact hashes and reproducibility: ok")
    print("report text integrity: ok")


if __name__ == "__main__":
    main()
