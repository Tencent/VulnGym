"""Verify code-location repair artifacts for issue #4.

This verifier is intentionally offline.  It checks that the committed fixed
JSONL is exactly the baseline JSONL plus the field-level repairs recorded in
`reports/fix_diff.csv`, while entries listed in `reports/needs_human.csv` remain
unchanged at the reported field paths.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASELINE_JSONL = ROOT / "data" / "entries.jsonl"
FIXED_JSONL = ROOT / "data" / "entries.fixed.jsonl"
DIFF_CSV = ROOT / "reports" / "fix_diff.csv"
NEEDS_HUMAN_CSV = ROOT / "reports" / "needs_human.csv"
SUMMARY_MD = ROOT / "reports" / "code_location_summary.md"

EXPECTED_ROWS = 408
EXPECTED_DIFF_ROWS = 12
EXPECTED_NEEDS_HUMAN_ROWS = 75
DAMAGED_TEXT_RE = re.compile(r"\?{4,}|\ufffd")
TRACE_RE = re.compile(r"^trace\[(\d+)\]$")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def normalized_code(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.strip() for line in lines).strip()


def node_at(entry: dict[str, Any], field_path: str) -> dict[str, Any]:
    if field_path in {"entry_point", "critical_operation"}:
        node = entry[field_path]
        if not isinstance(node, dict):
            raise AssertionError(f"{entry.get('entry_id')}:{field_path} is not an object")
        return node
    match = TRACE_RE.match(field_path)
    if match:
        trace = entry.get("trace")
        if not isinstance(trace, list):
            raise AssertionError(f"{entry.get('entry_id')}:trace is not a list")
        index = int(match.group(1))
        try:
            node = trace[index]
        except IndexError as exc:
            raise AssertionError(f"{entry.get('entry_id')}:{field_path} missing") from exc
        if not isinstance(node, dict):
            raise AssertionError(f"{entry.get('entry_id')}:{field_path} is not an object")
        return node
    raise AssertionError(f"unsupported field_path: {field_path}")


def check_schema(rows: list[dict[str, Any]]) -> None:
    required_entry = {
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
    required_node = {"file", "line", "code"}
    for row in rows:
        missing = required_entry - row.keys()
        if missing:
            raise AssertionError(f"{row.get('entry_id')} missing fields: {sorted(missing)}")
        if row["verify"] not in (0, 1):
            raise AssertionError(f"{row['entry_id']} invalid verify value")
        for field in ("entry_point", "critical_operation"):
            if required_node - row[field].keys():
                raise AssertionError(f"{row['entry_id']} {field} missing node fields")
        if not isinstance(row["trace"], list):
            raise AssertionError(f"{row['entry_id']} trace is not a list")
        for index, node in enumerate(row["trace"]):
            if required_node - node.keys():
                raise AssertionError(f"{row['entry_id']} trace[{index}] missing node fields")


def check_fixed_matches_diff(
    baseline_rows: list[dict[str, Any]],
    fixed_rows: list[dict[str, Any]],
    diff_rows: list[dict[str, str]],
) -> None:
    baseline_by_id = {row["entry_id"]: row for row in baseline_rows}
    fixed_by_id = {row["entry_id"]: row for row in fixed_rows}
    changed_paths = {(row["entry_id"], row["field_path"]) for row in diff_rows}

    for diff in diff_rows:
        baseline_node = node_at(baseline_by_id[diff["entry_id"]], diff["field_path"])
        fixed_node = node_at(fixed_by_id[diff["entry_id"]], diff["field_path"])
        if baseline_node.get("file") != diff["old_file"] or str(baseline_node.get("line")) != diff["old_line"]:
            raise AssertionError(
                f"diff old location mismatch for {diff['entry_id']} {diff['field_path']}"
            )
        if baseline_node.get("desc", "") != diff["old_desc"]:
            raise AssertionError(
                f"diff old desc mismatch for {diff['entry_id']} {diff['field_path']}"
            )
        if fixed_node.get("file") != diff["new_file"] or str(fixed_node.get("line")) != diff["new_line"]:
            raise AssertionError(
                f"fixed location mismatch for {diff['entry_id']} {diff['field_path']}"
            )
        if fixed_node.get("desc", "") != diff["new_desc"]:
            raise AssertionError(
                f"fixed desc mismatch for {diff['entry_id']} {diff['field_path']}"
            )
        if normalized_code(fixed_node.get("code")) != normalized_code(baseline_node.get("code")):
            raise AssertionError(
                f"fixed code changed semantically for {diff['entry_id']} {diff['field_path']}"
            )

    for baseline_row, fixed_row in zip(baseline_rows, fixed_rows):
        entry_id = baseline_row["entry_id"]
        for field_path in ["entry_point", "critical_operation"]:
            if (entry_id, field_path) not in changed_paths:
                if node_at(baseline_row, field_path) != node_at(fixed_row, field_path):
                    raise AssertionError(f"unexpected node change: {entry_id} {field_path}")
        baseline_trace = baseline_row.get("trace", [])
        fixed_trace = fixed_row.get("trace", [])
        if len(baseline_trace) != len(fixed_trace):
            raise AssertionError(f"unexpected trace length change: {entry_id}")
        for index in range(len(baseline_trace)):
            field_path = f"trace[{index}]"
            if (entry_id, field_path) not in changed_paths:
                if node_at(baseline_row, field_path) != node_at(fixed_row, field_path):
                    raise AssertionError(f"unexpected node change: {entry_id} {field_path}")


def check_needs_human_unchanged(
    baseline_by_id: dict[str, dict[str, Any]],
    fixed_by_id: dict[str, dict[str, Any]],
    needs_human_rows: list[dict[str, str]],
) -> None:
    for row in needs_human_rows:
        baseline_node = node_at(baseline_by_id[row["entry_id"]], row["field_path"])
        fixed_node = node_at(fixed_by_id[row["entry_id"]], row["field_path"])
        if baseline_node != fixed_node:
            raise AssertionError(
                f"needs-human node was changed: {row['entry_id']} {row['field_path']}"
            )


def check_text_artifacts() -> None:
    for path in (DIFF_CSV, NEEDS_HUMAN_CSV, SUMMARY_MD):
        text = path.read_text(encoding="utf-8")
        if DAMAGED_TEXT_RE.search(text):
            raise AssertionError(f"encoding damage pattern found in {path}")


def main() -> None:
    baseline_rows = load_jsonl(BASELINE_JSONL)
    fixed_rows = load_jsonl(FIXED_JSONL)
    diff_rows = load_csv(DIFF_CSV)
    needs_human_rows = load_csv(NEEDS_HUMAN_CSV)

    if len(baseline_rows) != EXPECTED_ROWS or len(fixed_rows) != EXPECTED_ROWS:
        raise AssertionError("unexpected JSONL row count")
    if [row["entry_id"] for row in baseline_rows] != [row["entry_id"] for row in fixed_rows]:
        raise AssertionError("entry order changed")
    if len(diff_rows) != EXPECTED_DIFF_ROWS:
        raise AssertionError(f"expected {EXPECTED_DIFF_ROWS} diff rows, got {len(diff_rows)}")
    if len(needs_human_rows) != EXPECTED_NEEDS_HUMAN_ROWS:
        raise AssertionError(
            f"expected {EXPECTED_NEEDS_HUMAN_ROWS} needs-human rows, got {len(needs_human_rows)}"
        )

    check_schema(fixed_rows)
    check_fixed_matches_diff(baseline_rows, fixed_rows, diff_rows)

    baseline_by_id = {row["entry_id"]: row for row in baseline_rows}
    fixed_by_id = {row["entry_id"]: row for row in fixed_rows}
    check_needs_human_unchanged(baseline_by_id, fixed_by_id, needs_human_rows)
    check_text_artifacts()

    print("code-location artifacts verified")
    print(f"full rows: {len(fixed_rows)}")
    print(f"diff rows: {len(diff_rows)}")
    print(f"needs-human rows: {len(needs_human_rows)}")
    print("schema errors: 0")


if __name__ == "__main__":
    main()
