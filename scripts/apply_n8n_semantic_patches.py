"""Apply the n8n semantic annotation patch fragment.

The patch fragment is the source of truth for issue #6.  This script keeps the
baseline dataset unchanged, validates the six repaired rows, writes a full
fixed JSONL, and emits a field-level review CSV.
"""

from __future__ import annotations

import csv
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASELINE_JSONL = ROOT / "data" / "entries.jsonl"
PATCH_JSONL = ROOT / "data" / "entries.n8n_semantic_fixed.jsonl"
FULL_JSONL = ROOT / "data" / "entries.fixed.jsonl"
DIFF_CSV = ROOT / "reports" / "n8n_semantic_fix_diff.csv"

TARGET_IDS = (
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00511",
    "entry-00512",
)

FIELDS_TO_DIFF = ("entry_point", "critical_operation", "trace", "verify")
LINE_RE = re.compile(r"^[1-9]\d*-[1-9]\d*$")
DAMAGED_TEXT_RE = re.compile(r"\?{4,}|\ufffd")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def dump_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )


def compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_line_span(line: int | str) -> tuple[int, int]:
    if isinstance(line, int):
        if line < 1:
            raise ValueError(f"line must be positive: {line!r}")
        return line, line
    if not isinstance(line, str) or not LINE_RE.match(line):
        raise ValueError(f"invalid line span: {line!r}")
    start_text, end_text = line.split("-", 1)
    start, end = int(start_text), int(end_text)
    if end < start:
        raise ValueError(f"invalid descending line span: {line!r}")
    return start, end


def validate_node(node: dict[str, Any], entry_id: str, path: str) -> None:
    missing = {"file", "line", "code"} - node.keys()
    if missing:
        raise AssertionError(f"{entry_id}:{path} missing {sorted(missing)}")
    parse_line_span(node["line"])
    if not isinstance(node["file"], str) or not node["file"]:
        raise AssertionError(f"{entry_id}:{path} has invalid file")
    if not isinstance(node["code"], str) or not node["code"].strip():
        raise AssertionError(f"{entry_id}:{path} has empty code")
    desc = node.get("desc", "")
    if not isinstance(desc, str) or len(desc) < 30:
        raise AssertionError(f"{entry_id}:{path} desc is too short")
    if DAMAGED_TEXT_RE.search(desc):
        raise AssertionError(f"{entry_id}:{path} desc appears encoding-damaged")


def validate_patch_rows(rows: list[dict[str, Any]]) -> None:
    ids = [row.get("entry_id") for row in rows]
    if ids != list(TARGET_IDS):
        raise AssertionError(f"patch rows must be sorted target ids, got {ids}")
    for row in rows:
        entry_id = row["entry_id"]
        if row.get("project") != "n8n":
            raise AssertionError(f"{entry_id} project must be n8n")
        if row.get("verify") != 1:
            raise AssertionError(f"{entry_id} verify must be 1 after source and fix review")
        for value in iter_text_values(row):
            if DAMAGED_TEXT_RE.search(value):
                raise AssertionError(f"{entry_id} contains encoding-damaged text")
        validate_node(row["entry_point"], entry_id, "entry_point")
        validate_node(row["critical_operation"], entry_id, "critical_operation")
        trace = row.get("trace")
        if not isinstance(trace, list) or not trace:
            raise AssertionError(f"{entry_id} trace must be a non-empty list")
        for index, node in enumerate(trace):
            validate_node(node, entry_id, f"trace[{index}]")


def iter_text_values(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from iter_text_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_text_values(nested)


def apply_patch_rows(
    baseline_rows: list[dict[str, Any]], patch_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    patch_by_id = {row["entry_id"]: row for row in patch_rows}
    missing = sorted(set(TARGET_IDS) - set(patch_by_id))
    if missing:
        raise KeyError(f"missing patch rows: {missing}")
    return [deepcopy(patch_by_id.get(row["entry_id"], row)) for row in baseline_rows]


def summarize_node(value: Any, fallback: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and value:
        return value[-1]
    return {"file": "multiple", "line": "multiple", "code": fallback, "desc": ""}


def write_diff_csv(
    baseline_rows: list[dict[str, Any]], patch_rows: list[dict[str, Any]]
) -> None:
    baseline_by_id = {row["entry_id"]: row for row in baseline_rows}
    fieldnames = [
        "entry_id",
        "field_path",
        "old_file",
        "old_line",
        "old_code",
        "old_desc",
        "new_file",
        "new_line",
        "new_code",
        "new_desc",
        "old_value_json",
        "new_value_json",
        "reason",
    ]
    reasons = {
        "entry_point": (
            "Move or retain the node that best represents external input, workflow "
            "configuration, request handling, or parameter entry into the vulnerable chain."
        ),
        "critical_operation": (
            "Point at the real execution, security decision, or bypass-enabling operation "
            "instead of a wrapper, static declaration, or defensive helper definition."
        ),
        "trace": (
            "Keep only the important data-flow or control-flow nodes from the entry point "
            "to the critical operation."
        ),
        "verify": (
            "Mark the row reviewed only after vulnerable-source snippets, advisory context, "
            "and the direct upstream fix delta have all been checked."
        ),
    }
    rows: list[dict[str, Any]] = []
    for patch_row in patch_rows:
        old = baseline_by_id[patch_row["entry_id"]]
        for field in FIELDS_TO_DIFF:
            old_value = old[field]
            new_value = patch_row[field]
            old_node = summarize_node(old_value, compact(old_value))
            new_node = summarize_node(new_value, compact(new_value))
            rows.append(
                {
                    "entry_id": patch_row["entry_id"],
                    "field_path": field,
                    "old_file": old_node.get("file", "multiple"),
                    "old_line": old_node.get("line", "multiple"),
                    "old_code": old_node.get("code", ""),
                    "old_desc": old_node.get("desc", ""),
                    "new_file": new_node.get("file", "multiple"),
                    "new_line": new_node.get("line", "multiple"),
                    "new_code": new_node.get("code", ""),
                    "new_desc": new_node.get("desc", ""),
                    "old_value_json": compact(old_value),
                    "new_value_json": compact(new_value),
                    "reason": reasons[field],
                }
            )

    with DIFF_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    baseline_rows = load_jsonl(BASELINE_JSONL)
    patch_rows = load_jsonl(PATCH_JSONL)
    validate_patch_rows(patch_rows)
    fixed_rows = apply_patch_rows(baseline_rows, patch_rows)
    if len(fixed_rows) != len(baseline_rows):
        raise AssertionError("full fixed JSONL row count changed")

    dump_jsonl(FULL_JSONL, fixed_rows)
    write_diff_csv(baseline_rows, patch_rows)
    print(f"patch rows: {len(patch_rows)} -> {PATCH_JSONL}")
    print(f"full rows: {len(fixed_rows)} -> {FULL_JSONL}")
    print(f"diff rows: {len(patch_rows) * len(FIELDS_TO_DIFF)} -> {DIFF_CSV}")


if __name__ == "__main__":
    main()
