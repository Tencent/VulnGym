"""Independently verify the committed Issue #5 cleanup artifacts.

This verifier deliberately does not import ``trace_cleanup.py``.  It rebuilds
the structural findings from the canonical dataset, checks every committed
artifact, and rejects manual-review decisions whose input, entry, node, or
anchor fingerprints no longer match the current data.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
REVIEW_FIELDS = [
    "review_id",
    "dataset_sha256",
    "entry_sha256",
    "node_sha256",
    "anchor_sha256",
    "entry_id",
    "verify",
    "trace_index",
    "kind",
    "action",
    "node_file",
    "node_line",
    "anchor_field",
    "anchor_file",
    "anchor_line",
    "reason",
    "decision",
    "reviewer",
    "rationale",
]
FINDING_FIELDS = [
    "entry_id",
    "verify",
    "trace_index",
    "kind",
    "action",
    "node_file",
    "node_line",
    "anchor_field",
    "anchor_file",
    "anchor_line",
    "reason",
]


def fail(message: str) -> None:
    raise ValueError(message)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def object_sha256(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_text(canonical)


def load_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    text = path.read_text(encoding="utf-8")
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return text, rows


def load_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        return list(reader.fieldnames or []), rows


def parse_span(value: int | str) -> tuple[int, int]:
    if isinstance(value, bool):
        fail(f"boolean is not a valid line: {value!r}")
    if isinstance(value, int):
        start = end = value
    elif isinstance(value, str) and re.fullmatch(r"\d+-\d+", value):
        start_text, end_text = value.split("-", 1)
        start, end = int(start_text), int(end_text)
    else:
        fail(f"invalid line: {value!r}")
    if start < 1 or end < start:
        fail(f"invalid line span: {value!r}")
    return start, end


def node_key(node: dict[str, Any]) -> tuple[str, str, str]:
    return (
        node["file"],
        json.dumps(node["line"], ensure_ascii=False),
        node["code"],
    )


def finding_row(
    entry: dict[str, Any],
    trace_index: int,
    kind: str,
    action: str,
    anchor_field: str,
    anchor: dict[str, Any],
) -> dict[str, str]:
    node = entry["trace"][trace_index]
    return {
        "entry_id": entry["entry_id"],
        "verify": str(entry["verify"]),
        "trace_index": str(trace_index),
        "kind": kind,
        "action": action,
        "node_file": node["file"],
        "node_line": str(node["line"]),
        "anchor_field": anchor_field,
        "anchor_file": anchor["file"],
        "anchor_line": str(anchor["line"]),
    }


def independently_analyze(
    entries: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    cross_file = 0
    trace_nodes = 0

    for entry in entries:
        entry_start, _entry_end = parse_span(entry["entry_point"]["line"])
        _critical_start, critical_end = parse_span(
            entry["critical_operation"]["line"]
        )
        seen: dict[tuple[str, str, str], tuple[int, dict[str, Any]]] = {}

        for index, node in enumerate(entry["trace"]):
            trace_nodes += 1
            node_start, node_end = parse_span(node["line"])
            key = node_key(node)
            if key in seen:
                first_index, first_node = seen[key]
                if entry["verify"] == 1:
                    action = "protected_verified"
                elif first_node.get("desc") != node.get("desc"):
                    action = "manual_review"
                else:
                    action = "remove"
                findings.append(
                    finding_row(
                        entry,
                        index,
                        "duplicate",
                        action,
                        f"trace[{first_index}]",
                        first_node,
                    )
                )
            else:
                seen[key] = (index, node)

            if node["file"] == entry["entry_point"]["file"]:
                if node_end < entry_start:
                    action = (
                        "protected_verified"
                        if entry["verify"] == 1
                        else "manual_review"
                    )
                    findings.append(
                        finding_row(
                            entry,
                            index,
                            "before_entry",
                            action,
                            "entry_point",
                            entry["entry_point"],
                        )
                    )
            else:
                cross_file += 1

            if node["file"] == entry["critical_operation"]["file"]:
                if node_start > critical_end:
                    action = (
                        "protected_verified"
                        if entry["verify"] == 1
                        else "manual_review"
                    )
                    findings.append(
                        finding_row(
                            entry,
                            index,
                            "after_critical",
                            action,
                            "critical_operation",
                            entry["critical_operation"],
                        )
                    )
            else:
                cross_file += 1

    finding_counts = Counter(row["kind"] for row in findings)
    action_counts = Counter(row["action"] for row in findings)
    stats = {
        "entries_scanned": len(entries),
        "trace_nodes_scanned": trace_nodes,
        "finding_counts": dict(sorted(finding_counts.items())),
        "action_counts": dict(sorted(action_counts.items())),
        "cross_file_comparisons_skipped": cross_file,
        "changes_applied": sum(
            row["action"] == "remove" for row in findings
        ),
        "changed_entries": sorted(
            {
                row["entry_id"]
                for row in findings
                if row["action"] == "remove"
            }
        ),
        "needs_human_entries": sorted(
            {
                row["entry_id"]
                for row in findings
                if row["action"] == "manual_review"
            }
        ),
    }
    return findings, stats


def validate_dataset(
    entries: list[dict[str, Any]],
    reports: list[dict[str, Any]],
) -> None:
    if len(entries) != 408:
        fail(f"expected 408 entries, found {len(entries)}")
    if len(reports) != 184:
        fail(f"expected 184 reports, found {len(reports)}")
    entry_ids = [entry["entry_id"] for entry in entries]
    if entry_ids != sorted(entry_ids) or len(entry_ids) != len(set(entry_ids)):
        fail("entry ids are not unique and sorted")

    grouped: dict[str, list[str]] = {}
    for entry in entries:
        if entry["verify"] not in {0, 1}:
            fail(f"{entry['entry_id']} has invalid verify")
        for node in (
            entry["entry_point"],
            entry["critical_operation"],
            *entry["trace"],
        ):
            if set(node) - {"file", "line", "code", "desc"}:
                fail(f"{entry['entry_id']} has unexpected node fields")
            if not {"file", "line", "code"}.issubset(node):
                fail(f"{entry['entry_id']} has an incomplete node")
            parse_span(node["line"])
        grouped.setdefault(entry["report_id"], []).append(entry["entry_id"])

    report_map = {report["report_id"]: report for report in reports}
    if set(grouped) != set(report_map):
        fail("entry/report advisory sets differ")
    for report_id, ids in grouped.items():
        report = report_map[report_id]
        if report["entry_ids"] != sorted(ids):
            fail(f"{report_id} has inconsistent entry_ids")
        if report["num_entries"] != len(ids):
            fail(f"{report_id} has inconsistent num_entries")


def validate_findings(
    expected: list[dict[str, str]],
    actual: list[dict[str, str]],
) -> None:
    if len(actual) != len(expected):
        fail(f"findings row count is {len(actual)}, expected {len(expected)}")
    for index, (expected_row, actual_row) in enumerate(
        zip(expected, actual, strict=True),
        start=2,
    ):
        for field, value in expected_row.items():
            if actual_row.get(field) != value:
                fail(
                    f"findings row {index} {field} is "
                    f"{actual_row.get(field)!r}, expected {value!r}"
                )
        if not actual_row.get("reason", "").strip():
            fail(f"findings row {index} has no reason")


def anchor_node(
    entry: dict[str, Any],
    anchor_field: str,
) -> dict[str, Any]:
    if anchor_field in {"entry_point", "critical_operation"}:
        return entry[anchor_field]
    match = re.fullmatch(r"trace\[(\d+)\]", anchor_field)
    if not match:
        fail(f"invalid anchor field: {anchor_field}")
    return entry["trace"][int(match.group(1))]


def expected_review_rows(
    entries: list[dict[str, Any]],
    findings: list[dict[str, str]],
    dataset_sha256: str,
) -> dict[str, dict[str, str]]:
    entry_map = {entry["entry_id"]: entry for entry in entries}
    expected: dict[str, dict[str, str]] = {}
    for finding in findings:
        if finding["action"] != "manual_review":
            continue
        entry = entry_map[finding["entry_id"]]
        trace_index = int(finding["trace_index"])
        node = entry["trace"][trace_index]
        anchor = anchor_node(entry, finding["anchor_field"])
        fingerprints = {
            "dataset_sha256": dataset_sha256,
            "entry_sha256": object_sha256(entry),
            "node_sha256": object_sha256(node),
            "anchor_sha256": object_sha256(anchor),
        }
        review_id = object_sha256(
            {
                "anchor_sha256": fingerprints["anchor_sha256"],
                "entry_id": finding["entry_id"],
                "entry_sha256": fingerprints["entry_sha256"],
                "kind": finding["kind"],
                "node_sha256": fingerprints["node_sha256"],
                "trace_index": trace_index,
            }
        )
        expected[review_id] = {
            "review_id": review_id,
            **fingerprints,
            **finding,
        }
    return expected


def validate_review_manifest(
    path: Path,
    expected: dict[str, dict[str, str]],
) -> None:
    fields, rows = load_csv(path)
    if fields != REVIEW_FIELDS:
        fail(f"{path} has unexpected columns")
    if len(rows) != len(expected):
        fail(f"{path} has {len(rows)} rows, expected {len(expected)}")

    seen: set[str] = set()
    for line_number, row in enumerate(rows, start=2):
        review_id = row["review_id"]
        if not HEX_SHA256.fullmatch(review_id):
            fail(f"{path}:{line_number} has invalid review_id")
        if review_id in seen:
            fail(f"{path}:{line_number} duplicates review_id {review_id}")
        seen.add(review_id)
        if review_id not in expected:
            fail(
                f"{path}:{line_number} is stale or unknown: "
                f"review_id {review_id}"
            )
        for field, value in expected[review_id].items():
            if row.get(field) != value:
                fail(
                    f"{path}:{line_number} stale {field}: "
                    f"{row.get(field)!r} != {value!r}"
                )
        if not row["reason"].strip():
            fail(f"{path}:{line_number} has no review reason")

        decision = row["decision"].strip()
        reviewer = row["reviewer"].strip()
        rationale = row["rationale"].strip()
        if decision not in {"", "keep", "remove"}:
            fail(f"{path}:{line_number} has invalid decision {decision!r}")
        if decision and (not reviewer or not rationale):
            fail(
                f"{path}:{line_number} decision requires reviewer and rationale"
            )
        if not decision and (reviewer or rationale):
            fail(
                f"{path}:{line_number} reviewer/rationale require a decision"
            )


def validate_report(
    report: dict[str, Any],
    expected_stats: dict[str, Any],
    input_sha256: str,
    output_sha256: str,
    manifest_sha256: str,
) -> None:
    expected = {
        **expected_stats,
        "mode": "fix",
        "order_policy": "review",
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "manual_review_rows": len(
            expected_stats["needs_human_entries"]
        ),
        "manual_review_schema_version": 1,
        "manual_review_manifest_sha256": manifest_sha256,
    }
    for field, value in expected.items():
        if report.get(field) != value:
            fail(
                f"report field {field} is {report.get(field)!r}, "
                f"expected {value!r}"
            )
    if set(report) != set(expected):
        fail(
            "report fields differ: "
            f"extra={sorted(set(report) - set(expected))}, "
            f"missing={sorted(set(expected) - set(report))}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--decisions",
        type=Path,
        help="also validate a filled manual-review decision CSV",
    )
    args = parser.parse_args()

    canonical_path = ROOT / "data" / "entries.jsonl"
    fixed_path = ROOT / "data" / "entries.trace_fixed.jsonl"
    reports_path = ROOT / "data" / "reports.jsonl"
    findings_path = ROOT / "reports" / "trace_findings.csv"
    diff_path = ROOT / "reports" / "trace_fix_diff.csv"
    review_path = ROOT / "reports" / "trace_needs_human.csv"
    report_path = ROOT / "reports" / "trace_structure_report.json"

    canonical_text, entries = load_jsonl(canonical_path)
    fixed_text, fixed_entries = load_jsonl(fixed_path)
    _reports_text, reports = load_jsonl(reports_path)
    validate_dataset(entries, reports)
    validate_dataset(fixed_entries, reports)
    if canonical_path.read_bytes() != fixed_path.read_bytes():
        fail("conservative fixed artifact differs from canonical bytes")

    fields, findings_rows = load_csv(findings_path)
    if fields != FINDING_FIELDS:
        fail("trace_findings.csv has unexpected columns")
    expected_findings, expected_stats = independently_analyze(entries)
    validate_findings(expected_findings, findings_rows)

    diff_fields, diff_rows = load_csv(diff_path)
    if diff_fields != [
        "entry_id",
        "field_path",
        "action",
        "before",
        "after",
        "reason",
    ]:
        fail("trace_fix_diff.csv has unexpected columns")
    if diff_rows:
        fail("conservative artifact unexpectedly records automatic changes")

    input_sha256 = sha256_text(canonical_text)
    output_sha256 = sha256_text(fixed_text)
    expected_reviews = expected_review_rows(
        entries,
        expected_findings,
        input_sha256,
    )
    validate_review_manifest(review_path, expected_reviews)
    manifest_text = review_path.read_text(encoding="utf-8")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate_report(
        report,
        expected_stats,
        input_sha256,
        output_sha256,
        sha256_text(manifest_text),
    )
    if args.decisions:
        validate_review_manifest(args.decisions, expected_reviews)

    print(
        "independent artifact verification passed: "
        f"{len(entries)} entries, "
        f"{expected_stats['trace_nodes_scanned']} trace nodes, "
        f"{len(expected_findings)} findings, "
        f"{len(expected_reviews)} fingerprinted manual reviews"
    )
    if args.decisions:
        print(f"manual-review decisions passed: {args.decisions}")


if __name__ == "__main__":
    main()
