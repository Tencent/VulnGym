"""Independently verify the committed Issue #7 data and review artifacts.

This script intentionally does not import the patch generator.  It validates
the dataset schema, reconstructs the pre-patch target records from the diff,
reapplies every field change, checks confidence boundaries, and verifies the
artifact manifest hashes.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
REPORTS_PATH = ROOT / "data" / "reports.jsonl"
DIFF_PATH = ROOT / "reports" / "issue-7-multistage-chains.diff.csv"
MANUAL_PATH = ROOT / "reports" / "issue-7-multistage-chains.manual_review.csv"
MANIFEST_PATH = ROOT / "reports" / "issue-7-multistage-chain-manifest.json"
REPORT_PATH = ROOT / "reports" / "issue-7-multistage-chain-rebuild.md"
TARGET_IDS = {
    "entry-00185",
    "entry-00197",
    "entry-00290",
    "entry-00320",
    "entry-00391",
    "entry-00394",
}
MANUAL_IDS = {"entry-00290", "entry-00392", "entry-00395"}
EXPECTED_DIFF_COUNTS = {
    "entry-00185": 4,
    "entry-00197": 4,
    "entry-00290": 3,
    "entry-00320": 4,
    "entry-00391": 4,
    "entry-00394": 3,
}
EXPECTED_VERIFIED_TARGETS = TARGET_IDS - {"entry-00290"}
DIFF_FIELDS = ["entry_id", "field", "before", "after", "reason"]
MANUAL_FIELDS = [
    "entry_id",
    "current_status",
    "blocker",
    "source_evidence",
    "fix_evidence",
    "candidate_action",
]


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def parse_line(value: int | str) -> tuple[int, int]:
    if isinstance(value, bool):
        fail(f"boolean line is invalid: {value!r}")
    if isinstance(value, int):
        start = end = value
    elif isinstance(value, str) and re.fullmatch(r"\d+-\d+", value):
        start_text, end_text = value.split("-", 1)
        start, end = int(start_text), int(end_text)
    else:
        fail(f"invalid line value: {value!r}")
    if start < 1 or end < start:
        fail(f"invalid line range: {value!r}")
    return start, end


def validate_schema(
    entries: list[dict[str, Any]],
    reports: list[dict[str, Any]],
) -> None:
    if len(entries) != 408:
        fail(f"expected 408 entries, found {len(entries)}")
    if len(reports) != 184:
        fail(f"expected 184 reports, found {len(reports)}")
    ids = [entry["entry_id"] for entry in entries]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        fail("entry ids are not unique and sorted")

    grouped: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        if entry["verify"] not in {0, 1}:
            fail(f"{entry['entry_id']} has invalid verify")
        if not re.fullmatch(r"[0-9a-f]{40}", entry["commit"]):
            fail(f"{entry['entry_id']} has invalid commit")
        for node in (
            entry["entry_point"],
            entry["critical_operation"],
            *entry["trace"],
        ):
            if set(node) - {"file", "line", "code", "desc"}:
                fail(f"{entry['entry_id']} has unexpected node fields")
            if not {"file", "line", "code"}.issubset(node):
                fail(f"{entry['entry_id']} has an incomplete node")
            parse_line(node["line"])
            if not node["file"] or not isinstance(node["code"], str):
                fail(f"{entry['entry_id']} has an invalid node")
        grouped[entry["report_id"]].append(entry["entry_id"])

    report_map = {report["report_id"]: report for report in reports}
    if set(grouped) != set(report_map):
        fail("entry/report advisory sets differ")
    for report_id, entry_ids in grouped.items():
        report = report_map[report_id]
        if report["entry_ids"] != sorted(entry_ids):
            fail(f"{report_id} has inconsistent entry_ids")
        if report["num_entries"] != len(entry_ids):
            fail(f"{report_id} has inconsistent num_entries")


def validate_diff(
    entries: list[dict[str, Any]],
    fields: list[str],
    rows: list[dict[str, str]],
) -> None:
    if fields != DIFF_FIELDS:
        fail("diff CSV has unexpected columns")
    if len(rows) != 22:
        fail(f"diff CSV has {len(rows)} rows, expected 22")
    if Counter(row["entry_id"] for row in rows) != EXPECTED_DIFF_COUNTS:
        fail("diff CSV target coverage differs from the audited matrix")
    if len({(row["entry_id"], row["field"]) for row in rows}) != len(rows):
        fail("diff CSV contains duplicate entry/field rows")

    entry_map = {entry["entry_id"]: entry for entry in entries}
    base_entries = copy.deepcopy(entries)
    base_map = {entry["entry_id"]: entry for entry in base_entries}
    for line_number, row in enumerate(rows, start=2):
        if row["entry_id"] not in TARGET_IDS:
            fail(f"diff row {line_number} has an unexpected entry")
        if row["field"] not in {
            "entry_point",
            "critical_operation",
            "trace",
            "verify",
        }:
            fail(f"diff row {line_number} has an unexpected field")
        before = json.loads(row["before"])
        after = json.loads(row["after"])
        if before == after:
            fail(f"diff row {line_number} is a no-op")
        if entry_map[row["entry_id"]][row["field"]] != after:
            fail(f"diff row {line_number} after value is stale")
        if not row["reason"].strip():
            fail(f"diff row {line_number} has no reason")
        base_map[row["entry_id"]][row["field"]] = before

    if sum(entry["verify"] == 1 for entry in base_entries) != 393:
        fail("reconstructed pre-patch dataset does not have 393 verified entries")
    reapplied = copy.deepcopy(base_entries)
    reapplied_map = {entry["entry_id"]: entry for entry in reapplied}
    for row in rows:
        reapplied_map[row["entry_id"]][row["field"]] = json.loads(row["after"])
    if reapplied != entries:
        fail("reapplying the diff does not reproduce canonical entries.jsonl")


def trace_text(entry: dict[str, Any]) -> str:
    return "\n".join(node["code"] for node in entry["trace"])


def validate_semantics(entries: list[dict[str, Any]]) -> None:
    entry_map = {entry["entry_id"]: entry for entry in entries}
    if not TARGET_IDS <= set(entry_map):
        fail("one or more Issue #7 target entries are missing")
    verified_targets = {
        entry_id for entry_id in TARGET_IDS if entry_map[entry_id]["verify"] == 1
    }
    if verified_targets != EXPECTED_VERIFIED_TARGETS:
        fail("verified target boundary differs from the audited policy")

    checks = {
        "entry-00185": (
            "getNodeParameter('fileName'",
            "fsWriteFile(resolvedFilePath",
            ("\treturn false;",),
        ),
        "entry-00197": (
            "readStringParam(params.args",
            "readFileOverride(mediaUrl)",
            (
                "resolveSandboxedMediaSource",
                "sandboxValidated: true",
                "assertLocalMediaAllowed",
            ),
        ),
        "entry-00290": (
            "execute: async",
            "fileOps.writeFile",
            ("assertNoPathAliasEscape", "resolveSymlinkHopPath"),
        ),
        "entry-00320": (
            "new_filename = file.filename",
            "async_open(str(file_path)",
            ("unique_filename", "folder_path / file_name"),
        ),
        "entry-00391": (
            "def build(",
            "url_path = url_path.replace",
            ("path_params[openapi_name] = value", "urljoin"),
        ),
        "entry-00394": (
            "async def run(",
            "url_path = url_path.replace",
            ("self._director.build", "self._client.send(request)"),
        ),
    }
    for entry_id, (entry_marker, critical_marker, trace_markers) in checks.items():
        entry = entry_map[entry_id]
        if entry_marker not in entry["entry_point"]["code"]:
            fail(f"{entry_id} has a stale entry-point anchor")
        if critical_marker not in entry["critical_operation"]["code"]:
            fail(f"{entry_id} has a stale critical anchor")
        text = trace_text(entry)
        for marker in trace_markers:
            if marker not in text:
                fail(f"{entry_id} trace lacks {marker!r}")

    if "logger." in trace_text(entry_map["entry-00391"]):
        fail("entry-00391 still contains a logger-only node")
    if entry_map["entry-00290"]["verify"] != 0:
        fail("entry-00290 must remain unverified")

    node_occurrences = sum(
        2 + len(entry_map[entry_id]["trace"]) for entry_id in TARGET_IDS
    )
    if node_occurrences != 52:
        fail(f"target node count is {node_occurrences}, expected 52")


def validate_manual_review(
    entries: list[dict[str, Any]],
    fields: list[str],
    rows: list[dict[str, str]],
) -> None:
    if fields != MANUAL_FIELDS:
        fail("manual-review CSV has unexpected columns")
    if {row["entry_id"] for row in rows} != MANUAL_IDS or len(rows) != 3:
        fail("manual-review CSV does not cover the three confidence boundaries")
    entry_map = {entry["entry_id"]: entry for entry in entries}
    for line_number, row in enumerate(rows, start=2):
        for field in MANUAL_FIELDS[1:]:
            if not row[field].strip():
                fail(f"manual-review row {line_number} lacks {field}")
    if entry_map["entry-00290"]["verify"] != 0:
        fail("entry-00290 manual-review row conflicts with verify")
    for entry_id in {"entry-00392", "entry-00395"}:
        if "canonical record retained" not in next(
            row["current_status"] for row in rows if row["entry_id"] == entry_id
        ):
            fail(f"{entry_id} confidence boundary is not explicit")


def validate_statistics(entries: list[dict[str, Any]]) -> None:
    verified = [entry for entry in entries if entry["verify"] == 1]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        grouped[entry["report_id"]].append(entry)
    full = sum(
        all(entry["verify"] == 1 for entry in group)
        for group in grouped.values()
    )
    partial = sum(
        any(entry["verify"] == 1 for entry in group)
        and any(entry["verify"] == 0 for entry in group)
        for group in grouped.values()
    )
    if (len(verified), full, partial) != (397, 178, 0):
        fail("verification statistics differ from 397 / 178 full / 0 partial")
    for filename, expected in (
        ("README.md", ("397 / 408 (97.3 %)", "**178** have all", "**0** are partially")),
        ("README_zh.md", ("397 / 408 (97.3%)", "**178** 条 advisory", "**0** 条为部分")),
    ):
        text = (ROOT / filename).read_text(encoding="utf-8")
        for marker in expected:
            if marker not in text:
                fail(f"{filename} lacks current statistic {marker!r}")


def validate_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected = {
        "schema_version": 1,
        "dataset_sha256": sha256(DATA_PATH),
        "diff_sha256": sha256(DIFF_PATH),
        "manual_review_sha256": sha256(MANUAL_PATH),
        "target_ids": sorted(TARGET_IDS),
        "manual_review_ids": sorted(MANUAL_IDS),
        "verified_target_ids": sorted(EXPECTED_VERIFIED_TARGETS),
        "node_occurrences": 52,
        "diff_rows": 22,
    }
    if manifest != expected:
        fail("artifact manifest is stale or malformed")


def validate_report() -> None:
    report = REPORT_PATH.read_text(encoding="utf-8")
    for marker in (
        "entry-00185",
        "entry-00197",
        "entry-00290",
        "entry-00320",
        "entry-00391",
        "entry-00394",
        "direct child",
        "52",
        "manual review",
        "verify=0",
    ):
        if marker not in report:
            fail(f"rebuild report lacks {marker!r}")


def main() -> None:
    entries = load_jsonl(DATA_PATH)
    reports = load_jsonl(REPORTS_PATH)
    validate_schema(entries, reports)
    diff_fields, diff_rows = load_csv(DIFF_PATH)
    validate_diff(entries, diff_fields, diff_rows)
    validate_semantics(entries)
    manual_fields, manual_rows = load_csv(MANUAL_PATH)
    validate_manual_review(entries, manual_fields, manual_rows)
    validate_statistics(entries)
    validate_manifest()
    validate_report()
    print(
        "independent Issue #7 verification passed: "
        "408 entries, 6 rebuilt targets, 52 nodes, "
        "22 diff rows, 3 manual-review boundaries"
    )


if __name__ == "__main__":
    main()
