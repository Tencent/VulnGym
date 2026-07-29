"""Independently verify the Issue #6 n8n semantic-annotation artifacts.

The default mode is offline and validates the canonical dataset, report
mapping, field-level diff, target scope, and semantic node structure.  The
optional upstream mode fetches each unique source file from the exact commit
recorded by the entry and checks every annotated source span byte-for-byte
after newline normalization.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
REPORTS_PATH = ROOT / "data" / "reports.jsonl"
DIFF_PATH = ROOT / "reports" / "issue-6-n8n-semantic-review.diff.csv"
TARGET_IDS = {
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00182",
    "entry-00511",
    "entry-00512",
}
EXPECTED_DIFF_ROWS = 22
EXPECTED_NODE_OCCURRENCES = 58
GITHUB_API = "https://api.github.com"

# Each fix is independently bound to the vulnerable snapshot recorded by the
# corresponding entry.  Patch markers are deliberately narrow security
# semantics, not commit-message or filename checks.
FIX_EVIDENCE = {
    "GHSA-5XRP-6693-JJX9": {
        "fix": "30383d86139f3279a698df8d229eadfefe8627f4",
        "vulnerable": "8ab4492e8c0b743455e51fc111441d8d5010a6ad",
        "markers": ("RESERVED_VARIABLE_NAMES", "visitWithStatement"),
    },
    "GHSA-825Q-W924-XHGX": {
        "fix": "ced34c0f93ab4c759a56065965986094d8ef7323",
        "vulnerable": "57d6015f2ea0442c24e0449105325b7e36f066df",
        "markers": ("contentType.trim().toLowerCase()",),
    },
    "GHSA-MMGG-M5J7-F83H": {
        "fix": "062644ef786b6af480afe4a0f12bc6d70040534a",
        "vulnerable": "3af9095245be3aaad6bc16622f379f79c6c6068f",
        "markers": ('"__objclass__"',),
    },
    "GHSA-VPCF-GVG4-6QWR": {
        "fix": "9e5212ecbc5d2d4e6f340b636a5e84be6369882e",
        "vulnerable": "8e81f3e31398b04fd6f8cc27cf844980cd382117",
        "markers": ('"__objclass__"',),
    },
    "GHSA-6CQR-8CFR-67F8": {
        "fix": "1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6",
        "vulnerable": "09e2c2b5547b49a824a8265d312583f5d1f5c79f",
        "markers": ("UNSAFE_PROPERTY_NAMES", "Object.defineProperty", "Cannot override"),
    },
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            rows.append(row)
    return rows


def line_bounds(value: int | str) -> tuple[int, int]:
    if isinstance(value, int):
        start = end = value
    elif isinstance(value, str) and re.fullmatch(r"[1-9]\d*", value):
        start = end = int(value)
    elif isinstance(value, str) and re.fullmatch(r"[1-9]\d*-[1-9]\d*", value):
        start_text, end_text = value.split("-", 1)
        start, end = int(start_text), int(end_text)
    else:
        raise ValueError(f"invalid line value: {value!r}")
    if start > end:
        raise ValueError(f"reversed line range: {value!r}")
    return start, end


def iter_nodes(entry: dict[str, Any]):
    yield "entry_point", entry["entry_point"]
    yield "critical_operation", entry["critical_operation"]
    for index, node in enumerate(entry["trace"]):
        yield f"trace[{index}]", node


def validate_node(entry_id: str, field: str, node: Any) -> None:
    if not isinstance(node, dict):
        raise ValueError(f"{entry_id}.{field}: expected an object")
    required = {"file", "line", "code", "desc"}
    if set(node) != required:
        raise ValueError(
            f"{entry_id}.{field}: expected keys {sorted(required)}, "
            f"got {sorted(node)}"
        )
    if not isinstance(node["file"], str) or not node["file"]:
        raise ValueError(f"{entry_id}.{field}: empty file")
    if node["file"].startswith("/") or ".." in Path(node["file"]).parts:
        raise ValueError(f"{entry_id}.{field}: unsafe file path {node['file']!r}")
    line_bounds(node["line"])
    for key in ("code", "desc"):
        if not isinstance(node[key], str) or not node[key].strip():
            raise ValueError(f"{entry_id}.{field}: empty {key}")
        if "\ufffd" in node[key] or "????" in node[key]:
            raise ValueError(f"{entry_id}.{field}: damaged text in {key}")


def location(node: dict[str, Any]) -> str:
    return f"{node['file']}:{node['line']}"


def validate_diff_summary(
    entry_id: str,
    field: str,
    value: str,
    record: dict[str, Any],
    column: str,
) -> None:
    if field == "verify":
        if value != str(record[field]):
            raise ValueError(
                f"{entry_id}.{field}: {column} does not match dataset value"
            )
        return
    if field in {"entry_point", "critical_operation"}:
        expected_prefix = f"{location(record[field])} | "
        if not value.startswith(expected_prefix):
            raise ValueError(
                f"{entry_id}.{field}: {column} does not match source location"
            )
        return
    if field == "trace":
        trace = record[field]
        expected = (
            f"{len(trace)} nodes | {location(trace[0])} -> {location(trace[-1])}"
        )
        if value != expected:
            raise ValueError(
                f"{entry_id}.{field}: {column} does not match trace endpoints"
            )
        return
    raise ValueError(f"{entry_id}: unsupported diff field {field!r}")


def validate_local(base_path: Path | None = None) -> dict[str, dict[str, Any]]:
    entries = read_jsonl(DATA_PATH)
    reports = read_jsonl(REPORTS_PATH)
    if len(entries) != 408:
        raise ValueError(f"expected 408 entries, got {len(entries)}")
    if len(reports) != 184:
        raise ValueError(f"expected 184 reports, got {len(reports)}")

    by_id = {entry["entry_id"]: entry for entry in entries}
    if len(by_id) != len(entries):
        raise ValueError("duplicate entry_id in canonical dataset")
    report_ids = {report["report_id"] for report in reports}
    if len(report_ids) != len(reports):
        raise ValueError("duplicate report_id in report dataset")
    missing_reports = {
        entry["report_id"] for entry in entries if entry["report_id"] not in report_ids
    }
    if missing_reports:
        raise ValueError(f"entries reference missing reports: {sorted(missing_reports)}")
    if not TARGET_IDS <= set(by_id):
        raise ValueError(f"missing target entries: {sorted(TARGET_IDS - set(by_id))}")

    node_count = 0
    for entry_id in sorted(TARGET_IDS):
        entry = by_id[entry_id]
        if entry["verify"] != 0:
            raise ValueError(f"{entry_id}: expected conservative verify=0")
        if not re.fullmatch(r"[0-9a-f]{40}", entry["commit"]):
            raise ValueError(f"{entry_id}: invalid commit")
        for field, node in iter_nodes(entry):
            validate_node(entry_id, field, node)
            node_count += 1
    if node_count != EXPECTED_NODE_OCCURRENCES:
        raise ValueError(
            f"expected {EXPECTED_NODE_OCCURRENCES} target node occurrences, "
            f"got {node_count}"
        )

    with DIFF_PATH.open(encoding="utf-8", newline="") as handle:
        diff_rows = list(csv.DictReader(handle))
    if len(diff_rows) != EXPECTED_DIFF_ROWS:
        raise ValueError(
            f"expected {EXPECTED_DIFF_ROWS} diff rows, got {len(diff_rows)}"
        )

    seen_fields: set[tuple[str, str]] = set()
    for row_number, row in enumerate(diff_rows, start=2):
        entry_id = row["entry_id"]
        field = row["field"]
        key = (entry_id, field)
        if entry_id not in TARGET_IDS:
            raise ValueError(f"{DIFF_PATH}:{row_number}: unexpected entry {entry_id}")
        if key in seen_fields:
            raise ValueError(f"{DIFF_PATH}:{row_number}: duplicate diff key {key}")
        seen_fields.add(key)
        if not row["old_value"] or not row["reason"]:
            raise ValueError(f"{DIFF_PATH}:{row_number}: incomplete audit evidence")
        validate_diff_summary(
            entry_id,
            field,
            row["new_value"],
            by_id[entry_id],
            "new_value",
        )

    if base_path is not None:
        base_entries = read_jsonl(base_path)
        base_by_id = {entry["entry_id"]: entry for entry in base_entries}
        if list(base_by_id) != list(by_id):
            raise ValueError("base and canonical entry order/IDs differ")
        changed_entries = {
            entry_id for entry_id in by_id if base_by_id[entry_id] != by_id[entry_id]
        }
        if changed_entries != TARGET_IDS:
            raise ValueError(
                f"changed entry scope differs: {sorted(changed_entries)}"
            )
        for entry_id in TARGET_IDS:
            changed_fields = {
                field
                for field in by_id[entry_id]
                if base_by_id[entry_id][field] != by_id[entry_id][field]
            }
            logged_fields = {
                field for logged_entry, field in seen_fields if logged_entry == entry_id
            }
            if changed_fields != logged_fields:
                raise ValueError(
                    f"{entry_id}: changed fields {sorted(changed_fields)} "
                    f"do not match diff {sorted(logged_fields)}"
                )
        for row in diff_rows:
            validate_diff_summary(
                row["entry_id"],
                row["field"],
                row["old_value"],
                base_by_id[row["entry_id"]],
                "old_value",
            )

    return {entry_id: by_id[entry_id] for entry_id in TARGET_IDS}


def github_repo_slug(repo_url: str) -> str:
    match = re.fullmatch(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?", repo_url)
    if not match:
        raise ValueError(f"unsupported repo_url: {repo_url!r}")
    return match.group(1)


def fetch_text(url: str, attempts: int = 3) -> str:
    headers = {"User-Agent": "VulnGym-Issue-6-validator"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(1 << attempt)
    raise RuntimeError(f"unable to fetch {url}: {last_error}")


def fetch_json(url: str) -> dict[str, Any]:
    payload = json.loads(fetch_text(url))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object from {url}")
    return payload


def validate_upstream(entries: dict[str, dict[str, Any]]) -> None:
    source_cache: dict[tuple[str, str, str], list[str]] = {}
    checked = 0
    for entry_id in sorted(entries):
        entry = entries[entry_id]
        repo_slug = github_repo_slug(entry["repo_url"])
        commit = entry["commit"]
        for field, node in iter_nodes(entry):
            key = (repo_slug, commit, node["file"])
            if key not in source_cache:
                url = (
                    f"https://raw.githubusercontent.com/{repo_slug}/"
                    f"{commit}/{node['file']}"
                )
                source_cache[key] = fetch_text(url).splitlines()
            source_lines = source_cache[key]
            start, end = line_bounds(node["line"])
            actual = "\n".join(source_lines[start - 1 : end])
            if actual != node["code"]:
                raise ValueError(
                    f"{entry_id}.{field}: source mismatch at "
                    f"{node['file']}:{node['line']}"
                )
            checked += 1
    if checked != EXPECTED_NODE_OCCURRENCES:
        raise ValueError(
            f"expected {EXPECTED_NODE_OCCURRENCES} upstream checks, got {checked}"
        )
    print(
        f"upstream verification passed: {checked} node occurrences, "
        f"{len(source_cache)} pinned source files"
    )


def validate_security_evidence(
    entries: dict[str, dict[str, Any]],
) -> None:
    report_ids = {entry["report_id"] for entry in entries.values()}
    if report_ids != set(FIX_EVIDENCE):
        raise ValueError(
            "target advisory coverage differs from fix evidence: "
            f"{sorted(report_ids)}"
        )

    for report_id, expected in FIX_EVIDENCE.items():
        advisory = fetch_json(f"{GITHUB_API}/advisories/{report_id}")
        if advisory.get("ghsa_id", "").upper() != report_id:
            raise ValueError(f"{report_id}: advisory identity mismatch")
        if advisory.get("source_code_location") != "https://github.com/n8n-io/n8n":
            raise ValueError(f"{report_id}: unexpected advisory source repository")
        if not advisory.get("summary") or not advisory.get("vulnerabilities"):
            raise ValueError(f"{report_id}: advisory lacks reviewed package evidence")

        commit = fetch_json(
            f"{GITHUB_API}/repos/n8n-io/n8n/commits/{expected['fix']}"
        )
        if commit.get("sha") != expected["fix"]:
            raise ValueError(f"{report_id}: fix commit identity mismatch")
        parents = commit.get("parents", [])
        if not parents or parents[0].get("sha") != expected["vulnerable"]:
            raise ValueError(
                f"{report_id}: vulnerable snapshot is not the fix's first parent"
            )
        patch = "\n".join(
            file.get("patch", "") for file in commit.get("files", [])
        )
        for marker in expected["markers"]:
            if marker not in patch:
                raise ValueError(
                    f"{report_id}: fix patch is missing marker {marker!r}"
                )

    print(
        "security evidence verification passed: "
        f"{len(FIX_EVIDENCE)} advisories, {len(FIX_EVIDENCE)} direct fixes, "
        f"{len(FIX_EVIDENCE)} vulnerable-parent relationships"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        type=Path,
        help="optional clean data/entries.jsonl used to verify mutation scope",
    )
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="fetch pinned n8n source files and verify all annotated spans",
    )
    args = parser.parse_args()

    entries = validate_local(args.base)
    print(
        f"artifact verification passed: 408 entries, 184 reports, "
        f"{len(entries)} targets, {EXPECTED_DIFF_ROWS} diff rows, "
        f"{EXPECTED_NODE_OCCURRENCES} nodes"
    )
    if args.check_upstream:
        validate_upstream(entries)
        validate_security_evidence(entries)


if __name__ == "__main__":
    main()
