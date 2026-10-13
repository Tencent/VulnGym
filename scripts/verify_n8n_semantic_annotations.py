"""Verify n8n semantic annotation artifacts and upstream evidence for issue #6."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import apply_n8n_semantic_patches as gen

ROOT = Path(__file__).resolve().parent.parent
TEXT_ARTIFACTS = (
    ROOT / "reports" / "n8n_semantic_fix_notes.md",
    ROOT / "reports" / "n8n_semantic_acceptance_matrix.md",
    ROOT / "reports" / "n8n_semantic_fix_diff.csv",
)
DAMAGED_TEXT_RE = re.compile(r"\?{4,}|\ufffd")
GITHUB_API = "https://api.github.com"

EXPECTED_ANCHORS = {
    "entry-00099": {
        "entry": ("packages/cli/src/workflows/workflows.controller.ts", "561-565"),
        "critical": ("packages/workflow/src/expression-evaluator-proxy.ts", "19-20"),
        "trace_nodes": 5,
    },
    "entry-00100": {
        "entry": ("packages/workflow/src/expression.ts", "368-382"),
        "critical": ("packages/workflow/src/expression-evaluator-proxy.ts", "19-20"),
        "trace_nodes": 5,
    },
    "entry-00103": {
        "entry": ("packages/cli/src/webhooks/webhook-helpers.ts", "882-892"),
        "critical": ("packages/cli/src/webhooks/webhook-request-handler.ts", "153-157"),
        "trace_nodes": 7,
    },
    "entry-00176": {
        "entry": ("packages/nodes-base/nodes/Code/Code.node.ts", "206"),
        "critical": ("packages/@n8n/task-runner-python/src/task_analyzer.py", "66"),
        "trace_nodes": 7,
    },
    "entry-00511": {
        "entry": ("packages/workflow/src/expression.ts", "451-455"),
        "critical": (
            "packages/@n8n/expression-runtime/src/extensions/extend.ts",
            "132-134",
        ),
        "trace_nodes": 8,
    },
    "entry-00512": {
        "entry": ("packages/workflow/src/expression.ts", "451-455"),
        "critical": ("packages/@n8n/expression-runtime/src/runtime/reset.ts", "46"),
        "trace_nodes": 5,
    },
}

FIX_EVIDENCE = {
    "GHSA-5XRP-6693-JJX9": {
        "sha": "30383d86139f3279a698df8d229eadfefe8627f4",
        "parent": "8ab4492e8c0b743455e51fc111441d8d5010a6ad",
        "markers": ("RESERVED_VARIABLE_NAMES", "visitWithStatement"),
    },
    "GHSA-825Q-W924-XHGX": {
        "sha": "ced34c0f93ab4c759a56065965986094d8ef7323",
        "parent": "57d6015f2ea0442c24e0449105325b7e36f066df",
        "markers": ("contentType.trim().toLowerCase()",),
    },
    "GHSA-MMGG-M5J7-F83H": {
        "sha": "062644ef786b6af480afe4a0f12bc6d70040534a",
        "parent": "3af9095245be3aaad6bc16622f379f79c6c6068f",
        "markers": ('"__objclass__"',),
    },
    "GHSA-6CQR-8CFR-67F8": {
        "sha": "1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6",
        "parent": "09e2c2b5547b49a824a8265d312583f5d1f5c79f",
        "markers": ("UNSAFE_PROPERTY_NAMES", "Object.defineProperty", "Cannot override"),
    },
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def assert_same_rows(
    label: str, actual: list[dict[str, Any]], expected: list[dict[str, Any]]
) -> None:
    actual_dump = [gen.compact(row) for row in actual]
    expected_dump = [gen.compact(row) for row in expected]
    if actual_dump != expected_dump:
        raise AssertionError(f"{label} is not reproducible")


def check_text_artifacts() -> None:
    for path in TEXT_ARTIFACTS:
        text = path.read_text(encoding="utf-8")
        if DAMAGED_TEXT_RE.search(text):
            raise AssertionError(f"encoding damage pattern found in {path}")


def check_diff_csv() -> None:
    with gen.DIFF_CSV.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected = len(gen.TARGET_IDS) * len(gen.FIELDS_TO_DIFF)
    if len(rows) != expected:
        raise AssertionError(f"expected {expected} diff rows, got {len(rows)}")
    seen = {(row["entry_id"], row["field_path"]) for row in rows}
    for entry_id in gen.TARGET_IDS:
        for field in gen.FIELDS_TO_DIFF:
            if (entry_id, field) not in seen:
                raise AssertionError(f"missing diff row: {entry_id} {field}")


def node_anchor(node: dict[str, Any]) -> tuple[str, str]:
    return node["file"], str(node["line"])


def check_semantic_anchors(patch_rows: list[dict[str, Any]]) -> None:
    by_id = {row["entry_id"]: row for row in patch_rows}
    for entry_id, expected in EXPECTED_ANCHORS.items():
        row = by_id[entry_id]
        if node_anchor(row["entry_point"]) != expected["entry"]:
            raise AssertionError(f"{entry_id} has unexpected entry_point anchor")
        if node_anchor(row["critical_operation"]) != expected["critical"]:
            raise AssertionError(f"{entry_id} has unexpected critical_operation anchor")
        if len(row["trace"]) != expected["trace_nodes"]:
            raise AssertionError(f"{entry_id} has unexpected trace length")
        if row["verify"] != 1:
            raise AssertionError(f"{entry_id} must be marked reviewed")


def request_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vulngym-n8n-semantic-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_bytes(url: str, attempts: int = 3) -> bytes:
    request = urllib.request.Request(url, headers=request_headers())
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.URLError:
            if attempt + 1 == attempts:
                raise
            time.sleep(1 + attempt)
    raise AssertionError("unreachable retry state")


def fetch_json(url: str) -> dict[str, Any]:
    return json.loads(fetch_bytes(url).decode("utf-8"))


def raw_url(row: dict[str, Any], file_name: str) -> str:
    repo = row["repo_url"].removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{repo}/{row['commit']}/{file_name}"


def source_slice(source: str, line: int | str) -> str:
    start, end = gen.parse_line_span(line)
    lines = source.splitlines()
    if end > len(lines):
        raise AssertionError(f"line span {line!r} exceeds source length {len(lines)}")
    return "\n".join(lines[start - 1 : end])


def check_upstream_sources(patch_rows: list[dict[str, Any]]) -> int:
    cache: dict[tuple[str, str], str] = {}
    for row in patch_rows:
        for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
            key = (row["commit"], node["file"])
            if key not in cache:
                cache[key] = fetch_bytes(raw_url(row, node["file"])).decode("utf-8")
            expected = source_slice(cache[key], node["line"])
            if node["code"] != expected:
                raise AssertionError(
                    f"code mismatch for {row['entry_id']} {node['file']}:{node['line']}"
                )
    return len(cache)


def check_fix_evidence(payloads: dict[str, dict[str, Any]]) -> None:
    for report_id, expected in FIX_EVIDENCE.items():
        payload = payloads[report_id]
        if payload.get("sha") != expected["sha"]:
            raise AssertionError(f"{report_id} fix commit mismatch")
        parents = payload.get("parents", [])
        if not parents or parents[0].get("sha") != expected["parent"]:
            raise AssertionError(f"{report_id} vulnerable commit is not the fix's first parent")
        patch = "\n".join(file.get("patch", "") for file in payload.get("files", []))
        for marker in expected["markers"]:
            if marker not in patch:
                raise AssertionError(f"{report_id} fix marker missing: {marker}")


def check_advisory_evidence(payloads: dict[str, dict[str, Any]]) -> None:
    for report_id, payload in payloads.items():
        if payload.get("ghsa_id", "").upper() != report_id:
            raise AssertionError(f"{report_id} advisory payload mismatch")
        if not payload.get("summary") or not payload.get("vulnerabilities"):
            raise AssertionError(f"{report_id} advisory lacks summary or affected versions")


def check_upstream_evidence() -> tuple[int, int]:
    fix_payloads = {
        report_id: fetch_json(
            f"{GITHUB_API}/repos/n8n-io/n8n/commits/{evidence['sha']}"
        )
        for report_id, evidence in FIX_EVIDENCE.items()
    }
    advisory_payloads = {
        report_id: fetch_json(f"{GITHUB_API}/advisories/{report_id}")
        for report_id in FIX_EVIDENCE
    }
    check_fix_evidence(fix_payloads)
    check_advisory_evidence(advisory_payloads)
    return len(fix_payloads), len(advisory_payloads)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help=(
            "compare every node with the vulnerable source and validate advisories, "
            "direct fix patches, and vulnerable-parent relationships"
        ),
    )
    args = parser.parse_args()

    baseline_rows = load_jsonl(gen.BASELINE_JSONL)
    patch_rows = load_jsonl(gen.PATCH_JSONL)
    fixed_rows = load_jsonl(gen.FULL_JSONL)
    expected_fixed_rows = gen.apply_patch_rows(baseline_rows, patch_rows)

    gen.validate_patch_rows(patch_rows)
    assert_same_rows("full fixed JSONL", fixed_rows, expected_fixed_rows)
    check_diff_csv()
    check_text_artifacts()
    check_semantic_anchors(patch_rows)

    print("n8n semantic artifacts verified")
    print(f"patch rows: {len(patch_rows)}")
    print(f"full rows: {len(fixed_rows)}")
    print(f"diff rows: {len(patch_rows) * len(gen.FIELDS_TO_DIFF)}")
    print("semantic anchors: ok")
    print("text integrity: ok")
    if args.check_upstream:
        source_files = check_upstream_sources(patch_rows)
        fix_commits, advisories = check_upstream_evidence()
        print(f"vulnerable source files: {source_files}, all snippets match")
        print(f"direct fix commits: {fix_commits}, parent relationships and patches match")
        print(f"GitHub advisories: {advisories}, metadata match")


if __name__ == "__main__":
    main()
