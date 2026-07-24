"""Verify Issue #8 configuration-vulnerability annotations and evidence."""

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
from typing import Any, Iterable
from urllib.parse import quote

import apply_config_vuln_patches as gen

ROOT = Path(__file__).resolve().parent.parent
ADVISORY_ID = "GHSA-w7j5-j98m-w679"
MISSING_USER_FILES = (
    "scripts/e2e/Dockerfile",
    "scripts/e2e/Dockerfile.qr-import",
    "scripts/docker/install-sh-e2e/Dockerfile",
)
NONROOT_FILE = "scripts/docker/install-sh-nonroot/Dockerfile"
EXPECTED_LOCATIONS = {
    "entry-00241": {
        "entry_point": 1,
        "critical_operation": 23,
        "trace": [1, "19-21", 23],
    },
    "entry-00242": {
        "entry_point": 1,
        "critical_operation": 9,
        "trace": [1, 9],
    },
    "entry-00243": {
        "entry_point": 1,
        "critical_operation": 14,
        "trace": [1, "11-12", 14],
    },
    "entry-00244": {
        "entry_point": "17-18",
        "critical_operation": 18,
        "trace": ["17-18", 20, 27, 29],
    },
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def assert_same_rows(
    label: str,
    actual: list[dict[str, Any]],
    expected: list[dict[str, Any]],
) -> None:
    actual_dump = [gen.compact(row) for row in actual]
    expected_dump = [gen.compact(row) for row in expected]
    if actual_dump != expected_dump:
        raise AssertionError(f"{label} is not reproducible from generator")


def iter_text_values(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "code":
                continue
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_text_values(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_text_values(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def check_text_integrity(patch_rows: list[dict[str, Any]]) -> None:
    text_files = [
        ROOT / "reports" / "config_vuln_annotation.md",
        ROOT / "reports" / "config_vuln_acceptance_matrix.md",
        ROOT / "reports" / "config_vuln_fix_diff.csv",
    ]
    for path in text_files:
        text = path.read_text(encoding="utf-8")
        if "\ufffd" in text or re.search(r"\?{4,}", text):
            raise AssertionError(f"possible encoding damage in {path}")
    for row in patch_rows:
        for path, value in iter_text_values(row):
            if "\ufffd" in value or re.search(r"\?{4,}", value):
                raise AssertionError(
                    f"possible encoding damage in {row['entry_id']}:{path}"
                )


def check_diff_csv() -> None:
    with gen.DIFF_CSV.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected = len(gen.TARGET_IDS) * 4
    if len(rows) != expected:
        raise AssertionError(f"expected {expected} diff rows, got {len(rows)}")
    seen = {(row["entry_id"], row["field_path"]) for row in rows}
    for entry_id in gen.TARGET_IDS:
        for field in ("entry_point", "critical_operation", "trace", "verify"):
            if (entry_id, field) not in seen:
                raise AssertionError(f"missing diff row: {entry_id} {field}")


def check_semantic_anchors(patch_rows: list[dict[str, Any]]) -> None:
    by_id = {row["entry_id"]: row for row in patch_rows}
    if set(by_id) != set(gen.TARGET_IDS):
        raise AssertionError("Issue #8 patch does not contain exactly four targets")
    for entry_id, expected in EXPECTED_LOCATIONS.items():
        row = by_id[entry_id]
        if row["verify"] != 1:
            raise AssertionError(f"{entry_id} must be human-reviewed with verify=1")
        if row["entry_point"]["line"] != expected["entry_point"]:
            raise AssertionError(f"{entry_id} entry point is not the expected state origin")
        if row["critical_operation"]["line"] != expected["critical_operation"]:
            raise AssertionError(
                f"{entry_id} critical operation is not the narrow effect point"
            )
        trace_lines = [node["line"] for node in row["trace"]]
        if trace_lines != expected["trace"]:
            raise AssertionError(f"{entry_id} trace does not match the state lifecycle")

    for path in MISSING_USER_FILES:
        users = active_user_directives(gen.SOURCE_FILES[path])
        if users:
            raise AssertionError(f"unexpected USER directive in vulnerable {path}: {users}")
    nonroot_source = gen.SOURCE_FILES[NONROOT_FILE]
    if "USER app" not in active_user_directives(nonroot_source):
        raise AssertionError("entry-00244 must retain its nominal USER app transition")
    if "NOPASSWD:ALL" not in nonroot_source:
        raise AssertionError("entry-00244 is missing the explicit dangerous sudoers rule")


def active_user_directives(source: str) -> list[str]:
    return [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("USER ")
        and not line.lstrip().startswith("#")
    ]


def fetch_bytes(
    request: urllib.request.Request,
    timeout: int,
    attempts: int = 3,
) -> bytes:
    last_error: OSError | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError:
            raise
        except OSError as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.5 * (2**attempt))
    assert last_error is not None
    raise last_error


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VulnGym-config-vuln-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers=github_headers())
    return fetch_bytes(request, timeout).decode("utf-8")


def fetch_json(url: str, timeout: int) -> dict[str, Any]:
    payload = json.loads(fetch_text(url, timeout))
    if not isinstance(payload, dict):
        raise AssertionError(f"unexpected JSON payload from {url}")
    return payload


def check_upstream_sources(timeout: int) -> None:
    base = (
        "https://raw.githubusercontent.com/openclaw/openclaw/"
        f"{gen.UPSTREAM_COMMIT}/"
    )
    for file_name, expected in gen.SOURCE_FILES.items():
        actual = fetch_text(base + quote(file_name), timeout).rstrip("\n")
        if actual != expected:
            raise AssertionError(f"upstream source mismatch: {file_name}")


def validate_upstream_evidence(
    fix_payload: dict[str, Any],
    compare_payload: dict[str, Any],
    advisory_payload: dict[str, Any],
) -> None:
    if fix_payload.get("sha") != gen.FIX_COMMIT:
        raise AssertionError("unexpected OpenClaw fix commit")
    if (
        compare_payload.get("status") != "ahead"
        or compare_payload.get("behind_by") != 0
        or compare_payload.get("merge_base_commit", {}).get("sha")
        != gen.UPSTREAM_COMMIT
    ):
        raise AssertionError("vulnerable commit is not an ancestor of the fix commit")

    patches = {
        str(item.get("filename", "")): str(item.get("patch", ""))
        for item in fix_payload.get("files", [])
        if isinstance(item, dict)
    }
    for path in MISSING_USER_FILES:
        patch = patches.get(path, "")
        if "+USER appuser" not in patch:
            raise AssertionError(f"fix commit does not add USER appuser to {path}")
    if NONROOT_FILE in patches:
        raise AssertionError(
            "entry-00244 must not be presented as part of the missing-USER fix delta"
        )

    if advisory_payload.get("ghsa_id", "").lower() != ADVISORY_ID.lower():
        raise AssertionError("unexpected advisory response")
    description = str(advisory_payload.get("description", ""))
    for path in (*MISSING_USER_FILES, NONROOT_FILE):
        if path not in description:
            raise AssertionError(f"advisory does not list affected component {path}")
    if "NOPASSWD sudo" not in description:
        raise AssertionError("advisory does not distinguish the NOPASSWD variant")


def check_upstream_evidence(timeout: int) -> None:
    api = "https://api.github.com"
    fix_payload = fetch_json(
        f"{api}/repos/openclaw/openclaw/commits/{gen.FIX_COMMIT}",
        timeout,
    )
    compare_payload = fetch_json(
        f"{api}/repos/openclaw/openclaw/compare/"
        f"{gen.UPSTREAM_COMMIT}...{gen.FIX_COMMIT}",
        timeout,
    )
    advisory_payload = fetch_json(f"{api}/advisories/{ADVISORY_ID}", timeout)
    validate_upstream_evidence(fix_payload, compare_payload, advisory_payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="check vulnerable sources, advisory text, fix patch, and ancestry",
    )
    parser.add_argument("--timeout", type=int, default=30)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    baseline_rows = load_jsonl(gen.BASELINE_JSONL)
    expected_patch_rows = gen.build_patch_rows(baseline_rows)
    expected_fixed_rows = gen.apply_patch_rows(baseline_rows, expected_patch_rows)
    actual_patch_rows = load_jsonl(gen.PATCH_JSONL)
    actual_fixed_rows = load_jsonl(gen.FULL_JSONL)

    gen.validate_patch_rows(actual_patch_rows)
    assert_same_rows("patch JSONL", actual_patch_rows, expected_patch_rows)
    assert_same_rows("full fixed JSONL", actual_fixed_rows, expected_fixed_rows)
    check_semantic_anchors(actual_patch_rows)
    check_diff_csv()
    check_text_integrity(actual_patch_rows)
    if args.check_upstream:
        check_upstream_sources(args.timeout)
        check_upstream_evidence(args.timeout)

    print("config-vuln artifacts verified")
    print(f"patch rows: {len(actual_patch_rows)}")
    print(f"full rows: {len(actual_fixed_rows)}")
    print(f"diff rows: {len(gen.TARGET_IDS) * 4}")
    print("semantic anchors: ok")
    print("text integrity: ok")
    if args.check_upstream:
        print("vulnerable source match: ok")
        print("advisory evidence: ok")
        print("fix patch evidence: ok")
        print("commit ancestry: ok")


if __name__ == "__main__":
    main()
