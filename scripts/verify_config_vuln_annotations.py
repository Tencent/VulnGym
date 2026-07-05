"""Verify config-vulnerability annotation artifacts for entry-00241..244."""

from __future__ import annotations

import argparse
import csv
import json
import urllib.request
from pathlib import Path
from typing import Any

import apply_config_vuln_patches as gen

ROOT = Path(__file__).resolve().parent.parent


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def assert_same_rows(label: str, actual: list[dict[str, Any]], expected: list[dict[str, Any]]) -> None:
    actual_dump = [gen.compact(row) for row in actual]
    expected_dump = [gen.compact(row) for row in expected]
    if actual_dump != expected_dump:
        raise AssertionError(f"{label} is not reproducible from generator")


def check_artifact_text() -> None:
    text_files = [
        ROOT / "reports" / "config_vuln_annotation.md",
        ROOT / "reports" / "config_vuln_acceptance_matrix.md",
        ROOT / "reports" / "config_vuln_fix_diff.csv",
    ]
    for path in text_files:
        text = path.read_text(encoding="utf-8")
        if "??" in text or "\ufffd" in text:
            raise AssertionError(f"possible encoding damage in {path}")


def check_diff_csv() -> None:
    with gen.DIFF_CSV.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected = len(gen.TARGET_IDS) * 3
    if len(rows) != expected:
        raise AssertionError(f"expected {expected} diff rows, got {len(rows)}")
    seen = {(row["entry_id"], row["field_path"]) for row in rows}
    for entry_id in gen.TARGET_IDS:
        for field in ("entry_point", "critical_operation", "trace"):
            if (entry_id, field) not in seen:
                raise AssertionError(f"missing diff row: {entry_id} {field}")


def check_upstream_sources() -> None:
    base = (
        "https://raw.githubusercontent.com/openclaw/openclaw/"
        f"{gen.UPSTREAM_COMMIT}/"
    )
    for file_name, expected in gen.SOURCE_FILES.items():
        url = base + file_name
        with urllib.request.urlopen(url, timeout=30) as response:
            actual = response.read().decode("utf-8").rstrip("\n")
        if actual != expected:
            raise AssertionError(f"upstream source mismatch: {file_name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="fetch OpenClaw raw files and compare the embedded source snippets",
    )
    args = parser.parse_args()

    baseline_rows = load_jsonl(gen.BASELINE_JSONL)
    expected_patch_rows = gen.build_patch_rows(baseline_rows)
    expected_fixed_rows = gen.apply_patch_rows(baseline_rows, expected_patch_rows)

    actual_patch_rows = load_jsonl(gen.PATCH_JSONL)
    actual_fixed_rows = load_jsonl(gen.FULL_JSONL)

    gen.validate_patch_rows(actual_patch_rows)
    assert_same_rows("patch JSONL", actual_patch_rows, expected_patch_rows)
    assert_same_rows("full fixed JSONL", actual_fixed_rows, expected_fixed_rows)
    check_diff_csv()
    check_artifact_text()
    if args.check_upstream:
        check_upstream_sources()

    print("config-vuln artifacts verified")
    print(f"patch rows: {len(actual_patch_rows)}")
    print(f"full rows: {len(actual_fixed_rows)}")
    print(f"diff rows: {len(gen.TARGET_IDS) * 3}")
    if args.check_upstream:
        print("upstream source check: ok")


if __name__ == "__main__":
    main()
