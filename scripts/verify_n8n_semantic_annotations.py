"""Verify n8n semantic annotation artifacts for issue #6."""

from __future__ import annotations

import argparse
import csv
import json
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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def assert_same_rows(label: str, actual: list[dict[str, Any]], expected: list[dict[str, Any]]) -> None:
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


def raw_url(row: dict[str, Any], file_name: str) -> str:
    repo = row["repo_url"].removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{repo}/{row['commit']}/{file_name}"


def source_slice(source: str, line: int | str) -> str:
    start, end = gen.parse_line_span(line)
    lines = source.rstrip("\n").splitlines()
    if end > len(lines):
        raise AssertionError(f"line span {line!r} exceeds source length {len(lines)}")
    return "\n".join(lines[start - 1 : end])


def check_upstream_sources(patch_rows: list[dict[str, Any]]) -> None:
    cache: dict[tuple[str, str], str] = {}
    for row in patch_rows:
        for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
            key = (row["commit"], node["file"])
            if key not in cache:
                request = urllib.request.Request(
                    raw_url(row, node["file"]),
                    headers={"User-Agent": "vulngym-n8n-semantic-verifier"},
                )
                for attempt in range(3):
                    try:
                        with urllib.request.urlopen(request, timeout=30) as response:
                            cache[key] = response.read().decode("utf-8")
                        break
                    except urllib.error.URLError:
                        if attempt == 2:
                            raise
                        time.sleep(1 + attempt)
            expected = source_slice(cache[key], node["line"])
            if node["code"] != expected:
                raise AssertionError(
                    f"code mismatch for {row['entry_id']} {node['file']}:{node['line']}"
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="fetch n8n raw sources and compare every repaired node's code snippet",
    )
    args = parser.parse_args()

    patch_rows = load_jsonl(gen.PATCH_JSONL)
    canonical_rows = load_jsonl(gen.CANONICAL_JSONL)

    gen.validate_patch_rows(patch_rows)
    if not gen.canonical_has_patch(canonical_rows, patch_rows):
        raise AssertionError("data/entries.jsonl does not contain the n8n semantic patch")
    check_diff_csv()
    check_text_artifacts()
    if args.check_upstream:
        check_upstream_sources(patch_rows)

    print("n8n semantic artifacts verified")
    print(f"patch rows: {len(patch_rows)}")
    print(f"canonical rows: {len(canonical_rows)}")
    print(f"diff rows: {len(patch_rows) * len(gen.FIELDS_TO_DIFF)}")
    if args.check_upstream:
        print("upstream source check: ok")


if __name__ == "__main__":
    main()
