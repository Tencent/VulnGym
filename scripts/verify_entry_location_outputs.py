#!/usr/bin/env python3
"""Verify issue #4 location-repair artifacts and VulnGym invariants."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

from repair_entry_locations import (
    DEFAULT_INPUT,
    DEFAULT_OUTPUT_DIR,
    DIFF_FIELDS,
    HUMAN_FIELDS,
    GitSourceCache,
    REPO_ROOT,
    iter_nodes,
    normalize_code_lines,
    parse_line_span,
    read_jsonl,
    sha256_file,
    validate_schema,
)


TRACE_PATH_RE = re.compile(r"^trace\[(\d+)]$")


def read_csv(path: Path, required_fields: Sequence[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(required_fields):
            raise AssertionError(
                f"{path}: unexpected header {reader.fieldnames!r}; expected {list(required_fields)!r}"
            )
        return list(reader)


def node_at(entry: dict[str, Any], field_path: str) -> dict[str, Any]:
    if field_path in {"entry_point", "critical_operation"}:
        node = entry.get(field_path)
    else:
        match = TRACE_PATH_RE.fullmatch(field_path)
        if not match:
            raise AssertionError(f"invalid field_path: {field_path}")
        trace = entry.get("trace")
        index = int(match.group(1))
        if not isinstance(trace, list) or index >= len(trace):
            raise AssertionError(f"missing field_path: {entry.get('entry_id')}:{field_path}")
        node = trace[index]
    if not isinstance(node, dict):
        raise AssertionError(f"node is not an object: {entry.get('entry_id')}:{field_path}")
    return node


def line_text(value: Any) -> str:
    return str(value)


def report_text(value: Any) -> str:
    """Normalize CSV-embedded newlines across Git checkout platforms."""
    return str(value).replace("\r\n", "\n").replace("\r", "\n")


def verify_reports(entries: list[dict[str, Any]], reports: list[dict[str, Any]]) -> None:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        grouped[entry["report_id"]].append(entry)
    report_by_id = {report["report_id"]: report for report in reports}
    assert len(report_by_id) == len(reports), "duplicate report_id"
    assert set(grouped) == set(report_by_id), "report/entry report_id sets differ"
    for report_id, rows in grouped.items():
        report = report_by_id[report_id]
        assert report["num_entries"] == len(rows), f"{report_id}: num_entries mismatch"
        expected = sorted(row["entry_id"] for row in rows)
        assert report["entry_ids"] == expected, f"{report_id}: entry_ids mismatch"


def verify_unchanged_structure(
    original: list[dict[str, Any]], fixed: list[dict[str, Any]]
) -> dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]]:
    assert len(original) == len(fixed), "row count changed"
    changed: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for old_entry, new_entry in zip(original, fixed, strict=True):
        entry_id = old_entry["entry_id"]
        assert new_entry["entry_id"] == entry_id, f"{entry_id}: order/id changed"
        assert set(old_entry) == set(new_entry), f"{entry_id}: top-level keys changed"
        for key in old_entry:
            if key not in {"entry_point", "critical_operation", "trace"}:
                assert old_entry[key] == new_entry[key], f"{entry_id}:{key} changed"

        old_nodes = [(path, node) for path, node, _ in iter_nodes(old_entry)]
        new_nodes = [(path, node) for path, node, _ in iter_nodes(new_entry)]
        assert [item[0] for item in old_nodes] == [item[0] for item in new_nodes], (
            f"{entry_id}: node shape changed"
        )
        for (field_path, old_node), (_, new_node) in zip(old_nodes, new_nodes, strict=True):
            assert set(old_node) == set(new_node), f"{entry_id}:{field_path}: node keys changed"
            assert old_node["code"] == new_node["code"], f"{entry_id}:{field_path}: code changed"
            for key in old_node:
                if key not in {"file", "line", "desc"}:
                    assert old_node[key] == new_node[key], f"{entry_id}:{field_path}:{key} changed"
            if old_node != new_node:
                changed[(entry_id, field_path)] = (old_node, new_node)
    return changed


def verify_diff(
    diff_rows: list[dict[str, str]],
    changed: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]],
    fixed_by_id: dict[str, dict[str, Any]],
) -> None:
    seen: set[tuple[str, str]] = set()
    for row in diff_rows:
        key = (row["entry_id"], row["field_path"])
        assert key not in seen, f"duplicate diff row: {key}"
        seen.add(key)
        assert key in changed, f"diff row has no corresponding change: {key}"
        old_node, new_node = changed[key]
        assert row["old_file"] == str(old_node["file"]), f"{key}: old_file mismatch"
        assert row["old_line"] == line_text(old_node["line"]), f"{key}: old_line mismatch"
        assert report_text(row["old_desc"]) == report_text(old_node.get("desc", "")), (
            f"{key}: old_desc mismatch"
        )
        assert row["new_file"] == str(new_node["file"]), f"{key}: new_file mismatch"
        assert row["new_line"] == line_text(new_node["line"]), f"{key}: new_line mismatch"
        assert report_text(row["new_desc"]) == report_text(new_node.get("desc", "")), (
            f"{key}: new_desc mismatch"
        )
        assert report_text(row["code"]) == report_text(new_node["code"]), (
            f"{key}: code mismatch"
        )
        assert row["strategy"], f"{key}: missing strategy"
        assert row["desc_status"], f"{key}: missing desc_status"
        assert row["evidence"], f"{key}: missing evidence"
        fixed_node = node_at(fixed_by_id[key[0]], key[1])
        assert fixed_node == new_node
    assert seen == set(changed), "some changed nodes are missing from fix_diff.csv"


def verify_human_queue(
    human_rows: list[dict[str, str]],
    original_by_id: dict[str, dict[str, Any]],
    fixed_by_id: dict[str, dict[str, Any]],
    changed_keys: set[tuple[str, str]],
) -> None:
    seen: set[tuple[str, str]] = set()
    for row in human_rows:
        key = (row["entry_id"], row["field_path"])
        assert key not in seen, f"duplicate human row: {key}"
        seen.add(key)
        assert key not in changed_keys, f"human queue overlaps automatic fix: {key}"
        assert row["reason"], f"{key}: missing human-review reason"
        old_node = node_at(original_by_id[key[0]], key[1])
        new_node = node_at(fixed_by_id[key[0]], key[1])
        assert old_node == new_node, f"{key}: human-review node was modified"
        assert row["file"] == str(old_node["file"]), f"{key}: human file mismatch"
        assert row["line"] == line_text(old_node["line"]), f"{key}: human line mismatch"
        assert report_text(row["code"]) == report_text(old_node["code"]), (
            f"{key}: human code mismatch"
        )
        assert report_text(row["desc"]) == report_text(old_node.get("desc", "")), (
            f"{key}: human desc mismatch"
        )


def verify_source_locations(
    fixed: list[dict[str, Any]],
    human_keys: set[tuple[str, str]],
    cache_dir: Path,
) -> tuple[int, int]:
    source_args = argparse.Namespace(
        cache_dir=cache_dir.resolve(),
        offline=True,
        git_protocol="https",
        git_timeout=120,
        max_file_bytes=8 * 1024 * 1024,
        max_repo_matches=50,
    )
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in fixed:
        grouped[entry["repo_url"]].append(entry)
    checked = 0
    skipped = 0
    for repo_url, entries in sorted(grouped.items()):
        source = GitSourceCache(repo_url, source_args)
        source.prepare({entry["commit"] for entry in entries})
        for entry in entries:
            for field_path, node, _ in iter_nodes(entry):
                key = (entry["entry_id"], field_path)
                if key in human_keys:
                    skipped += 1
                    continue
                span = parse_line_span(node["line"])
                needle = normalize_code_lines(node["code"])
                assert span is not None and needle, f"{key}: invalid source-check node"
                matches = source.search_file(
                    entry["commit"],
                    node["file"],
                    needle,
                    start_min=span.start,
                    start_max=span.start,
                )
                assert any(match.end == span.end for match in matches), (
                    f"{key}: fixed location does not match source at "
                    f"{entry['commit']}:{node['file']}:{node['line']}"
                )
                checked += 1
    return checked, skipped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--reports", type=Path, default=REPO_ROOT / "data" / "reports.jsonl")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument(
        "--source-cache",
        type=Path,
        help="offline bare-repository cache used to recheck every non-human node",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    original_path = args.original.resolve()
    reports_path = args.reports.resolve()
    output_dir = args.output_dir.resolve()
    fixed_path = output_dir / "entries.fixed.jsonl"
    diff_path = output_dir / "fix_diff.csv"
    human_path = output_dir / "needs_human.csv"
    summary_path = output_dir / "run_summary.json"

    try:
        original = read_jsonl(original_path)
        fixed = read_jsonl(fixed_path)
        reports = read_jsonl(reports_path)
        diff_rows = read_csv(diff_path, DIFF_FIELDS)
        human_rows = read_csv(human_path, HUMAN_FIELDS)
        summary = json.loads(summary_path.read_text(encoding="utf-8"))

        original_errors = validate_schema(original)
        fixed_errors = validate_schema(fixed)
        assert not original_errors, f"original schema errors: {original_errors[:5]}"
        assert not fixed_errors, f"fixed schema errors: {fixed_errors[:5]}"
        verify_reports(fixed, reports)

        changed = verify_unchanged_structure(original, fixed)
        original_by_id = {entry["entry_id"]: entry for entry in original}
        fixed_by_id = {entry["entry_id"]: entry for entry in fixed}
        assert len(original_by_id) == len(original)
        assert len(fixed_by_id) == len(fixed)
        verify_diff(diff_rows, changed, fixed_by_id)
        verify_human_queue(human_rows, original_by_id, fixed_by_id, set(changed))
        human_keys = {(row["entry_id"], row["field_path"]) for row in human_rows}

        assert summary["input_sha256"] == sha256_file(original_path), "input hash mismatch"
        assert summary["output_sha256"] == sha256_file(fixed_path), "output hash mismatch"
        assert summary["fix_rows"] == len(diff_rows), "fix count mismatch"
        assert summary["needs_human_rows"] == len(human_rows), "human count mismatch"
        assert summary["schema_errors"] == 0
        assert sum(summary["status_counts"].values()) == summary["selected_nodes"]
        if not args.allow_partial:
            assert summary["selected_entries"] == len(original) == 408
            assert summary["selected_nodes"] == sum(
                1 for entry in original for _ in iter_nodes(entry)
            ) == 2889
            assert summary["repo_count"] == len({entry["repo_url"] for entry in original}) == 23
            assert summary["repo_commit_groups"] == len(
                {(entry["repo_url"], entry["commit"]) for entry in original}
            ) == 166
        source_checked = 0
        source_skipped = len(human_rows)
        if args.source_cache:
            source_checked, source_skipped = verify_source_locations(
                fixed, human_keys, args.source_cache
            )
            assert source_checked + source_skipped == summary["selected_nodes"]
    except (AssertionError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1

    result = {
        "entries": len(fixed),
        "reports": len(reports),
        "nodes_checked": summary["selected_nodes"],
        "automatic_fixes": len(diff_rows),
        "needs_human": len(human_rows),
        "elapsed_seconds": summary["elapsed_seconds"],
        "schema_errors": 0,
        "source_nodes_checked": source_checked,
        "source_nodes_skipped_as_human": source_skipped,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
