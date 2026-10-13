#!/usr/bin/env python3
"""Independently verify code-location repair artifacts.

This verifier does not rerun the repair algorithm.  It proves that every
dataset mutation is represented by exactly one diff row, every diff row
matches the before/after datasets, repaired snippets exist at the recorded
vulnerable commit, and manual-review rows still identify the original nodes.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import repair_code_locations as repair


class VerificationError(RuntimeError):
    """Raised when a generated artifact is incomplete or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_csv(path: Path, fields: Sequence[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        require(reader.fieldnames == list(fields), f"{path}: unexpected header")
        return list(reader)


def task_map(
    entries: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], repair.NodeRef]:
    result: dict[tuple[str, str], repair.NodeRef] = {}
    for ref in repair.iter_nodes(entries):
        key = (ref.entry_id, ref.field_path)
        require(key not in result, f"duplicate node key: {key}")
        result[key] = ref
    return result


def csv_line(value: Any) -> str:
    return str(value)


def decoded_line(value: str, original: Any) -> int | str:
    if isinstance(original, int):
        require(value.isdigit(), f"integer line became non-integer: {value!r}")
        return int(value)
    return value


def get_mutable_node(
    entries: Sequence[dict[str, Any]], ref: repair.NodeRef
) -> dict[str, Any]:
    return repair._get_output_node(entries, ref)


def verify_source_match(
    row: Mapping[str, str],
    ref: repair.NodeRef,
    cache: repair.HttpSourceCache,
) -> None:
    file = repair.normalize_repo_path(row["new_file"])
    text = cache.read_file(ref.repo_url, ref.commit, file)
    require(text is not None, f"{ref.task_id}: repaired source is unavailable")
    span = repair.LineSpan.parse(
        decoded_line(row["new_line"], ref.node["line"])
    )
    patterns = [
        pattern
        for pattern in repair.build_patterns(row["new_code"])
        if pattern.lines
        and not pattern.unsafe_reason
        and pattern.mode == row["match_mode"]
    ]
    matches: list[repair.SourceMatch] = []
    for pattern in patterns:
        matches.extend(
            repair.find_matches(
                repair.source_lines(text),
                pattern,
                file=file,
                start_min=span.start,
                start_max=span.start,
            )
        )
    matches = [match for match in matches if span.contains_match(match)]
    require(
        len(set(matches)) == 1,
        f"{ref.task_id}: repaired location is not one exact source match",
    )
    match = matches[0]
    require(
        repair._match_sha(text, match) == row["source_sha256"],
        f"{ref.task_id}: source hash mismatch",
    )
    require(
        repair._source_url(ref, file, span.start) == row["source_url"],
        f"{ref.task_id}: source URL mismatch",
    )


def verify_artifacts(args: argparse.Namespace) -> dict[str, int]:
    original = repair.load_jsonl(args.input)
    fixed = repair.load_jsonl(args.output)
    reports = repair.load_jsonl(args.reports)
    repair.validate_dataset(original, reports)
    repair.validate_dataset(fixed, reports)
    require(len(original) == len(fixed), "entry count changed")

    before = task_map(original)
    after = task_map(fixed)
    require(before.keys() == after.keys(), "node set changed")

    diff_rows = load_csv(args.diff, repair.DIFF_FIELDS)
    human_rows = load_csv(args.needs_human, repair.HUMAN_FIELDS)
    source_rows = load_csv(args.source_manifest, repair.SOURCE_FIELDS)
    report = json.loads(args.report_json.read_text(encoding="utf-8"))
    require(isinstance(report, dict), "report JSON is not an object")
    require(
        "_elapsed_seconds" not in report and "elapsed_seconds" not in report,
        "runtime-dependent elapsed time leaked into deterministic report",
    )

    expected = copy.deepcopy(original)
    diff_keys: set[tuple[str, str]] = set()
    cache = repair.HttpSourceCache(args.cache_dir, offline=True)
    for row in diff_rows:
        key = (row["entry_id"], row["field_path"])
        require(key not in diff_keys, f"duplicate diff row: {key}")
        require(key in before, f"diff references unknown node: {key}")
        diff_keys.add(key)
        ref = before[key]
        old = ref.node
        new = after[key].node

        require(row["verify"] == str(ref.verify), f"{ref.task_id}: verify mismatch")
        require(row["repo_url"] == ref.repo_url, f"{ref.task_id}: repo mismatch")
        require(row["commit"] == ref.commit, f"{ref.task_id}: commit mismatch")
        require(row["old_file"] == str(old["file"]), f"{ref.task_id}: old file mismatch")
        require(row["old_line"] == csv_line(old["line"]), f"{ref.task_id}: old line mismatch")
        require(row["old_code"] == str(old["code"]), f"{ref.task_id}: old code mismatch")
        require(row["old_desc"] == str(old.get("desc", "")), f"{ref.task_id}: old desc mismatch")
        require(row["new_file"] == str(new["file"]), f"{ref.task_id}: new file mismatch")
        require(row["new_line"] == csv_line(new["line"]), f"{ref.task_id}: new line mismatch")
        require(row["new_code"] == str(new["code"]), f"{ref.task_id}: new code mismatch")
        require(row["new_desc"] == str(new.get("desc", "")), f"{ref.task_id}: new desc mismatch")
        require(old["code"] == new["code"], f"{ref.task_id}: code text changed")
        require(
            (old["file"], old["line"]) != (new["file"], new["line"]),
            f"{ref.task_id}: diff row has no location change",
        )
        require(row["candidate_count"] == "1", f"{ref.task_id}: fix was not unique")
        require(row["reason"] == "unique_source_match", f"{ref.task_id}: invalid fix reason")
        require(
            row["match_mode"] in {"verbatim", "annotation_projection"},
            f"{ref.task_id}: unsupported repair match mode",
        )
        require(
            ref.verify == 0 or row["match_mode"] == "verbatim",
            f"{ref.task_id}: verified repair is not verbatim",
        )
        verify_source_match(row, ref, cache)

        expected_node = get_mutable_node(expected, ref)
        expected_node["file"] = row["new_file"]
        expected_node["line"] = decoded_line(row["new_line"], old["line"])
        if "desc" in expected_node:
            expected_node["desc"] = row["new_desc"]

    require(expected == fixed, "fixed dataset contains an unlogged mutation")

    human_keys: set[tuple[str, str]] = set()
    review_ids: set[str] = set()
    for row in human_rows:
        key = (row["entry_id"], row["field_path"])
        require(key not in human_keys, f"duplicate human-review row: {key}")
        require(key not in diff_keys, f"node is both fixed and manual: {key}")
        require(key in before, f"manual row references unknown node: {key}")
        human_keys.add(key)
        ref = before[key]
        node = ref.node
        require(row["review_id"] not in review_ids, f"duplicate review ID: {row['review_id']}")
        review_ids.add(row["review_id"])
        require(row["review_id"] == repair._review_id(ref), f"{ref.task_id}: review ID mismatch")
        require(
            row["expected_node_sha256"] == repair._node_sha256(ref),
            f"{ref.task_id}: expected-node hash mismatch",
        )
        require(row["verify"] == str(ref.verify), f"{ref.task_id}: verify mismatch")
        require(row["repo_url"] == ref.repo_url, f"{ref.task_id}: repo mismatch")
        require(row["commit"] == ref.commit, f"{ref.task_id}: commit mismatch")
        require(row["file"] == str(node["file"]), f"{ref.task_id}: file mismatch")
        require(row["line"] == csv_line(node["line"]), f"{ref.task_id}: line mismatch")
        require(row["code"] == str(node["code"]), f"{ref.task_id}: code mismatch")
        require(row["desc"] == str(node.get("desc", "")), f"{ref.task_id}: desc mismatch")
        candidates = json.loads(row["candidates"])
        require(isinstance(candidates, list), f"{ref.task_id}: candidates must be a list")
        require(
            len(candidates) == int(row["candidate_count"]),
            f"{ref.task_id}: candidate count mismatch",
        )
        start = repair.LineSpan.parse(node["line"]).start
        require(
            row["source_url"] == repair._source_url(ref, str(node["file"]), start),
            f"{ref.task_id}: manual source URL mismatch",
        )

    source_keys: set[tuple[str, str]] = set()
    for row in source_rows:
        key = (row["repo_url"], row["commit"])
        require(key not in source_keys, f"duplicate source manifest row: {key}")
        source_keys.add(key)
        for field in (
            "files_requested",
            "files_available",
            "files_missing",
            "snapshot_required",
            "snapshot_available",
        ):
            require(row[field].isdigit(), f"{key}: invalid numeric source field {field}")
        requested = int(row["files_requested"])
        available = int(row["files_available"])
        missing = int(row["files_missing"])
        require(requested == available + missing, f"{key}: source totals do not balance")
        require(row["source_status"] in {"complete", "partial"}, f"{key}: invalid source status")

    expected_report = {
        "entries": len(original),
        "nodes": len(before),
        "fix_candidates": len(diff_rows),
        "changes_applied": len(diff_rows),
        "needs_human": len(human_rows),
        "source_commits": len(source_rows),
        "source_commits_complete": sum(
            row["source_status"] == "complete" for row in source_rows
        ),
        "input_sha256": repair.file_sha256(args.input),
        "output_sha256": repair.file_sha256(args.output),
    }
    for field, value in expected_report.items():
        require(report.get(field) == value, f"report field {field!r} is inconsistent")
    require(report.get("mode") == "fix", "committed report was not generated in fix mode")
    require(report.get("verified_policy") == "strict", "unexpected verified policy")
    require(
        report.get("source_commits") == report.get("source_commits_complete"),
        "source coverage is incomplete",
    )

    for path in (
        args.output,
        args.diff,
        args.needs_human,
        args.source_manifest,
        args.report_json,
        args.report_md,
    ):
        data = path.read_bytes()
        require(data.endswith(b"\n"), f"{path}: missing final LF")
        require(b"\r" not in data, f"{path}: contains CR line endings")

    return {
        "entries": len(original),
        "nodes": len(before),
        "fixes": len(diff_rows),
        "needs_human": len(human_rows),
        "source_commits": len(source_rows),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify generated VulnGym code-location repair artifacts.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=repair.DEFAULT_INPUT)
    parser.add_argument("--reports", type=Path, default=repair.DEFAULT_REPORTS)
    parser.add_argument("--output", type=Path, default=repair.DEFAULT_OUTPUT)
    parser.add_argument("--diff", type=Path, default=repair.DEFAULT_DIFF)
    parser.add_argument("--needs-human", type=Path, default=repair.DEFAULT_NEEDS_HUMAN)
    parser.add_argument("--report-json", type=Path, default=repair.DEFAULT_REPORT_JSON)
    parser.add_argument("--report-md", type=Path, default=repair.DEFAULT_REPORT_MD)
    parser.add_argument(
        "--source-manifest",
        type=Path,
        default=repair.DEFAULT_SOURCE_MANIFEST,
    )
    parser.add_argument("--cache-dir", type=Path, default=repair.DEFAULT_CACHE)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = verify_artifacts(args)
    except (VerificationError, repair.RepairError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"verification failed: {error}") from error
    print(
        "artifact verification passed: "
        f"{summary['entries']} entries, {summary['nodes']} nodes, "
        f"{summary['fixes']} fixes, {summary['needs_human']} manual, "
        f"{summary['source_commits']} source commits"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
