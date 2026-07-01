#!/usr/bin/env python3
"""Conservatively repair VulnGym entry node file/line locations.

The script reads data/entries.jsonl as JSON objects, validates each
entry_point / critical_operation / trace[*] node against the corresponding
repository snapshot, and writes a fixed JSONL plus audit CSVs.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulngym_auto_expander.git_tool import commit_exists, git  # noqa: E402


DEFAULT_OUTPUT_DIR = ROOT / "outputs/location_fix"
MAX_SCAN_FILE_BYTES = 2_000_000
DIFF_FIELDS = [
    "entry_id",
    "report_id",
    "node_path",
    "old_file",
    "old_line",
    "old_desc",
    "new_file",
    "new_line",
    "new_desc",
    "strategy",
    "evidence",
]
HUMAN_FIELDS = [
    "entry_id",
    "report_id",
    "node_path",
    "file",
    "line",
    "code",
    "desc",
    "reason",
    "candidate_count",
    "candidates",
]


@dataclass(frozen=True)
class Span:
    start: int
    end: int


@dataclass(frozen=True)
class Match:
    file: str
    start: int
    end: int
    code: str

    @property
    def line_value(self) -> int | str:
        if self.start == self.end:
            return self.start
        return f"{self.start}-{self.end}"

    def preview(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line_value,
            "code_preview": self.code[:160],
        }


@dataclass
class RepairResult:
    node: dict[str, Any]
    strategy: str
    evidence: str
    candidates: list[Match]
    step_logs: list[dict[str, Any]]
    human_reason: str | None = None
    desc_review_required: bool = False
    changed: bool = False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=Path, default=ROOT / "data/entries.jsonl")
    parser.add_argument("--repo-cache", type=Path, default=ROOT / "repo")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR / "entries.fixed.jsonl")
    parser.add_argument("--diff-csv", type=Path, default=DEFAULT_OUTPUT_DIR / "fix_diff.csv")
    parser.add_argument("--needs-human-csv", type=Path, default=DEFAULT_OUTPUT_DIR / "needs_human.csv")
    parser.add_argument("--log", type=Path, help="optional combined step log")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "logs")
    parser.add_argument("--window", type=int, default=5)
    parser.add_argument("--only-unverified", action="store_true")
    parser.add_argument("--workers", type=int, default=1, help="number of entries to process in parallel")
    parser.add_argument("--quiet", action="store_true", help="suppress per-entry progress output")
    parser.add_argument(
        "--entry-id",
        action="append",
        default=[],
        help="entry id to process; may be supplied multiple times",
    )
    args = parser.parse_args()

    stats = run(
        entries_path=args.entries,
        repo_cache=args.repo_cache,
        output=args.output,
        diff_csv=args.diff_csv,
        needs_human_csv=args.needs_human_csv,
        log_path=args.log,
        log_dir=args.log_dir,
        window=args.window,
        only_unverified=args.only_unverified,
        entry_ids=set(args.entry_id),
        workers=args.workers,
        progress=not args.quiet,
    )
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return 0


def run(
    entries_path: Path,
    repo_cache: Path,
    output: Path,
    diff_csv: Path,
    needs_human_csv: Path,
    log_path: Path | None,
    log_dir: Path,
    window: int = 5,
    only_unverified: bool = False,
    entry_ids: set[str] | None = None,
    workers: int = 1,
    progress: bool = False,
) -> dict[str, int]:
    entries = load_jsonl(entries_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    diff_csv.parent.mkdir(parents=True, exist_ok=True)
    needs_human_csv.parent.mkdir(parents=True, exist_ok=True)
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    stats = {
        "entries_read": len(entries),
        "entries_processed": 0,
        "nodes_checked": 0,
        "nodes_changed": 0,
        "diff_rows": 0,
        "needs_human_rows": 0,
        "log_rows": 0,
    }
    diff_rows: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    log_rows: list[dict[str, Any]] = []

    selected = [
        (idx, entry)
        for idx, entry in enumerate(entries)
        if should_process_entry(entry, entry_ids, only_unverified)
    ]
    stats["entries_processed"] = len(selected)
    workers = max(1, workers)
    started_at = time.monotonic()
    if progress:
        print(
            f"Starting location repair: entries={len(selected)}/{len(entries)} "
            f"workers={workers} log_dir={log_dir}",
            flush=True,
        )

    if workers == 1:
        results = []
        for completed, (idx, entry) in enumerate(selected, 1):
            result = process_entry(idx, entry, repo_cache, window)
            write_entry_log(log_dir, entry, result["debug_rows"])
            print_progress(entries, result, completed, len(selected), started_at, progress)
            results.append(result)
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_idx = {
                executor.submit(process_entry, idx, entry, repo_cache, window): idx
                for idx, entry in selected
            }
            for completed, future in enumerate(as_completed(future_to_idx), 1):
                result = future.result()
                entry = entries[result["index"]]
                write_entry_log(log_dir, entry, result["debug_rows"])
                print_progress(entries, result, completed, len(selected), started_at, progress)
                results.append(result)
        results.sort(key=lambda item: item["index"])

    for result in results:
        stats["nodes_checked"] += result["nodes_checked"]
        stats["nodes_changed"] += result["nodes_changed"]
        diff_rows.extend(result["diff_rows"])
        human_rows.extend(result["human_rows"])
        log_rows.extend(result["debug_rows"])

    write_jsonl(output, entries)
    if log_path is not None:
        write_log(log_path, log_rows)
    write_csv(diff_csv, DIFF_FIELDS, diff_rows)
    write_csv(needs_human_csv, HUMAN_FIELDS, human_rows)
    stats["diff_rows"] = len(diff_rows)
    stats["needs_human_rows"] = len(human_rows)
    stats["log_rows"] = len(log_rows)
    if progress:
        elapsed = time.monotonic() - started_at
        print(
            f"Finished location repair in {elapsed:.1f}s: "
            f"nodes_checked={stats['nodes_checked']} nodes_changed={stats['nodes_changed']} "
            f"needs_human={stats['needs_human_rows']}",
            flush=True,
        )
    return stats


def should_process_entry(entry: dict[str, Any], entry_ids: set[str] | None, only_unverified: bool) -> bool:
    if entry_ids and entry.get("entry_id") not in entry_ids:
        return False
    if only_unverified and entry.get("verify") != 0:
        return False
    return True


def process_entry(index: int, entry: dict[str, Any], repo_cache: Path, window: int) -> dict[str, Any]:
    diff_rows: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    debug_rows: list[dict[str, Any]] = []
    nodes_checked = 0
    nodes_changed = 0
    repo = repo_path_for(entry.get("repo_url", ""), repo_cache)
    commit = str(entry.get("commit", ""))

    if repo is None or not repo.exists():
        for node_path, node in iter_nodes(entry):
            nodes_checked += 1
            human_rows.append(human_row(entry, node_path, node, "repo_missing", []))
            debug_rows.append(step_log(entry, node_path, node, "repo_check", "repo_missing", "local repo cache directory was not found"))
        return entry_result(index, nodes_checked, nodes_changed, diff_rows, human_rows, debug_rows)
    if not commit_exists(repo, commit):
        for node_path, node in iter_nodes(entry):
            nodes_checked += 1
            human_rows.append(human_row(entry, node_path, node, "commit_missing", []))
            debug_rows.append(step_log(entry, node_path, node, "commit_check", "commit_missing", "commit was not found in local repo"))
        return entry_result(index, nodes_checked, nodes_changed, diff_rows, human_rows, debug_rows)

    files_cache: dict[str, list[str] | None] = {}
    tree_files_cache: list[str] | None = None

    def get_tree_files() -> list[str]:
        nonlocal tree_files_cache
        if tree_files_cache is None:
            tree_files_cache = list_tree_files(repo, commit)
        return tree_files_cache

    for node_path, node in iter_nodes(entry):
        nodes_checked += 1
        result = repair_node(repo, commit, node, window, files_cache, get_tree_files)
        debug_rows.extend(
            with_entry_context(entry, node_path, node, item)
            for item in result.step_logs
        )
        if result.changed:
            old = dict(node)
            node.clear()
            node.update(result.node)
            diff_rows.append(diff_row(entry, node_path, old, result.node, result.strategy, result.evidence))
            nodes_changed += 1
        if result.human_reason is not None:
            human_rows.append(human_row(entry, node_path, result.node, result.human_reason, result.candidates))
        if result.desc_review_required:
            human_rows.append(human_row(entry, node_path, result.node, "desc_review_required", result.candidates))
    return entry_result(index, nodes_checked, nodes_changed, diff_rows, human_rows, debug_rows)


def entry_result(
    index: int,
    nodes_checked: int,
    nodes_changed: int,
    diff_rows: list[dict[str, Any]],
    human_rows: list[dict[str, Any]],
    debug_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "index": index,
        "nodes_checked": nodes_checked,
        "nodes_changed": nodes_changed,
        "diff_rows": diff_rows,
        "human_rows": human_rows,
        "debug_rows": debug_rows,
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from None
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_log(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        current_node = None
        for row in rows:
            node_key = (row["entry_id"], row["node_path"])
            if node_key != current_node:
                if current_node is not None:
                    handle.write("\n")
                current_node = node_key
                handle.write("=" * 100 + "\n")
                handle.write(
                    f"{row['entry_id']} {row['node_path']}  "
                    f"{row['file']}:{row['line']}  report={row['report_id']}\n"
                )
                handle.write(f"repo={row['repo_url']}\n")
                handle.write(f"commit={row['commit']}\n")
                handle.write("expected code:\n")
                handle.write(indent_block(row.get("expected_code", "")) + "\n")
                handle.write(f"expected normalized: {row.get('expected_normalized', '')!r}\n")
            handle.write("-" * 100 + "\n")
            handle.write(f"step={row['step']} status={row['status']}\n")
            handle.write(f"detail={row['detail']}\n")
            compared = row.get("compared")
            if compared:
                handle.write(
                    f"compared source: {compared.get('file')}:{compared.get('line')}\n"
                )
                handle.write("actual code:\n")
                handle.write(indent_block(str(compared.get("code", ""))) + "\n")
                handle.write(f"actual normalized: {compared.get('normalized', '')!r}\n")
            candidates = row.get("candidates") or []
            if candidates:
                handle.write(f"candidates ({len(candidates)}):\n")
                for idx, candidate in enumerate(candidates, 1):
                    handle.write(
                        f"  [{idx}] {candidate.get('file')}:{candidate.get('line')}\n"
                    )
                    handle.write(indent_block(str(candidate.get("code", "")), prefix="      ") + "\n")


def write_entry_logs(log_dir: Path, entry_logs: dict[str, list[dict[str, Any]]]) -> None:
    for entry_id, rows in entry_logs.items():
        report_id = str(rows[0].get("report_id", "unknown")) if rows else "unknown"
        path = log_dir / f"{safe_filename(entry_id)}_{safe_filename(report_id)}.log"
        write_log(path, rows)


def write_entry_log(log_dir: Path, entry: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    entry_id = str(entry.get("entry_id", "unknown"))
    report_id = str(entry.get("report_id", "unknown"))
    path = log_dir / f"{safe_filename(entry_id)}_{safe_filename(report_id)}.log"
    write_log(path, rows)


def print_progress(
    entries: list[dict[str, Any]],
    result: dict[str, Any],
    completed: int,
    total: int,
    started_at: float,
    enabled: bool,
) -> None:
    if not enabled:
        return
    entry = entries[result["index"]]
    entry_id = entry.get("entry_id", f"entry-index-{result['index']}")
    report_id = entry.get("report_id", "")
    elapsed = time.monotonic() - started_at
    print(
        f"[{completed}/{total}] {entry_id} {report_id} "
        f"nodes={result['nodes_checked']} changed={result['nodes_changed']} "
        f"needs_human={len(result['human_rows'])} elapsed={elapsed:.1f}s",
        flush=True,
    )


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def indent_block(value: str, prefix: str = "    ") -> str:
    if value == "":
        return prefix + "<empty>"
    return "\n".join(prefix + line for line in value.splitlines())


def repo_path_for(repo_url: str, repo_cache: Path) -> Path | None:
    if not isinstance(repo_url, str):
        return None
    parsed = urlparse(repo_url.removesuffix(".git"))
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    return repo_cache / f"{parts[0]}__{parts[1]}"


def iter_nodes(entry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("entry_point", "critical_operation"):
        node = entry.get(key)
        if isinstance(node, dict):
            yield key, node
    trace = entry.get("trace")
    if isinstance(trace, list):
        for idx, node in enumerate(trace):
            if isinstance(node, dict):
                yield f"trace[{idx}]", node


def repair_node(
    repo: Path,
    commit: str,
    node: dict[str, Any],
    window: int,
    files_cache: dict[str, list[str] | None],
    tree_files: Any,
) -> RepairResult:
    file_path = str(node.get("file", ""))
    code = str(node.get("code", ""))
    logs: list[dict[str, Any]] = []
    span = parse_line(node.get("line"))
    if span is None:
        logs.append(local_step("parse_line", "invalid_line", node, "line is neither a positive int nor a valid start-end range"))
        return RepairResult(dict(node), "", "", [], logs, human_reason="invalid_line")
    if not normalized(code):
        logs.append(local_step("normalize_code", "no_match", node, "code is empty after whitespace normalization"))
        return RepairResult(dict(node), "", "", [], logs, human_reason="no_match")

    lines = cached_file(repo, commit, file_path, files_cache)
    if lines is not None:
        original = match_at(file_path, lines, span.start, code)
        logs.append(
            local_step(
                "original_location",
                "matched" if original is not None else "not_matched",
                node,
                "compare node code with source at the recorded file/line",
                compared=candidate_log(original) if original is not None else compared_at(file_path, lines, span.start, code),
            )
        )
        if original is not None:
            if is_low_information_code(code):
                repo_matches = find_in_repo(repo, commit, code, tree_files(), files_cache)
                logs.append(
                    local_step(
                        "low_information_anchor",
                        "multiple_matches" if len(repo_matches) != 1 else "needs_desc_review",
                        node,
                        "original location matched, but the code is too generic to trust as a unique anchor",
                        candidates=repo_matches,
                    )
                )
                reason = "multiple_matches" if len(repo_matches) != 1 else "desc_review_required"
                evidence = "original location matched, but code is too generic to be a reliable anchor"
                return RepairResult(dict(node), "already_matched", evidence, repo_matches or [original], logs, human_reason=reason)
            return RepairResult(dict(node), "already_matched", "original file/line matched", [original], logs)

        low_information = is_low_information_code(code)
        near = find_in_file(file_path, lines, code, max(1, span.start - window), span.start + window)
        logs.append(
            local_step(
                "nearby_window",
                match_status(near),
                node,
                f"search original file from line {max(1, span.start - window)} to {span.start + window}",
                candidates=near,
            )
        )
        if len(near) == 1:
            if low_information:
                return RepairResult(
                    dict(node),
                    "",
                    "",
                    near,
                    logs,
                    human_reason="low_information_code",
                )
            return fixed_result(node, near[0], "nearby_window", f"unique match within +/-{window} lines", logs)
        if len(near) > 1:
            return RepairResult(dict(node), "", "", near, logs, human_reason="multiple_matches")

        full = find_in_file(file_path, lines, code, 1, len(lines))
        logs.append(
            local_step(
                "same_file",
                match_status(full),
                node,
                f"search entire original file with {len(lines)} lines",
                candidates=full,
            )
        )
        if len(full) == 1:
            if low_information:
                return RepairResult(
                    dict(node),
                    "",
                    "",
                    full,
                    logs,
                    human_reason="low_information_code",
                )
            return fixed_result(node, full[0], "same_file", "unique match in original file", logs)
        if len(full) > 1:
            return RepairResult(dict(node), "", "", full, logs, human_reason="multiple_matches")
    else:
        logs.append(local_step("read_original_file", "file_missing", node, "original file was not found or was skipped"))

    repo_matches = find_in_repo(repo, commit, code, tree_files(), files_cache)
    logs.append(
        local_step(
            "whole_repo",
            match_status(repo_matches),
            node,
            "search every readable text file in the commit snapshot",
            candidates=repo_matches,
        )
    )
    if len(repo_matches) == 1:
        if is_low_information_code(code):
            return RepairResult(
                dict(node),
                "",
                "",
                repo_matches,
                logs,
                human_reason="low_information_code",
            )
        return fixed_result(node, repo_matches[0], "whole_repo", "unique match in commit snapshot", logs)
    if len(repo_matches) > 1:
        return RepairResult(dict(node), "", "", repo_matches, logs, human_reason="multiple_matches")
    reason = "file_missing" if lines is None else "no_match"
    return RepairResult(dict(node), "", "", [], logs, human_reason=reason)


def cached_file(repo: Path, commit: str, file_path: str, cache: dict[str, list[str] | None]) -> list[str] | None:
    if file_path not in cache:
        cache[file_path] = safe_file_at_commit(repo, commit, file_path)
    return cache[file_path]


def safe_file_at_commit(repo: Path, commit: str, file_path: str) -> list[str] | None:
    rev = f"{commit}:{file_path}"
    if not git_object_exists(repo, rev):
        return None
    size = git_object_size(repo, rev)
    if size is not None and size > MAX_SCAN_FILE_BYTES:
        return None
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", rev],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if proc.returncode != 0 or b"\x00" in proc.stdout:
        return None
    return proc.stdout.decode("utf-8", errors="replace").splitlines()


def git_object_exists(repo: Path, rev: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", rev],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def git_object_size(repo: Path, rev: str) -> int | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-s", rev],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def list_tree_files(repo: Path, commit: str) -> list[str]:
    out = git(repo, "ls-tree", "-r", "--name-only", commit, check=False)
    return [line for line in out.splitlines() if line.strip()]


def parse_line(value: Any) -> Span | None:
    if isinstance(value, int):
        return Span(value, value) if value >= 1 else None
    if isinstance(value, str):
        if value.isdigit():
            number = int(value)
            return Span(number, number) if number >= 1 else None
        match = re.fullmatch(r"(\d+)-(\d+)", value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if 1 <= start <= end:
                return Span(start, end)
    return None


def match_at(file_path: str, lines: list[str], line: int, code: str) -> Match | None:
    code_line_count = max(1, len(code.splitlines()))
    if line < 1 or line > len(lines):
        return None
    end = min(len(lines), line + code_line_count - 1)
    candidate = lines[line - 1 : end]
    if normalized("\n".join(candidate)) == normalized(code):
        return Match(file_path, line, end, "\n".join(candidate).rstrip())
    return None


def compared_at(file_path: str, lines: list[str], line: int, code: str) -> dict[str, Any]:
    code_line_count = max(1, len(code.splitlines()))
    if line < 1 or line > len(lines):
        return {
            "file": file_path,
            "line": line,
            "code": "<line outside file range>",
            "normalized": "",
        }
    end = min(len(lines), line + code_line_count - 1)
    actual = "\n".join(lines[line - 1 : end]).rstrip()
    line_value: int | str = line if line == end else f"{line}-{end}"
    return {
        "file": file_path,
        "line": line_value,
        "code": actual,
        "normalized": normalized(actual),
    }


def find_in_file(file_path: str, lines: list[str], code: str, start: int, end: int) -> list[Match]:
    code_line_count = max(1, len(code.splitlines()))
    start = max(1, start)
    end = min(len(lines), end)
    matches: list[Match] = []
    for line_no in range(start, end + 1):
        last = line_no + code_line_count - 1
        if last > len(lines):
            break
        candidate = lines[line_no - 1 : last]
        if normalized("\n".join(candidate)) == normalized(code):
            matches.append(Match(file_path, line_no, last, "\n".join(candidate).rstrip()))
    return matches


def find_in_repo(
    repo: Path,
    commit: str,
    code: str,
    files: list[str],
    files_cache: dict[str, list[str] | None],
) -> list[Match]:
    matches: list[Match] = []
    for file_path in files:
        lines = cached_file(repo, commit, file_path, files_cache)
        if lines is None:
            continue
        matches.extend(find_in_file(file_path, lines, code, 1, len(lines)))
        if len(matches) > 1:
            return matches
    return matches


def match_status(matches: list[Match]) -> str:
    if len(matches) == 1:
        return "unique_match"
    if len(matches) > 1:
        return "multiple_matches"
    return "no_match"


def local_step(
    step: str,
    status: str,
    node: dict[str, Any],
    detail: str,
    compared: dict[str, Any] | None = None,
    candidates: list[Match] | None = None,
) -> dict[str, Any]:
    return {
        "step": step,
        "status": status,
        "detail": detail,
        "file": node.get("file", ""),
        "line": node.get("line", ""),
        "expected_code": node.get("code", ""),
        "expected_normalized": normalized(str(node.get("code", ""))),
        "compared": compared,
        "candidates": [candidate_log(item) for item in candidates or []],
    }


def step_log(
    entry: dict[str, Any],
    node_path: str,
    node: dict[str, Any],
    step: str,
    status: str,
    detail: str,
) -> dict[str, Any]:
    return with_entry_context(entry, node_path, node, local_step(step, status, node, detail))


def candidate_log(match: Match) -> dict[str, Any]:
    return {
        "file": match.file,
        "line": match.line_value,
        "code": match.code,
        "normalized": normalized(match.code),
    }


def with_entry_context(
    entry: dict[str, Any],
    node_path: str,
    node: dict[str, Any],
    row: dict[str, Any],
) -> dict[str, Any]:
    enriched = dict(row)
    enriched.update(
        {
            "entry_id": entry.get("entry_id", ""),
            "report_id": entry.get("report_id", ""),
            "repo_url": entry.get("repo_url", ""),
            "commit": entry.get("commit", ""),
            "node_path": node_path,
            "file": node.get("file", ""),
            "line": node.get("line", ""),
        }
    )
    return enriched


def normalized(value: str) -> str:
    return " ".join(value.strip().split())


def is_low_information_code(code: str) -> bool:
    norm = normalized(code)
    if not norm:
        return True
    if norm in {"}", "{", ");", "};", ")", "]", "];", "return;", "else {"}:
        return True
    if len(norm) <= 3:
        return True
    return False


def fixed_result(
    node: dict[str, Any],
    match: Match,
    strategy: str,
    evidence: str,
    logs: list[dict[str, Any]],
) -> RepairResult:
    fixed = dict(node)
    old_file = str(node.get("file", ""))
    old_line = node.get("line")
    fixed["file"] = match.file
    fixed["line"] = match.line_value
    fixed["code"] = match.code
    old_desc = str(node.get("desc", ""))
    desc_review = False
    if old_desc:
        fixed["desc"], desc_review = sync_desc_location(
            old_desc,
            old_file,
            old_line,
            match.file,
            match.line_value,
        )
    changed = (
        fixed.get("file") != node.get("file")
        or fixed.get("line") != node.get("line")
        or fixed.get("code") != node.get("code")
        or fixed.get("desc") != node.get("desc")
    )
    return RepairResult(fixed, strategy, evidence, [match], logs, desc_review_required=desc_review, changed=changed)


def sync_desc_line(desc: str, old_line: Any, new_line: Any) -> str:
    old_text = str(old_line)
    new_text = str(new_line)
    if not old_text or old_text == new_text:
        return desc
    return re.sub(rf"(?<!\d){re.escape(old_text)}(?!\d)", new_text, desc)


def sync_desc_location(
    desc: str,
    old_file: str,
    old_line: Any,
    new_file: str,
    new_line: Any,
) -> tuple[str, bool]:
    updated = sync_desc_line(desc, old_line, new_line)
    review_required = False

    if old_file != new_file:
        if old_file and old_file in updated:
            updated = updated.replace(old_file, new_file)
        old_name = Path(old_file).name
        new_name = Path(new_file).name
        if old_name and old_name != new_name and old_name in updated:
            updated = updated.replace(old_name, new_name)
        review_required = True

    if old_line != new_line and line_reference_still_present(updated, old_line):
        review_required = True
    return updated, review_required


def line_reference_still_present(desc: str, line: Any) -> bool:
    text = str(line)
    if not text:
        return False
    if re.search(rf"(?<!\d){re.escape(text)}(?!\d)", desc):
        return True
    span = parse_line(line)
    if span is None or span.start == span.end:
        return False
    return bool(
        re.search(rf"(?<!\d){span.start}(?!\d)", desc)
        or re.search(rf"(?<!\d){span.end}(?!\d)", desc)
    )


def diff_row(
    entry: dict[str, Any],
    node_path: str,
    old: dict[str, Any],
    new: dict[str, Any],
    strategy: str,
    evidence: str,
) -> dict[str, Any]:
    return {
        "entry_id": entry.get("entry_id", ""),
        "report_id": entry.get("report_id", ""),
        "node_path": node_path,
        "old_file": old.get("file", ""),
        "old_line": old.get("line", ""),
        "old_desc": old.get("desc", ""),
        "new_file": new.get("file", ""),
        "new_line": new.get("line", ""),
        "new_desc": new.get("desc", ""),
        "strategy": strategy,
        "evidence": evidence,
    }


def human_row(
    entry: dict[str, Any],
    node_path: str,
    node: dict[str, Any],
    reason: str,
    candidates: list[Match],
) -> dict[str, Any]:
    return {
        "entry_id": entry.get("entry_id", ""),
        "report_id": entry.get("report_id", ""),
        "node_path": node_path,
        "file": node.get("file", ""),
        "line": node.get("line", ""),
        "code": node.get("code", ""),
        "desc": node.get("desc", ""),
        "reason": reason,
        "candidate_count": len(candidates),
        "candidates": json.dumps([item.preview() for item in candidates], ensure_ascii=False),
    }


if __name__ == "__main__":
    raise SystemExit(main())
