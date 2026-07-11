#!/usr/bin/env python3
"""Validate and conservatively repair VulnGym source-code node locations."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_CACHE = Path.home() / ".cache" / "vulngym" / "source-repos"
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
WHITESPACE_RE = re.compile(r"[ \t]+")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_RECORDED_MATCHES = 5

FIX_FIELDS = [
    "entry_id",
    "field_path",
    "old_file",
    "old_line",
    "old_desc",
    "new_file",
    "new_line",
    "new_desc",
    "strategy",
]
HUMAN_FIELDS = [
    "entry_id",
    "field_path",
    "file",
    "line",
    "desc",
    "reason",
    "candidates",
]


class RepairError(RuntimeError):
    """Raised when input validation or source retrieval fails."""


@dataclass(frozen=True)
class Match:
    file: str
    start: int
    end: int

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": format_match_line(self.start, self.end)}


@dataclass(frozen=True)
class NodeTask:
    task_id: int
    entry_index: int
    entry_id: str
    field_path: str
    node_key: str
    trace_index: int | None
    repo_url: str
    commit: str
    node: dict[str, Any]


@dataclass(frozen=True)
class TaskResult:
    task: NodeTask
    status: str
    strategy: str | None = None
    match: Match | None = None
    reason: str | None = None
    candidates: tuple[Match, ...] = ()


def parse_line(value: Any) -> tuple[int, int]:
    if isinstance(value, bool):
        raise RepairError(f"boolean is not a valid line: {value!r}")
    if isinstance(value, int):
        if value > 0:
            return value, value
        raise RepairError(f"line must be positive: {value!r}")
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return start, end
    raise RepairError(f"invalid line value: {value!r}")


def normalize_line(line: str) -> str:
    return WHITESPACE_RE.sub(" ", line.strip())


def normalize_code(code: str) -> tuple[str, ...]:
    lines = [normalize_line(line) for line in code.splitlines()]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return tuple(lines)


def normalized_source(text: str) -> tuple[str, ...]:
    return tuple(normalize_line(line) for line in text.splitlines())


def find_matches(
    source_lines: Sequence[str],
    snippet: Sequence[str],
    *,
    file: str,
    limit: int | None = None,
) -> list[Match]:
    if not snippet or len(snippet) > len(source_lines):
        return []
    matches: list[Match] = []
    width = len(snippet)
    for index in range(len(source_lines) - width + 1):
        candidate = tuple(source_lines[index : index + width])
        if source_lines[index] == snippet[0] and candidate == tuple(snippet):
            matches.append(Match(file=file, start=index + 1, end=index + width))
            if limit is not None and len(matches) >= limit:
                break
    return matches


def format_match_line(start: int, end: int) -> int | str:
    return start if start == end else f"{start}-{end}"


def repaired_line(original: int | str, match: Match) -> int | str:
    if isinstance(original, int):
        return match.start
    return f"{match.start}-{match.end}"


def match_has_annotated_location(line: int | str, match: Match) -> bool:
    start, end = parse_line(line)
    if isinstance(line, int):
        return match.start == start
    return match.start == start and match.end == end


def update_desc(
    desc: str | None,
    old_file: str,
    old_line: int | str,
    new_file: str,
    new_line: int | str,
) -> str | None:
    if desc is None:
        return None
    updated = desc
    if old_file != new_file:
        updated = updated.replace(old_file, new_file)
        old_name, new_name = Path(old_file).name, Path(new_file).name
        if old_name != new_name:
            updated = updated.replace(old_name, new_name)

    old_location = str(old_line)
    new_location = str(new_line)
    dash_pattern = re.escape(old_location).replace(r"\-", "[-–—]")
    patterns = [
        (rf"(第\s*){dash_pattern}(\s*行)", rf"\g<1>{new_location}\g<2>"),
        (rf"(?i)\b(lines?\s*){dash_pattern}\b", rf"\g<1>{new_location}"),
        (rf"(?i)\b(L\s*){dash_pattern}\b", rf"\g<1>{new_location}"),
    ]
    if old_location != new_location:
        for pattern, replacement in patterns:
            updated = re.sub(pattern, replacement, updated)
    return updated


def _run_git(repo: Path, args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess:
    command = ["git", f"--git-dir={repo}", *args]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise RepairError(f"failed to run git: {error}") from error
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RepairError(f"{' '.join(command)} failed: {stderr}")
    return result


class GitSourceRepository:
    def __init__(self, repo_url: str, cache_root: Path, max_file_bytes: int) -> None:
        self.repo_url = repo_url
        self.path = cache_root / cache_name(repo_url)
        self.max_file_bytes = max_file_bytes

    def prepare(self, commits: Sequence[str], *, offline: bool) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            if offline:
                raise RepairError(f"cache is missing for {self.repo_url}: {self.path}")
            subprocess.run(
                ["git", "init", "--quiet", "--bare", str(self.path)],
                check=True,
                stdout=subprocess.PIPE,
            )
            _run_git(self.path, ["remote", "add", "origin", self.repo_url])

        missing = [commit for commit in commits if not self.has_commit(commit)]
        if missing and offline:
            raise RepairError(f"{self.repo_url}: {len(missing)} commits are missing from cache")
        for offset in range(0, len(missing), 20):
            batch = missing[offset : offset + 20]
            _run_git(
                self.path,
                ["fetch", "--quiet", "--no-tags", "--depth=1", "origin", *batch],
            )

    def has_commit(self, commit: str) -> bool:
        result = _run_git(self.path, ["cat-file", "-e", f"{commit}^{{commit}}"], check=False)
        return result.returncode == 0

    def read_file(self, commit: str, file: str) -> str | None:
        result = _run_git(self.path, ["show", f"{commit}:{file}"], check=False)
        if result.returncode != 0:
            return None
        if len(result.stdout) > self.max_file_bytes or b"\x00" in result.stdout:
            return None
        return result.stdout.decode("utf-8", errors="replace")

    def iter_source_files(self, commit: str) -> Iterator[tuple[str, str]]:
        command = ["git", f"--git-dir={self.path}", "archive", "--format=tar", commit]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                for member in archive:
                    if not member.isfile() or member.size > self.max_file_bytes:
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        continue
                    content = stream.read()
                    if b"\x00" in content:
                        continue
                    yield member.name, content.decode("utf-8", errors="replace")
        except tarfile.TarError as error:
            process.kill()
            message = f"cannot read archive for {self.repo_url}@{commit}: {error}"
            raise RepairError(message) from error
        finally:
            process.stdout.close()
        stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
        return_code = process.wait()
        if return_code != 0:
            raise RepairError(f"git archive failed for {self.repo_url}@{commit}: {stderr.strip()}")

    def search_repository(
        self, commit: str, snippets: Iterable[tuple[str, ...]]
    ) -> dict[tuple[str, ...], list[Match]]:
        unique_snippets = set(snippets)
        matches: dict[tuple[str, ...], list[Match]] = {snippet: [] for snippet in unique_snippets}
        by_first_line: dict[str, list[tuple[str, ...]]] = defaultdict(list)
        for snippet in unique_snippets:
            if snippet:
                by_first_line[snippet[0]].append(snippet)

        for file, text in self.iter_source_files(commit):
            lines = normalized_source(text)
            for index, first_line in enumerate(lines):
                for snippet in by_first_line.get(first_line, ()):
                    if len(matches[snippet]) >= MAX_RECORDED_MATCHES:
                        continue
                    width = len(snippet)
                    if tuple(lines[index : index + width]) == snippet:
                        matches[snippet].append(
                            Match(file=file, start=index + 1, end=index + width)
                        )
        return matches


def cache_name(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RepairError(f"unsupported repository URL: {repo_url}")
    slug = parsed.path.strip("/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    if slug.count("/") != 1:
        raise RepairError(f"unsupported repository URL: {repo_url}")
    readable = re.sub(r"[^A-Za-z0-9_.-]+", "--", slug)
    digest = hashlib.sha256(repo_url.encode()).hexdigest()[:10]
    return f"{readable}--{digest}.git"


def validate_entries(entries: Sequence[dict[str, Any]]) -> None:
    seen_ids: set[str] = set()
    for row_number, entry in enumerate(entries, 1):
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or entry_id in seen_ids:
            raise RepairError(f"row {row_number}: invalid or duplicate entry_id")
        seen_ids.add(entry_id)
        if entry.get("verify") not in (0, 1) or isinstance(entry.get("verify"), bool):
            raise RepairError(f"{entry_id}: verify must be 0 or 1")
        if not isinstance(entry.get("repo_url"), str):
            raise RepairError(f"{entry_id}: repo_url must be a string")
        if not isinstance(entry.get("commit"), str) or not COMMIT_RE.fullmatch(entry["commit"]):
            raise RepairError(f"{entry_id}: invalid commit")
        for field_path, node in iter_entry_nodes(entry):
            if not isinstance(node, dict):
                raise RepairError(f"{entry_id}.{field_path}: node must be an object")
            if not isinstance(node.get("file"), str) or not node["file"]:
                raise RepairError(f"{entry_id}.{field_path}: invalid file")
            if not isinstance(node.get("code"), str):
                raise RepairError(f"{entry_id}.{field_path}: invalid code")
            if "desc" in node and not isinstance(node["desc"], str):
                raise RepairError(f"{entry_id}.{field_path}: invalid desc")
            parse_line(node.get("line"))


def iter_entry_nodes(entry: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    yield "entry_point", entry.get("entry_point")
    yield "critical_operation", entry.get("critical_operation")
    trace = entry.get("trace")
    if not isinstance(trace, list):
        raise RepairError(f"{entry.get('entry_id')}: trace must be an array")
    for index, node in enumerate(trace):
        yield f"trace[{index}]", node


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise RepairError(f"{path}:{line_number}: invalid JSON: {error}") from None
    validate_entries(entries)
    return entries


def build_tasks(entries: Sequence[dict[str, Any]], verify_filter: str) -> list[NodeTask]:
    tasks: list[NodeTask] = []
    for entry_index, entry in enumerate(entries):
        if verify_filter == "verified" and entry["verify"] != 1:
            continue
        if verify_filter == "unverified" and entry["verify"] != 0:
            continue
        for field_path, node in iter_entry_nodes(entry):
            if field_path.startswith("trace["):
                node_key, trace_index = "trace", int(field_path[6:-1])
            else:
                node_key, trace_index = field_path, None
            tasks.append(
                NodeTask(
                    task_id=len(tasks),
                    entry_index=entry_index,
                    entry_id=entry["entry_id"],
                    field_path=field_path,
                    node_key=node_key,
                    trace_index=trace_index,
                    repo_url=entry["repo_url"],
                    commit=entry["commit"],
                    node=node,
                )
            )
    return tasks


def repair_commit_tasks(
    repository: GitSourceRepository,
    commit: str,
    tasks: Sequence[NodeTask],
    nearby_lines: int,
) -> list[TaskResult]:
    results: list[TaskResult] = []
    repository_search: list[tuple[NodeTask, tuple[str, ...], str]] = []
    file_cache: dict[str, tuple[str, ...] | None] = {}

    for task in tasks:
        snippet = normalize_code(task.node["code"])
        if not snippet:
            results.append(TaskResult(task=task, status="human", reason="empty_code"))
            continue
        file = task.node["file"]
        if file not in file_cache:
            text = repository.read_file(commit, file)
            file_cache[file] = normalized_source(text) if text is not None else None
        lines = file_cache[file]
        if lines is None:
            repository_search.append((task, snippet, "original_file_missing"))
            continue

        matches = find_matches(lines, snippet, file=file)
        original_start, _ = parse_line(task.node["line"])
        if any(match_has_annotated_location(task.node["line"], match) for match in matches):
            results.append(TaskResult(task=task, status="matched", strategy="exact"))
            continue
        nearby = [
            match for match in matches if abs(match.start - original_start) <= nearby_lines
        ]
        if len(nearby) == 1:
            results.append(
                TaskResult(task=task, status="fixed", strategy="nearby_unique", match=nearby[0])
            )
        elif len(nearby) > 1:
            results.append(
                TaskResult(
                    task=task,
                    status="human",
                    reason="multiple_nearby_matches",
                    candidates=tuple(nearby[:MAX_RECORDED_MATCHES]),
                )
            )
        elif len(matches) == 1:
            results.append(
                TaskResult(task=task, status="fixed", strategy="file_unique", match=matches[0])
            )
        elif len(matches) > 1:
            results.append(
                TaskResult(
                    task=task,
                    status="human",
                    reason="multiple_file_matches",
                    candidates=tuple(matches[:MAX_RECORDED_MATCHES]),
                )
            )
        else:
            repository_search.append((task, snippet, "code_not_in_original_file"))

    if repository_search:
        repo_matches = repository.search_repository(
            commit, (snippet for _, snippet, _ in repository_search)
        )
        for task, snippet, initial_reason in repository_search:
            matches = repo_matches[snippet]
            if len(matches) == 1:
                results.append(
                    TaskResult(
                        task=task,
                        status="fixed",
                        strategy="repository_unique",
                        match=matches[0],
                    )
                )
            elif len(matches) > 1:
                results.append(
                    TaskResult(
                        task=task,
                        status="human",
                        reason="multiple_repository_matches",
                        candidates=tuple(matches),
                    )
                )
            else:
                reason = (
                    "original_file_missing_and_code_not_found"
                    if initial_reason == "original_file_missing"
                    else "code_not_found_in_repository"
                )
                results.append(
                    TaskResult(task=task, status="human", reason=reason)
                )
    return results


def get_output_node(entries: Sequence[dict[str, Any]], task: NodeTask) -> dict[str, Any]:
    entry = entries[task.entry_index]
    if task.node_key == "trace":
        assert task.trace_index is not None
        return entry["trace"][task.trace_index]
    return entry[task.node_key]


def apply_results(
    entries: Sequence[dict[str, Any]], results: Sequence[TaskResult]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    output = copy.deepcopy(entries)
    fixes: list[dict[str, Any]] = []
    needs_human: list[dict[str, Any]] = []

    for result in sorted(results, key=lambda item: item.task.task_id):
        task = result.task
        old_node = task.node
        if result.status == "fixed":
            assert result.match is not None and result.strategy is not None
            output_node = get_output_node(output, task)
            new_line = repaired_line(old_node["line"], result.match)
            new_desc = update_desc(
                old_node.get("desc"),
                old_node["file"],
                old_node["line"],
                result.match.file,
                new_line,
            )
            output_node["file"] = result.match.file
            output_node["line"] = new_line
            if "desc" in output_node:
                output_node["desc"] = new_desc
            fixes.append(
                {
                    "entry_id": task.entry_id,
                    "field_path": task.field_path,
                    "old_file": old_node["file"],
                    "old_line": old_node["line"],
                    "old_desc": old_node.get("desc", ""),
                    "new_file": result.match.file,
                    "new_line": new_line,
                    "new_desc": new_desc or "",
                    "strategy": result.strategy,
                }
            )
        elif result.status == "human":
            needs_human.append(
                {
                    "entry_id": task.entry_id,
                    "field_path": task.field_path,
                    "file": old_node["file"],
                    "line": old_node["line"],
                    "desc": old_node.get("desc", ""),
                    "reason": result.reason,
                    "candidates": json.dumps(
                        [candidate.as_dict() for candidate in result.candidates],
                        ensure_ascii=False,
                    ),
                }
            )
    validate_entries(output)
    return output, fixes, needs_human


def _atomic_text_write(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as stream:
        temporary_path = Path(stream.name)
        try:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary_path, path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    def writer(stream: Any) -> None:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    _atomic_text_write(path, writer)


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    def writer(stream: Any) -> None:
        csv_writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        csv_writer.writeheader()
        csv_writer.writerows(rows)

    _atomic_text_write(path, writer)


def write_json(path: Path, value: dict[str, Any]) -> None:
    def writer(stream: Any) -> None:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")

    _atomic_text_write(path, writer)


def prepare_repositories(
    tasks: Sequence[NodeTask],
    cache_root: Path,
    max_file_bytes: int,
    jobs: int,
    offline: bool,
) -> dict[str, GitSourceRepository]:
    commits_by_repo: dict[str, set[str]] = defaultdict(set)
    for task in tasks:
        commits_by_repo[task.repo_url].add(task.commit)
    repositories = {
        repo_url: GitSourceRepository(repo_url, cache_root, max_file_bytes)
        for repo_url in commits_by_repo
    }
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(
                repositories[repo_url].prepare,
                sorted(commits),
                offline=offline,
            ): repo_url
            for repo_url, commits in commits_by_repo.items()
        }
        for future in as_completed(futures):
            future.result()
    return repositories


def run_repairs(
    tasks: Sequence[NodeTask],
    repositories: dict[str, GitSourceRepository],
    nearby_lines: int,
    jobs: int,
) -> list[TaskResult]:
    tasks_by_commit: dict[tuple[str, str], list[NodeTask]] = defaultdict(list)
    for task in tasks:
        tasks_by_commit[(task.repo_url, task.commit)].append(task)
    results: list[TaskResult] = []
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(
                repair_commit_tasks,
                repositories[repo_url],
                commit,
                commit_tasks,
                nearby_lines,
            ): (repo_url, commit)
            for (repo_url, commit), commit_tasks in tasks_by_commit.items()
        }
        for future in as_completed(futures):
            results.extend(future.result())
    return sorted(results, key=lambda result: result.task.task_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=Path("entries.fixed.jsonl"))
    parser.add_argument("--diff-output", type=Path, default=Path("fix_diff.csv"))
    parser.add_argument("--human-output", type=Path, default=Path("needs_human.csv"))
    parser.add_argument(
        "--report-output", type=Path, default=Path("location_fix_report.json")
    )
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument(
        "--verify",
        choices=("all", "verified", "unverified"),
        default="all",
        help="select entries to check while preserving all rows in output",
    )
    parser.add_argument("--nearby-lines", type=int, default=5)
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--max-file-bytes", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--offline", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.nearby_lines < 0:
        parser.error("--nearby-lines must be non-negative")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.max_file_bytes < 1:
        parser.error("--max-file-bytes must be positive")
    output_paths = [
        args.output.resolve(),
        args.diff_output.resolve(),
        args.human_output.resolve(),
        args.report_output.resolve(),
    ]
    if args.input.resolve() in output_paths:
        parser.error("refusing to overwrite the input file")
    if len(output_paths) != len(set(output_paths)):
        parser.error("all output paths must be different")

    started = time.monotonic()
    try:
        entries = load_jsonl(args.input)
        tasks = build_tasks(entries, args.verify)
        repositories = prepare_repositories(
            tasks,
            args.cache_dir,
            args.max_file_bytes,
            args.jobs,
            args.offline,
        )
        results = run_repairs(tasks, repositories, args.nearby_lines, args.jobs)
        output, fixes, needs_human = apply_results(entries, results)
        status_counts = Counter(result.status for result in results)
        strategy_counts = Counter(result.strategy for result in results if result.strategy)
        reason_counts = Counter(result.reason for result in results if result.reason)
        report = {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "entries_total": len(entries),
            "entries_selected": len({task.entry_index for task in tasks}),
            "nodes_scanned": len(tasks),
            "repositories": len({task.repo_url for task in tasks}),
            "commits": len({(task.repo_url, task.commit) for task in tasks}),
            "status_counts": dict(sorted(status_counts.items())),
            "strategy_counts": dict(sorted(strategy_counts.items())),
            "human_reason_counts": dict(sorted(reason_counts.items())),
            "entries_modified": len({row["entry_id"] for row in fixes}),
            "entries_needing_human_review": len(
                {row["entry_id"] for row in needs_human}
            ),
            "descriptions_updated": sum(
                row["old_desc"] != row["new_desc"] for row in fixes
            ),
            "verify_filter": args.verify,
        }
        write_jsonl(args.output, output)
        write_csv(args.diff_output, FIX_FIELDS, fixes)
        write_csv(args.human_output, HUMAN_FIELDS, needs_human)
        write_json(args.report_output, report)
    except (OSError, RepairError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: {error}\n")

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"data: {args.output}")
    print(f"diff: {args.diff_output}")
    print(f"human review: {args.human_output}")
    print(f"report: {args.report_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
