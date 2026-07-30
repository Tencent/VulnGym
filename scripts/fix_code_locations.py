#!/usr/bin/env python3
"""Repair VulnGym code snippet locations in entries.jsonl.

The script is intentionally conservative: it updates a node only when a code
snippet has exactly one plausible match for the attempted strategy. Ambiguous
or missing matches are written to needs_human.csv.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


NODE_FIELDS = ("entry_point", "critical_operation")
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
}
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".jar",
    ".class",
    ".wasm",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".lock",
}


@dataclass(frozen=True)
class Match:
    file: str
    start_line: int
    end_line: int

    @property
    def line_value(self) -> int | str:
        if self.start_line == self.end_line:
            return self.start_line
        return f"{self.start_line}-{self.end_line}"


@dataclass
class NodeRef:
    path: str
    node: dict[str, Any]


def normalize_line(line: str) -> str:
    return re.sub(r"[ \t]+", " ", line.strip())


def normalize_snippet(text: str) -> list[str]:
    lines = [normalize_line(line) for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def parse_line(value: Any) -> tuple[int, int] | None:
    if isinstance(value, int):
        return (value, value) if value > 0 else None
    if isinstance(value, str):
        value = value.strip()
        if value.isdigit():
            line = int(value)
            return (line, line) if line > 0 else None
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start > 0 and end >= start:
                return start, end
    return None


def iter_nodes(entry: dict[str, Any]) -> Iterable[NodeRef]:
    for field in NODE_FIELDS:
        node = entry.get(field)
        if isinstance(node, dict):
            yield NodeRef(field, node)
    trace = entry.get("trace")
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            if isinstance(node, dict):
                yield NodeRef(f"trace[{index}]", node)


def run_git(args: list[str], cwd: Path | None = None) -> None:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        details = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {details}")


def cache_name(repo_url: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_.-]+", "-", repo_url.rstrip("/").split("/")[-1])
    digest = hashlib.sha1(repo_url.encode("utf-8")).hexdigest()[:12]
    return f"{readable}-{digest}"


def cache_has_content(path: Path) -> bool:
    for child in ("mirrors", "worktrees"):
        candidate = path / child
        if candidate.is_dir() and any(candidate.iterdir()):
            return True
    return False


def resolve_cache_dir(cache_dir_arg: str | None) -> Path:
    if cache_dir_arg:
        return Path(cache_dir_arg).resolve()

    cwd_cache = (Path.cwd() / ".cache" / "repos").resolve()
    script_cache = (Path(__file__).resolve().parent / ".cache" / "repos").resolve()
    project_cache = (Path(__file__).resolve().parent.parent / ".cache" / "repos").resolve()

    for candidate in (cwd_cache, script_cache, project_cache):
        if cache_has_content(candidate):
            return candidate
    return cwd_cache


def ensure_repo(repo_url: str, commit: str, cache_dir: Path, no_clone: bool) -> Path:
    cache_dir = cache_dir.resolve()
    name = cache_name(repo_url)
    mirror_dir = cache_dir / "mirrors" / f"{name}.git"
    worktree_dir = cache_dir / "worktrees" / name / commit

    if worktree_dir.is_dir():
        return worktree_dir

    if not mirror_dir.exists():
        if no_clone:
            raise RuntimeError(f"repository cache is missing: {worktree_dir}")
        mirror_dir.parent.mkdir(parents=True, exist_ok=True)
        run_git(["init", "--bare", str(mirror_dir)])
        run_git(["remote", "add", "origin", repo_url], cwd=mirror_dir)

    try:
        run_git(["cat-file", "-e", f"{commit}^{{commit}}"], cwd=mirror_dir)
    except RuntimeError:
        if no_clone:
            raise RuntimeError(f"commit is missing from cache: {commit}")
        run_git(["fetch", "--depth", "1", "origin", commit], cwd=mirror_dir)

    existing = find_existing_worktree(mirror_dir, commit)
    if existing is not None:
        return existing

    worktree_dir.parent.mkdir(parents=True, exist_ok=True)
    run_git(["worktree", "add", "--detach", str(worktree_dir), commit], cwd=mirror_dir)
    return worktree_dir


def prefetch_commits(
    rows: list[dict[str, Any]], cache_dir: Path, no_clone: bool, verbose: bool
) -> None:
    """Fetch missing commits once per repository to avoid repeated network waits."""
    if no_clone:
        return

    grouped: dict[str, set[str]] = {}
    for entry in rows:
        repo_url = entry.get("repo_url")
        commit = entry.get("commit")
        if isinstance(repo_url, str) and isinstance(commit, str):
            grouped.setdefault(repo_url, set()).add(commit)

    for repo_url, commits in grouped.items():
        name = cache_name(repo_url)
        mirror_dir = cache_dir / "mirrors" / f"{name}.git"
        if not mirror_dir.exists():
            mirror_dir.parent.mkdir(parents=True, exist_ok=True)
            run_git(["init", "--bare", str(mirror_dir)])
            run_git(["remote", "add", "origin", repo_url], cwd=mirror_dir)

        missing: list[str] = []
        for commit in sorted(commits):
            try:
                run_git(["cat-file", "-e", f"{commit}^{{commit}}"], cwd=mirror_dir)
            except RuntimeError:
                missing.append(commit)
        if not missing:
            continue
        if verbose:
            print(f"[fetch] {repo_url} missing_commits={len(missing)}", file=sys.stderr)
        try:
            run_git(["fetch", "--no-tags", "--depth", "1", "origin", *missing], cwd=mirror_dir)
        except RuntimeError as exc:
            # Fall back to per-commit fetch in ensure_repo so one unavailable
            # object cannot prevent the other commits from being processed.
            if verbose:
                print(f"[fetch-warning] {repo_url}: {exc}", file=sys.stderr)


def find_existing_worktree(mirror_dir: Path, commit: str) -> Path | None:
    completed = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=mirror_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        return None

    current_path: Path | None = None
    current_head: str | None = None
    for line in [*completed.stdout.splitlines(), ""]:
        if line.startswith("worktree "):
            current_path = Path(line.removeprefix("worktree ")).resolve()
            current_head = None
        elif line.startswith("HEAD "):
            current_head = line.removeprefix("HEAD ").strip()
        elif line == "" and current_path is not None:
            if current_head == commit and current_path.is_dir():
                return current_path
            current_path = None
            current_head = None
    return None


def read_text_file(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def normalized_file_lines(path: Path) -> list[str] | None:
    text = read_text_file(path)
    if text is None:
        return None
    return [normalize_line(line) for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]


def match_at(lines: list[str], snippet: list[str], start_line: int) -> bool:
    if start_line < 1:
        return False
    start = start_line - 1
    end = start + len(snippet)
    return end <= len(lines) and lines[start:end] == snippet


def find_in_lines(lines: list[str], snippet: list[str], rel_file: str) -> list[Match]:
    if not snippet or len(snippet) > len(lines):
        return []
    matches: list[Match] = []
    width = len(snippet)
    for index in range(0, len(lines) - width + 1):
        if lines[index : index + width] == snippet:
            start = index + 1
            matches.append(Match(rel_file, start, start + width - 1))
    return matches


def search_nearby(
    lines: list[str],
    snippet: list[str],
    rel_file: str,
    line_range: tuple[int, int],
    radius: int,
) -> list[Match]:
    start_line = line_range[0]
    candidates = range(max(1, start_line - radius), min(len(lines), start_line + radius) + 1)
    return [Match(rel_file, line, line + len(snippet) - 1) for line in candidates if match_at(lines, snippet, line)]


def iter_repo_files(repo_dir: Path) -> Iterable[Path]:
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        root_path = Path(root)
        for filename in files:
            path = root_path / filename
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            yield path


class CommitContext:
    def __init__(self, repo_dir: Path):
        self.repo_dir = repo_dir
        self._line_cache: dict[str, list[str] | None] = {}

    def get_lines(self, rel_file: str) -> list[str] | None:
        if rel_file not in self._line_cache:
            path = self.repo_dir / rel_file
            if not path.is_file():
                self._line_cache[rel_file] = None
            else:
                self._line_cache[rel_file] = normalized_file_lines(path)
        return self._line_cache[rel_file]

    def search_repo(self, snippet: list[str]) -> list[Match]:
        matches: list[Match] = []
        for path in iter_repo_files(self.repo_dir):
            rel_file = path.relative_to(self.repo_dir).as_posix()
            lines = self.get_lines(rel_file)
            if lines is None:
                continue
            matches.extend(find_in_lines(lines, snippet, rel_file))
            if len(matches) > 1:
                return matches
        return matches


def choose_unique(matches: list[Match]) -> Match | None:
    unique = {(m.file, m.start_line, m.end_line): m for m in matches}
    return next(iter(unique.values())) if len(unique) == 1 else None


def repair_node(ctx: CommitContext, node: dict[str, Any], radius: int) -> tuple[str, Match | None, str | None]:
    rel_file = node.get("file")
    code = node.get("code")
    line_range = parse_line(node.get("line"))
    if not isinstance(rel_file, str) or not rel_file:
        return "human", None, "missing_file"
    if not isinstance(code, str) or not code.strip():
        return "human", None, "missing_code"
    if not line_range:
        return "human", None, "invalid_line"

    snippet = normalize_snippet(code)
    if not snippet:
        return "human", None, "empty_normalized_code"

    lines = ctx.get_lines(rel_file)
    expected_range = (line_range[0], line_range[0] + len(snippet) - 1)
    if lines is not None and line_range == expected_range and match_at(lines, snippet, line_range[0]):
        return "matched", Match(rel_file, line_range[0], line_range[0] + len(snippet) - 1), None

    if lines is not None:
        match = choose_unique(search_nearby(lines, snippet, rel_file, line_range, radius))
        if match:
            return "nearby_line", match, None

        match = choose_unique(find_in_lines(lines, snippet, rel_file))
        if match:
            return "same_file", match, None

    repo_matches = ctx.search_repo(snippet)
    match = choose_unique(repo_matches)
    if match:
        return "whole_repo", match, None
    if len(repo_matches) > 1:
        return "human", None, f"multiple_repo_matches:{len(repo_matches)}"
    if lines is None:
        return "human", None, "file_not_found_and_no_repo_match"
    return "human", None, "code_not_found"


def csv_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def sync_desc(old_desc: Any, old_file: Any, match: Match) -> str | None:
    """Keep location references in desc consistent after a file move.

    Most descriptions explain the unchanged code snippet, so a line-only move
    needs no wording change. For file moves, update explicit path or basename
    references when they are present; free-form semantic rewrites are left to
    human review rather than guessed.
    """
    if not isinstance(old_desc, str):
        return old_desc
    if not isinstance(old_file, str) or old_file == match.file:
        return old_desc

    updated = old_desc.replace(old_file, match.file)
    old_name = Path(old_file).name
    new_name = Path(match.file).name
    if old_name != new_name:
        updated = updated.replace(old_name, new_name)
    return updated


def validate_rows(rows: list[dict[str, Any]]) -> None:
    """Validate the SCHEMA.md constraints relevant to entries.jsonl."""
    previous_id = ""
    for index, entry in enumerate(rows, 1):
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or not re.fullmatch(r"entry-\d{5}", entry_id):
            raise SystemExit(f"row {index}: invalid entry_id: {entry_id!r}")
        if previous_id and entry_id < previous_id:
            raise SystemExit(f"row {index}: entries are not sorted by entry_id")
        previous_id = entry_id
        if not re.fullmatch(r"[0-9a-f]{40}", csv_text(entry.get("commit"))):
            raise SystemExit(f"{entry_id}: invalid commit")
        if not csv_text(entry.get("repo_url")).startswith("https://github.com/"):
            raise SystemExit(f"{entry_id}: invalid repo_url")
        if entry.get("verify") not in (0, 1):
            raise SystemExit(f"{entry_id}: verify must be 0 or 1")
        for ref in iter_nodes(entry):
            if not isinstance(ref.node.get("file"), str) or not ref.node["file"]:
                raise SystemExit(f"{entry_id} {ref.path}: invalid file")
            if not isinstance(ref.node.get("code"), str):
                raise SystemExit(f"{entry_id} {ref.path}: invalid code")
            if parse_line(ref.node.get("line")) is None:
                raise SystemExit(f"{entry_id} {ref.path}: invalid line")
            if "desc" in ref.node and not isinstance(ref.node["desc"], str):
                raise SystemExit(f"{entry_id} {ref.path}: invalid desc")


def process_entries(args: argparse.Namespace) -> tuple[int, int, int]:
    entries_path = Path(args.entries)
    output_path = Path(args.output)
    diff_path = Path(args.diff)
    human_path = Path(args.needs_human)
    cache_dir = resolve_cache_dir(args.cache_dir)
    only_ids = set(args.entry_id or [])

    rows: list[dict[str, Any]] = []
    with entries_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{entries_path}:{line_number}: invalid JSON: {exc}") from exc

    selected_rows = [
        entry
        for entry in rows
        if (not args.only_verify_zero or entry.get("verify") == 0)
        and (not only_ids or entry.get("entry_id") in only_ids)
    ]
    prefetch_commits(selected_rows, cache_dir, args.no_clone, args.verbose)

    contexts: dict[tuple[str, str], CommitContext] = {}
    repo_failures: dict[tuple[str, str], str] = {}
    diff_rows: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    processed_entries = 0

    for entry in rows:
        entry_id = entry.get("entry_id", "")
        if args.only_verify_zero and entry.get("verify") != 0:
            continue
        if only_ids and entry_id not in only_ids:
            continue
        processed_entries += 1

        repo_url = entry.get("repo_url")
        commit = entry.get("commit")
        if not isinstance(repo_url, str) or not isinstance(commit, str):
            for ref in iter_nodes(entry):
                human_rows.append(human_record(entry, ref, "missing_repo_url_or_commit"))
            continue

        key = (repo_url, commit)
        if key in repo_failures:
            for ref in iter_nodes(entry):
                human_rows.append(human_record(entry, ref, f"repo_unavailable:{repo_failures[key]}"))
            continue

        if key not in contexts:
            try:
                if args.verbose:
                    print(f"[repo] {entry_id} {repo_url} {commit}", file=sys.stderr)
                contexts[key] = CommitContext(ensure_repo(repo_url, commit, cache_dir, args.no_clone))
            except Exception as exc:  # noqa: BLE001 - reported per node for auditability.
                repo_failures[key] = str(exc)
                for ref in iter_nodes(entry):
                    human_rows.append(human_record(entry, ref, f"repo_unavailable:{exc}"))
                continue
        ctx = contexts[key]

        for ref in iter_nodes(entry):
            old_file = ref.node.get("file")
            old_line = ref.node.get("line")
            old_desc = ref.node.get("desc")
            strategy, match, reason = repair_node(ctx, ref.node, args.radius)
            if strategy == "matched":
                continue
            if match is None:
                human_rows.append(human_record(entry, ref, reason or "unknown"))
                continue

            ref.node["file"] = match.file
            ref.node["line"] = match.line_value
            if "desc" in ref.node:
                ref.node["desc"] = sync_desc(old_desc, old_file, match)
            diff_rows.append(
                {
                    "entry_id": entry_id,
                    "field_path": ref.path,
                    "old_file": csv_text(old_file),
                    "old_line": csv_text(old_line),
                    "old_desc": csv_text(old_desc),
                    "new_file": match.file,
                    "new_line": csv_text(match.line_value),
                    "new_desc": csv_text(ref.node.get("desc")),
                    "strategy": strategy,
                }
            )

    validate_rows(rows)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.parent.mkdir(parents=True, exist_ok=True)
    human_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        for entry in rows:
            handle.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")

    write_csv(
        diff_path,
        [
            "entry_id",
            "field_path",
            "old_file",
            "old_line",
            "old_desc",
            "new_file",
            "new_line",
            "new_desc",
            "strategy",
        ],
        diff_rows,
    )
    write_csv(
        human_path,
        ["entry_id", "field_path", "file", "line", "code", "desc", "reason"],
        human_rows,
    )
    return processed_entries, len(diff_rows), len(human_rows)


def human_record(entry: dict[str, Any], ref: NodeRef, reason: str) -> dict[str, Any]:
    return {
        "entry_id": entry.get("entry_id", ""),
        "field_path": ref.path,
        "file": csv_text(ref.node.get("file")),
        "line": csv_text(ref.node.get("line")),
        "code": csv_text(ref.node.get("code")),
        "desc": csv_text(ref.node.get("desc")),
        "reason": reason,
    }


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Repair VulnGym entries.jsonl code location offsets.")
    parser.add_argument("--entries", default="data/entries.jsonl", help="Input JSONL file.")
    parser.add_argument("--output", default="entries.fixed.jsonl", help="Output repaired JSONL file.")
    parser.add_argument("--diff", default="fix_diff.csv", help="CSV of automatic fixes.")
    parser.add_argument("--needs-human", default="needs_human.csv", help="CSV of ambiguous or unresolved nodes.")
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Directory for source repository cache. Defaults to an existing .cache/repos near the cwd or script.",
    )
    parser.add_argument("--radius", type=int, default=5, help="Line search radius around the original line.")
    parser.add_argument("--only-verify-zero", action="store_true", help="Only attempt verify=0 entries.")
    parser.add_argument("--entry-id", action="append", help="Limit processing to one entry_id; may be repeated.")
    parser.add_argument("--no-clone", action="store_true", help="Use existing repository cache only; never clone/fetch.")
    parser.add_argument("--verbose", action="store_true", help="Print repository checkout progress to stderr.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    total, fixed, human = process_entries(args)
    print(f"processed_entries={total}")
    print(f"automatic_fixes={fixed}")
    print(f"needs_human={human}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
