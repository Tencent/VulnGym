#!/usr/bin/env python3
"""Conservatively repair VulnGym node locations from their code snippets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable, Optional, Union
from urllib.parse import urlparse


NODE_FIELDS = ("entry_point", "critical_operation")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
SEARCH_TOKEN_RE = re.compile(r"[A-Za-z_$@][A-Za-z0-9_$@./:-]{3,}")
DIFF_FIELDS = (
    "entry_id",
    "field_path",
    "old_file",
    "old_line",
    "old_desc",
    "new_file",
    "new_line",
    "new_desc",
    "strategy",
)
HUMAN_FIELDS = (
    "entry_id",
    "field_path",
    "file",
    "line",
    "code",
    "desc",
    "reason",
    "match_count",
    "candidates",
)


class SourceError(RuntimeError):
    """Raised when repository source cannot be prepared or read."""


def normalize_line(line: str) -> str:
    """Ignore leading/trailing whitespace and tab/space differences."""
    return re.sub(r"\s+", " ", line.strip())


def normalized_code_lines(code: str) -> list[str]:
    return [normalized for line in code.splitlines() if (normalized := normalize_line(line))]


def find_occurrences(text: str, code: str) -> list[tuple[int, int]]:
    """Return 1-based source spans whose normalized lines match code."""
    needle = normalized_code_lines(code)
    if not needle:
        return []

    source = [
        (line_number, normalized)
        for line_number, line in enumerate(text.splitlines(), 1)
        if (normalized := normalize_line(line))
    ]
    width = len(needle)
    matches: list[tuple[int, int]] = []
    for index in range(0, len(source) - width + 1):
        if [item[1] for item in source[index : index + width]] == needle:
            matches.append((source[index][0], source[index + width - 1][0]))
    return matches


def parse_line_span(value: Any) -> tuple[int, int]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value, value
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if match and int(match.group(1)) <= int(match.group(2)):
            return int(match.group(1)), int(match.group(2))
    raise ValueError(f"invalid line value: {value!r}")


def format_line_span(span: tuple[int, int]) -> Union[int, str]:
    start, end = span
    return start if start == end else f"{start}-{end}"


def line_value_text(value: Any) -> str:
    return str(value)


def select_search_token(code: str) -> Optional[str]:
    """Pick a selective whitespace-independent token for repository search."""
    tokens = SEARCH_TOKEN_RE.findall(code)
    if not tokens:
        return None
    return max(tokens, key=lambda token: (len(token), token))


def update_desc_location(
    desc: str,
    old_file: str,
    old_line: Any,
    new_file: str,
    new_line: Any,
) -> str:
    """Update explicit stale path/line references without rewriting semantics."""
    if not desc:
        return desc

    updated = desc
    if old_file != new_file:
        updated = updated.replace(old_file, new_file)
        old_name, new_name = Path(old_file).name, Path(new_file).name
        if old_name != new_name:
            updated = updated.replace(old_name, new_name)

    old_text = line_value_text(old_line)
    new_text = line_value_text(new_line)
    if old_text != new_text:
        old_line_pattern = re.escape(old_text)
        if "-" in old_text:
            old_line_pattern = re.escape(old_text).replace(r"\-", r"[-–—]")
        patterns = (
            (rf"第\s*{old_line_pattern}\s*行", f"第 {new_text} 行"),
            (rf"\blines?\s+{old_line_pattern}\b", f"line {new_text}"),
            (rf":{old_line_pattern}\b", f":{new_text}"),
        )
        for pattern, replacement in patterns:
            updated = re.sub(pattern, replacement, updated, flags=re.IGNORECASE)
    return updated


def repo_cache_name(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "__", parsed.path.strip("/").removesuffix(".git"))
    digest = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:10]
    return f"{slug}--{digest}.git"


class GitSourceCache:
    def __init__(self, cache_dir: Path, timeout: int = 180, offline: bool = False):
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.offline = offline
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._file_cache: dict[tuple[str, str, str], str] = {}
        self._grep_cache: dict[tuple[str, str, str], list[str]] = {}

    def repo_dir(self, repo_url: str) -> Path:
        return self.cache_dir / repo_cache_name(repo_url)

    def _run(
        self,
        args: list[str],
        *,
        check: bool = True,
        text: bool = True,
    ) -> subprocess.CompletedProcess[Any]:
        try:
            return subprocess.run(
                args,
                check=check,
                capture_output=True,
                text=text,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise SourceError(f"command timed out after {self.timeout}s: {' '.join(args[:4])}") from exc
        except subprocess.CalledProcessError as exc:
            message = (exc.stderr or exc.stdout or "").strip()
            raise SourceError(f"command failed ({exc.returncode}): {message[:500]}") from exc

    def _git(self, repo_url: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._run(
            ["git", f"--git-dir={self.repo_dir(repo_url)}", *args],
            check=check,
        )

    def prepare(self, repo_url: str, commits: Iterable[str]) -> None:
        repo_dir = self.repo_dir(repo_url)
        if not repo_dir.exists():
            if self.offline:
                raise SourceError(f"repository is not cached: {repo_url}")
            self._run(["git", "init", "--bare", str(repo_dir)])
            self._git(repo_url, "remote", "add", "origin", repo_url)

        missing: list[str] = []
        for commit in sorted(set(commits)):
            result = self._git(repo_url, "cat-file", "-e", f"{commit}^{{commit}}", check=False)
            if result.returncode != 0:
                missing.append(commit)

        if missing:
            if self.offline:
                raise SourceError(f"{len(missing)} commits are not cached for {repo_url}")
            # Fetch source-sized blobs with each requested commit. Large binary
            # blobs remain lazy, which keeps repeated dataset runs practical.
            self._git(
                repo_url,
                "fetch",
                "--no-tags",
                "--depth=1",
                "--filter=blob:limit=2m",
                "origin",
                *missing,
            )

    def read_file(self, repo_url: str, commit: str, file_path: str) -> str:
        key = (repo_url, commit, file_path)
        if key not in self._file_cache:
            result = self._git(repo_url, "show", f"{commit}:{file_path}", check=False)
            if result.returncode != 0:
                raise SourceError(f"file not found at commit: {file_path}")
            self._file_cache[key] = result.stdout
        return self._file_cache[key]

    def grep_files(self, repo_url: str, commit: str, token: str) -> list[str]:
        key = (repo_url, commit, token)
        if key in self._grep_cache:
            return self._grep_cache[key]

        result = self._git(
            repo_url,
            "grep",
            "-l",
            "-I",
            "-F",
            "-e",
            token,
            commit,
            "--",
            check=False,
        )
        if result.returncode not in (0, 1):
            message = (result.stderr or result.stdout).strip()
            raise SourceError(f"repository search failed: {message[:500]}")
        prefix = f"{commit}:"
        paths = [
            line[len(prefix) :] if line.startswith(prefix) else line.split(":", 1)[-1]
            for line in result.stdout.splitlines()
            if line
        ]
        self._grep_cache[key] = paths
        return paths


def iter_nodes(entry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for field in NODE_FIELDS:
        yield field, entry[field]
    for index, node in enumerate(entry["trace"]):
        yield f"trace[{index}]", node


def candidate_text(matches: list[tuple[str, tuple[int, int]]], limit: int = 20) -> str:
    rendered = [f"{path}:{format_line_span(span)}" for path, span in matches[:limit]]
    if len(matches) > limit:
        rendered.append(f"... and {len(matches) - limit} more")
    return " | ".join(rendered)


def repair_node(
    *,
    entry_id: str,
    field_path: str,
    node: dict[str, Any],
    repo_url: str,
    commit: str,
    source: GitSourceCache,
    near_lines: int,
    max_candidate_files: int,
) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """Return (diff row, human-review row); both None means already valid."""
    old_file = node.get("file")
    old_line = node.get("line")
    code = node.get("code")
    desc = node.get("desc", "")

    def human(
        reason: str,
        matches: Optional[list[tuple[str, tuple[int, int]]]] = None,
    ):
        found = matches or []
        return None, {
            "entry_id": entry_id,
            "field_path": field_path,
            "file": old_file,
            "line": old_line,
            "code": code,
            "desc": desc,
            "reason": reason,
            "match_count": len(found),
            "candidates": candidate_text(found),
        }

    if not isinstance(old_file, str) or not old_file:
        return human("invalid_file")
    if not isinstance(code, str) or not normalized_code_lines(code):
        return human("empty_or_whitespace_code")
    try:
        old_span = parse_line_span(old_line)
    except ValueError:
        return human("invalid_line")

    original_text: Optional[str]
    try:
        original_text = source.read_file(repo_url, commit, old_file)
    except SourceError:
        original_text = None

    file_matches: list[tuple[int, int]] = []
    if original_text is not None:
        file_matches = find_occurrences(original_text, code)
        if old_span in file_matches:
            return None, None

        nearby = [
            span for span in file_matches if abs(span[0] - old_span[0]) <= near_lines
        ]
        if len(nearby) == 1:
            chosen_file, chosen_span, strategy = old_file, nearby[0], "nearby_unique"
            return apply_repair(
                entry_id, field_path, node, old_file, old_line, desc,
                chosen_file, chosen_span, strategy,
            ), None

        if len(file_matches) == 1:
            chosen_file, chosen_span, strategy = old_file, file_matches[0], "file_unique"
            return apply_repair(
                entry_id, field_path, node, old_file, old_line, desc,
                chosen_file, chosen_span, strategy,
            ), None

    token = select_search_token(code)
    if token is None:
        reason = "ambiguous_in_file" if len(file_matches) > 1 else "no_selective_search_token"
        return human(reason, [(old_file, span) for span in file_matches])

    try:
        files = source.grep_files(repo_url, commit, token)
    except SourceError as exc:
        return human(f"repository_search_error: {exc}")
    if len(files) > max_candidate_files:
        return human(f"repository_search_too_broad: {len(files)} candidate files")

    repo_matches: list[tuple[str, tuple[int, int]]] = []
    for file_path in files:
        try:
            text = original_text if file_path == old_file and original_text is not None else source.read_file(
                repo_url, commit, file_path
            )
        except SourceError:
            continue
        repo_matches.extend((file_path, span) for span in find_occurrences(text, code))

    if len(repo_matches) == 1:
        chosen_file, chosen_span = repo_matches[0]
        return apply_repair(
            entry_id, field_path, node, old_file, old_line, desc,
            chosen_file, chosen_span, "repo_unique",
        ), None
    if not repo_matches:
        return human("code_not_found")
    return human("multiple_repository_matches", repo_matches)


def apply_repair(
    entry_id: str,
    field_path: str,
    node: dict[str, Any],
    old_file: str,
    old_line: Any,
    old_desc: str,
    new_file: str,
    new_span: tuple[int, int],
    strategy: str,
) -> dict[str, Any]:
    new_line = format_line_span(new_span)
    new_desc = update_desc_location(old_desc, old_file, old_line, new_file, new_line)
    node["file"] = new_file
    node["line"] = new_line
    if "desc" in node:
        node["desc"] = new_desc
    return {
        "entry_id": entry_id,
        "field_path": field_path,
        "old_file": old_file,
        "old_line": old_line,
        "old_desc": old_desc,
        "new_file": new_file,
        "new_line": new_line,
        "new_desc": new_desc,
        "strategy": strategy,
    }


def atomic_write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def atomic_write_csv(path: Path, fieldnames: tuple[str, ...], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def load_entries(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from None
    return entries


def selected(entry: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.entry_id and entry["entry_id"] not in args.entry_id:
        return False
    if args.only_unverified and entry.get("verify") != 0:
        return False
    return True


def validate_output(entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        if entry.get("verify") not in (0, 1):
            raise SystemExit(f"{entry.get('entry_id')}: invalid verify")
        for field_path, node in iter_nodes(entry):
            if not all(key in node for key in ("file", "line", "code")):
                raise SystemExit(f"{entry['entry_id']} {field_path}: missing node key")
            try:
                parse_line_span(node["line"])
            except ValueError as exc:
                raise SystemExit(f"{entry['entry_id']} {field_path}: {exc}") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/entries.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("entries.fixed.jsonl"))
    parser.add_argument("--diff", type=Path, default=Path("fix_diff.csv"))
    parser.add_argument("--needs-human", type=Path, default=Path("needs_human.csv"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/vulngym-source"))
    parser.add_argument("--entry-id", action="append", help="process only this entry; repeatable")
    parser.add_argument("--only-unverified", action="store_true")
    parser.add_argument("--offline", action="store_true", help="never fetch missing repositories/commits")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--near-lines", type=int, default=5)
    parser.add_argument("--max-candidate-files", type=int, default=500)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    started = time.monotonic()
    entries = load_entries(args.input)
    work_entries = [entry for entry in entries if selected(entry, args)]
    source = GitSourceCache(args.cache_dir, timeout=args.timeout, offline=args.offline)

    commits_by_repo: dict[str, set[str]] = defaultdict(set)
    for entry in work_entries:
        commits_by_repo[entry["repo_url"]].add(entry["commit"])

    prepare_errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
        futures = {
            executor.submit(source.prepare, repo, commits): repo
            for repo, commits in commits_by_repo.items()
        }
        for future in as_completed(futures):
            repo = futures[future]
            try:
                future.result()
            except Exception as exc:  # one failed repo must not discard other results
                prepare_errors[repo] = str(exc)

    diffs: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    checked = 0
    for entry in work_entries:
        repo_url = entry["repo_url"]
        if repo_url in prepare_errors:
            for field_path, node in iter_nodes(entry):
                human_rows.append(
                    {
                        "entry_id": entry["entry_id"],
                        "field_path": field_path,
                        "file": node.get("file"),
                        "line": node.get("line"),
                        "code": node.get("code"),
                        "desc": node.get("desc", ""),
                        "reason": f"source_prepare_error: {prepare_errors[repo_url]}",
                        "match_count": 0,
                        "candidates": "",
                    }
                )
            continue

        for field_path, node in iter_nodes(entry):
            checked += 1
            diff, human_row = repair_node(
                entry_id=entry["entry_id"],
                field_path=field_path,
                node=node,
                repo_url=repo_url,
                commit=entry["commit"],
                source=source,
                near_lines=args.near_lines,
                max_candidate_files=args.max_candidate_files,
            )
            if diff:
                diffs.append(diff)
            if human_row:
                human_rows.append(human_row)

    validate_output(entries)
    atomic_write_jsonl(args.output, entries)
    atomic_write_csv(args.diff, DIFF_FIELDS, diffs)
    atomic_write_csv(args.needs_human, HUMAN_FIELDS, human_rows)

    elapsed = time.monotonic() - started
    print(
        f"processed_entries={len(work_entries)} checked_nodes={checked} "
        f"fixed={len(diffs)} needs_human={len(human_rows)} elapsed={elapsed:.2f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
