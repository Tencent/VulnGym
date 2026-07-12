#!/usr/bin/env python3
"""Repair VulnGym node locations by matching their code at the pinned commit."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


NODE_KEYS = ("entry_point", "critical_operation")
DIFF_FIELDS = (
    "entry_id", "field_path", "old_file", "old_line", "old_desc",
    "new_file", "new_line", "new_desc", "strategy",
)
HUMAN_FIELDS = (
    "entry_id", "field_path", "repo_url", "commit", "file", "line",
    "code", "desc", "reason", "candidate_count", "candidates",
)


def normalized_lines(text: str, trim_blank_edges: bool = True) -> list[str]:
    """Normalize indentation and horizontal whitespace, preserving line structure."""
    lines = [re.sub(r"\s+", " ", line.strip()) for line in text.splitlines()]
    if trim_blank_edges:
        while lines and not lines[0]:
            lines.pop(0)
        while lines and not lines[-1]:
            lines.pop()
    return lines


def parse_line(value: object) -> tuple[int, int] | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value, value
    if isinstance(value, str):
        match = re.fullmatch(r"(\d+)-(\d+)", value)
        if match and 0 < int(match[1]) <= int(match[2]):
            return int(match[1]), int(match[2])
    return None


def format_line(start: int, span: int, original: object) -> int | str:
    end = start + span - 1
    if span == 1 and isinstance(original, int):
        return start
    return f"{start}-{end}"


def update_desc_location(desc: object, old_line: object, new_line: object) -> object:
    """Update an explicit old line reference without inventing new prose."""
    if not isinstance(desc, str):
        return desc
    old, new = str(old_line), str(new_line)
    variants = {old}
    if "-" in old:
        variants.update({old.replace("-", "–"), old.replace("-", "—")})
    for variant in sorted(variants, key=len, reverse=True):
        desc = desc.replace(variant, new)
    return desc


def find_matches(text: str, code: str) -> list[int]:
    haystack = normalized_lines(text, trim_blank_edges=False)
    needle = normalized_lines(code)
    if not needle:
        return []
    width = len(needle)
    return [i + 1 for i in range(len(haystack) - width + 1) if haystack[i:i + width] == needle]


def iter_nodes(entry: dict) -> Iterator[tuple[str, dict]]:
    for key in NODE_KEYS:
        node = entry.get(key)
        if isinstance(node, dict):
            yield key, node
    for index, node in enumerate(entry.get("trace", [])):
        if isinstance(node, dict):
            yield f"trace[{index}]", node


def run_git(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def repo_slug(url: str) -> str:
    clean = url.rstrip("/").removesuffix(".git")
    parts = clean.split("/")
    if len(parts) < 2:
        raise ValueError(f"unsupported repository URL: {url}")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", "__".join(parts[-2:]))


class RepositorySnapshot:
    def __init__(self, repo_url: str, commit: str, cache_dir: Path, offline: bool = False):
        self.repo_url = repo_url
        self.commit = commit
        cache_dir = cache_dir.resolve()
        self.repo_dir = cache_dir / "repos" / repo_slug(repo_url)
        self.root = cache_dir / "worktrees" / repo_slug(repo_url) / commit
        self.offline = offline

    def prepare(self) -> None:
        if not self.repo_dir.exists():
            if self.offline:
                raise RuntimeError("repository is not present in the offline cache")
            self.repo_dir.parent.mkdir(parents=True, exist_ok=True)
            run_git(["clone", "--filter=blob:none", "--no-checkout", self.repo_url, str(self.repo_dir)])
        try:
            run_git(["cat-file", "-e", f"{self.commit}^{{commit}}"], self.repo_dir)
        except RuntimeError:
            if self.offline:
                raise RuntimeError("commit is not present in the offline cache") from None
            run_git(["fetch", "--filter=blob:none", "origin", self.commit], self.repo_dir)
    def prepare_worktree(self) -> None:
        if not (self.root.is_dir() and (self.root / ".git").exists()):
            if self.root.exists():
                raise RuntimeError(f"incomplete worktree must be removed: {self.root}")
            self.root.parent.mkdir(parents=True, exist_ok=True)
            run_git(["worktree", "add", "--detach", str(self.root), self.commit], self.repo_dir)

    def read(self, relative: str) -> str | None:
        relative = relative.replace("\\", "/").lstrip("/")
        if not relative or ".." in Path(relative).parts:
            return None
        if not self.root.is_dir():
            try:
                return run_git(["show", f"{self.commit}:{relative}"], self.repo_dir)
            except RuntimeError:
                return None
        path = self.root / relative.replace("/", os.sep)
        try:
            if not path.is_file() or path.is_symlink():
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def files(self) -> Iterator[tuple[str, str]]:
        self.prepare_worktree()
        output = run_git(["ls-tree", "-r", "--name-only", "HEAD"], self.root)
        for relative in output.splitlines():
            content = self.read(relative)
            if content is not None and "\0" not in content:
                yield relative.replace("\\", "/"), content


@dataclass(frozen=True)
class RepairResult:
    file: str | None = None
    line: int | str | None = None
    strategy: str | None = None
    reason: str | None = None
    candidates: tuple[str, ...] = ()


def locate(snapshot: RepositorySnapshot, node: dict) -> RepairResult:
    relative = str(node.get("file", "")).replace("\\", "/").removeprefix("./")
    code = node.get("code")
    location = parse_line(node.get("line"))
    needle = normalized_lines(code) if isinstance(code, str) else []
    if not relative or not needle:
        return RepairResult(reason="invalid or empty file/code")
    if location is None:
        return RepairResult(reason="invalid line value")

    content = snapshot.read(relative)
    matches = find_matches(content, code) if content is not None else []
    span = len(needle)
    start, end = location
    if start in matches and end == start + span - 1:
        return RepairResult(strategy="exact")

    nearby = [line for line in matches if abs(line - start) <= 5]
    if len(nearby) == 1:
        return RepairResult(relative, format_line(nearby[0], span, node["line"]), "nearby")
    if len(nearby) > 1:
        candidates = tuple(f"{relative}:{line}" for line in nearby)
        return RepairResult(reason="multiple matches within +/-5 lines", candidates=candidates)
    if len(matches) == 1:
        return RepairResult(relative, format_line(matches[0], span, node["line"]), "same_file")
    if len(matches) > 1:
        candidates = tuple(f"{relative}:{line}" for line in matches)
        return RepairResult(reason="multiple matches in original file", candidates=candidates)

    repository_matches: list[tuple[str, int]] = []
    for candidate_file, candidate_content in snapshot.files():
        for line in find_matches(candidate_content, code):
            repository_matches.append((candidate_file, line))
            if len(repository_matches) > 100:
                break
        if len(repository_matches) > 100:
            break
    if len(repository_matches) == 1:
        found_file, found_line = repository_matches[0]
        return RepairResult(found_file, format_line(found_line, span, node["line"]), "repository")
    candidates = tuple(f"{path}:{line}" for path, line in repository_matches)
    reason = "code not found in repository" if not candidates else "multiple matches in repository"
    return RepairResult(reason=reason, candidates=candidates)


def load_entries(path: Path) -> list[dict]:
    entries = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{number}: expected a JSON object")
            entries.append(value)
    return entries


def write_csv(path: Path, fields: Iterable[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/entries.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("entries.fixed.jsonl"))
    parser.add_argument("--diff", type=Path, default=Path("fix_diff.csv"))
    parser.add_argument("--needs-human", type=Path, default=Path("needs_human.csv"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/vulngym-location-fixer"))
    parser.add_argument("--verify", choices=("all", "0", "1"), default="all")
    parser.add_argument("--entry-id", action="append", help="process only this entry id (repeatable)")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)

    entries = load_entries(args.input)
    selected_ids = set(args.entry_id or [])
    snapshots: dict[tuple[str, str], RepositorySnapshot] = {}
    diffs: list[dict] = []
    human: list[dict] = []

    for entry in entries:
        if selected_ids and entry.get("entry_id") not in selected_ids:
            continue
        if args.verify != "all" and str(entry.get("verify")) != args.verify:
            continue
        key = (str(entry.get("repo_url", "")), str(entry.get("commit", "")))
        snapshot = snapshots.setdefault(key, RepositorySnapshot(*key, args.cache_dir, args.offline))
        try:
            snapshot.prepare()
        except (RuntimeError, ValueError) as exc:
            for field_path, node in iter_nodes(entry):
                human.append({
                    "entry_id": entry.get("entry_id"), "field_path": field_path,
                    "repo_url": key[0], "commit": key[1], **node,
                    "reason": f"repository unavailable: {exc}", "candidate_count": 0, "candidates": "",
                })
            continue
        for field_path, node in iter_nodes(entry):
            result = locate(snapshot, node)
            if result.strategy == "exact":
                continue
            if result.strategy:
                old_file, old_line, old_desc = node.get("file"), node.get("line"), node.get("desc", "")
                node["file"], node["line"] = result.file, result.line
                if "desc" in node:
                    node["desc"] = update_desc_location(node["desc"], old_line, result.line)
                diffs.append({
                    "entry_id": entry.get("entry_id"), "field_path": field_path,
                    "old_file": old_file, "old_line": old_line, "old_desc": old_desc,
                    "new_file": result.file, "new_line": result.line,
                    "new_desc": node.get("desc", ""), "strategy": result.strategy,
                })
            else:
                human.append({
                    "entry_id": entry.get("entry_id"), "field_path": field_path,
                    "repo_url": key[0], "commit": key[1], **node, "reason": result.reason,
                    "candidate_count": len(result.candidates), "candidates": " | ".join(result.candidates),
                })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    write_csv(args.diff, DIFF_FIELDS, diffs)
    write_csv(args.needs_human, HUMAN_FIELDS, human)
    print(f"wrote {len(entries)} entries, {len(diffs)} fixes, {len(human)} human-review items")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
