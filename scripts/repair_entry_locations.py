#!/usr/bin/env python3
"""Conservatively repair VulnGym node locations from source snippets.

The default run checks every entry_point, critical_operation, and trace node
against the repository and commit recorded by the entry.  A mismatching node is
repaired only when its normalized code has exactly one match in the first
successful search scope:

1. original file, original start line +/- 5;
2. original file, full contents;
3. full repository tree at the recorded commit.

Ambiguous, missing, invalid, or low-information mismatches are never changed;
they are written to needs_human.csv.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "location_repair"
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "location_repair_repos_v2"

LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
NUMERIC_LINE_RE = re.compile(r"^[1-9]\d*$")
SPACE_RE = re.compile(r"[ \t]+")
MULTI_SLASH_RE = re.compile(r"/+" )
LEADING_DOT_RE = re.compile(r"^(?:\./)+")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ERE_SPECIAL_RE = re.compile(r"([.\[\]{}()*+?^$|\\])")

REQUIRED_ENTRY_FIELDS = {
    "commit",
    "critical_operation",
    "entry_id",
    "entry_point",
    "origin",
    "project",
    "repo_url",
    "report_id",
    "source_link",
    "trace",
    "verify",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_ids",
    "vuln_title",
}
REQUIRED_NODE_FIELDS = {"file", "line", "code"}
LOW_INFORMATION = {
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    ");",
    "};",
    "];",
    "else {",
    "return;",
}

DIFF_FIELDS = [
    "entry_id",
    "verify",
    "repo_url",
    "commit",
    "field_path",
    "code",
    "old_file",
    "old_line",
    "old_desc",
    "new_file",
    "new_line",
    "new_desc",
    "strategy",
    "desc_status",
    "evidence",
]
HUMAN_FIELDS = [
    "entry_id",
    "verify",
    "repo_url",
    "commit",
    "field_path",
    "file",
    "line",
    "code",
    "desc",
    "reason",
    "details",
]


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int


@dataclass(frozen=True, order=True)
class Match:
    file: str
    start: int
    end: int

    @property
    def line_value(self) -> int | str:
        return self.start if self.start == self.end else f"{self.start}-{self.end}"


@dataclass(frozen=True)
class Resolution:
    status: str
    match: Match | None = None
    strategy: str = ""
    reason: str = ""
    details: str = ""


class SourceError(RuntimeError):
    """Raised when a source repository or commit cannot be prepared."""


def normalize_repo_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def clone_url(repo_url: str, protocol: str) -> str:
    normalized = normalize_repo_url(repo_url)
    if normalized.startswith("https://github.com/"):
        tail = normalized.removeprefix("https://github.com/")
        if protocol == "ssh":
            return f"git@github.com:{tail}.git"
        return f"{normalized}.git"
    return repo_url


def cache_name(repo_url: str) -> str:
    normalized = normalize_repo_url(repo_url)
    tail = normalized.split("github.com/", 1)[-1].replace("/", "__")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", tail)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"{safe}__{digest}.git"


def normalize_path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = value.replace("\\", "/")
    value = LEADING_DOT_RE.sub("", value)
    return MULTI_SLASH_RE.sub("/", value)


def is_safe_repo_path(value: str) -> bool:
    if not value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def parse_line_span(value: Any) -> LineSpan | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return LineSpan(value, value) if value >= 1 else None
    if isinstance(value, str):
        if NUMERIC_LINE_RE.fullmatch(value):
            number = int(value)
            return LineSpan(number, number)
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return LineSpan(start, end)
    return None


def normalize_line(value: str) -> str:
    return SPACE_RE.sub(" ", value.strip())


def normalize_code_lines(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return tuple(normalize_line(line) for line in lines)


def is_low_information(needle: Sequence[str]) -> bool:
    combined = " ".join(needle).strip()
    if not combined or combined in LOW_INFORMATION:
        return True
    alphanumeric = re.sub(r"[^A-Za-z0-9_\u0080-\uffff]+", "", combined)
    return len(alphanumeric) < 4


def format_match_preview(matches: Sequence[Match], limit: int = 12) -> str:
    unique = sorted(set(matches))
    rendered = [f"{item.file}:{item.start}-{item.end}" for item in unique[:limit]]
    if len(unique) > limit:
        rendered.append(f"...(+{len(unique) - limit})")
    return "; ".join(rendered)


def unique_resolution(
    matches: Sequence[Match],
    *,
    strategy: str,
    scope: str,
) -> Resolution | None:
    unique = sorted(set(matches))
    if len(unique) == 1:
        return Resolution(
            status="fixed",
            match=unique[0],
            strategy=strategy,
            details=f"unique normalized match in {scope}: {format_match_preview(unique)}",
        )
    if len(unique) > 1:
        return Resolution(
            status="human",
            reason=f"multiple_matches_in_{scope}",
            details=f"candidate_count={len(unique)}; {format_match_preview(unique)}",
        )
    return None


def find_matches_in_lines(
    *,
    file: str,
    normalized_lines: Sequence[str],
    needle: Sequence[str],
    start_min: int | None = None,
    start_max: int | None = None,
) -> list[Match]:
    if not needle or len(normalized_lines) < len(needle):
        return []
    maximum = len(normalized_lines) - len(needle) + 1
    first = max(1, start_min if start_min is not None else 1)
    last = min(maximum, start_max if start_max is not None else maximum)
    if last < first:
        return []
    expected = tuple(needle)
    result: list[Match] = []
    for start in range(first, last + 1):
        offset = start - 1
        if tuple(normalized_lines[offset : offset + len(expected)]) == expected:
            result.append(Match(file=file, start=start, end=start + len(expected) - 1))
    return result


def anchor_pattern(needle: Sequence[str]) -> str:
    nonempty = [line for line in needle if line]
    anchor = max(nonempty, key=len, default="")
    pieces = re.split(r" +", anchor)
    escaped = [ERE_SPECIAL_RE.sub(r"\\\1", piece) for piece in pieces]
    return "[[:space:]]+".join(escaped)


def run_git(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 180,
    offline: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if offline:
        env["GIT_NO_LAZY_FETCH"] = "1"
    command = ["git"]
    if cwd is not None:
        command.extend(["-c", f"safe.directory={cwd.resolve().as_posix()}"])
    command.extend(args)
    try:
        return subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SourceError(f"git timeout after {timeout}s: {' '.join(args[:4])}") from exc


def git_error(result: subprocess.CompletedProcess[bytes], limit: int = 500) -> str:
    payload = result.stderr or result.stdout
    return payload.decode("utf-8", errors="replace").strip()[:limit]


class GitSourceCache:
    """Read source snapshots from one cached bare partial clone."""

    def __init__(self, repo_url: str, args: argparse.Namespace) -> None:
        self.repo_url = normalize_repo_url(repo_url)
        self.args = args
        self.path = args.cache_dir / cache_name(repo_url)
        self._files: dict[str, list[str]] = {}
        self._normalized: dict[tuple[str, str], list[str] | None] = {}
        self._repo_matches: dict[tuple[str, tuple[str, ...]], list[Match]] = {}

    def prepare(self, commits: Iterable[str]) -> None:
        self.args.cache_dir.mkdir(parents=True, exist_ok=True)
        if not (self.path / "HEAD").is_file():
            if self.args.offline:
                raise SourceError(f"repo_not_cached:{self.repo_url}")
            if self.path.exists():
                raise SourceError(f"cache_path_is_not_bare_repo:{self.path}")
            temporary = self.path.with_name(
                f"{self.path.name}.tmp-{os.getpid()}-{hash(self.repo_url) & 0xffff:x}"
            )
            if temporary.exists():
                shutil.rmtree(temporary)
            result = run_git(["init", "--bare", str(temporary)], timeout=60)
            if result.returncode == 0:
                result = run_git(
                    ["remote", "add", "origin", clone_url(self.repo_url, self.args.git_protocol)],
                    cwd=temporary,
                    timeout=60,
                )
            if result.returncode == 0:
                result = run_git(
                    ["config", "remote.origin.promisor", "true"], cwd=temporary, timeout=30
                )
            if result.returncode == 0:
                result = run_git(
                    [
                        "config",
                        "remote.origin.partialclonefilter",
                        f"blob:limit={self.args.max_file_bytes}",
                    ],
                    cwd=temporary,
                    timeout=30,
                )
            if result.returncode != 0:
                shutil.rmtree(temporary, ignore_errors=True)
                raise SourceError(f"cache_init_failed:{git_error(result)}")
            temporary.replace(self.path)

        missing = [commit for commit in sorted(set(commits)) if not self.has_commit(commit)]
        if not missing:
            return
        if self.args.offline:
            raise SourceError(f"commits_not_cached:{','.join(missing)}")

        result = run_git(
            [
                "fetch",
                f"--filter=blob:limit={self.args.max_file_bytes}",
                "--no-tags",
                "--depth=1",
                "origin",
                *missing,
            ],
            cwd=self.path,
            timeout=self.args.git_timeout,
        )
        if result.returncode != 0:
            for commit in missing:
                single = run_git(
                    [
                        "fetch",
                        f"--filter=blob:limit={self.args.max_file_bytes}",
                        "--no-tags",
                        "--depth=1",
                        "origin",
                        commit,
                    ],
                    cwd=self.path,
                    timeout=self.args.git_timeout,
                )
                if single.returncode != 0:
                    raise SourceError(f"fetch_failed:{commit}:{git_error(single)}")

        still_missing = [commit for commit in missing if not self.has_commit(commit)]
        if still_missing:
            raise SourceError(f"commit_unavailable:{','.join(still_missing)}")

    def has_commit(self, commit: str) -> bool:
        result = run_git(
            ["cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=self.path,
            timeout=30,
            offline=True,
        )
        return result.returncode == 0

    def list_files(self, commit: str) -> list[str]:
        if commit not in self._files:
            result = run_git(
                ["ls-tree", "-r", "-z", "--name-only", commit],
                cwd=self.path,
                timeout=90,
                offline=self.args.offline,
            )
            if result.returncode != 0:
                raise SourceError(f"ls_tree_failed:{commit}:{git_error(result)}")
            self._files[commit] = sorted(
                normalize_path(item.decode("utf-8", errors="surrogateescape"))
                for item in result.stdout.split(b"\0")
                if item
            )
        return self._files[commit]

    def normalized_lines(self, commit: str, file: str) -> list[str] | None:
        file = normalize_path(file)
        key = (commit, file)
        if key in self._normalized:
            return self._normalized[key]
        if not is_safe_repo_path(file):
            self._normalized[key] = None
            return None
        result = run_git(
            ["show", f"{commit}:{file}"],
            cwd=self.path,
            timeout=self.args.git_timeout,
            offline=self.args.offline,
        )
        if result.returncode != 0:
            if file in self.list_files(commit):
                raise SourceError(f"blob_unavailable:{commit}:{file}:{git_error(result)}")
            self._normalized[key] = None
            return None
        if len(result.stdout) > self.args.max_file_bytes:
            self._normalized[key] = None
            return None
        if b"\0" in result.stdout[:8192]:
            self._normalized[key] = None
            return None
        text = result.stdout.decode("utf-8", errors="replace")
        raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self._normalized[key] = [normalize_line(line) for line in raw_lines]
        return self._normalized[key]

    def search_file(
        self,
        commit: str,
        file: str,
        needle: Sequence[str],
        *,
        start_min: int | None = None,
        start_max: int | None = None,
    ) -> list[Match]:
        file = normalize_path(file)
        lines = self.normalized_lines(commit, file)
        if lines is None:
            return []
        return find_matches_in_lines(
            file=file,
            normalized_lines=lines,
            needle=needle,
            start_min=start_min,
            start_max=start_max,
        )

    def candidate_files(self, commit: str, needle: Sequence[str]) -> list[str]:
        pattern = anchor_pattern(needle)
        if not pattern:
            return self.list_files(commit)
        result = run_git(
            ["grep", "-I", "-l", "-z", "-E", pattern, commit, "--"],
            cwd=self.path,
            timeout=self.args.git_timeout,
            offline=self.args.offline,
        )
        if result.returncode == 1:
            return []
        if result.returncode != 0:
            return self.list_files(commit)
        prefix = f"{commit}:"
        candidates: list[str] = []
        for item in result.stdout.split(b"\0"):
            if not item:
                continue
            value = item.decode("utf-8", errors="surrogateescape")
            if value.startswith(prefix):
                value = value[len(prefix) :]
            value = normalize_path(value)
            if is_safe_repo_path(value):
                candidates.append(value)
        return sorted(set(candidates))

    def search_repo(self, commit: str, needle: Sequence[str]) -> list[Match]:
        key = (commit, tuple(needle))
        if key in self._repo_matches:
            return self._repo_matches[key]
        matches: list[Match] = []
        for file in self.candidate_files(commit, needle):
            matches.extend(self.search_file(commit, file, needle))
            if len(set(matches)) > self.args.max_repo_matches:
                break
        self._repo_matches[key] = sorted(set(matches))
        return self._repo_matches[key]


def resolve_node(
    source: GitSourceCache,
    *,
    commit: str,
    node: dict[str, Any],
    nearby_lines: int,
) -> Resolution:
    file = normalize_path(node.get("file"))
    span = parse_line_span(node.get("line"))
    needle = normalize_code_lines(node.get("code"))
    if not file or not is_safe_repo_path(file) or span is None:
        return Resolution(status="human", reason="invalid_file_or_line")
    if not needle:
        return Resolution(status="human", reason="empty_or_invalid_code")

    at_start = source.search_file(
        commit,
        file,
        needle,
        start_min=span.start,
        start_max=span.start,
    )
    exact = [match for match in at_start if match.end == span.end]
    if len(exact) == 1:
        return Resolution(status="ok", match=exact[0], strategy="exact_current_location")

    if is_low_information(needle):
        return Resolution(
            status="human",
            reason="low_information_code",
            details="mismatching snippet is too generic for a safe search",
        )

    nearby = source.search_file(
        commit,
        file,
        needle,
        start_min=span.start - nearby_lines,
        start_max=span.start + nearby_lines,
    )
    resolved = unique_resolution(
        nearby,
        strategy=(
            "current_start_span_repair"
            if len(set(nearby)) == 1 and nearby[0].start == span.start
            else f"nearby_plus_minus_{nearby_lines}"
        ),
        scope="nearby",
    )
    if resolved is not None:
        return resolved

    whole_file = source.search_file(commit, file, needle)
    resolved = unique_resolution(
        whole_file,
        strategy="same_file_unique",
        scope="original_file",
    )
    if resolved is not None:
        return resolved

    whole_repo = source.search_repo(commit, needle)
    resolved = unique_resolution(
        whole_repo,
        strategy="repository_unique",
        scope="repository",
    )
    if resolved is not None:
        return resolved
    return Resolution(status="human", reason="no_match", details="candidate_count=0")


def location_line_variants(value: Any) -> list[str]:
    text = str(value)
    variants = [text]
    if "-" in text:
        variants.extend([text.replace("-", "–"), text.replace("-", "—")])
    return variants


def synchronize_desc(
    desc: Any,
    *,
    old_file: str,
    old_line: Any,
    new_file: str,
    new_line: Any,
) -> tuple[Any, str]:
    if not isinstance(desc, str):
        return desc, "missing_desc"
    updated = desc
    old_file = normalize_path(old_file)
    new_file = normalize_path(new_file)
    old_name = PurePosixPath(old_file).name
    new_name = PurePosixPath(new_file).name
    if old_file != new_file:
        updated = updated.replace(old_file, new_file)
        if old_name and new_name and old_name != new_name:
            updated = updated.replace(old_name, new_name)

    if str(old_line) != str(new_line):
        replacement = str(new_line)
        for variant in location_line_variants(old_line):
            escaped = re.escape(variant)
            updated = re.sub(
                rf"(第\s*){escaped}(\s*行)",
                lambda match: f"{match.group(1)}{replacement}{match.group(2)}",
                updated,
            )
            updated = re.sub(
                rf"(?i)\b(lines?\s*){escaped}\b",
                lambda match: f"{match.group(1)}{replacement}",
                updated,
            )
            updated = re.sub(
                rf"({re.escape(new_name if old_file != new_file else old_name)}:){escaped}\b",
                lambda match: f"{match.group(1)}{replacement}",
                updated,
            )

    if updated != desc:
        return updated, "updated_location_references"
    return desc, "checked_no_location_reference"


def iter_nodes(entry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any], int]]:
    entry_point = entry.get("entry_point")
    if isinstance(entry_point, dict):
        yield "entry_point", entry_point, 0
    critical = entry.get("critical_operation")
    if isinstance(critical, dict):
        yield "critical_operation", critical, 1
    trace = entry.get("trace")
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            if isinstance(node, dict):
                yield f"trace[{index}]", node, index + 2


def human_row(
    entry: dict[str, Any],
    field_path: str,
    node: dict[str, Any],
    resolution: Resolution,
) -> dict[str, Any]:
    return {
        "entry_id": entry.get("entry_id", ""),
        "verify": entry.get("verify", ""),
        "repo_url": entry.get("repo_url", ""),
        "commit": entry.get("commit", ""),
        "field_path": field_path,
        "file": node.get("file", ""),
        "line": node.get("line", ""),
        "code": node.get("code", ""),
        "desc": node.get("desc", ""),
        "reason": resolution.reason,
        "details": resolution.details,
    }


def apply_match(
    entry: dict[str, Any],
    field_path: str,
    node: dict[str, Any],
    resolution: Resolution,
) -> dict[str, Any]:
    assert resolution.match is not None
    old_file = node.get("file", "")
    old_line = node.get("line", "")
    old_desc = node.get("desc", "")
    new_file = resolution.match.file
    new_line = resolution.match.line_value
    new_desc, desc_status = synchronize_desc(
        old_desc,
        old_file=old_file,
        old_line=old_line,
        new_file=new_file,
        new_line=new_line,
    )
    node["file"] = new_file
    node["line"] = new_line
    if "desc" in node:
        node["desc"] = new_desc
    return {
        "entry_id": entry.get("entry_id", ""),
        "verify": entry.get("verify", ""),
        "repo_url": entry.get("repo_url", ""),
        "commit": entry.get("commit", ""),
        "field_path": field_path,
        "code": node.get("code", ""),
        "old_file": old_file,
        "old_line": old_line,
        "old_desc": old_desc,
        "new_file": new_file,
        "new_line": new_line,
        "new_desc": new_desc,
        "strategy": resolution.strategy,
        "desc_status": desc_status,
        "evidence": resolution.details,
    }


def process_repository(
    repo_url: str,
    indexed_entries: Sequence[tuple[int, dict[str, Any]]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    source = GitSourceCache(repo_url, args)
    commits = {entry.get("commit", "") for _, entry in indexed_entries}
    entries_out: dict[int, dict[str, Any]] = {}
    diff_rows: list[tuple[int, int, dict[str, Any]]] = []
    human_rows: list[tuple[int, int, dict[str, Any]]] = []
    stats: Counter[str] = Counter()
    def unavailable_result(exc: SourceError) -> dict[str, Any]:
        unavailable_entries: dict[int, dict[str, Any]] = {}
        unavailable_human: list[tuple[int, int, dict[str, Any]]] = []
        unavailable_stats: Counter[str] = Counter()
        reason = Resolution(status="human", reason="repository_unavailable", details=str(exc)[:600])
        for row_index, original in indexed_entries:
            entry = copy.deepcopy(original)
            for field_path, node, node_order in iter_nodes(entry):
                unavailable_human.append(
                    (row_index, node_order, human_row(entry, field_path, node, reason))
                )
                unavailable_stats["human"] += 1
            unavailable_entries[row_index] = entry
        return {
            "repo_url": repo_url,
            "entries": unavailable_entries,
            "diff": [],
            "human": unavailable_human,
            "stats": unavailable_stats,
            "error": str(exc),
        }

    try:
        source.prepare(commits)
    except SourceError as exc:
        return unavailable_result(exc)

    try:
        for row_index, original in indexed_entries:
            entry = copy.deepcopy(original)
            commit = entry.get("commit", "")
            for field_path, node, node_order in iter_nodes(entry):
                resolution = resolve_node(
                    source,
                    commit=commit,
                    node=node,
                    nearby_lines=args.nearby_lines,
                )
                stats[resolution.status] += 1
                if resolution.status == "fixed":
                    diff_rows.append(
                        (row_index, node_order, apply_match(entry, field_path, node, resolution))
                    )
                elif resolution.status == "human":
                    human_rows.append(
                        (row_index, node_order, human_row(entry, field_path, node, resolution))
                    )
            entries_out[row_index] = entry
    except SourceError as exc:
        return unavailable_result(exc)
    return {
        "repo_url": repo_url,
        "entries": entries_out,
        "diff": diff_rows,
        "human": human_rows,
        "stats": stats,
        "error": "",
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from None
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number}: row must be an object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def write_csv(path: Path, fieldnames: Sequence[str], rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: Path) -> str:
    """Hash UTF-8 text with canonical LF newlines for cross-platform runs."""
    digest = hashlib.sha256()
    with path.open("r", encoding="utf-8", newline=None) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), ""):
            digest.update(chunk.encode("utf-8"))
    return digest.hexdigest()


def validate_schema(rows: Sequence[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(rows, 1):
        entry_id = entry.get("entry_id", f"row-{index}")
        if entry_id in seen:
            errors.append(f"{entry_id}: duplicate entry_id")
        seen.add(entry_id)
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        if missing:
            errors.append(f"{entry_id}: missing entry fields {sorted(missing)}")
        if not COMMIT_RE.fullmatch(str(entry.get("commit", ""))):
            errors.append(f"{entry_id}: invalid commit")
        if entry.get("verify") not in (0, 1) or isinstance(entry.get("verify"), bool):
            errors.append(f"{entry_id}: invalid verify")
        for field_path, node, _ in iter_nodes(entry):
            if not REQUIRED_NODE_FIELDS <= set(node):
                errors.append(f"{entry_id}:{field_path}: missing node fields")
            if parse_line_span(node.get("line")) is None:
                errors.append(f"{entry_id}:{field_path}: invalid line")
            if not isinstance(node.get("file"), str) or not node.get("file"):
                errors.append(f"{entry_id}:{field_path}: invalid file")
            if not isinstance(node.get("code"), str):
                errors.append(f"{entry_id}:{field_path}: invalid code")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--entry-id", action="append", default=[], help="check only this entry; repeatable")
    parser.add_argument("--nearby-lines", type=int, default=5)
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--offline", action="store_true", help="forbid clone, fetch, and lazy blob fetch")
    parser.add_argument("--git-protocol", choices=("https", "ssh"), default="https")
    parser.add_argument("--git-timeout", type=int, default=240)
    parser.add_argument("--max-file-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-repo-matches", type=int, default=50)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.input = args.input.resolve()
    args.output_dir = args.output_dir.resolve()
    args.cache_dir = args.cache_dir.resolve()
    if args.nearby_lines < 0 or args.jobs < 1:
        parser.error("--nearby-lines must be >= 0 and --jobs must be >= 1")

    started = time.monotonic()
    original = read_jsonl(args.input)
    schema_errors = validate_schema(original)
    if schema_errors:
        for error in schema_errors[:20]:
            print(error, file=sys.stderr)
        print(f"input schema errors: {len(schema_errors)}", file=sys.stderr)
        return 2

    requested = set(args.entry_id)
    known = {entry.get("entry_id") for entry in original}
    unknown = sorted(requested - known)
    if unknown:
        parser.error(f"unknown --entry-id values: {', '.join(unknown)}")

    grouped: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    output = copy.deepcopy(original)
    for index, entry in enumerate(original):
        if requested and entry.get("entry_id") not in requested:
            continue
        grouped[entry.get("repo_url", "")].append((index, entry))

    all_diff: list[tuple[int, int, dict[str, Any]]] = []
    all_human: list[tuple[int, int, dict[str, Any]]] = []
    totals: Counter[str] = Counter()
    repo_errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(args.jobs, max(1, len(grouped)))) as executor:
        futures = {
            executor.submit(process_repository, repo_url, items, args): repo_url
            for repo_url, items in sorted(grouped.items())
        }
        for future in as_completed(futures):
            result = future.result()
            for index, entry in result["entries"].items():
                output[index] = entry
            all_diff.extend(result["diff"])
            all_human.extend(result["human"])
            totals.update(result["stats"])
            if result["error"]:
                repo_errors[result["repo_url"]] = result["error"]
            print(
                f"[{result['repo_url']}] "
                f"ok={result['stats']['ok']} fixed={result['stats']['fixed']} "
                f"human={result['stats']['human']}",
                flush=True,
            )

    output_errors = validate_schema(output)
    if output_errors:
        for error in output_errors[:20]:
            print(error, file=sys.stderr)
        print(f"output schema errors: {len(output_errors)}", file=sys.stderr)
        return 3

    all_diff.sort(key=lambda item: (item[0], item[1]))
    all_human.sort(key=lambda item: (item[0], item[1]))
    diff_rows = [item[2] for item in all_diff]
    human_rows = [item[2] for item in all_human]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    fixed_path = args.output_dir / "entries.fixed.jsonl"
    diff_path = args.output_dir / "fix_diff.csv"
    human_path = args.output_dir / "needs_human.csv"
    summary_path = args.output_dir / "run_summary.json"
    write_jsonl(fixed_path, output)
    write_csv(diff_path, DIFF_FIELDS, diff_rows)
    write_csv(human_path, HUMAN_FIELDS, human_rows)

    elapsed = time.monotonic() - started
    selected_entries = sum(len(items) for items in grouped.values())
    selected_nodes = sum(totals.values())
    summary = {
        "input": (
            args.input.relative_to(REPO_ROOT).as_posix()
            if args.input.is_relative_to(REPO_ROOT)
            else str(args.input)
        ),
        "input_sha256": sha256_file(args.input),
        "output": (
            fixed_path.relative_to(REPO_ROOT).as_posix()
            if fixed_path.is_relative_to(REPO_ROOT)
            else str(fixed_path)
        ),
        "output_sha256": sha256_file(fixed_path),
        "selected_entries": selected_entries,
        "selected_nodes": selected_nodes,
        "repo_count": len(grouped),
        "repo_commit_groups": len(
            {(entry["repo_url"], entry["commit"]) for entry in original if not requested or entry["entry_id"] in requested}
        ),
        "status_counts": dict(sorted(totals.items())),
        "fix_rows": len(diff_rows),
        "needs_human_rows": len(human_rows),
        "strategy_counts": dict(sorted(Counter(row["strategy"] for row in diff_rows).items())),
        "human_reason_counts": dict(sorted(Counter(row["reason"] for row in human_rows).items())),
        "desc_status_counts": dict(sorted(Counter(row["desc_status"] for row in diff_rows).items())),
        "schema_errors": 0,
        "elapsed_seconds": round(elapsed, 3),
        "offline": bool(args.offline),
        "repository_errors": repo_errors,
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
