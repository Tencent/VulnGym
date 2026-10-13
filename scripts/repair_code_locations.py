#!/usr/bin/env python3
"""Audit and conservatively repair VulnGym code-node locations.

The resolver treats the vulnerable commit as the source of truth.  It checks
the recorded location, then searches the nearby window, the original file,
and finally the complete repository snapshot.  Only unique, sufficiently
informative matches are eligible for automatic repair.

The implementation is intentionally standard-library only so maintainers can
reproduce the generated artifacts without installing project dependencies.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import csv
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "entries.jsonl"
DEFAULT_REPORTS = ROOT / "data" / "reports.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "entries.fixed.jsonl"
DEFAULT_DIFF = ROOT / "reports" / "fix_diff.csv"
DEFAULT_NEEDS_HUMAN = ROOT / "reports" / "needs_human.csv"
DEFAULT_REPORT_JSON = ROOT / "reports" / "code_location_report.json"
DEFAULT_REPORT_MD = ROOT / "reports" / "code_location_report.md"
DEFAULT_SOURCE_MANIFEST = ROOT / "reports" / "code_location_sources.csv"
DEFAULT_CACHE = Path.home() / ".cache" / "vulngym-code-location"

LINE_RANGE_RE = re.compile(r"([1-9]\d*)-([1-9]\d*)")
SPACE_RE = re.compile(r"[^\S\r\n]+")
GITHUB_RE = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
ELLIPSIS_RE = re.compile(r"(?:^|\s)(?:\.\.\.|…)(?:\s|$)")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
REPORT_ID_RE = re.compile(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")

TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".dockerfile",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".md",
    ".php",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".svelte",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_NAMES = {
    "dockerfile",
    "makefile",
    "gemfile",
    "rakefile",
    "procfile",
}
SKIP_PARTS = {
    ".git",
    "__pycache__",
    "node_modules",
}

DIFF_FIELDS = (
    "entry_id",
    "verify",
    "repo_url",
    "commit",
    "field_path",
    "old_file",
    "old_line",
    "old_code",
    "old_desc",
    "new_file",
    "new_line",
    "new_code",
    "new_desc",
    "strategy",
    "match_mode",
    "desc_status",
    "source_url",
    "source_sha256",
    "candidate_count",
    "reason",
)
HUMAN_FIELDS = (
    "review_id",
    "expected_node_sha256",
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
    "stage",
    "match_mode",
    "candidate_count",
    "candidates",
    "source_url",
)
SOURCE_FIELDS = (
    "repo_url",
    "commit",
    "files_requested",
    "files_available",
    "files_missing",
    "snapshot_required",
    "snapshot_available",
    "source_status",
)


class RepairError(RuntimeError):
    """Raised for invalid input or unsafe source state."""


@dataclasses.dataclass(frozen=True)
class LineSpan:
    start: int
    end: int
    is_range: bool

    @classmethod
    def parse(cls, value: Any) -> "LineSpan":
        if isinstance(value, bool):
            raise RepairError(f"boolean is not a valid line: {value!r}")
        if isinstance(value, int):
            if value < 1:
                raise RepairError(f"line must be positive: {value!r}")
            return cls(value, value, False)
        if isinstance(value, str):
            match = LINE_RANGE_RE.fullmatch(value)
            if match:
                start, end = int(match.group(1)), int(match.group(2))
                if start <= end:
                    return cls(start, end, True)
        raise RepairError(f"invalid line value: {value!r}")

    def contains_match(self, match: "SourceMatch") -> bool:
        if self.is_range:
            return self.start == match.start and self.end == match.end
        return self.start == match.start

    def render_match(self, match: "SourceMatch") -> int | str:
        if not self.is_range:
            return match.start
        return f"{match.start}-{match.end}"


@dataclasses.dataclass(frozen=True, order=True)
class SourceMatch:
    file: str
    start: int
    end: int
    mode: str

    @property
    def line_value(self) -> int | str:
        return self.start if self.start == self.end else f"{self.start}-{self.end}"

    @property
    def preview(self) -> str:
        return f"{self.file}:{self.start}-{self.end}"


@dataclasses.dataclass(frozen=True)
class CodePattern:
    lines: tuple[str, ...]
    mode: str
    projected: bool
    unsafe_reason: str = ""


@dataclasses.dataclass(frozen=True)
class NodeRef:
    entry_index: int
    entry_id: str
    verify: int
    repo_url: str
    commit: str
    field_path: str
    node: Mapping[str, Any]

    @property
    def task_id(self) -> str:
        return f"{self.entry_id}:{self.field_path}"

    @property
    def source_key(self) -> tuple[str, str, str]:
        return (
            self.repo_url,
            self.commit,
            normalize_repo_path(str(self.node["file"])),
        )


@dataclasses.dataclass
class Resolution:
    ref: NodeRef
    status: str
    stage: str
    reason: str = ""
    match: SourceMatch | None = None
    candidates: tuple[SourceMatch, ...] = ()
    match_mode: str = ""
    desc_status: str = ""
    new_desc: str | None = None
    source_sha256: str = ""


def normalize_repo_path(value: str) -> str:
    value = value.replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\x00" in value
        or value.startswith("/")
    ):
        raise RepairError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def github_slug(repo_url: str) -> tuple[str, str]:
    match = GITHUB_RE.fullmatch(repo_url.strip())
    if not match:
        raise RepairError(f"unsupported repository URL: {repo_url!r}")
    return match.group("owner"), match.group("repo")


def normalize_line(value: str) -> str:
    return SPACE_RE.sub(" ", value.strip())


def normalize_code(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    raw = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while raw and not raw[0].strip():
        raw.pop(0)
    while raw and not raw[-1].strip():
        raw.pop()
    return tuple(normalize_line(line) for line in raw)


def _project_annotation_line(line: str) -> tuple[str | None, bool]:
    """Remove only a clearly annotator-authored CJK comment from the snippet.

    Source lines are never projected.  Exact matching always runs first, so a
    genuine upstream Chinese comment remains a verbatim match.
    """

    stripped = line.strip()
    if not stripped:
        return "", False
    for marker in ("//", "#"):
        start = stripped.find(marker)
        if start < 0:
            continue
        suffix = stripped[start + len(marker) :]
        if not CJK_RE.search(suffix):
            continue
        prefix = stripped[:start].rstrip()
        if not prefix:
            return None, True
        return normalize_line(prefix), True
    return normalize_line(stripped), False


def build_patterns(code: Any) -> tuple[CodePattern, ...]:
    exact = normalize_code(code)
    if not exact:
        return (CodePattern((), "verbatim", False, "empty_code"),)
    patterns = [CodePattern(exact, "verbatim", False)]
    if isinstance(code, str) and ELLIPSIS_RE.search(code):
        patterns.append(
            CodePattern((), "annotation_projection", True, "ellipsis_not_expanded")
        )
        return tuple(patterns)
    projected: list[str] = []
    changed = False
    for line in exact:
        value, line_changed = _project_annotation_line(line)
        changed = changed or line_changed
        if value is not None:
            projected.append(value)
    while projected and not projected[0]:
        projected.pop(0)
    while projected and not projected[-1]:
        projected.pop()
    projected_tuple = tuple(projected)
    if changed and projected_tuple and projected_tuple != exact:
        patterns.append(CodePattern(projected_tuple, "annotation_projection", True))
    return tuple(patterns)


def is_low_information(lines: Sequence[str]) -> bool:
    combined = " ".join(lines).strip()
    if not combined:
        return True
    meaningful = re.sub(r"[^A-Za-z0-9_\u0080-\uffff]+", "", combined)
    if len(meaningful) < 6:
        return True
    return combined in {"return", "else", "break", "continue", "pass", "}"}


def source_lines(text: str) -> tuple[str, ...]:
    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    return tuple(normalize_line(line) for line in unified.split("\n"))


def find_matches(
    lines: Sequence[str],
    pattern: CodePattern,
    *,
    file: str,
    start_min: int | None = None,
    start_max: int | None = None,
    limit: int | None = None,
) -> list[SourceMatch]:
    needle = pattern.lines
    if not needle or len(needle) > len(lines):
        return []
    maximum = len(lines) - len(needle) + 1
    first = max(1, start_min or 1)
    last = min(maximum, start_max if start_max is not None else maximum)
    if last < first:
        return []
    result: list[SourceMatch] = []
    expected = tuple(needle)
    for start in range(first, last + 1):
        offset = start - 1
        if lines[offset] != expected[0]:
            continue
        if tuple(lines[offset : offset + len(expected)]) == expected:
            result.append(
                SourceMatch(
                    file=file,
                    start=start,
                    end=start + len(expected) - 1,
                    mode=pattern.mode,
                )
            )
            if limit is not None and len(result) >= limit:
                break
    return result


def _node_sha256(ref: NodeRef) -> str:
    payload = {
        "entry_id": ref.entry_id,
        "field_path": ref.field_path,
        "node": ref.node,
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _review_id(ref: NodeRef) -> str:
    return "loc-" + hashlib.sha256(ref.task_id.encode("utf-8")).hexdigest()[:16]


def _source_url(ref: NodeRef, file: str, start: int | None = None) -> str:
    owner, repo = github_slug(ref.repo_url)
    path = urllib.parse.quote(file, safe="/")
    url = f"https://github.com/{owner}/{repo}/blob/{ref.commit}/{path}"
    return f"{url}#L{start}" if start else url


class HttpSourceCache:
    """Persistent raw-file cache plus lazy complete-commit snapshots."""

    def __init__(
        self,
        root: Path,
        *,
        offline: bool = False,
        timeout: float = 30.0,
        max_archive_bytes: int = 768 * 1024 * 1024,
        max_file_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self.root = root
        self.offline = offline
        self.timeout = timeout
        self.max_archive_bytes = max_archive_bytes
        self.max_file_bytes = max_file_bytes
        self._text: dict[tuple[str, str, str], str | None] = {}
        self._snapshot: dict[tuple[str, str], Path | None] = {}
        self._file_errors: dict[tuple[str, str, str], str] = {}
        self._snapshot_errors: dict[tuple[str, str], str] = {}
        self._indexes: dict[
            tuple[str, str], dict[str, list[tuple[str, int]]]
        ] = {}
        self._locks: defaultdict[tuple[str, str], Any] = defaultdict(
            __import__("threading").Lock
        )

    def _repo_name(self, repo_url: str) -> str:
        owner, repo = github_slug(repo_url)
        return f"{owner}__{repo}"

    def _file_path(self, key: tuple[str, str, str]) -> Path:
        repo_url, commit, file = key
        return self.root / "files" / self._repo_name(repo_url) / commit / file

    def _missing_path(self, key: tuple[str, str, str]) -> Path:
        return self._file_path(key).with_name(self._file_path(key).name + ".missing")

    def _request_bytes(self, url: str) -> bytes:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "VulnGym-code-location-repair/1.0",
                "Accept": "application/octet-stream",
            },
        )
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    length = response.headers.get("Content-Length")
                    if length and int(length) > self.max_archive_bytes:
                        raise RepairError(f"remote object too large: {url}")
                    data = response.read(self.max_archive_bytes + 1)
                    if len(data) > self.max_archive_bytes:
                        raise RepairError(f"remote object too large: {url}")
                    return data
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    raise FileNotFoundError(url) from error
                last_error = error
            except (OSError, TimeoutError) as error:
                last_error = error
            if attempt < 2:
                time.sleep(0.25 * (attempt + 1))
        raise RepairError(f"failed to download {url}: {last_error}")

    def read_file(self, repo_url: str, commit: str, file: str) -> str | None:
        file = normalize_repo_path(file)
        key = (repo_url, commit, file)
        if key in self._text:
            return self._text[key]
        path = self._file_path(key)
        missing = self._missing_path(key)
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            self._text[key] = text
            return text
        if missing.is_file():
            self._text[key] = None
            return None
        if self.offline:
            self._text[key] = None
            return None
        owner, repo = github_slug(repo_url)
        quoted = urllib.parse.quote(file, safe="/")
        url = (
            f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{quoted}"
        )
        try:
            data = self._request_bytes(url)
        except FileNotFoundError:
            missing.parent.mkdir(parents=True, exist_ok=True)
            missing.write_text("404\n", encoding="utf-8", newline="\n")
            self._text[key] = None
            return None
        except RepairError as error:
            self._file_errors[key] = str(error)
            self._text[key] = None
            return None
        if b"\x00" in data[:8192]:
            missing.parent.mkdir(parents=True, exist_ok=True)
            missing.write_text("binary\n", encoding="utf-8", newline="\n")
            self._text[key] = None
            return None
        text = data.decode("utf-8", errors="replace")
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(path, data)
        self._text[key] = text
        return text

    def prefetch_files(
        self,
        keys: Iterable[tuple[str, str, str]],
        *,
        workers: int,
    ) -> None:
        unique = sorted(set(keys))
        if workers <= 1:
            for key in unique:
                self.read_file(*key)
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self.read_file, *key) for key in unique]
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def _archive_path(self, repo_url: str, commit: str) -> Path:
        return self.root / "archives" / self._repo_name(repo_url) / f"{commit}.tar.gz"

    def _snapshot_path(self, repo_url: str, commit: str) -> Path:
        return self.root / "snapshots" / self._repo_name(repo_url) / commit

    def ensure_snapshot(self, repo_url: str, commit: str) -> Path | None:
        key = (repo_url, commit)
        if key in self._snapshot:
            return self._snapshot[key]
        with self._locks[key]:
            complete = self._snapshot_path(repo_url, commit) / ".complete"
            if complete.is_file():
                self._snapshot[key] = complete.parent
                return complete.parent
            if self.offline:
                self._snapshot[key] = None
                return None
            try:
                archive = self._archive_path(repo_url, commit)
                if not archive.is_file():
                    owner, repo = github_slug(repo_url)
                    url = (
                        f"https://codeload.github.com/{owner}/{repo}/tar.gz/{commit}"
                    )
                    data = self._request_bytes(url)
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    _atomic_write_bytes(archive, data)
                snapshot = self._snapshot_path(repo_url, commit)
                temporary = snapshot.with_name(snapshot.name + ".extracting")
                if temporary.exists():
                    shutil.rmtree(temporary)
                temporary.mkdir(parents=True, exist_ok=True)
                self._extract_archive(archive, temporary)
                (temporary / ".complete").write_text(
                    f"{repo_url}\n{commit}\n", encoding="utf-8", newline="\n"
                )
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                if snapshot.exists():
                    shutil.rmtree(snapshot)
                os.replace(temporary, snapshot)
            except (RepairError, FileNotFoundError, OSError, tarfile.TarError) as error:
                if "temporary" in locals():
                    shutil.rmtree(temporary, ignore_errors=True)
                self._snapshot_errors[key] = str(error)
                self._snapshot[key] = None
                return None
            self._snapshot[key] = snapshot
            return snapshot

    def _extract_archive(self, archive: Path, destination: Path) -> None:
        total = 0
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle:
                if not member.isfile():
                    continue
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2:
                    continue
                relative = PurePosixPath(*parts[1:])
                try:
                    safe = normalize_repo_path(relative.as_posix())
                except RepairError:
                    continue
                if any(part in SKIP_PARTS for part in PurePosixPath(safe).parts):
                    continue
                if member.size > self.max_file_bytes:
                    continue
                total += member.size
                if total > self.max_archive_bytes:
                    raise RepairError(f"expanded archive too large: {archive}")
                source = handle.extractfile(member)
                if source is None:
                    continue
                target = destination / safe
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)

    def prefetch_snapshots(
        self,
        keys: Iterable[tuple[str, str]],
        *,
        workers: int,
    ) -> None:
        unique = sorted(set(keys))
        if workers <= 1:
            for key in unique:
                self.ensure_snapshot(*key)
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self.ensure_snapshot, *key) for key in unique]
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def _is_text_candidate(self, path: Path) -> bool:
        relative_parts = set(path.parts)
        if relative_parts & SKIP_PARTS:
            return False
        return (
            path.name.lower() in TEXT_NAMES
            or path.suffix.lower() in TEXT_SUFFIXES
        )

    def _build_index(
        self, repo_url: str, commit: str
    ) -> dict[str, list[tuple[str, int]]]:
        key = (repo_url, commit)
        if key in self._indexes:
            return self._indexes[key]
        snapshot = self.ensure_snapshot(repo_url, commit)
        if snapshot is None:
            return {}
        index: defaultdict[str, list[tuple[str, int]]] = defaultdict(list)
        for path in sorted(snapshot.rglob("*")):
            if not path.is_file() or path.name == ".complete":
                continue
            relative = path.relative_to(snapshot).as_posix()
            if not self._is_text_candidate(Path(relative)):
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                continue
            lines = source_lines(data.decode("utf-8", errors="replace"))
            for number, line in enumerate(lines, 1):
                if line:
                    index[line].append((relative, number))
        result = dict(index)
        self._indexes[key] = result
        return result

    def search_repository(
        self,
        repo_url: str,
        commit: str,
        pattern: CodePattern,
        *,
        limit: int = 64,
    ) -> list[SourceMatch]:
        if not pattern.lines:
            return []
        snapshot = self.ensure_snapshot(repo_url, commit)
        if snapshot is None:
            return []
        index = self._build_index(repo_url, commit)
        matches: list[SourceMatch] = []
        for file, start in index.get(pattern.lines[0], ()):
            path = snapshot / file
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = source_lines(text)
            found = find_matches(
                lines,
                pattern,
                file=file,
                start_min=start,
                start_max=start,
                limit=1,
            )
            matches.extend(found)
            if len(matches) >= limit:
                break
        return sorted(set(matches))


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    os.replace(temporary, path)


def iter_nodes(entries: Sequence[Mapping[str, Any]]) -> Iterator[NodeRef]:
    for entry_index, entry in enumerate(entries):
        base = {
            "entry_index": entry_index,
            "entry_id": str(entry["entry_id"]),
            "verify": int(entry["verify"]),
            "repo_url": str(entry["repo_url"]),
            "commit": str(entry["commit"]),
        }
        yield NodeRef(field_path="entry_point", node=entry["entry_point"], **base)
        yield NodeRef(
            field_path="critical_operation", node=entry["critical_operation"], **base
        )
        for index, node in enumerate(entry["trace"]):
            yield NodeRef(field_path=f"trace[{index}]", node=node, **base)


def _unique_or_human(
    ref: NodeRef,
    matches: Sequence[SourceMatch],
    *,
    stage: str,
    pattern: CodePattern,
) -> Resolution | None:
    unique = sorted(set(matches))
    if len(unique) == 1:
        return Resolution(
            ref=ref,
            status="fixed",
            stage=stage,
            match=unique[0],
            candidates=tuple(unique),
            match_mode=pattern.mode,
        )
    if len(unique) > 1:
        return Resolution(
            ref=ref,
            status="human",
            stage=stage,
            reason=f"multiple_{stage}_matches",
            candidates=tuple(unique),
            match_mode=pattern.mode,
        )
    return None


def resolve_original_file(
    ref: NodeRef,
    cache: HttpSourceCache,
    *,
    nearby: int,
    verified_policy: str,
) -> Resolution:
    try:
        span = LineSpan.parse(ref.node["line"])
        file = normalize_repo_path(str(ref.node["file"]))
    except RepairError as error:
        return Resolution(
            ref=ref, status="human", stage="input", reason=str(error)
        )
    patterns = build_patterns(ref.node.get("code"))
    if not patterns[0].lines:
        return Resolution(
            ref=ref,
            status="human",
            stage="input",
            reason=patterns[0].unsafe_reason or "empty_code",
        )
    text = cache.read_file(ref.repo_url, ref.commit, file)
    if text is None:
        return Resolution(
            ref=ref,
            status="repo",
            stage="repository",
            reason="original_file_unavailable",
        )
    lines = source_lines(text)
    for pattern in patterns:
        if pattern.unsafe_reason:
            continue
        all_matches = find_matches(lines, pattern, file=file)
        current = [match for match in all_matches if span.contains_match(match)]
        if current:
            match = current[0]
            return Resolution(
                ref=ref,
                status="matched",
                stage="current",
                match=match,
                match_mode=pattern.mode,
                source_sha256=_match_sha(text, match),
            )
        if is_low_information(pattern.lines):
            if pattern.mode == "verbatim":
                return Resolution(
                    ref=ref,
                    status="human",
                    stage="input",
                    reason="low_information_code",
                    match_mode=pattern.mode,
                )
            continue
        nearby_matches = [
            match
            for match in all_matches
            if abs(match.start - span.start) <= nearby
        ]
        resolution = _unique_or_human(
            ref,
            nearby_matches,
            stage="nearby",
            pattern=pattern,
        )
        if resolution is not None:
            return _apply_verified_policy(resolution, verified_policy)
        resolution = _unique_or_human(
            ref,
            all_matches,
            stage="same_file",
            pattern=pattern,
        )
        if resolution is not None:
            return _apply_verified_policy(resolution, verified_policy)
    unsafe = next((p.unsafe_reason for p in patterns if p.unsafe_reason), "")
    return Resolution(
        ref=ref,
        status="repo",
        stage="repository",
        reason=unsafe or "not_found_in_original_file",
    )


def _apply_verified_policy(
    resolution: Resolution, verified_policy: str
) -> Resolution:
    if resolution.status != "fixed" or resolution.ref.verify == 0:
        return resolution
    if verified_policy == "protect":
        resolution.status = "human"
        resolution.reason = "verified_entry_protected"
        return resolution
    if resolution.match_mode != "verbatim":
        resolution.status = "human"
        resolution.reason = "verified_entry_requires_verbatim_match"
    return resolution


def resolve_repository(
    prior: Resolution,
    cache: HttpSourceCache,
    *,
    verified_policy: str,
) -> Resolution:
    ref = prior.ref
    patterns = build_patterns(ref.node.get("code"))
    for pattern in patterns:
        if pattern.unsafe_reason or is_low_information(pattern.lines):
            continue
        matches = cache.search_repository(
            ref.repo_url, ref.commit, pattern
        )
        resolution = _unique_or_human(
            ref,
            matches,
            stage="repository",
            pattern=pattern,
        )
        if resolution is not None:
            return _apply_verified_policy(resolution, verified_policy)
    snapshot = cache.ensure_snapshot(ref.repo_url, ref.commit)
    if snapshot is None:
        reason = "repository_snapshot_unavailable"
    elif prior.reason == "ellipsis_not_expanded":
        reason = prior.reason
    else:
        reason = "code_not_found_in_repository"
    return Resolution(
        ref=ref,
        status="human",
        stage="repository",
        reason=reason,
        match_mode=patterns[0].mode if patterns else "",
    )


def _match_sha(text: str, match: SourceMatch) -> str:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    selected = "\n".join(lines[match.start - 1 : match.end])
    return hashlib.sha256(selected.encode("utf-8")).hexdigest()


LINE_ANCHOR_RE = re.compile(
    r"(?P<prefix>"
    r"第\s*|"
    r"\b(?:lines?|L)\s*"
    r")"
    r"(?P<start>[1-9]\d*)"
    r"(?:\s*[-‐‑‒–—−]\s*(?P<end>[1-9]\d*))?"
    r"(?P<suffix>\s*行|\b)",
    re.IGNORECASE,
)


def synchronize_desc(
    desc: Any,
    *,
    old_file: str,
    old_span: LineSpan,
    new_file: str,
    new_span: LineSpan,
) -> tuple[Any, str, bool]:
    if not isinstance(desc, str):
        return desc, "missing_desc", False
    updated = desc
    changed = False
    old_file = normalize_repo_path(old_file)
    new_file = normalize_repo_path(new_file)
    if old_file != new_file:
        old_name = PurePosixPath(old_file).name
        new_name = PurePosixPath(new_file).name
        if old_file in updated:
            updated = updated.replace(old_file, new_file)
            changed = True
        if old_name != new_name and old_name in updated:
            updated = updated.replace(old_name, new_name)
            changed = True

    delta = new_span.start - old_span.start

    def replace_anchor(match: re.Match[str]) -> str:
        nonlocal changed
        start = int(match.group("start"))
        end_text = match.group("end")
        end = int(end_text) if end_text else start
        if start == old_span.start and end == old_span.end:
            mapped_start, mapped_end = new_span.start, new_span.end
        elif old_span.start <= start <= end <= old_span.end:
            mapped_start, mapped_end = start + delta, end + delta
        else:
            return match.group(0)
        changed = True
        line = (
            str(mapped_start)
            if mapped_start == mapped_end
            else f"{mapped_start}-{mapped_end}"
        )
        return f"{match.group('prefix')}{line}{match.group('suffix')}"

    updated = LINE_ANCHOR_RE.sub(replace_anchor, updated)
    old_text = (
        str(old_span.start)
        if not old_span.is_range
        else f"{old_span.start}-{old_span.end}"
    )
    new_text = (
        str(new_span.start)
        if not new_span.is_range
        else f"{new_span.start}-{new_span.end}"
    )
    old_name = PurePosixPath(old_file).name
    file_anchor = re.compile(
        rf"(?P<prefix>{re.escape(old_name)}:)"
        rf"{re.escape(old_text).replace(r'\-', '[-‐‑‒–—−]')}\b"
    )
    if file_anchor.search(updated):
        updated = file_anchor.sub(rf"\g<prefix>{new_text}", updated)
        changed = True
    return (
        updated,
        "updated_location_references" if changed else "checked_no_location_reference",
        False,
    )


def _get_output_node(entries: Sequence[dict[str, Any]], ref: NodeRef) -> dict[str, Any]:
    entry = entries[ref.entry_index]
    if ref.field_path == "entry_point":
        return entry["entry_point"]
    if ref.field_path == "critical_operation":
        return entry["critical_operation"]
    match = re.fullmatch(r"trace\[(\d+)\]", ref.field_path)
    if not match:
        raise RepairError(f"invalid field path: {ref.field_path}")
    return entry["trace"][int(match.group(1))]


def apply_resolutions(
    entries: Sequence[dict[str, Any]],
    resolutions: Sequence[Resolution],
    cache: HttpSourceCache,
    *,
    mode: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    output = copy.deepcopy(entries)
    diff_rows: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    for resolution in sorted(resolutions, key=lambda item: item.ref.task_id):
        ref = resolution.ref
        if resolution.status == "fixed" and resolution.match is not None:
            match = resolution.match
            old_span = LineSpan.parse(ref.node["line"])
            new_line = old_span.render_match(match)
            new_span = LineSpan.parse(new_line)
            new_desc, desc_status, conflict = synchronize_desc(
                ref.node.get("desc"),
                old_file=str(ref.node["file"]),
                old_span=old_span,
                new_file=match.file,
                new_span=new_span,
            )
            if conflict:
                resolution.status = "human"
                resolution.reason = "desc_location_conflict"
                resolution.desc_status = "conflict"
            else:
                resolution.desc_status = desc_status
                resolution.new_desc = new_desc
                text = cache.read_file(ref.repo_url, ref.commit, match.file) or ""
                resolution.source_sha256 = _match_sha(text, match) if text else ""
                row = {
                    "entry_id": ref.entry_id,
                    "verify": ref.verify,
                    "repo_url": ref.repo_url,
                    "commit": ref.commit,
                    "field_path": ref.field_path,
                    "old_file": ref.node["file"],
                    "old_line": ref.node["line"],
                    "old_code": ref.node["code"],
                    "old_desc": ref.node.get("desc", ""),
                    "new_file": match.file,
                    "new_line": new_line,
                    "new_code": ref.node["code"],
                    "new_desc": new_desc if new_desc is not None else "",
                    "strategy": f"{resolution.stage}_unique",
                    "match_mode": resolution.match_mode,
                    "desc_status": desc_status,
                    "source_url": _source_url(ref, match.file, match.start),
                    "source_sha256": resolution.source_sha256,
                    "candidate_count": len(resolution.candidates) or 1,
                    "reason": "unique_source_match",
                }
                diff_rows.append(row)
                if mode == "fix":
                    node = _get_output_node(output, ref)
                    node["file"] = match.file
                    node["line"] = new_line
                    if "desc" in node and new_desc is not None:
                        node["desc"] = new_desc
        if resolution.status == "human":
            candidates = [
                {
                    "file": candidate.file,
                    "line": candidate.line_value,
                    "mode": candidate.mode,
                }
                for candidate in resolution.candidates[:32]
            ]
            human_rows.append(
                {
                    "review_id": _review_id(ref),
                    "expected_node_sha256": _node_sha256(ref),
                    "entry_id": ref.entry_id,
                    "verify": ref.verify,
                    "repo_url": ref.repo_url,
                    "commit": ref.commit,
                    "field_path": ref.field_path,
                    "file": ref.node["file"],
                    "line": ref.node["line"],
                    "code": ref.node["code"],
                    "desc": ref.node.get("desc", ""),
                    "reason": resolution.reason,
                    "stage": resolution.stage,
                    "match_mode": resolution.match_mode,
                    "candidate_count": len(resolution.candidates),
                    "candidates": json.dumps(candidates, ensure_ascii=False),
                    "source_url": _source_url(
                        ref, str(ref.node["file"]), LineSpan.parse(ref.node["line"]).start
                    ),
                }
            )
    return output, diff_rows, human_rows


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                raise RepairError(f"{path}:{number}: blank JSONL row")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise RepairError(f"{path}:{number}: {error}") from error
            if not isinstance(value, dict):
                raise RepairError(f"{path}:{number}: row is not an object")
            rows.append(value)
    return rows


def validate_dataset(
    entries: Sequence[Mapping[str, Any]],
    reports: Sequence[Mapping[str, Any]],
) -> None:
    report_ids = {str(report.get("report_id", "")) for report in reports}
    previous = ""
    seen: set[str] = set()
    for index, entry in enumerate(entries, 1):
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or not re.fullmatch(r"entry-\d{5}", entry_id):
            raise RepairError(f"row {index}: invalid entry_id")
        if entry_id in seen or (previous and entry_id <= previous):
            raise RepairError(f"row {index}: entry IDs are not unique and sorted")
        seen.add(entry_id)
        previous = entry_id
        if entry.get("verify") not in (0, 1):
            raise RepairError(f"{entry_id}: verify must be 0 or 1")
        if not isinstance(entry.get("repo_url"), str):
            raise RepairError(f"{entry_id}: missing repo_url")
        github_slug(str(entry["repo_url"]))
        if not isinstance(entry.get("commit"), str) or not COMMIT_RE.fullmatch(
            str(entry["commit"])
        ):
            raise RepairError(f"{entry_id}: invalid commit")
        report_id = entry.get("report_id")
        if report_id not in report_ids:
            raise RepairError(f"{entry_id}: report_id is not present in reports")
        if not isinstance(report_id, str) or not REPORT_ID_RE.fullmatch(
            report_id.upper()
        ):
            raise RepairError(f"{entry_id}: invalid report_id")
        if not isinstance(entry.get("trace"), list):
            raise RepairError(f"{entry_id}: trace must be a list")
        for ref in iter_nodes([entry]):
            node = ref.node
            if not isinstance(node, Mapping):
                raise RepairError(f"{entry_id}:{ref.field_path}: node must be object")
            if not {"file", "line", "code"}.issubset(node):
                raise RepairError(f"{entry_id}:{ref.field_path}: missing node keys")
            normalize_repo_path(str(node["file"]))
            LineSpan.parse(node["line"])
            if not isinstance(node["code"], str):
                raise RepairError(f"{entry_id}:{ref.field_path}: code must be string")
            if "desc" in node and not isinstance(node["desc"], str):
                raise RepairError(f"{entry_id}:{ref.field_path}: desc must be string")


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    buffer = io.StringIO(newline="\n")
    for row in rows:
        buffer.write(
            json.dumps(
                row,
                ensure_ascii=False,
                sort_keys=True,
                separators=(", ", ": "),
            )
        )
        buffer.write("\n")
    _atomic_write_bytes(path, buffer.getvalue().encode("utf-8"))


def write_csv(
    path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, Any]]
) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(fields),
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    _atomic_write_bytes(path, buffer.getvalue().encode("utf-8"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_source_manifest(
    refs: Sequence[NodeRef],
    repo_stage: Sequence[Resolution],
    cache: HttpSourceCache,
) -> list[dict[str, Any]]:
    requested: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    for ref in refs:
        requested[(ref.repo_url, ref.commit)].add(str(ref.node["file"]))
    snapshot_keys = {
        (resolution.ref.repo_url, resolution.ref.commit)
        for resolution in repo_stage
    }
    rows: list[dict[str, Any]] = []
    for key in sorted(requested):
        repo_url, commit = key
        available = sum(
            cache.read_file(repo_url, commit, file) is not None
            for file in requested[key]
        )
        snapshot_required = key in snapshot_keys
        snapshot_available = (
            cache.ensure_snapshot(repo_url, commit) is not None
            if snapshot_required
            else False
        )
        rows.append(
            {
                "repo_url": repo_url,
                "commit": commit,
                "files_requested": len(requested[key]),
                "files_available": available,
                "files_missing": len(requested[key]) - available,
                "snapshot_required": int(snapshot_required),
                "snapshot_available": int(snapshot_available),
                "source_status": (
                    "complete"
                    if available == len(requested[key])
                    and (not snapshot_required or snapshot_available)
                    else "partial"
                ),
            }
        )
    return rows


def build_report(
    *,
    args: argparse.Namespace,
    entries: Sequence[Mapping[str, Any]],
    refs: Sequence[NodeRef],
    resolutions: Sequence[Resolution],
    diff_rows: Sequence[Mapping[str, Any]],
    human_rows: Sequence[Mapping[str, Any]],
    source_rows: Sequence[Mapping[str, Any]],
    input_sha256: str,
    output_sha256: str,
) -> dict[str, Any]:
    statuses = Counter(resolution.status for resolution in resolutions)
    stages = Counter(
        f"{resolution.status}:{resolution.stage}" for resolution in resolutions
    )
    modes = Counter(
        resolution.match_mode or "none" for resolution in resolutions
    )
    human_reasons = Counter(str(row["reason"]) for row in human_rows)
    strategies = Counter(str(row["strategy"]) for row in diff_rows)
    return {
        "mode": args.mode,
        "verified_policy": args.verified_policy,
        "nearby_window": args.nearby,
        "entries": len(entries),
        "nodes": len(refs),
        "matched": statuses["matched"],
        "fix_candidates": len(diff_rows),
        "changes_applied": len(diff_rows) if args.mode == "fix" else 0,
        "needs_human": len(human_rows),
        "repository_fallback_nodes": sum(
            resolution.stage == "repository" for resolution in resolutions
        ),
        "status_counts": dict(sorted(statuses.items())),
        "stage_counts": dict(sorted(stages.items())),
        "match_mode_counts": dict(sorted(modes.items())),
        "strategy_counts": dict(sorted(strategies.items())),
        "human_reason_counts": dict(sorted(human_reasons.items())),
        "source_commits": len(source_rows),
        "source_commits_complete": sum(
            row["source_status"] == "complete" for row in source_rows
        ),
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
    }


def write_report_json(path: Path, report: Mapping[str, Any]) -> None:
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _atomic_write_bytes(path, text.encode("utf-8"))


def write_report_md(path: Path, report: Mapping[str, Any]) -> None:
    lines = [
        "# Code location repair report",
        "",
        f"- Mode: `{report['mode']}`",
        f"- Verified policy: `{report['verified_policy']}`",
        f"- Entries: {report['entries']}",
        f"- Nodes: {report['nodes']}",
        f"- Accepted current-location matches: {report['matched']}",
        f"- Fix candidates: {report['fix_candidates']}",
        f"- Changes applied: {report['changes_applied']}",
        f"- Needs human review: {report['needs_human']}",
        f"- Repository fallback nodes: {report['repository_fallback_nodes']}",
        f"- Source commits: {report['source_commits']}",
        f"- Source commits complete: {report['source_commits_complete']}",
        "",
        "## Fix strategies",
        "",
    ]
    strategies = report["strategy_counts"]
    lines.extend(
        f"- `{key}`: {value}" for key, value in strategies.items()
    )
    lines.extend(["", "## Human-review reasons", ""])
    reasons = report["human_reason_counts"]
    lines.extend(f"- `{key}`: {value}" for key, value in reasons.items())
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Input SHA-256: `{report['input_sha256']}`",
            f"- Output SHA-256: `{report['output_sha256']}`",
            "",
        ]
    )
    _atomic_write_bytes(path, ("\n".join(lines)).encode("utf-8"))


def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    entries = load_jsonl(args.input)
    reports = load_jsonl(args.reports)
    validate_dataset(entries, reports)
    refs = list(iter_nodes(entries))
    if args.entry:
        selected = set(args.entry)
        refs = [ref for ref in refs if ref.entry_id in selected]
        missing = selected - {ref.entry_id for ref in refs}
        if missing:
            raise RepairError(f"unknown entry IDs: {sorted(missing)}")
    cache = HttpSourceCache(
        args.cache_dir,
        offline=args.offline,
        timeout=args.timeout,
    )
    cache.prefetch_files(
        (ref.source_key for ref in refs),
        workers=args.workers,
    )
    first_stage = [
        resolve_original_file(
            ref,
            cache,
            nearby=args.nearby,
            verified_policy=args.verified_policy,
        )
        for ref in refs
    ]
    repo_stage = [
        resolution for resolution in first_stage if resolution.status == "repo"
    ]
    cache.prefetch_snapshots(
        (
            (resolution.ref.repo_url, resolution.ref.commit)
            for resolution in repo_stage
        ),
        workers=args.snapshot_workers,
    )
    resolutions = [
        (
            resolve_repository(
                resolution,
                cache,
                verified_policy=args.verified_policy,
            )
            if resolution.status == "repo"
            else resolution
        )
        for resolution in first_stage
    ]
    output, diff_rows, human_rows = apply_resolutions(
        entries,
        resolutions,
        cache,
        mode=args.mode,
    )
    validate_dataset(output, reports)
    source_rows = build_source_manifest(refs, repo_stage, cache)
    write_jsonl(args.output, output if args.mode == "fix" else entries)
    write_csv(args.diff, DIFF_FIELDS, diff_rows)
    write_csv(args.needs_human, HUMAN_FIELDS, human_rows)
    write_csv(args.source_manifest, SOURCE_FIELDS, source_rows)
    report = build_report(
        args=args,
        entries=entries,
        refs=refs,
        resolutions=resolutions,
        diff_rows=diff_rows,
        human_rows=human_rows,
        source_rows=source_rows,
        input_sha256=file_sha256(args.input),
        output_sha256=file_sha256(args.output),
    )
    write_report_json(args.report_json, report)
    write_report_md(args.report_md, report)
    report["_elapsed_seconds"] = round(time.monotonic() - started, 3)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit and conservatively repair VulnGym code locations.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--reports", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--diff", type=Path, default=DEFAULT_DIFF)
    parser.add_argument("--needs-human", type=Path, default=DEFAULT_NEEDS_HUMAN)
    parser.add_argument("--report-json", type=Path, default=DEFAULT_REPORT_JSON)
    parser.add_argument("--report-md", type=Path, default=DEFAULT_REPORT_MD)
    parser.add_argument(
        "--source-manifest", type=Path, default=DEFAULT_SOURCE_MANIFEST
    )
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--mode", choices=("check", "fix"), default="check")
    parser.add_argument(
        "--verified-policy",
        choices=("strict", "protect"),
        default="strict",
        help=(
            "strict permits only verbatim unique fixes in verify=1 entries; "
            "protect reports every verified-entry repair candidate"
        ),
    )
    parser.add_argument("--nearby", type=int, default=5)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--snapshot-workers", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use cached sources only and report missing sources",
    )
    parser.add_argument(
        "--entry",
        action="append",
        default=[],
        help="limit source scanning to one entry ID; may be repeated",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.nearby < 0:
        parser.error("--nearby must be non-negative")
    if args.workers < 1 or args.snapshot_workers < 1:
        parser.error("worker counts must be positive")
    try:
        report = run(args)
    except (RepairError, OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")
    print(
        "code location repair complete: "
        f"{report['entries']} entries, {report['nodes']} nodes, "
        f"{report['fix_candidates']} fix candidates, "
        f"{report['needs_human']} needs human, "
        f"{report['_elapsed_seconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
