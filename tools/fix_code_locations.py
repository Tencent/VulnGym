#!/usr/bin/env python3
"""Conservatively repair VulnGym code-node file and line locations."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_KEYS = ("entry_point", "critical_operation")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HORIZONTAL_SPACE_RE = re.compile(r"[ \t]+")
CJK_RE = re.compile(r"[\u3400-\u9fff]")
INTERNAL_FIELDS = {
    "description",
    "human_remark",
    "pipeline_id",
    "annotated_by",
    "is_active",
    "created_at",
    "generality",
    "detection_type",
    "ground_truth",
    "taint_source",
    "taint_sink",
    "vuln_category_l3",
}
REQUIRED_TOP_LEVEL = {
    "entry_id",
    "report_id",
    "source_link",
    "vuln_ids",
    "origin",
    "project",
    "repo_url",
    "commit",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "entry_point",
    "critical_operation",
    "trace",
    "verify",
}
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
    "repo_url",
    "commit",
    "file",
    "line",
    "code",
    "desc",
    "reason",
    "candidate_count",
    "candidates",
    "proposed_file",
    "proposed_line",
    "proposed_desc",
)

LineValue = Union[int, str]


class RepairError(RuntimeError):
    """The input or a source snapshot cannot be processed safely."""


class GitError(RepairError):
    """A Git command failed."""


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int
    is_range: bool


@dataclass(frozen=True, order=True)
class Candidate:
    file: str
    start: int
    end: int

    def as_dict(self) -> Dict[str, Any]:
        line: LineValue = self.start if self.start == self.end else f"{self.start}-{self.end}"
        return {"file": self.file, "line": line}


@dataclass(frozen=True)
class LocateResult:
    strategy: Optional[str] = None
    candidate: Optional[Candidate] = None
    reason: Optional[str] = None
    candidates: Tuple[Candidate, ...] = ()
    repository_required: bool = False


def parse_line(value: Any) -> LineSpan:
    if isinstance(value, bool):
        raise RepairError(f"invalid line value: {value!r}")
    if isinstance(value, int) and value >= 1:
        return LineSpan(value, value, False)
    if isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return LineSpan(start, end, True)
    raise RepairError(f"invalid line value: {value!r}")


def normalize_repository_path(value: Any) -> str:
    if not isinstance(value, str):
        raise RepairError("file path is not a string")
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RepairError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def normalize_repo_url(value: Any) -> str:
    if not isinstance(value, str):
        raise RepairError("repo_url is not a string")
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RepairError(f"unsupported repo_url: {value!r}")
    parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
    if len(parts) != 2 or any(part in {".", ".."} for part in parts):
        raise RepairError(f"invalid GitHub repo_url: {value!r}")
    return f"https://github.com/{parts[0]}/{parts[1]}"


def normalize_line_text(value: str) -> str:
    return HORIZONTAL_SPACE_RE.sub(" ", value.strip(" \t"))


def normalized_code_lines(code: Any) -> List[str]:
    if not isinstance(code, str):
        return []
    lines = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip(" \t"):
        lines.pop(0)
    while lines and not lines[-1].strip(" \t"):
        lines.pop()
    return [normalize_line_text(line) for line in lines]


def _annotation_comment_index(line: str) -> Optional[int]:
    quote: Optional[str] = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote is not None:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            suffix = line[index + 2 :]
            if (index == 0 or line[index - 1].isspace()) and CJK_RE.search(suffix):
                return index
            index += 2
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            if CJK_RE.search(line[index + 1 :]):
                return index
        index += 1
    return None


def projected_annotation_lines(code: Any) -> Optional[List[str]]:
    if not isinstance(code, str):
        return None
    projected: List[str] = []
    changed = False
    for line in code.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        marker = _annotation_comment_index(line)
        if marker is not None:
            line = line[:marker].rstrip(" \t")
            changed = True
        projected.append(line)
    while projected and not projected[0].strip(" \t"):
        projected.pop(0)
    while projected and not projected[-1].strip(" \t"):
        projected.pop()
    normalized = [normalize_line_text(line) for line in projected]
    retained = " ".join(normalized)
    if not changed or len(re.sub(r"\W+", "", retained, flags=re.UNICODE)) < 4:
        return None
    return normalized


def code_match_variants(code: Any) -> List[List[str]]:
    exact = normalized_code_lines(code)
    variants = [exact] if exact else []
    projected = projected_annotation_lines(code)
    if projected and projected != exact:
        variants.append(projected)
    return variants


def normalized_source_lines(source: str) -> List[str]:
    return [
        normalize_line_text(line)
        for line in source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]


def find_matches(source: str, code: Any) -> List[int]:
    haystack = normalized_source_lines(source)
    for needle in code_match_variants(code):
        matches = find_normalized_matches(haystack, needle)
        if matches:
            return matches
    return []


def find_normalized_matches(haystack: Sequence[str], needle: Sequence[str]) -> List[int]:
    width = len(needle)
    if not width:
        return []
    return [
        index + 1
        for index in range(len(haystack) - width + 1)
        if list(haystack[index : index + width]) == list(needle)
    ]


def matches_at(source: str, needle: Sequence[str], start: int) -> bool:
    if start < 1 or not needle:
        return False
    haystack = normalized_source_lines(source)
    index = start - 1
    return index + len(needle) <= len(haystack) and haystack[index : index + len(needle)] == list(needle)


def format_repaired_line(start: int, width: int, original: Any) -> LineValue:
    if isinstance(original, int) and not isinstance(original, bool):
        return start
    return f"{start}-{start + width - 1}"


def iter_nodes(entry: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any], int]]:
    order = 0
    for key in NODE_KEYS:
        node = entry.get(key)
        if isinstance(node, dict):
            yield key, node, order
        order += 1
    trace = entry.get("trace")
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            if isinstance(node, dict):
                yield f"trace[{index}]", node, order
            order += 1


def run_git(
    args: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 120,
    offline: bool = False,
    allowed_codes: Sequence[int] = (0,),
) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.setdefault("GIT_TERMINAL_PROMPT", "0")
    if offline:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    try:
        command = ["git"]
        if cwd is not None:
            # Cached bare repositories may be created by a different local
            # runner account (for example an elevated first run followed by
            # an offline run). The cache path is tool-controlled, so scope the
            # ownership exception to this one repository only.
            command.extend(("-c", f"safe.directory={cwd.resolve()}"))
        command.extend(args)
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git command failed: {exc}") from exc
    if result.returncode not in allowed_codes:
        message = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        raise GitError(message or f"git {' '.join(args)} exited {result.returncode}")
    return result


def cache_path_for_repo(repo_url: str, cache_root: Path) -> Path:
    normalized = normalize_repo_url(repo_url)
    owner, name = normalized.rsplit("/", 2)[-2:]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{owner}__{name}")
    digest = hashlib.sha256(normalized.lower().encode("utf-8")).hexdigest()[:12]
    return cache_root / f"{safe}__{digest}.git"


class RepoCache:
    """A URL-isolated bare partial clone used to read pinned source snapshots."""

    def __init__(self, repo_url: str, cache_root: Path, offline: bool, timeout: int):
        self.repo_url = normalize_repo_url(repo_url)
        self.cache_root = cache_root.resolve()
        self.path = cache_path_for_repo(self.repo_url, self.cache_root)
        self.offline = offline
        self.timeout = timeout
        self._blob_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self._search_cache: Dict[Tuple[str, Tuple[str, ...]], Tuple[Candidate, ...]] = {}
        self._prepare()

    def _prepare(self) -> None:
        self.cache_root.mkdir(parents=True, exist_ok=True)
        if not (self.path / "HEAD").is_file():
            if self.offline:
                raise GitError(f"repository is not cached: {self.repo_url}")
            if self.path.exists():
                raise GitError(f"cache path is not a bare repository: {self.path}")
            temporary = self.cache_root / f".{self.path.name}.tmp-{uuid.uuid4().hex}"
            try:
                run_git(
                    [
                        "clone",
                        "--bare",
                        "--filter=blob:none",
                        "--no-tags",
                        self.repo_url,
                        str(temporary),
                    ],
                    timeout=self.timeout,
                )
                os.replace(temporary, self.path)
            except BaseException:
                if temporary.exists():
                    shutil.rmtree(temporary, ignore_errors=True)
                raise
        origin = run_git(
            ["config", "--get", "remote.origin.url"],
            cwd=self.path,
            timeout=self.timeout,
            offline=self.offline,
        ).stdout.decode("utf-8", errors="replace").strip()
        if normalize_repo_url(origin) != self.repo_url:
            raise GitError(
                f"cache origin mismatch: expected {self.repo_url}, found {origin or '<missing>'}"
            )

    def ensure_commit(self, commit: str) -> None:
        if not COMMIT_RE.fullmatch(commit):
            raise GitError(f"invalid commit: {commit!r}")
        exists = run_git(
            ["cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=self.path,
            timeout=self.timeout,
            offline=self.offline,
            allowed_codes=(0, 1, 128),
        )
        if exists.returncode == 0:
            return
        if self.offline:
            raise GitError(f"commit is not cached: {commit}")
        run_git(
            ["fetch", "--no-tags", "--filter=blob:none", "--depth=1", "origin", commit],
            cwd=self.path,
            timeout=self.timeout,
        )
        run_git(
            ["cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=self.path,
            timeout=self.timeout,
        )

    def _archive_path(self, commit: str) -> Path:
        repo_digest = hashlib.sha256(self.repo_url.lower().encode("utf-8")).hexdigest()[:12]
        return self.cache_root / "_archives" / repo_digest / f"{commit}.tar.gz"

    def _ensure_archive(self, commit: str) -> Path:
        if not COMMIT_RE.fullmatch(commit):
            raise RepairError(f"invalid commit: {commit!r}")
        archive = self._archive_path(commit)
        if archive.is_file() and archive.stat().st_size > 0:
            return archive
        if self.offline:
            raise RepairError(f"repository archive is not cached: {commit}")
        owner, name = self.repo_url.rsplit("/", 2)[-2:]
        url = f"https://codeload.github.com/{owner}/{name}/tar.gz/{commit}"
        archive.parent.mkdir(parents=True, exist_ok=True)
        temporary = archive.with_name(f".{archive.name}.tmp-{uuid.uuid4().hex}")
        headers = {"User-Agent": "VulnGym-location-fixer/1.0"}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            with urlopen(Request(url, headers=headers), timeout=self.timeout) as response:
                with temporary.open("wb") as output:
                    shutil.copyfileobj(response, output, length=1024 * 1024)
            if temporary.stat().st_size == 0:
                raise RepairError(f"downloaded empty repository archive: {commit}")
            os.replace(temporary, archive)
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            if isinstance(exc, RepairError):
                raise
            raise RepairError(f"repository archive download failed: {exc}") from exc
        return archive

    def _search_archive_many(
        self,
        commit: str,
        search_needles: Dict[Tuple[str, ...], Tuple[str, ...]],
    ) -> None:
        archive = self._ensure_archive(commit)
        candidates: Dict[Tuple[str, ...], List[Candidate]] = {
            key: [] for key in search_needles
        }
        anchors = {
            key: self._anchor(needle)[0] for key, needle in search_needles.items()
        }
        try:
            with tarfile.open(archive, mode="r:gz") as bundle:
                for member in bundle:
                    if not member.isfile():
                        continue
                    parts = PurePosixPath(member.name).parts
                    if len(parts) < 2:
                        continue
                    relative = PurePosixPath(*parts[1:])
                    if any(part in {"", ".", ".."} for part in relative.parts):
                        raise RepairError(f"unsafe path in repository archive: {member.name!r}")
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        continue
                    raw = extracted.read()
                    if b"\x00" in raw:
                        continue
                    source = raw.decode("utf-8", errors="replace")
                    source_lines = normalized_source_lines(source)
                    path = relative.as_posix()
                    for key, needle in search_needles.items():
                        if anchors[key] not in source:
                            continue
                        for start in find_normalized_matches(source_lines, needle):
                            candidates[key].append(
                                Candidate(path, start, start + len(needle) - 1)
                            )
        except (OSError, tarfile.TarError) as exc:
            raise RepairError(f"repository archive cannot be read: {exc}") from exc
        for key, found in candidates.items():
            self._search_cache[(commit, key)] = tuple(sorted(set(found)))

    def read_blob(self, commit: str, relative_path: str) -> Optional[str]:
        path = normalize_repository_path(relative_path)
        key = (commit, path)
        if key in self._blob_cache:
            return self._blob_cache[key]
        result = run_git(
            ["show", f"{commit}:{path}"],
            cwd=self.path,
            timeout=self.timeout,
            offline=self.offline,
            allowed_codes=(0, 128),
        )
        if result.returncode != 0 or b"\x00" in result.stdout:
            content = None
        else:
            content = result.stdout.decode("utf-8", errors="replace")
        self._blob_cache[key] = content
        return content

    @staticmethod
    def _anchor(needle: Sequence[str]) -> Tuple[str, int]:
        choices: List[Tuple[int, str, int]] = []
        for line_index, line in enumerate(needle):
            tokens = re.findall(r"\S+", line)
            for token in tokens:
                choices.append((len(token), token, line_index))
        if not choices:
            raise RepairError("code is empty after normalization")
        _, token, line_index = max(choices, key=lambda item: (item[0], item[1]))
        # Keep Windows command lines bounded when an annotation contains a very
        # long minified token. A literal prefix is sufficient for candidate
        # generation because the complete normalized snippet is verified later.
        return token[:200], line_index

    def search(self, commit: str, code: Any) -> Tuple[Candidate, ...]:
        needle = tuple(normalized_code_lines(code))
        return self.search_many(commit, [code]).get(needle, ())

    def search_many(
        self, commit: str, codes: Sequence[Any]
    ) -> Dict[Tuple[str, ...], Tuple[Candidate, ...]]:
        search_needles: Dict[Tuple[str, ...], Tuple[str, ...]] = {}
        for code in codes:
            exact = tuple(normalized_code_lines(code))
            if not exact:
                continue
            projected = projected_annotation_lines(code)
            search_needles[exact] = tuple(projected) if projected else exact
        needles = set(search_needles)
        unresolved = [
            needle for needle in sorted(needles) if (commit, needle) not in self._search_cache
        ]
        if not unresolved:
            return {needle: self._search_cache[(commit, needle)] for needle in needles}
        self._search_archive_many(
            commit, {needle: search_needles[needle] for needle in unresolved}
        )
        return {needle: self._search_cache[(commit, needle)] for needle in needles}


def locate_local(snapshot: Any, commit: str, node: Dict[str, Any]) -> LocateResult:
    try:
        path = normalize_repository_path(node.get("file"))
        recorded = parse_line(node.get("line"))
    except RepairError as exc:
        return LocateResult(reason=str(exc))
    needle = normalized_code_lines(node.get("code"))
    if not needle:
        return LocateResult(reason="code is empty after normalization")
    content = snapshot.read_blob(commit, path)
    matches = find_matches(content, node.get("code")) if content is not None else []
    expected_end = recorded.start + len(needle) - 1
    if recorded.start in matches and (not recorded.is_range or recorded.end == expected_end):
        return LocateResult(strategy="exact")
    nearby = [line for line in matches if abs(line - recorded.start) <= 5]
    if len(nearby) == 1:
        start = nearby[0]
        return LocateResult(
            strategy="nearby",
            candidate=Candidate(path, start, start + len(needle) - 1),
        )
    if len(nearby) > 1:
        candidates = tuple(Candidate(path, line, line + len(needle) - 1) for line in nearby)
        return LocateResult(
            reason="multiple matches within +/-5 lines", candidates=candidates
        )
    if len(matches) == 1:
        start = matches[0]
        return LocateResult(
            strategy="same_file",
            candidate=Candidate(path, start, start + len(needle) - 1),
        )
    if len(matches) > 1:
        candidates = tuple(Candidate(path, line, line + len(needle) - 1) for line in matches)
        return LocateResult(reason="multiple matches in original file", candidates=candidates)
    return LocateResult(repository_required=True)


def locate(snapshot: Any, commit: str, node: Dict[str, Any]) -> LocateResult:
    local = locate_local(snapshot, commit, node)
    if not local.repository_required:
        return local
    repository_matches = snapshot.search(commit, node.get("code"))
    if len(repository_matches) == 1:
        return LocateResult(strategy="repository", candidate=repository_matches[0])
    if repository_matches:
        return LocateResult(
            reason="multiple matches in repository", candidates=repository_matches
        )
    return LocateResult(reason="code not found in repository")


def _line_variants(value: Any) -> List[str]:
    text = str(value)
    variants = {text}
    if "-" in text:
        variants.add(text.replace("-", "–"))
        variants.add(text.replace("-", "—"))
    return sorted(variants, key=len, reverse=True)


def synchronize_desc(
    desc: Any,
    old_file: str,
    old_line: Any,
    new_file: str,
    new_line: Any,
) -> Tuple[bool, Any, str]:
    """Update only explicit file/line references; reject ambiguous stale references."""
    if not isinstance(desc, str) or not desc:
        return True, desc, ""
    updated = desc
    if old_file != new_file:
        updated = updated.replace(old_file, new_file)
        old_name, new_name = PurePosixPath(old_file).name, PurePosixPath(new_file).name
        if old_name != new_name:
            boundary = re.compile(
                rf"(?<![\w./\\-]){re.escape(old_name)}(?![\w./\\-])"
            )
            updated = boundary.sub(new_name, updated)
    if str(old_line) != str(new_line):
        for variant in _line_variants(old_line):
            escaped = re.escape(variant)
            patterns = (
                re.compile(rf"(?<!\d)(?P<prefix>第\s*){escaped}(?P<suffix>\s*行)"),
                re.compile(rf"(?<!\d){escaped}(?P<suffix>\s*行)"),
                re.compile(
                    rf"(?P<prefix>\blines?\s*(?:no\.?\s*)?[:#]?\s*){escaped}(?!\d)",
                    re.IGNORECASE,
                ),
            )
            for pattern in patterns:
                updated = pattern.sub(
                    lambda match: f"{match.groupdict().get('prefix') or ''}{new_line}"
                    f"{match.groupdict().get('suffix') or ''}",
                    updated,
                )
    if old_file != new_file:
        old_name = PurePosixPath(old_file).name
        if old_file in updated or (
            old_name != PurePosixPath(new_file).name and old_name in updated
        ):
            return False, desc, "description retains an ambiguous old file reference"
    if str(old_line) != str(new_line):
        location_words = r"(?:lines?|行|第|位置|位于|文件|file|path)"
        for variant in _line_variants(old_line):
            escaped = re.escape(variant)
            ambiguous = re.compile(
                rf"(?:{location_words}.{{0,24}}(?<!\d){escaped}(?!\d)|"
                rf"(?<!\d){escaped}(?!\d).{{0,24}}{location_words})",
                re.IGNORECASE,
            )
            if ambiguous.search(updated):
                return False, desc, "description retains an ambiguous old line reference"
    return True, updated, ""


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                raise RepairError(f"{path}:{line_number}: blank JSONL row")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RepairError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise RepairError(f"{path}:{line_number}: row is not an object")
            rows.append(row)
    return rows


def validate_entries(entries: Sequence[Dict[str, Any]]) -> None:
    seen: set[str] = set()
    previous = ""
    for row_number, entry in enumerate(entries, 1):
        missing = REQUIRED_TOP_LEVEL - set(entry)
        if missing:
            raise RepairError(f"entry row {row_number} is missing: {sorted(missing)}")
        forbidden = INTERNAL_FIELDS & set(entry)
        if forbidden:
            raise RepairError(f"entry row {row_number} contains internal fields: {sorted(forbidden)}")
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or not re.fullmatch(r"entry-\d{5}", entry_id):
            raise RepairError(f"entry row {row_number} has invalid entry_id")
        if entry_id in seen or (previous and entry_id < previous):
            raise RepairError("entry_id values must be unique and sorted")
        seen.add(entry_id)
        previous = entry_id
        normalize_repo_url(entry.get("repo_url"))
        if not isinstance(entry.get("commit"), str) or not COMMIT_RE.fullmatch(entry["commit"]):
            raise RepairError(f"{entry_id}: invalid commit")
        if entry.get("origin") != "GitHub Advisory Database (reviewed)":
            raise RepairError(f"{entry_id}: invalid origin")
        if entry.get("verify") not in (0, 1) or isinstance(entry.get("verify"), bool):
            raise RepairError(f"{entry_id}: verify must be 0 or 1")
        source_link = entry.get("source_link")
        if not isinstance(source_link, str) or "github.com/advisories/" not in source_link:
            raise RepairError(f"{entry_id}: invalid source_link")
        trace = entry.get("trace")
        if not isinstance(trace, list):
            raise RepairError(f"{entry_id}: trace must be a list")
        expected_nodes: List[Tuple[str, Any]] = [
            ("entry_point", entry.get("entry_point")),
            ("critical_operation", entry.get("critical_operation")),
        ] + [(f"trace[{index}]", node) for index, node in enumerate(trace)]
        for field_path, node in expected_nodes:
            if not isinstance(node, dict):
                raise RepairError(f"{entry_id}:{field_path}: node must be an object")
            if not {"file", "line", "code"}.issubset(node):
                raise RepairError(f"{entry_id}:{field_path}: missing required node keys")
            normalize_repository_path(node.get("file"))
            parse_line(node.get("line"))
            if not isinstance(node.get("code"), str):
                raise RepairError(f"{entry_id}:{field_path}: code must be a string")
            if "desc" in node and not isinstance(node["desc"], str):
                raise RepairError(f"{entry_id}:{field_path}: desc must be a string")


def _candidate_json(candidates: Sequence[Candidate], limit: int = 100) -> str:
    displayed = [candidate.as_dict() for candidate in candidates[:limit]]
    return json.dumps(displayed, ensure_ascii=False, separators=(",", ":"))


def human_row(
    entry: Dict[str, Any],
    field_path: str,
    node: Dict[str, Any],
    reason: str,
    candidates: Sequence[Candidate] = (),
    proposed_file: Any = "",
    proposed_line: Any = "",
    proposed_desc: Any = "",
) -> Dict[str, Any]:
    return {
        "entry_id": entry.get("entry_id", ""),
        "field_path": field_path,
        "repo_url": entry.get("repo_url", ""),
        "commit": entry.get("commit", ""),
        "file": node.get("file", ""),
        "line": node.get("line", ""),
        "code": node.get("code", ""),
        "desc": node.get("desc", ""),
        "reason": reason,
        "candidate_count": len(candidates),
        "candidates": _candidate_json(candidates),
        "proposed_file": proposed_file,
        "proposed_line": proposed_line,
        "proposed_desc": proposed_desc,
    }


def record_result(
    entry_index: int,
    node_order: int,
    entry: Dict[str, Any],
    field_path: str,
    node: Dict[str, Any],
    result: LocateResult,
    diffs: List[Tuple[Tuple[int, int], Dict[str, Any]]],
    humans: List[Tuple[Tuple[int, int], Dict[str, Any]]],
) -> None:
    order = (entry_index, node_order)
    if result.strategy == "exact":
        return
    if not result.strategy or result.candidate is None:
        humans.append(
            (
                order,
                human_row(
                    entry,
                    field_path,
                    node,
                    result.reason or "location is unresolved",
                    result.candidates,
                ),
            )
        )
        return
    candidate = result.candidate
    needle = normalized_code_lines(node["code"])
    new_line = format_repaired_line(candidate.start, len(needle), node["line"])
    old_file = node["file"]
    old_line = node["line"]
    old_desc = node.get("desc", "")
    safe_desc, new_desc, desc_reason = synchronize_desc(
        old_desc, old_file, old_line, candidate.file, new_line
    )
    if not safe_desc:
        humans.append(
            (
                order,
                human_row(
                    entry,
                    field_path,
                    node,
                    desc_reason,
                    (candidate,),
                    proposed_file=candidate.file,
                    proposed_line=new_line,
                    proposed_desc=new_desc,
                ),
            )
        )
        return
    node["file"] = candidate.file
    node["line"] = new_line
    if "desc" in node:
        node["desc"] = new_desc
    diffs.append(
        (
            order,
            {
                "entry_id": entry["entry_id"],
                "field_path": field_path,
                "old_file": old_file,
                "old_line": old_line,
                "old_desc": old_desc,
                "new_file": candidate.file,
                "new_line": new_line,
                "new_desc": node.get("desc", ""),
                "strategy": result.strategy,
            },
        )
    )


def process_repo_group(
    repo_url: str,
    indexes: Sequence[int],
    entries: List[Dict[str, Any]],
    cache_dir: Path,
    offline: bool,
    timeout: int,
    jobs: int,
) -> Tuple[List[Tuple[Tuple[int, int], Dict[str, Any]]], List[Tuple[Tuple[int, int], Dict[str, Any]]]]:
    diffs: List[Tuple[Tuple[int, int], Dict[str, Any]]] = []
    humans: List[Tuple[Tuple[int, int], Dict[str, Any]]] = []
    pending_by_commit: Dict[
        str, List[Tuple[int, int, Dict[str, Any], str, Dict[str, Any]]]
    ] = {}
    try:
        snapshot = RepoCache(repo_url, cache_dir, offline, timeout)
    except RepairError as exc:
        for entry_index in indexes:
            entry = entries[entry_index]
            for field_path, node, node_order in iter_nodes(entry):
                humans.append(
                    (
                        (entry_index, node_order),
                        human_row(entry, field_path, node, f"repository unavailable: {exc}"),
                    )
                )
        return diffs, humans
    prepared_commits: Dict[str, Optional[str]] = {}
    for entry_index in indexes:
        commit = entries[entry_index]["commit"]
        if commit in prepared_commits:
            continue
        try:
            snapshot.ensure_commit(commit)
            prepared_commits[commit] = None
        except RepairError as exc:
            prepared_commits[commit] = str(exc)
    for entry_index in indexes:
        entry = entries[entry_index]
        commit = entry["commit"]
        commit_error = prepared_commits[commit]
        for field_path, node, node_order in iter_nodes(entry):
            order = (entry_index, node_order)
            if commit_error:
                humans.append(
                    (
                        order,
                        human_row(
                            entry,
                            field_path,
                            node,
                            f"commit unavailable: {commit_error}",
                        ),
                    )
                )
                continue
            try:
                result = locate_local(snapshot, commit, node)
            except RepairError as exc:
                humans.append(
                    (order, human_row(entry, field_path, node, f"source lookup failed: {exc}"))
                )
                continue
            if result.repository_required:
                pending_by_commit.setdefault(commit, []).append(
                    (entry_index, node_order, entry, field_path, node)
                )
                continue
            record_result(
                entry_index,
                node_order,
                entry,
                field_path,
                node,
                result,
                diffs,
                humans,
            )
    search_results: Dict[
        str, Union[Dict[Tuple[str, ...], Tuple[Candidate, ...]], RepairError]
    ] = {}

    def search_commit(
        commit_and_pending: Tuple[
            str, List[Tuple[int, int, Dict[str, Any], str, Dict[str, Any]]]
        ]
    ) -> Tuple[str, Union[Dict[Tuple[str, ...], Tuple[Candidate, ...]], RepairError]]:
        commit, pending = commit_and_pending
        try:
            return commit, snapshot.search_many(
                commit, [node.get("code") for _, _, _, _, node in pending]
            )
        except RepairError as exc:
            return commit, exc

    if pending_by_commit:
        with ThreadPoolExecutor(max_workers=min(jobs, len(pending_by_commit))) as executor:
            futures = [executor.submit(search_commit, item) for item in pending_by_commit.items()]
            for future in as_completed(futures):
                commit, result = future.result()
                search_results[commit] = result

    for commit, pending in pending_by_commit.items():
        matches_by_needle = search_results[commit]
        if isinstance(matches_by_needle, RepairError):
            for entry_index, node_order, entry, field_path, node in pending:
                humans.append(
                    (
                        (entry_index, node_order),
                        human_row(
                            entry,
                            field_path,
                            node,
                            f"source lookup failed: {matches_by_needle}",
                        ),
                    )
                )
            continue
        for entry_index, node_order, entry, field_path, node in pending:
            needle = tuple(normalized_code_lines(node.get("code")))
            repository_matches = matches_by_needle.get(needle, ())
            if len(repository_matches) == 1:
                result = LocateResult(
                    strategy="repository", candidate=repository_matches[0]
                )
            elif repository_matches:
                result = LocateResult(
                    reason="multiple matches in repository", candidates=repository_matches
                )
            else:
                result = LocateResult(reason="code not found in repository")
            record_result(
                entry_index,
                node_order,
                entry,
                field_path,
                node,
                result,
                diffs,
                humans,
            )
    return diffs, humans


def atomic_write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            for row in rows:
                output.write(
                    json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                )
                output.write("\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_csv(
    path: Path, fields: Sequence[str], rows: Iterable[Dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(
                output, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
            )
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=REPO_ROOT / "data" / "entries.jsonl")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "entries.fixed.jsonl")
    parser.add_argument("--diff", type=Path, default=REPO_ROOT / "fix_diff.csv")
    parser.add_argument("--needs-human", type=Path, default=REPO_ROOT / "needs_human.csv")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=REPO_ROOT / ".cache" / "vulngym-location-fixer",
    )
    parser.add_argument("--verify", choices=("all", "0", "1"), default="all")
    parser.add_argument("--entry-id", action="append", default=[])
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--git-timeout", type=int, default=120)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.jobs < 1:
        raise RepairError("--jobs must be at least 1")
    if args.git_timeout < 1:
        raise RepairError("--git-timeout must be at least 1")
    started = time.monotonic()
    entries = load_jsonl(args.input)
    validate_entries(entries)
    requested_ids = set(args.entry_id)
    known_ids = {entry["entry_id"] for entry in entries}
    unknown_ids = requested_ids - known_ids
    if unknown_ids:
        raise RepairError(f"unknown --entry-id values: {sorted(unknown_ids)}")
    selected_indexes = [
        index
        for index, entry in enumerate(entries)
        if (not requested_ids or entry["entry_id"] in requested_ids)
        and (args.verify == "all" or str(entry["verify"]) == args.verify)
    ]
    groups: Dict[str, List[int]] = {}
    for index in selected_indexes:
        groups.setdefault(entries[index]["repo_url"], []).append(index)
    ordered_groups = sorted(groups.items())
    all_diffs: List[Tuple[Tuple[int, int], Dict[str, Any]]] = []
    all_humans: List[Tuple[Tuple[int, int], Dict[str, Any]]] = []
    if ordered_groups:
        with ThreadPoolExecutor(max_workers=min(args.jobs, len(ordered_groups))) as executor:
            futures = {
                executor.submit(
                    process_repo_group,
                    repo_url,
                    indexes,
                    entries,
                    args.cache_dir,
                    args.offline,
                    args.git_timeout,
                    args.jobs,
                ): repo_url
                for repo_url, indexes in ordered_groups
            }
            completed = 0
            for future in as_completed(futures):
                repo_url = futures[future]
                diffs, humans = future.result()
                all_diffs.extend(diffs)
                all_humans.extend(humans)
                completed += 1
                print(
                    f"[{completed}/{len(futures)}] {repo_url}: "
                    f"{len(diffs)} fixes, {len(humans)} review items",
                    file=sys.stderr,
                )
    all_diffs.sort(key=lambda item: item[0])
    all_humans.sort(key=lambda item: item[0])
    diff_rows = [row for _, row in all_diffs]
    human_rows = [row for _, row in all_humans]
    validate_entries(entries)
    atomic_write_jsonl(args.output, entries)
    atomic_write_csv(args.diff, DIFF_FIELDS, diff_rows)
    atomic_write_csv(args.needs_human, HUMAN_FIELDS, human_rows)
    elapsed = time.monotonic() - started
    print(
        f"wrote {len(entries)} entries; checked {len(selected_indexes)} entries; "
        f"applied {len(diff_rows)} fixes; queued {len(human_rows)} review items; "
        f"elapsed {elapsed:.2f}s"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RepairError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
