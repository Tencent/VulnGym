#!/usr/bin/env python3
"""Initialize and safely apply human decisions for code-location review queues.

The automatic repair workflows proposed for issue #4 intentionally leave
ambiguous locations in ``needs_human.csv``.  This tool closes the remaining
manual-review loop without guessing: it creates a decision sheet bound to the
current node contents, then validates each selected location against the
declared repository and commit before writing a new JSONL file.
"""

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
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "entries.jsonl"
DEFAULT_CACHE = ROOT / ".cache" / "location-review"
DEFAULT_DECISIONS = ROOT / "reports" / "location_review_decisions.csv"
DEFAULT_OUTPUT = ROOT / "data" / "entries.reviewed.jsonl"
DEFAULT_DIFF = ROOT / "reports" / "location_review_diff.csv"
DEFAULT_AUDIT = ROOT / "reports" / "location_review_audit.csv"

QUEUE_REQUIRED_FIELDS = {"entry_id"}
QUEUE_PATH_FIELDS = ("field_path", "node_path")
DECISION_FIELDS = [
    "review_id",
    "entry_id",
    "field_path",
    "expected_node_sha256",
    "original_file",
    "original_line",
    "reason",
    "decision",
    "new_file",
    "new_line",
    "reviewer",
    "rationale",
]
DIFF_FIELDS = [
    "review_id",
    "entry_id",
    "field_path",
    "old_file",
    "old_line",
    "new_file",
    "new_line",
    "old_desc",
    "new_desc",
    "reviewer",
    "rationale",
    "match_mode",
    "source_blob_oid",
    "source_sha256",
]
AUDIT_FIELDS = [
    "review_id",
    "entry_id",
    "field_path",
    "decision",
    "status",
    "reviewer",
    "rationale",
    "old_file",
    "old_line",
    "new_file",
    "new_line",
    "match_mode",
    "source_blob_oid",
    "source_sha256",
]

TRACE_PATH_RE = re.compile(r"^trace\[(\d+)]$")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
SPACE_RE = re.compile(r"\s+")
CJK_RE = re.compile(r"[\u3400-\u9fff]")
PROVENANCE_REF_PREFIX = "refs/vulngym-location-review/fetched"


class ReviewError(RuntimeError):
    """A decision sheet or source location failed conservative validation."""


class SourceError(ReviewError):
    """A pinned repository source blob could not be verified."""


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int


@dataclass(frozen=True)
class SourceEvidence:
    match_mode: str
    blob_oid: str
    source_sha256: str


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReviewError(f"{path}:{line_number}: invalid JSON: {exc}") from None
            if not isinstance(row, dict):
                raise ReviewError(f"{path}:{line_number}: JSONL row must be an object")
            rows.append(row)
    return rows


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ReviewError(f"{path}: CSV header is missing")
        return list(reader.fieldnames), list(reader)


def atomic_write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
                handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_csv(
    path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def node_at(entry: dict[str, Any], field_path: str) -> dict[str, Any]:
    if field_path in {"entry_point", "critical_operation"}:
        node = entry.get(field_path)
    else:
        match = TRACE_PATH_RE.fullmatch(field_path)
        if match is None:
            raise ReviewError(f"invalid field_path: {field_path!r}")
        trace = entry.get("trace")
        index = int(match.group(1))
        if not isinstance(trace, list) or index >= len(trace):
            raise ReviewError(
                f"{entry.get('entry_id')}:{field_path}: trace node does not exist"
            )
        node = trace[index]
    if not isinstance(node, dict):
        raise ReviewError(f"{entry.get('entry_id')}:{field_path}: node is not an object")
    return node


def parse_line(value: Any) -> tuple[int | str, LineSpan]:
    if isinstance(value, bool):
        raise ReviewError(f"invalid line value: {value!r}")
    if isinstance(value, int) and value >= 1:
        return value, LineSpan(value, value)
    if isinstance(value, str):
        value = value.strip()
        if value.isdigit() and int(value) >= 1:
            number = int(value)
            return number, LineSpan(number, number)
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return f"{start}-{end}", LineSpan(start, end)
    raise ReviewError(f"invalid line value: {value!r}")


def normalize_repo_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise SourceError(f"unsupported repo_url: {value!r}")
    parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
    if len(parts) != 2 or any(part in {".", ".."} for part in parts):
        raise SourceError(f"invalid GitHub repo_url: {value!r}")
    return f"https://github.com/{parts[0]}/{parts[1]}"


def normalize_repo_identity(value: str) -> str:
    return normalize_repo_url(value).lower()


def cache_name(repo_url: str) -> str:
    normalized = normalize_repo_url(repo_url)
    owner, repo = normalized.rsplit("/", 2)[-2:]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{owner}__{repo}")
    digest = hashlib.sha256(normalized.lower().encode()).hexdigest()[:12]
    return f"{safe}__{digest}.git"


def normalize_repo_path(value: str) -> str:
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
        raise SourceError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def canonical_node_payload(
    entry: dict[str, Any], field_path: str, node: dict[str, Any]
) -> bytes:
    payload = {
        "entry_id": entry.get("entry_id"),
        "repo_url": entry.get("repo_url"),
        "commit": entry.get("commit"),
        "field_path": field_path,
        "node": node,
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def node_sha256(entry: dict[str, Any], field_path: str, node: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_node_payload(entry, field_path, node)).hexdigest()


def review_id(entry: dict[str, Any], field_path: str, node: dict[str, Any]) -> str:
    return f"loc-{node_sha256(entry, field_path, node)[:20]}"


def normalize_line_text(value: str) -> str:
    return SPACE_RE.sub(" ", value.strip())


def normalized_code_lines(code: Any) -> list[str]:
    if not isinstance(code, str):
        return []
    lines = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return [normalize_line_text(line) for line in lines]


def annotation_comment_index(line: str) -> int | None:
    quote: str | None = None
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
            if index == 0 or line[index - 1].isspace():
                suffix = line[index + 2 :]
                if CJK_RE.search(suffix):
                    return index
            index += 2
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            suffix = line[index + 1 :]
            if CJK_RE.search(suffix):
                return index
        index += 1
    return None


def projected_annotation_lines(code: Any) -> list[str] | None:
    if not isinstance(code, str):
        return None
    projected: list[str] = []
    changed = False
    for line in code.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        marker = annotation_comment_index(line)
        if marker is not None:
            line = line[:marker].rstrip()
            changed = True
        projected.append(line)
    while projected and not projected[0].strip():
        projected.pop(0)
    while projected and not projected[-1].strip():
        projected.pop()
    normalized = [normalize_line_text(line) for line in projected]
    retained = " ".join(normalized).strip()
    if not changed or len(re.sub(r"\W+", "", retained, flags=re.UNICODE)) < 4:
        return None
    return normalized


def match_source(code: Any, source_text: str, span: LineSpan) -> str:
    source_lines = source_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    exact = normalized_code_lines(code)
    if not exact:
        raise SourceError("node code is empty after normalization")
    start_index = span.start - 1
    if start_index < 0 or start_index + len(exact) > len(source_lines):
        raise SourceError("selected line is outside the source file")
    candidate = [
        normalize_line_text(line)
        for line in source_lines[start_index : start_index + len(exact)]
    ]
    expected_end = span.start + len(exact) - 1
    if span.end != span.start and span.end != expected_end:
        raise SourceError(
            f"selected range ends at {span.end}, but the snippet ends at {expected_end}"
        )
    if candidate == exact:
        return "normalized_exact"
    projected = projected_annotation_lines(code)
    if projected is not None and len(projected) == len(candidate) and candidate == projected:
        return "annotator_comment_projection"
    raise SourceError("selected source location does not match node code")


def run_git(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
    no_lazy_fetch: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    if no_lazy_fetch:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError(f"git command failed: {exc}") from exc


def git_error(result: subprocess.CompletedProcess[bytes]) -> str:
    raw = result.stderr or result.stdout
    return raw.decode("utf-8", errors="replace").strip()


class GitBlobCache:
    """Read exact blobs from a URL-isolated bare Git repository cache."""

    def __init__(
        self,
        repo_url: str,
        cache_root: Path,
        *,
        offline: bool = False,
        timeout: int = 120,
        max_blob_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self.repo_url = normalize_repo_url(repo_url)
        self.cache_root = cache_root
        self.path = cache_root / cache_name(repo_url)
        self.offline = offline
        self.timeout = timeout
        self.max_blob_bytes = max_blob_bytes
        self._prepare_repo()

    def _prepare_repo(self) -> None:
        self.cache_root.mkdir(parents=True, exist_ok=True)
        if not (self.path / "HEAD").is_file():
            if self.offline:
                raise SourceError(f"repository is not cached: {self.repo_url}")
            if self.path.exists():
                raise SourceError(f"cache path is not a bare repository: {self.path}")
            temporary = self.path.with_name(f"{self.path.name}.tmp-{os.getpid()}")
            shutil.rmtree(temporary, ignore_errors=True)
            result = run_git(["init", "--bare", str(temporary)], timeout=self.timeout)
            if result.returncode == 0:
                result = run_git(
                    ["remote", "add", "origin", f"{self.repo_url}.git"],
                    cwd=temporary,
                    timeout=self.timeout,
                )
            if result.returncode == 0:
                result = run_git(
                    ["config", "remote.origin.promisor", "true"],
                    cwd=temporary,
                    timeout=self.timeout,
                )
            if result.returncode == 0:
                result = run_git(
                    ["config", "remote.origin.partialclonefilter", "blob:none"],
                    cwd=temporary,
                    timeout=self.timeout,
                )
            if result.returncode != 0:
                shutil.rmtree(temporary, ignore_errors=True)
                raise SourceError(f"cache initialization failed: {git_error(result)}")
            try:
                os.replace(temporary, self.path)
            except FileExistsError:
                shutil.rmtree(temporary, ignore_errors=True)
        remote = run_git(
            ["config", "--get", "remote.origin.url"],
            cwd=self.path,
            timeout=self.timeout,
        )
        if remote.returncode != 0:
            raise SourceError(f"cached repository has no origin: {self.path}")
        configured = remote.stdout.decode("utf-8", errors="replace").strip()
        if normalize_repo_identity(configured) != normalize_repo_identity(self.repo_url):
            raise SourceError(
                f"cache origin mismatch: expected {self.repo_url}, found {configured}"
            )

    def ensure_commit(self, commit: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise SourceError(f"invalid commit: {commit!r}")
        provenance_ref = f"{PROVENANCE_REF_PREFIX}/{commit}"
        provenance = run_git(
            ["rev-parse", "--verify", provenance_ref],
            cwd=self.path,
            timeout=self.timeout,
            no_lazy_fetch=self.offline,
        )
        if provenance.returncode == 0:
            marked_commit = provenance.stdout.decode("ascii", errors="replace").strip()
            exists = run_git(
                ["cat-file", "-e", f"{commit}^{{commit}}"],
                cwd=self.path,
                timeout=self.timeout,
                no_lazy_fetch=self.offline,
            )
            if marked_commit == commit and exists.returncode == 0:
                return
        if self.offline:
            raise SourceError(f"commit is not provenance-verified in cache: {commit}")
        fetched = run_git(
            [
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "--depth=1",
                "origin",
                commit,
            ],
            cwd=self.path,
            timeout=self.timeout,
        )
        if fetched.returncode != 0:
            fetched = run_git(
                ["fetch", "--no-tags", "origin", commit],
                cwd=self.path,
                timeout=self.timeout,
            )
        if fetched.returncode != 0:
            raise SourceError(f"commit fetch failed: {git_error(fetched)}")
        exists = run_git(
            ["cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=self.path,
            timeout=self.timeout,
        )
        if exists.returncode != 0:
            raise SourceError(f"fetched object is not a commit: {commit}")
        marked = run_git(
            ["update-ref", provenance_ref, commit],
            cwd=self.path,
            timeout=self.timeout,
        )
        if marked.returncode != 0:
            raise SourceError(f"cannot record commit provenance: {git_error(marked)}")

    def read_blob(self, commit: str, file: str) -> tuple[str, str, str]:
        self.ensure_commit(commit)
        file = normalize_repo_path(file)
        tree = run_git(
            ["ls-tree", "-z", commit, "--", file],
            cwd=self.path,
            timeout=self.timeout,
            no_lazy_fetch=self.offline,
        )
        if tree.returncode != 0 or not tree.stdout:
            raise SourceError(f"source path does not exist with exact case: {file}")
        record = tree.stdout.rstrip(b"\0").split(b"\0")
        if len(record) != 1:
            raise SourceError(f"source path is ambiguous in Git tree: {file}")
        metadata, _, returned_path = record[0].partition(b"\t")
        parts = metadata.split()
        if len(parts) != 3 or returned_path.decode("utf-8", errors="replace") != file:
            raise SourceError(f"unexpected Git tree record for: {file}")
        mode, object_type, oid = [part.decode("ascii") for part in parts]
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise SourceError(f"source path is not a regular file: {file} ({mode})")
        size = run_git(
            ["cat-file", "-s", oid],
            cwd=self.path,
            timeout=self.timeout,
            no_lazy_fetch=self.offline,
        )
        if size.returncode != 0:
            raise SourceError(f"cannot read source blob size: {file}")
        if int(size.stdout.strip()) > self.max_blob_bytes:
            raise SourceError(f"source blob exceeds size limit: {file}")
        blob = run_git(
            ["cat-file", "blob", oid],
            cwd=self.path,
            timeout=self.timeout,
            no_lazy_fetch=self.offline,
        )
        if blob.returncode != 0:
            raise SourceError(f"cannot read source blob: {file}: {git_error(blob)}")
        if b"\0" in blob.stdout:
            raise SourceError(f"source blob is binary: {file}")
        return (
            blob.stdout.decode("utf-8", errors="strict"),
            oid,
            hashlib.sha256(blob.stdout).hexdigest(),
        )


def synchronize_desc(
    desc: Any,
    *,
    old_file: str,
    old_line: Any,
    new_file: str,
    new_line: Any,
) -> Any:
    if not isinstance(desc, str):
        return desc
    updated = desc
    old_path = old_file.replace("\\", "/")
    new_path = new_file.replace("\\", "/")
    old_name = PurePosixPath(old_path).name
    new_name = PurePosixPath(new_path).name
    if old_path != new_path:
        updated = updated.replace(old_path, new_path)
        if old_name != new_name:
            updated = updated.replace(old_name, new_name)
    if str(old_line) != str(new_line):
        old = re.escape(str(old_line))
        replacement = str(new_line)
        updated = re.sub(
            rf"(第\s*){old}(\s*行)",
            lambda match: f"{match.group(1)}{replacement}{match.group(2)}",
            updated,
        )
        updated = re.sub(
            rf"(?i)\b(lines?\s*){old}\b",
            lambda match: f"{match.group(1)}{replacement}",
            updated,
        )
        anchor_name = re.escape(new_name if old_path != new_path else old_name)
        if anchor_name:
            updated = re.sub(
                rf"({anchor_name}:){old}\b",
                lambda match: f"{match.group(1)}{replacement}",
                updated,
            )
    return updated


def initialize_decisions(
    input_path: Path, queue_path: Path, decisions_path: Path
) -> int:
    entries = read_jsonl(input_path)
    entries_by_id = {str(entry.get("entry_id")): entry for entry in entries}
    if len(entries_by_id) != len(entries):
        raise ReviewError("input contains duplicate entry_id values")
    headers, queue_rows = read_csv(queue_path)
    missing = QUEUE_REQUIRED_FIELDS - set(headers)
    if missing:
        raise ReviewError(f"{queue_path}: missing required columns: {sorted(missing)}")
    if not any(field in headers for field in QUEUE_PATH_FIELDS):
        raise ReviewError(
            f"{queue_path}: expected one location column: {list(QUEUE_PATH_FIELDS)}"
        )
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for queue_row in queue_rows:
        entry_id = queue_row.get("entry_id", "").strip()
        field_path = next(
            (
                queue_row.get(field, "").strip()
                for field in QUEUE_PATH_FIELDS
                if queue_row.get(field, "").strip()
            ),
            "",
        )
        if not field_path:
            raise ReviewError(f"queue row for {entry_id!r} has no location path")
        key = (entry_id, field_path)
        if key in seen:
            raise ReviewError(f"duplicate queue row: {entry_id}:{field_path}")
        seen.add(key)
        entry = entries_by_id.get(entry_id)
        if entry is None:
            raise ReviewError(f"queue references unknown entry_id: {entry_id!r}")
        node = node_at(entry, field_path)
        rows.append(
            {
                "review_id": review_id(entry, field_path, node),
                "entry_id": entry_id,
                "field_path": field_path,
                "expected_node_sha256": node_sha256(entry, field_path, node),
                "original_file": node.get("file", ""),
                "original_line": node.get("line", ""),
                "reason": queue_row.get("reason", ""),
                "decision": "",
                "new_file": "",
                "new_line": "",
                "reviewer": "",
                "rationale": "",
            }
        )
    atomic_write_csv(decisions_path, DECISION_FIELDS, rows)
    return len(rows)


def apply_decisions(
    *,
    input_path: Path,
    decisions_path: Path,
    output_path: Path,
    diff_path: Path,
    audit_path: Path,
    cache_root: Path,
    offline: bool = False,
    allow_pending: bool = False,
    include_verified: bool = False,
    git_timeout: int = 120,
    max_blob_bytes: int = 8 * 1024 * 1024,
) -> tuple[int, int, int]:
    artifact_paths = {
        "input": input_path.resolve(),
        "decisions": decisions_path.resolve(),
        "output": output_path.resolve(),
        "diff": diff_path.resolve(),
        "audit": audit_path.resolve(),
    }
    destinations = {
        artifact_paths["output"], artifact_paths["diff"], artifact_paths["audit"]
    }
    if len(destinations) != 3:
        raise ReviewError("output, diff, and audit paths must be different")
    if artifact_paths["input"] in destinations:
        raise ReviewError("review output must not overwrite the input JSONL")
    if artifact_paths["decisions"] in destinations:
        raise ReviewError("review output must not overwrite the decision sheet")

    entries = read_jsonl(input_path)
    entries_by_id = {str(entry.get("entry_id")): entry for entry in entries}
    headers, decisions = read_csv(decisions_path)
    missing = set(DECISION_FIELDS) - set(headers)
    if missing:
        raise ReviewError(
            f"{decisions_path}: missing decision columns: {sorted(missing)}"
        )
    seen: set[tuple[str, str]] = set()
    cache_by_repo: dict[str, GitBlobCache] = {}
    diff_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    applied = kept = pending = 0

    for row_number, row in enumerate(decisions, 2):
        entry_id = row.get("entry_id", "").strip()
        field_path = row.get("field_path", "").strip()
        key = (entry_id, field_path)
        if key in seen:
            raise ReviewError(f"{decisions_path}:{row_number}: duplicate decision: {key}")
        seen.add(key)
        entry = entries_by_id.get(entry_id)
        if entry is None:
            raise ReviewError(f"{decisions_path}:{row_number}: unknown entry_id: {entry_id}")
        node = node_at(entry, field_path)
        current_sha = node_sha256(entry, field_path, node)
        if row.get("expected_node_sha256", "").strip() != current_sha:
            raise ReviewError(
                f"{entry_id}:{field_path}: stale decision; node fingerprint changed"
            )
        expected_review_id = review_id(entry, field_path, node)
        if row.get("review_id", "").strip() != expected_review_id:
            raise ReviewError(f"{entry_id}:{field_path}: review_id does not match node")
        if str(node.get("file", "")) != row.get("original_file", "") or str(
            node.get("line", "")
        ) != row.get("original_line", ""):
            raise ReviewError(f"{entry_id}:{field_path}: original location columns changed")

        decision = row.get("decision", "").strip().lower()
        reviewer = row.get("reviewer", "").strip()
        rationale = row.get("rationale", "").strip()
        common = {
            "review_id": expected_review_id,
            "entry_id": entry_id,
            "field_path": field_path,
            "decision": decision,
            "reviewer": reviewer,
            "rationale": rationale,
            "old_file": node.get("file", ""),
            "old_line": node.get("line", ""),
            "new_file": row.get("new_file", "").strip(),
            "new_line": row.get("new_line", "").strip(),
            "match_mode": "",
            "source_blob_oid": "",
            "source_sha256": "",
        }
        if not decision:
            pending += 1
            common.update(status="pending")
            audit_rows.append(common)
            continue
        if decision not in {"apply", "keep"}:
            raise ReviewError(
                f"{decisions_path}:{row_number}: decision must be apply, keep, or blank"
            )
        if not reviewer or not rationale:
            raise ReviewError(
                f"{entry_id}:{field_path}: reviewer and rationale are required"
            )
        if decision == "keep":
            if row.get("new_file", "").strip() or row.get("new_line", "").strip():
                raise ReviewError(
                    f"{entry_id}:{field_path}: keep decision cannot set a new location"
                )
            kept += 1
            common.update(status="kept")
            audit_rows.append(common)
            continue
        if entry.get("verify") == 1 and not include_verified:
            raise ReviewError(
                f"{entry_id}:{field_path}: verify=1 is protected; use --include-verified"
            )
        new_file = normalize_repo_path(row.get("new_file", "").strip())
        new_line, new_span = parse_line(row.get("new_line", "").strip())
        old_file = str(node.get("file", ""))
        old_line = node.get("line")
        _, old_span = parse_line(old_line)
        if new_file == normalize_repo_path(old_file) and new_span == old_span:
            raise ReviewError(
                f"{entry_id}:{field_path}: apply decision does not change the location; use keep"
            )
        repo_url = str(entry.get("repo_url", ""))
        cache_key = normalize_repo_identity(repo_url)
        if cache_key not in cache_by_repo:
            cache_by_repo[cache_key] = GitBlobCache(
                repo_url,
                cache_root,
                offline=offline,
                timeout=git_timeout,
                max_blob_bytes=max_blob_bytes,
            )
        source_text, blob_oid, source_sha = cache_by_repo[cache_key].read_blob(
            str(entry.get("commit", "")), new_file
        )
        match_mode = match_source(node.get("code"), source_text, new_span)
        old_desc = node.get("desc", "")
        new_desc = synchronize_desc(
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
        applied += 1
        common.update(
            status="applied",
            new_file=new_file,
            new_line=new_line,
            match_mode=match_mode,
            source_blob_oid=blob_oid,
            source_sha256=source_sha,
        )
        audit_rows.append(common)
        diff_rows.append(
            {
                "review_id": expected_review_id,
                "entry_id": entry_id,
                "field_path": field_path,
                "old_file": old_file,
                "old_line": old_line,
                "new_file": new_file,
                "new_line": new_line,
                "old_desc": old_desc,
                "new_desc": new_desc,
                "reviewer": reviewer,
                "rationale": rationale,
                "match_mode": match_mode,
                "source_blob_oid": blob_oid,
                "source_sha256": source_sha,
            }
        )

    if pending and not allow_pending:
        raise ReviewError(
            f"{pending} decision rows are still pending; complete them or use --allow-pending"
        )
    atomic_write_jsonl(output_path, entries)
    atomic_write_csv(diff_path, DIFF_FIELDS, diff_rows)
    atomic_write_csv(audit_path, AUDIT_FIELDS, audit_rows)
    return applied, kept, pending


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init", help="create a fingerprinted decision sheet from needs_human.csv"
    )
    init_parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    init_parser.add_argument("--queue", type=Path, required=True)
    init_parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)

    apply_parser = subparsers.add_parser(
        "apply", help="verify and atomically apply completed human decisions"
    )
    apply_parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    apply_parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    apply_parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    apply_parser.add_argument("--diff", type=Path, default=DEFAULT_DIFF)
    apply_parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    apply_parser.add_argument("--repo-cache", type=Path, default=DEFAULT_CACHE)
    apply_parser.add_argument("--offline", action="store_true")
    apply_parser.add_argument("--allow-pending", action="store_true")
    apply_parser.add_argument("--include-verified", action="store_true")
    apply_parser.add_argument("--git-timeout", type=int, default=120)
    apply_parser.add_argument("--max-blob-bytes", type=int, default=8 * 1024 * 1024)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            count = initialize_decisions(
                args.input.resolve(), args.queue.resolve(), args.decisions.resolve()
            )
            print(f"initialized {count} review decisions: {args.decisions}")
            return 0
        applied, kept, pending = apply_decisions(
            input_path=args.input.resolve(),
            decisions_path=args.decisions.resolve(),
            output_path=args.output.resolve(),
            diff_path=args.diff.resolve(),
            audit_path=args.audit.resolve(),
            cache_root=args.repo_cache.resolve(),
            offline=args.offline,
            allow_pending=args.allow_pending,
            include_verified=args.include_verified,
            git_timeout=args.git_timeout,
            max_blob_bytes=args.max_blob_bytes,
        )
        print(f"applied={applied} kept={kept} pending={pending}")
        print(f"output: {args.output}")
        print(f"diff: {args.diff}")
        print(f"audit: {args.audit}")
        return 0
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
