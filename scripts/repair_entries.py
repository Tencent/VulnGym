"""Repair entries.jsonl positions by re-matching code snippets against cached git snapshots.

Pipeline per node:
    original position match
      -> nearby ±5 lines unique
      -> original file full-text unique
      -> current commit repo-wide unique
      -> needs_human.csv

See scripts/README_repair_entries.md for usage.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

SCRIPT_DEFAULTS = {
    "input": Path("data/entries.jsonl"),
    "output_jsonl": Path("data/entries.fixed.jsonl"),
    "fix_diff_csv": Path("data/fix_diff.csv"),
    "needs_human_csv": Path("data/needs_human.csv"),
    "cache_dir": Path("tmp_v0"),
}

NEARBY_WINDOW = 5

STRATEGY_NEARBY = "nearby_unique"
STRATEGY_FILE = "file_unique"
STRATEGY_REPO = "repository_unique"

REASON_REPO_UNAVAILABLE = "repository_or_commit_unavailable"
REASON_INVALID_NODE = "invalid_node"
REASON_EMPTY_CODE = "empty_code"
REASON_FILE_NOT_FOUND = "file_not_found"
REASON_MULTIPLE_NEARBY = "multiple_nearby_matches"
REASON_MULTIPLE_FILE = "multiple_file_matches"
REASON_MULTIPLE_REPO = "multiple_repository_matches"
REASON_CODE_NOT_FOUND = "code_not_found"
REASON_DESC_CONFLICT = "desc_location_conflict"

# Anchors we accept in desc before attempting location rewrite. Anything else
# is left untouched so we never guess natural-language semantics.
_DASH = r"[-‐-―−]"  # ASCII hyphen + Unicode dashes
DESC_LINE_ANCHOR_PATTERNS = [
    re.compile(r"第\s*\d+(?:\s*" + _DASH + r"\s*\d+)?\s*行"),
    re.compile(r"line\s*\d+(?:\s*" + _DASH + r"\s*\d+)?", re.IGNORECASE),
    re.compile(r"lines?\s*\d+\s*" + _DASH + r"\s*\d+", re.IGNORECASE),
    re.compile(r"\b\d{2,5}\s*" + _DASH + r"\s*\d{2,5}\s*行"),
]
DESC_FILE_EXT_RE = re.compile(r"\.[a-zA-Z0-9]{1,8}$")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class SchemaError(ValueError):
    """Raised when entries.jsonl violates the documented schema."""


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


INTERNAL_FORBIDDEN_KEYS = {
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

REQUIRED_ENTRY_KEYS = (
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
)

REQUIRED_NODE_KEYS = ("file", "line", "code")
OPTIONAL_NODE_KEYS = ("desc",)

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^https://github\.com/.+/.+")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")


def parse_line(raw: object, field_path: str) -> tuple[int, int]:
    """Return (start, end) 1-based inclusive. Raises SchemaError on bad input."""
    if isinstance(raw, bool):  # bool is subclass of int — reject explicitly
        raise SchemaError(f"{field_path}: line must be int or 'a-b', got bool")
    if isinstance(raw, int):
        if raw < 1:
            raise SchemaError(f"{field_path}: line int must be >=1, got {raw}")
        return raw, raw
    if isinstance(raw, str):
        s = raw.strip()
        m = re.fullmatch(r"(\d+)-(\d+)", s)
        if not m:
            raise SchemaError(f"{field_path}: line string must be 'a-b', got {raw!r}")
        a, b = int(m.group(1)), int(m.group(2))
        if a < 1 or b < a:
            raise SchemaError(f"{field_path}: line range invalid: {raw!r}")
        return a, b
    raise SchemaError(f"{field_path}: line must be int or 'a-b', got {type(raw).__name__}")


def format_line(start: int, end: int, *, original_was_range: bool) -> int | str:
    """Preserve original line representation form."""
    if original_was_range:
        return f"{start}-{end}"
    return start


def line_was_range(raw: object) -> bool:
    return isinstance(raw, str)


def validate_entry(idx: int, raw: dict) -> None:
    if not isinstance(raw, dict):
        raise SchemaError(f"row {idx}: not an object")
    missing = [k for k in REQUIRED_ENTRY_KEYS if k not in raw]
    if missing:
        raise SchemaError(f"row {idx}: missing keys {missing}")
    forbidden = INTERNAL_FORBIDDEN_KEYS & set(raw.keys())
    if forbidden:
        raise SchemaError(f"row {idx}: forbidden keys present {sorted(forbidden)}")
    if not COMMIT_RE.fullmatch(str(raw["commit"])):
        raise SchemaError(f"row {idx}: commit malformed: {raw['commit']!r}")
    if not REPO_RE.match(str(raw["repo_url"])):
        raise SchemaError(f"row {idx}: repo_url malformed: {raw['repo_url']!r}")
    if not isinstance(raw["verify"], int) or raw["verify"] not in (0, 1):
        raise SchemaError(f"row {idx}: verify must be 0/1 int, got {raw['verify']!r}")
    if not isinstance(raw["vuln_ids"], list):
        raise SchemaError(f"row {idx}: vuln_ids must be list")
    if not isinstance(raw["trace"], list):
        raise SchemaError(f"row {idx}: trace must be list")
    for node_path, node in _iter_nodes(raw):
        _validate_node(idx, node_path, node)


def _iter_nodes(entry: dict) -> Iterable[tuple[str, dict]]:
    yield "entry_point", entry["entry_point"]
    yield "critical_operation", entry["critical_operation"]
    for i, t in enumerate(entry["trace"]):
        yield f"trace[{i}]", t


def _validate_node(idx: int, path: str, node: object) -> None:
    if not isinstance(node, dict):
        raise SchemaError(f"row {idx} {path}: not an object")
    missing = [k for k in REQUIRED_NODE_KEYS if k not in node]
    if missing:
        raise SchemaError(f"row {idx} {path}: missing keys {missing}")
    extra = set(node.keys()) - set(REQUIRED_NODE_KEYS) - set(OPTIONAL_NODE_KEYS)
    if extra:
        raise SchemaError(f"row {idx} {path}: unexpected keys {sorted(extra)}")
    if not isinstance(node["file"], str) or not node["file"]:
        raise SchemaError(f"row {idx} {path}: file must be non-empty string")
    parse_line(node["line"], f"row {idx} {path}")  # raises on bad
    if not isinstance(node["code"], str):
        raise SchemaError(f"row {idx} {path}: code must be string")
    if "desc" in node and (not isinstance(node["desc"], str) or not node["desc"]):
        raise SchemaError(f"row {idx} {path}: desc must be non-empty string if present")


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #


def normalize_code_block(code: str) -> list[str]:
    """Return normalized lines for matching.

    - CRLF/CR -> LF
    - strip leading and trailing empty lines (but keep internal blanks)
    - per-line: collapse runs of whitespace to single space + outer strip
    """
    unified = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = unified.split("\n")
    while lines and lines[0].strip() == "":
        lines.pop(0)
    while lines and lines[-1].strip() == "":
        lines.pop()
    return [" ".join(line.split()) for line in lines]


def normalize_file_lines(content: str) -> list[str]:
    """Return one normalized line per source line (1-based: use [i-1])."""
    unified = content.replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = unified.split("\n")
    return [" ".join(line.split()) for line in raw_lines]


# --------------------------------------------------------------------------- #
# Matchers
# --------------------------------------------------------------------------- #


def match_block_at(
    file_norm: list[str], code_norm: list[str], start_1based: int
) -> bool:
    if not code_norm:
        return False
    if start_1based < 1:
        return False
    idx = start_1based - 1
    if idx + len(code_norm) > len(file_norm):
        return False
    for i, cl in enumerate(code_norm):
        if file_norm[idx + i] != cl:
            return False
    return True


def find_matches_in_range(
    file_norm: list[str], code_norm: list[str], lo: int, hi: int
) -> list[int]:
    if not code_norm:
        return []
    out: list[int] = []
    lo = max(1, lo)
    hi = min(len(file_norm) - len(code_norm) + 1, hi)
    for start in range(lo, hi + 1):
        if match_block_at(file_norm, code_norm, start):
            out.append(start)
    return out


def find_matches_in_file(file_norm: list[str], code_norm: list[str]) -> list[int]:
    if not code_norm:
        return []
    return find_matches_in_range(
        file_norm, code_norm, 1, len(file_norm) - len(code_norm) + 1
    )


# --------------------------------------------------------------------------- #
# Repo / commit cache
# --------------------------------------------------------------------------- #


def run_git(args: list[str], cwd: Path, *, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        errors="replace",
        encoding="utf-8",
        check=False,
        timeout=timeout,
    )


@dataclass
class CommitContext:
    repo_url: str
    commit: str
    worktree: Path
    base_repo: Path
    _file_cache: dict[str, Optional[list[str]]] = field(default_factory=dict)
    _rels: Optional[tuple[str, ...]] = None
    _first_line_index: Optional[dict[str, list[tuple[str, int]]]] = None

    def all_rels(self) -> tuple[str, ...]:
        if self._rels is None:
            res = run_git(["ls-tree", "-r", "--name-only", "HEAD"], self.worktree)
            if res.returncode != 0:
                self._rels = ()
            else:
                self._rels = tuple(
                    line for line in res.stdout.split("\n") if line.strip()
                )
        return self._rels

    def read_file(self, rel: str) -> Optional[list[str]]:
        if rel in self._file_cache:
            return self._file_cache[rel]
        result = self._read_file_raw(rel)
        self._file_cache[rel] = result
        return result

    def _read_file_raw(self, rel: str) -> Optional[list[str]]:
        p = self.worktree / rel
        try:
            if p.is_file():
                content = p.read_text(encoding="utf-8", errors="replace")
                return normalize_file_lines(content)
        except OSError:
            pass
        # Fallback to git cat-file (handles case-mismatch on case-sensitive FS too)
        res = run_git(
            ["cat-file", "-p", f"HEAD:{rel}"], self.worktree, timeout=60
        )
        if res.returncode != 0:
            # Try case-insensitive lookup via ls-tree
            alt = self._find_canonical_case(rel)
            if alt is not None and alt != rel:
                return self._read_file_raw_cache_only(alt)
            return None
        return normalize_file_lines(res.stdout)

    def _read_file_raw_cache_only(self, rel: str) -> Optional[list[str]]:
        # already-known canonical case path — read directly
        p = self.worktree / rel
        try:
            if p.is_file():
                return normalize_file_lines(
                    p.read_text(encoding="utf-8", errors="replace")
                )
        except OSError:
            pass
        return None

    def _find_canonical_case(self, rel: str) -> Optional[str]:
        parts = rel.split("/")
        cur = self.worktree
        for i, part in enumerate(parts):
            low = part.lower()
            try:
                entries = list(cur.iterdir())
            except OSError:
                return None
            match = None
            for e in entries:
                if e.name.lower() == low:
                    match = e.name
                    break
            if match is None:
                return None
            cur = cur / match
        canonical = str(cur.relative_to(self.worktree)).replace("\\", "/")
        return canonical

    def build_first_line_index(self) -> dict[str, list[tuple[str, int]]]:
        if self._first_line_index is not None:
            return self._first_line_index
        idx: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for rel in self.all_rels():
            lines = self.read_file(rel)
            if not lines:
                continue
            for i, line in enumerate(lines):
                if line:  # skip blank lines from indexing (collapses to empty)
                    idx[line].append((rel, i + 1))
        self._first_line_index = idx
        return idx


class RepoCache:
    """Owns cache layout. Lazy; creates worktrees only when asked (online mode)."""

    def __init__(self, cache_root: Path, *, offline: bool, verbose: bool = False):
        self.cache_root = cache_root
        self.offline = offline
        self.verbose = verbose
        self._commit_ctx: dict[tuple[str, str], Optional[CommitContext]] = {}

    @staticmethod
    def repo_slug(repo_url: str) -> str:
        parts = repo_url.rstrip("/").split("/")
        return "__".join(parts[-2:])

    def base_repo_dir(self, repo_url: str) -> Path:
        return self.cache_root / self.repo_slug(repo_url)

    def worktree_dir(self, repo_url: str, commit: str) -> Path:
        return self.cache_root / f"{self.repo_slug(repo_url)}__{commit[:8]}"

    def get(self, repo_url: str, commit: str) -> Optional[CommitContext]:
        key = (repo_url, commit)
        if key in self._commit_ctx:
            return self._commit_ctx[key]
        ctx = self._load_or_create(repo_url, commit)
        self._commit_ctx[key] = ctx
        return ctx

    def _load_or_create(
        self, repo_url: str, commit: str
    ) -> Optional[CommitContext]:
        wt = self.worktree_dir(repo_url, commit)
        if wt.exists() and wt.is_dir():
            head = self._rev_parse_head(wt)
            if head == commit:
                return CommitContext(
                    repo_url=repo_url,
                    commit=commit,
                    worktree=wt,
                    base_repo=self.base_repo_dir(repo_url),
                )
            # stale worktree — fall through to recreate if online
            if self.verbose:
                print(
                    f"[cache] stale worktree {wt.name}: head={head} want={commit}",
                    file=sys.stderr,
                )
        if self.offline:
            if self.verbose:
                print(
                    f"[cache] offline: missing {wt.name}",
                    file=sys.stderr,
                )
            return None
        if not self._fetch_and_attach(repo_url, commit, wt):
            return None
        head = self._rev_parse_head(wt)
        if head != commit:
            return None
        return CommitContext(
            repo_url=repo_url,
            commit=commit,
            worktree=wt,
            base_repo=self.base_repo_dir(repo_url),
        )

    def _rev_parse_head(self, wt: Path) -> Optional[str]:
        res = run_git(["rev-parse", "HEAD"], wt)
        if res.returncode != 0:
            return None
        return res.stdout.strip()

    def _fetch_and_attach(
        self, repo_url: str, commit: str, wt: Path
    ) -> bool:
        base = self.base_repo_dir(repo_url)
        if not (base / ".git").exists() and not base.exists():
            base.mkdir(parents=True, exist_ok=True)
            res = subprocess.run(
                ["git", "init", str(base)],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                return False
        # Ensure remote
        res = run_git(["remote", "get-url", "origin"], base)
        if res.returncode != 0:
            run_git(["remote", "add", "origin", repo_url], base)
        else:
            if repo_url not in res.stdout:
                run_git(["remote", "set-url", "origin", repo_url], base)
        # Fetch commit
        res = subprocess.run(
            ["git", "-C", str(base), "fetch", "--no-tags", "--depth=1", "origin", commit],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        if res.returncode != 0:
            # try full fetch fallback
            res2 = subprocess.run(
                ["git", "-C", str(base), "fetch", "origin"],
                capture_output=True,
                text=True,
                check=False,
                timeout=900,
            )
            if res2.returncode != 0:
                return False
        # Check object exists
        res = run_git(["cat-file", "-t", commit], base)
        if res.returncode != 0 or res.stdout.strip() != "commit":
            return False
        # Attach worktree at commit
        wt.parent.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            [
                "git",
                "-C",
                str(base),
                "worktree",
                "add",
                "--detach",
                "--force",
                str(wt),
                commit,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        if res.returncode != 0:
            return False
        return True


# --------------------------------------------------------------------------- #
# Pipeline data types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class NodeRef:
    entry_id: str
    field_path: str
    file: str
    line_raw: int | str
    code: str
    desc: Optional[str]


@dataclass
class Outcome:
    node: NodeRef
    strategy: Optional[str]  # one of STRATEGY_*
    reason: Optional[str]  # one of REASON_*
    new_file: Optional[str] = None
    new_start: Optional[int] = None
    new_end: Optional[int] = None
    new_desc: Optional[str] = None
    candidates: list[tuple[str, int]] = field(default_factory=list)

    @property
    def repaired(self) -> bool:
        return self.strategy is not None


def iter_nodes(entry: dict) -> Iterable[NodeRef]:
    eid = entry["entry_id"]
    ep = entry["entry_point"]
    yield NodeRef(eid, "entry_point", ep["file"], ep["line"], ep["code"], ep.get("desc"))
    co = entry["critical_operation"]
    yield NodeRef(
        eid,
        "critical_operation",
        co["file"],
        co["line"],
        co["code"],
        co.get("desc"),
    )
    for i, t in enumerate(entry["trace"]):
        yield NodeRef(
            eid,
            f"trace[{i}]",
            t["file"],
            t["line"],
            t["code"],
            t.get("desc"),
        )


# --------------------------------------------------------------------------- #
# Matching pipeline
# --------------------------------------------------------------------------- #


def repair_node(
    node: NodeRef,
    *,
    repo_url: str,
    commit: str,
    cache: RepoCache,
    nearby_window: int = NEARBY_WINDOW,
) -> Outcome:
    # Validate code non-empty after normalization
    code_norm = normalize_code_block(node.code)
    if not code_norm:
        return Outcome(node=node, strategy=None, reason=REASON_EMPTY_CODE)

    ctx = cache.get(repo_url, commit)
    if ctx is None:
        return Outcome(node=node, strategy=None, reason=REASON_REPO_UNAVAILABLE)

    start, end = parse_line(node.line_raw, node.field_path)
    was_range = line_was_range(node.line_raw)
    orig_file = node.file
    file_norm = ctx.read_file(orig_file)

    # 1. Original position
    if file_norm is not None and match_block_at(file_norm, code_norm, start):
        return Outcome(
            node=node,
            strategy=None,  # no repair needed — handled by caller as no-op
            reason=None,
            new_file=orig_file,
            new_start=start,
            new_end=_end_from_start(code_norm, start, was_range, end - start),
        )

    # 2. Nearby ±window (only if file exists)
    if file_norm is not None:
        lo = start - nearby_window
        hi = start + nearby_window
        near = find_matches_in_range(file_norm, code_norm, lo, hi)
        if len(near) == 1:
            s = near[0]
            return Outcome(
                node=node,
                strategy=STRATEGY_NEARBY,
                reason=None,
                new_file=orig_file,
                new_start=s,
                new_end=_end_from_start(code_norm, s, was_range, end - start),
                candidates=[(orig_file, s)],
            )
        if len(near) > 1:
            return Outcome(
                node=node,
                strategy=None,
                reason=REASON_MULTIPLE_NEARBY,
                candidates=[(orig_file, s) for s in near],
            )

    # 3. Original file full-text unique (file exists, but no nearby match)
    if file_norm is not None:
        all_in_file = find_matches_in_file(file_norm, code_norm)
        if len(all_in_file) == 1:
            s = all_in_file[0]
            return Outcome(
                node=node,
                strategy=STRATEGY_FILE,
                reason=None,
                new_file=orig_file,
                new_start=s,
                new_end=_end_from_start(code_norm, s, was_range, end - start),
                candidates=[(orig_file, s)],
            )
        if len(all_in_file) > 1:
            # Plan: original file with multiple candidates -> do not go repo-wide
            return Outcome(
                node=node,
                strategy=None,
                reason=REASON_MULTIPLE_FILE,
                candidates=[(orig_file, s) for s in all_in_file],
            )

    # 4. File missing OR no candidates in original file -> repo-wide search
    if file_norm is None:
        # file missing entirely — go straight to repo
        pass
    # Build inverted index on first normalized line
    idx = ctx.build_first_line_index()
    candidates: list[tuple[str, int]] = []
    first = code_norm[0]
    bucket = idx.get(first, ())
    for rel, line_no in bucket:
        if rel == orig_file:
            continue  # already examined original file above
        lines = ctx.read_file(rel)
        if lines is None:
            continue
        if match_block_at(lines, code_norm, line_no):
            candidates.append((rel, line_no))
    # If original file existed but had zero candidates, also include any (none here).
    # If original file did not exist, the bucket above is the complete set.

    # Also include candidates from original file (for accurate count) when file existed
    # but had zero matches — there are none to add.
    if not candidates:
        return Outcome(
            node=node,
            strategy=None,
            reason=REASON_FILE_NOT_FOUND if file_norm is None else REASON_CODE_NOT_FOUND,
        )
    if len(candidates) == 1:
        rel, s = candidates[0]
        return Outcome(
            node=node,
            strategy=STRATEGY_REPO,
            reason=None,
            new_file=rel,
            new_start=s,
            new_end=_end_from_start(code_norm, s, was_range, end - start),
            candidates=candidates,
        )
    return Outcome(
        node=node,
        strategy=None,
        reason=REASON_MULTIPLE_REPO,
        candidates=candidates,
    )


def _end_from_start(
    code_norm: list[str], start: int, was_range: bool, orig_span: int
) -> int:
    """Compute new end line given the new start.

    Block occupies [start, start + len(code_norm) - 1]. For range inputs that
    originally spanned more lines than the code block (rare — happens when
    desc annotates a region), keep the same trailing offset.
    """
    natural_end = start + len(code_norm) - 1
    if was_range and orig_span + 1 > len(code_norm):
        return start + orig_span
    return natural_end


# --------------------------------------------------------------------------- #
# desc rewrite
# --------------------------------------------------------------------------- #


def _old_filename_anchors(file_path: str) -> set[str]:
    """Return set of substrings that count as 'old file basename' anchors."""
    parts = re.split(r"[\\/]", file_path)
    anchors: set[str] = set()
    for i, p in enumerate(parts):
        if p and DESC_FILE_EXT_RE.search(p):
            anchors.add(p)
            # also full suffix from this point
            sub = "/".join(parts[i:])
            if sub:
                anchors.add(sub)
            sub_bs = "\\".join(parts[i:])
            if sub_bs:
                anchors.add(sub_bs)
    return anchors


def _has_line_anchor(desc: str) -> bool:
    return any(p.search(desc) for p in DESC_LINE_ANCHOR_PATTERNS)


def _rewrite_desc(
    desc: str,
    *,
    old_file: str,
    old_start: int,
    new_file: str,
    new_start: int,
    new_end: int,
) -> tuple[Optional[str], bool]:
    """Return (rewritten_desc, conflict_flag).

    conflict_flag True means we cannot safely rewrite — caller should emit a
    needs_human row with REASON_DESC_CONFLICT while keeping the position fix.
    """
    if not desc:
        return None, False
    has_line = _has_line_anchor(desc)
    file_anchors = _old_filename_anchors(old_file)
    has_file = any(a in desc for a in file_anchors)

    if not has_line and not has_file:
        # No positional anchors — desc is semantic, leave as-is
        return None, False

    new_desc = desc
    if has_file:
        new_anchors = _old_filename_anchors(new_file)
        # Replace longest old anchors first to avoid partial replacement
        old_sorted = sorted(file_anchors, key=len, reverse=True)
        new_map: dict[str, Optional[str]] = {}
        for old in old_sorted:
            # find a matching new anchor by basename similarity
            new_match = _pick_new_anchor(old, new_file, new_anchors)
            new_map[old] = new_match
        for old in old_sorted:
            repl = new_map[old]
            if repl is None:
                # cannot confidently map — leave untouched but flag conflict
                return None, True
            new_desc = new_desc.replace(old, repl)
    if has_line:
        new_desc = _replace_line_numbers(
            new_desc,
            old_start=old_start,
            new_start=new_start,
            new_end=new_end,
        )
        if new_desc is None:
            return None, True
    return new_desc, False


def _pick_new_anchor(
    old_anchor: str, new_file: str, new_anchors: set[str]
) -> Optional[str]:
    """Given an old file anchor, pick a replacement from new_anchors.

    Strategy: match by basename (last path component). If no match, return None.
    """
    old_base = old_anchor.split("/")[-1]
    # If new_file has same basename, return the corresponding suffix.
    new_parts = re.split(r"[\\/]", new_file)
    for i, p in enumerate(new_parts):
        if p == old_base:
            return "/".join(new_parts[i:])
    # fall back: any new anchor whose basename equals old_base
    for na in new_anchors:
        if na.split("/")[-1] == old_base:
            return na
    return None


_LINE_ANCHOR_REGEX = re.compile(
    r"(?P<zh_range>第\s*(?P<zh_range_a>\d+)\s*(?P<zh_range_sep>" + _DASH + r")\s*(?P<zh_range_b>\d+)\s*行)"
    r"|(?P<zh_single>第\s*(?P<zh_single_a>\d+)\s*行)"
    r"|(?P<en_range>(?P<en_pre>lines?)\s*(?P<en_range_a>\d+)\s*(?P<en_range_sep>" + _DASH + r")\s*(?P<en_range_b>\d+))"
    r"|(?P<en_single>(?P<en_single_pre>line)\s*(?P<en_single_a>\d+))"
    r"|(?P<bare_range>(?P<bare_a>\d{2,5})\s*(?P<bare_sep>" + _DASH + r")\s*(?P<bare_b>\d{2,5})\s*行)",
    re.IGNORECASE,
)


def _replace_line_numbers(
    desc: str, *, old_start: int, new_start: int, new_end: int
) -> Optional[str]:
    """Replace line-number anchors. Single pass via alternation so ranges
    that are part of a 第…行 / line… span are not double-shifted."""
    delta = new_start - old_start

    def _shift_pair(prefix: str, a: str, sep: str, b: str, suffix: str) -> str:
        return f"{prefix}{int(a) + delta}{sep}{int(b) + delta}{suffix}"

    def _shift_single(prefix: str, a: str, suffix: str) -> str:
        return f"{prefix}{int(a) + delta}{suffix}"

    def _repl(m: re.Match) -> str:
        if m.group("zh_range") is not None:
            return _shift_pair(
                "第 ", m.group("zh_range_a"), m.group("zh_range_sep"),
                m.group("zh_range_b"), " 行",
            )
        if m.group("zh_single") is not None:
            return _shift_single(
                "第 ", m.group("zh_single_a"), " 行",
            )
        if m.group("en_range") is not None:
            return _shift_pair(
                m.group("en_pre") + " ", m.group("en_range_a"),
                m.group("en_range_sep"), m.group("en_range_b"), "",
            )
        if m.group("en_single") is not None:
            return _shift_single(
                m.group("en_single_pre") + " ", m.group("en_single_a"), "",
            )
        if m.group("bare_range") is not None:
            return _shift_pair(
                "", m.group("bare_a"), m.group("bare_sep"),
                m.group("bare_b"), " 行",
            )
        return m.group(0)

    return _LINE_ANCHOR_REGEX.sub(_repl, desc)


# --------------------------------------------------------------------------- #
# Entry-level repair driver
# --------------------------------------------------------------------------- #


@dataclass
class EntryRepair:
    entry: dict
    fixes: list[Outcome]  # repaired outcomes (strategy is not None and position changed)
    unchanged: list[Outcome]  # strategy None, reason None — original position held
    needs_human: list[Outcome]


def repair_entry(
    entry: dict, cache: RepoCache, *, nearby_window: int = NEARBY_WINDOW
) -> EntryRepair:
    repo_url = entry["repo_url"]
    commit = entry["commit"]
    outcomes_by_path: dict[str, Outcome] = {}
    fixes: list[Outcome] = []
    unchanged: list[Outcome] = []
    needs_human: list[Outcome] = []

    for raw_node in iter_nodes(entry):
        outcome = repair_node(
            raw_node,
            repo_url=repo_url,
            commit=commit,
            cache=cache,
            nearby_window=nearby_window,
        )
        outcomes_by_path[raw_node.field_path] = outcome
        if outcome.strategy is None and outcome.reason is None:
            unchanged.append(outcome)
        elif outcome.strategy is None:
            needs_human.append(outcome)
        else:
            fixes.append(outcome)

    # Apply desc rewrites for fixes; emit desc conflict as extra needs_human
    extra_needs_human: list[Outcome] = []
    for fix in fixes:
        if fix.node.desc:
            new_desc, conflict = _rewrite_desc(
                fix.node.desc,
                old_file=fix.node.file,
                old_start=parse_line(fix.node.line_raw, fix.node.field_path)[0],
                new_file=fix.new_file or fix.node.file,
                new_start=fix.new_start or 0,
                new_end=fix.new_end or 0,
            )
            if conflict:
                # position fix kept, but flag for human review
                nh = Outcome(
                    node=fix.node,
                    strategy=None,
                    reason=REASON_DESC_CONFLICT,
                    new_file=fix.new_file,
                    new_start=fix.new_start,
                    new_end=fix.new_end,
                    candidates=fix.candidates,
                )
                extra_needs_human.append(nh)
            elif new_desc is not None:
                fix.new_desc = new_desc

    needs_human.extend(extra_needs_human)

    # Mutate entry in place with new positions
    _apply_outcomes(entry, outcomes_by_path)

    return EntryRepair(
        entry=entry, fixes=fixes, unchanged=unchanged, needs_human=needs_human
    )


def _apply_outcomes(entry: dict, outcomes: dict[str, Outcome]) -> None:
    for path, out in outcomes.items():
        if out.strategy is None:
            continue  # no repair
        if out.new_file is None or out.new_start is None:
            continue
        node = _get_node(entry, path)
        was_range = line_was_range(node["line"])
        node["file"] = out.new_file
        node["line"] = (
            f"{out.new_start}-{out.new_end}"
            if was_range and out.new_end is not None
            else out.new_start
        )
        if out.new_desc is not None:
            node["desc"] = out.new_desc


def _get_node(entry: dict, path: str) -> dict:
    if path in ("entry_point", "critical_operation"):
        return entry[path]
    m = re.fullmatch(r"trace\[(\d+)\]", path)
    if not m:
        raise ValueError(f"bad path: {path}")
    return entry["trace"][int(m.group(1))]


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #


FIX_DIFF_HEADER = [
    "entry_id",
    "field_path",
    "old_file",
    "old_line",
    "old_desc",
    "new_file",
    "new_line",
    "new_desc",
    "strategy",
    "match_mode",
    "evidence",
]

NEEDS_HUMAN_HEADER = [
    "entry_id",
    "field_path",
    "file",
    "line",
    "code",
    "desc",
    "reason",
    "candidate_count",
    "candidates",
]


def write_fix_diff_csv(outcomes: Iterable[Outcome], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        w.writerow(FIX_DIFF_HEADER)
        for out in outcomes:
            if not out.strategy:
                continue
            old_start = parse_line(out.node.line_raw, out.node.field_path)[0]
            old_end = parse_line(out.node.line_raw, out.node.field_path)[1]
            old_line = (
                f"{old_start}-{old_end}"
                if line_was_range(out.node.line_raw)
                else old_start
            )
            new_line = (
                f"{out.new_start}-{out.new_end}"
                if line_was_range(out.node.line_raw) and out.new_end is not None
                else out.new_start
            )
            evidence = "; ".join(f"{rel}:{ln}" for rel, ln in out.candidates)
            w.writerow(
                [
                    out.node.entry_id,
                    out.node.field_path,
                    out.node.file,
                    old_line,
                    out.node.desc or "",
                    out.new_file or "",
                    new_line if new_line is not None else "",
                    out.new_desc or "",
                    out.strategy,
                    _match_mode_for(out),
                    evidence,
                ]
            )
            n += 1
    return n


def _match_mode_for(out: Outcome) -> str:
    code_lines = normalize_code_block(out.node.code)
    if len(code_lines) > 1:
        return "multiline"
    return "single"


def write_needs_human_csv(outcomes: Iterable[Outcome], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        w.writerow(NEEDS_HUMAN_HEADER)
        for out in outcomes:
            if out.strategy is not None:
                continue
            if out.reason is None:
                continue  # original-position no-op is not a human item
            start, end = parse_line(out.node.line_raw, out.node.field_path)
            old_line = (
                f"{start}-{end}" if line_was_range(out.node.line_raw) else start
            )
            cand = "; ".join(f"{rel}:{ln}" for rel, ln in out.candidates)
            w.writerow(
                [
                    out.node.entry_id,
                    out.node.field_path,
                    out.node.file,
                    old_line,
                    out.node.code,
                    out.node.desc or "",
                    out.reason,
                    len(out.candidates),
                    cand,
                ]
            )
            n += 1
    return n


def write_fixed_jsonl(entries: Iterable[dict], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True))
            f.write("\n")
            n += 1
    return n


# --------------------------------------------------------------------------- #
# Main driver
# --------------------------------------------------------------------------- #


def load_entries(path: Path) -> list[dict]:
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise SchemaError(f"row {i}: invalid JSON: {e}") from e
            validate_entry(i, obj)
            out.append(obj)
    return out


def run(
    input_path: Path,
    output_jsonl: Path,
    fix_diff_csv: Path,
    needs_human_csv: Path,
    cache_dir: Path,
    *,
    only_unverified: bool = False,
    offline: bool = False,
    nearby_window: int = NEARBY_WINDOW,
    verbose: bool = False,
) -> dict:
    entries = load_entries(input_path)
    if only_unverified:
        targets = [e for e in entries if e.get("verify") != 1]
    else:
        targets = entries
    if verbose:
        print(
            f"[run] {len(targets)} entries (only_unverified={only_unverified})",
            file=sys.stderr,
        )

    cache = RepoCache(cache_dir, offline=offline, verbose=verbose)
    repaired_entries: list[dict] = []
    all_fixes: list[Outcome] = []
    all_needs: list[Outcome] = []

    # Pre-sort targets by entry_id for deterministic processing order
    targets_sorted = sorted(targets, key=lambda e: e["entry_id"])
    # But preserve original output order: build index map
    id_to_entry_orig_order: dict[str, int] = {
        e["entry_id"]: i for i, e in enumerate(entries)
    }

    repaired_by_id: dict[str, dict] = {}

    for entry in targets_sorted:
        try:
            r = repair_entry(entry, cache, nearby_window=nearby_window)
        except SchemaError as e:
            raise SchemaError(f"{entry['entry_id']}: {e}") from e
        repaired_by_id[entry["entry_id"]] = r.entry
        all_fixes.extend(r.fixes)
        all_needs.extend(r.needs_human)
        if verbose and (len(repaired_by_id) % 25 == 0):
            print(
                f"[run] processed {len(repaired_by_id)}/{len(targets_sorted)} "
                f"fixes={len(all_fixes)} needs_human={len(all_needs)}",
                file=sys.stderr,
            )

    # Output: keep original entry order (not target subset order).
    # For --only-unverified runs, only output the subset but in original order.
    target_ids = {e["entry_id"] for e in targets}
    if only_unverified:
        out_entries = [
            repaired_by_id[e["entry_id"]]
            for e in entries
            if e["entry_id"] in target_ids
        ]
    else:
        out_entries = [
            repaired_by_id.get(e["entry_id"], e) for e in entries
        ]

    n_jsonl = write_fixed_jsonl(out_entries, output_jsonl)
    n_fix = write_fix_diff_csv(all_fixes, fix_diff_csv)
    n_nh = write_needs_human_csv(all_needs, needs_human_csv)

    return {
        "entries_total": len(entries),
        "entries_processed": len(targets),
        "entries_written": n_jsonl,
        "fixes": n_fix,
        "needs_human": n_nh,
    }


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Repair VulnGym entries.jsonl positions against cached git snapshots."
    )
    p.add_argument(
        "--input",
        type=Path,
        default=SCRIPT_DEFAULTS["input"],
        help=f"Input entries.jsonl path (default: {SCRIPT_DEFAULTS['input']})",
    )
    p.add_argument(
        "--output-jsonl",
        type=Path,
        default=SCRIPT_DEFAULTS["output_jsonl"],
        help=f"Output repaired JSONL path (default: {SCRIPT_DEFAULTS['output_jsonl']})",
    )
    p.add_argument(
        "--fix-diff-csv",
        type=Path,
        default=SCRIPT_DEFAULTS["fix_diff_csv"],
        help=f"Output fix_diff.csv path (default: {SCRIPT_DEFAULTS['fix_diff_csv']})",
    )
    p.add_argument(
        "--needs-human-csv",
        type=Path,
        default=SCRIPT_DEFAULTS["needs_human_csv"],
        help=f"Output needs_human.csv path (default: {SCRIPT_DEFAULTS['needs_human_csv']})",
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=SCRIPT_DEFAULTS["cache_dir"],
        help=f"Cache directory (default: {SCRIPT_DEFAULTS['cache_dir']})",
    )
    p.add_argument(
        "--only-unverified",
        action="store_true",
        help="Process only entries with verify != 1",
    )
    p.add_argument(
        "--offline",
        action="store_true",
        help="Do not fetch or create worktrees. Missing commits go to needs_human.",
    )
    p.add_argument(
        "--nearby-window",
        type=int,
        default=NEARBY_WINDOW,
        help=f"Nearby-search window in lines (default: {NEARBY_WINDOW})",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Emit progress diagnostics to stderr.",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    try:
        stats = run(
            input_path=args.input,
            output_jsonl=args.output_jsonl,
            fix_diff_csv=args.fix_diff_csv,
            needs_human_csv=args.needs_human_csv,
            cache_dir=args.cache_dir,
            only_unverified=args.only_unverified,
            offline=args.offline,
            nearby_window=args.nearby_window,
            verbose=args.verbose,
        )
    except SchemaError as e:
        print(f"schema error: {e}", file=sys.stderr)
        return 2
    print(
        f"entries_total={stats['entries_total']} "
        f"processed={stats['entries_processed']} "
        f"written={stats['entries_written']} "
        f"fixes={stats['fixes']} "
        f"needs_human={stats['needs_human']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
