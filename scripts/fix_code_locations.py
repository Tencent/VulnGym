#!/usr/bin/env python3
"""Repair VulnGym node file/line locations using source-code snippets.

For each selected entry, this script checks entry_point, critical_operation,
and trace[*] nodes against the corresponding repository at the annotated
commit. When the annotated location does not match the node's code snippet, it
tries conservative repairs in this order:

1. Search within +/- N lines of the original line in the original file.
2. Search the original file.
3. Search the whole repository.

Only unique matches are applied. Ambiguous or missing matches are written to
needs_human.csv.
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
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENTRIES = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_REPO_CACHE = REPO_ROOT / ".cache" / "source_repos"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "entries.fixed.jsonl"
DEFAULT_DIFF = REPO_ROOT / "reports" / "fix_diff.csv"
DEFAULT_NEEDS_HUMAN = REPO_ROOT / "reports" / "needs_human.csv"

LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
NUMERIC_LINE_RE = re.compile(r"^[1-9]\d*$")
LEADING_DOT_SLASH_RE = re.compile(r"^(?:\./)+")
MULTI_SLASH_RE = re.compile(r"/+")
SPACE_RE = re.compile(r"[ \t]+")

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


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int


@dataclass(frozen=True)
class Match:
    file: str
    start: int
    end: int

    @property
    def line_value(self) -> int | str:
        return self.start if self.start == self.end else f"{self.start}-{self.end}"


class CheckoutError(RuntimeError):
    pass


def run_git(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    no_lazy_fetch: bool = False,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if no_lazy_fetch:
        env["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def normalize_repo_url(url: str) -> str:
    url = url.strip()
    if url.endswith("/"):
        url = url[:-1]
    if url.endswith(".git"):
        url = url[:-4]
    return url


def repo_cache_name(repo_url: str) -> str:
    normalized = normalize_repo_url(repo_url)
    tail = normalized.split("github.com/", 1)[-1].replace("/", "__")
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:10]
    safe_tail = re.sub(r"[^A-Za-z0-9_.-]+", "_", tail)
    return f"{safe_tail}__{digest}"


def clone_url_for(repo_url: str, protocol: str) -> str:
    normalized = normalize_repo_url(repo_url)
    if protocol == "ssh" and normalized.startswith("https://github.com/"):
        return "git@github.com:" + normalized.split("https://github.com/", 1)[1] + ".git"
    return normalized + ".git"


def normalize_path(path: Any) -> str:
    if not isinstance(path, str):
        return ""
    path = path.replace("\\", "/")
    path = LEADING_DOT_SLASH_RE.sub("", path)
    return MULTI_SLASH_RE.sub("/", path)


def parse_line_span(value: Any) -> LineSpan | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return LineSpan(value, value) if value >= 1 else None
    if isinstance(value, str):
        if NUMERIC_LINE_RE.fullmatch(value):
            line = int(value)
            return LineSpan(line, line)
        match = LINE_RANGE_RE.fullmatch(value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return LineSpan(start, end)
    return None


def format_line_value(start: int, end: int) -> int | str:
    return start if start == end else f"{start}-{end}"


def normalize_line(line: str) -> str:
    return SPACE_RE.sub(" ", line.strip())


def normalize_code_lines(code: Any) -> tuple[str, ...]:
    if not isinstance(code, str):
        return ()
    text = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return tuple(normalize_line(line) for line in lines)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from None
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_no}: row must be a JSON object")
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def read_text_lines(path: Path, max_bytes: int) -> list[str] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size > max_bytes:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def find_matches_in_lines(
    *,
    file_path: str,
    lines: list[str],
    needle: tuple[str, ...],
    start_min: int | None = None,
    start_max: int | None = None,
) -> list[Match]:
    if not needle:
        return []
    needle_len = len(needle)
    if len(lines) < needle_len:
        return []
    normalized_lines = [normalize_line(line) for line in lines]
    first = max(1, start_min or 1)
    last = min(start_max or (len(lines) - needle_len + 1), len(lines) - needle_len + 1)
    matches: list[Match] = []
    for start_line in range(first, last + 1):
        start_index = start_line - 1
        if tuple(normalized_lines[start_index : start_index + needle_len]) == needle:
            matches.append(Match(file=file_path, start=start_line, end=start_line + needle_len - 1))
    return matches


def unique_or_reason(matches: list[Match], scope: str) -> tuple[Match | None, str | None]:
    unique = sorted({(m.file, m.start, m.end) for m in matches})
    if len(unique) == 1:
        file_path, start, end = unique[0]
        return Match(file=file_path, start=start, end=end), None
    if len(unique) > 1:
        return None, f"multiple_matches_in_{scope}:{len(unique)}"
    return None, None


def line_desc_pattern_variants(value: Any) -> list[str]:
    if isinstance(value, int):
        return [str(value)]
    if isinstance(value, str):
        variants = [value]
        if "-" in value:
            variants.append(value.replace("-", "–"))
            variants.append(value.replace("-", "—"))
        return variants
    return []


def maybe_update_desc(
    desc: Any,
    *,
    old_file: str,
    old_line: Any,
    new_file: str,
    new_line: Any,
) -> tuple[Any, str]:
    if not isinstance(desc, str):
        return desc, "missing"

    updated = desc
    old_file_norm = normalize_path(old_file)
    new_file_norm = normalize_path(new_file)
    if old_file_norm and new_file_norm and old_file_norm != new_file_norm:
        updated = updated.replace(old_file_norm, new_file_norm)
        old_base = Path(old_file_norm).name
        new_base = Path(new_file_norm).name
        if old_base and new_base and old_base != new_base:
            updated = updated.replace(old_base, new_base)

    old_line_texts = line_desc_pattern_variants(old_line)
    new_line_text = str(new_line)
    if old_line_texts and str(old_line) != new_line_text:
        for old_line_text in old_line_texts:
            escaped = re.escape(old_line_text)
            updated = re.sub(rf"(第\s*){escaped}(\s*行)", rf"\g<1>{new_line_text}\2", updated)
            updated = re.sub(rf"(?i)\b(line\s*){escaped}\b", rf"\g<1>{new_line_text}", updated)
            updated = re.sub(rf"(?i)\b(lines\s*){escaped}\b", rf"\g<1>{new_line_text}", updated)

    if updated != desc:
        return updated, "updated_by_text_rewrite"
    return desc, "unchanged_needs_review"


class RepoWorkspace:
    def __init__(self, repo_url: str, commit: str, cache_root: Path, args: argparse.Namespace) -> None:
        self.repo_url = normalize_repo_url(repo_url)
        self.commit = commit
        self.cache_root = cache_root
        self.args = args
        self.path = cache_root / repo_cache_name(repo_url)
        self.file_list: list[str] | None = None
        self.lines_cache: dict[str, list[str] | None] = {}

    def ensure(self) -> None:
        self.cache_root.mkdir(parents=True, exist_ok=True)
        if not (self.path / ".git").exists():
            if self.args.offline:
                raise CheckoutError(f"repo_not_cached:{self.repo_url}")
            if self.path.exists():
                shutil.rmtree(self.path)
            clone_url = clone_url_for(self.repo_url, self.args.git_protocol)
            result = run_git(
                ["clone", "--filter=blob:none", "--no-checkout", clone_url, str(self.path)],
                timeout=self.args.git_timeout,
            )
            if result.returncode != 0:
                raise CheckoutError(f"clone_failed:{result.stderr.strip() or result.stdout.strip()}")

        exists = run_git(
            ["cat-file", "-e", f"{self.commit}^{{commit}}"],
            cwd=self.path,
            timeout=30,
            no_lazy_fetch=self.args.offline,
        )
        if exists.returncode != 0:
            if self.args.offline:
                raise CheckoutError(f"commit_not_cached:{self.commit}")
            fetched = run_git(["fetch", "--depth", "1", "origin", self.commit], cwd=self.path, timeout=self.args.git_timeout)
            if fetched.returncode != 0:
                fetched = run_git(["fetch", "origin", self.commit], cwd=self.path, timeout=self.args.git_timeout)
            if fetched.returncode != 0:
                raise CheckoutError(f"fetch_failed:{fetched.stderr.strip() or fetched.stdout.strip()}")

        current = run_git(["rev-parse", "HEAD"], cwd=self.path, timeout=30, no_lazy_fetch=self.args.offline)
        if current.returncode != 0 or current.stdout.strip() != self.commit:
            checked = run_git(
                ["checkout", "--force", self.commit],
                cwd=self.path,
                timeout=self.args.git_timeout,
                no_lazy_fetch=self.args.offline,
            )
            if checked.returncode != 0:
                raise CheckoutError(f"checkout_failed:{checked.stderr.strip() or checked.stdout.strip()}")

    def list_files(self) -> list[str]:
        if self.file_list is None:
            result = run_git(["ls-files", "-z"], cwd=self.path, timeout=60)
            if result.returncode != 0:
                raise CheckoutError(f"ls_files_failed:{result.stderr.strip() or result.stdout.strip()}")
            self.file_list = [
                normalize_path(item)
                for item in result.stdout.split("\0")
                if item and not item.endswith("/")
            ]
        return self.file_list

    def read_lines(self, relative_file: str) -> list[str] | None:
        rel = normalize_path(relative_file)
        if rel not in self.lines_cache:
            full_path = self.path / Path(rel)
            self.lines_cache[rel] = read_text_lines(full_path, self.args.max_file_bytes)
        return self.lines_cache[rel]

    def search_file(
        self,
        relative_file: str,
        needle: tuple[str, ...],
        start_min: int | None = None,
        start_max: int | None = None,
    ) -> list[Match]:
        rel = normalize_path(relative_file)
        lines = self.read_lines(rel)
        if lines is None:
            return []
        return find_matches_in_lines(
            file_path=rel,
            lines=lines,
            needle=needle,
            start_min=start_min,
            start_max=start_max,
        )

    def search_repo(self, needle: tuple[str, ...]) -> list[Match]:
        matches: list[Match] = []
        for rel in self.list_files():
            matches.extend(self.search_file(rel, needle))
            if len({(m.file, m.start, m.end) for m in matches}) > self.args.max_repo_matches:
                break
        return matches


def iter_nodes(entry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(entry.get("entry_point"), dict):
        yield "entry_point", entry["entry_point"]
    if isinstance(entry.get("critical_operation"), dict):
        yield "critical_operation", entry["critical_operation"]
    trace = entry.get("trace", [])
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            if isinstance(node, dict):
                yield f"trace[{index}]", node


def fix_node(
    *,
    workspace: RepoWorkspace,
    entry: dict[str, Any],
    field_path: str,
    node: dict[str, Any],
    diff_rows: list[dict[str, Any]],
    human_rows: list[dict[str, Any]],
    args: argparse.Namespace,
) -> str:
    old_file = normalize_path(node.get("file"))
    old_line = node.get("line")
    old_desc = node.get("desc", "")
    line_span = parse_line_span(old_line)
    needle = normalize_code_lines(node.get("code"))

    if not old_file or line_span is None:
        human_rows.append(make_human_row(entry, field_path, node, "invalid_file_or_line", ""))
        return "human"
    if not needle:
        human_rows.append(make_human_row(entry, field_path, node, "empty_or_invalid_code", ""))
        return "human"

    current_matches = workspace.search_file(old_file, needle, start_min=line_span.start, start_max=line_span.start)
    current_match, _ = unique_or_reason(current_matches, "current_line")
    if current_match is not None:
        new_line = current_match.line_value
        if normalize_path(current_match.file) == old_file and new_line == old_line:
            return "ok"
        apply_match(
            node=node,
            entry=entry,
            field_path=field_path,
            old_file=old_file,
            old_line=old_line,
            old_desc=old_desc,
            match=current_match,
            strategy="current_start_span_repair",
            diff_rows=diff_rows,
        )
        return "fixed"

    nearby = workspace.search_file(
        old_file,
        needle,
        start_min=line_span.start - args.nearby_lines,
        start_max=line_span.start + args.nearby_lines,
    )
    nearby_match, nearby_reason = unique_or_reason(nearby, "nearby")
    if nearby_match is not None:
        apply_match(
            node=node,
            entry=entry,
            field_path=field_path,
            old_file=old_file,
            old_line=old_line,
            old_desc=old_desc,
            match=nearby_match,
            strategy=f"nearby_plus_minus_{args.nearby_lines}",
            diff_rows=diff_rows,
        )
        return "fixed"
    if nearby_reason:
        human_rows.append(make_human_row(entry, field_path, node, nearby_reason, match_preview(nearby)))
        return "human"

    file_matches = workspace.search_file(old_file, needle)
    file_match, file_reason = unique_or_reason(file_matches, "file")
    if file_match is not None:
        apply_match(
            node=node,
            entry=entry,
            field_path=field_path,
            old_file=old_file,
            old_line=old_line,
            old_desc=old_desc,
            match=file_match,
            strategy="same_file_unique",
            diff_rows=diff_rows,
        )
        return "fixed"
    if file_reason:
        human_rows.append(make_human_row(entry, field_path, node, file_reason, match_preview(file_matches)))
        return "human"

    repo_matches = workspace.search_repo(needle)
    repo_match, repo_reason = unique_or_reason(repo_matches, "repo")
    if repo_match is not None:
        apply_match(
            node=node,
            entry=entry,
            field_path=field_path,
            old_file=old_file,
            old_line=old_line,
            old_desc=old_desc,
            match=repo_match,
            strategy="repo_unique",
            diff_rows=diff_rows,
        )
        return "fixed"

    human_rows.append(
        make_human_row(
            entry,
            field_path,
            node,
            repo_reason or "not_found",
            match_preview(repo_matches),
        )
    )
    return "human"


def match_preview(matches: list[Match], limit: int = 10) -> str:
    unique = sorted({(m.file, m.start, m.end) for m in matches})
    rendered = [f"{file}:{start}-{end}" for file, start, end in unique[:limit]]
    if len(unique) > limit:
        rendered.append(f"...(+{len(unique) - limit})")
    return "; ".join(rendered)


def make_human_row(entry: dict[str, Any], field_path: str, node: dict[str, Any], reason: str, details: str) -> dict[str, Any]:
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
        "reason": reason,
        "details": details,
    }


def apply_match(
    *,
    node: dict[str, Any],
    entry: dict[str, Any],
    field_path: str,
    old_file: str,
    old_line: Any,
    old_desc: Any,
    match: Match,
    strategy: str,
    diff_rows: list[dict[str, Any]],
) -> None:
    new_file = match.file
    new_line = match.line_value
    new_desc, desc_status = maybe_update_desc(
        old_desc,
        old_file=old_file,
        old_line=old_line,
        new_file=new_file,
        new_line=new_line,
    )
    node["file"] = new_file
    node["line"] = new_line
    if isinstance(old_desc, str):
        node["desc"] = new_desc
    diff_rows.append(
        {
            "entry_id": entry.get("entry_id", ""),
            "verify": entry.get("verify", ""),
            "repo_url": entry.get("repo_url", ""),
            "commit": entry.get("commit", ""),
            "field_path": field_path,
            "old_file": old_file,
            "old_line": old_line,
            "old_desc": old_desc,
            "new_file": new_file,
            "new_line": new_line,
            "new_desc": new_desc,
            "strategy": strategy,
            "desc_status": desc_status,
            "evidence": f"{new_file}:{match.start}-{match.end}",
        }
    )


def selected(entry: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.verify != "all" and str(entry.get("verify")) != args.verify:
        return False
    if args.entry_id and entry.get("entry_id") not in args.entry_id:
        return False
    return True


def validate_node(node: Any, path: str) -> list[str]:
    if not isinstance(node, dict):
        return [f"{path}: must be object"]
    errors: list[str] = []
    missing = REQUIRED_NODE_FIELDS - set(node)
    if missing:
        errors.append(f"{path}: missing fields {sorted(missing)}")
    if "line" in node and parse_line_span(node.get("line")) is None:
        errors.append(f"{path}.line invalid: {node.get('line')!r}")
    return errors


def validate_entries(rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for row_index, entry in enumerate(rows, 1):
        entry_id = entry.get("entry_id", f"row-{row_index}")
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        if missing:
            errors.append(f"{entry_id}: missing top-level fields {sorted(missing)}")
        if entry.get("verify") not in {0, 1}:
            errors.append(f"{entry_id}: verify must be 0 or 1")
        errors.extend(f"{entry_id}: {err}" for err in validate_node(entry.get("entry_point"), "entry_point"))
        errors.extend(
            f"{entry_id}: {err}"
            for err in validate_node(entry.get("critical_operation"), "critical_operation")
        )
        trace = entry.get("trace")
        if not isinstance(trace, list):
            errors.append(f"{entry_id}: trace must be list")
        else:
            for index, node in enumerate(trace):
                errors.extend(f"{entry_id}: {err}" for err in validate_node(node, f"trace[{index}]"))
    return errors


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Repair VulnGym node file/line locations from code snippets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--entries", type=Path, default=DEFAULT_ENTRIES)
    parser.add_argument("--repo-cache", type=Path, default=DEFAULT_REPO_CACHE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--diff-out", type=Path, default=DEFAULT_DIFF)
    parser.add_argument("--needs-human-out", type=Path, default=DEFAULT_NEEDS_HUMAN)
    parser.add_argument("--verify", choices=("0", "1", "all"), default="0")
    parser.add_argument("--entry-id", action="append", default=[])
    parser.add_argument("--nearby-lines", type=int, default=5)
    parser.add_argument("--max-file-bytes", type=int, default=3_000_000)
    parser.add_argument("--max-repo-matches", type=int, default=100)
    parser.add_argument("--git-timeout", type=int, default=600)
    parser.add_argument("--git-protocol", choices=("https", "ssh"), default="https")
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.nearby_lines < 0:
        raise SystemExit("--nearby-lines must be >= 0")

    rows = read_jsonl(args.entries)
    fixed_rows = json.loads(json.dumps(rows, ensure_ascii=False))
    diff_rows: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()

    selected_indexes = [index for index, entry in enumerate(fixed_rows) if selected(entry, args)]
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index in selected_indexes:
        entry = fixed_rows[index]
        groups[(entry.get("repo_url", ""), entry.get("commit", ""))].append(index)

    print(f"selected entries: {len(selected_indexes)}", flush=True)
    print(f"repo/commit groups: {len(groups)}", flush=True)

    for group_no, ((repo_url, commit), indexes) in enumerate(groups.items(), 1):
        print(f"[{group_no}/{len(groups)}] {repo_url} @ {str(commit)[:12]} ({len(indexes)} entries)", flush=True)
        workspace = RepoWorkspace(str(repo_url), str(commit), args.repo_cache, args)
        try:
            workspace.ensure()
        except (CheckoutError, subprocess.TimeoutExpired) as exc:
            reason = f"checkout_failed:{exc}"
            print(f"  {reason}", flush=True)
            for index in indexes:
                entry = fixed_rows[index]
                for field_path, node in iter_nodes(entry):
                    human_rows.append(make_human_row(entry, field_path, node, reason, ""))
                    stats["human"] += 1
            continue

        for index in indexes:
            entry = fixed_rows[index]
            for field_path, node in iter_nodes(entry):
                result = fix_node(
                    workspace=workspace,
                    entry=entry,
                    field_path=field_path,
                    node=node,
                    diff_rows=diff_rows,
                    human_rows=human_rows,
                    args=args,
                )
                stats[result] += 1

    validation_errors = validate_entries(fixed_rows)
    if validation_errors:
        for error in validation_errors[:20]:
            print(f"schema error: {error}", file=sys.stderr)
        print(f"schema validation errors: {len(validation_errors)}", file=sys.stderr)

    write_jsonl(args.output, fixed_rows)
    write_csv(
        args.diff_out,
        diff_rows,
        [
            "entry_id",
            "verify",
            "repo_url",
            "commit",
            "field_path",
            "old_file",
            "old_line",
            "old_desc",
            "new_file",
            "new_line",
            "new_desc",
            "strategy",
            "desc_status",
            "evidence",
        ],
    )
    write_csv(
        args.needs_human_out,
        human_rows,
        [
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
        ],
    )

    print("summary", flush=True)
    print("-------", flush=True)
    print(f"ok nodes: {stats['ok']}", flush=True)
    print(f"fixed nodes: {stats['fixed']}", flush=True)
    print(f"human nodes: {stats['human']}", flush=True)
    print(f"schema errors: {len(validation_errors)}", flush=True)
    print(f"wrote fixed jsonl: {args.output}", flush=True)
    print(f"wrote diff csv: {args.diff_out}", flush=True)
    print(f"wrote needs-human csv: {args.needs_human_out}", flush=True)

    return 1 if validation_errors else 0


if __name__ == "__main__":
    sys.exit(main())
