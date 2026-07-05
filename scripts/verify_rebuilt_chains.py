#!/usr/bin/env python3
"""Validate rebuilt issue #7 entries and optionally match code against GitHub raw sources."""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATCH = ROOT / "data" / "entries.rebuilt_chains.jsonl"
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
REQUIRED_NODE_FIELDS = {"file", "line", "code", "desc"}
TARGET_IDS = {"entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391"}


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from None
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_no}: row must be an object")
            rows.append(row)
    return rows


def parse_line_span(value: Any) -> LineSpan | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return LineSpan(value, value) if value >= 1 else None
    if isinstance(value, str):
        if value.isdigit():
            number = int(value)
            return LineSpan(number, number) if number >= 1 else None
        match = re.fullmatch(r"([1-9]\d*)-([1-9]\d*)", value)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end:
                return LineSpan(start, end)
    return None


def iter_nodes(entry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("entry_point", "critical_operation"):
        node = entry.get(key)
        if isinstance(node, dict):
            yield key, node
    trace = entry.get("trace")
    if isinstance(trace, list):
        for index, node in enumerate(trace):
            if isinstance(node, dict):
                yield f"trace[{index}]", node


def validate_entries(entries: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen = set()
    for row_index, entry in enumerate(entries, 1):
        entry_id = str(entry.get("entry_id", f"row-{row_index}"))
        seen.add(entry_id)
        missing = sorted(REQUIRED_ENTRY_FIELDS - set(entry))
        if missing:
            errors.append(f"{entry_id}: missing entry fields {missing}")
        if entry.get("verify") not in (0, 1):
            errors.append(f"{entry_id}: verify must be 0 or 1")
        if not isinstance(entry.get("trace"), list):
            errors.append(f"{entry_id}: trace must be a list")
        for node_path, node in iter_nodes(entry):
            errors.extend(validate_node(entry_id, node_path, node))
    missing_targets = sorted(TARGET_IDS - seen)
    if missing_targets:
        errors.append(f"missing issue #7 target entries: {', '.join(missing_targets)}")
    return errors


def validate_node(entry_id: str, node_path: str, node: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_NODE_FIELDS - set(node))
    if missing:
        errors.append(f"{entry_id} {node_path}: missing node fields {missing}")
    if parse_line_span(node.get("line")) is None:
        errors.append(f"{entry_id} {node_path}: invalid line {node.get('line')!r}")
    if not str(node.get("file", "")).strip():
        errors.append(f"{entry_id} {node_path}: empty file")
    if not str(node.get("code", "")).strip():
        errors.append(f"{entry_id} {node_path}: empty code")
    if not str(node.get("desc", "")).strip():
        errors.append(f"{entry_id} {node_path}: empty desc")
    return errors


def normalize_code(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    lines = value.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(line.rstrip() for line in lines)


def source_slice(source: str, span: LineSpan) -> str:
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(lines[span.start - 1 : span.end])


def raw_url(repo_url: str, commit: str, file_path: str) -> str:
    parsed = urlparse(repo_url.removesuffix(".git"))
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError(f"unsupported repo_url: {repo_url}")
    owner, repo = parts[0], parts[1]
    quoted_file = quote(file_path.replace("\\", "/"))
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{quoted_file}"


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "VulnGym-rebuild-verifier"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def audit_remote(entries: list[dict[str, Any]], timeout: int) -> list[str]:
    failures: list[str] = []
    cache: dict[tuple[str, str, str], str] = {}
    for entry in entries:
        entry_id = str(entry.get("entry_id", ""))
        repo_url = str(entry.get("repo_url", ""))
        commit = str(entry.get("commit", ""))
        for node_path, node in iter_nodes(entry):
            span = parse_line_span(node.get("line"))
            if span is None:
                failures.append(f"{entry_id} {node_path}: invalid line")
                continue
            file_path = str(node.get("file", ""))
            key = (repo_url, commit, file_path)
            try:
                if key not in cache:
                    cache[key] = fetch_text(raw_url(repo_url, commit, file_path), timeout)
                actual = source_slice(cache[key], span)
            except (OSError, ValueError, urllib.error.URLError) as exc:
                failures.append(f"{entry_id} {node_path}: fetch failed for {file_path}: {exc}")
                continue
            expected = str(node.get("code", ""))
            if normalize_code(actual) != normalize_code(expected):
                failures.append(f"{entry_id} {node_path}: code mismatch at {file_path}:{node.get('line')}")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--use-remote", action="store_true", help="fetch GitHub raw files and compare each node's code")
    parser.add_argument("--timeout", type=int, default=30)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    entries = read_jsonl(args.patch)
    schema_errors = validate_entries(entries)
    remote_errors = audit_remote(entries, args.timeout) if args.use_remote else []
    print(f"entries: {len(entries)}")
    print(f"nodes: {sum(2 + len(entry.get('trace', [])) for entry in entries)}")
    print(f"schema errors: {len(schema_errors)}")
    print(f"remote match errors: {len(remote_errors)}")
    for error in schema_errors[:20] + remote_errors[:20]:
        print(f"- {error}")
    return 1 if schema_errors or remote_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
