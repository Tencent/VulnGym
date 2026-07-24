#!/usr/bin/env python3
"""Validate rebuilt issue #7 entries and optionally match code against GitHub raw sources."""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATCH = ROOT / "data" / "entries.rebuilt_chains.jsonl"
DEFAULT_MANUAL_REVIEW = ROOT / "reports" / "rebuild_manual_review.csv"
UPSTREAM_FIX_COMMITS = {
    "entry-00197": "c823a85302119044bc26763644c15fe35dd04f4a",
    "entry-00290": "4fd29a35bb85a1898ebff518364c467058b50e14",
    "entry-00391": "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71",
}
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
CORRUPTION_MARKERS = (
    "\ufffd",
    "锟斤拷",
    "娉ㄥ",
    "閰嶇",
    "瑙﹀",
    "缂哄",
    "璺",
    "瀵艰",
)


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


def read_manual_review_ids(path: Path) -> set[str]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {
            str(row.get("entry_id", "")).strip()
            for row in csv.DictReader(handle)
            if str(row.get("entry_id", "")).strip()
        }


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
        errors.extend(validate_text_integrity(entry_id, entry))
        for node_path, node in iter_nodes(entry):
            errors.extend(validate_node(entry_id, node_path, node))
    missing_targets = sorted(TARGET_IDS - seen)
    if missing_targets:
        errors.append(f"missing issue #7 target entries: {', '.join(missing_targets)}")
    return errors


def find_node(
    entry: dict[str, Any],
    file_path: str,
    line: str,
    code_fragment: str = "",
) -> bool:
    return any(
        str(node.get("file", "")) == file_path
        and str(node.get("line", "")) == line
        and code_fragment in str(node.get("code", ""))
        for _, node in iter_nodes(entry)
    )


def validate_target_semantics(
    entries: list[dict[str, Any]],
    manual_review_ids: set[str],
) -> list[str]:
    errors: list[str] = []
    by_id = {str(entry.get("entry_id", "")): entry for entry in entries}

    media_entry = by_id.get("entry-00197", {})
    media_expectations = (
        ("src/infra/outbound/message-action-params.ts", "288", "readStringParam"),
        ("src/infra/outbound/message-action-params.ts", "296", "resolveSandboxedMediaSource"),
        ("src/infra/outbound/message-action-params.ts", "215-216", "sandboxValidated: true"),
        ("src/web/media.ts", "353-355", "sandboxValidated || localRoots"),
        ("src/web/media.ts", "360", "readFileOverride"),
    )
    for file_path, line, fragment in media_expectations:
        if not find_node(media_entry, file_path, line, fragment):
            errors.append(f"entry-00197: missing TOCTOU semantic anchor {file_path}:{line}")

    patch_entry = by_id.get("entry-00290", {})
    if patch_entry.get("verify") != 0:
        errors.append("entry-00290: verify must remain 0 until the vulnerable revision is proven")
    if "entry-00290" not in manual_review_ids:
        errors.append("entry-00290: unresolved provenance must be listed in manual review")
    if not find_node(
        patch_entry,
        "src/infra/boundary-path.ts",
        "196-197",
        "resolveSymlinkHopPath",
    ):
        errors.append("entry-00290: missing recorded fail-closed guard evidence")

    fastmcp_entry = by_id.get("entry-00391", {})
    critical = fastmcp_entry.get("critical_operation", {})
    if (
        str(critical.get("file", "")) != "src/fastmcp/utilities/openapi/director.py"
        or str(critical.get("line", "")) != "208-213"
        or "replace(placeholder, str(param_value))" not in str(critical.get("code", ""))
    ):
        errors.append("entry-00391: critical operation must isolate raw path-parameter substitution")

    return errors


def iter_text_values(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "code":
                continue
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_text_values(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_text_values(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def validate_text_integrity(entry_id: str, entry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for path, value in iter_text_values(entry):
        if re.search(r"\?{4,}", value):
            errors.append(f"{entry_id} {path}: suspicious replacement question marks")
        marker = next((marker for marker in CORRUPTION_MARKERS if marker in value), None)
        if marker is not None:
            errors.append(f"{entry_id} {path}: suspicious mojibake marker {marker!r}")
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


def commit_api_url(repo_url: str, commit: str) -> str:
    parsed = urlparse(repo_url.removesuffix(".git"))
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError(f"unsupported repo_url: {repo_url}")
    return f"https://api.github.com/repos/{parts[0]}/{parts[1]}/commits/{commit}"


def fetch_bytes(request: urllib.request.Request, timeout: int, attempts: int = 3) -> bytes:
    last_error: OSError | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError:
            raise
        except OSError as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.5 * (2**attempt))
    assert last_error is not None
    raise last_error


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "VulnGym-rebuild-verifier"})
    return fetch_bytes(request, timeout).decode("utf-8", errors="replace")


def fetch_json(url: str, timeout: int) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VulnGym-rebuild-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    payload = json.loads(fetch_bytes(request, timeout).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected JSON payload from {url}")
    return payload


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


def validate_upstream_evidence(
    entries: list[dict[str, Any]],
    payloads: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    by_id = {str(entry.get("entry_id", "")): entry for entry in entries}

    for entry_id, fix_commit in UPSTREAM_FIX_COMMITS.items():
        entry = by_id.get(entry_id)
        payload = payloads.get(entry_id)
        if entry is None or payload is None:
            errors.append(f"{entry_id}: missing upstream fix evidence for {fix_commit}")
            continue
        parents = payload.get("parents", [])
        parent_sha = parents[0].get("sha") if parents and isinstance(parents[0], dict) else ""
        if parent_sha != entry.get("commit"):
            errors.append(
                f"{entry_id}: fix parent {parent_sha or '<missing>'} "
                f"does not match recorded commit {entry.get('commit')}"
            )

    if "entry-00197" in payloads:
        media_files = {
            str(item.get("filename", "")): str(item.get("patch", ""))
            for item in payloads["entry-00197"].get("files", [])
            if isinstance(item, dict)
        }
        media_patch = "\n".join(media_files.values())
        for anchor in (
            "createRootScopedReadFile",
            "normalizeSandboxMediaParams",
            "hydrateAttachmentParamsForAction",
        ):
            if anchor not in media_patch:
                errors.append(f"entry-00197: fix patch is missing evidence anchor {anchor}")

    if "entry-00290" in payloads:
        patch_files = [
            str(item.get("filename", ""))
            for item in payloads["entry-00290"].get("files", [])
            if isinstance(item, dict)
        ]
        if not patch_files or any(not filename.endswith(".test.ts") for filename in patch_files):
            errors.append("entry-00290: advisory fix is expected to contain test-only changes")
        if by_id.get("entry-00290", {}).get("verify") != 0:
            errors.append("entry-00290: test-only advisory fix requires verify=0")

    if "entry-00391" in payloads:
        fastmcp_patch = "\n".join(
            str(item.get("patch", ""))
            for item in payloads["entry-00391"].get("files", [])
            if isinstance(item, dict)
            and str(item.get("filename", "")).endswith("utilities/openapi/director.py")
        )
        for anchor in (
            "from urllib.parse import quote",
            "safe_value",
            "replace(placeholder, safe_value)",
        ):
            if anchor not in fastmcp_patch:
                errors.append(f"entry-00391: fix patch is missing evidence anchor {anchor}")

    return errors


def audit_upstream_evidence(entries: list[dict[str, Any]], timeout: int) -> list[str]:
    failures: list[str] = []
    by_id = {str(entry.get("entry_id", "")): entry for entry in entries}
    payloads: dict[str, dict[str, Any]] = {}
    for entry_id, fix_commit in UPSTREAM_FIX_COMMITS.items():
        entry = by_id.get(entry_id)
        if entry is None:
            failures.append(f"{entry_id}: target entry is missing")
            continue
        try:
            payloads[entry_id] = fetch_json(
                commit_api_url(str(entry.get("repo_url", "")), fix_commit),
                timeout,
            )
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
            failures.append(f"{entry_id}: failed to fetch fix commit {fix_commit}: {exc}")
    failures.extend(validate_upstream_evidence(entries, payloads))
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--manual-review", type=Path, default=DEFAULT_MANUAL_REVIEW)
    parser.add_argument("--use-remote", action="store_true", help="fetch GitHub raw files and compare each node's code")
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="validate recorded commits against the advisory fix commits",
    )
    parser.add_argument("--timeout", type=int, default=30)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    entries = read_jsonl(args.patch)
    schema_errors = validate_entries(entries)
    semantic_errors = validate_target_semantics(entries, read_manual_review_ids(args.manual_review))
    remote_errors = audit_remote(entries, args.timeout) if args.use_remote else []
    upstream_errors = audit_upstream_evidence(entries, args.timeout) if args.check_upstream else []
    print(f"entries: {len(entries)}")
    print(f"nodes: {sum(2 + len(entry.get('trace', [])) for entry in entries)}")
    print(f"schema errors: {len(schema_errors)}")
    print(f"semantic errors: {len(semantic_errors)}")
    print(f"remote match errors: {len(remote_errors)}")
    print(f"upstream evidence errors: {len(upstream_errors)}")
    for error in schema_errors[:20] + semantic_errors[:20] + remote_errors[:20] + upstream_errors[:20]:
        print(f"- {error}")
    return 1 if schema_errors or semantic_errors or remote_errors or upstream_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
