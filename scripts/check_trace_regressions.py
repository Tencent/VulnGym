#!/usr/bin/env python3
"""Fail only on trace-structure findings introduced by a candidate dataset.

The current VulnGym dataset contains legacy trace findings that need human
review. A full-dataset linter would therefore be unsuitable as a CI gate.
This tool compares a baseline JSONL file with a candidate JSONL file and
returns a failure only when the candidate introduces new findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
FINDING_KINDS = ("duplicate", "before_entry", "after_critical")


class TraceDataError(ValueError):
    """Raised when an input cannot be compared safely."""


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    entry_id: str
    kind: str
    file: str
    line: int | str
    trace_index: int
    occurrence: int
    code_sha256: str
    code_preview: str
    detail: str


@dataclass
class ScanResult:
    source_sha256: str
    entry_count: int
    trace_node_count: int
    skipped_cross_file_comparisons: int
    findings: list[Finding]

    def kind_counts(self) -> dict[str, int]:
        counts = {kind: 0 for kind in FINDING_KINDS}
        for finding in self.findings:
            counts[finding.kind] += 1
        return counts


@dataclass
class Comparison:
    baseline: ScanResult
    candidate: ScanResult
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    unchanged_finding_count: int


def parse_line_span(value: object, context: str) -> tuple[int, int]:
    if isinstance(value, bool):
        raise TraceDataError(f"{context}: line must not be a boolean")
    if isinstance(value, int):
        if value < 1:
            raise TraceDataError(f"{context}: line must be >= 1")
        return value, value
    if isinstance(value, str):
        parts = value.split("-")
        if len(parts) != 2 or not all(part.isdigit() for part in parts):
            raise TraceDataError(
                f'{context}: line range must use the "start-end" form'
            )
        start, end = (int(part) for part in parts)
        if start < 1 or end < start:
            raise TraceDataError(
                f"{context}: line range must satisfy 1 <= start <= end"
            )
        return start, end
    raise TraceDataError(f"{context}: line must be an integer or range string")


def load_jsonl_text(text: str, source: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise TraceDataError(
                f"{source}:{line_number}: invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(entry, dict):
            raise TraceDataError(f"{source}:{line_number}: entry must be an object")
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or not entry_id:
            raise TraceDataError(
                f"{source}:{line_number}: entry_id must be a non-empty string"
            )
        if entry_id in seen_ids:
            raise TraceDataError(f"{source}:{line_number}: duplicate entry_id {entry_id}")
        seen_ids.add(entry_id)
        entries.append(entry)
    return entries


def _require_node(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TraceDataError(f"{context}: node must be an object")
    for field in ("file", "line", "code"):
        if field not in value:
            raise TraceDataError(f"{context}: missing required field {field}")
    if not isinstance(value["file"], str) or not value["file"]:
        raise TraceDataError(f"{context}: file must be a non-empty string")
    if not isinstance(value["code"], str):
        raise TraceDataError(f"{context}: code must be a string")
    parse_line_span(value["line"], context)
    return value


def _line_token(value: int | str) -> str:
    # Preserve the issue's exact {file, line, code} duplicate definition.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _node_key(node: dict[str, Any]) -> tuple[str, str, str]:
    return node["file"], _line_token(node["line"]), node["code"]


def _finding_fingerprint(
    entry_id: str,
    kind: str,
    node: dict[str, Any],
    occurrence: int,
) -> str:
    payload = {
        "entry_id": entry_id,
        "kind": kind,
        "file": node["file"],
        "line": node["line"],
        "code": node["code"],
        "occurrence": occurrence,
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _code_preview(code: str, limit: int = 96) -> str:
    compact = " ".join(code.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _make_finding(
    entry_id: str,
    kind: str,
    node: dict[str, Any],
    trace_index: int,
    occurrence: int,
    detail: str,
) -> Finding:
    code = node["code"]
    return Finding(
        fingerprint=_finding_fingerprint(entry_id, kind, node, occurrence),
        entry_id=entry_id,
        kind=kind,
        file=node["file"],
        line=node["line"],
        trace_index=trace_index,
        occurrence=occurrence,
        code_sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
        code_preview=_code_preview(code),
        detail=detail,
    )


def scan_entries(entries: Iterable[dict[str, Any]], source_text: str) -> ScanResult:
    findings: list[Finding] = []
    entry_count = 0
    trace_node_count = 0
    skipped_cross_file = 0

    for entry in entries:
        entry_count += 1
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str) or not entry_id:
            raise TraceDataError("entry_id must be a non-empty string")

        entry_point = _require_node(entry.get("entry_point"), f"{entry_id}.entry_point")
        critical = _require_node(
            entry.get("critical_operation"), f"{entry_id}.critical_operation"
        )
        trace = entry.get("trace")
        if not isinstance(trace, list):
            raise TraceDataError(f"{entry_id}.trace: must be an array")

        entry_start, _ = parse_line_span(
            entry_point["line"], f"{entry_id}.entry_point"
        )
        _, critical_end = parse_line_span(
            critical["line"], f"{entry_id}.critical_operation"
        )

        first_duplicate_index: dict[tuple[str, str, str], int] = {}
        duplicate_counts: defaultdict[tuple[str, str, str], int] = defaultdict(int)
        order_counts: defaultdict[tuple[str, tuple[str, str, str]], int] = defaultdict(int)

        for trace_index, raw_node in enumerate(trace):
            context = f"{entry_id}.trace[{trace_index}]"
            node = _require_node(raw_node, context)
            trace_node_count += 1
            node_start, node_end = parse_line_span(node["line"], context)
            key = _node_key(node)

            if key in first_duplicate_index:
                duplicate_counts[key] += 1
                first_index = first_duplicate_index[key]
                findings.append(
                    _make_finding(
                        entry_id,
                        "duplicate",
                        node,
                        trace_index,
                        duplicate_counts[key],
                        f"duplicates trace[{first_index}]",
                    )
                )
            else:
                first_duplicate_index[key] = trace_index

            if node["file"] == entry_point["file"]:
                if node_end < entry_start:
                    count_key = ("before_entry", key)
                    order_counts[count_key] += 1
                    findings.append(
                        _make_finding(
                            entry_id,
                            "before_entry",
                            node,
                            trace_index,
                            order_counts[count_key],
                            f"node span {node_start}-{node_end} is before "
                            f"entry start {entry_start}",
                        )
                    )
            else:
                skipped_cross_file += 1

            if node["file"] == critical["file"]:
                if node_start > critical_end:
                    count_key = ("after_critical", key)
                    order_counts[count_key] += 1
                    findings.append(
                        _make_finding(
                            entry_id,
                            "after_critical",
                            node,
                            trace_index,
                            order_counts[count_key],
                            f"node span {node_start}-{node_end} is after "
                            f"critical end {critical_end}",
                        )
                    )
            else:
                skipped_cross_file += 1

    findings.sort(key=lambda finding: (finding.entry_id, finding.kind, finding.fingerprint))
    return ScanResult(
        source_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        entry_count=entry_count,
        trace_node_count=trace_node_count,
        skipped_cross_file_comparisons=skipped_cross_file,
        findings=findings,
    )


def compare_scans(baseline: ScanResult, candidate: ScanResult) -> Comparison:
    baseline_by_id = {finding.fingerprint: finding for finding in baseline.findings}
    candidate_by_id = {finding.fingerprint: finding for finding in candidate.findings}
    new_ids = sorted(candidate_by_id.keys() - baseline_by_id.keys())
    resolved_ids = sorted(baseline_by_id.keys() - candidate_by_id.keys())
    return Comparison(
        baseline=baseline,
        candidate=candidate,
        new_findings=[candidate_by_id[fingerprint] for fingerprint in new_ids],
        resolved_findings=[baseline_by_id[fingerprint] for fingerprint in resolved_ids],
        unchanged_finding_count=len(baseline_by_id.keys() & candidate_by_id.keys()),
    )


def compare_jsonl_texts(
    baseline_text: str,
    candidate_text: str,
    baseline_source: str = "baseline",
    candidate_source: str = "candidate",
) -> Comparison:
    baseline_entries = load_jsonl_text(baseline_text, baseline_source)
    candidate_entries = load_jsonl_text(candidate_text, candidate_source)
    return compare_scans(
        scan_entries(baseline_entries, baseline_text),
        scan_entries(candidate_entries, candidate_text),
    )


def _scan_summary(scan: ScanResult) -> dict[str, Any]:
    return {
        "source_sha256": scan.source_sha256,
        "entries": scan.entry_count,
        "trace_nodes": scan.trace_node_count,
        "skipped_cross_file_comparisons": scan.skipped_cross_file_comparisons,
        "finding_count": len(scan.findings),
        "findings_by_kind": scan.kind_counts(),
    }


def comparison_to_dict(comparison: Comparison) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "baseline": _scan_summary(comparison.baseline),
        "candidate": _scan_summary(comparison.candidate),
        "comparison": {
            "result": "fail" if comparison.new_findings else "pass",
            "new_finding_count": len(comparison.new_findings),
            "resolved_finding_count": len(comparison.resolved_findings),
            "unchanged_finding_count": comparison.unchanged_finding_count,
            "new_findings": [asdict(finding) for finding in comparison.new_findings],
            "resolved_findings": [
                asdict(finding) for finding in comparison.resolved_findings
            ],
        },
    }


def render_markdown(comparison: Comparison) -> str:
    result = "FAIL" if comparison.new_findings else "PASS"
    lines = [
        "# Trace Structure Regression Report",
        "",
        f"- Result: **{result}**",
        f"- Baseline findings: {len(comparison.baseline.findings)}",
        f"- Candidate findings: {len(comparison.candidate.findings)}",
        f"- New findings: {len(comparison.new_findings)}",
        f"- Resolved findings: {len(comparison.resolved_findings)}",
        f"- Unchanged legacy findings: {comparison.unchanged_finding_count}",
        "",
        "## New Findings",
        "",
    ]
    if not comparison.new_findings:
        lines.append("No new trace-structure findings were introduced.")
    else:
        lines.extend(
            [
                "| Entry | Kind | Location | Trace index | Detail |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for finding in comparison.new_findings:
            location = f"{finding.file}:{finding.line}"
            detail = finding.detail.replace("|", "\\|")
            lines.append(
                f"| {finding.entry_id} | {finding.kind} | {location} | "
                f"{finding.trace_index} | {detail} |"
            )
    lines.extend(
        [
            "",
            "## Input Fingerprints",
            "",
            f"- Baseline SHA-256: `{comparison.baseline.source_sha256}`",
            f"- Candidate SHA-256: `{comparison.candidate.source_sha256}`",
            "",
        ]
    )
    return "\n".join(lines)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _read_utf8_file(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TraceDataError(f"{path}: input is not valid UTF-8") from exc


def _read_git_blob(ref: str, git_path: str) -> str:
    normalized_path = git_path.replace("\\", "/")
    result = subprocess.run(
        ["git", "show", f"{ref}:{normalized_path}"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        message = message or "git show failed"
        raise TraceDataError(f"cannot read {normalized_path} from {ref}: {message}")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TraceDataError(
            f"{ref}:{normalized_path}: input is not valid UTF-8"
        ) from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail only on trace-structure findings introduced by a candidate JSONL."
    )
    baseline = parser.add_mutually_exclusive_group(required=True)
    baseline.add_argument("--baseline", type=Path, help="baseline entries JSONL")
    baseline.add_argument("--base-ref", help="git ref containing the baseline JSONL")
    parser.add_argument(
        "--baseline-git-path",
        default="data/entries.jsonl",
        help="path to entries JSONL inside --base-ref",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        default=Path("data/entries.jsonl"),
        help="candidate entries JSONL (default: data/entries.jsonl)",
    )
    parser.add_argument("--json-report", type=Path, help="write a deterministic JSON report")
    parser.add_argument(
        "--markdown-report", type=Path, help="write a human-readable Markdown report"
    )
    parser.add_argument(
        "--max-details",
        type=int,
        default=20,
        help="maximum new findings printed to stdout",
    )
    return parser


def _print_summary(comparison: Comparison, max_details: int) -> None:
    baseline = comparison.baseline
    candidate = comparison.candidate
    print("== trace structure regression gate ==")
    print(
        "baseline: "
        f"entries={baseline.entry_count}, trace_nodes={baseline.trace_node_count}, "
        f"findings={len(baseline.findings)}"
    )
    print(
        "candidate: "
        f"entries={candidate.entry_count}, trace_nodes={candidate.trace_node_count}, "
        f"findings={len(candidate.findings)}"
    )
    print(
        "comparison: "
        f"new={len(comparison.new_findings)}, "
        f"resolved={len(comparison.resolved_findings)}, "
        f"unchanged={comparison.unchanged_finding_count}"
    )
    for finding in comparison.new_findings[: max(0, max_details)]:
        print(
            f"NEW {finding.entry_id} {finding.kind} "
            f"{finding.file}:{finding.line} trace[{finding.trace_index}]"
        )
    hidden = len(comparison.new_findings) - max(0, max_details)
    if hidden > 0:
        print(f"... {hidden} additional new findings omitted")
    print("result: " + ("FAIL" if comparison.new_findings else "PASS"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        candidate_text = _read_utf8_file(args.candidate)
        if args.baseline is not None:
            baseline_text = _read_utf8_file(args.baseline)
            baseline_source = str(args.baseline)
        else:
            baseline_text = _read_git_blob(args.base_ref, args.baseline_git_path)
            baseline_source = f"{args.base_ref}:{args.baseline_git_path}"

        comparison = compare_jsonl_texts(
            baseline_text,
            candidate_text,
            baseline_source=baseline_source,
            candidate_source=str(args.candidate),
        )
        if args.json_report:
            payload = json.dumps(
                comparison_to_dict(comparison),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            _write_text(args.json_report, payload + "\n")
        if args.markdown_report:
            _write_text(args.markdown_report, render_markdown(comparison))
        _print_summary(comparison, args.max_details)
        return 1 if comparison.new_findings else 0
    except (OSError, TraceDataError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
