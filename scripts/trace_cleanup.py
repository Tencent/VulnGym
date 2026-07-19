"""Detect and conservatively repair structural findings in VulnGym traces.

Source order is not execution order.  This tool reports exact duplicate trace
nodes and same-file boundary findings, but only removes a node when the chosen
policy and the entry's review state make that decision safe and auditable.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "entries.jsonl"
DEFAULT_REPORTS = ROOT / "data" / "reports.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "entries.trace_fixed.jsonl"
DEFAULT_FINDINGS = ROOT / "reports" / "trace_findings.csv"
DEFAULT_DIFF = ROOT / "reports" / "trace_fix_diff.csv"
DEFAULT_NEEDS_HUMAN = ROOT / "reports" / "trace_needs_human.csv"
DEFAULT_REPORT_JSON = ROOT / "reports" / "trace_structure_report.json"
DEFAULT_REPORT_MD = ROOT / "reports" / "trace_structure_report.md"

TARGET_REVIEW_IDS = {
    "entry-00103",
    "entry-00185",
    "entry-00320",
    "entry-00511",
}

# These four findings are explicitly reviewed instead of being deleted by a
# structural line-order heuristic.  Their source order and runtime order differ,
# or their current anchors are themselves semantically questionable.
REVIEW_DECISIONS: dict[tuple[str, int, str], str] = {
    (
        "entry-00103",
        1,
        "before_entry",
    ): (
        "The current entry point is only the closing brace at line 615. "
        "Lines 605-614 are the semantically relevant streaming branch, so "
        "deleting them would remove evidence rather than repair the chain."
    ),
    (
        "entry-00185",
        2,
        "after_critical",
    ): (
        "The later return false is the path-blocking decision and remains "
        "security-relevant. The current critical anchor is a closing brace; "
        "the entry requires semantic review rather than trace deletion."
    ),
    (
        "entry-00320",
        2,
        "before_entry",
    ): (
        "save_file_routine is defined earlier in the same file but is called "
        "downstream at runtime. Source line order does not make this node an "
        "invalid call-chain step."
    ),
    (
        "entry-00511",
        4,
        "after_critical",
    ): (
        "extend is defined after findExtendedFunction but calls that helper at "
        "runtime. Removing the caller because of declaration order would invert "
        "the actual execution relationship."
    ),
}

FORBIDDEN_ENTRY_FIELDS = {
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

FINDING_FIELDS = [
    "entry_id",
    "verify",
    "trace_index",
    "kind",
    "action",
    "node_file",
    "node_line",
    "anchor_field",
    "anchor_file",
    "anchor_line",
    "reason",
]

DIFF_FIELDS = [
    "entry_id",
    "field_path",
    "action",
    "before",
    "after",
    "reason",
]


@dataclass(frozen=True)
class Span:
    start: int
    end: int

    @classmethod
    def parse(cls, value: int | str) -> "Span":
        if isinstance(value, bool):
            raise ValueError("boolean is not a valid line")
        if isinstance(value, int):
            start = end = value
        elif isinstance(value, str) and re.fullmatch(r"\d+-\d+", value):
            start_text, end_text = value.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            raise ValueError(f"invalid line value: {value!r}")
        if start < 1 or end < start:
            raise ValueError(f"invalid line span: {value!r}")
        return cls(start=start, end=end)


@dataclass(frozen=True)
class Finding:
    entry_id: str
    verify: int
    trace_index: int
    kind: str
    action: str
    node_file: str
    node_line: int | str
    anchor_field: str
    anchor_file: str
    anchor_line: int | str
    reason: str

    def csv_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Change:
    entry_id: str
    field_path: str
    action: str
    before: dict[str, Any]
    after: None
    reason: str

    def csv_row(self) -> dict[str, str]:
        return {
            "entry_id": self.entry_id,
            "field_path": self.field_path,
            "action": self.action,
            "before": json.dumps(
                self.before, ensure_ascii=False, sort_keys=True
            ),
            "after": "null",
            "reason": self.reason,
        }


@dataclass
class CleanupResult:
    entries: list[dict[str, Any]]
    findings: list[Finding]
    changes: list[Change]
    stats: dict[str, Any]


def load_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_text(encoding="utf-8")
    entries = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return raw, entries


def _node_key(node: dict[str, Any]) -> tuple[str, str, str]:
    # Keep int 97 distinct from the string "97-97"; the issue defines an exact
    # {file, line, code} duplicate, not a normalized-location duplicate.
    return (
        node["file"],
        json.dumps(node["line"], ensure_ascii=False),
        node["code"],
    )


def _base_reason(kind: str) -> str:
    return {
        "duplicate": (
            "A previous trace node has the exact same {file, line, code}."
        ),
        "before_entry": (
            "The trace span ends before the same-file entry-point span begins; "
            "this is a structural finding, not proof of runtime misordering."
        ),
        "after_critical": (
            "The trace span starts after the same-file critical-operation span "
            "ends; this is a structural finding, not proof of runtime misordering."
        ),
    }[kind]


def _action_for_order_finding(
    entry_id: str,
    verify: int,
    trace_index: int,
    kind: str,
    mode: str,
    order_policy: str,
) -> tuple[str, str]:
    reason = _base_reason(kind)
    reviewed_reason = REVIEW_DECISIONS.get((entry_id, trace_index, kind))
    if reviewed_reason:
        return "manual_review", f"{reason} {reviewed_reason}"
    if verify == 1:
        return (
            "protected_verified",
            f"{reason} The entry is verify=1 and is never auto-modified.",
        )
    if mode == "fix" and order_policy == "structural":
        return (
            "remove",
            f"{reason} Structural removal was explicitly requested.",
        )
    return (
        "manual_review",
        f"{reason} Conservative policy retains the node for semantic review.",
    )


def analyze_entries(
    entries: list[dict[str, Any]],
    *,
    mode: str = "check",
    order_policy: str = "review",
) -> CleanupResult:
    if mode not in {"check", "fix"}:
        raise ValueError(f"unsupported mode: {mode}")
    if order_policy not in {"review", "structural"}:
        raise ValueError(f"unsupported order policy: {order_policy}")

    output_entries = copy.deepcopy(entries)
    findings: list[Finding] = []
    changes: list[Change] = []
    cross_file_comparisons = 0
    trace_nodes = 0

    for entry, output_entry in zip(entries, output_entries, strict=True):
        entry_id = entry["entry_id"]
        verify = entry["verify"]
        entry_point = entry["entry_point"]
        critical = entry["critical_operation"]
        entry_span = Span.parse(entry_point["line"])
        critical_span = Span.parse(critical["line"])
        seen: dict[tuple[str, str, str], tuple[int, dict[str, Any]]] = {}
        remove_indices: set[int] = set()

        for trace_index, node in enumerate(entry["trace"]):
            trace_nodes += 1
            node_span = Span.parse(node["line"])
            key = _node_key(node)
            if key in seen:
                first_index, first_node = seen[key]
                same_desc = first_node.get("desc") == node.get("desc")
                reason = _base_reason("duplicate")
                if verify == 1:
                    action = "protected_verified"
                    reason += " The entry is verify=1 and is never auto-modified."
                elif not same_desc:
                    action = "manual_review"
                    reason += (
                        " The duplicate descriptions conflict, so automatic "
                        "merging could change annotation meaning."
                    )
                elif mode == "fix":
                    action = "remove"
                    reason += (
                        f" The description matches trace[{first_index}], so the "
                        "later duplicate is safe to remove."
                    )
                    remove_indices.add(trace_index)
                else:
                    action = "candidate_remove"
                    reason += (
                        f" It matches trace[{first_index}] and would be removed "
                        "in fix mode."
                    )
                findings.append(
                    Finding(
                        entry_id=entry_id,
                        verify=verify,
                        trace_index=trace_index,
                        kind="duplicate",
                        action=action,
                        node_file=node["file"],
                        node_line=node["line"],
                        anchor_field=f"trace[{first_index}]",
                        anchor_file=first_node["file"],
                        anchor_line=first_node["line"],
                        reason=reason,
                    )
                )
            else:
                seen[key] = (trace_index, node)

            if node["file"] == entry_point["file"]:
                if node_span.end < entry_span.start:
                    action, reason = _action_for_order_finding(
                        entry_id,
                        verify,
                        trace_index,
                        "before_entry",
                        mode,
                        order_policy,
                    )
                    findings.append(
                        Finding(
                            entry_id=entry_id,
                            verify=verify,
                            trace_index=trace_index,
                            kind="before_entry",
                            action=action,
                            node_file=node["file"],
                            node_line=node["line"],
                            anchor_field="entry_point",
                            anchor_file=entry_point["file"],
                            anchor_line=entry_point["line"],
                            reason=reason,
                        )
                    )
                    if action == "remove":
                        remove_indices.add(trace_index)
            else:
                cross_file_comparisons += 1

            if node["file"] == critical["file"]:
                if node_span.start > critical_span.end:
                    action, reason = _action_for_order_finding(
                        entry_id,
                        verify,
                        trace_index,
                        "after_critical",
                        mode,
                        order_policy,
                    )
                    findings.append(
                        Finding(
                            entry_id=entry_id,
                            verify=verify,
                            trace_index=trace_index,
                            kind="after_critical",
                            action=action,
                            node_file=node["file"],
                            node_line=node["line"],
                            anchor_field="critical_operation",
                            anchor_file=critical["file"],
                            anchor_line=critical["line"],
                            reason=reason,
                        )
                    )
                    if action == "remove":
                        remove_indices.add(trace_index)
            else:
                cross_file_comparisons += 1

        if remove_indices:
            output_entry["trace"] = [
                node
                for index, node in enumerate(output_entry["trace"])
                if index not in remove_indices
            ]
            for index in sorted(remove_indices):
                matching = [
                    finding
                    for finding in findings
                    if finding.entry_id == entry_id
                    and finding.trace_index == index
                    and finding.action == "remove"
                ]
                reason = " | ".join(
                    dict.fromkeys(finding.reason for finding in matching)
                )
                changes.append(
                    Change(
                        entry_id=entry_id,
                        field_path=f"trace[{index}]",
                        action="remove",
                        before=entry["trace"][index],
                        after=None,
                        reason=reason,
                    )
                )

    finding_counts = Counter(finding.kind for finding in findings)
    action_counts = Counter(finding.action for finding in findings)
    changed_ids = sorted({change.entry_id for change in changes})
    stats: dict[str, Any] = {
        "mode": mode,
        "order_policy": order_policy,
        "entries_scanned": len(entries),
        "trace_nodes_scanned": trace_nodes,
        "finding_counts": dict(sorted(finding_counts.items())),
        "action_counts": dict(sorted(action_counts.items())),
        "cross_file_comparisons_skipped": cross_file_comparisons,
        "changes_applied": len(changes),
        "changed_entries": changed_ids,
        "needs_human_entries": sorted(
            {
                finding.entry_id
                for finding in findings
                if finding.action == "manual_review"
            }
        ),
    }
    return CleanupResult(
        entries=output_entries,
        findings=findings,
        changes=changes,
        stats=stats,
    )


def validate_dataset(
    entries: list[dict[str, Any]],
    reports: list[dict[str, Any]],
) -> None:
    entry_ids = [entry["entry_id"] for entry in entries]
    if entry_ids != sorted(entry_ids) or len(entry_ids) != len(set(entry_ids)):
        raise ValueError("entry ids must be unique and sorted")

    grouped: dict[str, list[str]] = {}
    for entry in entries:
        if entry["verify"] not in {0, 1}:
            raise ValueError(f"{entry['entry_id']} has invalid verify")
        if FORBIDDEN_ENTRY_FIELDS.intersection(entry):
            raise ValueError(f"{entry['entry_id']} contains internal fields")
        if not re.fullmatch(r"[0-9a-f]{40}", entry["commit"]):
            raise ValueError(f"{entry['entry_id']} has invalid commit")
        if not entry["repo_url"].startswith("https://github.com/"):
            raise ValueError(f"{entry['entry_id']} has invalid repo_url")
        if entry["report_id"] not in entry["source_link"].upper():
            raise ValueError(f"{entry['entry_id']} has inconsistent advisory id")
        for node in [
            entry["entry_point"],
            entry["critical_operation"],
            *entry["trace"],
        ]:
            if not {"file", "line", "code"}.issubset(node):
                raise ValueError(f"{entry['entry_id']} has incomplete node")
            if set(node) - {"file", "line", "code", "desc"}:
                raise ValueError(f"{entry['entry_id']} has unexpected node fields")
            Span.parse(node["line"])
            if not node["file"] or not isinstance(node["code"], str):
                raise ValueError(f"{entry['entry_id']} has an invalid node")
        grouped.setdefault(entry["report_id"], []).append(entry["entry_id"])

    report_map = {report["report_id"]: report for report in reports}
    if set(grouped) != set(report_map):
        raise ValueError("entry/report advisory sets differ")
    for report_id, entry_group in grouped.items():
        report = report_map[report_id]
        if report["entry_ids"] != sorted(entry_group):
            raise ValueError(f"{report_id} has inconsistent entry_ids")
        if report["num_entries"] != len(entry_group):
            raise ValueError(f"{report_id} has inconsistent num_entries")


def _write_csv(
    path: Path,
    fieldnames: list[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def _serialize_jsonl(entries: list[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(entry, ensure_ascii=False) + "\n" for entry in entries
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _render_report(
    stats: dict[str, Any],
    input_sha256: str,
    output_sha256: str,
) -> str:
    finding_counts = stats["finding_counts"]
    action_counts = stats["action_counts"]
    review_rows = "\n".join(
        f"| `{entry_id}` | `{trace_index}` | `{kind}` | {reason} |"
        for (entry_id, trace_index, kind), reason in REVIEW_DECISIONS.items()
    )
    return f"""# Trace structure cleanup report

## Summary

- Mode: `{stats['mode']}`
- Order policy: `{stats['order_policy']}`
- Entries scanned: {stats['entries_scanned']}
- Trace nodes scanned: {stats['trace_nodes_scanned']}
- Exact duplicate findings: {finding_counts.get('duplicate', 0)}
- Before-entry findings: {finding_counts.get('before_entry', 0)}
- After-critical findings: {finding_counts.get('after_critical', 0)}
- Cross-file comparisons skipped: {stats['cross_file_comparisons_skipped']}
- Automatic changes: {stats['changes_applied']}
- Protected verified findings: {action_counts.get('protected_verified', 0)}
- Manual-review findings: {action_counts.get('manual_review', 0)}
- Input SHA-256: `{input_sha256}`
- Output SHA-256: `{output_sha256}`

The default result intentionally makes no source-order deletion when execution
semantics are not proven. Identical hashes demonstrate that the conservative
fixed artifact preserves the canonical dataset byte-for-byte.

## Reviewed unverified findings

| Entry | Trace index | Finding | Decision |
|---|---:|---|---|
{review_rows}

## Policy boundary

`before_entry` and `after_critical` describe source-layout findings only.
Functions and helpers can be defined before or after their callers, so source
line order must not be treated as runtime order without stronger evidence.

`--order-policy structural` is available for explicitly requested mechanical
removal, but reviewed exceptions above remain protected. Cross-file trace nodes
are never reordered or compared by line number.
"""


def write_artifacts(
    input_text: str,
    result: CleanupResult,
    *,
    output_path: Path = DEFAULT_OUTPUT,
    findings_path: Path = DEFAULT_FINDINGS,
    diff_path: Path = DEFAULT_DIFF,
    needs_human_path: Path = DEFAULT_NEEDS_HUMAN,
    report_json_path: Path = DEFAULT_REPORT_JSON,
    report_md_path: Path = DEFAULT_REPORT_MD,
) -> None:
    output_text = _serialize_jsonl(result.entries)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output_text, encoding="utf-8", newline="\n")

    _write_csv(
        findings_path,
        FINDING_FIELDS,
        (finding.csv_row() for finding in result.findings),
    )
    _write_csv(
        diff_path,
        DIFF_FIELDS,
        (change.csv_row() for change in result.changes),
    )
    _write_csv(
        needs_human_path,
        FINDING_FIELDS,
        (
            finding.csv_row()
            for finding in result.findings
            if finding.action == "manual_review"
        ),
    )

    stats = dict(result.stats)
    stats["input_sha256"] = _sha256(input_text)
    stats["output_sha256"] = _sha256(output_text)
    report_json_path.parent.mkdir(parents=True, exist_ok=True)
    report_json_path.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    report_md_path.write_text(
        _render_report(
            stats,
            stats["input_sha256"],
            stats["output_sha256"],
        ),
        encoding="utf-8",
        newline="\n",
    )


def _source_text(entry: dict[str, Any], path: str) -> str:
    repo = entry["repo_url"].removeprefix("https://github.com/").rstrip("/")
    url = (
        f"https://raw.githubusercontent.com/{repo}/{entry['commit']}/{path}"
    )
    request = Request(url, headers={"User-Agent": "VulnGym-Issue-5-validator"})
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def validate_review_sources(entries: list[dict[str, Any]]) -> None:
    entry_map = {entry["entry_id"]: entry for entry in entries}
    source_cache: dict[tuple[str, str], str] = {}
    occurrences = 0
    unique_nodes: set[tuple[str, str, str, str]] = set()

    for entry_id, trace_index, _kind in REVIEW_DECISIONS:
        entry = entry_map[entry_id]
        for node in (
            entry["entry_point"],
            entry["critical_operation"],
            entry["trace"][trace_index],
        ):
            cache_key = (entry_id, node["file"])
            if cache_key not in source_cache:
                source_cache[cache_key] = _source_text(entry, node["file"])
            start_end = Span.parse(node["line"])
            actual = "\n".join(
                source_cache[cache_key].splitlines()[
                    start_end.start - 1 : start_end.end
                ]
            )
            if actual != node["code"]:
                raise RuntimeError(
                    f"source mismatch: {entry_id} {node['file']}:{node['line']}"
                )
            occurrences += 1
            unique_nodes.add(
                (
                    entry_id,
                    node["file"],
                    str(node["line"]),
                    node["code"],
                )
            )

    print(
        "review source validation passed: "
        f"{occurrences} occurrences, {len(unique_nodes)} unique nodes, "
        f"{len(source_cache)} source files"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--reports", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--mode",
        choices=("check", "fix"),
        default="check",
        help="check reports only; fix applies policy-approved removals",
    )
    parser.add_argument(
        "--order-policy",
        choices=("review", "structural"),
        default="review",
        help="review preserves order findings; structural removes unreviewed "
        "verify=0 findings in fix mode",
    )
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="match the four unverified review cases against pinned sources",
    )
    args = parser.parse_args()

    input_text, entries = load_jsonl(args.input)
    _, reports = load_jsonl(args.reports)
    validate_dataset(entries, reports)
    if args.check_upstream:
        validate_review_sources(entries)
        return

    result = analyze_entries(
        entries,
        mode=args.mode,
        order_policy=args.order_policy,
    )
    validate_dataset(result.entries, reports)
    write_artifacts(input_text, result, output_path=args.output)
    print(
        f"trace cleanup complete: {result.stats['entries_scanned']} entries, "
        f"{result.stats['trace_nodes_scanned']} trace nodes, "
        f"{len(result.findings)} findings, "
        f"{result.stats['changes_applied']} changes"
    )


if __name__ == "__main__":
    main()
