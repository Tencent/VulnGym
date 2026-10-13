from __future__ import annotations

from collections import defaultdict

from .lines import SpanRelation, classify_span, parse_line
from .models import DetectionResult, Finding


def normalize_path(path: str) -> str:
    """Normalize only separators and leading './'; preserve case."""
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _duplicate_findings(entry: dict) -> list[Finding]:
    groups: dict[tuple[object, ...], list[int]] = defaultdict(list)
    trace = entry["trace"]
    for index, item in enumerate(trace):
        key = (item["file"], item["line"], item["code"])
        groups[key].append(index)

    findings: list[Finding] = []
    for indices in groups.values():
        if len(indices) < 2:
            continue
        nodes = [trace[index] for index in indices]
        desc_presence = ["desc" in item for item in nodes]
        all_missing = not any(desc_presence)
        all_present_equal = (
            all(desc_presence)
            and len({item["desc"] for item in nodes}) == 1
        )
        safe = all_missing or all_present_equal
        kept_index = indices[0]
        findings.append(
            Finding(
                entry_id=entry["entry_id"],
                report_id=entry["report_id"],
                verify=entry["verify"],
                rule_id="duplicate_trace_node",
                field_path=",".join(f"trace[{index}]" for index in indices),
                trace_index=kept_index,
                file=nodes[0]["file"],
                raw_line=nodes[0]["line"],
                relation="exact_duplicate",
                reason=(
                    "严格重复节点且 desc 一致，可在安全策略下保留第一次出现"
                    if safe
                    else "严格重复节点的 desc 不一致或存在性不同，需要人工复核"
                ),
                before=nodes,
                after=nodes[0],
                kept_index=kept_index,
                indices=tuple(indices),
                safe_duplicate=safe,
            )
        )
    return findings


def _order_finding(
    entry: dict,
    item: dict,
    index: int,
    *,
    rule_id: str,
    boundary_role: str,
    boundary: dict,
    relation: SpanRelation,
    reason: str,
) -> Finding:
    return Finding(
        entry_id=entry["entry_id"],
        report_id=entry["report_id"],
        verify=entry["verify"],
        rule_id=rule_id,
        field_path=f"trace[{index}]",
        trace_index=index,
        file=item["file"],
        raw_line=item["line"],
        boundary_role=boundary_role,
        boundary_file=boundary["file"],
        boundary_raw_line=boundary["line"],
        relation=relation.value,
        before=item,
        after=None if rule_id.endswith("_definite") else item,
        reason=reason,
        indices=(index,),
    )


def _order_findings(entry: dict) -> list[Finding]:
    findings: list[Finding] = []
    entry_point = entry["entry_point"]
    critical = entry["critical_operation"]
    entry_file = normalize_path(entry_point["file"])
    critical_file = normalize_path(critical["file"])
    entry_span = parse_line(entry_point["line"])
    critical_span = parse_line(critical["line"])

    for index, item in enumerate(entry["trace"]):
        item_file = normalize_path(item["file"])
        item_span = parse_line(item["line"])
        comparable_entry = item_file == entry_file
        comparable_critical = item_file == critical_file

        if not comparable_entry and not comparable_critical:
            findings.append(
                Finding(
                    entry_id=entry["entry_id"],
                    report_id=entry["report_id"],
                    verify=entry["verify"],
                    rule_id="cross_file_skipped",
                    field_path=f"trace[{index}]",
                    trace_index=index,
                    file=item["file"],
                    raw_line=item["line"],
                    relation="cross_file",
                    reason="trace 文件与入口及关键操作文件均不同，不参与行号比较",
                    before=item,
                    after=item,
                    indices=(index,),
                )
            )
            continue

        if comparable_entry:
            relation = classify_span(item_span, entry_span)
            if relation is SpanRelation.BEFORE:
                findings.append(
                    _order_finding(
                        entry,
                        item,
                        index,
                        rule_id="before_entry_definite",
                        boundary_role="entry_point",
                        boundary=entry_point,
                        relation=relation,
                        reason=(
                            "同文件 trace 区间完全早于 entry_point；"
                            "这是机械结构候选，不是运行时顺序证明"
                        ),
                    )
                )
            elif item_span.start < entry_span.start <= item_span.end:
                findings.append(
                    _order_finding(
                        entry,
                        item,
                        index,
                        rule_id="overlap_entry",
                        boundary_role="entry_point",
                        boundary=entry_point,
                        relation=relation,
                        reason="trace 区间从入口前开始但与 entry_point 重叠，不自动删除",
                    )
                )

        if comparable_critical:
            relation = classify_span(item_span, critical_span)
            if relation is SpanRelation.AFTER:
                findings.append(
                    _order_finding(
                        entry,
                        item,
                        index,
                        rule_id="after_critical_definite",
                        boundary_role="critical_operation",
                        boundary=critical,
                        relation=relation,
                        reason=(
                            "同文件 trace 区间完全晚于 critical_operation；"
                            "这是机械结构候选，不是运行时顺序证明"
                        ),
                    )
                )
            elif item_span.start <= critical_span.end < item_span.end:
                findings.append(
                    _order_finding(
                        entry,
                        item,
                        index,
                        rule_id="overlap_critical",
                        boundary_role="critical_operation",
                        boundary=critical,
                        relation=relation,
                        reason="trace 区间延伸到关键操作之后但与其重叠，不自动删除",
                    )
                )
    return findings


def detect_entry(entry: dict) -> list[Finding]:
    """Detect findings for one entry without mutating it."""
    return _duplicate_findings(entry) + _order_findings(entry)


def scan_entries(entries: list[dict]) -> DetectionResult:
    findings: list[Finding] = []
    trace_nodes = 0
    for entry in entries:
        trace_nodes += len(entry["trace"])
        findings.extend(detect_entry(entry))
    duplicate_findings = [
        finding for finding in findings
        if finding.rule_id == "duplicate_trace_node"
    ]
    return DetectionResult(
        findings=tuple(findings),
        entries_scanned=len(entries),
        trace_nodes_scanned=trace_nodes,
        duplicate_groups=len(duplicate_findings),
        duplicate_extra_nodes=sum(
            len(finding.indices) - 1 for finding in duplicate_findings
        ),
    )
