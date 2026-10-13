"""报告生成模块。

生成三类输出：
  1. trace_findings.csv — 详细检测结果
  2. trace_fix_log.csv — 修改日志
  3. trace_needs_human.csv — 人工复核清单
  4. trace_structure_report.json — 汇总统计
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def generate_reports(
    entries: list[dict],
    dup_results: dict[str, list[dict]],
    order_results: dict[str, list[dict]],
    fix_log: list[dict],
    mode: str,
    output_dir: Path,
) -> dict[str, Any]:
    """生成所有报告文件。

    Args:
        entries: entries 列表
        dup_results: entry_id → 重复检测结果
        order_results: entry_id → 顺序检测结果
        fix_log: 修改日志列表
        mode: 运行模式
        output_dir: 输出目录

    Returns:
        汇总统计字典
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 统计
    stats = _compute_stats(entries, dup_results, order_results, fix_log)

    # 1) findings.csv
    _write_findings_csv(entries, dup_results, order_results, output_dir / "trace_findings.csv")

    # 2) fix_log.csv
    if fix_log:
        _write_fix_log_csv(fix_log, output_dir / "trace_fix_log.csv")

    # 3) needs_human.csv
    _write_human_review_csv(entries, dup_results, order_results, output_dir / "trace_needs_human.csv")

    # 4) structure_report.json
    with open(output_dir / "trace_structure_report.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    return stats


def _compute_stats(
    entries: list[dict],
    dup_results: dict[str, list[dict]],
    order_results: dict[str, list[dict]],
    fix_log: list[dict],
) -> dict[str, Any]:
    """计算汇总统计。"""
    total_entries = len(entries)
    total_trace_nodes = sum(len(e.get("trace", [])) for e in entries)
    verify0_count = sum(1 for e in entries if e.get("verify") == 0)
    verify1_count = sum(1 for e in entries if e.get("verify") == 1)

    dup_count = sum(
        1 for drs in dup_results.values()
        for dr in drs if dr["action"] == "remove"
    )
    dup_desc_conflict = sum(
        1 for drs in dup_results.values()
        for dr in drs if dr["action"] == "remove" and dr["desc_conflict"]
    )

    before_entry_count = 0
    before_entry_clear = 0
    after_critical_count = 0
    after_critical_clear = 0
    cross_file_count = 0

    for ors in order_results.values():
        for or_ in ors:
            if or_["anomaly"] == "before_entry":
                before_entry_count += 1
                if or_["certainty"] == "clear":
                    before_entry_clear += 1
            elif or_["anomaly"] == "after_critical":
                after_critical_count += 1
                if or_["certainty"] == "clear":
                    after_critical_clear += 1
            if or_["file_group"] == "cross_file":
                cross_file_count += 1

    fix_entries_modified = len(set(log["entry_id"] for log in fix_log))

    human_review_entries = set()
    for eid, drs in dup_results.items():
        for dr in drs:
            if dr["desc_conflict"]:
                human_review_entries.add(eid)
    for eid, ors in order_results.items():
        for or_ in ors:
            if or_["anomaly"] != "none" and or_["certainty"] == "ambiguous":
                human_review_entries.add(eid)

    return {
        "summary": {
            "total_entries": total_entries,
            "verify_0": verify0_count,
            "verify_1": verify1_count,
            "total_trace_nodes": total_trace_nodes,
        },
        "duplicates": {
            "total": dup_count,
            "desc_conflict_need_human": dup_desc_conflict,
            "auto_mergeable": dup_count - dup_desc_conflict,
        },
        "order_anomalies": {
            "before_entry": {
                "total": before_entry_count,
                "clear": before_entry_clear,
                "ambiguous": before_entry_count - before_entry_clear,
            },
            "after_critical": {
                "total": after_critical_count,
                "clear": after_critical_clear,
                "ambiguous": after_critical_count - after_critical_clear,
            },
        },
        "cross_file_nodes": cross_file_count,
        "fixes": {
            "mode": fix_log[0].get("action", "") if fix_log else "conservative (no changes)",
            "total_fix_entries": len(fix_log),
            "entries_modified": fix_entries_modified,
        },
        "human_review_needed": len(human_review_entries),
    }


def _write_findings_csv(
    entries: list[dict],
    dup_results: dict[str, list[dict]],
    order_results: dict[str, list[dict]],
    path: Path,
) -> None:
    """写入详细检测结果 CSV。"""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "entry_id", "verify", "trace_index", "file", "line", "line_start", "line_end",
            "duplicate", "anomaly", "certainty", "file_group", "comparison",
            "vs_entry", "vs_critical", "code_preview",
        ])
        for entry in entries:
            eid = entry["entry_id"]
            verify = entry.get("verify", 0)
            trace = entry.get("trace", [])
            dr_map = {dr["index"]: dr for dr in dup_results.get(eid, [])}
            or_map = {or_["index"]: or_ for or_ in order_results.get(eid, [])}

            for i, node in enumerate(trace):
                dr = dr_map.get(i, {})
                or_ = or_map.get(i, {})

                is_dup = "yes" if dr.get("action") == "remove" else "no"
                anomaly = or_.get("anomaly", "none")
                certainty = or_.get("certainty", "n/a")
                file_group = or_.get("file_group", "n/a")
                comparison = or_.get("comparison", "n/a")
                vs_entry = or_.get("vs_entry", "n/a")
                vs_critical = or_.get("vs_critical", "n/a")
                lr = or_.get("line_range", (0, 0))
                code_preview = node.get("code", "")[:100]

                writer.writerow([
                    eid, verify, i, node.get("file", ""), node.get("line", ""),
                    lr[0], lr[1],
                    is_dup, anomaly, certainty, file_group, comparison,
                    vs_entry, vs_critical, code_preview,
                ])


def _write_fix_log_csv(fix_log: list[dict], path: Path) -> None:
    """写入修改日志 CSV。"""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["entry_id", "verify", "field", "action", "before", "after", "reason", "desc_merged"])
        for log in fix_log:
            writer.writerow([
                log["entry_id"], log["verify"], log["field"], log["action"],
                log.get("before", ""), log.get("after", ""),
                log.get("reason", ""), log.get("desc_merged", ""),
            ])


def _write_human_review_csv(
    entries: list[dict],
    dup_results: dict[str, list[dict]],
    order_results: dict[str, list[dict]],
    path: Path,
) -> None:
    """写入需要人工复核的条目清单。"""
    review_items: list[dict] = []

    for entry in entries:
        eid = entry["entry_id"]
        verify = entry.get("verify", 0)

        # 重复节点的 desc 冲突
        for dr in dup_results.get(eid, []):
            if dr["desc_conflict"]:
                review_items.append({
                    "entry_id": eid,
                    "verify": verify,
                    "trace_index": dr["index"],
                    "issue_type": "duplicate_desc_conflict",
                    "description": (
                        f"trace[{dr['index']}] 与 trace[{dr['kept_index']}] 重复但 desc 不一致; "
                        f"first='{dr['first_desc']}' vs current='{dr['current_desc']}'"
                    ),
                })

        # 模糊异常
        for or_ in order_results.get(eid, []):
            if or_["anomaly"] != "none" and or_["certainty"] == "ambiguous":
                review_items.append({
                    "entry_id": eid,
                    "verify": verify,
                    "trace_index": or_["index"],
                    "issue_type": f"ambiguous_{or_['anomaly']}",
                    "description": (
                        f"trace[{or_['index']}] 在 {or_['file_group']} 中 "
                        f"comparison={or_['comparison']}, vs_entry={or_['vs_entry']}, "
                        f"vs_critical={or_['vs_critical']}"
                    ),
                })

    if review_items:
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["entry_id", "verify", "trace_index", "issue_type", "description"])
            for item in review_items:
                writer.writerow([
                    item["entry_id"], item["verify"], item["trace_index"],
                    item["issue_type"], item["description"],
                ])


def print_summary(stats: dict) -> None:
    """打印人类可读的统计摘要。"""
    s = stats["summary"]
    d = stats["duplicates"]
    o = stats["order_anomalies"]
    f = stats["fixes"]

    print()
    print("=" * 60)
    print("  VulnGym Trace Cleanup — 检测与修复报告")
    print("=" * 60)
    print()
    print(f"  数据集: {s['total_entries']} entries  ({s['verify_1']} 已审核, {s['verify_0']} 未审核)")
    print(f"  总 trace 节点: {s['total_trace_nodes']}")
    print()
    print("  ── 重复节点 ──")
    print(f"    总计: {d['total']} 重复节点")
    print(f"    desc 冲突 (需人工): {d['desc_conflict_need_human']}")
    print(f"    可自动合并: {d['auto_mergeable']}")
    print()
    print("  ── before_entry 异常 ──")
    print(f"    总计: {o['before_entry']['total']}")
    print(f"      明确越界: {o['before_entry']['clear']}")
    print(f"      模糊(需人工): {o['before_entry']['ambiguous']}")
    print()
    print("  ── after_critical 异常 ──")
    print(f"    总计: {o['after_critical']['total']}")
    print(f"      明确越界: {o['after_critical']['clear']}")
    print(f"      模糊(需人工): {o['after_critical']['ambiguous']}")
    print()
    print(f"  ── 跨文件节点 (不做比较): {stats['cross_file_nodes']}")
    print()
    print(f"  ── 修复操作 ──")
    print(f"    模式: {f['mode']}")
    print(f"    共 {f['total_fix_entries']} 条修改, 涉及 {f['entries_modified']} 个 entry")
    if f['total_fix_entries'] == 0 and f['mode'] != 'conservative (no changes)':
        print(f"    注意: 未执行任何自动修复（保守策略）")
    print()
    print(f"  需人工复核: {stats['human_review_needed']} 个 entry")
    print()
    print("=" * 60)
