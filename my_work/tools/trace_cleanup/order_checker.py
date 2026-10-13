"""顺序异常检测模块。

检测 trace 中同文件节点与 entry_point / critical_operation 的行号关系异常。

跨文件安全约束：仅在同一 file 内进行行号比较，不同文件的节点之间不做任何比较或排序。
"""

from __future__ import annotations

from .line_parser import parse_line, is_strictly_before, is_strictly_after, is_overlapping
from .line_parser import LineRange


def _cmp_label(t_range: LineRange, ref_range: LineRange) -> str:
    """将比较结果映射为人类可读标签。"""
    if is_strictly_before(t_range, ref_range):
        return "strictly_before"
    if is_strictly_after(t_range, ref_range):
        return "strictly_after"
    if is_overlapping(t_range, ref_range):
        return "overlapping"
    return "other"


def check_order(
    entry_point: dict,
    critical_operation: dict,
    trace: list[dict],
) -> list[dict]:
    """检测 trace 中的顺序异常。

    对每个 trace 节点进行分类：
    - 与 entry_point 同文件：检查是否在 entry_point 之前（before-entry 异常）
    - 与 critical_operation 同文件：检查是否在 critical_operation 之后（after-critical 异常）
    - 跨文件节点：不做行号比较（安全保护）

    Args:
        entry_point: 入口点对象 {file, line, code, desc?}
        critical_operation: 关键操作对象 {file, line, code, desc?}
        trace: 有序的 trace 节点数组

    Returns:
        每个 trace 节点的分类结果列表，包含字段：
        - index: 节点在 trace 中的下标
        - file: 节点文件路径
        - file_group: "entry_file" | "critical_file" | "cross_file" | "both"
        - comparison: "strictly_before" | "strictly_after" | "overlapping" | "n/a"
        - vs_entry: 与 entry_point 的相对位置
        - vs_critical: 与 critical_operation 的相对位置
        - anomaly: "before_entry" | "after_critical" | "none"
        - certainty: "clear" | "ambiguous"
    """
    ep_file = entry_point.get("file", "")
    co_file = critical_operation.get("file", "")
    same_file = (ep_file == co_file)

    ep_range = parse_line(entry_point["line"])
    co_range = parse_line(critical_operation["line"])

    results: list[dict] = []

    for i, node in enumerate(trace):
        f = node.get("file", "")
        t_range = parse_line(node["line"])

        in_ep = (f == ep_file)
        in_co = (f == co_file)

        # 确定 file_group
        if in_ep and in_co:
            file_group = "both"
        elif in_ep:
            file_group = "entry_file"
        elif in_co:
            file_group = "critical_file"
        else:
            file_group = "cross_file"

        vs_entry = "n/a"
        vs_critical = "n/a"
        comparison = "n/a"
        anomaly = "none"
        certainty = "n/a"

        if file_group == "both":
            # 同一文件同时是 entry_point 和 critical_operation 所在文件
            cmp_ep = _cmp_label(t_range, ep_range)
            cmp_co = _cmp_label(t_range, co_range)
            vs_entry = cmp_ep
            vs_critical = cmp_co

            if cmp_ep == "strictly_before" and cmp_co == "strictly_before":
                comparison = cmp_ep
                anomaly = "before_entry"
                certainty = "clear"
            elif cmp_ep == "strictly_after" and cmp_co == "strictly_after":
                comparison = cmp_ep
                anomaly = "after_critical"
                certainty = "clear"
            elif cmp_ep == "strictly_before":
                comparison = cmp_ep
                anomaly = "before_entry"
                certainty = "ambiguous"
            elif cmp_co == "strictly_after":
                comparison = cmp_co
                anomaly = "after_critical"
                certainty = "ambiguous"
            else:
                comparison = f"ep={cmp_ep},co={cmp_co}"
                certainty = "ambiguous"

        elif file_group == "entry_file":
            vs_entry = _cmp_label(t_range, ep_range)
            comparison = vs_entry
            if vs_entry == "strictly_before":
                anomaly = "before_entry"
                certainty = "clear"
            elif vs_entry == "overlapping":
                # t_start < ep_start ≤ t_end → 部分重叠，需人工判断 (instruction.md §3.2)
                anomaly = "before_entry"
                certainty = "ambiguous"

        elif file_group == "critical_file":
            vs_critical = _cmp_label(t_range, co_range)
            comparison = vs_critical
            if vs_critical == "strictly_after":
                anomaly = "after_critical"
                certainty = "clear"
            elif vs_critical == "overlapping":
                # t_start ≤ co_end < t_end → 部分重叠，需人工判断 (instruction.md §3.3)
                anomaly = "after_critical"
                certainty = "ambiguous"

        elif file_group == "cross_file":
            comparison = "n/a (cross-file)"
            certainty = "n/a"

        results.append({
            "index": i,
            "file": f,
            "line": node.get("line"),
            "line_range": t_range,
            "file_group": file_group,
            "comparison": comparison,
            "vs_entry": vs_entry,
            "vs_critical": vs_critical,
            "anomaly": anomaly,
            "certainty": certainty,
        })

    return results
