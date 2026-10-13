"""修复执行模块。

根据检测结果执行实际的 trace 修复操作：
  - 保守模式 (conservative)：仅记录，不做任何修改
  - 修复模式 (fix)：对 verify=0 的明确越界节点执行删除
"""

from __future__ import annotations

import copy
from typing import Any


def fix_entries(
    entries: list[dict],
    dup_results: dict[str, list[dict]],
    order_results: dict[str, list[dict]],
    mode: str = "conservative",
) -> tuple[list[dict], list[dict]]:
    """对 entries 执行 trace 修复。

    策略：
    - verify=1 条目：完全保护，不做任何自动修改
    - verify=0 条目：
      - 保守模式：不修改
      - 修复模式：
        - 重复节点（desc 不冲突）：删除重复，合并 desc
        - 明确 before-entry 节点：删除
        - 明确 after-critical 节点：删除
        - 模糊异常：不修改，进入人工复核

    Args:
        entries: 原始 entries 列表
        dup_results: entry_id → 重复检测结果列表
        order_results: entry_id → 顺序检测结果列表
        mode: "conservative" 或 "fix"

    Returns:
        (fixed_entries, fix_log) 元组。
        fixed_entries: 修复后的 entries（conservative 模式下与输入相同）
        fix_log: 每一条修改记录
    """
    fixed_entries = copy.deepcopy(entries)
    fix_log: list[dict] = []

    for i, entry in enumerate(fixed_entries):
        entry_id = entry["entry_id"]
        verify = entry.get("verify", 0)
        dup_list = dup_results.get(entry_id, [])
        order_list = order_results.get(entry_id, [])

        # verify=1 条目完全保护
        if verify == 1:
            continue

        if mode == "conservative":
            continue

        # 修复模式：收集需要删除的 trace 索引
        delete_indices: set[int] = set()

        # 1) 处理重复节点
        for dr in dup_list:
            if dr["action"] == "remove" and not dr["desc_conflict"]:
                delete_indices.add(dr["index"])
                # 合并 desc
                if dr["merge_desc"]:
                    kept_idx = dr["kept_index"]
                    entry["trace"][kept_idx]["desc"] = dr["current_desc"]

                fix_log.append({
                    "entry_id": entry_id,
                    "verify": verify,
                    "field": f"trace[{dr['index']}]",
                    "action": "remove_duplicate",
                    "before": _format_node_brief(entry["trace"][dr["index"]]),
                    "after": None,
                    "reason": dr["reason"],
                    "desc_merged": dr["merge_desc"],
                })

        # 2) 处理顺序异常
        for or_ in order_list:
            if or_["anomaly"] != "none" and or_["certainty"] == "clear":
                delete_indices.add(or_["index"])
                fix_log.append({
                    "entry_id": entry_id,
                    "verify": verify,
                    "field": f"trace[{or_['index']}]",
                    "action": f"remove_{or_['anomaly']}",
                    "before": _format_node_brief(entry["trace"][or_["index"]]),
                    "after": None,
                    "reason": f"{or_['anomaly']}: 节点在 {or_['file_group']} 中 {or_['comparison']}",
                })

        # 执行删除（从大到小排序索引，避免偏移问题）
        if delete_indices:
            new_trace = [
                node for j, node in enumerate(entry["trace"])
                if j not in delete_indices
            ]
            entry["trace"] = new_trace

    return fixed_entries, fix_log


def _format_node_brief(node: dict) -> str:
    """格式化节点的简要信息字符串。"""
    f = node.get("file", "")
    l = node.get("line", "")
    c = node.get("code", "")
    preview = c[:80] + ("..." if len(c) > 80 else "")
    return f"{f}:{l} [{preview}]"
