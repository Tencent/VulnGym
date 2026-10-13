"""重复节点检测模块。

检测 trace 数组中 {file, line, code} 三元组完全相同的重复节点。
"""

from __future__ import annotations

from typing import Any


def normalize_node_key(node: dict) -> tuple:
    """将 trace 节点归一化为可哈希的比较键。"""
    return (
        node.get("file", ""),
        str(node.get("line", "")),
        node.get("code", ""),
    )


def detect_duplicates(trace: list[dict]) -> list[dict]:
    """在 trace 数组中检测重复节点。

    比较规则：{file, line, code} 三元组（字符串化后比较）。
    保留第一次出现的节点，标记所有后续重复。

    Args:
        trace: 有序的 trace 节点数组。

    Returns:
        检测结果列表，每个元素包含：
        - index: 重复节点的数组下标
        - kept_index: 保留的第一次出现下标
        - action: "keep" 或 "remove"
        - reason: 重复原因描述
        - desc_conflict: 两个重复节点的 desc 是否冲突
    """
    results: list[dict] = []
    seen: dict[tuple, int] = {}  # key → 第一次出现的索引

    for i, node in enumerate(trace):
        key = normalize_node_key(node)

        if key in seen:
            first_idx = seen[key]
            first_node = trace[first_idx]
            first_desc = first_node.get("desc")
            current_desc = node.get("desc")

            desc_conflict = False
            if first_desc and current_desc and first_desc != current_desc:
                desc_conflict = True

            # 如果第一次出现没有 desc，而当前有，则提示可以合并
            merge_desc = False
            if not first_desc and current_desc:
                merge_desc = True

            results.append({
                "index": i,
                "kept_index": first_idx,
                "file": node.get("file", ""),
                "line": node.get("line"),
                "code": node.get("code", ""),
                "action": "remove",
                "reason": f"与 trace[{first_idx}] 完全重复（{file_line_code(node)}）",
                "desc_conflict": desc_conflict,
                "merge_desc": merge_desc,
                "first_desc": first_desc,
                "current_desc": current_desc,
            })
        else:
            seen[key] = i
            results.append({
                "index": i,
                "kept_index": i,
                "file": node.get("file", ""),
                "line": node.get("line"),
                "code": node.get("code", ""),
                "action": "keep",
                "reason": "唯一节点",
                "desc_conflict": False,
                "merge_desc": False,
                "first_desc": None,
                "current_desc": None,
            })

    return results


def file_line_code(node: dict) -> str:
    """格式化节点的 {file, line, code} 摘要。"""
    f = node.get("file", "")
    l = node.get("line", "")
    c = node.get("code", "")
    code_preview = c[:60] + ("..." if len(c) > 60 else "")
    return f"{f}:{l}  [{code_preview}]"
