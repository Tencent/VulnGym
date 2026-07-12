from typing import Dict, List, Any
from collections import defaultdict
from parser import parse_line


def _node_key(node: Dict[str, Any]) -> tuple:
    return (
        node.get("file"),
        node.get("line"),
        node.get("code"),
    )


def clean_trace(
    trace: List[Dict[str, Any]],
    entry_point_line: int,
    critical_op_line: int,
) -> Dict[str, Any]:
    """
    清洗 trace：
    - 去重（保留首次出现）
    - 检测越界（同文件内）
    - 跨文件不参与行号比较
    """
    cleaned = []
    seen = set()
    duplicates = 0
    out_of_order = 0

    current_file = None
    for node in trace:
        key = _node_key(node)

        # 去重
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)

        # 同文件才做行号校验
        if node.get("file") == current_file:
            try:
                line = parse_line(node.get("line"))
                if isinstance(line, int):
                    if int(line) < int(entry_point_line) or int(line) > int(critical_op_line):
                        out_of_order += 1
            except ValueError:
                pass  # 非法格式跳过，不崩

        current_file = node.get("file")
        cleaned.append(node)

    return {
        "trace": cleaned,
        "stats": {
            "duplicates_removed": duplicates,
            "out_of_order_detected": out_of_order,
        },
    }