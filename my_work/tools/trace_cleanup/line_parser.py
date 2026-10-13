"""行号归一化模块。

将 entries.jsonl 中两种 line 格式统一解析为 (start, end) 元组：
  - int n         → (n, n)
  - 字符串 "a-b"    → (int(a), int(b))
"""

from __future__ import annotations

from typing import Union


LineType = Union[int, str]
LineRange = tuple[int, int]


def parse_line(line_val: LineType) -> LineRange:
    """归一化 line 字段为 (start, end) 行号范围。

    Args:
        line_val: int ≥ 1 或 "start-end" 字符串 (1 ≤ start ≤ end)。

    Returns:
        (start, end) 元组。int n 映射为 (n, n)；"a-b" 映射为 (int(a), int(b))。

    Raises:
        ValueError: 格式不符合 SCHEMA.md 规范时抛出。
    """
    if isinstance(line_val, bool):
        raise ValueError(f"line 不能为布尔值: {line_val!r}")

    if isinstance(line_val, int):
        if line_val < 1:
            raise ValueError(f"line 必须 ≥ 1，实际为 {line_val}")
        return (line_val, line_val)

    if isinstance(line_val, str):
        s = line_val.strip()
        if '-' not in s:
            raise ValueError(f"字符串 line 必须包含 '-' 分界符: {s!r}")
        parts = s.split('-', 1)
        try:
            a = int(parts[0])
            b = int(parts[1])
        except ValueError:
            raise ValueError(f"line 区间解析失败: {s!r}")
        if a < 1 or b < 1:
            raise ValueError(f"line 区间边界必须 ≥ 1: {s!r}")
        if a > b:
            raise ValueError(f"line 区间 start({a}) 不能大于 end({b})")
        return (a, b)

    raise ValueError(f"line 类型错误（应为 int 或 str）: {type(line_val).__name__}: {line_val!r}")


def is_strictly_before(t_range: LineRange, ref_range: LineRange) -> bool:
    """判断 t 是否严格在 ref 之前。"""
    return t_range[1] < ref_range[0]


def is_strictly_after(t_range: LineRange, ref_range: LineRange) -> bool:
    """判断 t 是否严格在 ref 之后。"""
    return t_range[0] > ref_range[1]


def is_overlapping(t_range: LineRange, ref_range: LineRange) -> bool:
    """判断两个行号范围是否重叠。"""
    return t_range[0] <= ref_range[1] and t_range[1] >= ref_range[0]
