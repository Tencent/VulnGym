from typing import Tuple, Union


def parse_line(line: Union[int, str]) -> Union[int, Tuple[int, int]]:
    """
    解析 trace 中的 line 字段
    支持：
    - int: 123
    - str: "123-130"
    """
    if isinstance(line, int):
        return line

    if isinstance(line, str):
        if "-" in line:
            start, end = map(int, line.split("-"))
            return start, end

    raise ValueError(f"Unsupported line format: {line}")