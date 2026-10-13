#!/usr/bin/env python3
"""
数据读写与输出模块
负责读取 JSONL、写入 JSONL 和 CSV 文件。
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any

def read_entries(file_path: Path) -> List[Dict[str, Any]]:
    """
    读取 JSONL 文件，每行一个 JSON 对象。

    Args:
        file_path (Path): 文件路径

    Returns:
        List[Dict]: 所有 entry 对象列表
    """
    entries = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries

def write_jsonl(file_path: Path, data: List[Dict]) -> None:
    """
    将数据列表逐行写入 JSONL 文件。

    Args:
        file_path (Path): 输出路径
        data (List[Dict]): 要写入的 entry 列表（顺序与索引对应）
    """
    with open(file_path, 'w', encoding='utf-8') as f:
        for item in data:
            if item is not None:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')

def write_csv(file_path: Path, fieldnames: List[str], rows: List[Dict]) -> None:
    """
    写入 CSV 文件（使用 utf-8-sig 编码支持 Excel 中文）。

    Args:
        file_path (Path): 输出路径
        fieldnames (List[str]): CSV 列名
        rows (List[Dict]): 数据行列表
    """
    if not rows:
        return
    with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
