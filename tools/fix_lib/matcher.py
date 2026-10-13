#!/usr/bin/env python3
"""
代码匹配与搜索模块
提供行内容规范化、单文件匹配、全仓库搜索等功能，带缓存机制。
"""
import os
from pathlib import Path
from typing import List, Dict, Union, Optional
from .config import IGNORE_DIRS, COMMON_EXTS

# ---------- 行规范化 ----------
def normalize_code_lines(code: str) -> List[str]:
    """
    将代码字符串拆分为行，并去除每行首尾空白（容忍缩进差异）。

    Args:
        code (str): 多行代码字符串

    Returns:
        List[str]: 每行 strip() 后的字符串列表
    """
    if not code:
        return []
    return [line.strip() for line in code.splitlines()]

def match_code_at(lines: List[str], start_idx: int, code_lines: List[str]) -> bool:
    """
    检查从 start_idx 开始是否逐行匹配 code_lines（仅比较 strip 后的内容）。

    Args:
        lines (List[str]): 文件的全部行（未 strip）
        start_idx (int): 起始行索引（0-based）
        code_lines (List[str]): 目标代码行列表（已 strip）

    Returns:
        bool: 是否完全匹配
    """
    if start_idx < 0 or start_idx + len(code_lines) > len(lines):
        return False
    for i, cline in enumerate(code_lines):
        if lines[start_idx + i].strip() != cline:
            return False
    return True

# ---------- 缓存型文件读取 ----------
def get_file_lines_local(file_path: Path, file_cache: Dict) -> Optional[List[str]]:
    """
    获取文件行内容，带缓存（缓存字典由调用者维护）。

    Args:
        file_path (Path): 文件路径
        file_cache (Dict): 缓存字典 {(str(file_path)): lines}

    Returns:
        Optional[List[str]]: 行列表，若读取失败返回 None
    """
    key = str(file_path)
    if key in file_cache:
        return file_cache[key]
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        file_cache[key] = lines
        return lines
    except:
        file_cache[key] = None
        return None

def find_matches_in_file_cached(file_path: Path,
                                code_lines: List[str],
                                file_cache: Dict,
                                match_cache: Dict) -> List[int]:
    """
    在单个文件中搜索 code_lines 的所有匹配位置，带缓存。

    Args:
        file_path (Path): 文件路径
        code_lines (List[str]): 目标代码行列表（已 strip）
        file_cache (Dict): 文件内容缓存
        match_cache (Dict): 匹配结果缓存，键为 (str(file_path), tuple(code_lines))

    Returns:
        List[int]: 匹配的起始行索引列表（0-based）
    """
    cache_key = (str(file_path), tuple(code_lines))
    if cache_key in match_cache:
        return match_cache[cache_key]

    lines = get_file_lines_local(file_path, file_cache)
    if lines is None:
        match_cache[cache_key] = []
        return []

    matches = []
    max_start = len(lines) - len(code_lines)
    for i in range(max_start + 1):
        if match_code_at(lines, i, code_lines):
            matches.append(i)
    match_cache[cache_key] = matches
    return matches

# ---------- 仓库级搜索（提前终止） ----------
def search_in_repo_local(repo_path: Path,
                         code_lines: List[str],
                         file_exts: set,
                         file_cache: Dict,
                         match_cache: Dict,
                         repo_search_cache: Dict) -> Union[Dict, str]:
    """
    在整个仓库中搜索 code_lines，忽略 IGNORE_DIRS 和二进制文件。
    一旦找到 ≥2 个匹配，立即返回 'MULTIPLE' 并缓存结果，避免继续扫描。

    Args:
        repo_path (Path): 仓库根目录
        code_lines (List[str]): 目标代码行列表（已 strip）
        file_exts (set): 允许的扩展名集合（如 {'.py', '.js'}）
        file_cache (Dict): 文件内容缓存
        match_cache (Dict): 单文件匹配缓存
        repo_search_cache (Dict): 仓库级搜索缓存

    Returns:
        Union[Dict, str]:
            - 若唯一匹配：返回 {rel_path: [line_indices]}
            - 若 ≥2 个匹配：返回 'MULTIPLE'
            - 若无匹配：返回 {}
    """
    ext_tuple = frozenset(file_exts) if file_exts else frozenset()
    cache_key = (tuple(code_lines), ext_tuple)
    if cache_key in repo_search_cache:
        cached = repo_search_cache[cache_key]
        if cached == 'MULTIPLE':
            return 'MULTIPLE'
        return cached

    matches = {}
    total_matches = 0

    for root, dirs, files in os.walk(repo_path):
        # 按固定顺序遍历保证确定性
        dirs.sort()
        files.sort()
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            file_path = Path(root) / file

            # 扩展名过滤
            if file_exts and file_path.suffix not in file_exts:
                continue

            # 跳过二进制文件（检测空字节）
            try:
                with open(file_path, 'rb') as f:
                    head = f.read(1024)
                    if b'\0' in head:
                        continue
            except:
                continue

            rel_path = str(file_path.relative_to(repo_path))
            m = find_matches_in_file_cached(file_path, code_lines, file_cache, match_cache)
            if m:
                matches[rel_path] = m
                total_matches += len(m)
                if total_matches >= 2:
                    repo_search_cache[cache_key] = 'MULTIPLE'
                    return 'MULTIPLE'

    if not matches:
        repo_search_cache[cache_key] = {}
        return {}
    else:
        repo_search_cache[cache_key] = matches
        return matches
