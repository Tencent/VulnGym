#!/usr/bin/env python3
"""
VulnGym Code Locator — 代码片段定位偏差自动修复工具
====================================================

根据 `Issue #4 <https://github.com/Tencent/VulnGym/issues/4>`_ 要求，
自动检测并修复 ``data/entries.jsonl`` 中 ``{file, line, code, desc}``
节点的定位偏差。

对每个 ``entry_point`` / ``critical_operation`` / ``trace[*]`` 节点:

1. 在对应仓库的对应 commit 检出源码，验证 ``code`` 是否出现在
   ``file:line`` 位置。
2. 若不匹配，按以下顺序尝试修复：
   - 在原始行号 **±5 行**范围内搜索 ``code``，命中唯一则修正 ``line``；
   - 在**原始文件全文**搜索 ``code``，命中唯一则修正 ``line``；
   - 在**整个仓库**搜索 ``code``，命中唯一则同时修正 ``file`` 和 ``line``。
3. 多处命中、完全找不到、或无法判断的节点写入 ``needs_human.csv``。
4. 修复后的数据写入 ``entries.fixed.jsonl``，逐条修改记录写入
   ``fix_diff.csv``。

用法::

    python tools/code_locator.py --mode dry-run           # 仅检测，生成报告
    python tools/code_locator.py --mode fix               # 检测并修复
    python tools/code_locator.py --mode fix --verify-filter 0  # 仅处理 verify=0

依赖:
    - Python ≥ 3.9
    - Git ≥ 2.30（需在 PATH 中可用）
    - 网络访问（用于 clone 仓库）

缓存:
    仓库默认缓存在 ``~/.cache/vulngym-repos/``，可通过 ``--cache-dir``
    自定义。同一仓库的不同 commit 共享同一个 clone，通过
    ``git fetch && git checkout`` 切换。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "entries.fixed.jsonl"
DEFAULT_FIX_DIFF = REPO_ROOT / "data" / "fix_diff.csv"
DEFAULT_NEEDS_HUMAN = REPO_ROOT / "data" / "needs_human.csv"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "vulngym-repos"

SEARCH_WINDOW = 5  # ± lines for nearby search

# 需要在每个 entry 中检查的字段路径（节点类型）
NODE_FIELDS = ["entry_point", "critical_operation"]


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def normalize_line(line_val) -> tuple[int, int]:
    """将 ``line`` 字段标准化为 ``(start, end)`` 整数元组。

    支持两种格式：
    - 整数 ``97`` → ``(97, 97)``
    - 范围字符串 ``"348-352"`` → ``(348, 352)``
    """
    if isinstance(line_val, int):
        return (line_val, line_val)
    if isinstance(line_val, str) and "-" in line_val:
        a, b = line_val.split("-", 1)
        return (int(a), int(b))
    n = int(line_val)
    return (n, n)


def format_line(line_val) -> str:
    """将 ``line`` 值格式化为字符串表示。"""
    if isinstance(line_val, int):
        return str(line_val)
    return str(line_val)


def _normalize_ws(text: str) -> str:
    """规范化空白字符用于代码比较。

    - 将制表符替换为空格（1 tab = 4 spaces，近似）
    - 折叠连续空格
    - 去除首尾空白
    """
    # Expand tabs to spaces (approximate; most TS/Python code uses 2-4 space tabs)
    text = text.expandtabs(4)
    # Collapse multiple spaces
    text = re.sub(r" +", " ", text)
    # Strip leading/trailing whitespace per line, then whole string
    lines = [l.strip() for l in text.splitlines()]
    return "\n".join(lines).strip()


def code_matches(needle: str, haystack: str) -> bool:
    """检查 ``needle`` 代码片段是否与 ``haystack`` 匹配。

    匹配规则：
    - 忽略首尾空白
    - 忽略制表符/空格差异
    - 忽略连续空格数量差异
    - 支持多行代码片段
    """
    return _normalize_ws(needle) == _normalize_ws(haystack)


def find_code_in_lines(
    needle: str, lines: list[str], start_line_1: int = 1
) -> list[int]:
    """在行列表中搜索 ``needle``，返回所有匹配的起始行号（1-indexed）。

    对于多行代码片段，返回匹配的第一行行号；对于单行代码，返回
    所有匹配行的行号。
    """
    needle_norm = _normalize_ws(needle)
    needle_lines = needle_norm.split("\n")
    num_needle_lines = len(needle_lines)

    matches: list[int] = []
    for i in range(len(lines) - num_needle_lines + 1):
        candidate_lines = lines[i : i + num_needle_lines]
        candidate_norm = _normalize_ws("\n".join(candidate_lines))
        if candidate_norm == needle_norm:
            matches.append(start_line_1 + i)
    return matches


def load_jsonl(path: str | Path) -> list[dict]:
    """读取 JSONL 文件，返回 list[dict]。"""
    entries: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def save_jsonl(entries: list[dict], path: str | Path) -> None:
    """将 entry 列表写入 JSONL 文件。"""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# 仓库管理
# ---------------------------------------------------------------------------


class RepoCache:
    """管理漏洞仓库的本地缓存。

    同一仓库的不同 commit 共享同一个 clone 目录。
    """

    def __init__(
        self,
        cache_dir: str | Path = DEFAULT_CACHE_DIR,
        skip_network: bool = False,
        git_timeout: int = 120,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.skip_network = skip_network
        self.git_timeout = git_timeout
        # {repo_url: local_path}
        self._repo_paths: dict[str, Path] = {}

    def _repo_name(self, repo_url: str) -> str:
        """从 URL 提取仓库目录名。"""
        # https://github.com/org/repo → org_repo
        name = repo_url.rstrip("/").rstrip(".git").split("github.com/")[-1]
        return name.replace("/", "_")

    def _repo_path(self, repo_url: str) -> Path:
        """获取仓库在缓存中的目录路径。"""
        return self.cache_dir / self._repo_name(repo_url)

    def ensure_commit(self, repo_url: str, commit: str) -> Optional[Path]:
        """确保仓库在指定 commit 处已检出。

        Returns
        -------
        Path 或 None
            仓库工作目录的路径；若无法获取则返回 None。
        """
        repo_path = self._repo_path(repo_url)

        # 检查是否已在目标 commit
        if (repo_path / ".git").exists():
            try:
                result = subprocess.run(
                    ["git", "-C", str(repo_path), "rev-parse", "--quiet", "--verify", commit + "^{commit}"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    # Commit 已在本地，直接 checkout
                    subprocess.run(
                        ["git", "-C", str(repo_path), "checkout", "--quiet", commit],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                    self._repo_paths[repo_url] = repo_path
                    return repo_path
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass  # 继续尝试

        # 如果禁止网络操作且仓库不存在/commit 不在本地
        if self.skip_network:
            if (repo_path / ".git").exists():
                # 仓库存在但 commit 不在本地，尝试 checkout（可能已存在）
                try:
                    subprocess.run(
                        ["git", "-C", str(repo_path), "checkout", "--quiet", commit],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                    self._repo_paths[repo_url] = repo_path
                    return repo_path
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
            print(f"  [跳过] --skip-clone 模式，仓库不可用: {repo_url}")
            return None

        # 需要网络操作
        if not (repo_path / ".git").exists():
            # 首次 clone（使用浅克隆以加速）
            print(f"  [clone] {repo_url} ...", flush=True)
            try:
                subprocess.run(
                    ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(repo_path)],
                    check=True,
                    capture_output=True,
                    timeout=self.git_timeout,
                )
                # 只 checkout 目标 commit
                subprocess.run(
                    ["git", "-C", str(repo_path), "checkout", "--quiet", commit],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as e:
                err = e.stderr.decode(errors="replace")[:200] if e.stderr else str(e)
                print(f"  [clone FAILED] {repo_url}: {err}")
                return None
            except subprocess.TimeoutExpired:
                print(f"  [clone TIMEOUT] {repo_url}")
                return None
        else:
            # 已有 clone，但 commit 不在本地，需要 fetch
            print(f"  [fetch] {repo_url} ...", flush=True)
            try:
                subprocess.run(
                    ["git", "-C", str(repo_path), "fetch", "--depth=1", "origin", commit],
                    check=True,
                    capture_output=True,
                    timeout=self.git_timeout,
                )
            except subprocess.CalledProcessError:
                # 浅克隆可能不支持 fetch 特定 commit，尝试 unshallow 后 fetch
                try:
                    subprocess.run(
                        ["git", "-C", str(repo_path), "fetch", "--unshallow"],
                        check=False,
                        capture_output=True,
                        timeout=self.git_timeout,
                    )
                except subprocess.TimeoutExpired:
                    pass
            except subprocess.TimeoutExpired:
                print(f"  [fetch TIMEOUT] {repo_url}")
                return None

            # 检出目标 commit
            try:
                subprocess.run(
                    ["git", "-C", str(repo_path), "checkout", "--quiet", commit],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as e:
                err = e.stderr.decode(errors="replace")[:200] if e.stderr else str(e)
                print(f"  [checkout FAILED] {repo_url} @ {commit[:12]}: {err}")
                return None
            except subprocess.TimeoutExpired:
                print(f"  [checkout TIMEOUT] {repo_url} @ {commit[:12]}")
                return None

        self._repo_paths[repo_url] = repo_path
        return repo_path

    def get_repo_path(self, repo_url: str) -> Optional[Path]:
        """返回已缓存的仓库路径（不执行 clone/fetch）。"""
        return self._repo_paths.get(repo_url)


# ---------------------------------------------------------------------------
# 代码搜索与修复
# ---------------------------------------------------------------------------


class CodeLocator:
    """在仓库源码中搜索代码片段并修正定位。"""

    def __init__(self, repo_cache: RepoCache):
        self.repo_cache = repo_cache

    def _read_file_lines(self, repo_path: Path, file: str) -> Optional[list[str]]:
        """读取仓库中指定文件的所有行。"""
        file_path = repo_path / file
        if not file_path.is_file():
            return None
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.readlines()
        except (OSError, UnicodeDecodeError):
            return None

    def verify_at_location(
        self, repo_path: Path, file: str, line_val, code: str
    ) -> bool:
        """验证 ``code`` 是否在 ``file:line`` 处匹配。

        对于多行代码，检查从 ``line`` 开始的多行是否匹配；
        对于范围行号，先扩展为行范围再检查。
        """
        lines = self._read_file_lines(repo_path, file)
        if lines is None:
            return False

        line_start, line_end = normalize_line(line_val)
        if line_start < 1 or line_start > len(lines):
            return False

        # 提取对应行范围
        if isinstance(line_val, int) or (isinstance(line_val, str) and "-" not in str(line_val)):
            # 单行 line，但 code 可能是多行的
            num_code_lines = len(code.split("\n"))
            extract_start = line_start - 1
            extract_end = extract_start + num_code_lines
        else:
            # 范围 line
            extract_start = line_start - 1
            extract_end = line_end

        if extract_end > len(lines):
            extract_end = len(lines)

        haystack = "".join(lines[extract_start:extract_end]).rstrip("\n").rstrip("\r")
        return code_matches(code, haystack)

    def search_nearby(
        self, repo_path: Path, file: str, line_val, code: str, window: int = SEARCH_WINDOW
    ) -> Optional[int]:
        """在原始行号 ±window 行内搜索 ``code``。

        Returns
        -------
        int 或 None
            唯一的匹配行号；无匹配或多处匹配返回 None。
        """
        lines = self._read_file_lines(repo_path, file)
        if lines is None:
            return None

        line_start, line_end = normalize_line(line_val)
        # 搜索窗口：[line_start - window, line_end + window]
        search_start = max(0, line_start - 1 - window)
        search_end = min(len(lines), line_end + window)

        window_lines = lines[search_start:search_end]
        matches = find_code_in_lines(code, window_lines, search_start + 1)

        if len(matches) == 1:
            return matches[0]
        return None

    def search_file(
        self, repo_path: Path, file: str, code: str
    ) -> Optional[int]:
        """在原始文件全文搜索 ``code``。

        Returns
        -------
        int 或 None
            唯一的匹配行号。
        """
        lines = self._read_file_lines(repo_path, file)
        if lines is None:
            return None

        matches = find_code_in_lines(code, lines, 1)
        if len(matches) == 1:
            return matches[0]
        return None

    def search_repo(
        self, repo_path: Path, code: str, exclude_file: Optional[str] = None
    ) -> Optional[tuple[str, int]]:
        """在整个仓库中搜索 ``code``。

        使用 ``git grep`` 进行高效搜索。

        Returns
        -------
        (file, line) 或 None
            唯一的匹配位置。
        """
        # 提取搜索关键词：使用 code 的第一行作为 grep 模式
        first_line = code.split("\n")[0].strip()
        if not first_line or len(first_line) < 3:
            return None

        # 转义特殊字符用于正则匹配
        # 简单处理：取一个足够有辨识度的子串
        search_str = first_line[:80]

        try:
            result = subprocess.run(
                [
                    "git", "-C", str(repo_path),
                    "grep", "-n", "-I", "--heading", "--break",
                    "-F", search_str,  # 固定字符串匹配
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return None

        if result.returncode not in (0, 1):
            return None

        # 解析 git grep 输出，收集所有匹配位置
        candidates: list[tuple[str, int]] = []
        current_file = None
        for line in result.stdout.splitlines():
            if not line:
                continue
            if not line.startswith(" "):  # 文件头
                current_file = line.rstrip(":")
                continue
            # 匹配行： "行号:内容"
            if current_file and ":" in line:
                try:
                    line_num_str = line.split(":", 1)[0].strip()
                    line_num = int(line_num_str)
                    candidates.append((current_file, line_num))
                except ValueError:
                    continue

        if not candidates:
            return None

        # 对每个候选位置验证完整 code 是否匹配
        verified: list[tuple[str, int]] = []
        for candidate_file, candidate_line in candidates:
            # 允许行号有 ±2 的偏差（git grep 找到的可能只是首行匹配）
            for offset in range(-2, 3):
                test_line = candidate_line + offset
                if test_line < 1:
                    continue
                if self.verify_at_location(repo_path, candidate_file, test_line, code):
                    verified.append((candidate_file, test_line))
                    break  # 每个候选文件只取第一个验证通过的位置

        # 去重
        unique = list(set(verified))
        if len(unique) == 1:
            return unique[0]
        return None

    def locate_code(
        self,
        repo_path: Path,
        file: str,
        line_val,
        code: str,
    ) -> dict[str, Any]:
        """尝试定位代码片段的正确位置。

        Parameters
        ----------
        repo_path : Path
            仓库工作目录路径。
        file : str
            当前声明的文件路径。
        line_val : int | str
            当前声明的行号。
        code : str
            要搜索的代码片段。

        Returns
        -------
        dict
            {
                "status": "ok" | "fixed_nearby" | "fixed_file" | "fixed_repo" | "needs_human",
                "file": str | None,     # 修正后的文件路径
                "line": int | None,     # 修正后的行号（1-indexed）
                "reason": str,          # 状态说明
            }
        """
        # 第一步：验证原始位置
        if self.verify_at_location(repo_path, file, line_val, code):
            return {
                "status": "ok",
                "file": file,
                "line": normalize_line(line_val)[0],
                "reason": "代码在原始位置匹配成功",
            }

        # 第二步：±5 行搜索
        nearby = self.search_nearby(repo_path, file, line_val, code)
        if nearby is not None:
            return {
                "status": "fixed_nearby",
                "file": file,
                "line": nearby,
                "reason": f"在原始行±{SEARCH_WINDOW}行内找到唯一匹配，行号 {format_line(line_val)} → {nearby}",
            }

        # 第三步：全文件搜索
        file_match = self.search_file(repo_path, file, code)
        if file_match is not None:
            return {
                "status": "fixed_file",
                "file": file,
                "line": file_match,
                "reason": f"在原始文件全文找到唯一匹配，行号 {format_line(line_val)} → {file_match}",
            }

        # 第四步：全仓库搜索
        repo_match = self.search_repo(repo_path, code, exclude_file=file)
        if repo_match is not None:
            new_file, new_line = repo_match
            return {
                "status": "fixed_repo",
                "file": new_file,
                "line": new_line,
                "reason": f"在全仓库找到唯一匹配，{file}:{format_line(line_val)} → {new_file}:{new_line}",
            }

        # 无法确定
        # 检查是"文件中找不到代码"还是"代码在多处出现"
        lines = self._read_file_lines(repo_path, file)
        if lines is not None:
            matches = find_code_in_lines(code, lines, 1)
            if len(matches) > 1:
                return {
                    "status": "needs_human",
                    "file": None,
                    "line": None,
                    "reason": f"代码在原文件中出现 {len(matches)} 次（行 {', '.join(map(str, matches[:5]))}{'...' if len(matches) > 5 else ''}），无法确定正确位置",
                }

        return {
            "status": "needs_human",
            "file": None,
            "line": None,
            "reason": "代码在仓库中未找到唯一匹配，可能需要人工判断",
        }


# ---------------------------------------------------------------------------
# desc 描述更新
# ---------------------------------------------------------------------------

def update_desc_for_location_change(
    desc: str,
    old_file: str,
    new_file: str,
    old_line_val,
    new_line: int,
) -> tuple[str, bool]:
    """当节点的 file 或 line 发生变化时，尝试更新 desc 中的引用。

    这是一个保守的更新策略：
    - 仅替换 desc 中明确出现的旧行号文本（如 "xxx.ts:97"）
    - 不尝试理解语义或改写句子

    Returns
    -------
    (updated_desc, changed) : (str, bool)
    """
    if not desc:
        return desc, False

    updated = desc
    changed = False

    old_line_str = format_line(old_line_val)
    new_line_str = str(new_line)

    # 替换 "filename:oldline" 模式
    old_location = f"{old_file}:{old_line_str}"
    new_location = f"{new_file}:{new_line_str}"
    if old_location in updated:
        updated = updated.replace(old_location, new_location)
        changed = True

    # 替换 "filename 第 oldline 行" 模式
    old_file_basename = old_file.split("/")[-1]
    new_file_basename = new_file.split("/")[-1] if new_file != old_file else old_file_basename

    for pattern in [
        f"{old_file_basename} 第 {old_line_str} 行",
        f"{old_file_basename} {old_line_str} 行",
        f"{old_file_basename} 的第 {old_line_str} 行",
    ]:
        replacement = pattern.replace(old_file_basename, new_file_basename).replace(
            old_line_str, new_line_str
        )
        if pattern in updated and pattern != replacement:
            updated = updated.replace(pattern, replacement)
            changed = True

    return updated, changed


# ---------------------------------------------------------------------------
# 单条 entry 处理
# ---------------------------------------------------------------------------


def process_entry(
    entry: dict,
    repo_path: Path,
    locator: CodeLocator,
    verify_filter: str = "all",
) -> tuple[dict, list[dict], list[dict]]:
    """处理单条 entry 的代码定位验证与修复。

    Parameters
    ----------
    entry : dict
        一条完整的 entry 记录。
    repo_path : Path
        已检出到目标 commit 的仓库路径。
    locator : CodeLocator
        代码搜索器实例。
    verify_filter : str
        ``"0"`` — 仅处理 verify=0; ``"1"`` — 仅处理 verify=1;
        ``"all"`` — 处理所有。

    Returns
    -------
    (fixed_entry, fix_logs, human_logs) : (dict, list[dict], list[dict])
    """
    if verify_filter != "all":
        if str(entry.get("verify", -1)) != verify_filter:
            return entry, [], []

    fix_logs: list[dict] = []
    human_logs: list[dict] = []
    fixed = deepcopy(entry)
    entry_id = entry["entry_id"]

    # 处理 entry_point 和 critical_operation
    for field_name in NODE_FIELDS:
        node = fixed[field_name]
        result = locator.locate_code(
            repo_path, node["file"], node["line"], node["code"]
        )

        if result["status"] == "ok":
            continue

        if result["status"].startswith("fixed_"):
            old_file = node["file"]
            old_line = node["line"]

            # 记录修改
            fix_logs.append({
                "entry_id": entry_id,
                "field_path": field_name,
                "change_type": result["status"],
                "old_file": old_file,
                "old_line": format_line(old_line),
                "new_file": result["file"],
                "new_line": str(result["line"]),
                "fix_reason": result["reason"],
                "old_code": node["code"][:120].replace("\n", "\\n"),
                "new_code": node["code"][:120].replace("\n", "\\n"),
            })

            # 应用修复
            node["file"] = result["file"]
            node["line"] = result["line"]

            # 更新 desc
            if "desc" in node:
                new_desc, desc_changed = update_desc_for_location_change(
                    node["desc"],
                    old_file,
                    result["file"],
                    old_line,
                    result["line"],
                )
                if desc_changed:
                    node["desc"] = new_desc
                    fix_logs[-1]["desc_updated"] = "true"
                else:
                    fix_logs[-1]["desc_updated"] = "false"
        else:
            # needs_human
            human_logs.append({
                "entry_id": entry_id,
                "field_path": field_name,
                "file": node["file"],
                "line": format_line(node["line"]),
                "code": node["code"][:200].replace("\n", "\\n"),
                "reason": result["reason"],
            })

    # 处理 trace 数组
    trace = fixed.get("trace", [])
    for i, node in enumerate(trace):
        result = locator.locate_code(
            repo_path, node["file"], node["line"], node["code"]
        )

        if result["status"] == "ok":
            continue

        if result["status"].startswith("fixed_"):
            old_file = node["file"]
            old_line = node["line"]

            fix_logs.append({
                "entry_id": entry_id,
                "field_path": f"trace[{i}]",
                "change_type": result["status"],
                "old_file": old_file,
                "old_line": format_line(old_line),
                "new_file": result["file"],
                "new_line": str(result["line"]),
                "fix_reason": result["reason"],
                "old_code": node["code"][:120].replace("\n", "\\n"),
                "new_code": node["code"][:120].replace("\n", "\\n"),
            })

            node["file"] = result["file"]
            node["line"] = result["line"]

            if "desc" in node:
                new_desc, desc_changed = update_desc_for_location_change(
                    node["desc"],
                    old_file,
                    result["file"],
                    old_line,
                    result["line"],
                )
                if desc_changed:
                    node["desc"] = new_desc
                    fix_logs[-1]["desc_updated"] = "true"
                else:
                    fix_logs[-1]["desc_updated"] = "false"
        else:
            human_logs.append({
                "entry_id": entry_id,
                "field_path": f"trace[{i}]",
                "file": node["file"],
                "line": format_line(node["line"]),
                "code": node["code"][:200].replace("\n", "\\n"),
                "reason": result["reason"],
            })

    return fixed, fix_logs, human_logs


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------


def save_fix_diff_csv(logs: list[dict], path: str | Path) -> None:
    """将修改日志写入 CSV 文件。"""
    fieldnames = [
        "entry_id", "field_path", "change_type", "old_file", "old_line",
        "new_file", "new_line", "fix_reason", "desc_updated",
        "old_code", "new_code",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(logs)


def save_needs_human_csv(logs: list[dict], path: str | Path) -> None:
    """将人工复核日志写入 CSV 文件。"""
    fieldnames = ["entry_id", "field_path", "file", "line", "code", "reason"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(logs)


def generate_report(
    total_entries: int,
    fix_logs: list[dict],
    human_logs: list[dict],
    mode: str,
    verify_filter: str,
    start_time: float,
) -> dict:
    """生成统计摘要报告。"""
    change_types: dict[str, int] = defaultdict(int)
    affected_entries: set[str] = set()
    fixed_entries: set[str] = set()
    human_entries: set[str] = set()

    for log in fix_logs:
        change_types[log["change_type"]] += 1
        fixed_entries.add(log["entry_id"])
        affected_entries.add(log["entry_id"])

    for log in human_logs:
        human_entries.add(log["entry_id"])
        affected_entries.add(log["entry_id"])

    elapsed = time.time() - start_time

    return {
        "run_time": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "verify_filter": verify_filter,
        "elapsed_seconds": round(elapsed, 1),
        "total_entries_scanned": total_entries,
        "total_fixes": len(fix_logs),
        "fixed_entries_count": len(fixed_entries),
        "fixed_entry_ids": sorted(fixed_entries),
        "total_needs_human": len(human_logs),
        "human_entries_count": len(human_entries),
        "human_entry_ids": sorted(human_entries),
        "change_type_counts": dict(change_types),
        "total_affected_entries": len(affected_entries),
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def validate_entry(entry: dict, index: int) -> list[str]:
    """验证修复后的 entry 是否满足 SCHEMA.md 基本约束。"""
    errors: list[str] = []

    required = [
        "entry_id", "report_id", "source_link", "vuln_ids", "origin",
        "project", "repo_url", "commit", "vuln_title",
        "vuln_category_l1", "vuln_category_l2",
        "entry_point", "critical_operation", "trace", "verify",
    ]
    for field in required:
        if field not in entry:
            errors.append(f"缺少必填字段 {field}")

    if entry.get("verify") not in (0, 1):
        errors.append(f"verify 字段值无效: {entry.get('verify')}")

    commit = entry.get("commit", "")
    if not (isinstance(commit, str) and len(commit) == 40 and all(c in "0123456789abcdef" for c in commit)):
        errors.append(f"commit 格式异常: {commit}")

    repo = entry.get("repo_url", "")
    if not repo.startswith("https://github.com/"):
        errors.append(f"repo_url 格式异常: {repo}")

    for field_name in NODE_FIELDS + ["trace"]:
        items = [entry.get(field_name)] if field_name != "trace" else entry.get("trace", [])
        if field_name != "trace" and not items[0]:
            continue
        for i, node in enumerate(items):
            if not node:
                continue
            for key in ("file", "line", "code"):
                if key not in node:
                    field_label = field_name if field_name != "trace" else f"trace[{i}]"
                    errors.append(f"{field_label} 缺少必填键 '{key}'")
            if "line" in node:
                try:
                    s, e = normalize_line(node["line"])
                    if s < 1 or e < s:
                        field_label = field_name if field_name != "trace" else f"trace[{i}]"
                        errors.append(f"{field_label}.line 范围无效: {node['line']}")
                except (ValueError, TypeError):
                    field_label = field_name if field_name != "trace" else f"trace[{i}]"
                    errors.append(f"{field_label}.line 格式无法解析: {node['line']}")

    return errors


def print_report(report: dict) -> None:
    """在终端打印统计摘要。"""
    print()
    print("=" * 60)
    print("  VulnGym Code Locator — 修复报告")
    print("=" * 60)
    print(f"  运行模式:         {report['mode']}")
    print(f"  verify 过滤:      {report['verify_filter']}")
    print(f"  扫描 entry 总数:  {report['total_entries_scanned']}")
    print(f"  耗时:             {report['elapsed_seconds']:.1f} 秒")
    print(f"  自动修复:         {report['total_fixes']} 处 ({report['fixed_entries_count']} 条 entry)")
    for ct, count in sorted(report["change_type_counts"].items()):
        print(f"    - {ct}: {count}")
    print(f"  需人工复核:       {report['total_needs_human']} 处 ({report['human_entries_count']} 条 entry)")
    print("=" * 60)
    print()


def main() -> int:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="VulnGym Code Locator — 代码片段定位偏差自动修复",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python tools/code_locator.py --mode dry-run
  python tools/code_locator.py --mode fix
  python tools/code_locator.py --mode fix --verify-filter 0
  python tools/code_locator.py --mode fix --cache-dir /tmp/vulngym-cache
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["dry-run", "fix"],
        default="dry-run",
        help="运行模式：dry-run=仅检测，fix=检测并修复（默认: dry-run）",
    )
    parser.add_argument(
        "--input",
        type=str,
        default=str(DEFAULT_INPUT),
        help=f"输入 JSONL 文件路径（默认: {DEFAULT_INPUT.relative_to(REPO_ROOT) if DEFAULT_INPUT.is_relative_to(REPO_ROOT) else DEFAULT_INPUT}）",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_OUTPUT),
        help=f"修复后输出路径（默认: {DEFAULT_OUTPUT.relative_to(REPO_ROOT) if DEFAULT_OUTPUT.is_relative_to(REPO_ROOT) else DEFAULT_OUTPUT}，仅 fix 模式生效）",
    )
    parser.add_argument(
        "--fix-diff",
        type=str,
        default=str(DEFAULT_FIX_DIFF),
        help=f"修改对比 CSV 输出路径（默认: {DEFAULT_FIX_DIFF.relative_to(REPO_ROOT) if DEFAULT_FIX_DIFF.is_relative_to(REPO_ROOT) else DEFAULT_FIX_DIFF}）",
    )
    parser.add_argument(
        "--needs-human",
        type=str,
        default=str(DEFAULT_NEEDS_HUMAN),
        help=f"人工复核 CSV 输出路径（默认: {DEFAULT_NEEDS_HUMAN.relative_to(REPO_ROOT) if DEFAULT_NEEDS_HUMAN.is_relative_to(REPO_ROOT) else DEFAULT_NEEDS_HUMAN}）",
    )
    parser.add_argument(
        "--verify-filter",
        choices=["0", "1", "all"],
        default="all",
        help="按 verify 字段过滤：0=仅未校验，1=仅已校验，all=全部（默认: all）",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default=str(DEFAULT_CACHE_DIR),
        help=f"仓库缓存目录（默认: {DEFAULT_CACHE_DIR}）",
    )
    parser.add_argument(
        "--skip-clone",
        action="store_true",
        help="跳过 clone，仅使用已缓存的仓库（用于离线模式）",
    )
    parser.add_argument(
        "--entry-id",
        type=str,
        default=None,
        help="仅处理指定的 entry_id（用于调试）",
    )
    parser.add_argument(
        "--git-timeout",
        type=int,
        default=120,
        help="Git 操作超时秒数（默认: 120）",
    )
    args = parser.parse_args()

    # 路径处理
    input_path = Path(args.input)
    output_path = Path(args.output)
    fix_diff_path = Path(args.fix_diff)
    needs_human_path = Path(args.needs_human)
    cache_dir = Path(args.cache_dir)

    # ------------------------------------------------------------------
    # 读取输入
    # ------------------------------------------------------------------
    if not input_path.exists():
        print(f"[错误] 找不到输入文件: {input_path}")
        return 1

    print(f"[信息] 读取数据: {input_path}")
    entries = load_jsonl(input_path)
    total = len(entries)
    print(f"[信息] 共 {total} 条 entry")

    # 过滤特定 entry_id
    if args.entry_id:
        entries = [e for e in entries if e["entry_id"] == args.entry_id]
        if not entries:
            print(f"[错误] 找不到 entry_id={args.entry_id}")
            return 1
        print(f"[信息] 过滤后: {len(entries)} 条 entry")

    # ------------------------------------------------------------------
    # 按 (repo_url, commit) 分组
    # ------------------------------------------------------------------
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for entry in entries:
        key = (entry["repo_url"], entry["commit"])
        groups[key].append(entry)

    print(f"[信息] 共 {len(groups)} 个唯一 (repo, commit) 组合")

    # ------------------------------------------------------------------
    # 初始化
    # ------------------------------------------------------------------
    repo_cache = RepoCache(cache_dir, skip_network=args.skip_clone, git_timeout=args.git_timeout)
    locator = CodeLocator(repo_cache)

    all_fix_logs: list[dict] = []
    all_human_logs: list[dict] = []
    fixed_entries: list[dict] = []
    validation_errors: list[str] = []
    skipped_repos: set[str] = set()

    start_time = time.time()
    repo_count = 0
    total_entry_count = 0

    # ------------------------------------------------------------------
    # 逐仓库处理
    # ------------------------------------------------------------------
    for (repo_url, commit), group_entries in sorted(groups.items()):
        repo_count += 1
        total_entry_count += len(group_entries)
        eids = ", ".join(e["entry_id"] for e in group_entries[:5])
        if len(group_entries) > 5:
            eids += f" ... (+{len(group_entries) - 5})"

        print(f"\n[{repo_count}/{len(groups)}] {repo_url.split('github.com/')[-1]} "
              f"@ {commit[:12]} ({len(group_entries)} entries)")

        # 获取仓库
        repo_path = repo_cache.ensure_commit(repo_url, commit)
        if repo_path is None:
            skipped_repos.add(repo_url)
            # 将所有 entry 标记为 needs_human
            for entry in group_entries:
                eid = entry["entry_id"]
                for field_name in NODE_FIELDS:
                    node = entry[field_name]
                    all_human_logs.append({
                        "entry_id": eid,
                        "field_path": field_name,
                        "file": node["file"],
                        "line": format_line(node["line"]),
                        "code": node["code"][:200].replace("\n", "\\n"),
                        "reason": "仓库无法获取（clone/checkout 失败）",
                    })
                for i, node in enumerate(entry.get("trace", [])):
                    all_human_logs.append({
                        "entry_id": eid,
                        "field_path": f"trace[{i}]",
                        "file": node["file"],
                        "line": format_line(node["line"]),
                        "code": node["code"][:200].replace("\n", "\\n"),
                        "reason": "仓库无法获取（clone/checkout 失败）",
                    })
                # 保持原始 entry
                if args.mode == "fix":
                    fixed_entries.append(deepcopy(entry))
            print(f"  [跳过] 仓库不可用，{len(group_entries)} 条 entry 进入人工复核")
            continue

        # 处理组内每条 entry
        for entry in group_entries:
            fixed, fix_logs, human_logs = process_entry(
                entry, repo_path, locator, args.verify_filter
            )

            if args.mode == "fix":
                fixed_entries.append(fixed)
                errs = validate_entry(fixed, 0)
                if errs:
                    for e in errs:
                        validation_errors.append(f"{fixed['entry_id']}: {e}")

            all_fix_logs.extend(fix_logs)
            all_human_logs.extend(human_logs)

        # 进度报告
        fixes_this_round = sum(
            1 for l in all_fix_logs
            if any(e["entry_id"] == l["entry_id"] for e in group_entries)
        )
        if fixes_this_round:
            print(f"  修复: {fixes_this_round} 处")

    # ------------------------------------------------------------------
    # 输出
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time

    # 修复数据
    if args.mode == "fix" and fixed_entries:
        save_jsonl(fixed_entries, output_path)
        print(f"\n[信息] 修复后数据已写入: {output_path}")

        if validation_errors:
            print(f"[警告] 验证发现 {len(validation_errors)} 个问题:")
            for err in validation_errors[:10]:
                print(f"  - {err}")
            if len(validation_errors) > 10:
                print(f"  ... 还有 {len(validation_errors) - 10} 个")
        else:
            print("[信息] 所有修复后数据通过 SCHEMA.md 基础约束验证 [OK]")

    if args.mode == "dry-run":
        print(f"\n[信息] 仅检测模式 —— 不产生修复后数据文件。")

    # 修改日志
    if all_fix_logs:
        save_fix_diff_csv(all_fix_logs, fix_diff_path)
        print(f"[信息] 修改日志已写入: {fix_diff_path} ({len(all_fix_logs)} 条)")
    else:
        print("[信息] 未检测到可自动修复的定位偏差")
        save_fix_diff_csv(all_fix_logs, fix_diff_path)

    # 人工复核
    if all_human_logs:
        save_needs_human_csv(all_human_logs, needs_human_path)
        print(f"[信息] 人工复核清单已写入: {needs_human_path} ({len(all_human_logs)} 条)")
    else:
        save_needs_human_csv(all_human_logs, needs_human_path)

    if skipped_repos:
        print(f"[信息] 无法获取的仓库 ({len(skipped_repos)} 个):")
        for r in sorted(skipped_repos):
            print(f"  - {r}")

    # 报告
    report = generate_report(
        total_entries=len(entries),
        fix_logs=all_fix_logs,
        human_logs=all_human_logs,
        mode=args.mode,
        verify_filter=args.verify_filter,
        start_time=start_time,
    )
    report["skipped_repos"] = len(skipped_repos)

    report_path = Path(args.cache_dir) / "code_locator_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[信息] 统计报告已写入: {report_path}")

    print_report(report)

    if args.mode == "dry-run" and all_fix_logs:
        print("  提示: 当前为 dry-run 模式，仅记录了可修复项。")
        print("  如需自动修复，请运行:")
        print("    python tools/code_locator.py --mode fix")

    return 0


if __name__ == "__main__":
    sys.exit(main())
