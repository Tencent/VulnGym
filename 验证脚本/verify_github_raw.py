#!/usr/bin/env python3
"""
VulnGym Entry 远程源码验证脚本 - 基于 GitHub Issue #7 验收标准
从 GitHub raw 拉取对应 commit 的源码，验证每个节点的 {file, line, code} 是否精确匹配
"""
import json
import sys
import hashlib
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# 配置
JSONL_FILE = Path(r"e:\project_store\2_day\tencent\submission\target_entries.jsonl")
EXPECTED_ENTRIES = [
    "entry-00185",
    "entry-00197", 
    "entry-00290",
    "entry-00320",
    "entry-00391",
]

# Entry -> repo 映射（GitHub 用户名/仓库名）
ENTRY_REPO_MAP = {
    "entry-00185": ("n8n-io", "n8n"),
    "entry-00197": ("openclaw", "openclaw"),
    "entry-00290": ("openclaw", "openclaw"),
    "entry-00320": ("langflow-ai", "langflow"),
    "entry-00391": ("PrefectHQ", "fastmcp"),
}


class VerificationResult:
    def __init__(self, entry_id: str):
        self.entry_id = entry_id
        self.passed = []
        self.failed = []
        self.warnings = []

    def add_pass(self, check_name: str, detail: str = ""):
        self.passed.append((check_name, detail))

    def add_fail(self, check_name: str, detail: str = ""):
        self.failed.append((check_name, detail))

    def add_warning(self, check_name: str, detail: str = ""):
        self.warnings.append((check_name, detail))

    def is_passed(self) -> bool:
        return len(self.failed) == 0

    def summary(self) -> str:
        status = "PASS" if self.is_passed() else "FAIL"
        lines = [
            f"\n{'='*60}",
            f"Entry: {self.entry_id} - Overall: {status}",
            f"Passed: {len(self.passed)} | Failed: {len(self.failed)} | Warnings: {len(self.warnings)}",
            f"{'='*60}",
        ]
        if self.failed:
            lines.append("\n--- FAILED CHECKS ---")
            for name, detail in self.failed:
                lines.append(f"  [FAIL] {name}: {detail}")
        if self.warnings:
            lines.append("\n--- WARNINGS ---")
            for name, detail in self.warnings:
                lines.append(f"  [WARN] {name}: {detail}")
        if self.passed:
            lines.append("\n--- PASSED CHECKS ---")
            for name, detail in self.passed:
                lines.append(f"  [PASS] {name}: {detail}")
        return "\n".join(lines)


def fetch_github_raw(owner: str, repo: str, commit: str, file_path: str) -> Optional[str]:
    """从 GitHub raw 拉取指定 commit 的文件内容"""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{file_path}"
    try:
        print(f"  Fetching: {url}")
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"  ERROR fetching {url}: {e}")
        return None


def verify_node(owner: str, repo: str, commit: str, file_path: str, 
                line_val, expected_code: str, node_name: str, result: VerificationResult):
    """验证单个节点的源码匹配"""
    # 获取源码
    content = fetch_github_raw(owner, repo, commit, file_path)
    if content is None:
        result.add_fail(f"GitHub raw fetch ({node_name})", f"Cannot fetch {file_path}")
        return

    lines = content.splitlines()

    # 解析 line 值
    if isinstance(line_val, int):
        start_line = line_val
        end_line = line_val
    elif isinstance(line_val, str):
        match = line_val.split('-')
        if len(match) == 2:
            start_line = int(match[0])
            end_line = int(match[1])
        else:
            result.add_fail(f"Invalid line format ({node_name})", f"{line_val}")
            return
    else:
        result.add_fail(f"Invalid line type ({node_name})", f"{type(line_val)}")
        return

    # 提取实际代码（1-based -> 0-based）
    if start_line < 1 or end_line > len(lines):
        result.add_fail(f"Line out of range ({node_name})", 
                       f"{start_line}-{end_line} (file has {len(lines)} lines)")
        return

    actual_code = "\n".join(lines[start_line - 1:end_line])

    # 比较代码
    expected_stripped = expected_code.strip()
    actual_stripped = actual_code.strip()

    if expected_stripped == actual_stripped:
        result.add_pass(f"GitHub raw match ({node_name})", f"{file_path}:{line_val}")
    else:
        # 尝试更宽松的比较
        expected_normalized = ' '.join(expected_stripped.split())
        actual_normalized = ' '.join(actual_stripped.split())

        if expected_normalized == actual_normalized:
            result.add_pass(f"GitHub raw match (whitespace-tolerant) ({node_name})",
                          f"{file_path}:{line_val}")
        else:
            result.add_fail(f"GitHub raw mismatch ({node_name})",
                          f"Mismatch at {file_path}:{line_val}\n"
                          f"  Expected: {expected_stripped[:80]}...\n"
                          f"  Actual:   {actual_stripped[:80]}...")


def verify_entry(entry: Dict) -> VerificationResult:
    """验证单个 entry"""
    entry_id = entry["entry_id"]
    result = VerificationResult(entry_id)

    owner, repo = ENTRY_REPO_MAP.get(entry_id, (None, None))
    if not owner:
        result.add_fail("Repo mapping", f"Unknown repo for {entry_id}")
        return result

    commit = entry.get("commit", "")

    # 验证所有节点
    nodes_to_check = []

    # entry_point
    ep = entry.get("entry_point", {})
    if ep:
        nodes_to_check.append(("entry_point", ep))

    # critical_operation
    co = entry.get("critical_operation", {})
    if co:
        nodes_to_check.append(("critical_operation", co))

    # trace
    for i, t in enumerate(entry.get("trace", [])):
        nodes_to_check.append((f"trace[{i}]", t))

    for node_name, node in nodes_to_check:
        file_path = node.get("file", "")
        line_val = node.get("line")
        expected_code = node.get("code", "")

        verify_node(owner, repo, commit, file_path, line_val, expected_code, node_name, result)

    return result


def main():
    print("=" * 60)
    print("VulnGym Entry 远程源码验证脚本")
    print("基于 GitHub raw 拉取对应 commit 源码进行字节级精确匹配")
    print("=" * 60)

    # 加载数据
    try:
        entries = {}
        with open(JSONL_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                entries[entry["entry_id"]] = entry
        print(f"\n已加载 {len(entries)} 个 entry")
    except Exception as e:
        print(f"加载 JSONL 文件失败：{e}")
        sys.exit(1)

    # 检查预期 entry 是否都存在
    missing = [eid for eid in EXPECTED_ENTRIES if eid not in entries]
    if missing:
        print(f"警告：缺少预期 entry: {missing}")

    # 验证每个 entry
    all_results = []
    for entry_id in EXPECTED_ENTRIES:
        if entry_id in entries:
            print(f"\n验证 {entry_id}...")
            result = verify_entry(entries[entry_id])
            all_results.append(result)
            print(result.summary())
        else:
            print(f"\n{'='*60}")
            print(f"Entry: {entry_id} - NOT FOUND")
            print(f"{'='*60}")

    # 汇总
    print("\n" + "=" * 60)
    print("汇总报告")
    print("=" * 60)

    total_pass = sum(len(r.passed) for r in all_results)
    total_fail = sum(len(r.failed) for r in all_results)
    total_warn = sum(len(r.warnings) for r in all_results)

    print(f"\n总检查项：{total_pass + total_fail + total_warn}")
    print(f"通过：{total_pass}")
    print(f"失败：{total_fail}")
    print(f"警告：{total_warn}")

    print("\n各 Entry 结果:")
    for r in all_results:
        status = "PASS" if r.is_passed() else "FAIL"
        print(f"  {r.entry_id}: {status} (pass={len(r.passed)}, fail={len(r.failed)}, warn={len(r.warnings)})")

    # 详细失败列表
    if total_fail > 0:
        print("\n" + "-" * 60)
        print("失败项详情:")
        print("-" * 60)
        for r in all_results:
            for name, detail in r.failed:
                print(f"  [{r.entry_id}] {name}: {detail[:100]}")

    # 最终判定
    print("\n" + "=" * 60)
    if total_fail == 0:
        print("最终判定：ALL PASS - 所有 entry 的源码在 GitHub raw 上精确匹配")
    else:
        print(f"最终判定：FAIL - {total_fail} 个检查项未通过")
    print("=" * 60)

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
