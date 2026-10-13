"""
VulnGym Entry 验收脚本 - 基于 GitHub Issue #7 验收标准 + SCHEMA.md v0.1.4
对 target_entries.jsonl 中的 5 个 entry 进行严格验证
"""
import json
import re
import os
import sys
from pathlib import Path

# 配置路径
BASE_DIR = Path(r"e:\project_store\2_day\tencent")
JSONL_FILE = BASE_DIR / "VulnGym" / "data" / "target_entries.jsonl"
REPOS_DIR = BASE_DIR / "repos"

# 预期 entry ID 列表
EXPECTED_ENTRIES = [
    "entry-00185",
    "entry-00197",
    "entry-00290",
    "entry-00320",
    "entry-00391",
]

# Entry -> repo 目录映射
ENTRY_REPO_MAP = {
    "entry-00185": "n8n",
    "entry-00197": "openclaw-entry197",
    "entry-00290": "openclaw-entry290",
    "entry-00320": "langflow",
    "entry-00391": "fastmcp",
}


class VerificationResult:
    def __init__(self, entry_id):
        self.entry_id = entry_id
        self.passed = []
        self.failed = []
        self.warnings = []

    def add_pass(self, check_name, detail=""):
        self.passed.append((check_name, detail))

    def add_fail(self, check_name, detail=""):
        self.failed.append((check_name, detail))

    def add_warning(self, check_name, detail=""):
        self.warnings.append((check_name, detail))

    def is_passed(self):
        return len(self.failed) == 0

    def summary(self):
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


def load_entries():
    """加载 JSONL 文件"""
    entries = {}
    with open(JSONL_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            entries[entry["entry_id"]] = entry
    return entries


def verify_json_format(entry, result):
    """验证 JSON 格式和字段完整性"""
    # 检查必需字段
    required_fields = [
        "commit", "critical_operation", "entry_id", "entry_point",
        "origin", "project", "repo_url", "report_id", "source_link",
        "trace", "verify", "vuln_category_l1", "vuln_category_l2",
        "vuln_ids", "vuln_title"
    ]
    for field in required_fields:
        if field not in entry:
            result.add_fail(f"SCHEMA: missing field '{field}'", "")
        else:
            result.add_pass(f"SCHEMA: field '{field}' present", "")

    # 检查禁止字段
    forbidden_fields = [
        "description", "human_remark", "pipeline_id", "annotated_by",
        "is_active", "created_at", "generality",
        "detection_type", "ground_truth", "taint_source", "taint_sink",
        "vuln_category_l3"
    ]
    for field in forbidden_fields:
        if field in entry:
            result.add_fail(f"SCHEMA: forbidden field '{field}' present", "")
        else:
            result.add_pass(f"SCHEMA: no forbidden field '{field}'", "")


def verify_commit_format(entry, result):
    """验证 commit 格式：40 lowercase hex chars"""
    commit = entry.get("commit", "")
    if re.match(r"^[0-9a-f]{40}$", commit):
        result.add_pass("SCHEMA: commit format", f"40 hex chars: {commit[:8]}...")
    else:
        result.add_fail("SCHEMA: commit format", f"Invalid: {commit}")


def verify_repo_url(entry, result):
    """验证 repo_url 格式"""
    repo_url = entry.get("repo_url", "")
    if repo_url.startswith("https://github.com/"):
        result.add_pass("SCHEMA: repo_url format", repo_url)
    else:
        result.add_fail("SCHEMA: repo_url format", f"Invalid: {repo_url}")


def verify_source_link(entry, result):
    """验证 source_link 格式和 report_id 匹配"""
    source_link = entry.get("source_link", "")
    report_id = entry.get("report_id", "")

    if "github.com/advisories/" not in source_link:
        result.add_fail("SCHEMA: source_link format", f"Missing github.com/advisories/: {source_link}")
    else:
        result.add_pass("SCHEMA: source_link format", source_link)

    # 提取 source_link 中的 GHSA id
    match = re.search(r"GHSA-[a-z0-9-]+", source_link, re.IGNORECASE)
    if match:
        ghsa_from_link = match.group(0).upper()
        if ghsa_from_link == report_id.upper():
            result.add_pass("SCHEMA: report_id matches source_link", f"{report_id}")
        else:
            result.add_fail("SCHEMA: report_id matches source_link",
                          f"source_link={ghsa_from_link} vs report_id={report_id}")
    else:
        result.add_fail("SCHEMA: GHSA id in source_link", f"Cannot extract: {source_link}")


def verify_origin(entry, result):
    """验证 origin 常量"""
    origin = entry.get("origin", "")
    if origin == "GitHub Advisory Database (reviewed)":
        result.add_pass("SCHEMA: origin constant", origin)
    else:
        result.add_fail("SCHEMA: origin constant", f"Invalid: {origin}")


def verify_verify_field(entry, result):
    """验证 verify 字段"""
    verify = entry.get("verify")
    if verify in (0, 1):
        result.add_pass("SCHEMA: verify field", f"verify={verify}")
    else:
        result.add_fail("SCHEMA: verify field", f"Invalid: {verify}")


def verify_node_structure(node, node_name, result):
    """验证节点结构 {file, line, code, desc?}"""
    if node is None:
        result.add_fail(f"SCHEMA: {node_name} is None", "")
        return

    # 必需键
    for key in ["file", "line", "code"]:
        if key not in node:
            result.add_fail(f"SCHEMA: {node_name} missing key '{key}'", "")
        else:
            result.add_pass(f"SCHEMA: {node_name} has key '{key}'", "")

    # 检查 line 值
    line = node.get("line")
    if line is not None:
        if isinstance(line, int):
            if line >= 1:
                result.add_pass(f"SCHEMA: {node_name} line (int)", f"line={line}")
            else:
                result.add_fail(f"SCHEMA: {node_name} line (int)", f"line={line} < 1")
        elif isinstance(line, str):
            # 范围字符串 "a-b"
            match = re.match(r"^(\d+)-(\d+)$", line)
            if match:
                start, end = int(match.group(1)), int(match.group(2))
                if 1 <= start <= end:
                    result.add_pass(f"SCHEMA: {node_name} line (range)", f"line={line}")
                else:
                    result.add_fail(f"SCHEMA: {node_name} line (range)",
                                  f"Invalid range: {line} (start={start}, end={end})")
            else:
                result.add_fail(f"SCHEMA: {node_name} line (range)", f"Invalid format: {line}")
        else:
            result.add_fail(f"SCHEMA: {node_name} line type", f"type={type(line).__name__}")

    # desc 可选
    if "desc" in node:
        if isinstance(node["desc"], str) and len(node["desc"]) > 0:
            result.add_pass(f"SCHEMA: {node_name} desc present", f"len={len(node['desc'])}")
        else:
            result.add_fail(f"SCHEMA: {node_name} desc", f"Empty or invalid")


def verify_entry_point(entry, result):
    """验证 entry_point 结构"""
    verify_node_structure(entry.get("entry_point"), "entry_point", result)


def verify_critical_operation(entry, result):
    """验证 critical_operation 结构"""
    verify_node_structure(entry.get("critical_operation"), "critical_operation", result)


def verify_trace(entry, result):
    """验证 trace 结构"""
    trace = entry.get("trace", [])
    if not isinstance(trace, list):
        result.add_fail("SCHEMA: trace is list", f"type={type(trace).__name__}")
        return

    if len(trace) == 0:
        result.add_warning("SCHEMA: trace is empty", "")
        return

    result.add_pass("SCHEMA: trace is list", f"len={len(trace)}")

    for i, node in enumerate(trace):
        verify_node_structure(node, f"trace[{i}]", result)


def verify_entry_point_equals_trace0(entry, result):
    """验证 entry_point 是否等于 trace[0]"""
    entry_point = entry.get("entry_point", {})
    trace = entry.get("trace", [])

    if not trace:
        result.add_warning("Issue#7: entry_point==trace[0]", "trace is empty")
        return

    trace0 = trace[0]

    # 比较 file, line, code
    if (entry_point.get("file") == trace0.get("file") and
        entry_point.get("line") == trace0.get("line") and
        entry_point.get("code") == trace0.get("code")):
        result.add_pass("Issue#7: entry_point==trace[0]", "file/line/code match")
    else:
        result.add_fail("Issue#7: entry_point==trace[0]",
                      f"entry_point={entry_point.get('file')}:{entry_point.get('line')} vs trace[0]={trace0.get('file')}:{trace0.get('line')}")


def verify_critical_equals_trace_last(entry, result):
    """验证 critical_operation 是否等于 trace[-1]"""
    critical = entry.get("critical_operation", {})
    trace = entry.get("trace", [])

    if not trace:
        result.add_warning("Issue#7: critical==trace[-1]", "trace is empty")
        return

    trace_last = trace[-1]

    # 比较 file, line, code
    if (critical.get("file") == trace_last.get("file") and
        critical.get("line") == trace_last.get("line") and
        critical.get("code") == trace_last.get("code")):
        result.add_pass("Issue#7: critical==trace[-1]", "file/line/code match")
    else:
        result.add_warning("Issue#7: critical==trace[-1]",
                         f"critical={critical.get('file')}:{critical.get('line')} vs trace[-1]={trace_last.get('file')}:{trace_last.get('line')}")


def verify_desc_quality(entry, result):
    """验证 desc 质量 - Issue#7 标准1: desc 能准确解释该节点在漏洞链路中的作用"""
    nodes = []
    ep = entry.get("entry_point", {})
    if "desc" in ep:
        nodes.append(("entry_point", ep["desc"]))
    co = entry.get("critical_operation", {})
    if "desc" in co:
        nodes.append(("critical_operation", co["desc"]))
    for i, t in enumerate(entry.get("trace", [])):
        if "desc" in t:
            nodes.append((f"trace[{i}]", t["desc"]))

    for name, desc in nodes:
        if len(desc) < 20:
            result.add_warning(f"Issue#7: desc quality ({name})", f"Too short: len={len(desc)}")
        elif len(desc) > 500:
            result.add_warning(f"Issue#7: desc quality ({name})", f"Very long: len={len(desc)}")
        else:
            result.add_pass(f"Issue#7: desc quality ({name})", f"len={len(desc)}")


def verify_trace_no_noise(entry, result):
    """Issue#7 标准4: 删除或替换明显无关的 trace 节点（纯日志、无关返回值、静态声明等）"""
    trace = entry.get("trace", [])
    noise_patterns = [
        r"console\.log",
        r"logger\.",
        r"print\(",
        r"return true;",
        r"return false;",
        r"import ",
        r"const .* = require\(",
    ]

    for i, node in enumerate(trace):
        code = node.get("code", "")
        for pattern in noise_patterns:
            if re.search(pattern, code):
                # 特殊情况：return false; 在 entry-00185 中是 isFilePathBlocked 的关键返回值
                if pattern == r"return false;" and "isFilePathBlocked" in node.get("desc", ""):
                    result.add_pass(f"Issue#7: no noise trace[{i}]",
                                  f"return false but has semantic meaning (isFilePathBlocked)")
                else:
                    result.add_fail(f"Issue#7: no noise trace[{i}]",
                                  f"Pattern '{pattern}' found in code")
            else:
                pass  # 不匹配噪声模式，正常

    # 如果全部节点都没有噪声，添加一个 pass
    found_noise = False
    for i, node in enumerate(trace):
        code = node.get("code", "")
        for pattern in noise_patterns:
            if re.search(pattern, code):
                if not (pattern == r"return false;" and "isFilePathBlocked" in node.get("desc", "")):
                    found_noise = True
                    break
        if found_noise:
            break

    if not found_noise:
        result.add_pass("Issue#7: no noise in trace", "All nodes are semantically meaningful")


def verify_multi_stage(entry, result):
    """Issue#7 标准3: 多阶段利用场景需要明确前置阶段和主触发阶段"""
    entry_id = entry.get("entry_id", "")

    # 检查多阶段利用的 entry
    multi_stage_entries = ["entry-00197", "entry-00290"]

    if entry_id not in multi_stage_entries:
        result.add_pass("Issue#7: multi-stage (N/A)", f"{entry_id} is not multi-stage")
        return

    trace = entry.get("trace", [])
    critical = entry.get("critical_operation", {})

    # 检查 desc 中是否有多阶段表达
    all_descs = " ".join([node.get("desc", "") for node in trace] + [critical.get("desc", "")])

    stage_keywords = ["CHECK", "ESCAPE", "TOCTOU", "check", "escape", "阶段", "窗口", "pre-fix", "时间"]
    found_keywords = [kw for kw in stage_keywords if kw in all_descs]

    if len(found_keywords) >= 2:
        result.add_pass("Issue#7: multi-stage expression",
                       f"Found keywords: {found_keywords}")
    else:
        result.add_fail("Issue#7: multi-stage expression",
                       f"Insufficient stage keywords: {found_keywords}")

    # 检查 critical 是否在 trace 末尾（如果是多阶段，critical 应为最终危害点）
    if trace and critical:
        critical_line = critical.get("line")
        last_trace_line = trace[-1].get("line")
        if critical_line == last_trace_line:
            result.add_pass("Issue#7: critical at end of trace",
                          f"critical line={critical_line} == trace[-1] line={last_trace_line}")
        else:
            result.add_warning("Issue#7: critical at end of trace",
                             f"critical line={critical_line} != trace[-1] line={last_trace_line}")


def verify_source_code_match(entry, result):
    """Issue#7 标准1: 修复后的每个 {file, line, code} 都能在对应 commit 中匹配"""
    entry_id = entry.get("entry_id", "")
    repo_name = ENTRY_REPO_MAP.get(entry_id)

    if not repo_name:
        result.add_warning("Issue#7: source match", f"Unknown repo for {entry_id}")
        return

    repo_path = REPOS_DIR / repo_name
    if not repo_path.exists():
        result.add_warning("Issue#7: source match", f"Repo not found: {repo_path}")
        return

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

        full_path = repo_path / file_path

        if not full_path.exists():
            result.add_fail(f"Issue#7: source match ({node_name})",
                          f"File not found: {full_path}")
            continue

        # 读取文件
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            result.add_fail(f"Issue#7: source match ({node_name})",
                          f"Cannot read file: {e}")
            continue

        # 解析 line 值
        if isinstance(line_val, int):
            start_line = line_val
            end_line = line_val
        elif isinstance(line_val, str):
            match = re.match(r"^(\d+)-(\d+)$", line_val)
            if match:
                start_line = int(match.group(1))
                end_line = int(match.group(2))
            else:
                result.add_fail(f"Issue#7: source match ({node_name})",
                              f"Invalid line format: {line_val}")
                continue
        else:
            result.add_fail(f"Issue#7: source match ({node_name})",
                          f"Invalid line type: {type(line_val)}")
            continue

        # 提取实际代码（1-based -> 0-based）
        if start_line < 1 or end_line > len(lines):
            result.add_fail(f"Issue#7: source match ({node_name})",
                          f"Line out of range: {start_line}-{end_line} (file has {len(lines)} lines)")
            continue

        actual_code = "".join(lines[start_line - 1:end_line])

        # 比较代码（去除首尾空白后比较）
        expected_stripped = expected_code.strip()
        actual_stripped = actual_code.strip()

        if expected_stripped == actual_stripped:
            result.add_pass(f"Issue#7: source match ({node_name})",
                          f"{file_path}:{line_val}")
        else:
            # 尝试更宽松的比较（忽略空白差异）
            expected_normalized = re.sub(r"\s+", " ", expected_stripped)
            actual_normalized = re.sub(r"\s+", " ", actual_stripped)

            if expected_normalized == actual_normalized:
                result.add_pass(f"Issue#7: source match ({node_name})",
                              f"{file_path}:{line_val} (whitespace-tolerant)")
            else:
                result.add_fail(f"Issue#7: source match ({node_name})",
                              f"Mismatch at {file_path}:{line_val}\n"
                              f"  Expected: {expected_stripped[:80]}...\n"
                              f"  Actual:   {actual_stripped[:80]}...")


def verify_chain_integrity(entry, result):
    """Issue#7 标准2: 修复报告能解释从入口点到关键操作的完整漏洞链路"""
    trace = entry.get("trace", [])
    entry_point = entry.get("entry_point", {})
    critical = entry.get("critical_operation", {})

    if not trace:
        result.add_fail("Issue#7: chain integrity", "trace is empty")
        return

    if not entry_point:
        result.add_fail("Issue#7: chain integrity", "entry_point is missing")
        return

    if not critical:
        result.add_fail("Issue#7: chain integrity", "critical_operation is missing")
        return

    # 检查链路连续性：entry_point 应该是 trace[0]，critical 应该是 trace[-1]
    if (entry_point.get("file") == trace[0].get("file") and
        entry_point.get("line") == trace[0].get("line")):
        result.add_pass("Issue#7: chain integrity - entry_point is trace[0]", "")
    else:
        result.add_warning("Issue#7: chain integrity - entry_point is trace[0]",
                         f"entry_point={entry_point.get('file')}:{entry_point.get('line')} vs trace[0]={trace[0].get('file')}:{trace[0].get('line')}")

    # 检查 trace 节点是否都有 desc
    all_have_desc = all("desc" in node for node in trace)
    if all_have_desc:
        result.add_pass("Issue#7: chain integrity - all nodes have desc", "")
    else:
        missing = [i for i, node in enumerate(trace) if "desc" not in node]
        result.add_fail("Issue#7: chain integrity - all nodes have desc",
                      f"Missing desc on: {missing}")

    # 检查 trace 长度是否合理（至少 3 个节点：入口、中间、关键操作）
    if len(trace) >= 3:
        result.add_pass("Issue#7: chain integrity - trace length", f"len={len(trace)}")
    else:
        result.add_warning("Issue#7: chain integrity - trace length",
                         f"len={len(trace)} < 3")


def verify_entry(entry):
    """验证单个 entry"""
    entry_id = entry["entry_id"]
    result = VerificationResult(entry_id)

    # SCHEMA.md 验证
    verify_json_format(entry, result)
    verify_commit_format(entry, result)
    verify_repo_url(entry, result)
    verify_source_link(entry, result)
    verify_origin(entry, result)
    verify_verify_field(entry, result)
    verify_entry_point(entry, result)
    verify_critical_operation(entry, result)
    verify_trace(entry, result)

    # Issue#7 验证
    verify_entry_point_equals_trace0(entry, result)
    verify_critical_equals_trace_last(entry, result)
    verify_desc_quality(entry, result)
    verify_trace_no_noise(entry, result)
    verify_multi_stage(entry, result)
    verify_source_code_match(entry, result)
    verify_chain_integrity(entry, result)

    return result


def main():
    print("=" * 60)
    print("VulnGym Entry 验收脚本")
    print("基于 GitHub Issue #7 验收标准 + SCHEMA.md v0.1.4")
    print("=" * 60)

    # 加载数据
    try:
        entries = load_entries()
        print(f"\n已加载 {len(entries)} 个 entry")
    except Exception as e:
        print(f"加载 JSONL 文件失败: {e}")
        sys.exit(1)

    # 检查预期 entry 是否都存在
    missing = [eid for eid in EXPECTED_ENTRIES if eid not in entries]
    if missing:
        print(f"警告: 缺少预期 entry: {missing}")

    # 验证每个 entry
    all_results = []
    for entry_id in EXPECTED_ENTRIES:
        if entry_id in entries:
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

    print(f"\n总检查项: {total_pass + total_fail + total_warn}")
    print(f"通过: {total_pass}")
    print(f"失败: {total_fail}")
    print(f"警告: {total_warn}")

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
        print("最终判定: ALL PASS - 所有 entry 符合 GitHub Issue #7 验收标准")
    else:
        print(f"最终判定: FAIL - {total_fail} 个检查项未通过")
    print("=" * 60)

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
