#!/usr/bin/env python3
"""
VulnGym Trace Fixer — 调用链顺序异常和重复节点检测与清理工具
============================================================

根据 Issue #5 的要求，自动检测并清理 VulnGym 数据集中 ``trace`` 字段的
两类结构性问题：

1. **重复节点** — trace 内部出现完全相同的 ``{file, line, code}`` 组合
2. **顺序异常** — 同一文件内 trace 节点的行号早于 entry_point 或晚于
   critical_operation

用法::

    python tools/trace_fixer.py --mode conservative   # 仅检测，不修改
    python tools/trace_fixer.py --mode fix             # 检测并修复

输出::

    data/entries.trace_fixed.jsonl   — 修复后的数据（fix 模式）
    data/trace_fix_log.csv           — 逐条修改日志
    data/trace_fix_report.json       — 统计摘要报告
"""

import argparse
import csv
import json
import os
import sys
from copy import deepcopy
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def normalize_line(line_val):
    """将 line 字段标准化为 ``(start, end)`` 整数元组。

    支持两种格式：
    - 整数 ``97`` → ``(97, 97)``
    - 范围字符串 ``"348-352"`` → ``(348, 352)``
    """
    if isinstance(line_val, int):
        return (line_val, line_val)
    if isinstance(line_val, str) and "-" in line_val:
        a, b = line_val.split("-", 1)
        return (int(a), int(b))
    # 兜底：纯数字字符串
    n = int(line_val)
    return (n, n)


def node_key(node):
    """返回节点的去重键 ``(file, line_str, code)``。"""
    return (node["file"], str(node["line"]), node["code"])


def nodes_equal(a, b):
    """判断两个节点是否完全相同（file + line + code）。"""
    return node_key(a) == node_key(b)


def is_before_ep(trace_node, ep):
    """trace 节点是否在同一文件中，且行号**完全早于** entry_point。

    判定条件：trace 的结束行 < entry_point 的起始行。
    """
    if trace_node["file"] != ep["file"]:
        return False
    t_start, t_end = normalize_line(trace_node["line"])
    ep_start, ep_end = normalize_line(ep["line"])
    return t_end < ep_start


def is_after_co(trace_node, co):
    """trace 节点是否在同一文件中，且行号**完全晚于** critical_operation。

    判定条件：trace 的起始行 > critical_operation 的结束行。
    """
    if trace_node["file"] != co["file"]:
        return False
    t_start, t_end = normalize_line(trace_node["line"])
    co_start, co_end = normalize_line(co["line"])
    return t_start > co_end


def is_cross_field_duplicate(trace_node, target_node):
    """trace 节点是否与 entry_point / critical_operation 完全相同。"""
    return nodes_equal(trace_node, target_node)


# ---------------------------------------------------------------------------
# 单条 entry 的检测与修复
# ---------------------------------------------------------------------------


def process_entry(entry, mode="conservative", verify_filter="all"):
    """检测并（可选）修复单条 entry 的 trace。

    Parameters
    ----------
    entry : dict
        一条完整的 entry 记录。
    mode : str
        ``"conservative"`` — 仅检测，不修改。
        ``"fix"`` — 检测并移除确定有问题的节点。
    verify_filter : str
        ``"0"`` — 仅处理 verify=0 的 entry。
        ``"1"`` — 仅处理 verify=1 的 entry。
        ``"all"`` — 处理所有 entry。

    Returns
    -------
    (fixed_entry, log_entries) : (dict, list[dict])
        ``fixed_entry`` — 修复后的 entry（conservative 模式下为原对象）。
        ``log_entries`` — 本 entry 产生的所有日志条目。
    """
    # 根据 verify_filter 判断是否需要跳过
    if verify_filter != "all":
        if str(entry.get("verify", -1)) != verify_filter:
            return entry, []
    log_entries = []
    trace = entry.get("trace", [])
    if not trace:
        return entry, log_entries

    ep = entry["entry_point"]
    co = entry["critical_operation"]
    entry_id = entry["entry_id"]

    # ---- 第 1 步：检测 trace 内部重复 ----
    # 保留第一次出现，后续重复的标记为 DUPLICATE_INTERNAL
    # fix 模式下移除重复；conservative 模式下仅记录
    seen_keys = []  # (node_key, position_in_new_trace)
    deduped_trace = []
    for i, node in enumerate(trace):
        nk = node_key(node)
        dup_of = None
        for j, (sk, pos) in enumerate(seen_keys):
            if nk == sk:
                dup_of = pos
                break
        if dup_of is not None:
            should_remove_dup = mode == "fix"
            action = "DUPLICATE_INTERNAL_REMOVED" if should_remove_dup else "DUPLICATE_INTERNAL_DETECTED"
            log_entries.append(
                {
                    "entry_id": entry_id,
                    "field_path": f"trace[{i}]",
                    "action": action,
                    "reason": f"与 trace[{dup_of}] 完全重复（file + line + code 相同）",
                    "before": json.dumps(node, ensure_ascii=False),
                    "after": "(已移除)" if should_remove_dup else "(保留 — 保守模式，仅记录)",
                    "mode": mode,
                }
            )
            if not should_remove_dup:
                # conservative 模式：仍然保留
                seen_keys.append((nk, len(deduped_trace)))
                deduped_trace.append(node)
        else:
            seen_keys.append((nk, len(deduped_trace)))
            deduped_trace.append(node)

    # ---- 第 2 步：检测跨字段重复（trace 节点与 entry_point / critical_operation 相同）----
    trace = deduped_trace
    deduped_trace = []
    for i, node in enumerate(trace):
        flags = []
        if is_cross_field_duplicate(node, ep):
            flags.append(f"与 entry_point 相同 ({ep['file']}:{ep['line']})")
        if is_cross_field_duplicate(node, co):
            flags.append(f"与 critical_operation 相同 ({co['file']}:{co['line']})")

        if flags:
            # 跨字段重复不一定错误，仅记录供人工复核
            log_entries.append(
                {
                    "entry_id": entry_id,
                    "field_path": f"trace[{i}]",
                    "action": "CROSS_FIELD_DUPLICATE",
                    "reason": "；".join(flags) + "。trace 中包含入口点/关键操作本身不一定是错误，保留待人工复核。",
                    "before": json.dumps(node, ensure_ascii=False),
                    "after": "(保留 — 需人工复核)",
                    "mode": mode,
                }
            )
        deduped_trace.append(node)

    # ---- 第 3 步：检测顺序异常 ----
    trace = deduped_trace
    result_trace = []
    for i, node in enumerate(trace):
        reasons = []

        if is_before_ep(node, ep):
            t_start, t_end = normalize_line(node["line"])
            ep_start, ep_end = normalize_line(ep["line"])
            reasons.append(
                f"同一文件内 trace 行号 ({node['line']}) "
                f"早于 entry_point ({ep['line']}) — "
                f"trace 结束行 {t_end} < entry_point 起始行 {ep_start}"
            )

        if is_after_co(node, co):
            t_start, t_end = normalize_line(node["line"])
            co_start, co_end = normalize_line(co["line"])
            reasons.append(
                f"同一文件内 trace 行号 ({node['line']}) "
                f"晚于 critical_operation ({co['line']}) — "
                f"trace 起始行 {t_start} > critical_operation 结束行 {co_end}"
            )

        if reasons:
            # 仅对 verify=0（未人工校验）的条目自动移除顺序异常节点。
            # verify=1 的条目已经人工确认，其 trace 中的"越界"节点
            # 可能是跨函数调用跳转造成的，属于正确的语义结构。
            is_verified = entry.get("verify", 0) == 1
            should_remove = (mode == "fix" and not is_verified)
            action = "ORDER_ANOMALY_REMOVED" if should_remove else "ORDER_ANOMALY_DETECTED"
            log_entries.append(
                {
                    "entry_id": entry_id,
                    "field_path": f"trace[{i}]",
                    "action": action,
                    "reason": "；".join(reasons),
                    "before": json.dumps(node, ensure_ascii=False),
                    "after": (
                        "(已移除)"
                        if should_remove
                        else "(保留 — 人工校验条目，顺序可能为正确语义)"
                        if is_verified
                        else "(保留 — 保守模式，仅记录)"
                    ),
                    "mode": mode,
                }
            )
            if should_remove:
                continue  # 不加入结果

        result_trace.append(node)

    # ---- 第 4 步：生成修复后的 entry ----
    if mode == "fix":
        fixed = deepcopy(entry)
        fixed["trace"] = result_trace
    else:
        fixed = entry

    return fixed, log_entries


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------


def generate_report(log_entries, total_entries, mode):
    """从日志条目生成统计报告。"""
    actions = {}
    affected_entries = set()
    verify_0_affected = set()
    verify_1_affected = set()

    for log in log_entries:
        action = log["action"]
        actions[action] = actions.get(action, 0) + 1
        affected_entries.add(log["entry_id"])

    # 找出受影响的 entry 的 verify 状态
    # 需要在调用处补充（这里仅计数）
    return {
        "run_time": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "total_entries_scanned": total_entries,
        "total_log_entries": len(log_entries),
        "unique_entries_affected": len(affected_entries),
        "action_counts": actions,
    }


def load_entries(path):
    """读取 JSONL 文件，返回 list[dict]。"""
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def save_jsonl(entries, path):
    """将 entry 列表写入 JSONL 文件，每行一个 JSON 对象。"""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def save_csv(log_entries, path):
    """将日志条目写入 CSV 文件。"""
    if not log_entries:
        # 写一个空日志
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["entry_id", "field_path", "action", "reason", "before", "after", "mode"])
        return

    fieldnames = ["entry_id", "field_path", "action", "reason", "before", "after", "mode"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(log_entries)


def validate_entry(entry, index):
    """验证修复后的 entry 是否满足 SCHEMA.md 基本约束。

    Returns
    -------
    list[str] : 错误信息列表，空列表表示通过验证。
    """
    errors = []

    # 必填字段
    required = [
        "entry_id", "report_id", "source_link", "vuln_ids", "origin",
        "project", "repo_url", "commit", "vuln_title",
        "vuln_category_l1", "vuln_category_l2",
        "entry_point", "critical_operation", "trace", "verify",
    ]
    for field in required:
        if field not in entry:
            errors.append(f"缺少必填字段 {field}")

    # verify 字段
    if entry.get("verify") not in (0, 1):
        errors.append(f"verify 字段值无效: {entry.get('verify')}")

    # commit 格式
    commit = entry.get("commit", "")
    if not (isinstance(commit, str) and len(commit) == 40 and all(c in "0123456789abcdef" for c in commit)):
        errors.append(f"commit 格式异常: {commit}")

    # repo_url
    repo = entry.get("repo_url", "")
    if not repo.startswith("https://github.com/"):
        errors.append(f"repo_url 格式异常: {repo}")

    # trace 元素验证
    trace = entry.get("trace", [])
    for i, node in enumerate(trace):
        for key in ("file", "line", "code"):
            if key not in node:
                errors.append(f"trace[{i}] 缺少必填键 '{key}'")
        if "line" in node:
            line_val = node["line"]
            try:
                s, e = normalize_line(line_val)
                if s < 1 or e < s:
                    errors.append(f"trace[{i}].line 范围无效: {line_val}")
            except (ValueError, TypeError):
                errors.append(f"trace[{i}].line 格式无法解析: {line_val}")

    # entry_point / critical_operation 验证
    for field_name in ("entry_point", "critical_operation"):
        node = entry.get(field_name, {})
        for key in ("file", "line", "code"):
            if key not in node:
                errors.append(f"{field_name} 缺少必填键 '{key}'")
        if "line" in node:
            try:
                s, e = normalize_line(node["line"])
                if s < 1 or e < s:
                    errors.append(f"{field_name}.line 范围无效: {node['line']}")
            except (ValueError, TypeError):
                errors.append(f"{field_name}.line 格式无法解析: {node['line']}")

    return errors


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def main():
    # 确保 Windows 环境下 stdout 使用 UTF-8
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="VulnGym Trace Fixer — 调用链顺序异常和重复节点检测与清理",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python tools/trace_fixer.py --mode conservative
  python tools/trace_fixer.py --mode fix
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["conservative", "fix"],
        default="conservative",
        help="运行模式：conservative=仅检测并记录，不修改数据；fix=检测并移除确定有问题的节点（默认: conservative）",
    )
    parser.add_argument(
        "--input",
        default="data/entries.jsonl",
        help="输入 JSONL 文件路径（默认: data/entries.jsonl）",
    )
    parser.add_argument(
        "--output",
        default="data/entries.trace_fixed.jsonl",
        help="修复后的输出路径（默认: data/entries.trace_fixed.jsonl，仅 fix 模式生效）",
    )
    parser.add_argument(
        "--log",
        default="data/trace_fix_log.csv",
        help="修改日志 CSV 输出路径（默认: data/trace_fix_log.csv）",
    )
    parser.add_argument(
        "--report",
        default="data/trace_fix_report.json",
        help="统计报告 JSON 输出路径（默认: data/trace_fix_report.json）",
    )
    parser.add_argument(
        "--verify-filter",
        choices=["0", "1", "all"],
        default="all",
        help="按 verify 字段过滤：0=仅处理未校验条目，1=仅处理已校验条目，all=处理全部（默认: all）",
    )
    args = parser.parse_args()

    # 确定脚本所在目录 → 项目根目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir) if os.path.basename(script_dir) == "tools" else script_dir

    input_path = os.path.join(project_root, args.input)
    output_path = os.path.join(project_root, args.output)
    log_path = os.path.join(project_root, args.log)
    report_path = os.path.join(project_root, args.report)

    # ------------------------------------------------------------------
    # 读取输入
    # ------------------------------------------------------------------
    if not os.path.exists(input_path):
        print(f"[错误] 找不到输入文件: {input_path}")
        sys.exit(1)

    print(f"[信息] 读取数据: {input_path}")
    entries = load_entries(input_path)
    total = len(entries)
    print(f"[信息] 共 {total} 条 entry")

    # ------------------------------------------------------------------
    # 逐条处理
    # ------------------------------------------------------------------
    all_logs = []
    fixed_entries = []
    validation_errors = []

    for idx, entry in enumerate(entries):
        fixed, logs = process_entry(entry, mode=args.mode, verify_filter=args.verify_filter)
        fixed_entries.append(fixed)
        all_logs.extend(logs)

        # 修复模式下验证每条输出
        if args.mode == "fix":
            errs = validate_entry(fixed, idx)
            if errs:
                for e in errs:
                    validation_errors.append(f"{fixed.get('entry_id', '?')}: {e}")

    # ------------------------------------------------------------------
    # 统计报告
    # ------------------------------------------------------------------
    report = generate_report(all_logs, total, args.mode)
    report["verify_filter"] = args.verify_filter

    # 按动作类型细分
    action_counts = {}
    verify_0_affected = set()
    verify_1_affected = set()
    verify_0_entries = set()
    verify_1_entries = set()

    for entry in entries:
        if entry["verify"] == 0:
            verify_0_entries.add(entry["entry_id"])
        else:
            verify_1_entries.add(entry["entry_id"])

    for log in all_logs:
        a = log["action"]
        action_counts[a] = action_counts.get(a, 0) + 1
        eid = log["entry_id"]
        # 找到对应 entry 的 verify 状态
        for entry in entries:
            if entry["entry_id"] == eid:
                if entry["verify"] == 0:
                    verify_0_affected.add(eid)
                else:
                    verify_1_affected.add(eid)
                break

    report["action_counts"] = action_counts
    report["verify_0_total"] = len(verify_0_entries)
    report["verify_1_total"] = len(verify_1_entries)
    report["verify_0_affected"] = len(verify_0_affected)
    report["verify_1_affected"] = len(verify_1_affected)
    report["verify_0_affected_ids"] = sorted(verify_0_affected)
    report["verify_1_affected_ids"] = sorted(verify_1_affected)
    report["validation_errors"] = len(validation_errors)

    # ------------------------------------------------------------------
    # 输出
    # ------------------------------------------------------------------
    # 日志 CSV
    if all_logs:
        save_csv(all_logs, log_path)
        print(f"[信息] 修改日志已写入: {log_path} ({len(all_logs)} 条记录)")
    else:
        print("[信息] 未检测到任何问题 — 数据集调用链结构正常 [OK]")
        save_csv(all_logs, log_path)  # 写空日志

    # 修复数据
    if args.mode == "fix":
        save_jsonl(fixed_entries, output_path)
        print(f"[信息] 修复后数据已写入: {output_path}")

        if validation_errors:
            print(f"[警告] 验证发现 {len(validation_errors)} 个问题:")
            for err in validation_errors[:10]:
                print(f"  - {err}")
            if len(validation_errors) > 10:
                print(f"  ... 还有 {len(validation_errors) - 10} 个")
        else:
            print("[信息] 所有修复后数据通过 SCHEMA.md 基础约束验证 [OK]")

    # 报告 JSON
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[信息] 统计报告已写入: {report_path}")

    # ------------------------------------------------------------------
    # 终端摘要
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print(f"  VulnGym Trace Fixer — 扫描报告")
    print("=" * 60)
    print(f"  运行模式:        {args.mode}")
    print(f"  扫描 entry 总数: {total}")
    print(f"  发现问题条目数:  {len(verify_0_affected) + len(verify_1_affected)}")
    print(f"    - verify=0:     {len(verify_0_affected)} / {len(verify_0_entries)}")
    print(f"    - verify=1:     {len(verify_1_affected)} / {len(verify_1_entries)}")
    print(f"  日志总条数:      {len(all_logs)}")
    for action, count in sorted(action_counts.items()):
        print(f"    {action}: {count}")
    if validation_errors:
        print(f"  验证错误:        {len(validation_errors)}")
    print("=" * 60)

    if args.mode == "conservative" and all_logs:
        print()
        print("  提示: 当前为保守模式，仅记录了异常。")
        print("  如需自动修复，请运行:")
        print("    python tools/trace_fixer.py --mode fix")
    print()


if __name__ == "__main__":
    main()
