#!/usr/bin/env python3
"""VulnGym Trace Cleanup 主入口。

对 entries.jsonl 中的 trace 调用链执行：
  1. 重复节点检测与合并
  2. 同文件内 before-entry / after-critical 顺序异常检测
  3. 跨文件节点保护（不做行号比较）

两种运行模式：
  - conservative（默认）：仅检测和报告，不做任何修改
  - fix：对 verify=0 条目的明确异常执行自动修复

用法：
  # 保守模式（仅检测）
  python tools/trace_cleanup/cleanup.py

  # 修复模式
  python tools/trace_cleanup/cleanup.py --mode fix

  # 指定输入/输出路径
  python tools/trace_cleanup/cleanup.py --input data/entries.jsonl --output data/entries.trace_fixed.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .line_parser import parse_line
from .duplicate_detector import detect_duplicates
from .order_checker import check_order
from .fixer import fix_entries
from .report_generator import generate_reports, print_summary


# 默认路径（相对于 VulnGym 仓库根目录）
DEFAULT_INPUT = "data/entries.jsonl"
DEFAULT_OUTPUT = "data/entries.trace_fixed.jsonl"
DEFAULT_REPORTS_DIR = "reports"


def load_jsonl(path: Path) -> list[dict]:
    """加载 JSONL 文件。"""
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"{path}:{i}: 无效 JSON: {e}") from None
            rows.append(row)
    return rows


def save_jsonl(entries: list[dict], path: Path) -> None:
    """保存 JSONL 文件，保持字段字母序排列。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for entry in entries:
            # 按 key 字母序排列，与 SCHEMA.md 一致
            sorted_entry = {k: entry[k] for k in sorted(entry)}
            f.write(json.dumps(sorted_entry, ensure_ascii=False) + "\n")


def validate_output(entries: list[dict], input_count: int) -> list[str]:
    """验证输出满足 SCHEMA.md 约束。"""
    errors: list[str] = []

    if len(entries) != input_count:
        errors.append(f"条目数不匹配: 期望 {input_count}, 实际 {len(entries)}")

    required_keys = [
        "entry_id", "report_id", "source_link", "vuln_ids", "origin",
        "project", "repo_url", "commit", "vuln_title",
        "vuln_category_l1", "vuln_category_l2",
        "entry_point", "critical_operation", "trace", "verify",
    ]

    for entry in entries:
        eid = entry.get("entry_id", "?")
        for key in required_keys:
            if key not in entry:
                errors.append(f"{eid}: 缺少必需字段 '{key}'")
        if "verify" in entry and entry["verify"] not in (0, 1):
            errors.append(f"{eid}: verify 值无效: {entry['verify']}")

        # 验证 trace 中每个节点的必需字段
        for i, node in enumerate(entry.get("trace", [])):
            for k in ("file", "line", "code"):
                if k not in node:
                    errors.append(f"{eid} trace[{i}]: 缺少 '{k}'")
                    break
            try:
                parse_line(node.get("line", 1))
            except ValueError as e:
                errors.append(f"{eid} trace[{i}]: {e}")

        # 验证 entry_point / critical_operation
        for field in ("entry_point", "critical_operation"):
            ep = entry.get(field, {})
            for k in ("file", "line", "code"):
                if k not in ep:
                    errors.append(f"{eid} {field}: 缺少 '{k}'")
            try:
                parse_line(ep.get("line", 1))
            except ValueError as e:
                errors.append(f"{eid} {field}: {e}")

    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="VulnGym Trace Cleanup — 调用链重复节点与顺序异常清理",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--input", type=Path,
        default=Path(DEFAULT_INPUT),
        help=f"输入 entries.jsonl 路径（默认: {DEFAULT_INPUT}）",
    )
    p.add_argument(
        "--output", type=Path,
        default=Path(DEFAULT_OUTPUT),
        help=f"输出修复后 JSONL 路径（默认: {DEFAULT_OUTPUT}）",
    )
    p.add_argument(
        "--reports-dir", type=Path,
        default=Path(DEFAULT_REPORTS_DIR),
        help=f"报告输出目录（默认: {DEFAULT_REPORTS_DIR}）",
    )
    p.add_argument(
        "--mode", choices=["conservative", "fix"],
        default="conservative",
        help="运行模式: conservative（仅检测，默认）| fix（修复 verify=0 的明确异常）",
    )
    p.add_argument(
        "--validate-only", action="store_true",
        help="仅验证输入文件格式，不做检测和修复",
    )
    args = p.parse_args(argv)

    print(f"加载数据: {args.input}")
    entries = load_jsonl(args.input)
    print(f"读取 {len(entries)} 条 entries")

    if args.validate_only:
        errors = validate_output(entries, len(entries))
        if errors:
            print(f"\n发现 {len(errors)} 个格式错误:")
            for e in errors[:20]:
                print(f"  - {e}")
            if len(errors) > 20:
                print(f"  ... 还有 {len(errors) - 20} 个错误")
            return 1
        print("格式验证通过!")
        return 0

    print(f"运行模式: {args.mode}")

    # 1) 检测重复节点
    print("检测重复节点...")
    dup_results: dict[str, list[dict]] = {}
    for entry in entries:
        eid = entry["entry_id"]
        dup_results[eid] = detect_duplicates(entry.get("trace", []))

    # 2) 检测顺序异常
    print("检测顺序异常...")
    order_results: dict[str, list[dict]] = {}
    for entry in entries:
        eid = entry["entry_id"]
        order_results[eid] = check_order(
            entry["entry_point"],
            entry["critical_operation"],
            entry.get("trace", []),
        )

    # 3) 执行修复
    print("执行修复...")
    fixed_entries, fix_log = fix_entries(entries, dup_results, order_results, mode=args.mode)

    # 4) 验证输出
    print("验证输出...")
    errors = validate_output(fixed_entries, len(entries))
    if errors:
        print(f"\n警告: 发现 {len(errors)} 个格式错误!")
        for e in errors[:10]:
            print(f"  - {e}")
        if len(errors) > 10:
            print(f"  ... 还有 {len(errors) - 10} 个错误")
    else:
        print("输出格式验证通过!")

    # 5) 保存修复后文件
    print(f"保存修复后文件: {args.output}")
    save_jsonl(fixed_entries, args.output)

    # 6) 生成报告
    print(f"生成报告: {args.reports_dir}")
    stats = generate_reports(
        entries=entries,
        dup_results=dup_results,
        order_results=order_results,
        fix_log=fix_log,
        mode=args.mode,
        output_dir=args.reports_dir,
    )

    # 7) 打印摘要
    print_summary(stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())
