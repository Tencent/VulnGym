"""推理链路可视化命令行工具

独立运行入口，可视化验证报告的推理链路。
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

from .visualizer import ChainVisualizer


def load_reports(jsonl_path: str) -> List[Dict[str, Any]]:
    """加载 JSONL 格式的验证报告"""
    reports = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                report = json.loads(line)
                reports.append(report)
            except json.JSONDecodeError as e:
                print(f"警告: 第 {line_no} 行 JSON 解析失败: {e}", file=sys.stderr)
    
    return reports


def visualize_single(report_id: str, reports_path: str, output_path: str, 
                    output_format: str = "markdown"):
    """可视化单条报告"""
    print(f"正在加载报告: {reports_path}")
    reports = load_reports(reports_path)
    
    # 查找指定 report_id
    target_report = None
    for report in reports:
        if report.get("entry_id") == report_id or report.get("report_id") == report_id:
            target_report = report
            break
    
    if not target_report:
        print(f"错误: 未找到 report_id={report_id} 的报告", file=sys.stderr)
        sys.exit(1)
    
    print(f"正在生成推理链路可视化...")
    visualizer = ChainVisualizer()
    
    if output_format == "json":
        # JSON 格式
        result = visualizer.visualize_report(target_report, output_format="json")
    elif output_format == "mermaid":
        # 纯 Mermaid
        result = visualizer.visualize_report(target_report, output_format="mermaid")
    else:
        # Markdown（默认）
        result = visualizer.visualize_report(target_report, output_format="markdown")
    
    # 保存到文件
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result)
    
    print(f"[OK] 可视化已保存到: {output_path}")


def visualize_all(reports_path: str, output_dir: str, 
                 output_format: str = "markdown",
                 filter_verdict: str = None,
                 filter_failed_tools: int = None):
    """可视化所有报告"""
    print(f"正在加载报告: {reports_path}")
    reports = load_reports(reports_path)
    print(f"已加载 {len(reports)} 条报告")
    
    if len(reports) == 0:
        print("错误: 没有有效的报告记录", file=sys.stderr)
        sys.exit(1)
    
    visualizer = ChainVisualizer()
    
    # 应用过滤器
    if filter_verdict:
        reports = visualizer.filter_by_verdict(reports, filter_verdict)
        print(f"按 verdict={filter_verdict} 过滤后: {len(reports)} 条")
    
    if filter_failed_tools is not None:
        reports = visualizer.filter_by_failed_tools(reports, filter_failed_tools)
        print(f"按 failed_tools>={filter_failed_tools} 过滤后: {len(reports)} 条")
    
    if len(reports) == 0:
        print("警告: 过滤后没有报告", file=sys.stderr)
        return
    
    print(f"正在生成 {len(reports)} 条报告的可视化...")
    visualizer.save_multiple(reports, output_dir, output_format)
    
    print(f"[OK] 可视化已保存到: {output_dir}")
    print(f"  - 单独文件: {len(reports)} 个")
    print(f"  - 对比文件: comparison.md")


def visualize_comparison(reports_path: str, output_path: str,
                        filter_verdict: str = None):
    """生成对比报告"""
    print(f"正在加载报告: {reports_path}")
    reports = load_reports(reports_path)
    print(f"已加载 {len(reports)} 条报告")
    
    visualizer = ChainVisualizer()
    
    # 应用过滤器
    if filter_verdict:
        reports = visualizer.filter_by_verdict(reports, filter_verdict)
        print(f"按 verdict={filter_verdict} 过滤后: {len(reports)} 条")
    
    if len(reports) == 0:
        print("错误: 没有有效的报告记录", file=sys.stderr)
        sys.exit(1)
    
    print("正在生成对比分析...")
    result = visualizer.visualize_multiple(reports, output_format="comparison")
    
    # 保存到文件
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result)
    
    print(f"[OK] 对比报告已保存到: {output_path}")


def show_statistics(reports_path: str):
    """显示推理链路统计信息"""
    print(f"正在加载报告: {reports_path}")
    reports = load_reports(reports_path)
    print(f"已加载 {len(reports)} 条报告\n")
    
    if len(reports) == 0:
        print("错误: 没有有效的报告记录", file=sys.stderr)
        sys.exit(1)
    
    visualizer = ChainVisualizer()
    stats = visualizer.get_chain_statistics(reports)
    
    print("=== 推理链路统计 ===\n")
    print(f"总报告数: {stats['total_reports']}")
    print(f"\nVerdict 分布:")
    print(f"  - Correct:   {stats['verdict_distribution']['correct']}")
    print(f"  - Incorrect: {stats['verdict_distribution']['incorrect']}")
    print(f"  - Uncertain: {stats['verdict_distribution']['uncertain']}")
    print(f"\n平均指标:")
    print(f"  - 每报告工具数: {stats['avg_tools_per_report']:.2f}")
    print(f"  - 每报告失败工具数: {stats['avg_failed_tools']:.2f}")
    print(f"\n覆盖率:")
    print(f"  - 包含 Plan: {stats['reports_with_plan']} ({stats['reports_with_plan']/stats['total_reports']*100:.1f}%)")
    print(f"  - 包含 Self-Check: {stats['reports_with_self_check']} ({stats['reports_with_self_check']/stats['total_reports']*100:.1f}%)")
    print(f"\n总错误字段数: {stats['total_incorrect_fields']}")


def main():
    """CLI 主入口"""
    parser = argparse.ArgumentParser(
        description="VulnGym I10 Bonus: 推理链路可视化",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 可视化单条报告
  python -m bonus.visualization.cli --report-id entry-00001 --reports out/reports.jsonl --output chain.md
  
  # 可视化所有报告（保存到目录）
  python -m bonus.visualization.cli --reports out/reports.jsonl --output-dir out/chains/
  
  # 只可视化 incorrect 报告
  python -m bonus.visualization.cli --reports out/reports.jsonl --output-dir out/chains/ --filter-verdict incorrect
  
  # 只可视化有失败工具的报告
  python -m bonus.visualization.cli --reports out/reports.jsonl --output-dir out/chains/ --filter-failed-tools 1
  
  # 生成对比报告
  python -m bonus.visualization.cli --reports out/reports.jsonl --comparison comparison.md
  
  # 显示统计信息
  python -m bonus.visualization.cli --reports out/reports.jsonl --stats
  
  # 输出纯 Mermaid 格式
  python -m bonus.visualization.cli --report-id entry-00001 --reports out/reports.jsonl --output chain.mermaid --format mermaid
        """
    )
    
    parser.add_argument(
        "--reports",
        type=str,
        required=True,
        help="输入的验证报告 JSONL 文件路径"
    )
    
    parser.add_argument(
        "--report-id",
        type=str,
        help="要可视化的单条报告 ID (entry_id 或 report_id)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="单条报告的输出文件路径"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        help="批量输出的目录路径"
    )
    
    parser.add_argument(
        "--format",
        type=str,
        choices=["markdown", "mermaid", "json"],
        default="markdown",
        help="输出格式（默认: markdown）"
    )
    
    parser.add_argument(
        "--comparison",
        type=str,
        help="生成对比报告的输出路径"
    )
    
    parser.add_argument(
        "--filter-verdict",
        type=str,
        choices=["correct", "incorrect", "uncertain"],
        help="按 verdict 过滤报告"
    )
    
    parser.add_argument(
        "--filter-failed-tools",
        type=int,
        help="只显示失败工具数 >= N 的报告"
    )
    
    parser.add_argument(
        "--stats",
        action="store_true",
        help="显示推理链路统计信息"
    )
    
    args = parser.parse_args()
    
    # 统计模式
    if args.stats:
        show_statistics(args.reports)
        return
    
    # 对比模式
    if args.comparison:
        visualize_comparison(args.reports, args.comparison, args.filter_verdict)
        return
    
    # 单条报告模式
    if args.report_id and args.output:
        visualize_single(args.report_id, args.reports, args.output, args.format)
        return
    
    # 批量模式
    if args.output_dir:
        visualize_all(
            args.reports, 
            args.output_dir, 
            args.format,
            args.filter_verdict,
            args.filter_failed_tools
        )
        return
    
    # 参数不足
    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
