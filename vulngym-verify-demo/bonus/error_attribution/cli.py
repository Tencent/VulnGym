"""错误归因分析命令行工具

独立运行入口，分析验证报告并生成归因报告。
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

from .analyzer import ErrorAnalyzer
from .aggregator import ErrorAggregator
from .report_template import AttributionReport


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


def analyze_reports(reports_path: str, output_path: str, text_summary: bool = False):
    """分析报告并生成归因"""
    print(f"正在加载报告: {reports_path}")
    reports = load_reports(reports_path)
    print(f"已加载 {len(reports)} 条报告")
    
    if len(reports) == 0:
        print("错误: 没有有效的报告记录", file=sys.stderr)
        sys.exit(1)
    
    print("正在聚合错误模式...")
    aggregator = ErrorAggregator()
    aggregation = aggregator.aggregate(reports)
    
    print("正在生成归因报告...")
    report = AttributionReport.generate(
        aggregation=aggregation,
        output_path=output_path,
        add_recommendations=True
    )
    
    print(f"[OK] 归因报告已保存到: {output_path}")
    
    # 打印文本摘要
    if text_summary:
        print("\n" + AttributionReport.format_text_summary(report))
    else:
        print(f"  - 总报告数: {report['total_reports']}")
        print(f"  - 总错误数: {report['total_errors']}")
        print(f"  - 识别根因数: {len(report['error_summary']['by_root_cause'])}")
        print(f"  - 修复建议数: {len(report.get('recommendations', []))}")


def compare_reports(baseline_path: str, current_path: str, output_path: str):
    """比较两次运行的差异"""
    print(f"正在加载基线报告: {baseline_path}")
    baseline_reports = load_reports(baseline_path)
    
    print(f"正在加载当前报告: {current_path}")
    current_reports = load_reports(current_path)
    
    print("正在分析差异...")
    aggregator = ErrorAggregator()
    
    baseline_agg = aggregator.aggregate(baseline_reports)
    current_agg = aggregator.aggregate(current_reports)
    
    # 构建差异报告
    diff_report = {
        "baseline": {
            "total_reports": baseline_agg["total_reports"],
            "total_errors": baseline_agg["total_errors"]
        },
        "current": {
            "total_reports": current_agg["total_reports"],
            "total_errors": current_agg["total_errors"]
        },
        "changes": {
            "error_delta": current_agg["total_errors"] - baseline_agg["total_errors"],
            "field_changes": _compare_field_stats(
                baseline_agg.get("by_field", []),
                current_agg.get("by_field", [])
            ),
            "new_root_causes": _find_new_root_causes(
                baseline_agg.get("root_causes", []),
                current_agg.get("root_causes", [])
            ),
            "resolved_root_causes": _find_resolved_root_causes(
                baseline_agg.get("root_causes", []),
                current_agg.get("root_causes", [])
            )
        }
    }
    
    # 保存差异报告
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(diff_report, f, indent=2, ensure_ascii=False)
    
    print(f"[OK] 差异报告已保存到: {output_path}")
    print(f"  - 错误变化: {diff_report['changes']['error_delta']:+d}")
    print(f"  - 新增根因: {len(diff_report['changes']['new_root_causes'])}")
    print(f"  - 已解决根因: {len(diff_report['changes']['resolved_root_causes'])}")


def _compare_field_stats(baseline: List[Dict], current: List[Dict]) -> Dict[str, Any]:
    """比较字段级统计变化"""
    baseline_map = {stat["field_name"]: stat for stat in baseline}
    current_map = {stat["field_name"]: stat for stat in current}
    
    changes = {}
    for field_name in set(baseline_map.keys()) | set(current_map.keys()):
        base_stat = baseline_map.get(field_name, {})
        curr_stat = current_map.get(field_name, {})
        
        base_total = base_stat.get("incorrect_count", 0) + base_stat.get("uncertain_count", 0)
        curr_total = curr_stat.get("incorrect_count", 0) + curr_stat.get("uncertain_count", 0)
        
        if base_total != curr_total:
            changes[field_name] = {
                "before": base_total,
                "after": curr_total,
                "delta": curr_total - base_total
            }
    
    return changes


def _find_new_root_causes(baseline: List[Dict], current: List[Dict]) -> List[str]:
    """查找新增的根因模式"""
    baseline_patterns = {rc["pattern"] for rc in baseline}
    current_patterns = {rc["pattern"] for rc in current}
    return list(current_patterns - baseline_patterns)


def _find_resolved_root_causes(baseline: List[Dict], current: List[Dict]) -> List[str]:
    """查找已解决的根因模式"""
    baseline_patterns = {rc["pattern"] for rc in baseline}
    current_patterns = {rc["pattern"] for rc in current}
    return list(baseline_patterns - current_patterns)


def main():
    """CLI 主入口"""
    parser = argparse.ArgumentParser(
        description="VulnGym I9 Bonus: 系统性错误识别与归因",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 分析单个报告文件
  python -m bonus.error_attribution.cli --reports out/reports.jsonl --output analysis.json
  
  # 显示文本摘要
  python -m bonus.error_attribution.cli --reports out/reports.jsonl --output analysis.json --summary
  
  # 比较两次运行
  python -m bonus.error_attribution.cli --baseline run1.jsonl --current run2.jsonl --diff diff.json
        """
    )
    
    parser.add_argument(
        "--reports",
        type=str,
        help="输入的验证报告 JSONL 文件路径"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="输出归因报告的 JSON 文件路径"
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="在控制台打印文本摘要"
    )
    
    parser.add_argument(
        "--baseline",
        type=str,
        help="基线报告路径（用于比较模式）"
    )
    
    parser.add_argument(
        "--current",
        type=str,
        help="当前报告路径（用于比较模式）"
    )
    
    parser.add_argument(
        "--diff",
        type=str,
        help="输出差异报告路径（用于比较模式）"
    )
    
    args = parser.parse_args()
    
    # 比较模式
    if args.baseline and args.current and args.diff:
        compare_reports(args.baseline, args.current, args.diff)
        return
    
    # 分析模式
    if args.reports and args.output:
        analyze_reports(args.reports, args.output, args.summary)
        return
    
    # 参数不足
    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
