"""演示推理链路可视化功能

展示如何使用 I10 Bonus 模块可视化验证报告的推理过程。
"""

import json
import sys
from pathlib import Path

# 添加父目录到路径以导入 bonus 模块
sys.path.insert(0, str(Path(__file__).parent.parent))

from bonus.visualization import ChainVisualizer


def demo_single_report():
    """演示：可视化单条报告"""
    print("=" * 60)
    print("Demo 1: 可视化单条报告")
    print("=" * 60)
    
    # 加载报告
    reports_path = Path("out/reports_e2e.jsonl")
    with open(reports_path, "r", encoding="utf-8") as f:
        report = json.loads(f.readline())
    
    visualizer = ChainVisualizer()
    
    # 生成 Markdown
    markdown = visualizer.visualize_report(report, "markdown")
    
    # 保存
    output_path = Path("out/demo_single_chain.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    
    print(f"[OK] 已生成: {output_path}")
    print(f"  Entry ID: {report['entry_id']}")
    print(f"  Verdict: {report['verdict']}")


def demo_filter_incorrect():
    """演示：只可视化错误报告"""
    print("\n" + "=" * 60)
    print("Demo 2: 过滤并可视化错误报告")
    print("=" * 60)
    
    # 加载所有报告
    reports = []
    reports_path = Path("out/reports_e2e.jsonl")
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                reports.append(json.loads(line))
    
    visualizer = ChainVisualizer()
    
    # 过滤错误报告
    incorrect_reports = visualizer.filter_by_verdict(reports, "incorrect")
    
    print(f"总报告数: {len(reports)}")
    print(f"错误报告数: {len(incorrect_reports)}")
    
    # 批量保存
    output_dir = Path("out/chains_incorrect")
    visualizer.save_multiple(incorrect_reports, str(output_dir))
    
    print(f"[OK] 已生成: {output_dir}/")
    for report in incorrect_reports:
        print(f"  - {report['entry_id']}.md")


def demo_statistics():
    """演示：推理链路统计"""
    print("\n" + "=" * 60)
    print("Demo 3: 推理链路统计")
    print("=" * 60)
    
    # 加载所有报告
    reports = []
    reports_path = Path("out/reports_e2e.jsonl")
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                reports.append(json.loads(line))
    
    visualizer = ChainVisualizer()
    stats = visualizer.get_chain_statistics(reports)
    
    print(f"\n总报告数: {stats['total_reports']}")
    print(f"\nVerdict 分布:")
    print(f"  Correct:   {stats['verdict_distribution']['correct']}")
    print(f"  Incorrect: {stats['verdict_distribution']['incorrect']}")
    print(f"  Uncertain: {stats['verdict_distribution']['uncertain']}")
    print(f"\n平均指标:")
    print(f"  每报告工具数: {stats['avg_tools_per_report']:.2f}")
    print(f"  每报告失败工具数: {stats['avg_failed_tools']:.2f}")
    print(f"\n覆盖率:")
    print(f"  包含 Plan: {stats['reports_with_plan']} ({stats['reports_with_plan']/stats['total_reports']*100:.1f}%)")
    print(f"  包含 Self-Check: {stats['reports_with_self_check']} ({stats['reports_with_self_check']/stats['total_reports']*100:.1f}%)")


def demo_failed_tools():
    """演示：定位失败的工具"""
    print("\n" + "=" * 60)
    print("Demo 4: 定位失败的工具")
    print("=" * 60)
    
    # 加载所有报告
    reports = []
    reports_path = Path("out/reports_e2e.jsonl")
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                reports.append(json.loads(line))
    
    visualizer = ChainVisualizer()
    
    # 过滤有失败工具的报告
    failed_reports = visualizer.filter_by_failed_tools(reports, min_failures=1)
    
    print(f"有失败工具的报告数: {len(failed_reports)}")
    
    for report in failed_reports:
        chain = visualizer.builder.build(report)
        failed_tools = chain.get_failed_tools()
        
        print(f"\n  Entry: {report['entry_id']}")
        print(f"  Verdict: {report['verdict']}")
        print(f"  失败工具:")
        for tool in failed_tools:
            error = tool.metadata.get("error", "Unknown")
            print(f"    - {tool.metadata['tool']}: {error}")


def demo_comparison():
    """演示：生成对比报告"""
    print("\n" + "=" * 60)
    print("Demo 5: 生成对比报告")
    print("=" * 60)
    
    # 加载所有报告
    reports = []
    reports_path = Path("out/reports_e2e.jsonl")
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                reports.append(json.loads(line))
    
    visualizer = ChainVisualizer()
    
    # 生成对比
    comparison = visualizer.visualize_multiple(reports, output_format="comparison")
    
    # 保存
    output_path = Path("out/demo_comparison.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(comparison)
    
    print(f"[OK] 已生成: {output_path}")


if __name__ == "__main__":
    print("\n=== I10 Bonus: 推理链路可视化 - 功能演示 ===\n")
    
    demo_single_report()
    demo_filter_incorrect()
    demo_statistics()
    demo_failed_tools()
    demo_comparison()
    
    print("\n" + "=" * 60)
    print("[DONE] 所有演示完成")
    print("=" * 60)
    print("\n查看生成的文件:")
    print("  - out/demo_single_chain.md")
    print("  - out/chains_incorrect/*.md")
    print("  - out/demo_comparison.md")
