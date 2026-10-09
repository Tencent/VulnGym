#!/usr/bin/env python3
"""错误归因分析演示脚本

展示 I9 Bonus 模块的核心功能。
"""

import json
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from bonus.error_attribution import ErrorAggregator, AttributionReport


def demo_basic_analysis():
    """演示基本归因分析"""
    print("=" * 60)
    print("演示 1: 基本错误归因分析")
    print("=" * 60)
    
    # 加载真实报告
    reports_path = Path(__file__).parent.parent / "out" / "reports_e2e.jsonl"
    
    if not reports_path.exists():
        print(f"错误: 找不到报告文件 {reports_path}")
        return
    
    print(f"\n加载报告: {reports_path}")
    reports = []
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                reports.append(json.loads(line))
    
    print(f"已加载 {len(reports)} 条报告\n")
    
    # 聚合分析
    print("正在聚合错误模式...")
    aggregator = ErrorAggregator()
    aggregation = aggregator.aggregate(reports)
    
    # 显示统计
    print(f"\n总错误数: {aggregation['total_errors']}")
    print(f"\n字段错误分布:")
    for stat in aggregation['by_field'][:3]:  # 显示前 3 个
        print(f"  - {stat['field_name']}: incorrect={stat['incorrect_count']}, uncertain={stat['uncertain_count']}")
    
    print(f"\n工具失败率:")
    for stat in aggregation['by_tool']:
        tool = stat['tool_name']
        rate = stat['failure_rate']
        print(f"  - {tool}: {rate*100:.1f}%")
    
    print(f"\n识别到 {len(aggregation['root_causes'])} 个公共根因")
    for rc in aggregation['root_causes']:
        print(f"  - [{rc['pattern']}] {rc['description']} (影响 {rc['count']} 条记录)")
    
    # 生成报告
    output_path = reports_path.parent / "demo_attribution.json"
    print(f"\n生成归因报告: {output_path}")
    report = AttributionReport.generate(
        aggregation=aggregation,
        output_path=str(output_path),
        add_recommendations=True
    )
    
    print(f"\n修复建议 ({len(report['recommendations'])} 条):")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"  {i}. {rec}")


def demo_injected_scenarios():
    """演示注入场景识别"""
    print("\n\n" + "=" * 60)
    print("演示 2: 注入场景识别")
    print("=" * 60)
    
    from tests.test_error_attribution import make_report
    
    # 场景: checkout 失败导致连锁错误
    print("\n场景: checkout 工具失败导致 3 条记录 entry_point=uncertain")
    
    reports = [
        make_report(
            f"entry-{i:03d}",
            f"GHSA-TEST-{i:03d}",
            verdict="uncertain",
            field_overrides={
                "entry_point": {"status": "uncertain", "confidence": 0.5, 
                               "evidence": "checkout failed", "evidence_refs": []}
            },
            tool_trace_overrides=[
                {"seq": 1, "tool": "read_advisory", "ok": True, "error": None, "evidence_refs": []},
                {"seq": 2, "tool": "checkout", "ok": False, "error": "commit not found", 
                 "evidence_refs": ["fields.entry_point.evidence"]},
            ]
        )
        for i in range(1, 4)
    ]
    
    aggregator = ErrorAggregator()
    result = aggregator.aggregate(reports)
    
    print(f"\n检测结果:")
    print(f"  - 总错误数: {result['total_errors']}")
    print(f"  - checkout 失败率: {result['by_tool'][0]['failure_rate']*100:.0f}%")
    
    root_causes = {rc['pattern']: rc for rc in result['root_causes']}
    if 'checkout_failure' in root_causes:
        rc = root_causes['checkout_failure']
        print(f"  - [OK] 识别到根因: {rc['pattern']}")
        print(f"    影响记录数: {rc['count']}")
        print(f"    受影响字段: {', '.join(rc['affected_fields'])}")
    else:
        print(f"  - [WARN] 未识别到 checkout_failure 根因")


def demo_text_summary():
    """演示文本摘要生成"""
    print("\n\n" + "=" * 60)
    print("演示 3: 文本摘要生成")
    print("=" * 60)
    
    # 使用已生成的报告
    reports_path = Path(__file__).parent.parent / "out" / "demo_attribution.json"
    
    if not reports_path.exists():
        print("错误: 请先运行演示 1")
        return
    
    with open(reports_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    
    print("\n生成可读文本摘要:\n")
    text_summary = AttributionReport.format_text_summary(report)
    print(text_summary)


if __name__ == "__main__":
    try:
        demo_basic_analysis()
        demo_injected_scenarios()
        demo_text_summary()
        
        print("\n" + "=" * 60)
        print("演示完成!")
        print("=" * 60)
        print("\n查看生成的报告:")
        print("  - vulngym-verify-demo/out/demo_attribution.json")
        print("  - vulngym-verify-demo/out/error_attribution_e2e.json")
        print("\n运行测试:")
        print("  pytest tests/test_error_attribution.py -v")
        print("\n查看文档:")
        print("  vulngym-verify-demo/docs/ERROR_ATTRIBUTION.md")
        
    except Exception as e:
        print(f"\n错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
