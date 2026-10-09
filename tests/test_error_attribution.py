"""I9 Bonus: 错误归因分析测试

测试错误识别、聚合和归因功能。
"""

import json
import pytest
from pathlib import Path

from bonus.error_attribution.analyzer import ErrorAnalyzer, AnalysisResult
from bonus.error_attribution.aggregator import ErrorAggregator
from bonus.error_attribution.report_template import AttributionReport


# ========== Fixture 构造 ==========

def make_report(entry_id: str, report_id: str, verdict: str = "correct",
                field_overrides: dict = None, tool_trace_overrides: list = None) -> dict:
    """构造标准报告模板"""
    fields = {
        "entry_point": {"status": "correct", "confidence": 0.9, "evidence": "ok", "evidence_refs": []},
        "critical_operation": {"status": "correct", "confidence": 0.9, "evidence": "ok", "evidence_refs": []},
        "commit": {"status": "correct", "confidence": 0.9, "evidence": "ok", "evidence_refs": []},
        "vuln_ids": {"status": "correct", "confidence": 0.9, "evidence": "ok", "evidence_refs": []},
        "vuln_title": {"status": "correct", "confidence": 0.75, "evidence": "ok", "evidence_refs": []},
        "vuln_category_l1": {"status": "correct", "confidence": 0.85, "evidence": "ok", "evidence_refs": []},
        "vuln_category_l2": {"status": "correct", "confidence": 0.85, "evidence": "ok", "evidence_refs": []},
        "trace": {"status": "correct", "confidence": 0.7, "evidence": "ok", "evidence_refs": []}
    }
    
    if field_overrides:
        for field_name, overrides in field_overrides.items():
            fields[field_name].update(overrides)
    
    tool_trace = tool_trace_overrides or [
        {"seq": 1, "tool": "read_advisory", "ok": True, "error": None, "evidence_refs": []},
        {"seq": 2, "tool": "checkout", "ok": True, "error": None, "evidence_refs": []},
        {"seq": 3, "tool": "read_file_lines", "ok": True, "error": None, "evidence_refs": []}
    ]
    
    return {
        "report_id": report_id,
        "entry_id": entry_id,
        "verdict": verdict,
        "fields": fields,
        "summary": f"verdict={verdict}",
        "self_check": {"status": "completed", "agree": True, "comment": "ok", "checked_fields": []},
        "plan": {"version": "1", "tools_planned": [], "fields_planned": []},
        "tool_trace": tool_trace
    }


# ========== 场景 1: 工具偏差（checkout 失败） ==========

def test_tool_bias_checkout_failure():
    """场景 1: 3 条记录都因 checkout 失败导致 entry_point=uncertain"""
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
    
    # 验证聚合结果
    assert result["total_reports"] == 3
    assert result["total_errors"] >= 3  # 至少有 3 个 entry_point uncertain
    
    # 验证字段级聚合
    field_stats = {stat["field_name"]: stat for stat in result["by_field"]}
    assert "entry_point" in field_stats
    assert field_stats["entry_point"]["uncertain_count"] == 3
    
    # 验证工具级聚合
    tool_stats = {stat["tool_name"]: stat for stat in result["by_tool"]}
    assert "checkout" in tool_stats
    assert tool_stats["checkout"]["failed_count"] == 3
    assert tool_stats["checkout"]["failure_rate"] == 1.0  # 100% 失败
    
    # 验证根因识别
    root_causes = {rc["pattern"]: rc for rc in result["root_causes"]}
    assert "checkout_failure" in root_causes
    assert root_causes["checkout_failure"]["count"] == 3
    assert "entry_point" in root_causes["checkout_failure"]["affected_fields"]
    
    print("✓ 场景 1 通过: checkout 失败模式识别正确")


# ========== 场景 2: LLM 偏差（低置信度 uncertain） ==========

def test_llm_bias_low_confidence():
    """场景 2: 5 条记录的 vuln_category_l2 都是低置信度 uncertain"""
    reports = [
        make_report(
            f"entry-{i:03d}",
            f"GHSA-TEST-{i:03d}",
            verdict="uncertain",
            field_overrides={
                "vuln_category_l2": {"status": "uncertain", "confidence": 0.45, 
                                    "evidence": "LLM low confidence", "evidence_refs": []}
            }
        )
        for i in range(1, 6)
    ]
    
    aggregator = ErrorAggregator()
    result = aggregator.aggregate(reports)
    
    # 验证字段级聚合
    field_stats = {stat["field_name"]: stat for stat in result["by_field"]}
    assert "vuln_category_l2" in field_stats
    assert field_stats["vuln_category_l2"]["uncertain_count"] == 5
    assert field_stats["vuln_category_l2"]["low_confidence_count"] == 5
    
    print("✓ 场景 2 通过: LLM 低置信度模式识别正确")


# ========== 场景 3: 证据链断裂 ==========

def test_evidence_chain_broken():
    """场景 3: 2 条记录 commit=incorrect 但 evidence_refs=[]"""
    reports = [
        make_report(
            f"entry-{i:03d}",
            f"GHSA-TEST-{i:03d}",
            verdict="incorrect",
            field_overrides={
                "commit": {"status": "incorrect", "confidence": 0.8, 
                          "evidence": "commit hash mismatch but no refs", "evidence_refs": []}
            }
        )
        for i in range(1, 3)
    ]
    
    aggregator = ErrorAggregator()
    result = aggregator.aggregate(reports)
    
    # 验证字段级聚合
    field_stats = {stat["field_name"]: stat for stat in result["by_field"]}
    assert "commit" in field_stats
    assert field_stats["commit"]["evidence_chain_broken_count"] == 2
    
    # 验证根因识别
    root_causes = {rc["pattern"]: rc for rc in result["root_causes"]}
    assert "evidence_chain_broken" in root_causes
    assert root_causes["evidence_chain_broken"]["count"] == 2
    
    print("✓ 场景 3 通过: 证据链断裂模式识别正确")


# ========== 场景 4: 公共根因（advisory 404） ==========

def test_advisory_404_pattern():
    """场景 4: 4 条记录都涉及同一个 404 公告，vuln_ids=uncertain"""
    reports = [
        make_report(
            f"entry-{i:03d}",
            f"GHSA-TEST-{i:03d}",
            verdict="uncertain",
            field_overrides={
                "vuln_ids": {"status": "uncertain", "confidence": 0.4, 
                            "evidence": "advisory not found", "evidence_refs": []}
            },
            tool_trace_overrides=[
                {"seq": 1, "tool": "read_advisory", "ok": False, 
                 "error": "404 not found", "evidence_refs": ["fields.vuln_ids.evidence"]},
            ]
        )
        for i in range(1, 5)
    ]
    
    aggregator = ErrorAggregator()
    result = aggregator.aggregate(reports)
    
    # 验证根因识别
    root_causes = {rc["pattern"]: rc for rc in result["root_causes"]}
    assert "advisory_404" in root_causes
    assert root_causes["advisory_404"]["count"] == 4
    assert "vuln_ids" in root_causes["advisory_404"]["affected_fields"]
    
    print("✓ 场景 4 通过: advisory 404 模式识别正确")


# ========== 场景 5: 空 trace 高频 ==========

def test_empty_trace_pattern():
    """场景 5: 3 条记录 trace 为空"""
    reports = [
        make_report(
            f"entry-{i:03d}",
            f"GHSA-TEST-{i:03d}",
            verdict="uncertain",
            field_overrides={
                "trace": {"status": "uncertain", "confidence": 0.3, 
                         "evidence": "trace empty", "evidence_refs": []}
            }
        )
        for i in range(1, 4)
    ]
    
    aggregator = ErrorAggregator()
    result = aggregator.aggregate(reports)
    
    # 验证根因识别
    root_causes = {rc["pattern"]: rc for rc in result["root_causes"]}
    assert "empty_trace" in root_causes
    assert root_causes["empty_trace"]["count"] == 3
    assert "trace" in root_causes["empty_trace"]["affected_fields"]
    
    print("✓ 场景 5 通过: 空 trace 模式识别正确")


# ========== 归因报告生成测试 ==========

def test_attribution_report_generation(tmp_path):
    """测试归因报告生成"""
    # 混合场景
    reports = [
        # checkout 失败
        make_report(
            "entry-001", "GHSA-001", verdict="uncertain",
            field_overrides={
                "entry_point": {"status": "uncertain", "confidence": 0.5, 
                               "evidence": "checkout failed", "evidence_refs": []}
            },
            tool_trace_overrides=[
                {"seq": 1, "tool": "read_advisory", "ok": True, "error": None, "evidence_refs": []},
                {"seq": 2, "tool": "checkout", "ok": False, "error": "commit not found",
                 "evidence_refs": ["fields.entry_point.evidence"]},
            ]
        ),
        # 证据链断裂
        make_report(
            "entry-002", "GHSA-002", verdict="incorrect",
            field_overrides={
                "commit": {"status": "incorrect", "confidence": 0.8, 
                          "evidence": "wrong commit", "evidence_refs": []}
            }
        ),
        # 正常记录
        make_report("entry-003", "GHSA-003", verdict="correct")
    ]
    
    aggregator = ErrorAggregator()
    aggregation = aggregator.aggregate(reports)
    
    output_path = tmp_path / "attribution_report.json"
    report = AttributionReport.generate(
        aggregation=aggregation,
        output_path=str(output_path),
        add_recommendations=True
    )
    
    # 验证报告结构
    assert "analysis_id" in report
    assert "total_reports" in report
    assert report["total_reports"] == 3
    assert "error_summary" in report
    assert "recommendations" in report
    
    # 验证文件已生成
    assert output_path.exists()
    
    # 验证可以读取并解析
    with open(output_path, "r", encoding="utf-8") as f:
        loaded_report = json.load(f)
    assert loaded_report["total_reports"] == 3
    
    # 生成文本摘要
    text_summary = AttributionReport.format_text_summary(report)
    assert "错误归因分析报告" in text_summary
    assert "字段级错误分布" in text_summary
    assert "修复建议" in text_summary
    
    print("✓ 归因报告生成测试通过")
    print(f"  报告路径: {output_path}")
    print(f"  修复建议数: {len(report.get('recommendations', []))}")


# ========== 端到端测试（真实数据） ==========

def test_real_reports_analysis():
    """使用真实的 e2e 报告测试"""
    real_reports_path = Path(__file__).parent.parent.parent / "out" / "reports_e2e.jsonl"
    
    if not real_reports_path.exists():
        pytest.skip("真实报告文件不存在，跳过测试")
    
    # 加载真实报告
    reports = []
    with open(real_reports_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                reports.append(json.loads(line))
    
    assert len(reports) > 0, "没有加载到报告"
    
    # 聚合分析
    aggregator = ErrorAggregator()
    result = aggregator.aggregate(reports)
    
    # 基本验证
    assert result["total_reports"] == len(reports)
    assert "by_field" in result
    assert "by_tool" in result
    assert "root_causes" in result
    
    # 生成报告
    output_path = real_reports_path.parent / "error_attribution_e2e.json"
    report = AttributionReport.generate(
        aggregation=result,
        output_path=str(output_path),
        add_recommendations=True
    )
    
    print(f"✓ 真实数据分析完成")
    print(f"  总报告数: {report['total_reports']}")
    print(f"  总错误数: {report['total_errors']}")
    print(f"  识别根因数: {len(report['error_summary']['by_root_cause'])}")
    print(f"  输出路径: {output_path}")


# ========== 单元测试 ==========

def test_error_analyzer_basic():
    """测试 ErrorAnalyzer 基本功能"""
    analyzer = ErrorAnalyzer()
    
    report = make_report(
        "entry-001", "GHSA-001",
        verdict="incorrect",
        field_overrides={
            "entry_point": {"status": "incorrect", "confidence": 0.85, 
                           "evidence": "line mismatch", "evidence_refs": [{"source": "repository"}]},
            "vuln_ids": {"status": "uncertain", "confidence": 0.5, 
                        "evidence": "missing GHSA", "evidence_refs": []}
        }
    )
    
    result = analyzer.analyze(report)
    
    assert result.entry_id == "entry-001"
    assert result.verdict == "incorrect"
    assert len(result.field_errors) == 2
    assert len(result.low_confidence_fields) >= 1
    
    # 检查字段错误详情
    field_errors_map = {fe.field_name: fe for fe in result.field_errors}
    assert "entry_point" in field_errors_map
    assert field_errors_map["entry_point"].status == "incorrect"
    assert field_errors_map["vuln_ids"].status == "uncertain"
    
    print("✓ ErrorAnalyzer 基本功能测试通过")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
