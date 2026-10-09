"""I10 Bonus 推理链路可视化测试

测试 ChainBuilder、MermaidRenderer 和 ChainVisualizer。
"""

import json
import pytest
from pathlib import Path

from bonus.visualization import ChainBuilder, MermaidRenderer, ChainVisualizer


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sample_report_correct():
    """正确的验证报告样本"""
    return {
        "report_id": "GHSA-DEMO-0001-XSS",
        "entry_id": "entry-00001",
        "verdict": "correct",
        "fields": {
            "entry_point": {
                "status": "correct",
                "confidence": 0.9,
                "evidence": "checkout 后 src/handlers/comment.js:97 代码片段匹配",
                "evidence_refs": [
                    {
                        "source": "repository",
                        "locator": "1111111:src/handlers/comment.js:97",
                        "quote": "insertTextHandler(data.content);"
                    }
                ]
            },
            "critical_operation": {
                "status": "correct",
                "confidence": 0.9,
                "evidence": "checkout 后 src/lib/RichTextInput.svelte:348 匹配",
                "evidence_refs": []
            },
            "commit": {
                "status": "correct",
                "confidence": 0.9,
                "evidence": "commit 1111111 在本地缓存可用",
                "evidence_refs": []
            },
            "vuln_ids": {"status": "correct", "confidence": 0.9, "evidence": "", "evidence_refs": []},
            "vuln_title": {"status": "correct", "confidence": 0.75, "evidence": "", "evidence_refs": []},
            "vuln_category_l1": {"status": "correct", "confidence": 0.85, "evidence": "", "evidence_refs": []},
            "vuln_category_l2": {"status": "correct", "confidence": 0.85, "evidence": "", "evidence_refs": []},
            "trace": {"status": "correct", "confidence": 0.7, "evidence": "", "evidence_refs": []}
        },
        "summary": "整体判定为 correct",
        "self_check": {
            "status": "completed",
            "agree": True,
            "comment": "各字段证据一致",
            "checked_fields": ["entry_point", "critical_operation", "commit"]
        },
        "plan": {
            "version": "1",
            "entry_id": "entry-00001",
            "report_id": "GHSA-DEMO-0001-XSS",
            "tools_planned": ["read_advisory", "checkout", "read_file_lines"],
            "fields_planned": ["entry_point", "critical_operation", "commit"]
        },
        "tool_trace": [
            {
                "seq": 1,
                "tool": "read_advisory",
                "input": {"report_id": "GHSA-DEMO-0001-XSS"},
                "ok": True,
                "error": None,
                "evidence_refs": ["fields.vuln_ids.evidence", "fields.vuln_title.evidence"]
            },
            {
                "seq": 2,
                "tool": "checkout",
                "input": {"project": "blog-platform", "commit": "1111111"},
                "ok": True,
                "error": None,
                "evidence_refs": ["fields.entry_point.evidence", "fields.commit.evidence"]
            },
            {
                "seq": 3,
                "tool": "read_file_lines",
                "input": {"file": "src/handlers/comment.js", "start": 90, "end": 100},
                "ok": True,
                "error": None,
                "evidence_refs": ["fields.entry_point.evidence"]
            }
        ]
    }


@pytest.fixture
def sample_report_incorrect():
    """包含错误的验证报告样本"""
    return {
        "report_id": "GHSA-DEMO-0002-RCE",
        "entry_id": "entry-00002",
        "verdict": "incorrect",
        "fields": {
            "entry_point": {"status": "correct", "confidence": 0.9, "evidence": "", "evidence_refs": []},
            "critical_operation": {
                "status": "incorrect",
                "confidence": 0.85,
                "evidence": "行号错误：实际匹配行 250，标注 200",
                "evidence_refs": []
            },
            "commit": {"status": "correct", "confidence": 0.9, "evidence": "", "evidence_refs": []},
            "vuln_ids": {"status": "uncertain", "confidence": 0.55, "evidence": "", "evidence_refs": []},
            "vuln_title": {"status": "correct", "confidence": 0.75, "evidence": "", "evidence_refs": []},
            "vuln_category_l1": {"status": "correct", "confidence": 0.85, "evidence": "", "evidence_refs": []},
            "vuln_category_l2": {"status": "correct", "confidence": 0.85, "evidence": "", "evidence_refs": []},
            "trace": {"status": "uncertain", "confidence": 0.4, "evidence": "", "evidence_refs": []}
        },
        "summary": "整体判定为 incorrect",
        "self_check": {
            "status": "completed",
            "agree": True,
            "comment": "发现 critical_operation 行号不匹配",
            "checked_fields": ["entry_point", "critical_operation"]
        },
        "plan": {
            "version": "1",
            "tools_planned": ["read_advisory", "checkout"],
            "fields_planned": ["entry_point", "critical_operation"]
        },
        "tool_trace": [
            {
                "seq": 1,
                "tool": "read_advisory",
                "input": {"report_id": "GHSA-DEMO-0002-RCE"},
                "ok": True,
                "error": None,
                "evidence_refs": ["fields.vuln_ids.evidence"]
            },
            {
                "seq": 2,
                "tool": "checkout",
                "input": {"project": "shell-runner", "commit": "2222222"},
                "ok": False,
                "error": "commit not found",
                "evidence_refs": []
            }
        ]
    }


# ============================================================================
# ChainBuilder 测试
# ============================================================================

def test_chain_builder_correct_report(sample_report_correct):
    """测试构建正确报告的推理链路"""
    builder = ChainBuilder()
    chain = builder.build(sample_report_correct)
    
    assert chain.entry_id == "entry-00001"
    assert chain.verdict == "correct"
    
    # 检查节点数量
    assert len(chain.nodes) > 0
    
    # 检查有 plan 节点
    plan_nodes = [n for n in chain.nodes if n.node_id == "plan"]
    assert len(plan_nodes) == 1
    
    # 检查有 3 个工具节点
    tool_nodes = chain.get_tool_nodes()
    assert len(tool_nodes) == 3
    
    # 检查有 8 个字段节点
    field_nodes = chain.get_field_nodes()
    assert len(field_nodes) == 8
    
    # 检查有 verdict 节点
    verdict_nodes = [n for n in chain.nodes if n.node_id == "verdict"]
    assert len(verdict_nodes) == 1
    
    # 检查边
    assert len(chain.edges) > 0


def test_chain_builder_incorrect_report(sample_report_incorrect):
    """测试构建错误报告的推理链路"""
    builder = ChainBuilder()
    chain = builder.build(sample_report_incorrect)
    
    assert chain.entry_id == "entry-00002"
    assert chain.verdict == "incorrect"
    
    # 检查失败的工具
    failed_tools = chain.get_failed_tools()
    assert len(failed_tools) == 1
    assert failed_tools[0].metadata["tool"] == "checkout"
    
    # 检查错误的字段
    incorrect_fields = chain.get_incorrect_fields()
    assert len(incorrect_fields) == 1
    assert incorrect_fields[0].metadata["field_name"] == "critical_operation"


def test_chain_metadata(sample_report_correct):
    """测试链路元数据"""
    builder = ChainBuilder()
    chain = builder.build(sample_report_correct)
    
    meta = chain.metadata
    assert meta["has_plan"] is True
    assert meta["has_self_check"] is True
    assert meta["total_tools"] == 3
    assert meta["failed_tools"] == 0
    assert meta["total_fields"] == 8
    assert meta["incorrect_fields"] == 0


# ============================================================================
# MermaidRenderer 测试
# ============================================================================

def test_mermaid_renderer_basic(sample_report_correct):
    """测试基本 Mermaid 渲染"""
    builder = ChainBuilder()
    chain = builder.build(sample_report_correct)
    
    renderer = MermaidRenderer()
    mermaid_code = renderer.render(chain)
    
    # 检查 Mermaid 语法
    assert mermaid_code.startswith("graph TD")
    assert "plan" in mermaid_code
    assert "verdict" in mermaid_code
    assert "tool_1" in mermaid_code
    
    # 检查箭头连接
    assert "-->" in mermaid_code
    
    # 检查样式定义
    assert "style" in mermaid_code


def test_mermaid_renderer_markdown(sample_report_correct):
    """测试渲染为 Markdown"""
    builder = ChainBuilder()
    chain = builder.build(sample_report_correct)
    
    renderer = MermaidRenderer()
    markdown = renderer.render_to_markdown(chain)
    
    # 检查 Markdown 结构
    assert "# Reasoning Chain:" in markdown
    assert "## Summary" in markdown
    assert "## Reasoning Flow" in markdown
    assert "```mermaid" in markdown
    assert "## Details" in markdown


def test_mermaid_renderer_failed_tools(sample_report_incorrect):
    """测试失败工具的渲染"""
    builder = ChainBuilder()
    chain = builder.build(sample_report_incorrect)
    
    renderer = MermaidRenderer()
    markdown = renderer.render_to_markdown(chain)
    
    # 检查失败工具详情
    assert "### Failed Tools" in markdown
    assert "checkout" in markdown
    assert "commit not found" in markdown


# ============================================================================
# ChainVisualizer 测试
# ============================================================================

def test_visualizer_single_report(sample_report_correct):
    """测试可视化单条报告"""
    visualizer = ChainVisualizer()
    
    # Markdown 格式
    markdown = visualizer.visualize_report(sample_report_correct, "markdown")
    assert "# Reasoning Chain:" in markdown
    
    # Mermaid 格式
    mermaid = visualizer.visualize_report(sample_report_correct, "mermaid")
    assert "graph TD" in mermaid
    
    # JSON 格式
    json_str = visualizer.visualize_report(sample_report_correct, "json")
    data = json.loads(json_str)
    assert data["entry_id"] == "entry-00001"
    assert "nodes" in data
    assert "edges" in data


def test_visualizer_filter_by_verdict(sample_report_correct, sample_report_incorrect):
    """测试按 verdict 过滤"""
    visualizer = ChainVisualizer()
    reports = [sample_report_correct, sample_report_incorrect]
    
    # 过滤 correct
    correct_reports = visualizer.filter_by_verdict(reports, "correct")
    assert len(correct_reports) == 1
    assert correct_reports[0]["entry_id"] == "entry-00001"
    
    # 过滤 incorrect
    incorrect_reports = visualizer.filter_by_verdict(reports, "incorrect")
    assert len(incorrect_reports) == 1
    assert incorrect_reports[0]["entry_id"] == "entry-00002"


def test_visualizer_filter_by_failed_tools(sample_report_correct, sample_report_incorrect):
    """测试按失败工具数过滤"""
    visualizer = ChainVisualizer()
    reports = [sample_report_correct, sample_report_incorrect]
    
    # 有失败工具的报告
    failed_reports = visualizer.filter_by_failed_tools(reports, min_failures=1)
    assert len(failed_reports) == 1
    assert failed_reports[0]["entry_id"] == "entry-00002"


def test_visualizer_statistics(sample_report_correct, sample_report_incorrect):
    """测试统计信息"""
    visualizer = ChainVisualizer()
    reports = [sample_report_correct, sample_report_incorrect]
    
    stats = visualizer.get_chain_statistics(reports)
    
    assert stats["total_reports"] == 2
    assert stats["verdict_distribution"]["correct"] == 1
    assert stats["verdict_distribution"]["incorrect"] == 1
    assert stats["reports_with_plan"] == 2
    assert stats["reports_with_self_check"] == 2


# ============================================================================
# 真实数据测试
# ============================================================================

def test_real_reports_e2e():
    """使用真实 E2E 报告测试"""
    reports_path = Path("vulngym-verify-demo/out/reports_e2e.jsonl")
    
    if not reports_path.exists():
        pytest.skip("真实报告文件不存在")
    
    # 加载报告
    reports = []
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                reports.append(json.loads(line))
    
    assert len(reports) > 0, "应该至少有一条报告"
    
    # 测试构建和渲染
    visualizer = ChainVisualizer()
    for report in reports:
        # 构建链路
        chain = visualizer.builder.build(report)
        assert chain.entry_id
        assert chain.verdict in ["correct", "incorrect", "uncertain"]
        
        # 渲染 Markdown
        markdown = visualizer.visualize_report(report, "markdown")
        assert "# Reasoning Chain:" in markdown
        
        # 渲染 Mermaid
        mermaid = visualizer.visualize_report(report, "mermaid")
        assert "graph TD" in mermaid


def test_visualization_output_files(tmp_path, sample_report_correct):
    """测试输出文件生成"""
    visualizer = ChainVisualizer()
    
    # 保存单个文件
    output_file = tmp_path / "chain.md"
    visualizer.save_visualization(sample_report_correct, str(output_file), "markdown")
    
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "# Reasoning Chain:" in content


def test_comparison_renderer(sample_report_correct, sample_report_incorrect):
    """测试对比渲染器"""
    builder = ChainBuilder()
    chains = [
        builder.build(sample_report_correct),
        builder.build(sample_report_incorrect)
    ]
    
    from bonus.visualization.mermaid_renderer import ComparisonRenderer
    renderer = ComparisonRenderer()
    comparison = renderer.render_comparison(chains)
    
    assert "# Reasoning Chains Comparison" in comparison
    assert "## Statistics" in comparison
    assert "## Individual Chains" in comparison
    assert "entry-00001" in comparison
    assert "entry-00002" in comparison
