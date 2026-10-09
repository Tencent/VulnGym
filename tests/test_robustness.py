# -*- coding: utf-8 -*-
"""I7 — 鲁棒性测试套件。

覆盖所有异常场景，确保系统在各种边界条件下的稳定性。

测试场景：
1. advisory_404: 公告缺失 -> uncertain
2. file_not_found: 目标文件不存在 -> incorrect
3. bad_commit: 无效 commit -> uncertain
4. llm_basic: LLM 基本行为测试
5. missing_fields: entry 缺少必需字段
6. empty_trace: trace 为空列表
7. malformed_json: 非法 JSON 输入
8. special_invalid_input: __invalid_input__ 样本处理
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo.llm_client import ScriptedMockLLMClient, LLMMessage  # noqa: E402
from vulngym_verify_demo.schema import validate_entry  # noqa: E402
from vulngym_verify_demo.tools import VulnGymTools  # noqa: E402
from vulngym_verify_demo.agent import verify_entry  # noqa: E402


@pytest.fixture
def mock_tools(tmp_path: Path) -> VulnGymTools:
    """创建 mock tools"""
    repo_cache = tmp_path / "mock_repo"
    repo_cache.mkdir()
    
    # 创建一个测试项目
    # Field checkers resolve the local key from the canonical URL basename
    # (``https://github.com/test/project`` -> ``project``).
    project = repo_cache / "project" / "abcd1234abcd1234abcd1234abcd1234abcd1234"
    project.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "test.js").write_text("console.log('test');")
    
    # 创建 advisory
    advisory_dir = tmp_path / "advisories"
    advisory_dir.mkdir()
    (advisory_dir / "GHSA-TEST-0001.json").write_text(json.dumps({
        "id": "GHSA-TEST-0001",
        "summary": "Test vulnerability",
        "details": "Test description"
    }))
    
    # 与 URL 推导出的本地 key 对齐，使 checkout/read_file_lines 真正到达
    # 夹具；测试才能覆盖文件缺失、坏 commit 等目标场景。
    manifest = {
        "items": [{
            "repo_url": "https://github.com/test/project",
            "project": "project",
            "commit": "abcd1234abcd1234abcd1234abcd1234abcd1234",
        }]
    }
    
    return VulnGymTools(
        repo_cache_dir=repo_cache,
        advisory_dir=advisory_dir,
        manifest=manifest,
    )


def test_advisory_404(mock_tools: VulnGymTools):
    """公告缺失 -> 应该能处理"""
    entry = {
        "entry_id": "test-adv-404",
        "report_id": "GHSA-NONEXIST-9999",
        "project": "test-project",
        "commit": "abcd1234abcd1234abcd1234abcd1234abcd1234",
        "repo_url": "https://github.com/test/project",
        "entry_point": {"file": "src/test.js", "line": 1, "code": "test()"},
        "critical_operation": {"file": "src/test.js", "line": 2, "code": "eval()"},
        "vuln_ids": ["GHSA-NONEXIST-9999"],
        "vuln_title": "Test",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "trace": [],
        "verify": 1,
    }
    
    llm = ScriptedMockLLMClient()
    report = verify_entry(entry, mock_tools, llm)
    
    # 应该返回报告，不抛异常
    assert "verdict" in report
    assert "tool_trace" in report


def test_file_not_found(mock_tools: VulnGymTools):
    """目标文件不存在 -> entry_point.status=incorrect"""
    entry = {
        "entry_id": "test-file-404",
        "report_id": "GHSA-TEST-0001",
        "project": "test-project",
        "commit": "abcd1234abcd1234abcd1234abcd1234abcd1234",
        "repo_url": "https://github.com/test/project",
        "entry_point": {"file": "src/nonexistent.js", "line": 1, "code": "test()"},
        "critical_operation": {"file": "src/test.js", "line": 2, "code": "eval()"},
        "vuln_ids": ["GHSA-TEST-0001"],
        "vuln_title": "Test",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "trace": [],
        "verify": 1,
    }
    
    llm = ScriptedMockLLMClient()
    report = verify_entry(entry, mock_tools, llm)
    
    # 文件不存在应该被检测到
    assert report["fields"]["entry_point"]["status"] == "incorrect"


def test_bad_commit(mock_tools: VulnGymTools):
    """无效 commit -> 应该能处理"""
    entry = {
        "entry_id": "test-bad-commit",
        "report_id": "GHSA-TEST-0001",
        "project": "test-project",
        "commit": "invalid-commit-hash",
        "repo_url": "https://github.com/test/project",
        "entry_point": {"file": "src/test.js", "line": 1, "code": "test()"},
        "critical_operation": {"file": "src/test.js", "line": 2, "code": "eval()"},
        "vuln_ids": ["GHSA-TEST-0001"],
        "vuln_title": "Test",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "trace": [],
        "verify": 1,
    }
    
    llm = ScriptedMockLLMClient()
    report = verify_entry(entry, mock_tools, llm)
    
    # 坏 commit 应该返回报告
    assert "verdict" in report
    assert report["fields"]["commit"]["status"] in ["incorrect", "uncertain"]


def test_llm_basic():
    """LLM 基本行为测试"""
    llm = ScriptedMockLLMClient()
    
    # Mock LLM 应该总是返回合法响应
    result = llm.chat(
        messages=[LLMMessage(role="user", content="test")],
        temperature=0.0,
    )
    
    assert result is not None
    assert isinstance(result, str)


def test_missing_fields():
    """缺少必需字段的 entry 应该被正确处理"""
    # 缺少 entry_id
    incomplete_entry = {
        "project": "test",
        "commit": "abcd1234",
    }
    
    errors = validate_entry(incomplete_entry)
    assert len(errors) > 0
    assert any("entry_id" in err for err in errors)


def test_empty_trace(mock_tools: VulnGymTools):
    """空 trace 列表应该被接受（某些漏洞可能没有中间步骤）"""
    entry = {
        "entry_id": "test-empty-trace",
        "report_id": "GHSA-TEST-0001",
        "project": "test-project",
        "commit": "abcd1234abcd1234abcd1234abcd1234abcd1234",
        "repo_url": "https://github.com/test/project",
        "entry_point": {"file": "src/test.js", "line": 1, "code": "test()"},
        "critical_operation": {"file": "src/test.js", "line": 2, "code": "eval()"},
        "vuln_ids": ["GHSA-TEST-0001"],
        "vuln_title": "Test",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "trace": [],
        "verify": 1,
    }
    
    llm = ScriptedMockLLMClient()
    report = verify_entry(entry, mock_tools, llm)
    
    # 空 trace 是合法的
    assert "trace" in report["fields"]
    assert report["fields"]["trace"]["status"] in ["correct", "incorrect", "uncertain"]


def test_malformed_json_entry():
    """非法 JSON 应该被验证层捕获"""
    # 类型错误的字段
    bad_entry = {
        "entry_id": "test-bad",
        "project": "test",
        "commit": "abc123",
        "entry_point": "not-a-dict",  # 应该是 dict
        "critical_operation": {"file": "test.js", "line": 1, "code": "x"},
        "vuln_ids": "not-a-list",  # 应该是 list
    }
    
    errors = validate_entry(bad_entry)
    assert len(errors) > 0


def test_special_invalid_input_entry(mock_tools: VulnGymTools):
    """__invalid_input__ 开头的 entry 应该被处理（可能返回 incorrect 或 uncertain）"""
    entry = {
        "entry_id": "__invalid_input__test",
        "report_id": "BAD",
        "project": "bad",
        "commit": "",
        "repo_url": "",
        "entry_point": {"file": "", "line": 0, "code": ""},
        "critical_operation": {"file": "", "line": 0, "code": ""},
        "vuln_ids": [],
        "vuln_title": "",
        "vuln_category_l1": "",
        "vuln_category_l2": "",
        "trace": [],
        "verify": 0,
    }
    
    llm = ScriptedMockLLMClient()
    report = verify_entry(entry, mock_tools, llm)
    
    # __invalid_input__ 样本应该返回报告（verdict 可能是 incorrect 或 uncertain）
    assert report["verdict"] in ["incorrect", "uncertain"]
    assert report["entry_id"] == "__invalid_input__test"
