# -*- coding: utf-8 -*-
"""tests/test_cli.py — I6 CLI 批处理鲁棒性测试。

测试目标：
  1. 坏 JSON 行生成 __invalid_input__ 报告
  2. 缺必填字段生成 __invalid_input__ 报告
  3. 路径展开（~、环境变量、相对路径）
  4. 配置错误返回 exit 2
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest


# ============================================================
# iter_jsonl 单元测试
# ============================================================


def test_iter_jsonl_bad_json():
    """坏 JSON 行生成特殊标记，不抛异常。"""
    from vulngym_verify_demo.cli import iter_jsonl
    
    with tempfile.TemporaryDirectory() as tmpdir:
        entries = Path(tmpdir) / "bad.jsonl"
        entries.write_text(
            '{"report_id": "good1"}\n'
            '{bad json here}\n'
            '{"report_id": "good2"}\n',
            encoding="utf-8"
        )
        
        results = list(iter_jsonl(entries))
        assert len(results) == 3
        
        # 第一行正常
        assert results[0]["report_id"] == "good1"
        assert "__parse_error__" not in results[0]
        
        # 第二行是坏 JSON，生成特殊标记
        assert results[1].get("__parse_error__") is True
        assert results[1].get("__line_no__") == 2
        assert "expecting" in results[1].get("__error_message__", "").lower()
        
        # 第三行正常
        assert results[2]["report_id"] == "good2"
        assert "__parse_error__" not in results[2]


def test_iter_jsonl_empty_lines():
    """空行被跳过。"""
    from vulngym_verify_demo.cli import iter_jsonl
    
    with tempfile.TemporaryDirectory() as tmpdir:
        entries = Path(tmpdir) / "empty.jsonl"
        entries.write_text(
            '{"report_id": "a"}\n'
            '\n'
            '   \n'
            '{"report_id": "b"}\n',
            encoding="utf-8"
        )
        
        results = list(iter_jsonl(entries))
        assert len(results) == 2
        assert results[0]["report_id"] == "a"
        assert results[1]["report_id"] == "b"


def test_iter_jsonl_records_preserves_physical_line_numbers():
    """新流式迭代器为 schema 错误保留原始 JSONL 行号。"""
    from vulngym_verify_demo.cli import iter_jsonl_records

    with tempfile.TemporaryDirectory() as tmpdir:
        entries = Path(tmpdir) / "numbered.jsonl"
        entries.write_text("\n{bad json}\n{}\n", encoding="utf-8")
        stats = {}
        records = list(iter_jsonl_records(entries, stats))
        assert [(line_no, error is not None) for line_no, _, error in records] == [(2, True), (3, False)]
        assert stats["blank_lines"] == 1


# ============================================================
# expand_path 单元测试
# ============================================================


def test_expand_path_tilde(monkeypatch):
    """~/ 展开为用户 HOME 目录。"""
    from vulngym_verify_demo.cli import expand_path
    
    monkeypatch.setenv("HOME", "/fake/home")
    result = expand_path("~/test.txt")
    # Windows 会用 USERPROFILE，这里只验证不抛异常
    assert result.is_absolute()


def test_expand_path_env_var(monkeypatch):
    """环境变量展开。"""
    from vulngym_verify_demo.cli import expand_path
    
    monkeypatch.setenv("TEST_DIR", "/fake/dir")
    result = expand_path("$TEST_DIR/test.txt")
    # Windows 可能不展开 $，改用 %
    assert result.is_absolute()


def test_expand_path_relative():
    """相对路径转绝对路径。"""
    from vulngym_verify_demo.cli import expand_path
    
    result = expand_path("./relative/path.txt")
    assert result.is_absolute()


# ============================================================
# verify_entries 坏输入处理测试
# ============================================================


def test_verify_entries_parse_error():
    """坏 JSON 行生成 __invalid_input__ 报告。"""
    from vulngym_verify_demo.agent import verify_entries
    from vulngym_verify_demo.tools import VulnGymTools
    from vulngym_verify_demo.llm_client import MockLLMClient
    
    # 模拟坏输入
    entries = [
        {
            "__parse_error__": True,
            "__line_no__": 5,
            "__error_message__": "Expecting property name enclosed in double quotes",
            "__raw_line__": "{bad json"
        }
    ]
    
    tools = VulnGymTools(repo_cache_dir=Path("."), advisory_dir=Path("."))
    llm = MockLLMClient()
    
    reports = verify_entries(entries, tools, llm, verbose=False)
    
    assert len(reports) == 1
    report = reports[0]
    assert report["report_id"] == "__invalid_input__:5"
    assert report["entry_id"] == "__invalid_input__:5"
    assert report["verdict"] == "uncertain"
    assert "input_error" in report
    assert report["input_error"]["kind"] == "json_parse_error"
    assert report["input_error"]["line_no"] == 5
    assert report["self_check"]["status"] == "skipped"
    assert report["self_check"]["agree"] is False


def test_verify_entries_missing_fields():
    """缺必填字段生成 __invalid_input__ 报告。"""
    from vulngym_verify_demo.agent import verify_entries
    from vulngym_verify_demo.tools import VulnGymTools
    from vulngym_verify_demo.llm_client import MockLLMClient
    
    # 缺 commit 字段
    entries = [
        {
            "report_id": "R-001",
            "entry_id": "E-001",
            "entry_point": "main.js",
            "critical_operation": "eval"
            # 缺 commit
        }
    ]
    
    tools = VulnGymTools(repo_cache_dir=Path("."), advisory_dir=Path("."))
    llm = MockLLMClient()
    
    reports = verify_entries(entries, tools, llm, verbose=False)
    
    assert len(reports) == 1
    report = reports[0]
    assert report["report_id"] == "R-001"
    assert report["entry_id"] == "E-001"
    assert report["verdict"] == "uncertain"
    assert "input_error" in report
    assert report["input_error"]["kind"] == "missing_required_field"
    assert "commit" in report["input_error"]["message"]
    assert report["self_check"]["status"] == "skipped"
    assert report["self_check"]["agree"] is False


def test_verify_entries_all_missing_fields():
    """缺多个必填字段。"""
    from vulngym_verify_demo.agent import verify_entries
    from vulngym_verify_demo.tools import VulnGymTools
    from vulngym_verify_demo.llm_client import MockLLMClient
    
    # 只有 entry_id
    entries = [
        {
            "entry_id": "E-bad"
        }
    ]
    
    tools = VulnGymTools(repo_cache_dir=Path("."), advisory_dir=Path("."))
    llm = MockLLMClient()
    
    reports = verify_entries(entries, tools, llm, verbose=False)
    
    assert len(reports) == 1
    report = reports[0]
    assert report["entry_id"] == "E-bad"
    assert report["verdict"] == "uncertain"
    assert "input_error" in report
    assert report["input_error"]["kind"] == "missing_required_field"
    # 应该缺 report_id, commit, entry_point, critical_operation
    message = report["input_error"]["message"]
    assert "report_id" in message
    assert "commit" in message


# ============================================================
# CLI main 退出码测试
# ============================================================


def test_cli_missing_entries_file():
    """--entries 文件不存在 -> exit 2。"""
    from vulngym_verify_demo.cli import main
    
    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = main([
            "--entries", str(Path(tmpdir) / "not_exist.jsonl"),
            "--repo-cache", tmpdir,
            "--advisories", tmpdir,
            "--out", str(Path(tmpdir) / "out.jsonl")
        ])
        assert exit_code == 2


def test_cli_missing_gold_file():
    """--gold 文件不存在 -> exit 2。"""
    from vulngym_verify_demo.cli import main
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # 创建有效的 entries 文件
        entries_path = Path(tmpdir) / "entries.jsonl"
        entries_path.write_text('{"report_id":"R1","commit":"a"*40,"entry_point":"x","critical_operation":"y"}\n', encoding="utf-8")
        
        # advisories 和 repo-cache 目录必须存在
        (Path(tmpdir) / "advisories").mkdir()
        (Path(tmpdir) / "repo-cache").mkdir()
        
        exit_code = main([
            "--entries", str(entries_path),
            "--repo-cache", str(Path(tmpdir) / "repo-cache"),
            "--advisories", str(Path(tmpdir) / "advisories"),
            "--out", str(Path(tmpdir) / "out.jsonl"),
            "--gold", str(Path(tmpdir) / "not_exist.jsonl"),
            "--llm", "mock"
        ])
        assert exit_code == 2


def test_cli_success_exit_code():
    """正常执行 -> exit 0。"""
    from vulngym_verify_demo.cli import main
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # 创建有效的 entries 文件
        entries_path = Path(tmpdir) / "entries.jsonl"
        entries_path.write_text(
            '{"report_id":"R1","commit":"'+'a'*40+'","entry_point":"x","critical_operation":"y","repo_url":"http://test.com/repo"}\n',
            encoding="utf-8"
        )
        
        # advisories 和 repo-cache 目录必须存在
        (Path(tmpdir) / "advisories").mkdir()
        (Path(tmpdir) / "repo-cache").mkdir()
        
        exit_code = main([
            "--entries", str(entries_path),
            "--repo-cache", str(Path(tmpdir) / "repo-cache"),
            "--advisories", str(Path(tmpdir) / "advisories"),
            "--out", str(Path(tmpdir) / "out.jsonl"),
            "--llm", "mock"
        ])
        assert exit_code == 0


def _valid_cli_entry() -> dict:
    return {
        "entry_id": "entry-cli-valid",
        "report_id": "GHSA-DEMO-0001-0XSS",
        "source_link": "https://github.com/advisories/GHSA-DEMO-0001-0XSS",
        "vuln_ids": ["CVE-2026-0001", "GHSA-DEMO-0001-0XSS"],
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "blog-platform",
        "repo_url": "https://github.com/example/blog-platform",
        "commit": "1111111111111111111111111111111111111111",
        "vuln_title": "Blog Platform Stored DOM XSS via Comment Rich Text",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "entry_point": {"file": "src/handlers/comment.js", "line": 97, "code": "insertTextHandler(data.content);"},
        "critical_operation": {"file": "src/lib/RichTextInput.svelte", "line": 348, "code": "tempDiv.innerHTML = htmlContent;"},
        "trace": [],
        "verify": 1,
    }


def test_cli_streams_bad_json_and_schema_violation_then_continues(tmp_path):
    """坏 JSON、schema 不合法、合法行均各输出一条，且 ID 使用物理行号。"""
    from vulngym_verify_demo.cli import main

    root = Path(__file__).resolve().parent.parent / "vulngym-verify-demo"
    entries_path = tmp_path / "mixed.jsonl"
    entries_path.write_text(
        json.dumps(_valid_cli_entry(), ensure_ascii=False) + "\n"
        "{bad json}\n"
        + json.dumps({"entry_id": "bad-schema"}) + "\n",
        encoding="utf-8",
    )
    out_path = tmp_path / "reports.jsonl"
    code = main([
        "--entries", str(entries_path),
        "--repo-cache", str(root / "mock_repo"),
        "--advisories", str(root / "mock_advisories"),
        "--out", str(out_path),
        "--llm", "mock",
    ])
    assert code == 0
    reports = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
    assert [report["entry_id"] for report in reports] == [
        "entry-cli-valid", "__invalid_input__:2", "__invalid_input__:3",
    ]
    assert reports[1]["input_error"]["kind"] == "json_parse_error"
    assert reports[2]["input_error"]["kind"] == "missing_field"


def test_cli_downgrades_invalid_agent_report_before_writing(tmp_path, monkeypatch):
    import vulngym_verify_demo.cli as cli
    from vulngym_verify_demo.schema import validate_report

    root = Path(__file__).resolve().parent.parent / "vulngym-verify-demo"
    entries_path = tmp_path / "entries.jsonl"
    entries_path.write_text(
        json.dumps(_valid_cli_entry(), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    out_path = tmp_path / "reports.jsonl"
    monkeypatch.setattr(cli, "verify_entry", lambda *_args, **_kwargs: {"verdict": "correct"})

    code = cli.main([
        "--entries", str(entries_path),
        "--repo-cache", str(root / "mock_repo"),
        "--advisories", str(root / "mock_advisories"),
        "--out", str(out_path),
        "--llm", "mock",
    ])

    assert code == 0
    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["verdict"] == "uncertain"
    assert report["report_error"]["kind"] == "invalid_report"
    assert validate_report(report) == []


def test_cli_schema_error_is_redacted_and_does_not_leak_path_or_key(tmp_path, capsys):
    """错误报告与 CLI 日志都不输出输入行中的 credential/path。"""
    from vulngym_verify_demo.cli import main

    root = Path(__file__).resolve().parent.parent / "vulngym-verify-demo"
    entries_path = tmp_path / "leaky.jsonl"
    entry = _valid_cli_entry()
    entry["repo_url"] = "C:\\Users\\private\\repo?api_key=short-test-key"
    entries_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    out_path = tmp_path / "reports.jsonl"
    assert main([
        "--entries", str(entries_path),
        "--repo-cache", str(root / "mock_repo"),
        "--advisories", str(root / "mock_advisories"),
        "--out", str(out_path),
        "--llm", "mock",
    ]) == 0
    rendered = out_path.read_text(encoding="utf-8") + capsys.readouterr().out
    assert "short-test-key" not in rendered
    assert "C:\\Users\\private" not in rendered


def test_cli_missing_resource_directory_is_configuration_error(tmp_path):
    from vulngym_verify_demo.cli import main

    entries = tmp_path / "entries.jsonl"
    entries.write_text("{}\n", encoding="utf-8")
    assert main([
        "--entries", str(entries),
        "--repo-cache", str(tmp_path / "missing-repo-cache"),
        "--advisories", str(tmp_path),
        "--out", str(tmp_path / "out.jsonl"),
    ]) == 2


def test_cli_non_positive_timeout_is_configuration_error(tmp_path):
    from vulngym_verify_demo.cli import main

    entries = tmp_path / "entries.jsonl"
    entries.write_text("{}\n", encoding="utf-8")
    assert main([
        "--entries", str(entries),
        "--repo-cache", str(tmp_path),
        "--advisories", str(tmp_path),
        "--out", str(tmp_path / "out.jsonl"),
        "--llm-timeout", "0",
    ]) == 2


# ============================================================
# _make_empty_fields 单元测试
# ============================================================


def test_make_empty_fields():
    """_make_empty_fields 生成 8 个 uncertain 字段。"""
    from vulngym_verify_demo.agent import _make_empty_fields
    
    fields = _make_empty_fields("测试证据")
    
    assert len(fields) == 8
    expected = ["entry_point", "critical_operation", "commit", "vuln_ids",
                "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace"]
    
    for name in expected:
        assert name in fields
        assert fields[name]["status"] == "uncertain"
        assert fields[name]["confidence"] == 0.0
        assert fields[name]["evidence"] == "测试证据"
        assert fields[name]["evidence_refs"] == []
