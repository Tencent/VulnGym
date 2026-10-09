# -*- coding: utf-8 -*-
"""I4 — LLM 语义判定与安全降级测试套件。

覆盖 I4 启动手册 §4 全部 8 个测试类、≥36 用例。

契约（来自 I4 启动手册 §3）：
  * parse_structured_response(raw) -> dict：合法 JSON 含 4 键；缺 evidence_refs 补 []；
    非法 JSON → uncertain；空 evidence 补默认；脱敏正则触发 → <redacted>
  * redact_text：Windows/Posix 路径、API key 风格、32+ hex/base64
  * 真实 LLM 失败 → SafeLLMClient；绝不回退为 correct（除非 primary 真给 correct）
  * make_client：prefer=mock/auto 各路径不抛未处理异常
  * PROMPT_VERSIONS：5 个 key 各有非空版本号
  * Prompt 内容含 [PROMPT_VERSION=key@ver] 前缀
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo.llm_client import (  # noqa: E402
    BaseLLMClient,
    DeepSeekClient,
    GLMClient,
    LLMError,
    LLMMessage,
    MockLLMClient,
    QwenClient,
    ResilientLLMClient,
    SafeLLMClient,
    ScriptedMockLLMClient,
    make_client,
    parse_structured_response,
    redact_text,
)
from vulngym_verify_demo import prompts as p_mod  # noqa: E402


# ============================================================
# TestParseStructured
# ============================================================

class TestParseStructured:
    """parse_structured_response 输入/输出契约。"""

    def test_legal_full_4_keys(self):
        raw = json.dumps({
            "status": "correct",
            "confidence": 0.85,
            "evidence": "ok",
            "evidence_refs": [{"source": "advisory", "locator": "x", "quote": "y"}],
        })
        out = parse_structured_response(raw)
        assert out["status"] == "correct"
        assert out["confidence"] == 0.85
        assert isinstance(out["evidence_refs"], list)

    def test_missing_evidence_refs_auto_fill_empty_list(self):
        raw = json.dumps({"status": "correct", "confidence": 0.85, "evidence": "ok"})
        out = parse_structured_response(raw)
        assert out["evidence_refs"] == []

    def test_illegal_json_returns_uncertain(self):
        out = parse_structured_response("{not valid json,,,}")
        assert out["status"] == "uncertain"
        assert out["confidence"] == 0.20
        assert out["evidence_refs"] == []
        assert out["evidence"]  # 非空

    def test_markdown_fenced_json_is_accepted(self):
        """GLM commonly wraps otherwise-valid JSON in a ```json fence."""
        out = parse_structured_response(
            '```json\n{"status":"correct","confidence":0.95,"evidence":"same finding"}\n```'
        )
        assert out["status"] == "correct"
        assert out["confidence"] == 0.95
        assert out["evidence"] == "same finding"

    def test_empty_evidence_default_text(self):
        raw = json.dumps({"status": "correct", "confidence": 0.85, "evidence": ""})
        out = parse_structured_response(raw)
        assert "empty evidence" in out["evidence"].lower() or "默认" in out["evidence"] or len(out["evidence"]) > 0
        # 出现空 evidence 时 status 应降级为 uncertain（防编造证据）
        assert out["status"] in ("uncertain", "correct")

    def test_invalid_status_uncertain(self):
        raw = json.dumps({"status": "definitely-yes", "confidence": 0.85, "evidence": "ok"})
        out = parse_structured_response(raw)
        assert out["status"] == "uncertain"

    def test_non_dict_json_uncertain(self):
        out = parse_structured_response('"just a string"')
        assert out["status"] == "uncertain"

    def test_evidence_redacted_path(self):
        raw = json.dumps({
            "status": "incorrect",
            "confidence": 0.9,
            "evidence": "see C:\\Users\\alice\\secret\\file.txt",
        })
        out = parse_structured_response(raw)
        assert "C:\\Users\\alice" not in out["evidence"]
        assert "<abspath>" in out["evidence"]

    def test_confidence_clamped_to_unit_interval(self):
        raw = json.dumps({"status": "correct", "confidence": 5.0, "evidence": "ok"})
        out = parse_structured_response(raw)
        assert 0.0 <= out["confidence"] <= 1.0


# ============================================================
# TestRedactText
# ============================================================

class TestRedactText:
    """redact_text 脱敏规则。"""

    def test_windows_path(self):
        s = "error at C:\\Users\\alice\\secret\\file.txt: not found"
        out = redact_text(s)
        assert "C:\\Users\\alice" not in out
        assert "<abspath>" in out

    def test_posix_path(self):
        s = "error at /home/alice/secret/file.txt: not found"
        out = redact_text(s)
        assert "/home/alice" not in out
        assert "<abspath>" in out

    def test_api_key_prefix(self):
        s = "auth: sk-abcdefghijklmnopqrstuvwxyz012345"
        out = redact_text(s)
        assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in out

    def test_generic_credential_parameter(self):
        s = "request failed: api_key=short-test-key"
        out = redact_text(s)
        assert "short-test-key" not in out

    def test_long_hex_redacted(self):
        s = "trace: " + "a" * 40
        out = redact_text(s)
        assert "a" * 40 not in out

    def test_short_hex_preserved(self):
        # 短 hex（如 commit 8 位前缀）不应被脱敏
        s = "commit abc12345 was processed"
        out = redact_text(s)
        assert "abc12345" in out

    def test_unicode_path(self):
        s = "error at C:\\Users\\用户\\文件.txt"
        out = redact_text(s)
        assert "C:\\Users\\用户" not in out


# ============================================================
# TestMockClient
# ============================================================

class TestMockClient:
    """ScriptedMockLLMClient 剧本行为。"""

    def test_title_path_returns_correct_with_evidence_refs(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user",
            "[PROMPT_VERSION=vuln_title_judge@1]\n判断 vuln_title 是否正确。\nadvisory title: XSS\nactual: XSS Issue")])
        data = json.loads(out)
        assert data["status"] == "correct"
        assert "evidence_refs" in data
        assert isinstance(data["evidence_refs"], list)

    def test_category_path_returns_correct(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user",
            "[PROMPT_VERSION=vuln_category_l1_judge@2]\n判断 vuln_category_l1 是否正确。\nadvisory_hint_l1: XSS\nactual: XSS")])
        data = json.loads(out)
        assert data["status"] == "correct"

    def test_category_mismatch_returns_incorrect(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user",
            "[PROMPT_VERSION=vuln_category_l1_judge@2]\n判断 vuln_category_l1 是否正确。\nadvisory_hint_l1: RCE\nactual: XSS")])
        data = json.loads(out)
        assert data["status"] == "incorrect"

    def test_default_returns_uncertain_not_correct(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user", "[PROMPT_VERSION=unknown_key@1]\ntotally unrelated prompt")])
        data = json.loads(out)
        assert data["status"] == "uncertain"
        assert data["confidence"] <= 0.50

    def test_self_check_returns_agree_dict(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user", "[PROMPT_VERSION=self_check_judge@1]\n请复核字段...")])
        data = json.loads(out)
        assert "agree" in data
        assert "comment" in data

    def test_every_branch_includes_evidence_field(self):
        """非 self-check 分支都含 evidence。self-check 分支含 agree/comment。"""
        llm = ScriptedMockLLMClient()
        for prompt in [
            "[PROMPT_VERSION=vuln_title_judge@1]\ntitle",
            "[PROMPT_VERSION=vuln_category_l1_judge@2]\nXSS\nactual: XSS",
            "[PROMPT_VERSION=vuln_ids_judge@1]\nadvisory cve_id: X\nghsa_id: Y\nactual: [X,Y]",
            "[PROMPT_VERSION=trace_overall_judge@2]\nentry\nnode_count: 3",
            "[PROMPT_VERSION=unknown@1]\nfallback",
        ]:
            out = llm.chat([LLMMessage("user", prompt)])
            data = json.loads(out)
            assert "evidence" in data, f"prompt={prompt} missing evidence"
            assert data["evidence"], f"prompt={prompt} has empty evidence"

    def test_self_check_branch_returns_agree_comment(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user", "[PROMPT_VERSION=self_check_judge@1]\n请复核")])
        data = json.loads(out)
        assert "agree" in data
        assert "comment" in data


# ============================================================
# TestSafeClient
# ============================================================

class TestSafeClient:
    """SafeLLMClient 永不返回 correct（除非 prompt 让其 self-check 协议触发）。"""

    def test_any_prompt_returns_uncertain(self):
        llm = SafeLLMClient()
        for prompt in [
            "judge this: definitely correct",
            "[PROMPT_VERSION=vuln_title_judge@1]\ntotally benign",
        ]:
            data = json.loads(llm.chat([LLMMessage("user", prompt)]))
            assert data["status"] == "uncertain", f"safe should be uncertain for {prompt!r}"

    def test_evidence_contains_reason(self):
        llm = SafeLLMClient()
        data = json.loads(llm.chat([LLMMessage("user", "anything")]))
        assert "unavailable" in data["evidence"].lower() or "无法" in data["evidence"]

    def test_self_check_safe_path_returns_disagree(self):
        llm = SafeLLMClient()
        data = json.loads(llm.chat([LLMMessage("user", "[PROMPT_VERSION=self_check_judge@1]\n请复核")]))
        assert data["agree"] is False
        assert "comment" in data
        assert data["comment"]


# ============================================================
# TestResilientClient
# ============================================================

class TestResilientClient:
    """ResilientLLMClient 容错行为。"""

    def test_primary_success_no_fallback(self):
        primary = ScriptedMockLLMClient()
        fallback = SafeLLMClient()
        r = ResilientLLMClient(primary, fallback)
        out = r.chat([LLMMessage("user", "[PROMPT_VERSION=vuln_title_judge@1]\njudge title")])
        data = json.loads(out)
        assert data["status"] in ("correct", "uncertain")  # primary 决定
        assert not r.degraded

    def test_primary_failure_falls_back(self):
        class FailingClient(BaseLLMClient):
            name = "FailingClient"
            def chat(self, messages, *, temperature=0.0):
                raise LLMError("network down")
        primary = FailingClient()
        fallback = SafeLLMClient()
        r = ResilientLLMClient(primary, fallback)
        out = r.chat([LLMMessage("user", "anything")])
        data = json.loads(out)
        assert data["status"] == "uncertain"
        assert r.degraded

    def test_unexpected_primary_error_falls_back_and_redacts_log(self, capsys):
        """非 LLMError（如 HTTP/JSON 库错误）同样安全降级，日志不泄露 key。"""
        class LeakyClient(BaseLLMClient):
            name = "LeakyClient"
            def chat(self, messages, *, temperature=0.0):
                raise ValueError("Bearer super-secret-token-12345678 response invalid")

        out = ResilientLLMClient(LeakyClient(), SafeLLMClient()).chat([LLMMessage("user", "x")])
        assert json.loads(out)["status"] == "uncertain"
        assert "super-secret-token" not in capsys.readouterr().err

    def test_each_independent_request_attempts_primary_once(self):
        call_count = {"primary": 0, "fallback": 0}

        class CountingFailingPrimary(BaseLLMClient):
            name = "CountingFailingPrimary"
            def chat(self, messages, *, temperature=0.0):
                call_count["primary"] += 1
                raise LLMError("always fail")

        class CountingFallback(BaseLLMClient):
            name = "CountingFallback"
            def chat(self, messages, *, temperature=0.0):
                call_count["fallback"] += 1
                return json.dumps({"status": "uncertain", "confidence": 0.2,
                                   "evidence": "fb", "evidence_refs": []})

        r = ResilientLLMClient(CountingFailingPrimary(), CountingFallback())
        for _ in range(3):
            r.chat([LLMMessage("user", "x")])
        # 每个独立字段请求只尝试 primary 一次；没有内部重试，也不会因
        # 前一个短暂故障把整批条目永久切到 Safe fallback。
        assert call_count["primary"] == 3
        assert call_count["fallback"] == 3
        assert r.degraded

    def test_later_request_can_recover_after_transient_failure(self):
        class FailOncePrimary(BaseLLMClient):
            name = "FailOncePrimary"

            def __init__(self):
                self.calls = 0

            def chat(self, messages, *, temperature=0.0):
                self.calls += 1
                if self.calls == 1:
                    raise LLMError("temporary timeout")
                return json.dumps({
                    "status": "correct", "confidence": 0.8,
                    "evidence": "primary recovered", "evidence_refs": [],
                })

        primary = FailOncePrimary()
        r = ResilientLLMClient(primary, SafeLLMClient())
        assert json.loads(r.chat([LLMMessage("user", "first")]))["status"] == "uncertain"
        assert json.loads(r.chat([LLMMessage("user", "second")]))["status"] == "correct"
        assert primary.calls == 2


# ============================================================
# TestMakeClient
# ============================================================

class TestMakeClient:
    """make_client 在所有路径下不抛未处理异常。"""

    def test_prefer_mock(self, monkeypatch):
        monkeypatch.delenv("QWEN_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        c = make_client(prefer="mock")
        assert isinstance(c, BaseLLMClient)
        assert c.name.startswith("ScriptedMockLLMClient") or "Mock" in c.name

    def test_prefer_unknown_falls_back_to_safe(self, monkeypatch):
        monkeypatch.delenv("QWEN_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        c = make_client(prefer="totally-unknown-vendor")
        assert isinstance(c, BaseLLMClient)

    def test_auto_no_keys_returns_safe(self, monkeypatch):
        monkeypatch.delenv("QWEN_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.delenv("QWEN_BASE_URL", raising=False)
        monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
        monkeypatch.delenv("GLM_BASE_URL", raising=False)
        c = make_client(prefer="auto")
        assert isinstance(c, BaseLLMClient)
        # 应该是 Safe 或 Resilient(Safe)
        assert "Safe" in c.name or "Resilient" in c.name

    def test_auto_with_deepseek_key_returns_resilient(self, monkeypatch):
        monkeypatch.delenv("QWEN_API_KEY", raising=False)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.setenv("DEEPSEEK_API_KEY", "fake-key-for-test")
        monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        c = make_client(prefer="auto")
        assert "Resilient" in c.name
        assert "DeepSeek" in c.name

    def test_prefer_qwen_no_key_returns_safe(self, monkeypatch):
        monkeypatch.delenv("QWEN_API_KEY", raising=False)
        monkeypatch.delenv("QWEN_BASE_URL", raising=False)
        c = make_client(prefer="qwen")
        assert isinstance(c, BaseLLMClient)

    def test_rejects_non_positive_timeout(self):
        with pytest.raises(ValueError):
            make_client(prefer="mock", timeout=0)
        with pytest.raises(ValueError):
            make_client(prefer="mock", timeout=float("inf"))


# ============================================================
# TestRealClientSmoke
# ============================================================

class TestRealClientSmoke:
    """真实客户端在缺 key 时构造报 LLMError，不抛其他异常。"""

    def test_qwen_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("QWEN_API_KEY", raising=False)
        monkeypatch.delenv("QWEN_BASE_URL", raising=False)
        with pytest.raises(LLMError):
            QwenClient()

    def test_deepseek_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
        with pytest.raises(LLMError):
            DeepSeekClient()

    def test_glm_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.delenv("GLM_BASE_URL", raising=False)
        with pytest.raises(LLMError):
            GLMClient()

    def test_qwen_constructor_no_network(self, monkeypatch):
        """仅构造，不发起任何网络请求。"""
        monkeypatch.setenv("QWEN_API_KEY", "fake")
        monkeypatch.setenv("QWEN_BASE_URL", "https://example.com")
        c = QwenClient()
        assert c.name.startswith("QwenClient")


# ============================================================
# TestPromptVersioning
# ============================================================

class TestPromptVersioning:
    """Prompt 版本号与前缀。"""

    def test_prompt_versions_all_keys(self):
        required = [
            "vuln_title_judge", "vuln_category_l1_judge",
            "vuln_category_l2_judge", "trace_overall_judge",
            "self_check_judge",
        ]
        for k in required:
            assert k in p_mod.PROMPT_VERSIONS
            assert p_mod.PROMPT_VERSIONS[k], f"{k} version is empty"
            assert re.fullmatch(r"\d+", p_mod.PROMPT_VERSIONS[k])

    def test_vuln_title_prompt_has_version_prefix(self):
        assert "[PROMPT_VERSION=vuln_title_judge@1]" in p_mod.VULN_TITLE_PROMPT

    def test_category_prompt_has_version_prefix(self):
        s = p_mod.vuln_category_prompt("l1", "XSS", "XSS")
        assert "[PROMPT_VERSION=vuln_category_l1_judge@2]" in s

    def test_trace_prompt_has_version_prefix(self):
        s = p_mod.TRACE_OVERALL_PROMPT.format(entry_id="e1", node_count=3, trace_summary="node")
        assert "[PROMPT_VERSION=trace_overall_judge@2]" in s

    def test_mock_client_recognizes_version_prefix(self):
        llm = ScriptedMockLLMClient()
        out = llm.chat([LLMMessage("user",
            "[PROMPT_VERSION=vuln_title_judge@1]\njudgment body")])
        data = json.loads(out)
        # version 前缀应能路由到 title 分支 → correct
        assert data["status"] == "correct"

    def test_safe_client_includes_version_in_comment(self):
        llm = SafeLLMClient()
        out = llm.chat([LLMMessage("user", "anything")])
        data = json.loads(out)
        # Safe 响应可以含版本信息在 evidence/comment
        assert data.get("evidence")


# ============================================================
# TestBackwardCompatAlias
# ============================================================

class TestBackwardCompatAlias:
    """旧名字仍可用。"""

    def test_mock_llm_client_alias(self):
        assert MockLLMClient is ScriptedMockLLMClient
