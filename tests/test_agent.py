# -*- coding: utf-8 -*-
"""I5 — Agent 规划、tool_trace、self-check 测试套件。

覆盖 I5 启动手册 §4 全部 7 个测试类、≥35 用例。

契约（来自 I5_START_HANDBOOK §3 与 I1 report_schema.json）：
  * plan 必含 version="1" / tools_planned / fields_planned
  * 正常完整路径的 tool_trace 覆盖 advisory + repository + git；降级路径只记录真实调用
  * tool_trace 失败也记录（ok=false + error），不抛未处理异常
  * tool_trace.input 脱敏（commit ≤12 字符、不含绝对路径）
  * self_check 必含 status/agree/comment/checked_fields 四键
  * self_check status=skipped|failed → agree 强制 false
  * verify_entry 返回 dict 必含 I1 schema 全部顶层字段
  * verify_entries 顺序处理 + 坏 entry 不中断
  * 完整 report 可被 schema.validate_report 校验通过
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo import agent as agent_mod  # noqa: E402
from vulngym_verify_demo.agent import (  # noqa: E402
    EIGHT_FIELDS,
    _RecordingTools,
    _revisit_semantic_fields,
    get_eight_fields,
    get_tool_category,
    plan_for_entry,
    self_check,
    verify_entries,
    verify_entry,
)
from vulngym_verify_demo.llm_client import (  # noqa: E402
    BaseLLMClient,
    LLMMessage,
    SafeLLMClient,
    ScriptedMockLLMClient,
)
from vulngym_verify_demo.schema import (  # noqa: E402
    validate_plan,
    validate_report,
    validate_self_check,
    validate_tool_call,
)
from vulngym_verify_demo.tools import (  # noqa: E402
    ToolResult,
    VulnGymTools,
    load_manifest,
)

MOCK_REPO_ROOT = ROOT / "vulngym-verify-demo" / "mock_repo"
MOCK_ADV_DIR = ROOT / "vulngym-verify-demo" / "mock_advisories"


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture(scope="module")
def manifest() -> Dict[str, Any]:
    with open(MOCK_REPO_ROOT / "manifest.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def workspace(tmp_path: Path):
    """构造独立 repo_cache + advisory，复制 mock_repo + mock_advisories 内容。"""
    repo_cache = tmp_path / "repo_cache"
    advisory_dir = tmp_path / "advisories"
    repo_cache.mkdir()
    advisory_dir.mkdir()
    for src in MOCK_REPO_ROOT.rglob("*"):
        if src.is_file():
            rel = src.relative_to(MOCK_REPO_ROOT)
            dst = repo_cache / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
    for src in MOCK_ADV_DIR.glob("*.json"):
        (advisory_dir / src.name).write_bytes(src.read_bytes())
    return repo_cache, advisory_dir


@pytest.fixture
def tools(workspace, manifest) -> VulnGymTools:
    repo_cache, advisory_dir = workspace
    return VulnGymTools(
        repo_cache_dir=repo_cache,
        advisory_dir=advisory_dir,
        manifest=manifest,
    )


@pytest.fixture
def llm() -> BaseLLMClient:
    return ScriptedMockLLMClient()


def _valid_entry() -> Dict[str, Any]:
    """构造一条最小合法 entry。"""
    return {
        "entry_id": "entry-00001",
        "report_id": "GHSA-DEMO-0001-0XSS",
        "repo_url": "https://github.com/example/blog-platform",
        "commit": "1111111111111111111111111111111111111111",
        "verify": {
            "file": "src/handlers/comment.js",
            "commit": "1111111111111111111111111111111111111111",
        },
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "blog-platform",
        "source_link": "https://github.com/advisories/GHSA-DEMO-0001-0XSS",
        "vuln_ids": ["CVE-2026-0001", "GHSA-DEMO-0001-0XSS"],
        "vuln_title": "Blog Platform Stored DOM XSS via Comment Rich Text",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "entry_point": {
            "file": "src/handlers/comment.js",
            "line": 97,
            "code": "insertTextHandler(data.content);",
        },
        "critical_operation": {
            "file": "src/lib/RichTextInput.svelte",
            "line": 348,
            "code": "tempDiv.innerHTML = htmlContent;",
        },
        "trace": [
            {
                "file": "src/lib/RichTextInput.svelte",
                "line": 343,
                "code": "renderRichText(content);",
            }
        ],
    }


# ============================================================
# TestPlan: plan_for_entry
# ============================================================


class TestPlan:
    """plan_for_entry 输出契约。"""

    def test_plan_version_is_string_one(self):
        plan = plan_for_entry(_valid_entry())
        assert plan["version"] == "1"
        assert isinstance(plan["version"], str)

    def test_plan_tools_covers_three_categories(self):
        plan = plan_for_entry(_valid_entry())
        cats = {get_tool_category(t) for t in plan["tools_planned"]}
        assert "advisory" in cats
        assert "repository" in cats
        assert "git" in cats

    def test_plan_fields_planned_has_eight_fields(self):
        plan = plan_for_entry(_valid_entry())
        assert set(plan["fields_planned"]) == set(EIGHT_FIELDS)
        assert len(plan["fields_planned"]) == 8

    def test_plan_round_trip_json(self):
        plan = plan_for_entry(_valid_entry())
        s = json.dumps(plan, ensure_ascii=False)
        loaded = json.loads(s)
        assert loaded == plan
        # schema 校验
        errs = validate_plan(loaded)
        assert errs == [], f"plan validate errors: {errs}"

    def test_plan_entry_id_report_id_propagated(self):
        entry = _valid_entry()
        plan = plan_for_entry(entry)
        assert plan["entry_id"] == entry["entry_id"]
        assert plan["report_id"] == entry["report_id"]

    def test_plan_with_minimal_entry(self):
        """空 entry 不抛异常。"""
        plan = plan_for_entry({})
        assert plan["version"] == "1"
        assert plan["entry_id"] is None
        assert plan["report_id"] is None


# ============================================================
# TestToolTrace: _build_tool_trace / tool_trace schema
# ============================================================


class TestToolTrace:
    """tool_trace 构造与 schema 契约。"""

    def test_three_categories_present(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        cats = {get_tool_category(t["tool"]) for t in rep["tool_trace"]}
        assert "advisory" in cats
        assert "repository" in cats
        assert "git" in cats

    def test_seq_strictly_monotonic(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        seqs = [t["seq"] for t in rep["tool_trace"]]
        assert seqs == sorted(seqs)
        assert all(isinstance(s, int) for s in seqs)
        assert all(s >= 1 for s in seqs)

    def test_trace_records_only_actual_checker_calls(self, tools):
        """trace 是检查器真实调用的顺序记录，不能在结束后补做审计调用。"""
        calls: List[str] = []
        for name in (
            "read_advisory", "checkout", "read_file_lines", "grep_code",
            "git_log", "git_tags_at_commit",
        ):
            original = getattr(tools, name)

            def wrapper(*args, _name=name, _original=original, **kwargs):
                calls.append(_name)
                return _original(*args, **kwargs)

            setattr(tools, name, wrapper)

        rep = verify_entry(_valid_entry(), tools, ScriptedMockLLMClient())
        assert [call["tool"] for call in rep["tool_trace"]] == calls

    def test_ok_false_recorded_on_failure(self, tools):
        """advisory 找不到时仍记录（ok=false + error）。"""
        entry = _valid_entry()
        entry["report_id"] = "GHSA-NOT-EXIST-XYZ"
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        adv = next(t for t in rep["tool_trace"] if t["tool"] == "read_advisory")
        assert adv["ok"] is False
        assert isinstance(adv["error"], str) and adv["error"]
        assert adv["error_code"] == "advisory_not_found"

    def test_input_redacted_for_commit(self, tools):
        """commit 在 trace.input 中只出现前 12 字符（防 32+ hex 触发 redact）。"""
        entry = _valid_entry()
        full_commit = "1111111111111111111111111111111111111111"
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        # 把所有 input 序列化成字符串后校验
        all_input_str = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        assert full_commit not in all_input_str
        # 但 commit 前 12 字符应出现
        assert "111111111111" in all_input_str

    def test_input_no_absolute_path(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        all_input_str = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        # 不能出现 Windows / POSIX 绝对路径
        assert "C:\\" not in all_input_str
        assert "C:/" not in all_input_str
        assert not any(seg in all_input_str for seg in ["/home/", "/Users/", "/tmp/", "/var/"])

    def test_no_unhandled_exception_on_bad_commit(self, tools):
        """坏 commit 仍生成报告，不抛异常。"""
        entry = _valid_entry()
        entry["commit"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  # 不在缓存
        entry["verify"]["commit"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        assert isinstance(rep, dict)
        assert "tool_trace" in rep
        # clone 无法解析时不会伪造 repository 调用；字段 evidence 会说明降级原因。
        cats = {get_tool_category(t["tool"]) for t in rep["tool_trace"]}
        assert "advisory" in cats
        assert "git" in cats
        assert "repository" not in cats
        assert "本地" in rep["fields"]["entry_point"]["evidence"]

    def test_evidence_refs_are_json_paths(self, tools):
        """trace.evidence_refs 必须是 JSON 路径格式 (fields.<name>.evidence)。"""
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        for t in rep["tool_trace"]:
            for ref in t["evidence_refs"]:
                assert isinstance(ref, str)
                assert ref.startswith("fields.")
                assert ".evidence" in ref

    def test_all_tool_calls_have_ok_field(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        for t in rep["tool_trace"]:
            assert "ok" in t
            assert isinstance(t["ok"], bool)
            # schema 校验通过
            errs = validate_tool_call(t)
            assert errs == [], f"validate_tool_call errors: {errs}"


# ============================================================
# TestSelfCheck: self_check 函数契约
# ============================================================


class TestSelfCheck:
    """self_check 四键契约与 skipped/failed→agree=false 约束。"""

    def test_completed_path_agree_from_llm(self):
        """LLM 返回 agree=True → status=completed + agree=True。"""
        llm = ScriptedMockLLMClient()  # self-check 分支默认返回 agree=True
        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, llm)
        assert out["status"] == "completed"
        assert out["agree"] is True
        assert isinstance(out["comment"], str) and out["comment"]
        assert isinstance(out["checked_fields"], list)

    def test_self_check_uses_versioned_prompt(self):
        captured: List[str] = []

        class CaptureLLM(BaseLLMClient):
            def chat(self, messages, *, temperature=0.0):
                captured.append(messages[0].content)
                return json.dumps({"agree": True, "comment": "ok"})

        self_check(_valid_entry(), {}, CaptureLLM())
        assert "[PROMPT_VERSION=self_check_judge@1]" in captured[0]

    def test_self_check_accepts_markdown_fenced_json(self):
        """Provider formatting must not turn a completed self-check into skipped."""
        class FencedJSONLLM(BaseLLMClient):
            def chat(self, messages, *, temperature=0.0):
                return '```json\n{"agree": true, "comment": "evidence is consistent"}\n```'

        out = self_check(_valid_entry(), {}, FencedJSONLLM())
        assert out["status"] == "completed"
        assert out["agree"] is True

    def test_skipped_path_agree_is_false(self):
        """LLM 抛异常 → status=skipped + agree=False（I5 契约）。"""
        class BoomLLM(BaseLLMClient):
            name = "BoomLLM"
            def chat(self, messages, *, temperature=0.0):
                raise RuntimeError("network down")

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, BoomLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False
        assert isinstance(out["comment"], str) and out["comment"]

    def test_skipped_path_safe_client(self):
        """SafeLLMClient 是 fallback → self_check 必须返回 skipped + agree=False。"""
        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, SafeLLMClient())
        # SafeLLMClient 的 chat_with_provenance 标记 used_fallback=True → skipped
        assert out["status"] == "skipped"
        assert out["agree"] is False
        assert out["comment"]
        assert "fallback" in out["comment"].lower() or "unavailable" in out["comment"].lower()

    def test_checked_fields_lists_all_fields(self):
        llm = ScriptedMockLLMClient()
        fr = {k: {"status": "correct", "confidence": 0.9, "evidence": "x",
                  "evidence_refs": []} for k in EIGHT_FIELDS}
        out = self_check(_valid_entry(), fr, llm)
        assert set(out["checked_fields"]) == set(EIGHT_FIELDS)

    def test_comment_never_empty(self):
        """comment 必须非空（I1 schema 隐式）。"""
        class EmptyCommentLLM(BaseLLMClient):
            name = "EmptyCommentLLM"
            def chat(self, messages, *, temperature=0.0):
                return json.dumps({"agree": True, "comment": "   "})

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, EmptyCommentLLM())
        assert out["comment"]  # 非空
        # 若 LLM 返回空白 comment，应替换为默认
        assert out["comment"].strip()

    def test_illegal_json_returns_skipped(self):
        """LLM 返回非法 JSON → status=skipped + agree=False。"""
        class BadJSONLLM(BaseLLMClient):
            name = "BadJSONLLM"
            def chat(self, messages, *, temperature=0.0):
                return "not a json at all"

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, BadJSONLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_non_dict_json_returns_skipped(self):
        """LLM 返回合法 JSON 但不是 dict → skipped + agree=False。"""
        class NonDictLLM(BaseLLMClient):
            name = "NonDictLLM"
            def chat(self, messages, *, temperature=0.0):
                return json.dumps([1, 2, 3])

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, NonDictLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_self_check_schema_validate(self):
        """self_check 返回值必须通过 validate_self_check。"""
        llm = ScriptedMockLLMClient()
        fr = {k: {"status": "correct", "confidence": 0.9, "evidence": "x",
                  "evidence_refs": []} for k in EIGHT_FIELDS}
        out = self_check(_valid_entry(), fr, llm)
        errs = validate_self_check(out)
        assert errs == [], f"validate_self_check errors: {errs}"

    def test_resilient_fallback_marks_skipped(self):
        """ResilientLLMClient primary 失败走 Safe fallback → self_check skipped。"""
        from vulngym_verify_demo.llm_client import ResilientLLMClient

        class BoomPrimary(BaseLLMClient):
            name = "BoomPrimary"
            def chat(self, messages, *, temperature=0.0):
                raise RuntimeError("primary down")

        llm = ResilientLLMClient(primary=BoomPrimary(), fallback=SafeLLMClient())
        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, llm)
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_revisit_only_touches_semantic_fields(self):
        """复核只修改 title/L1/L2/trace，确定性字段不变。"""
        class ReviseLLM(BaseLLMClient):
            name = "ReviseLLM"
            def chat(self, messages, *, temperature=0.0):
                return json.dumps({
                    "vuln_title": {"status": "incorrect", "confidence": 0.7, "evidence": "revised"},
                    "vuln_category_l1": {"status": "correct", "confidence": 0.8, "evidence": "kept"},
                    "vuln_category_l2": {"status": "uncertain", "confidence": 0.5, "evidence": "revised"},
                    "trace": {"status": "correct", "confidence": 0.6, "evidence": "kept"},
                })

        fields = {
            "entry_point": {"status": "correct", "confidence": 0.9, "evidence": "ep", "evidence_refs": []},
            "critical_operation": {"status": "correct", "confidence": 0.9, "evidence": "co", "evidence_refs": []},
            "commit": {"status": "uncertain", "confidence": 0.4, "evidence": "commit", "evidence_refs": []},
            "vuln_ids": {"status": "correct", "confidence": 0.95, "evidence": "ids", "evidence_refs": []},
            "vuln_title": {"status": "correct", "confidence": 0.8, "evidence": "title orig", "evidence_refs": []},
            "vuln_category_l1": {"status": "correct", "confidence": 0.8, "evidence": "l1 orig", "evidence_refs": []},
            "vuln_category_l2": {"status": "correct", "confidence": 0.8, "evidence": "l2 orig", "evidence_refs": []},
            "trace": {"status": "incorrect", "confidence": 0.7, "evidence": "trace orig", "evidence_refs": []},
        }
        updated, record = _revisit_semantic_fields(_valid_entry(), fields, ReviseLLM())
        # 确定性字段不变
        assert updated["entry_point"]["status"] == "correct"
        assert updated["critical_operation"]["status"] == "correct"
        assert updated["commit"]["status"] == "uncertain"
        assert updated["vuln_ids"]["status"] == "correct"
        # 语义字段被复核修改
        assert updated["vuln_title"]["status"] == "incorrect"
        assert updated["vuln_category_l2"]["status"] == "uncertain"
        assert record["status"] == "completed"
        assert len(record["changes"]) >= 1

    def test_revisit_failure_preserves_original(self):
        """复核 LLM 失败 / fallback 时保留原初判。"""
        fields = {
            "vuln_title": {"status": "correct", "confidence": 0.8, "evidence": "t", "evidence_refs": []},
            "vuln_category_l1": {"status": "correct", "confidence": 0.8, "evidence": "l1", "evidence_refs": []},
            "vuln_category_l2": {"status": "correct", "confidence": 0.8, "evidence": "l2", "evidence_refs": []},
            "trace": {"status": "correct", "confidence": 0.8, "evidence": "tr", "evidence_refs": []},
        }
        updated, record = _revisit_semantic_fields(_valid_entry(), fields, SafeLLMClient())
        assert updated["vuln_title"]["status"] == "correct"
        assert record["status"] == "skipped"
        assert record["changes"] == []


# ============================================================
# TestVerifyEntry: verify_entry 完整流程
# ============================================================


class TestVerifyEntry:
    """verify_entry 端到端契约。"""

    def test_returns_all_required_top_fields(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        for key in (
            "report_id", "entry_id", "verdict", "fields",
            "summary", "self_check", "plan", "tool_trace",
        ):
            assert key in rep, f"missing top-level key: {key}"

    def test_tool_trace_has_three_categories(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        cats = {get_tool_category(t["tool"]) for t in rep["tool_trace"]}
        assert {"advisory", "repository", "git"}.issubset(cats)

    def test_verdict_is_three_state_value(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert rep["verdict"] in ("correct", "incorrect", "uncertain")

    def test_summary_non_empty(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert isinstance(rep["summary"], str)
        assert rep["summary"].strip()

    def test_bad_commit_still_generates_report(self, tools, llm):
        entry = _valid_entry()
        entry["commit"] = "0" * 40  # 不在 manifest 中
        entry["verify"]["commit"] = "0" * 40
        rep = verify_entry(entry, tools, llm)
        assert isinstance(rep, dict)
        assert "fields" in rep
        assert len(rep["fields"]) == 8

    def test_missing_report_id_still_generates_report(self, tools, llm):
        entry = _valid_entry()
        entry["report_id"] = ""
        rep = verify_entry(entry, tools, llm)
        assert isinstance(rep, dict)
        assert rep["report_id"] == ""
        # tool_trace 的 read_advisory 记录应当 ok=false
        adv = next(t for t in rep["tool_trace"] if t["tool"] == "read_advisory")
        assert adv["ok"] is False

    def test_self_check_has_four_keys(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        sc = rep["self_check"]
        for key in ("status", "agree", "comment", "checked_fields"):
            assert key in sc, f"self_check missing key: {key}"

    def test_plan_version_equals_one(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert rep["plan"]["version"] == "1"


# ============================================================
# TestVerifyEntries: 批量处理
# ============================================================


class TestVerifyEntries:
    """verify_entries 顺序处理 + 鲁棒性。"""

    def test_empty_list_returns_empty(self, tools, llm):
        out = verify_entries([], tools, llm)
        assert out == []

    def test_processes_in_order(self, tools, llm):
        e1 = _valid_entry()
        e2 = _valid_entry()
        e2["entry_id"] = "entry-00002"
        e2["report_id"] = "GHSA-DEMO-0002-0RCE"
        e2["repo_url"] = "https://github.com/example/shell-runner"
        e2["commit"] = "2222222222222222222222222222222222222222"
        e2["verify"]["commit"] = "2222222222222222222222222222222222222222"
        e2["verify"]["file"] = "src/api.js"
        e2["entry_point"]["file"] = "src/api.js"
        e2["entry_point"]["code"] = 'spawn("sh", ["-c", cmd]);'
        e2["critical_operation"]["file"] = "src/runner.js"
        e2["critical_operation"]["code"] = "child_process.exec(userInput);"
        e2["trace"] = []
        e2["vuln_ids"] = ["CVE-2026-0002"]
        e2["vuln_title"] = "Shell Runner RCE"
        e2["vuln_category_l1"] = "代码注入"
        e2["vuln_category_l2"] = "命令注入"

        out = verify_entries([e1, e2], tools, llm)
        assert len(out) == 2
        assert out[0]["entry_id"] == "entry-00001"
        assert out[1]["entry_id"] == "entry-00002"

    def test_mixed_valid_and_bad_does_not_break(self, tools, llm):
        good = _valid_entry()
        bad = _valid_entry()
        bad["commit"] = "X" * 40  # 坏 commit
        bad["verify"]["commit"] = "X" * 40
        out = verify_entries([good, bad], tools, llm)
        assert len(out) == 2
        # 两条都返回 dict
        assert all(isinstance(r, dict) for r in out)
        assert all("fields" in r and len(r["fields"]) == 8 for r in out)

    def test_verbose_does_not_raise(self, tools, llm, capsys):
        out = verify_entries([_valid_entry()], tools, llm, verbose=True)
        assert len(out) == 1
        # 输出捕获存在（verbose 模式打了字）
        captured = capsys.readouterr()
        assert "[plan]" in captured.out or "[verdict]" in captured.out


# ============================================================
# TestSchemaConformance: 整报告通过 I1 schema 校验
# ============================================================


class TestSchemaConformance:
    """完整 VerificationReport 必须通过 validate_report。"""

    def test_full_report_validates(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        errs = validate_report(rep)
        assert errs == [], f"validate_report errors: {errs}"

    def test_plan_version_strict_one(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert rep["plan"]["version"] == "1"

    def test_self_check_agree_false_when_skipped(self):
        class BoomLLM(BaseLLMClient):
            name = "BoomLLM"
            def chat(self, messages, *, temperature=0.0):
                raise RuntimeError("net down")
        fr = {k: {"status": "correct", "confidence": 0.9, "evidence": "x",
                  "evidence_refs": []} for k in EIGHT_FIELDS}
        out = self_check(_valid_entry(), fr, BoomLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_tool_trace_seq_at_least_one(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert len(rep["tool_trace"]) >= 1
        for t in rep["tool_trace"]:
            assert t["seq"] >= 1

    def test_eight_fields_present(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert set(rep["fields"].keys()) == set(EIGHT_FIELDS)


# ============================================================
# TestRedaction: trace.input 脱敏规则
# ============================================================


class TestRedaction:
    """trace.input 必须脱敏：commit ≤12 字符 + 无绝对路径。"""

    def test_commit_truncated(self, tools):
        entry = _valid_entry()
        long_commit = "abcdef0123456789abcdef0123456789abcdef01"  # 40 chars
        entry["commit"] = long_commit
        entry["verify"]["commit"] = long_commit
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        all_input = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        # 完整 40-char commit 不应出现
        assert long_commit not in all_input
        # 前 12 字符 + ellipsis 应出现
        assert "abcdef012345" in all_input

    def test_no_absolute_path_in_trace(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        all_input = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        # 不包含 Windows 绝对路径特征
        assert not any(s in all_input for s in ("C:\\", "D:\\", "/home/", "/Users/", "/tmp/"))


# ============================================================
# TestHelpers: 辅助函数
# ============================================================


class TestHelpers:
    """暴露给上层的 helper 函数。"""

    def test_get_eight_fields_returns_copy(self):
        f1 = get_eight_fields()
        f1.append("extra")
        f2 = get_eight_fields()
        assert "extra" not in f2
        assert len(f2) == 8

    def test_get_tool_category_known(self):
        assert get_tool_category("read_advisory") == "advisory"
        assert get_tool_category("checkout") == "git"
        assert get_tool_category("read_file_lines") == "repository"
        assert get_tool_category("git_log") == "git"
        assert get_tool_category("git_tags_at_commit") == "git"
        assert get_tool_category("grep_code") == "repository"

    def test_get_tool_category_unknown(self):
        assert get_tool_category("nope") is None


# ============================================================
# TestImportSurface: 公共符号导出
# ============================================================


class TestImportSurface:
    """I5 公共符号可从 agent 模块导入。"""

    def test_public_functions_importable(self):
        from vulngym_verify_demo.agent import (  # noqa: F401
            plan_for_entry,
            self_check,
            verify_entry,
            verify_entries,
            get_eight_fields,
            get_tool_category,
            EIGHT_FIELDS,
        )


# ============================================================
# TestPerEntryCache — per-entry 只读 cache（P1-A）
# ============================================================


class TestPerEntryCache:
    """per-entry 只读 cache 契约：重复读取只调一次底层工具，cache hit 不伪造 trace。"""

    def test_cache_key_accepts_kwargs_for_git_log(self):
        """_cache_key 必须接受 **kwargs——git_log 传 limit= 不能 TypeError。

        回归测试：真实运行时 _cache_key 缺少 **kwargs，git_log(limit=5) 直接
        TypeError 导致整条 entry 降级为 agent-level fallback。
        """
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        # git_log 传 limit 作为 kwarg（与 agent.git_log() 实际调用方式一致）
        key = tools._cache_key("git_log", "myproject", "abc1234", limit=10)
        assert key is not None
        assert "10" in key
        assert key == "git_log:myproject:abc1234:10"

    def test_cache_key_default_limit_when_omitted(self):
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        key = tools._cache_key("git_log", "proj", "commit")
        assert key == "git_log:proj:commit:5"

    def test_cache_key_different_limit_different_key(self):
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        k1 = tools._cache_key("git_log", "p", "c", limit=5)
        k2 = tools._cache_key("git_log", "p", "c", limit=20)
        assert k1 != k2

    def test_cache_key_checkout(self):
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        key = tools._cache_key("checkout", "proj", "abc1234")
        assert key == "checkout:proj:abc1234"

    def test_cache_key_read_file_lines(self):
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        key = tools._cache_key("read_file_lines", "/cwd", "src/a.js", 1, 10)
        assert key == "read_file_lines:/cwd:src/a.js:1:10"

    def test_cache_key_git_tags_at_commit(self):
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        key = tools._cache_key("git_tags_at_commit", "proj", "abc1234")
        assert key == "git_tags_at_commit:proj:abc1234"

    def test_cache_key_returns_none_for_uncached_tools(self):
        """read_advisory / grep_code 不缓存。"""
        tools = _RecordingTools.__new__(_RecordingTools)
        tools._cache = {}
        assert tools._cache_key("read_advisory", "GHSA-X") is None
        assert tools._cache_key("grep_code", "/cwd", "f", "pat") is None

    def test_cache_hit_does_not_record_tool_trace(self):
        """cache hit 直接返回缓存结果，不追加 tool_trace。"""
        class FakeTools:
            def __init__(self):
                self.call_count = 0
            def read_file_lines(self, cwd, file, start, end):
                self.call_count += 1
                from vulngym_verify_demo.tools import ToolResult
                return ToolResult("read_file_lines", True, {"lines": ["x"]}, None, None)

        fake = FakeTools()
        rec = _RecordingTools(fake)
        # 第一次调用：底层工具被调用，trace 记录一条
        r1 = rec.read_file_lines("/cwd", "a.js", 1, 5)
        assert fake.call_count == 1
        assert len(rec.trace) == 1
        # 第二次相同调用：cache hit，底层工具不被调用，trace 不增加
        r2 = rec.read_file_lines("/cwd", "a.js", 1, 5)
        assert fake.call_count == 1  # 没有再次调用
        assert len(rec.trace) == 1  # 没有追加 trace
        assert r2.ok is True

    def test_cache_only_stores_successful_results(self):
        """失败结果不缓存，允许后续重试。"""
        from vulngym_verify_demo.tools import ToolResult

        call_count = {"n": 0}

        class FlakyTools:
            def checkout(self, project, commit):
                call_count["n"] += 1
                if call_count["n"] == 1:
                    return ToolResult("checkout", False, None, "not found", "checkout_failed")
                return ToolResult("checkout", True, {"dir": "/tmp/x"}, None, None)

        rec = _RecordingTools(FlakyTools())
        # 第一次失败：不缓存
        r1 = rec.checkout("proj", "abc1234")
        assert r1.ok is False
        assert len(rec.trace) == 1
        # 第二次相同调用：因为失败没缓存，底层工具再次被调用
        r2 = rec.checkout("proj", "abc1234")
        assert call_count["n"] == 2
        assert r2.ok is True
        assert len(rec.trace) == 2
        # 第三次：成功结果已缓存，不再调用底层工具
        r3 = rec.checkout("proj", "abc1234")
        assert call_count["n"] == 2
        assert len(rec.trace) == 2

    def test_cache_is_per_instance_not_global(self):
        """cache 绑定在 _RecordingTools 实例上，不同实例不共享。"""
        from vulngym_verify_demo.tools import ToolResult

        class CountingTools:
            def __init__(self):
                self.n = 0
            def checkout(self, project, commit):
                self.n += 1
                return ToolResult("checkout", True, {}, None, None)

        t = CountingTools()
        rec1 = _RecordingTools(t)
        rec2 = _RecordingTools(t)
        rec1.checkout("p", "c")
        assert t.n == 1
        # rec2 有自己独立的 cache，不会命中 rec1 的缓存
        rec2.checkout("p", "c")
        assert t.n == 2
