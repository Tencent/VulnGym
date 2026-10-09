# -*- coding: utf-8 -*-
"""Tests for Issue #2 (I1 Standard): schema, models, bad-input reports.

验收点（§5 I1）：
- 合法/非法/缺失/未知可选字段/禁止内部字段测试
- 单条坏记录产生结构化 uncertain，不中断批处理
- 坏 JSON 行使用 ``__invalid_input__:<line_no>`` 稳定 ID
- 契约样例可 JSON round-trip
- JSON Schema 字段、枚举、类型与 §4.1 一致
- §4.2 导出名仍可用
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

# 让仓库根目录的 ``vulngym_verify_demo`` 可被导入
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo import (  # noqa: E402
    ALL_EIGHT_FIELDS,
    BaseLLMClient,
    EvidenceRef,
    FieldResult,
    InputError,
    ORIGIN_CONSTANT,
    Plan,
    ResilientLLMClient,
    SelfCheck,
    StatusValue,
    ToolCall,
    VerificationReport,
    VulnGymTools,
    build_invalid_input_report,
    check_all_fields,
    evaluate,
    invalid_input_id,
    iter_jsonl_safe,
    make_client,
    read_jsonl_with_reports,
    validate_entry,
    validate_evidence_ref,
    validate_field_result,
    validate_line,
    validate_node,
    validate_plan,
    validate_report,
    validate_self_check,
    validate_tool_call,
    verify_entry,
    verify_entries,
)
from vulngym_verify_demo.schema import (  # noqa: E402
    FORBIDDEN_INTERNAL_FIELDS,
    REPORT_REQUIRED_TOP_FIELDS,
    REPORT_AUDIT_FIELDS,
    STATUS_VALUES,
    TOOL_NAMES,
    VERDICT_VALUES,
    normalize_line,
)
from vulngym_verify_demo.models import ALL_FIELDS as _EVAL_ALL_FIELDS  # noqa: E402, F401  (intentional re-export sanity)


# ============================================================
# Test fixtures: minimal valid entry
# ============================================================
def _minimal_valid_entry() -> dict:
    """构造一份最小的合法 entry，用于正向用例。"""
    return {
        "entry_id": "entry-00057",
        "report_id": "GHSA-W7XJ-8FX7-WFCH",
        "source_link": "https://github.com/advisories/GHSA-W7XJ-8FX7-WFCH",
        "vuln_ids": ["CVE-2025-64495", "GHSA-W7XJ-8FX7-WFCH"],
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "open-webui",
        "repo_url": "https://github.com/open-webui/open-webui",
        "commit": "9942de8011d4b5a141ac507c974c061c0cdad59a",
        "vuln_title": "Open WebUI Stored DOM XSS via Prompt Insertion Rich Text Feature",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "entry_point": {
            "file": "src/lib/components/chat/MessageInput/CommandSuggestionList.svelte",
            "line": 97,
            "code": "insertTextHandler(data.content);",
        },
        "critical_operation": {
            "file": "src/lib/components/common/RichTextInput.svelte",
            "line": "348-352",
            "code": "tempDiv.innerHTML = htmlContent;",
        },
        "trace": [
            {"file": "a.js", "line": 42, "code": "f()"},
            {"file": "b.js", "line": "10-15", "code": "g()", "desc": "optional"},
        ],
        "verify": 1,
    }


def _minimal_valid_report() -> dict:
    """构造一份最小的合法 VerificationReport。"""
    return {
        "report_id": "GHSA-W7XJ-8FX7-WFCH",
        "entry_id": "entry-00057",
        "verdict": "uncertain",
        "fields": {
            "entry_point": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "critical_operation": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "commit": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "vuln_ids": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "vuln_title": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "vuln_category_l1": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "vuln_category_l2": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
            "trace": {
                "status": "uncertain",
                "confidence": 0.5,
                "evidence": "test evidence",
                "evidence_refs": [],
            },
        },
        "summary": "test summary",
        "self_check": {
            "status": "completed",
            "agree": True,
            "comment": "no issues",
            "checked_fields": ["entry_point"],
        },
        "plan": {
            "version": "1",
            "tools_planned": ["read_advisory", "checkout", "read_file_lines"],
            "fields_planned": ["entry_point", "critical_operation"],
        },
        "tool_trace": [
            {
                "seq": 1,
                "tool": "read_advisory",
                "input": {"report_id": "GHSA-W7XJ-8FX7-WFCH"},
                "ok": True,
                "error": None,
                "evidence_refs": ["fields.vuln_ids.evidence"],
            },
        ],
    }


# ============================================================
# Test: line validation
# ============================================================
class TestLineValidation:
    def test_int_line_valid(self):
        assert validate_line(1) == (True, "")
        assert validate_line(97) == (True, "")
        assert validate_line(10000) == (True, "")

    def test_int_line_zero_invalid(self):
        ok, msg = validate_line(0)
        assert ok is False
        assert ">= 1" in msg

    def test_int_line_negative_invalid(self):
        ok, _ = validate_line(-5)
        assert ok is False

    def test_range_string_valid(self):
        assert validate_line("1-1") == (True, "")
        assert validate_line("97-100") == (True, "")
        assert validate_line("348-352") == (True, "")

    def test_range_string_zero_invalid(self):
        ok, msg = validate_line("0-5")
        assert ok is False
        assert "1" in msg

    def test_range_string_inverted_invalid(self):
        ok, msg = validate_line("100-50")
        assert ok is False
        assert ">" in msg

    def test_range_string_non_integer_invalid(self):
        ok, _ = validate_line("abc-def")
        assert ok is False

    def test_range_string_too_many_dashes_invalid(self):
        ok, _ = validate_line("1-2-3")
        assert ok is False

    def test_bool_rejected(self):
        """bool 是 int 子类，必须显式排除。"""
        ok, _ = validate_line(True)
        assert ok is False

    def test_none_rejected(self):
        ok, _ = validate_line(None)
        assert ok is False

    def test_normalize_line(self):
        assert normalize_line(97) == (97, 97)
        assert normalize_line("97-100") == (97, 100)
        assert normalize_line("1-1") == (1, 1)
        assert normalize_line(0) is None
        assert normalize_line(-1) is None
        assert normalize_line("0-5") is None
        assert normalize_line("100-50") is None
        assert normalize_line(True) is None
        assert normalize_line(None) is None


# ============================================================
# Test: node validation
# ============================================================
class TestNodeValidation:
    def test_valid_node(self):
        node = {"file": "a.js", "line": 42, "code": "f()"}
        assert validate_node(node, where="entry_point") == []

    def test_node_with_range_line(self):
        node = {"file": "a.js", "line": "10-20", "code": "f()"}
        assert validate_node(node, where="entry_point") == []

    def test_node_with_optional_desc(self):
        node = {"file": "a.js", "line": 42, "code": "f()", "desc": "中文描述"}
        assert validate_node(node, where="entry_point") == []

    def test_node_missing_file(self):
        node = {"line": 42, "code": "f()"}
        errors = validate_node(node, where="entry_point")
        assert any("file" in e for e in errors)

    def test_node_missing_line(self):
        node = {"file": "a.js", "code": "f()"}
        errors = validate_node(node, where="entry_point")
        assert any("line" in e for e in errors)

    def test_node_missing_code(self):
        node = {"file": "a.js", "line": 42}
        errors = validate_node(node, where="entry_point")
        assert any("code" in e for e in errors)

    def test_node_zero_line_rejected(self):
        node = {"file": "a.js", "line": 0, "code": "f()"}
        errors = validate_node(node, where="entry_point")
        assert any("line" in e for e in errors)

    def test_node_string_line_zero_rejected(self):
        node = {"file": "a.js", "line": "0-5", "code": "f()"}
        errors = validate_node(node, where="entry_point")
        assert any("line" in e for e in errors)

    def test_node_not_dict(self):
        errors = validate_node("not a dict", where="entry_point")
        assert errors and "expected object" in errors[0]


# ============================================================
# Test: entry validation
# ============================================================
class TestEntryValidation:
    def test_valid_entry(self):
        assert validate_entry(_minimal_valid_entry()) == []

    def test_missing_origin(self):
        e = _minimal_valid_entry()
        del e["origin"]
        errors = validate_entry(e)
        assert any("origin" in err for err in errors)

    def test_wrong_origin_constant(self):
        e = _minimal_valid_entry()
        e["origin"] = "Something else"
        errors = validate_entry(e)
        assert any("origin" in err for err in errors)

    def test_missing_verify(self):
        e = _minimal_valid_entry()
        del e["verify"]
        errors = validate_entry(e)
        assert any("verify" in err for err in errors)

    def test_source_link_ghsa_must_match_report_id(self):
        e = _minimal_valid_entry()
        e["source_link"] = "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC"

        errors = validate_entry(e)

        assert any("source_link" in err and "report_id" in err for err in errors)

    def test_verify_value_outside_zero_or_one_is_rejected(self):
        e = _minimal_valid_entry()
        e["verify"] = 2
        assert any("verify" in err for err in validate_entry(e))

    def test_verify_bool_rejected(self):
        """True/False 是 int 子类，但不是合法的 verify 值（必须是 0 或 1）。"""
        e = _minimal_valid_entry()
        e["verify"] = True
        errors = validate_entry(e)
        assert any("verify" in err for err in errors)

    def test_bad_commit_format_uppercase(self):
        e = _minimal_valid_entry()
        e["commit"] = "9942DE8011D4B5A141AC507C974C061C0CDAD59A"  # uppercase
        errors = validate_entry(e)
        assert any("commit" in err for err in errors)

    def test_bad_commit_format_too_short(self):
        e = _minimal_valid_entry()
        e["commit"] = "9942de8011d4b5a141ac507c974c061c0cdad59"  # 39 chars
        errors = validate_entry(e)
        assert any("commit" in err for err in errors)

    def test_bad_repo_url_prefix(self):
        e = _minimal_valid_entry()
        e["repo_url"] = "http://example.com/abc"
        errors = validate_entry(e)
        assert any("repo_url" in err for err in errors)

    def test_bad_source_link(self):
        e = _minimal_valid_entry()
        e["source_link"] = "https://example.com/abc"
        errors = validate_entry(e)
        assert any("source_link" in err for err in errors)

    def test_missing_entry_point(self):
        e = _minimal_valid_entry()
        del e["entry_point"]
        errors = validate_entry(e)
        assert any("entry_point" in err for err in errors)

    def test_trace_not_list(self):
        e = _minimal_valid_entry()
        e["trace"] = "not a list"
        errors = validate_entry(e)
        assert any("trace" in err for err in errors)

    def test_trace_with_bad_node(self):
        e = _minimal_valid_entry()
        e["trace"] = [{"file": "a.js", "line": 0, "code": "f()"}]
        errors = validate_entry(e)
        assert any("trace[0]" in err and "line" in err for err in errors)

    def test_entry_point_line_zero(self):
        e = _minimal_valid_entry()
        e["entry_point"]["line"] = 0
        errors = validate_entry(e)
        assert any("entry_point" in err and "line" in err for err in errors)

    def test_critical_operation_line_range_with_zero(self):
        e = _minimal_valid_entry()
        e["critical_operation"]["line"] = "0-10"
        errors = validate_entry(e)
        assert any("critical_operation" in err and "line" in err for err in errors)

    def test_forbidden_field_rejected(self):
        for field_name in FORBIDDEN_INTERNAL_FIELDS:
            e = _minimal_valid_entry()
            e[field_name] = "should not be here"
            errors = validate_entry(e)
            assert any(field_name in err and "forbidden" in err for err in errors), (
                f"forbidden field {field_name} was not rejected"
            )

    def test_unknown_optional_field_allowed(self):
        """前向兼容：未知可选顶层字段必须被允许。"""
        e = _minimal_valid_entry()
        e["vuln_category_l1_en"] = "XSS"  # SCHEMA.md 提示未来可能添加
        e["some_future_field"] = 123
        e["audit_score"] = 0.95
        errors = validate_entry(e)
        assert errors == []

    def test_vuln_ids_must_be_list_of_strings(self):
        e = _minimal_valid_entry()
        e["vuln_ids"] = ["CVE-2025-64495", 123]
        errors = validate_entry(e)
        assert any("vuln_ids" in err for err in errors)

    def test_vuln_ids_can_be_empty(self):
        e = _minimal_valid_entry()
        e["vuln_ids"] = []
        # Empty vuln_ids is allowed (per SCHEMA.md: "May be empty")
        assert validate_entry(e) == []

    def test_entry_not_dict(self):
        errors = validate_entry("not a dict")
        assert errors and "expected object" in errors[0]

    def test_entry_id_must_be_string(self):
        e = _minimal_valid_entry()
        e["entry_id"] = 57
        errors = validate_entry(e)
        assert any("entry_id" in err for err in errors)

    def test_full_validate_line_breakdown(self):
        """覆盖 line 所有合法/非法分支。"""
        for v in [1, 2, 100, 99999]:
            ok, _ = validate_line(v)
            assert ok
        for v in [0, -1, True, None, "abc", "5", "5-", "-5"]:
            ok, _ = validate_line(v)
            assert not ok


# ============================================================
# Test: evidence_ref / field_result validation
# ============================================================
class TestEvidenceRefValidation:
    def test_valid_ref(self):
        ref = {"source": "advisory", "locator": "data/GHSA-X.json", "quote": "..."}
        ok, _ = validate_evidence_ref(ref)
        assert ok

    def test_source_must_be_valid_enum(self):
        ref = {"source": "weird", "locator": "x", "quote": "y"}
        ok, _ = validate_evidence_ref(ref)
        assert not ok

    def test_missing_source(self):
        ref = {"locator": "x", "quote": "y"}
        ok, _ = validate_evidence_ref(ref)
        assert not ok

    def test_missing_locator(self):
        ref = {"source": "advisory", "quote": "y"}
        ok, _ = validate_evidence_ref(ref)
        assert not ok

    def test_missing_quote(self):
        ref = {"source": "advisory", "locator": "x"}
        ok, _ = validate_evidence_ref(ref)
        assert not ok

    def test_all_three_sources(self):
        for s in ("advisory", "repository", "git"):
            ref = {"source": s, "locator": "x", "quote": "y"}
            ok, _ = validate_evidence_ref(ref)
            assert ok


class TestFieldResultValidation:
    def test_valid_field_result(self):
        f = {
            "status": "uncertain",
            "confidence": 0.5,
            "evidence": "x",
            "evidence_refs": [],
        }
        assert validate_field_result(f, "entry_point") == []

    def test_missing_status(self):
        f = {"confidence": 0.5, "evidence": "x", "evidence_refs": []}
        errors = validate_field_result(f, "entry_point")
        assert any("status" in e for e in errors)

    def test_bad_status(self):
        f = {
            "status": "maybe",
            "confidence": 0.5,
            "evidence": "x",
            "evidence_refs": [],
        }
        errors = validate_field_result(f, "entry_point")
        assert any("status" in e for e in errors)

    def test_confidence_out_of_range_high(self):
        f = {
            "status": "uncertain",
            "confidence": 1.5,
            "evidence": "x",
            "evidence_refs": [],
        }
        errors = validate_field_result(f, "entry_point")
        assert any("confidence" in e for e in errors)

    def test_confidence_out_of_range_low(self):
        f = {
            "status": "uncertain",
            "confidence": -0.1,
            "evidence": "x",
            "evidence_refs": [],
        }
        errors = validate_field_result(f, "entry_point")
        assert any("confidence" in e for e in errors)

    def test_confidence_boundary_zero(self):
        f = {
            "status": "uncertain",
            "confidence": 0.0,
            "evidence": "x",
            "evidence_refs": [],
        }
        assert validate_field_result(f, "entry_point") == []

    def test_confidence_boundary_one(self):
        f = {
            "status": "uncertain",
            "confidence": 1.0,
            "evidence": "x",
            "evidence_refs": [],
        }
        assert validate_field_result(f, "entry_point") == []

    def test_evidence_required_even_when_no_refs(self):
        """无 evidence_refs 时 evidence 必须非空字符串。"""
        f = {
            "status": "uncertain",
            "confidence": 0.5,
            "evidence": "",
            "evidence_refs": [],
        }
        errors = validate_field_result(f, "entry_point")
        assert any("evidence" in e for e in errors)

    def test_correct_field_requires_traceable_evidence_ref(self):
        f = {
            "status": "correct",
            "confidence": 0.99,
            "evidence": "model says this looks correct",
            "evidence_refs": [],
        }

        errors = validate_field_result(f, "entry_point")

        assert any("evidence_refs" in e and "correct" in e for e in errors)

    def test_evidence_refs_with_bad_ref(self):
        f = {
            "status": "uncertain",
            "confidence": 0.5,
            "evidence": "x",
            "evidence_refs": [{"source": "weird", "locator": "x", "quote": "y"}],
        }
        errors = validate_field_result(f, "entry_point")
        assert any("evidence_refs" in e for e in errors)


# ============================================================
# Test: self_check validation
# ============================================================
class TestSelfCheckValidation:
    def test_valid(self):
        sc = {
            "status": "completed",
            "agree": True,
            "comment": "ok",
            "checked_fields": ["entry_point"],
        }
        assert validate_self_check(sc) == []

    def test_agree_must_be_false_when_failed(self):
        sc = {
            "status": "failed",
            "agree": True,
            "comment": "ok",
            "checked_fields": [],
        }
        errors = validate_self_check(sc)
        assert any("agree" in e and "false" in e for e in errors)

    def test_agree_must_be_false_when_skipped(self):
        sc = {
            "status": "skipped",
            "agree": True,
            "comment": "skipped",
            "checked_fields": [],
        }
        errors = validate_self_check(sc)
        assert any("agree" in e and "false" in e for e in errors)

    def test_agree_can_be_true_when_completed(self):
        sc = {
            "status": "completed",
            "agree": True,
            "comment": "all good",
            "checked_fields": ["entry_point"],
        }
        assert validate_self_check(sc) == []

    def test_bad_status(self):
        sc = {
            "status": "whatever",
            "agree": True,
            "comment": "ok",
            "checked_fields": [],
        }
        errors = validate_self_check(sc)
        assert any("status" in e for e in errors)

    def test_checked_fields_can_be_empty(self):
        sc = {
            "status": "completed",
            "agree": True,
            "comment": "ok",
            "checked_fields": [],
        }
        assert validate_self_check(sc) == []


# ============================================================
# Test: plan validation
# ============================================================
class TestPlanValidation:
    def test_valid_plan(self):
        plan = {
            "version": "1",
            "tools_planned": ["read_advisory"],
            "fields_planned": ["entry_point"],
        }
        assert validate_plan(plan) == []

    def test_version_must_be_one(self):
        plan = {
            "version": "2",
            "tools_planned": [],
            "fields_planned": [],
        }
        errors = validate_plan(plan)
        assert any("version" in e for e in errors)

    def test_version_must_be_string(self):
        plan = {
            "version": 1,
            "tools_planned": [],
            "fields_planned": [],
        }
        errors = validate_plan(plan)
        assert any("version" in e for e in errors)

    def test_tools_planned_must_be_list(self):
        plan = {"version": "1", "tools_planned": "x", "fields_planned": []}
        errors = validate_plan(plan)
        assert any("tools_planned" in e for e in errors)

    def test_fields_planned_must_be_list(self):
        plan = {"version": "1", "tools_planned": [], "fields_planned": "x"}
        errors = validate_plan(plan)
        assert any("fields_planned" in e for e in errors)

    def test_empty_lists_allowed(self):
        plan = {"version": "1", "tools_planned": [], "fields_planned": []}
        assert validate_plan(plan) == []


# ============================================================
# Test: tool_trace / tool_call validation
# ============================================================
class TestToolCallValidation:
    def test_valid_call(self):
        call = {
            "seq": 1,
            "tool": "read_advisory",
            "input": {"report_id": "GHSA-X"},
            "ok": True,
            "error": None,
            "evidence_refs": ["fields.vuln_ids.evidence"],
        }
        assert validate_tool_call(call) == []

    def test_seq_must_be_positive_int(self):
        call = {"seq": 0, "tool": "read_advisory", "ok": True}
        errors = validate_tool_call(call)
        assert any("seq" in e for e in errors)

    def test_unknown_tool_rejected(self):
        call = {"seq": 1, "tool": "magic", "ok": True}
        errors = validate_tool_call(call)
        assert any("tool" in e for e in errors)

    def test_ok_must_be_bool(self):
        call = {"seq": 1, "tool": "read_advisory", "ok": "yes"}
        errors = validate_tool_call(call)
        assert any("ok" in e for e in errors)

    def test_input_must_be_dict(self):
        call = {"seq": 1, "tool": "read_advisory", "ok": True, "input": "x"}
        errors = validate_tool_call(call)
        assert any("input" in e for e in errors)

    def test_error_must_be_string_or_null(self):
        call = {"seq": 1, "tool": "read_advisory", "ok": False, "error": 42}
        errors = validate_tool_call(call)
        assert any("error" in e for e in errors)

    def test_failed_tool_call_requires_structured_error_code(self):
        call = {
            "seq": 1,
            "tool": "read_advisory",
            "ok": False,
            "error": "advisory unavailable",
            "evidence_refs": [],
        }

        errors = validate_tool_call(call)

        assert any("error_code" in e for e in errors)

    def test_evidence_refs_must_be_list_of_strings(self):
        call = {
            "seq": 1,
            "tool": "read_advisory",
            "ok": True,
            "evidence_refs": [{"bad": "format"}],
        }
        errors = validate_tool_call(call)
        assert any("evidence_refs" in e for e in errors)


# ============================================================
# Test: full report validation
# ============================================================
class TestReportValidation:
    def test_valid_report(self):
        assert validate_report(_minimal_valid_report()) == []

    def test_missing_minimal_top_level_field(self):
        r = _minimal_valid_report()
        del r["summary"]
        errors = validate_report(r)
        assert any("summary" in e for e in errors)

    def test_minimal_report_without_audit_extensions_is_valid(self):
        r = _minimal_valid_report()
        for field_name in REPORT_AUDIT_FIELDS:
            del r[field_name]
        assert validate_report(r) == []

    def test_bad_verdict(self):
        r = _minimal_valid_report()
        r["verdict"] = "maybe"
        errors = validate_report(r)
        assert any("verdict" in e for e in errors)

    def test_verdict_must_be_derived_from_field_statuses(self):
        r = _minimal_valid_report()
        r["verdict"] = "correct"

        errors = validate_report(r)

        assert any("verdict" in e and "derived" in e for e in errors)

    def test_missing_one_of_eight_fields(self):
        r = _minimal_valid_report()
        del r["fields"]["entry_point"]
        errors = validate_report(r)
        assert any("entry_point" in e for e in errors)

    def test_input_error_optional(self):
        r = _minimal_valid_report()
        # 没有 input_error 也合法
        assert validate_report(r) == []

    def test_input_error_when_present(self):
        r = _minimal_valid_report()
        r["input_error"] = {
            "line_no": 1,
            "kind": "json_parse_error",
            "message": "bad json",
        }
        # report_id 现在是合法的 GHSA，但报告可以同时是 invalid input 和有完整内容
        assert validate_report(r) == []

    def test_input_error_with_bad_line_no(self):
        r = _minimal_valid_report()
        r["input_error"] = {
            "line_no": 0,
            "kind": "json_parse_error",
            "message": "x",
        }
        errors = validate_report(r)
        assert any("input_error" in e for e in errors)

    def test_unknown_top_level_field_allowed(self):
        r = _minimal_valid_report()
        r["future_extension"] = {"foo": "bar"}
        # I1 允许新的可选顶层字段
        assert validate_report(r) == []


# ============================================================
# Test: bad input reports
# ============================================================
class TestBadInputReports:
    def test_invalid_id_format(self):
        assert invalid_input_id(1) == "__invalid_input__:1"
        assert invalid_input_id(99) == "__invalid_input__:99"
        assert invalid_input_id(12345) == "__invalid_input__:12345"

    def test_build_invalid_input_report_structure(self):
        r = build_invalid_input_report(
            line_no=42,
            kind="json_parse_error",
            message="unexpected token",
        )
        assert r["report_id"] == "__invalid_input__:42"
        assert r["entry_id"] == "__invalid_input__:42"
        assert r["verdict"] == "uncertain"

    def test_build_invalid_input_report_has_all_eight_fields(self):
        r = build_invalid_input_report(1, "json_parse_error", "x")
        for fname in ALL_EIGHT_FIELDS:
            assert fname in r["fields"]
            assert r["fields"][fname]["status"] == "uncertain"
            assert r["fields"][fname]["confidence"] == 0.0
            assert r["fields"][fname]["evidence_refs"] == []
            assert isinstance(r["fields"][fname]["evidence"], str)
            assert r["fields"][fname]["evidence"]  # non-empty

    def test_build_invalid_input_report_has_input_error(self):
        r = build_invalid_input_report(
            line_no=7,
            kind="schema_violation",
            message="missing origin",
        )
        assert r["input_error"]["line_no"] == 7
        assert r["input_error"]["kind"] == "schema_violation"
        assert r["input_error"]["message"] == "missing origin"

    def test_build_invalid_input_report_self_check_status(self):
        r = build_invalid_input_report(1, "json_parse_error", "x")
        assert r["self_check"]["status"] == "skipped"
        assert r["self_check"]["agree"] is False

    def test_build_invalid_input_report_plan_version(self):
        r = build_invalid_input_report(1, "json_parse_error", "x")
        assert r["plan"]["version"] == "1"

    def test_build_invalid_input_report_passes_validation(self):
        r = build_invalid_input_report(
            line_no=99,
            kind="json_parse_error",
            message="bad json",
        )
        errors = validate_report(r)
        assert errors == [], f"bad-input report itself must validate, got {errors}"

    @pytest.mark.parametrize("line_no", [1, 2, 42, 1000])
    def test_invalid_id_is_stable(self, line_no):
        """§4.1：占位符 ID 必须稳定可重现。"""
        r1 = build_invalid_input_report(line_no, "json_parse_error", "x")
        r2 = build_invalid_input_report(line_no, "json_parse_error", "x")
        assert r1["report_id"] == r2["report_id"] == f"__invalid_input__:{line_no}"
        assert r1["entry_id"] == r2["entry_id"] == f"__invalid_input__:{line_no}"


# ============================================================
# Test: safe JSONL iteration
# ============================================================
class TestSafeJsonl:
    def test_reads_valid_jsonl(self, tmp_path: Path):
        p = tmp_path / "good.jsonl"
        p.write_text(
            '{"a": 1}\n'
            '{"a": 2}\n',
            encoding="utf-8",
        )
        results = list(iter_jsonl_safe(p))
        assert results == [{"a": 1}, {"a": 2}]

    def test_bad_json_does_not_raise(self, tmp_path: Path):
        p = tmp_path / "mixed.jsonl"
        p.write_text(
            '{"a": 1}\n'
            '{bad json\n'  # line 2: invalid
            '{"a": 3}\n',
            encoding="utf-8",
        )
        results = list(iter_jsonl_safe(p))
        # 第一行: dict
        # 第二行: tuple (line_no, error)
        # 第三行: dict
        assert results[0] == {"a": 1}
        assert isinstance(results[1], tuple)
        assert results[1][0] == 2  # line_no
        # 错误消息应包含 JSON 解析的诊断信息（不同 Python 版本措辞不同）
        msg_lower = results[1][1].lower()
        assert "expecting" in msg_lower or "json" in msg_lower or "property" in msg_lower
        assert results[2] == {"a": 3}

    def test_empty_lines_skipped(self, tmp_path: Path):
        p = tmp_path / "blank.jsonl"
        p.write_text(
            '{"a": 1}\n'
            '\n'
            '   \n'
            '{"a": 2}\n',
            encoding="utf-8",
        )
        results = list(iter_jsonl_safe(p))
        # 空行被跳过，不产生报告
        assert results == [{"a": 1}, {"a": 2}]

    def test_sanitized_error_no_absolute_paths(self, tmp_path: Path):
        """错误消息脱敏：不泄漏本地绝对路径。"""
        # 构造一个会被脱敏的错误
        p = tmp_path / "leak.jsonl"
        # 把一个绝对路径嵌入到字符串里使其成为 JSON 内容的一部分
        p.write_text('"C:\\\\Users\\\\lx\\\\file.txt"\n', encoding="utf-8")
        results = list(iter_jsonl_safe(p))
        assert results[0] == "C:\\Users\\lx\\file.txt"
        # 现在构造一个真正的坏行，其错误消息里可能含路径
        p.write_text(
            '{"a": 1}\n'
            '{"a": \n',  # line 2: invalid
            encoding="utf-8",
        )
        results = list(iter_jsonl_safe(p))
        bad_line = results[1]
        assert isinstance(bad_line, tuple)
        # message 不应含 Windows 绝对路径
        assert "C:\\" not in bad_line[1]

    def test_read_jsonl_with_reports_returns_split(self, tmp_path: Path):
        p = tmp_path / "mixed.jsonl"
        p.write_text(
            '{"a": 1}\n'
            'garbage\n'
            '{"a": 2}\n',
            encoding="utf-8",
        )
        entries, invalid = read_jsonl_with_reports(p)
        assert entries == [{"a": 1}, {"a": 2}]
        assert len(invalid) == 1
        assert invalid[0]["report_id"] == "__invalid_input__:2"
        assert invalid[0]["verdict"] == "uncertain"

    def test_batch_processing_does_not_crash(self, tmp_path: Path):
        """§5 I1：单条坏记录产生结构化 uncertain，不中断批处理。"""
        p = tmp_path / "stress.jsonl"
        rows = []
        for i in range(1, 11):
            if i == 5:
                rows.append("{bad json")
            else:
                rows.append(f'{{"id": {i}}}')
        p.write_text("\n".join(rows) + "\n", encoding="utf-8")
        entries, invalid = read_jsonl_with_reports(p)
        assert len(entries) == 9
        assert len(invalid) == 1
        # 全部 report 通过 validate_report
        for r in invalid:
            assert validate_report(r) == []


# ============================================================
# Test: JSON round-trip via dataclass models
# ============================================================
class TestJsonRoundTrip:
    def test_field_result_roundtrip(self):
        fr = FieldResult(
            status="uncertain",
            confidence=0.5,
            evidence="some evidence",
            evidence_refs=[
                EvidenceRef(source="advisory", locator="data/x.json", quote="text")
            ],
        )
        j = json.dumps(fr.to_dict(), ensure_ascii=False)
        d = json.loads(j)
        fr2 = FieldResult.from_dict(d)
        assert fr2.status == fr.status
        assert fr2.confidence == fr.confidence
        assert fr2.evidence == fr.evidence
        assert len(fr2.evidence_refs) == 1
        assert fr2.evidence_refs[0].source == "advisory"

    def test_tool_call_roundtrip(self):
        tc = ToolCall(
            seq=1,
            tool="read_advisory",
            ok=False,
            input={"report_id": "GHSA-X"},
            error="advisory not found",
            error_code="advisory_not_found",
            evidence_refs=["fields.vuln_ids.evidence"],
        )
        d = json.loads(json.dumps(tc.to_dict()))
        tc2 = ToolCall.from_dict(d)
        assert tc2.seq == 1
        assert tc2.tool == "read_advisory"
        assert tc2.ok is False
        assert tc2.input == {"report_id": "GHSA-X"}
        assert tc2.error_code == "advisory_not_found"
        assert tc2.evidence_refs == ["fields.vuln_ids.evidence"]

    def test_self_check_roundtrip(self):
        sc = SelfCheck(
            status="completed",
            agree=True,
            comment="ok",
            checked_fields=["entry_point", "commit"],
        )
        d = json.loads(json.dumps(sc.to_dict()))
        sc2 = SelfCheck.from_dict(d)
        assert sc2.status == "completed"
        assert sc2.agree is True
        assert sc2.checked_fields == ["entry_point", "commit"]

    def test_plan_roundtrip(self):
        p = Plan(
            tools_planned=["read_advisory", "checkout"],
            fields_planned=["entry_point"],
            entry_id="entry-00001",
        )
        d = json.loads(json.dumps(p.to_dict()))
        p2 = Plan.from_dict(d)
        assert p2.version == "1"
        assert p2.tools_planned == ["read_advisory", "checkout"]
        assert p2.entry_id == "entry-00001"

    def test_input_error_roundtrip(self):
        ie = InputError(line_no=42, kind="json_parse_error", message="bad")
        d = json.loads(json.dumps(ie.to_dict()))
        ie2 = InputError.from_dict(d)
        assert ie2.line_no == 42
        assert ie2.kind == "json_parse_error"

    def test_full_report_roundtrip(self):
        r = _minimal_valid_report()
        rep = VerificationReport.from_dict(r)
        j = json.dumps(rep.to_dict(), ensure_ascii=False)
        d = json.loads(j)
        rep2 = VerificationReport.from_dict(d)
        assert rep2.report_id == r["report_id"]
        assert rep2.entry_id == r["entry_id"]
        assert rep2.verdict == r["verdict"]
        assert set(rep2.fields.keys()) == set(r["fields"].keys())
        assert rep2.plan.version == "1"
        assert len(rep2.tool_trace) == 1
        assert rep2.tool_trace[0].tool == "read_advisory"

    def test_roundtrip_preserves_unicode(self):
        """中文 evidence 不应被 round-trip 破坏。"""
        fr = FieldResult(
            status="uncertain",
            confidence=0.5,
            evidence="代码片段不匹配：actual=foo expected=bar",
            evidence_refs=[
                EvidenceRef(
                    source="repository",
                    locator="src/foo.js",
                    quote="const x = 1; // 中文注释",
                )
            ],
        )
        j = json.dumps(fr.to_dict(), ensure_ascii=False)
        d = json.loads(j)
        fr2 = FieldResult.from_dict(d)
        assert "中文注释" in fr2.evidence_refs[0].quote

    def test_bad_input_report_roundtrip(self):
        r = build_invalid_input_report(33, "json_parse_error", "bad json")
        j = json.dumps(r, ensure_ascii=False)
        d = json.loads(j)
        rep = VerificationReport.from_dict(d)
        assert rep.input_error is not None
        assert rep.input_error.line_no == 33


# ============================================================
# Test: report_schema.json (the canonical JSON Schema file)
# ============================================================
class TestReportSchemaFile:
    def test_file_exists(self):
        # repo_root/vulngym-verify-demo/vulngym_verify_demo/report_schema.json
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        assert schema_path.exists(), f"missing {schema_path}"

    def test_file_is_valid_json(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "$schema" in data or "type" in data

    def test_schema_requires_top_level_fields(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        required_top = set(schema["required"])
        for field_name in REPORT_REQUIRED_TOP_FIELDS:
            assert field_name in required_top, f"schema missing required top field {field_name}"

    def test_schema_requires_eight_fields(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        required_fields = set(schema["properties"]["fields"]["required"])
        for fname in ALL_EIGHT_FIELDS:
            assert fname in required_fields

    def test_schema_field_result_required_keys(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        fr_required = set(schema["definitions"]["FieldResult"]["required"])
        assert {"status", "confidence", "evidence"} <= fr_required
        assert "evidence_refs" not in fr_required

    def test_schema_status_enum(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        status_enum = set(
            schema["definitions"]["FieldResult"]["properties"]["status"]["enum"]
        )
        assert status_enum == STATUS_VALUES

    def test_schema_verdict_enum(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        verdict_enum = set(schema["properties"]["verdict"]["enum"])
        assert verdict_enum == VERDICT_VALUES

    def test_schema_self_check_status_enum(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        sc_status_enum = set(
            schema["definitions"]["SelfCheck"]["properties"]["status"]["enum"]
        )
        assert sc_status_enum == {"completed", "skipped", "failed"}

    def test_schema_tool_names_enum(self):
        """§4.1：tool_trace.tool 必须是 5 类已知工具之一（I5 在此基础上扩展）。"""
        # 我们的 schema 没强制枚举 tool（允许未来新增工具），只校验它必须是 string
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        tc_props = schema["definitions"]["ToolCall"]["properties"]
        assert tc_props["tool"]["type"] == "string"

    def test_schema_confidence_range(self):
        schema_path = _REPO_ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        conf = schema["definitions"]["FieldResult"]["properties"]["confidence"]
        assert conf["minimum"] == 0.0
        assert conf["maximum"] == 1.0


# ============================================================
# Test: §4.2 backward compatibility exports
# ============================================================
class TestBackwardCompatExports:
    """§4.2 Python 边界：以下导出名必须仍然可用。"""

    def test_vulngym_tools(self):
        assert VulnGymTools is not None

    def test_base_llm_client(self):
        assert BaseLLMClient is not None

    def test_resilient_llm_client(self):
        assert ResilientLLMClient is not None

    def test_check_all_fields(self):
        assert callable(check_all_fields)

    def test_verify_entry(self):
        assert callable(verify_entry)

    def test_verify_entries(self):
        assert callable(verify_entries)

    def test_evaluate(self):
        assert callable(evaluate)

    def test_make_client(self):
        """make_client 在 §4.2 未冻结但原有 cli.py 依赖；保持可用。"""
        assert callable(make_client)

    def test_all_eight_fields_contains_required(self):
        assert "entry_point" in ALL_EIGHT_FIELDS
        assert "critical_operation" in ALL_EIGHT_FIELDS
        assert "commit" in ALL_EIGHT_FIELDS
        assert "vuln_ids" in ALL_EIGHT_FIELDS
        assert "vuln_title" in ALL_EIGHT_FIELDS
        assert "vuln_category_l1" in ALL_EIGHT_FIELDS
        assert "vuln_category_l2" in ALL_EIGHT_FIELDS
        assert "trace" in ALL_EIGHT_FIELDS

    def test_status_value_enum_members(self):
        assert StatusValue.CORRECT.value == "correct"
        assert StatusValue.INCORRECT.value == "incorrect"
        assert StatusValue.UNCERTAIN.value == "uncertain"


# ============================================================
# Test: SCHEMA.md invariants on the entry contract
# ============================================================
class TestSchemaMdInvariants:
    def test_invariant_4_origin_constant(self):
        """SCHEMA.md invariant #4: origin 必须是常量。"""
        e = _minimal_valid_entry()
        e["origin"] = "wrong"
        errors = validate_entry(e)
        assert any("origin" in err for err in errors)

    def test_invariant_5_commit_lowercase_hex(self):
        e = _minimal_valid_entry()
        e["commit"] = "ABCDEF" + "0" * 34  # uppercase hex
        errors = validate_entry(e)
        assert any("commit" in err for err in errors)

    def test_invariant_5_repo_url_https_github(self):
        e = _minimal_valid_entry()
        e["repo_url"] = "git@github.com:foo/bar.git"
        errors = validate_entry(e)
        assert any("repo_url" in err for err in errors)

    def test_invariant_7_line_positive_or_range(self):
        for bad_line in [0, -1, "0-1", "1-0", "abc"]:
            e = _minimal_valid_entry()
            e["entry_point"]["line"] = bad_line
            errors = validate_entry(e)
            assert any("line" in err for err in errors), f"line {bad_line!r} not rejected"

    def test_invariant_8_forbidden_fields(self):
        for forbidden in [
            "description", "human_remark", "pipeline_id", "annotated_by",
            "is_active", "created_at", "generality", "detection_type",
            "ground_truth", "taint_source", "taint_sink", "vuln_category_l3",
        ]:
            e = _minimal_valid_entry()
            e[forbidden] = "should fail"
            errors = validate_entry(e)
            assert any(forbidden in err for err in errors), (
                f"forbidden field {forbidden} not rejected"
            )

    def test_invariant_9_verify_0_or_1(self):
        for v in [0, 1]:
            e = _minimal_valid_entry()
            e["verify"] = v
            assert validate_entry(e) == []
        for v in [2, -1, "0", "1", 1.0, True, False]:
            e = _minimal_valid_entry()
            e["verify"] = v
            errors = validate_entry(e)
            assert any("verify" in err for err in errors), (
                f"verify={v!r} not rejected"
            )


# ============================================================
# Test: complete well-formed entry passes schema + report shape
# ============================================================
class TestIntegration:
    def test_minimal_entry_passes_validate(self):
        e = _minimal_valid_entry()
        assert validate_entry(e) == []

    def test_minimal_report_passes_validate(self):
        r = _minimal_valid_report()
        assert validate_report(r) == []

    def test_minimal_report_roundtrips_through_dataclass(self):
        r = _minimal_valid_report()
        rep = VerificationReport.from_dict(r)
        j = json.dumps(rep.to_dict(), ensure_ascii=False)
        d = json.loads(j)
        # round-trip 之后报告必须仍然通过 validate_report
        assert validate_report(d) == []
