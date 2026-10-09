# -*- coding: utf-8 -*-
"""I7 — 评测器测试套件。

测试 eval.py 的核心功能：
1. 显式三态 gold 格式支持
2. 兼容旧格式
3. 缺失报告处理
4. 字段 breakdown 计算
5. 异常样本处理
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo.eval import evaluate, format_metrics, load_gold  # noqa: E402


def test_explicit_gold_format():
    """显式三态 gold 格式"""
    reports = [
        {
            "entry_id": "e1",
            "verdict": "correct",
            "fields": {
                "entry_point": {"status": "correct", "comment": "ok"},
                "critical_operation": {"status": "correct", "comment": "ok"},
                "commit": {"status": "correct", "comment": "ok"},
                "vuln_ids": {"status": "correct", "comment": "ok"},
                "vuln_title": {"status": "correct", "comment": "ok"},
                "vuln_category_l1": {"status": "correct", "comment": "ok"},
                "vuln_category_l2": {"status": "correct", "comment": "ok"},
                "trace": {"status": "correct", "comment": "ok"},
            },
        }
    ]
    
    gold = {
        "e1": {
            "verdict": "correct",
            "fields": {
                "entry_point": "correct",
                "critical_operation": "correct",
                "commit": "correct",
                "vuln_ids": "correct",
                "vuln_title": "correct",
                "vuln_category_l1": "correct",
                "vuln_category_l2": "correct",
                "trace": "correct",
            },
        }
    }
    
    m = evaluate(reports, gold)
    
    assert m["field_accuracy"] == 1.0
    assert m["field_hit"] == 8
    assert m["field_total"] == 8
    assert m["verdict_accuracy"] == 1.0
    assert m["error_recall"] == 1.0  # 无错误样本，默认 1.0


def test_explicit_gold_with_incorrect():
    """显式三态 gold - 含错误字段"""
    reports = [
        {
            "entry_id": "e2",
            "verdict": "incorrect",
            "fields": {
                "entry_point": {"status": "incorrect", "comment": "wrong"},
                "critical_operation": {"status": "correct", "comment": "ok"},
                "commit": {"status": "correct", "comment": "ok"},
                "vuln_ids": {"status": "correct", "comment": "ok"},
                "vuln_title": {"status": "correct", "comment": "ok"},
                "vuln_category_l1": {"status": "correct", "comment": "ok"},
                "vuln_category_l2": {"status": "incorrect", "comment": "wrong"},
                "trace": {"status": "uncertain", "comment": "unclear"},
            },
        }
    ]
    
    gold = {
        "e2": {
            "verdict": "incorrect",
            "fields": {
                "entry_point": "incorrect",
                "critical_operation": "correct",
                "commit": "correct",
                "vuln_ids": "correct",
                "vuln_title": "correct",
                "vuln_category_l1": "correct",
                "vuln_category_l2": "incorrect",
                "trace": "uncertain",
            },
            "incorrect_fields": ["entry_point", "vuln_category_l2"],
        }
    }
    
    m = evaluate(reports, gold)
    
    assert m["field_accuracy"] == 1.0
    assert m["field_hit"] == 8
    assert m["field_total"] == 8
    assert m["error_recall"] == 1.0  # 找到了错误
    assert m["error_hit"] == 1
    assert m["error_total"] == 1


def test_compatible_gold_format():
    """兼容旧格式 gold"""
    reports = [
        {
            "entry_id": "e3",
            "verdict": "incorrect",
            "fields": {
                "entry_point": {"status": "uncertain", "comment": "unclear"},
                "critical_operation": {"status": "incorrect", "comment": "wrong"},
                "commit": {"status": "uncertain", "comment": "unclear"},
                "vuln_ids": {"status": "uncertain", "comment": "unclear"},
                "vuln_title": {"status": "uncertain", "comment": "unclear"},
                "vuln_category_l1": {"status": "uncertain", "comment": "unclear"},
                "vuln_category_l2": {"status": "uncertain", "comment": "unclear"},
                "trace": {"status": "uncertain", "comment": "unclear"},
            },
        }
    ]
    
    gold = {
        "e3": {
            "verdict": "incorrect",
            "incorrect_fields": ["critical_operation"],
        }
    }
    
    m = evaluate(reports, gold)
    
    # 兼容格式：incorrect 字段 1 个 + 其他 7 个应该是 uncertain
    assert m["field_hit"] == 8  # 全对
    assert m["field_total"] == 8
    assert m["field_accuracy"] == 1.0
    assert m["error_recall"] == 1.0


def test_missing_report():
    """缺失报告 -> 全错"""
    reports = []  # 没有报告
    
    gold = {
        "e4": {
            "verdict": "correct",
            "fields": {
                "entry_point": "correct",
                "critical_operation": "correct",
                "commit": "correct",
                "vuln_ids": "correct",
                "vuln_title": "correct",
                "vuln_category_l1": "correct",
                "vuln_category_l2": "correct",
                "trace": "correct",
            },
        }
    }
    
    m = evaluate(reports, gold)
    
    assert m["field_hit"] == 0
    assert m["field_total"] == 8
    assert m["field_accuracy"] == 0.0
    assert m["verdict_correct"] == 0
    assert m["n_entries"] == 1


def test_invalid_input_entry():
    """__invalid_input__ 样本特殊处理"""
    reports = [
        {
            "entry_id": "__invalid_input__bad",
            "verdict": "uncertain",
            "fields": {},
        }
    ]
    
    gold = {
        "__invalid_input__bad": {
            "verdict": "uncertain",
            "fields": {
                "entry_point": "uncertain",
                "critical_operation": "uncertain",
                "commit": "uncertain",
                "vuln_ids": "uncertain",
                "vuln_title": "uncertain",
                "vuln_category_l1": "uncertain",
                "vuln_category_l2": "uncertain",
                "trace": "uncertain",
            },
        }
    }
    
    m = evaluate(reports, gold)
    
    # 损坏输入 fixture 不混入冻结的字段准确率或找错召回率。
    assert m["n_entries"] == 0
    assert m["verdict_correct"] == 0
    assert m["field_total"] == 0  # 不计入字段
    assert m["excluded_invalid_entries"] == 1


def test_field_breakdown():
    """字段 breakdown 计算正确"""
    reports = [
        {
            "entry_id": "e5",
            "verdict": "incorrect",
            "fields": {
                "entry_point": {"status": "correct", "comment": "ok"},
                "critical_operation": {"status": "incorrect", "comment": "wrong"},
                "commit": {"status": "correct", "comment": "ok"},
                "vuln_ids": {"status": "correct", "comment": "ok"},
                "vuln_title": {"status": "correct", "comment": "ok"},
                "vuln_category_l1": {"status": "correct", "comment": "ok"},
                "vuln_category_l2": {"status": "correct", "comment": "ok"},
                "trace": {"status": "correct", "comment": "ok"},
            },
        },
        {
            "entry_id": "e6",
            "verdict": "correct",
            "fields": {
                "entry_point": {"status": "correct", "comment": "ok"},
                "critical_operation": {"status": "correct", "comment": "ok"},
                "commit": {"status": "incorrect", "comment": "wrong"},
                "vuln_ids": {"status": "correct", "comment": "ok"},
                "vuln_title": {"status": "correct", "comment": "ok"},
                "vuln_category_l1": {"status": "correct", "comment": "ok"},
                "vuln_category_l2": {"status": "correct", "comment": "ok"},
                "trace": {"status": "correct", "comment": "ok"},
            },
        },
    ]
    
    gold = {
        "e5": {
            "verdict": "incorrect",
            "incorrect_fields": ["critical_operation"],
        },
        "e6": {
            "verdict": "correct",
            "incorrect_fields": [],
        },
    }
    
    m = evaluate(reports, gold)
    
    # 检查 breakdown
    assert "field_breakdown" in m
    assert "entry_point" in m["field_breakdown"]
    assert "critical_operation" in m["field_breakdown"]
    
    # entry_point: e5 应该是 uncertain (因为 verdict=incorrect)，但 report 是 correct -> 错
    #             e6 应该是 correct (因为 verdict=correct)，report 是 correct -> 对
    # 所以应该是 1/2
    assert m["field_breakdown"]["entry_point"]["hit"] == 1
    assert m["field_breakdown"]["entry_point"]["total"] == 2
    assert m["field_breakdown"]["entry_point"]["accuracy"] == 0.5
    
    # critical_operation: e5 应该是 incorrect，report 是 incorrect -> 对
    #                     e6 应该是 correct，report 是 correct -> 对
    # 所以应该是 2/2
    assert m["field_breakdown"]["critical_operation"]["hit"] == 2
    assert m["field_breakdown"]["critical_operation"]["total"] == 2
    assert m["field_breakdown"]["critical_operation"]["accuracy"] == 1.0
    
    # commit: e5 应该是 uncertain，report 是 correct -> 错
    #         e6 应该是 correct，report 是 incorrect -> 错
    # 所以应该是 0/2
    assert m["field_breakdown"]["commit"]["hit"] == 0
    assert m["field_breakdown"]["commit"]["total"] == 2


def test_format_metrics():
    """format_metrics 输出正确"""
    m = {
        "n_entries": 2,
        "field_accuracy": 0.875,
        "field_hit": 14,
        "field_total": 16,
        "error_recall": 1.0,
        "error_hit": 1,
        "error_total": 1,
        "verdict_accuracy": 1.0,
        "verdict_correct": 2,
        "field_breakdown": {
            "entry_point": {"accuracy": 1.0, "hit": 2, "total": 2},
            "critical_operation": {"accuracy": 0.5, "hit": 1, "total": 2},
            "commit": {"accuracy": 1.0, "hit": 2, "total": 2},
            "vuln_ids": {"accuracy": 1.0, "hit": 2, "total": 2},
            "vuln_title": {"accuracy": 1.0, "hit": 2, "total": 2},
            "vuln_category_l1": {"accuracy": 1.0, "hit": 2, "total": 2},
            "vuln_category_l2": {"accuracy": 1.0, "hit": 2, "total": 2},
            "trace": {"accuracy": 1.0, "hit": 2, "total": 2},
        },
        "per_entry": [
            {
                "entry_id": "e1",
                "verdict_pred": "correct",
                "verdict_gold": "correct",
                "incorrect_pred": [],
                "incorrect_gold": [],
            },
            {
                "entry_id": "e2",
                "verdict_pred": "incorrect",
                "verdict_gold": "incorrect",
                "incorrect_pred": ["critical_operation"],
                "incorrect_gold": ["critical_operation"],
            },
        ],
    }
    
    output = format_metrics(m)
    
    assert "VulnGym 字段级验证" in output
    assert "0.875" in output
    assert "14/16" in output
    assert "1.000" in output
    assert "1/1" in output
    assert "entry_point" in output
    assert "critical_operation" in output


def test_error_recall_calculation():
    """错误召回率计算正确"""
    reports = [
        {
            "entry_id": "e7",
            "verdict": "incorrect",
            "fields": {
                "entry_point": {"status": "incorrect", "comment": "wrong"},
                "critical_operation": {"status": "correct", "comment": "ok"},
                "commit": {"status": "correct", "comment": "ok"},
                "vuln_ids": {"status": "correct", "comment": "ok"},
                "vuln_title": {"status": "correct", "comment": "ok"},
                "vuln_category_l1": {"status": "correct", "comment": "ok"},
                "vuln_category_l2": {"status": "correct", "comment": "ok"},
                "trace": {"status": "correct", "comment": "ok"},
            },
        },
        {
            "entry_id": "e8",
            "verdict": "correct",  # 漏判了，实际应该是 incorrect
            "fields": {
                "entry_point": {"status": "correct", "comment": "ok"},
                "critical_operation": {"status": "correct", "comment": "ok"},
                "commit": {"status": "correct", "comment": "ok"},
                "vuln_ids": {"status": "correct", "comment": "ok"},
                "vuln_title": {"status": "correct", "comment": "ok"},
                "vuln_category_l1": {"status": "correct", "comment": "ok"},
                "vuln_category_l2": {"status": "correct", "comment": "ok"},
                "trace": {"status": "correct", "comment": "ok"},
            },
        },
    ]
    
    gold = {
        "e7": {
            "verdict": "incorrect",
            "incorrect_fields": ["entry_point"],
        },
        "e8": {
            "verdict": "incorrect",
            "incorrect_fields": ["commit"],
        },
    }
    
    m = evaluate(reports, gold)
    
    # 2 个错误样本，找到 1 个
    assert m["error_total"] == 2
    assert m["error_hit"] == 1
    assert m["error_recall"] == 0.5


def test_error_recall_requires_incorrect_verdict_not_matching_field_only():
    """冻结口径：错误 entry 只有 verdict=incorrect 才算找出。"""
    reports = [{
        "entry_id": "e9", "verdict": "uncertain",
        "fields": {name: {"status": "incorrect"} for name in (
            "entry_point", "critical_operation", "commit", "vuln_ids",
            "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace",
        )},
    }]
    gold = {"e9": {
        "verdict": "incorrect",
        "fields": {
            "entry_point": "incorrect", "critical_operation": "correct", "commit": "correct",
            "vuln_ids": "correct", "vuln_title": "correct", "vuln_category_l1": "correct",
            "vuln_category_l2": "correct", "trace": "correct",
        },
    }}
    metrics = evaluate(reports, gold)
    assert metrics["error_total"] == 1
    assert metrics["error_hit"] == 0
    assert metrics["error_recall"] == 0.0


def test_error_recall_counts_incorrect_verdict_even_when_wrong_field_is_different():
    """召回是 entry 级，字段归因仍由 field_accuracy 单独度量。"""
    reports = [{
        "entry_id": "e10", "verdict": "incorrect",
        "fields": {name: {"status": "correct"} for name in (
            "entry_point", "critical_operation", "commit", "vuln_ids",
            "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace",
        )},
    }]
    reports[0]["fields"]["trace"] = {"status": "incorrect"}
    gold = {"e10": {
        "verdict": "incorrect",
        "fields": {
            "entry_point": "incorrect", "critical_operation": "correct", "commit": "correct",
            "vuln_ids": "correct", "vuln_title": "correct", "vuln_category_l1": "correct",
            "vuln_category_l2": "correct", "trace": "correct",
        },
    }}
    metrics = evaluate(reports, gold)
    assert metrics["error_recall"] == 1.0
    assert metrics["field_accuracy"] < 1.0


def test_missing_incorrect_report_counts_as_field_errors_and_recall_miss():
    gold = {"e11": {
        "verdict": "incorrect",
        "fields": {
            "entry_point": "incorrect", "critical_operation": "correct", "commit": "correct",
            "vuln_ids": "correct", "vuln_title": "correct", "vuln_category_l1": "correct",
            "vuln_category_l2": "correct", "trace": "correct",
        },
    }}
    metrics = evaluate([], gold)
    assert metrics["field_hit"] == 0
    assert metrics["field_total"] == 8
    assert metrics["error_recall"] == 0.0


def test_invalid_status_and_missing_field_are_scored_as_field_errors():
    """报告不是有效三态时不能被宽松地当作 uncertain 或 correct。"""
    gold = {"e12": {
        "verdict": "correct",
        "fields": {
            "entry_point": "correct", "critical_operation": "correct", "commit": "correct",
            "vuln_ids": "correct", "vuln_title": "correct", "vuln_category_l1": "correct",
            "vuln_category_l2": "correct", "trace": "correct",
        },
    }}
    report = {
        "entry_id": "e12", "verdict": "correct",
        "fields": {name: {"status": "correct"} for name in gold["e12"]["fields"]},
    }
    report["fields"]["commit"] = {"status": "maybe"}
    report["fields"].pop("trace")
    metrics = evaluate([report], gold)
    assert metrics["field_hit"] == 6
    assert metrics["field_total"] == 8


def test_duplicate_and_unexpected_reports_are_auditable_and_do_not_score():
    gold = {"e13": {
        "verdict": "correct",
        "fields": {
            "entry_point": "correct", "critical_operation": "correct", "commit": "correct",
            "vuln_ids": "correct", "vuln_title": "correct", "vuln_category_l1": "correct",
            "vuln_category_l2": "correct", "trace": "correct",
        },
    }}
    valid = {
        "entry_id": "e13", "verdict": "correct",
        "fields": {name: {"status": "correct"} for name in gold["e13"]["fields"]},
    }
    metrics = evaluate([valid, valid, {"entry_id": "not-in-gold", "verdict": "correct"}], gold)
    # Repeated entry IDs are removed from the prediction index, so e13 is a
    # missing report rather than allowing last-write-wins behavior.
    assert metrics["duplicate_report_count"] == 1
    assert metrics["unexpected_report_count"] == 1
    assert metrics["field_hit"] == 0
    assert metrics["verdict_correct"] == 0


def test_load_gold_rejects_incomplete_explicit_statuses_and_duplicates(tmp_path: Path):
    incomplete = tmp_path / "incomplete.jsonl"
    incomplete.write_text(json.dumps({"entry_id": "e", "verdict": "correct", "fields": {}}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_gold(incomplete)

    duplicate = tmp_path / "duplicate.jsonl"
    row = {"entry_id": "e", "verdict": "correct", "incorrect_fields": []}
    duplicate.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_gold(duplicate)


def test_load_gold_normalises_compatibility_format(tmp_path: Path):
    path = tmp_path / "compat.jsonl"
    path.write_text(
        json.dumps({
            "entry_id": "compat", "verdict": "incorrect",
            "incorrect_fields": ["commit"],
        }) + "\n",
        encoding="utf-8",
    )
    gold = load_gold(path)
    assert gold["compat"]["format"] == "compat"
    assert gold["compat"]["fields"]["commit"] == "incorrect"
    assert gold["compat"]["fields"]["entry_point"] == "uncertain"


def test_public_smoke_fixture_has_no_gold_file():
    """公开输入可生成报告，但金标必须保留在非公开评测边界之外。"""
    public_dir = ROOT / "vulngym-verify-demo" / "public_fixtures"
    assert (public_dir / "entries.jsonl").is_file()
    assert not (public_dir / "gold.jsonl").exists()
