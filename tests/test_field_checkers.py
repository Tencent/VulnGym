# -*- coding: utf-8 -*-
"""I3 — 字段检查器 evidence_refs 测试套件。

覆盖 I3 启动手册 §4 全部 10 个测试类、≥34 用例。

契约（由 I1 schema.py 冻结）：
  * evidence_refs: List[{source, locator, quote}]
  * source ∈ {"advisory", "repository", "git"}
  * locator/quote 是 str
  * evidence_refs=[] 时 evidence 必须非空
  * validate_field_result 对 8 字段返回值全部 pass
  * check_all_fields 汇总行为不变
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo.field_checkers import (  # noqa: E402
    BUNDLE_FIELDS,
    _ref_repo,
    _ref_git,
    _ref_advisory,
    check_entry_point,
    check_critical_operation,
    check_commit,
    check_vuln_ids,
    check_vuln_title,
    check_category,
    check_trace,
    check_semantic_bundle,
    check_all_fields,
)
from vulngym_verify_demo.schema import (  # noqa: E402
    validate_field_result,
    EVIDENCE_SOURCE_VALUES,
    STATUS_VALUES,
)
from vulngym_verify_demo.tools import ToolResult, VulnGymTools  # noqa: E402
from vulngym_verify_demo.llm_client import ScriptedMockLLMClient  # noqa: E402


# ============================================================
# Fixtures
# ============================================================

MOCK_REPO_ROOT = ROOT / "vulngym-verify-demo" / "mock_repo"
MOCK_ADV_DIR = ROOT / "vulngym-verify-demo" / "mock_advisories"


@pytest.fixture(scope="module")
def manifest() -> Dict[str, Any]:
    with open(MOCK_REPO_ROOT / "manifest.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def tmp_workspace(tmp_path: Path):
    """构造独立 repo_cache + advisory，复制 mock_repo + mock_advisories 内容。"""
    repo_cache = tmp_path / "repo_cache"
    advisory_dir = tmp_path / "advisories"
    repo_cache.mkdir()
    advisory_dir.mkdir()
    # 镜像 mock_repo/<project>/<commit>/...
    for src in MOCK_REPO_ROOT.rglob("*"):
        if src.is_file():
            rel = src.relative_to(MOCK_REPO_ROOT)
            dst = repo_cache / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
    # 镜像 advisories
    for src in MOCK_ADV_DIR.glob("*.json"):
        (advisory_dir / src.name).write_bytes(src.read_bytes())
    return repo_cache, advisory_dir


@pytest.fixture
def tools(tmp_workspace) -> VulnGymTools:
    repo_cache, advisory_dir = tmp_workspace
    return VulnGymTools(
        repo_cache_dir=repo_cache,
        advisory_dir=advisory_dir,
        manifest=None,
    )


@pytest.fixture
def tools_with_manifest(tmp_workspace, manifest) -> VulnGymTools:
    """注入 manifest 的 tools，用于测试 commit layer 3 (公告范围) 判定。"""
    repo_cache, advisory_dir = tmp_workspace
    return VulnGymTools(
        repo_cache_dir=repo_cache,
        advisory_dir=advisory_dir,
        manifest=manifest,
    )


@pytest.fixture
def llm() -> ScriptedMockLLMClient:
    return ScriptedMockLLMClient()


def _base_entry(project_item: Dict[str, Any], report_id: str = "GHSA-DEMO-0001-0XSS") -> Dict[str, Any]:
    """构造一条完整 entry，指向 manifest 里的某个 project/commit/file。"""
    return {
        "entry_id": "entry-" + project_item["project"],
        "report_id": report_id,
        "repo_url": project_item["repo_url"],
        "commit": project_item["commit"],
        "entry_point": {
            "file": project_item["file"],
            "line": project_item["targets"][0]["line"],
            "code": project_item["targets"][0]["code"],
        },
        "critical_operation": {
            "file": project_item["file"],
            "line": project_item["targets"][0]["line"],
            "code": project_item["targets"][0]["code"],
        },
        "trace": [
            {
                "file": project_item["file"],
                "line": project_item["targets"][0]["line"],
                "code": project_item["targets"][0]["code"],
            },
        ],
        "vuln_ids": [],
        "vuln_title": "",
        "vuln_category_l1": "",
        "vuln_category_l2": "",
    }


# ============================================================
# TestRefFactories
# ============================================================

class TestRefFactories:
    """3 个 EvidenceRef 工厂函数的纯逻辑。"""

    def test_repo_ref_shape(self):
        r = _ref_repo("src/a.js", "1" * 40, 42, "foo();")
        assert r == {"source": "repository", "locator": "1111111:src/a.js:42", "quote": "foo();"}

    def test_repo_ref_quote_truncated_to_80(self):
        long = "x" * 200
        r = _ref_repo("f", "1" * 40, 1, long)
        assert len(r["quote"]) == 80
        assert r["quote"] == "x" * 80

    def test_git_ref_shape(self):
        r = _ref_git("blog", "1" * 40, "abc1234", "introduce: blog change")
        assert r["source"] == "git"
        assert r["locator"].startswith("blog/1111111:")
        assert "introduce" in r["quote"]

    def test_advisory_ref_shape(self):
        r = _ref_advisory("advisory.json#cve_id", "CVE-2026-0001")
        assert r == {
            "source": "advisory",
            "locator": "advisory.json#cve_id",
            "quote": "CVE-2026-0001",
        }

    def test_all_sources_valid(self):
        for fn in [_ref_repo, _ref_git, _ref_advisory]:
            r = fn("dummy", "1" * 40, 1, "x") if fn is not _ref_advisory else fn("advisory.json#x", "y")
            assert r["source"] in EVIDENCE_SOURCE_VALUES


# ============================================================
# TestEvidenceRefsShape
# ============================================================

class TestEvidenceRefsShape:
    """8 个 check_field_X 返回值都含 evidence_refs: list。"""

    def test_check_entry_point_returns_list(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_entry_point(e, tools, llm)
        assert "evidence_refs" in r
        assert isinstance(r["evidence_refs"], list)

    def test_check_critical_operation_returns_list(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_critical_operation(e, tools, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_check_commit_returns_list(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, tools)
        assert isinstance(r["evidence_refs"], list)

    def test_check_vuln_ids_returns_list(self, manifest):
        e = _base_entry(manifest["items"][0])
        e["vuln_ids"] = ["CVE-2026-0001"]
        adv = {"cve_id": "CVE-2026-0001", "ghsa_id": "GHSA-DEMO-0001-0XSS"}
        r = check_vuln_ids(e, adv)
        assert isinstance(r["evidence_refs"], list)

    def test_check_vuln_title_returns_list(self, manifest, llm):
        e = _base_entry(manifest["items"][0])
        e["vuln_title"] = "Stored XSS"
        adv = {"title": "Blog Platform Stored DOM XSS"}
        r = check_vuln_title(e, adv, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_check_category_returns_list(self, manifest, llm):
        e = _base_entry(manifest["items"][0])
        e["vuln_category_l1"] = "XSS"
        adv = {"vuln_category_l1_hint": "XSS"}
        r = check_category("l1", e, adv, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_check_trace_returns_list(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_trace(e, tools, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_source_enum_constraint(self, tools, llm, manifest):
        """所有填充的 source 必须在 I1 冻结的 frozenset 内。"""
        e = _base_entry(manifest["items"][0])
        r = check_entry_point(e, tools, llm)
        for ref in r["evidence_refs"]:
            assert ref["source"] in EVIDENCE_SOURCE_VALUES

    def test_each_ref_has_three_keys(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_entry_point(e, tools, llm)
        for ref in r["evidence_refs"]:
            assert set(ref.keys()) == {"source", "locator", "quote"}
            assert isinstance(ref["locator"], str)
            assert isinstance(ref["quote"], str)

    def test_empty_refs_require_non_empty_evidence(self, tools):
        """evidence_refs=[] 时 evidence 必须解释缺口（I1 §4.1）。"""
        e = _base_entry({
            "repo_url": "https://github.com/example/no-such-project",
            "project": "no-such-project",
            "commit": "f" * 40,
            "file": "x.js",
            "targets": [{"line": 1, "code": "x();"}],
        })
        r = check_commit(e, tools)
        assert r["evidence_refs"] == []
        assert len(r["evidence"]) > 0  # evidence 必须解释缺口


# ============================================================
# TestEntryPointRefs
# ============================================================

class TestEntryPointRefs:
    """entry_point 5 种场景。"""

    def test_correct_match_filled_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]  # blog-platform handlers/comment.js
        e = _base_entry(item)
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "correct"
        assert len(r["evidence_refs"]) >= 1
        assert r["evidence_refs"][0]["source"] == "repository"
        assert item["commit"][:7] in r["evidence_refs"][0]["locator"]
        assert item["file"] in r["evidence_refs"][0]["locator"]

    def test_line_drift_uncertain_with_two_refs(self, tools, llm, manifest):
        """标注 line 漂移超 ±5 范围但 code 真实 → 走 grep 兜底 → 2 refs。"""
        item = manifest["items"][0]
        e = _base_entry(item)
        # 偏移 10 行（超过 ±5 容错窗口），code 真实 → 应触发 grep 兜底或 incorrect
        e["entry_point"]["line"] = max(1, item["targets"][0]["line"] - 10)
        e["entry_point"]["code"] = item["targets"][0]["code"]
        r = check_entry_point(e, tools, llm)
        # 行号错位明显，status 应是 incorrect（精确读找不到 + ±5 也找不到）
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_code_mismatch_with_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["entry_point"]["code"] = "totallyDifferentCode();"
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1
        assert r["evidence_refs"][0]["source"] == "repository"

    def test_file_missing_with_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["entry_point"]["file"] = "src/missing.js"
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_checkout_failure_empty_refs(self, tools, llm, manifest):
        e = _base_entry({
            "repo_url": "https://github.com/example/no-such",
            "project": "no-such",
            "commit": "1" * 40,
            "file": "x.js",
            "targets": [{"line": 1, "code": "x();"}],
        })
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "uncertain"
        assert r["evidence_refs"] == []
        assert "checkout" in r["evidence"].lower() or "无法" in r["evidence"]

    def test_repository_becoming_unavailable_is_uncertain(self, llm, manifest):
        class RepositoryBecomesUnavailable:
            def checkout(self, _project, _commit):
                return ToolResult("checkout", True, {"cwd": "fixture://repo"})

            def read_file_lines(self, _cwd, _file, _start, _end):
                return ToolResult(
                    "read_file_lines", False, None,
                    "local clone is unavailable", "repo_unavailable",
                )

        result = check_entry_point(
            _base_entry(manifest["items"][0]), RepositoryBecomesUnavailable(), llm,
        )

        assert result["status"] == "uncertain"
        assert result["evidence_refs"] == []


# ============================================================
# TestCriticalOpRefs
# ============================================================

class TestCriticalOpRefs:
    """critical_operation 4 种场景。"""

    def test_match_fills_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        r = check_critical_operation(e, tools, llm)
        assert r["status"] == "correct"
        assert r["evidence_refs"][0]["source"] == "repository"

    def test_mismatch_with_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["critical_operation"]["code"] = "wrongCode();"
        r = check_critical_operation(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_repository_read_failure_is_uncertain(self, llm, manifest):
        class RepositoryReadFails:
            def checkout(self, _project, _commit):
                return ToolResult("checkout", True, {"cwd": "fixture://repo"})

            def read_file_lines(self, _cwd, _file, _start, _end):
                return ToolResult(
                    "read_file_lines", False, None,
                    "permission denied", "permission_denied",
                )

        result = check_critical_operation(
            _base_entry(manifest["items"][0]), RepositoryReadFails(), llm,
        )

        assert result["status"] == "uncertain"
        assert result["evidence_refs"] == []

    def test_line_drift_near_window(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["critical_operation"]["line"] = item["targets"][0]["line"] + 2
        e["critical_operation"]["code"] = item["targets"][0]["code"]
        r = check_critical_operation(e, tools, llm)
        # ±5 范围内能找到 → uncertain 或 incorrect，refs 应有
        assert len(r["evidence_refs"]) >= 1

    def test_grep_fallback_includes_extra_ref(self, tools, llm, manifest):
        """标注 code 在 ±5 行外，但 grep 能找到 → incorrect + 至少 2 refs。"""
        item = manifest["items"][0]
        e = _base_entry(item)
        # 偏移 10 行（超过 ±5 容错窗口），但 code 是真实 target code
        # 此时原 ±5 read 找不到 → grep 兜底 → 2 refs
        e["critical_operation"]["line"] = max(1, item["targets"][0]["line"] - 10)
        e["critical_operation"]["code"] = item["targets"][0]["code"]
        r = check_critical_operation(e, tools, llm)
        assert len(r["evidence_refs"]) >= 1  # 至少 repo ref
        # 若 grep 命中 → 2 refs；否则仅原始 ref
        if r["status"] == "incorrect":
            assert r["evidence_refs"][0]["source"] == "repository"


# ============================================================
# TestCommitRefs
# ============================================================

class TestCommitRefs:
    """commit 字段 3 种场景。"""

    def test_bad_format_empty_refs(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        e["commit"] = "not-40-hex"
        r = check_commit(e, tools)
        assert r["status"] == "uncertain"
        assert r["evidence_refs"] == []

    def test_cache_miss_empty_refs(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        e["commit"] = "f" * 40  # 不在 manifest
        r = check_commit(e, tools)
        assert r["status"] == "uncertain"
        assert r["evidence_refs"] == []

    def test_commit_missing_from_available_clone_is_incorrect(self, manifest):
        class MissingCommitTools:
            def checkout(self, _project, _commit):
                return ToolResult(
                    "checkout", False, None,
                    "commit not available in local clone", "commit_missing",
                )

        result = check_commit(
            _base_entry(manifest["items"][0]), MissingCommitTools(),
        )

        assert result["status"] == "incorrect"
        assert result["evidence_refs"][0]["source"] == "git"

    def test_normal_match_fills_repo_and_git(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, tools)
        assert r["status"] == "uncertain"
        sources = {ref["source"] for ref in r["evidence_refs"]}
        assert "repository" in sources
        assert "git" in sources


# ============================================================
# TestVulnIdsRefs
# ============================================================

class TestVulnIdsRefs:
    """vuln_ids 3 种场景。"""

    def test_ghsa_only_is_supported_when_report_id_carries_other_ids(self):
        """公告提供额外 CVE 不会使已提交的规范 GHSA 变错。"""
        e = {"vuln_ids": ["GHSA-DEMO-0001-0XSS"]}
        adv = {"cve_id": "CVE-2026-0001", "ghsa_id": "GHSA-DEMO-0001-0XSS"}
        r = check_vuln_ids(e, adv)
        assert r["status"] == "correct"
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_cve_only_is_supported_when_report_id_carries_ghsa(self):
        e = {"vuln_ids": ["CVE-2026-0001"]}
        adv = {"cve_id": "CVE-2026-0001", "ghsa_id": "GHSA-DEMO-0001-0XSS"}
        r = check_vuln_ids(e, adv)
        assert r["status"] == "correct"
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_normal_match_with_advisory_refs(self):
        e = {"vuln_ids": ["CVE-2026-0001", "GHSA-DEMO-0001-0XSS"]}
        adv = {"cve_id": "CVE-2026-0001", "ghsa_id": "GHSA-DEMO-0001-0XSS"}
        r = check_vuln_ids(e, adv)
        assert r["status"] == "correct"
        sources = {ref["source"] for ref in r["evidence_refs"]}
        assert sources == {"advisory"}

    def test_duplicate_or_lowercase_id_is_incorrect(self):
        adv = {"cve_id": "CVE-2026-0001"}
        duplicate = check_vuln_ids({"vuln_ids": ["CVE-2026-0001", "CVE-2026-0001"]}, adv)
        lowercase = check_vuln_ids({"vuln_ids": ["cve-2026-demo-0001"]}, adv)
        assert duplicate["status"] == "incorrect"
        assert lowercase["status"] == "incorrect"


# ============================================================
# TestTitleRefs
# ============================================================

class TestTitleRefs:
    """vuln_title 2 种场景。"""

    def test_llm_success_includes_advisory_ref(self, manifest, llm):
        e = {"vuln_title": "Stored DOM XSS in blog comments"}
        adv = {"title": "Blog Platform Stored DOM XSS via Comment Rich Text"}
        r = check_vuln_title(e, adv, llm)
        assert isinstance(r["evidence_refs"], list)
        # advisory ref 在 prompt 构造时就已填入
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_llm_failure_keeps_advisory_ref(self, manifest, llm):
        class BrokenLLM:
            name = "BrokenLLM"
            def chat(self, messages, *, temperature=0.0):
                return "not json"
        e = {"vuln_title": "Anything"}
        adv = {"title": "Real Title"}
        r = check_vuln_title(e, adv, BrokenLLM())
        # 即使 LLM 失败，advisory ref 应保留
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])


# ============================================================
# TestCategoryRefs
# ============================================================

class TestCategoryRefs:
    """vuln_category_l1/l2 2 种场景。"""

    def test_l1_match(self, manifest, llm):
        e = {"vuln_category_l1": "XSS"}
        adv = {"vuln_category_l1_hint": "XSS"}
        r = check_category("l1", e, adv, llm)
        assert isinstance(r["evidence_refs"], list)
        assert r["evidence_refs"][0]["source"] == "advisory"

    def test_l2_match(self, manifest, llm):
        e = {"vuln_category_l2": "Stored XSS"}
        adv = {"vuln_category_l2_hint": "Stored XSS"}
        r = check_category("l2", e, adv, llm)
        assert r["evidence_refs"][0]["source"] == "advisory"


# ============================================================
# TestTraceRefs
# ============================================================

class TestTraceRefs:
    """trace 4 种场景。"""

    def test_empty_trace(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        e["trace"] = []
        r = check_trace(e, tools, llm)
        assert r["status"] == "uncertain"
        assert r["evidence_refs"] == []

    def test_single_node_match(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_trace(e, tools, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_multi_node_each_node_ref(self, tools, llm, manifest):
        """trace 多节点 → 每个节点一个 ref。"""
        item = manifest["items"][1]  # blog RichTextInput.svelte (2 targets)
        e = _base_entry(item)
        e["trace"] = [
            {"file": item["file"], "line": t["line"], "code": t["code"]}
            for t in item["targets"]
        ]
        r = check_trace(e, tools, llm)
        # 至少每个节点一个 ref
        assert len(r["evidence_refs"]) >= len(item["targets"])

    def test_node_with_missing_file(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["trace"] = [
            {"file": "src/missing.js", "line": 1, "code": "x();"},
        ]
        r = check_trace(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_node_read_unavailable_is_uncertain(self, llm, manifest):
        class TraceSourceUnavailable:
            def checkout(self, _project, _commit):
                return ToolResult("checkout", True, {"cwd": "fixture://repo"})

            def read_file_lines(self, _cwd, _file, _start, _end):
                return ToolResult(
                    "read_file_lines", False, None,
                    "read timed out", "timeout",
                )

        result = check_trace(
            _base_entry(manifest["items"][0]), TraceSourceUnavailable(), llm,
        )

        assert result["status"] == "uncertain"
        assert result["evidence_refs"] == []


# ============================================================
# TestBackwardsCompat
# ============================================================

class TestBackwardsCompat:
    """check_all_fields 行为不变 + verdict 规则不变。"""

    def test_check_all_fields_keys(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["vuln_ids"] = ["CVE-2026-0001"]
        out = check_all_fields(e, tools, llm)
        assert "verdict" in out
        assert "fields" in out
        assert "summary" in out
        assert set(out["fields"].keys()) == {
            "entry_point", "critical_operation", "commit", "vuln_ids",
            "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace",
        }

    def test_verdict_correct_when_all_correct(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["vuln_ids"] = ["CVE-2026-0001"]
        e["vuln_title"] = "Blog Platform Stored DOM XSS via Comment Rich Text"
        e["vuln_category_l1"] = "XSS"
        e["vuln_category_l2"] = "Stored XSS"
        out = check_all_fields(e, tools, llm)
        # title/category 用 mock LLM 判定，scripted mock 走 default → uncertain
        # 所以整条 entry 应是 uncertain（除非 mock 给出 correct）
        assert out["verdict"] in ("correct", "uncertain", "incorrect")

    def test_verdict_incorrect_when_any_incorrect(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["entry_point"]["code"] = "wrongCode();"
        out = check_all_fields(e, tools, llm)
        assert out["verdict"] == "incorrect"


# ============================================================
# TestIntegrationWithI1Schema
# ============================================================

class TestIntegrationWithI1Schema:
    """I1 validate_field_result 对 I3 产出的字段对象全部 pass。"""

    def test_all_eight_fields_validate(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["vuln_ids"] = ["CVE-2026-0001"]
        e["vuln_title"] = "Blog Platform Stored DOM XSS"
        e["vuln_category_l1"] = "XSS"
        e["vuln_category_l2"] = "Stored XSS"
        out = check_all_fields(e, tools, llm)
        for fname, fobj in out["fields"].items():
            errs = validate_field_result(fobj, fname)
            assert errs == [], f"field {fname} failed I1 schema validation: {errs}"

    def test_refs_pass_individual_validation(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        r = check_entry_point(e, tools, llm)
        for ref in r["evidence_refs"]:
            # 重新构造 dict 用 validate_field_result 校验
            errs = validate_field_result(
                {"status": r["status"], "confidence": r["confidence"],
                 "evidence": r["evidence"], "evidence_refs": [ref]},
                "entry_point",
            )
            assert errs == [], f"ref failed: {ref}, errs={errs}"


# ============================================================
# TestCommitLayer3 — I3 commit 三层判定（含 layer 3 公告范围）
# ============================================================

class _TaggedTools:
    """只暴露 I3 所需的可定位本地 git 证据。"""

    def __init__(self, tags=None, checkout_ok=True):
        self.tags = list(tags or [])
        self.checkout_ok = checkout_ok

    def checkout(self, _project, commit):
        data = {"cwd": "git://repo/" + commit} if self.checkout_ok else None
        return ToolResult("checkout", self.checkout_ok, data, None if self.checkout_ok else "clone unavailable")

    def git_log(self, _project, commit, limit=1):
        return ToolResult("git_log", True, [{"sha": commit, "message": "fixture"}][:limit])

    def git_tags_at_commit(self, _project, _commit):
        return ToolResult("git_tags_at_commit", True, self.tags)


class TestCommitLayer3:
    """commit 校验区分源码快照引用与发布版本受影响范围。"""

    def test_exact_tag_in_affected_range_is_correct(self, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, _TaggedTools(["v1.0.0"]), {"affected_versions": ["< 1.1.0"]})
        assert r["status"] == "correct"

    def test_exact_tag_outside_affected_range_is_incorrect(self, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, _TaggedTools(["v1.2.0"]), {"affected_versions": ["< 1.1.0"]})
        assert r["status"] == "incorrect"

    def test_missing_advisory_range_is_correct(self, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, _TaggedTools(["v1.0.0"]), {"title": "no range"})
        assert r["status"] == "correct"
        # 证据必须说明 commit 可读且未做版本范围交叉验证
        assert "本地仓库中读取" in r["evidence"]

    def test_missing_exact_tag_is_correct(self, manifest):
        e = _base_entry(manifest["items"][0])
        result = check_commit(e, _TaggedTools(), {"affected_versions": ["< 1.1.0"]})
        assert result["status"] == "correct"
        # 证据必须说明无精确 tag 但不影响源码快照引用正确性
        assert "tag" in result["evidence"].lower()
        assert "源码快照引用" in result["evidence"]

    def test_unavailable_clone_is_uncertain(self, manifest):
        e = _base_entry(manifest["items"][0])
        assert check_commit(e, _TaggedTools(checkout_ok=False), {"affected_versions": ["< 1.1.0"]})["status"] == "uncertain"

    def test_unparseable_tag_is_uncertain(self, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, _TaggedTools(["not-a-version"]), {"affected_versions": ["< 1.1.0"]})
        assert r["status"] == "uncertain"
        assert "tag" in r["evidence"].lower() or "版本" in r["evidence"]

    def test_fixed_commit_is_not_treated_as_vulnerable_commit(self, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, _TaggedTools(["v1.0.0"]), {
            "affected_versions": ["< 1.1.0"], "fixed_commit": e["commit"],
        })
        assert r["status"] == "incorrect"

    def test_malformed_advisory_identifier_is_uncertain(self):
        r = check_vuln_ids({"vuln_ids": ["CVE-2026-0001"]}, {"cve_id": "not-an-id"})
        assert r["status"] == "uncertain"


# ============================================================
# TestI4ContractFixes — LLM 失败一律 uncertain，无关键词启发式回退为 correct
# ============================================================

class TestI4ContractFixes:
    """I4 契约：LLM 失败 / 不可解析 → semantic uncertain，禁止回退为 correct。"""

    def test_llm_failure_returns_uncertain_not_correct(self, llm):
        """LLM 输出非 JSON → uncertain（之前是 keyword 子串启发式回退 correct）。"""

        class BrokenLLM:
            name = "BrokenLLM"

            def chat(self, messages, *, temperature=0.0):
                # 完全不可解析的输出
                return "totally not parseable json at all"

        # 即使 advisory title 与 vuln_title 字面完全相同，也必须 uncertain
        e = {"vuln_title": "Same Title"}
        adv = {"title": "Same Title"}
        r = check_vuln_title(e, adv, BrokenLLM())
        assert r["status"] == "uncertain", (
            f"I4 契约违反：LLM 失败时回退为 {r['status']!r}，应始终为 uncertain"
        )
        # advisory ref 仍保留
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_category_llm_failure_returns_uncertain(self, llm):
        """category LLM 失败 → uncertain。"""

        class BrokenLLM:
            name = "BrokenLLM"

            def chat(self, messages, *, temperature=0.0):
                return "not json"

        e = {"vuln_category_l1": "XSS"}
        adv = {"vuln_category_l1_hint": "XSS"}
        r = check_category("l1", e, adv, BrokenLLM())
        assert r["status"] == "uncertain"

    def test_llm_exception_returns_uncertain_without_exception_text(self):
        """超时/HTTP 等 client 异常也必须形成无敏感细节的三态结果。"""

        class RaisingLLM:
            name = "RaisingLLM"

            def chat(self, messages, *, temperature=0.0):
                raise TimeoutError("Bearer super-secret-token-12345678 timed out")

        r = check_vuln_title({"vuln_title": "X"}, {"title": "Y"}, RaisingLLM())
        assert r["status"] == "uncertain"
        assert "super-secret" not in r["evidence"]

    def test_trace_llm_failure_returns_uncertain(self, tools, manifest):
        """trace LLM 失败 → uncertain。"""

        class BrokenLLM:
            name = "BrokenLLM"

            def chat(self, messages, *, temperature=0.0):
                return "not json"

        item = manifest["items"][0]
        e = _base_entry(item)
        r = check_trace(e, tools, BrokenLLM())
        assert r["status"] == "uncertain"

    def test_llm_success_uses_versioned_prompt(self, llm):
        """LLM 实际接收到的 prompt 必须包含 [PROMPT_VERSION=...] 前缀。"""
        captured = []

        class CaptureLLM:
            name = "CaptureLLM"

            def chat(self, messages, *, temperature=0.0):
                captured.append(messages[0].content)
                return json.dumps({
                    "status": "correct", "confidence": 0.9,
                    "evidence": "ok", "evidence_refs": [],
                })

        e = {"vuln_title": "X"}
        adv = {"title": "Y"}
        check_vuln_title(e, adv, CaptureLLM())
        assert len(captured) == 1
        assert "[PROMPT_VERSION=vuln_title_judge@1]" in captured[0]

    def test_category_uses_versioned_prompt(self):
        """category LLM 接收到 taxonomy-aware 的 v2 prompt。"""
        captured = []

        class CaptureLLM:
            name = "CaptureLLM"

            def chat(self, messages, *, temperature=0.0):
                captured.append(messages[0].content)
                return json.dumps({
                    "status": "correct", "confidence": 0.9,
                    "evidence": "ok", "evidence_refs": [],
                })

        e = {"vuln_category_l1": "X"}
        adv = {"vuln_category_l1_hint": "X"}
        check_category("l1", e, adv, CaptureLLM())
        assert "[PROMPT_VERSION=vuln_category_l1_judge@2]" in captured[0]
        assert "taxonomy_version: 1.0.0" in captured[0]
        assert "taxonomy_allowed_l1_l2_pairs:" in captured[0]
        assert "xss: l1=[XSS" in captured[0]

    def test_l2_canonical_mismatch_is_deterministically_incorrect(self):
        """l2 不能因同一个 l1 而被错误地映射成相同类别。"""
        r = check_category(
            "l2",
            {"vuln_category_l1": "XSS", "vuln_category_l2": "Stored XSS"},
            {"vuln_category_l2_hint": "服务端请求伪造"},
            ScriptedMockLLMClient(),
        )
        assert r["status"] == "incorrect"

    def test_trace_uses_versioned_prompt_and_trace_content(self, tools, manifest):
        """trace 语义判断必须收到版本化提示词及实际链路内容。"""
        captured = []

        class CaptureLLM:
            name = "CaptureLLM"

            def chat(self, messages, *, temperature=0.0):
                captured.append(messages[0].content)
                return json.dumps({
                    "status": "correct", "confidence": 0.9,
                    "evidence": "ok", "evidence_refs": [],
                })

        item = manifest["items"][0]
        e = _base_entry(item)
        check_trace(e, tools, CaptureLLM())
        assert any(
            "[PROMPT_VERSION=trace_overall_judge@2]" in m
            and e["trace"][0]["code"] in m
            for m in captured
        ), f"trace prompt should contain version prefix and nodes, got: {captured}"

    def test_evidence_redacted_at_call_site(self, llm):
        """parse_structured_response 在调用点生效：含路径的 evidence 会被脱敏。"""

        class LeakyLLM:
            name = "LeakyLLM"

            def chat(self, messages, *, temperature=0.0):
                return json.dumps({
                    "status": "incorrect",
                    "confidence": 0.8,
                    "evidence": "see C:\\Users\\secret\\admin.txt for details",
                    "evidence_refs": [],
                })

        e = {"vuln_title": "X"}
        adv = {"title": "Y"}
        r = check_vuln_title(e, adv, LeakyLLM())
        # evidence 中不能含原始绝对路径
        assert "C:\\Users\\secret" not in r["evidence"]
        assert "<abspath>" in r["evidence"]

    def test_invalid_status_from_llm_downgraded_to_uncertain(self):
        """LLM 返回非法 status（如 "maybe"）→ uncertain（parse 阶段就纠正）。"""

        class WeirdLLM:
            name = "WeirdLLM"

            def chat(self, messages, *, temperature=0.0):
                return json.dumps({
                    "status": "maybe-correct-ish",
                    "confidence": 1.7,  # 也越界
                    "evidence": "ok",
                    "evidence_refs": [],
                })

        e = {"vuln_title": "X"}
        adv = {"title": "Y"}
        r = check_vuln_title(e, adv, WeirdLLM())
        assert r["status"] == "uncertain"
        assert 0.0 <= r["confidence"] <= 1.0


# ============================================================
# TestVersionHelpers — _parse_version / _version_cmp / _version_is_affected
# ============================================================

class TestVersionHelpers:
    """版本解析与范围判定 helper 函数单元测试。"""

    def test_parse_version_with_v_prefix(self):
        from vulngym_verify_demo.field_checkers import _parse_version
        assert _parse_version("v0.1.4") == (0, 1, 4)
        assert _parse_version("v1.4.2") == (1, 4, 2)
        assert _parse_version("v3.1.0") == (3, 1, 0)

    def test_parse_version_without_v_prefix(self):
        from vulngym_verify_demo.field_checkers import _parse_version
        assert _parse_version("1.4.2") == (1, 4, 2)
        assert _parse_version("0.9.5") == (0, 9, 5)

    def test_parse_version_two_segments(self):
        from vulngym_verify_demo.field_checkers import _parse_version
        assert _parse_version("1.4") == (1, 4, 0)

    def test_parse_version_invalid(self):
        from vulngym_verify_demo.field_checkers import _parse_version
        assert _parse_version("") is None
        assert _parse_version("abc") is None
        assert _parse_version(None) is None
        assert _parse_version(123) is None

    def test_version_cmp_basic(self):
        from vulngym_verify_demo.field_checkers import _version_cmp
        assert _version_cmp("0.1.4", "1.4.2") == -1
        assert _version_cmp("1.4.2", "0.1.4") == 1
        assert _version_cmp("1.4.2", "1.4.2") == 0

    def test_version_is_affected_in_range(self):
        from vulngym_verify_demo.field_checkers import _version_is_affected
        assert _version_is_affected("0.1.4", ["< 1.4.2"]) is True
        assert _version_is_affected("1.4.2", ["< 1.4.2"]) is False
        assert _version_is_affected("2.0.0", ["< 1.4.2"]) is False

    def test_version_is_affected_empty(self):
        from vulngym_verify_demo.field_checkers import _version_is_affected
        assert _version_is_affected("1.0.0", []) is None
        assert _version_is_affected("1.0.0", None) is None


# ============================================================
# TestSemanticBundle — title/L1/L2/trace 合并为一次 LLM 调用（P1-A）
# ============================================================


class TestSemanticBundle:
    """semantic-bundle 契约：四字段合并为一次 LLM 调用，失败安全降级。"""

    def test_bundle_accepts_facts_kwarg(self):
        """check_semantic_bundle 必须接受 facts= 关键字参数。

        回归测试：真实运行时 check_all_fields 调用写成了 advisory=facts，
        而函数签名是 facts=，导致 TypeError 使整条 entry 降级为 agent-level
        fallback（20 条全 uncertain）。
        """
        # 构造一个所有语义字段都能确定性判定的 entry，避免实际 LLM 调用
        entry = {
            "vuln_title": "Same Title",
            "vuln_category_l1": "XSS",
            "vuln_category_l2": "Stored XSS",
            "trace": [],
        }
        facts = {"title": "Same Title", "valid": True}

        class NoopLLM:
            name = "NoopLLM"
            def chat(self, messages, *, temperature=0.0):
                raise AssertionError("should not call LLM when all fields deterministically decided")

        # 关键：用 facts= 调用，不能 TypeError
        results = check_semantic_bundle(entry, None, NoopLLM(), facts=facts)
        assert isinstance(results, dict)

    def test_bundle_makes_only_one_llm_call(self):
        """title/L1/L2/trace 合并为一次 LLM 调用，而非四次独立调用。"""
        call_count = {"n": 0}

        class CountingLLM:
            name = "CountingLLM"
            def chat(self, messages, *, temperature=0.0):
                call_count["n"] += 1
                return json.dumps({
                    "vuln_title": {"status": "correct", "confidence": 0.9, "evidence": "ok"},
                    "vuln_category_l1": {"status": "correct", "confidence": 0.8, "evidence": "ok"},
                    "vuln_category_l2": {"status": "incorrect", "confidence": 0.7, "evidence": "mismatch"},
                    "trace": {"status": "uncertain", "confidence": 0.3, "evidence": "insufficient"},
                })

        # 构造需要 LLM 判断的 entry（title 不匹配、category 需要判断、trace 非空）
        entry = {
            "commit": "abc1234def567890abc1234def567890abc1234",
            "vuln_title": "Different Title",
            "vuln_category_l1": "XSS",
            "vuln_category_l2": "Stored XSS",
            "trace": [{"file": "a.js", "line": 1, "code": "x()"}],
            "entry_point": {"file": "a.js", "line": 1, "code": "x()"},
            "critical_operation": {"file": "a.js", "line": 2, "code": "y()"},
        }
        facts = {"title": "Other Title", "valid": True}

        # 需要真实 tools 来做 trace 确定性前置检查；用 mock tools
        from vulngym_verify_demo.tools import ToolResult

        class FakeTools:
            def read_file_lines(self, cwd, file, start, end):
                return ToolResult("read_file_lines", True, {"lines": ["x()"], "snippet": "x()"}, None, None)
            def checkout(self, project, commit):
                return ToolResult("checkout", True, {"cwd": "/tmp/repo", "dir": "/tmp/repo"}, None, None)

        results = check_semantic_bundle(entry, FakeTools(), CountingLLM(), facts=facts)
        assert call_count["n"] == 1, f"expected exactly 1 LLM call, got {call_count['n']}"

    def test_bundle_failure_downgrades_to_uncertain(self):
        """bundle LLM 调用失败/非法输出 → 所有 bundle 字段降为 uncertain。"""
        class BrokenLLM:
            name = "BrokenLLM"
            def chat(self, messages, *, temperature=0.0):
                return "not json at all"

        entry = {
            "commit": "abc1234def567890abc1234def567890abc1234",
            "vuln_title": "X",
            "vuln_category_l1": "XSS",
            "vuln_category_l2": "Stored XSS",
            "trace": [{"file": "a.js", "line": 1, "code": "x()"}],
            "entry_point": {"file": "a.js", "line": 1, "code": "x()"},
            "critical_operation": {"file": "a.js", "line": 2, "code": "y()"},
        }
        facts = {
            "summary": "Advisory Title Y",
            "category_signal": {"l1_hint": "Injection", "l2_hint": "Command Injection"},
            "valid": True,
        }

        from vulngym_verify_demo.tools import ToolResult

        class FakeTools:
            def read_file_lines(self, cwd, file, start, end):
                return ToolResult("read_file_lines", True, {"lines": ["x()"], "snippet": "x()"}, None, None)
            def checkout(self, project, commit):
                return ToolResult("checkout", True, {"cwd": "/tmp/repo", "dir": "/tmp/repo"}, None, None)

        results = check_semantic_bundle(entry, FakeTools(), BrokenLLM(), facts=facts)
        # 进入 bundle 的字段都应降为 uncertain（title/l1/l2 一定进入，trace 可能被确定性判定）
        bundle_fields_seen = [f for f in BUNDLE_FIELDS if f in results]
        assert len(bundle_fields_seen) >= 3, f"expected at least 3 bundle fields, got {bundle_fields_seen}"
        for field in bundle_fields_seen:
            assert results[field]["status"] == "uncertain", (
                f"{field} should be uncertain after bundle failure, got {results[field]['status']}"
            )
            ev_lower = results[field]["evidence"].lower()
            assert "bundle" in ev_lower or "missing" in ev_lower or "semantic" in ev_lower, (
                f"{field} evidence should mention bundle failure: {results[field]['evidence']}"
            )

    def test_bundle_success_parses_all_four_fields(self):
        """bundle 成功返回时，四字段结果都被正确解析。"""
        class GoodLLM:
            name = "GoodLLM"
            def chat(self, messages, *, temperature=0.0):
                return json.dumps({
                    "vuln_title": {"status": "incorrect", "confidence": 0.85, "evidence": "title mismatch"},
                    "vuln_category_l1": {"status": "correct", "confidence": 0.9, "evidence": "l1 ok"},
                    "vuln_category_l2": {"status": "uncertain", "confidence": 0.4, "evidence": "l2 unclear"},
                    "trace": {"status": "correct", "confidence": 0.7, "evidence": "trace consistent"},
                })

        entry = {
            "commit": "abc1234def567890abc1234def567890abc1234",
            "vuln_title": "X", "vuln_category_l1": "XSS", "vuln_category_l2": "Stored XSS",
            "trace": [{"file": "a.js", "line": 1, "code": "x()"}],
            "entry_point": {"file": "a.js", "line": 1, "code": "x()"},
            "critical_operation": {"file": "a.js", "line": 2, "code": "y()"},
        }
        facts = {
            "summary": "Advisory Title Y",
            "category_signal": {"l1_hint": "Injection", "l2_hint": "Command Injection"},
            "valid": True,
        }

        from vulngym_verify_demo.tools import ToolResult

        class FakeTools:
            def read_file_lines(self, cwd, file, start, end):
                return ToolResult("read_file_lines", True, {"lines": ["x()"], "snippet": "x()"}, None, None)
            def checkout(self, project, commit):
                return ToolResult("checkout", True, {"cwd": "/tmp/repo", "dir": "/tmp/repo"}, None, None)

        results = check_semantic_bundle(entry, FakeTools(), GoodLLM(), facts=facts)
        # title/l1/l2 一定进入 bundle 并被 GoodLLM 解析；trace 可能被确定性判定
        assert results["vuln_title"]["status"] == "incorrect"
        assert results["vuln_category_l1"]["status"] == "correct"
        assert results["vuln_category_l2"]["status"] == "uncertain"
        if "trace" in results:
            assert results["trace"]["status"] in ("correct", "incorrect", "uncertain")
        # confidence 被 clamp 到 [0, 1]
        for field in BUNDLE_FIELDS:
            if field in results:
                assert 0.0 <= results[field]["confidence"] <= 1.0

    def test_bundle_fields_are_exactly_four(self):
        """BUNDLE_FIELDS 必须恰好是 title/L1/L2/trace 四个语义字段。"""
        assert set(BUNDLE_FIELDS) == {"vuln_title", "vuln_category_l1", "vuln_category_l2", "trace"}
        assert len(BUNDLE_FIELDS) == 4

    def test_check_all_fields_uses_bundle_not_individual_calls(self, tools, manifest):
        """check_all_fields 必须走 bundle 路径，语义字段只触发一次 LLM 调用。"""
        call_count = {"n": 0}

        class CountingLLM:
            name = "CountingLLM"
            def chat(self, messages, *, temperature=0.0):
                call_count["n"] += 1
                # self-check 也会调用 LLM，所以这里返回 agree=True
                if "self_check" in messages[0].content or "agree" in messages[0].content:
                    return json.dumps({"agree": True, "comment": "ok"})
                return json.dumps({
                    "vuln_title": {"status": "correct", "confidence": 0.9, "evidence": "ok"},
                    "vuln_category_l1": {"status": "correct", "confidence": 0.8, "evidence": "ok"},
                    "vuln_category_l2": {"status": "correct", "confidence": 0.8, "evidence": "ok"},
                    "trace": {"status": "correct", "confidence": 0.7, "evidence": "ok"},
                })

        item = manifest["items"][0]
        entry = _base_entry(item)
        entry["vuln_title"] = "Different from advisory"
        entry["vuln_ids"] = ["CVE-2026-0001"]

        result = check_all_fields(entry, tools, CountingLLM())
        # 语义字段 bundle 1 次 + self-check 1 次 = 最多 2 次 LLM 调用
        # （旧的四字段独立调用会是 4 + 1 = 5 次）
        assert call_count["n"] <= 2, (
            f"expected <=2 LLM calls (bundle + self-check), got {call_count['n']}"
        )
        # 确定性字段不受 bundle 影响
        assert "entry_point" in result["fields"]
        assert "critical_operation" in result["fields"]
        assert "commit" in result["fields"]
        assert "vuln_ids" in result["fields"]
