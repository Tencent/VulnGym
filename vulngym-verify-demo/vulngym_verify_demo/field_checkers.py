# -*- coding: utf-8 -*-
"""字段级三态判定：entry_point / critical_operation / vuln_ids / commit /
vuln_title / vuln_category_l1 / vuln_category_l2 / trace。

每个 check_field_X 返回：
    {
      "status":     "correct" | "incorrect" | "uncertain",
      "confidence": float in [0, 1],
      "evidence":   一句话以上，引用工具返回的具体内容
      "evidence_refs": List[Dict[str, str]]   # I3 新增 — I1 schema 已冻结字段
    }

策略：
- 优先用工具做确定性检查（grep_code / read_file_lines）
- 信息不足或需要语义理解时调用 LLM（带 mock fallback）

I3 升级：
  * 每个 check_field_X 填充 evidence_refs:
    - 确定性字段（entry_point / critical_operation / commit / trace）：repository / git
    - 公告相关字段（vuln_ids / title / category_l1 / l2）：advisory
  * check_all_fields 汇总逻辑**不改**（ISSUE_OUTLINE §5 I3 明确约束）
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .advisory_adapter import AdvisoryAdapter, version_in_range
from .llm_client import BaseLLMClient, LLMMessage, parse_json_object, parse_structured_response, redact_text
from .tools import ToolResult, VulnGymTools, normalize_project_from_repo
from .prompts import (
    SEMANTIC_BUNDLE_PROMPT,
    TRACE_OVERALL_PROMPT,
    VULN_TITLE_PROMPT,
    vuln_category_prompt,
)
from .taxonomy import load_category_taxonomy
# 避免循环导入：models.py 末尾会 import field_checkers，所以这里不能用
# `from .models import EvidenceRef`。直接用具名字典构造（schema.py §4.1
# 与 validate_evidence_ref 完全兼容），并在 to_dict 输出时保持同构。


# ============================================================
# P0-4：公告适配层（raw GHSA / demo fixture → 内部事实视图）
# ============================================================

_ADAPTER = AdvisoryAdapter()


def _facts(advisory: Any) -> Dict[str, Any]:
    """把任意公告输入统一成内部事实视图（幂等）。

    接受原始 GitHub Advisory、demo fixture 或已适配的 facts；非 dict 一律视为
    ``advisory_invalid``，由上层输出 ``uncertain``。
    """
    return _ADAPTER.adapt(advisory if isinstance(advisory, dict) else {})


def _repo_handle(entry: Dict[str, Any], tools: Any) -> Optional[str]:
    """entry → 仓库句柄 / project key。

    * 有 :class:`RepositoryResolver` 时返回不透明的 ``repo:<owner>/<name>``；
    * 否则回退到 manifest/basename（仅用于旧 demo 与单元桩）。
    """
    getter = getattr(tools, "repo_handle", None)
    if callable(getter):
        try:
            return getter(entry)
        except Exception:
            return None
    return normalize_project_from_repo(entry.get("repo_url", "")) or None


def _checkout_entry(entry: Dict[str, Any], tools: Any) -> tuple:
    """按 entry 的 ``repo_url`` 解析并 checkout（只读）。

    返回 ``(handle, ToolResult)``。当 ``repo_url`` 未能映射时传递 ``None``，由
    ``VulnGymTools.checkout`` 返回 ``repo_unavailable`` —— 这样失败调用**仍然经过
    recording proxy 进入 tool_trace**，不会出现"无证据也无解释"的报告。
    """
    handle = _repo_handle(entry, tools)
    return handle, tools.checkout(handle, entry.get("commit", ""))


# ============================================================
# EvidenceRef 工厂函数（I3 新增）
# ============================================================


def _ref_repo(file: str, commit: str, line_spec: Any, quote: str) -> Dict[str, str]:
    """构造 repository 类型引用 dict（与 EvidenceRef.to_dict() 同构）。

    locator 格式: <commit[:7]>:<file>:<line>
    quote 截断到 80 字符（schema.py §4.1 限制）
    """
    locator = "{}:{}:{}".format(commit[:7], file, line_spec)
    q = (quote or "").strip()
    if len(q) > 80:
        q = q[:80]
    return {"source": "repository", "locator": locator, "quote": q}


def _ref_git(project: str, commit: str, sha_or_message: str, quote: str = "") -> Dict[str, str]:
    """构造 git 类型引用 dict。

    locator 格式: <project>/<commit[:7]>:<sha_or_message>
    """
    locator = "{}/{}:{}".format(project, commit[:7], sha_or_message)
    q = (quote or "").strip()
    if len(q) > 80:
        q = q[:80]
    return {"source": "git", "locator": locator, "quote": q}


def _ref_advisory(advisory_locator: str, quote: str) -> Dict[str, str]:
    """构造 advisory 类型引用 dict。

    locator 格式: advisory.json#<json_path>
    """
    q = (quote or "").strip()
    if len(q) > 80:
        q = q[:80]
    return {"source": "advisory", "locator": advisory_locator, "quote": q}


# ---------- 辅助：line 归一化 ----------
# ---------- 分类重叠簇（避免用 CWE 过度反证） ----------

#: taxonomy 中语义相互重叠的类别簇。
#:
#: CWE→类别的映射是**粗粒度**的（例如 CWE-863 "Incorrect Authorization" 既可归入
#: ``access_control``，也可归入 VulnGym 自己的 ``business_logic``——后者显式定义了
#: ``BL-AUTH-BYPASS`` / ``BL-AUTHZ-BROKEN`` 等 L2 别名）。因此当条目标签与 CWE 映射
#: 落在**同一个重叠簇**内时，证据不足以确定性反证，必须交由 LLM 语义判断；
#: 无模型时保持 ``uncertain``，不得输出 ``incorrect``。
CATEGORY_OVERLAP_CLUSTERS: Tuple[frozenset, ...] = (
    frozenset({"access_control", "business_logic"}),
    frozenset({"code_injection", "command_injection"}),
    frozenset({"file_system", "sandbox_escape"}),
    frozenset({"information_disclosure", "ssrf"}),
    frozenset({"information_disclosure", "file_system"}),
    frozenset({"deserialization", "code_injection"}),
    frozenset({"supply_chain", "code_injection"}),
    frozenset({"prototype_pollution", "code_injection"}),
)


def _categories_overlap(left: Optional[str], right: Optional[str]) -> bool:
    """两个 taxonomy 类别是否属于同一个语义重叠簇（是则不作为确定性反证）。"""
    if not left or not right:
        return False
    return any(left in cluster and right in cluster for cluster in CATEGORY_OVERLAP_CLUSTERS)


def _line_range(value: Any) -> Tuple[int, int]:
    """把 int 或 "a-b" 转成 (start, end)。"""
    if isinstance(value, int):
        return (value, value)
    if isinstance(value, str) and "-" in value:
        a, b = value.split("-", 1)
        return (int(a), int(b))
    raise ValueError(f"bad line spec: {value!r}")


def _line_spec_repr(value: Any) -> str:
    """把 line spec 序列化成 locator 用字符串。"""
    if isinstance(value, int):
        return str(value)
    return str(value)


def _norm_code(code: str) -> str:
    # 归一化工具 1/2：把连续空白(空格/制表/换行)折叠成单空格
    # 目的：实测代码和标注代码常常只是缩进/换行不同，归一化后方便做包含判定
    return re.sub(r"\s+", " ", (code or "").strip())


_SOURCE_CONTRADICTION_CODES = {
    "file_missing_at_commit",
    "line_out_of_range",
}


def _source_read_failure(
    field_name: str,
    node: Dict[str, Any],
    commit: str,
    result: ToolResult,
) -> Dict[str, Any]:
    """Map a source-read failure without confusing missing evidence with a contradiction."""
    error_code = getattr(result, "error_code", None)
    if error_code in _SOURCE_CONTRADICTION_CODES:
        detail = result.error or error_code
        return {
            "status": "incorrect",
            "confidence": 0.95,
            "evidence": f"{field_name} 在指定 commit 下无法与标注位置匹配：{detail}",
            "evidence_refs": [
                _ref_repo(node["file"], commit, node["line"], detail),
            ],
        }
    return {
        "status": "uncertain",
        "confidence": 0.30,
        "evidence": (
            f"{field_name} 源码证据不可用，无法判定标注对错："
            f"{result.error or error_code or 'unknown tool failure'}"
        ),
        "evidence_refs": [],
    }


# ============================================================
# I3 Layer-3: 版本号解析与公告范围判定（I3 启动手册 §5 验收 2-3）
# ============================================================

_VERSION_RX = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_version(s: Any) -> Optional[Tuple[int, int, int]]:
    """解析 '1.4.2' / 'v0.1.4' 为 (1,4,2) 元组；不可解析返回 None。"""
    if not s or not isinstance(s, str):
        return None
    m = _VERSION_RX.fullmatch(s.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _version_cmp(a: Any, b: Any) -> Optional[int]:
    """比较两个版本；不可解析返回 None。"""
    va, vb = _parse_version(a), _parse_version(b)
    if va is None or vb is None:
        return None
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def _version_is_affected(version: Any, affected_versions: Any) -> Optional[bool]:
    """判定 version 是否落在 affected_versions 任何一个区间内。

    返回：
        True  - 落在区间（受影响）
        False - 全部区间都不命中（不受影响）
        None  - 无法判定（区间格式未知或 version 无法解析）

    仅支持 ``< X.Y.Z`` 形式（与 mock advisories 当前形态一致）。
    """
    if not version or not affected_versions or not isinstance(affected_versions, list):
        return None
    any_decidable = False
    for spec in affected_versions:
        if not isinstance(spec, str):
            return None
        spec = spec.strip()
        if spec.startswith("< "):
            threshold = spec[2:].strip()
            c = _version_cmp(version, threshold)
            if c is not None:
                any_decidable = True
                if c < 0:
                    return True
        else:
            # 不支持的范围表达式（如 "<="、">"、"="）→ 视为不可判定
            return None
    if any_decidable:
        return False
    return None


def _version_meets_or_exceeds(version: Any, threshold: Any) -> Optional[bool]:
    """判定 version >= threshold；不可解析返回 None。"""
    if not version or not threshold:
        return None
    c = _version_cmp(version, threshold)
    if c is None:
        return None
    return c >= 0


def _merge_refs(*ref_lists: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """按 (source, locator, quote) 三键去重合并多组 refs。"""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for refs in ref_lists:
        if not refs:
            continue
        for r in refs:
            if not isinstance(r, dict):
                continue
            key = (r.get("source"), r.get("locator"), r.get("quote"))
            if key not in seen:
                out.append(r)
                seen.add(key)
    return out


def _trace_summary_for_prompt(trace: List[Dict[str, Any]]) -> str:
    """Return bounded, data-only trace context for the semantic trace judge.

    A node count alone cannot establish whether a chain is coherent.  Send the
    ordered local evidence while bounding each untrusted value so one malformed
    input cannot exhaust the provider context window.
    """
    compact: List[Dict[str, Any]] = []
    for index, node in enumerate(trace[:12]):
        if not isinstance(node, dict):
            continue
        compact.append({
            "index": index,
            "file": str(node.get("file", ""))[:240],
            "line": str(node.get("line", ""))[:40],
            "code": str(node.get("code", ""))[:320],
            "description": str(node.get("desc", ""))[:480],
        })
    return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))


def _semantic_llm_result(
    llm: BaseLLMClient,
    prompt: str,
    refs: List[Dict[str, str]],
) -> Dict[str, Any]:
    """Call an LLM without letting a provider failure escape a field checker.

    Provider timeouts, HTTP failures and malformed client implementations are
    evidence gaps, not evidence that the submitted field is wrong.  Do not copy
    an exception into the report: clients may include endpoint or credential
    material in their diagnostic text.
    """
    try:
        raw = llm.chat([LLMMessage("user", prompt)])
    except Exception:
        return {
            "status": "uncertain",
            "confidence": 0.20,
            "evidence": "LLM unavailable; cannot perform semantic judgement.",
            "evidence_refs": refs,
        }
    data = parse_structured_response(raw)
    data["evidence_refs"] = _merge_refs(data.get("evidence_refs") or [], refs)
    return data


# ============================================================
# 单字段判定
# ============================================================
def check_entry_point(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    # entry_point 是高优先级字段，判定顺序分三层：
    # 1) 精确校验：checkout 到目标 commit，直接读取标注 line 对应代码；
    # 2) 容错校验：若当前行不匹配，再检查邻近 ±5 行是否只是行号漂移；
    # 3) 最终兜底：仍不匹配则判 incorrect，并把 actual/expected 写进 evidence。
    ep = entry["entry_point"]
    commit = entry["commit"]
    _handle, co = _checkout_entry(entry, tools)
    if not co.ok:
        return {"status": "uncertain", "confidence": 0.35,
                "evidence": f"无法读取本地 commit={commit[:7]}；需要可访问的本地仓库或快照：{co.error}",
                "evidence_refs": []}

    reads = tools.read_file_lines(co.data["cwd"], ep["file"],
                                  *_line_range(ep["line"]))
    if not reads.ok:
        return _source_read_failure("entry_point", ep, commit, reads)

    snippet = reads.data["snippet"]
    actual = _norm_code(snippet)
    expected = _norm_code(ep["code"])
    refs: List[Dict[str, str]] = [
        _ref_repo(ep["file"], commit, ep["line"], snippet),
    ]
    # 允许"标注代码是实测代码的子串"或反过来，兼容多行截取差异。
    if expected in actual or actual in expected:
        return {"status": "correct", "confidence": 0.90,
                "evidence": f"checkout 后 {ep['file']}:{ep['line']} 代码片段匹配 (snippet={snippet.strip()[:120]})",
                "evidence_refs": refs}

    # 第二层：行号可能因为 commit 漂移或标注误差发生偏移，尝试局部窗口复核。
    s, e = _line_range(ep["line"])
    near_start, near_end = max(1, s - 5), e + 5
    near = tools.read_file_lines(co.data["cwd"], ep["file"], near_start, near_end)
    if near.ok and expected in _norm_code(near.data["snippet"]):
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"行号偏移：在 {near_start}-{near_end} 范围内找到匹配代码片段，但原 line {ep['line']} 不匹配",
                "evidence_refs": refs + [
                    _ref_repo(ep["file"], commit,
                              f"{near_start}-{near_end}",
                              near.data["snippet"]),
                ]}

    return {"status": "incorrect", "confidence": 0.85,
            "evidence": f"代码片段不匹配：actual={actual[:80]} expected={expected[:80]}",
            "evidence_refs": refs}


def check_critical_operation(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    co_field = entry["critical_operation"]
    commit = entry["commit"]
    _handle, co = _checkout_entry(entry, tools)
    if not co.ok:
        return {"status": "uncertain", "confidence": 0.35,
                "evidence": f"无法读取本地 commit；需要可访问的本地仓库或快照：{co.error}",
                "evidence_refs": []}

    reads = tools.read_file_lines(co.data["cwd"], co_field["file"],
                                  *_line_range(co_field["line"]))
    if not reads.ok:
        return _source_read_failure(
            "critical_operation", co_field, commit, reads,
        )

    actual = _norm_code(reads.data["snippet"])
    expected = _norm_code(co_field["code"])
    refs: List[Dict[str, str]] = [
        _ref_repo(co_field["file"], commit, co_field["line"], reads.data["snippet"]),
    ]
    if expected in actual or actual in expected:
        return {"status": "correct", "confidence": 0.90,
                "evidence": f"checkout 后 {co_field['file']}:{co_field['line']} 匹配 (snippet={reads.data['snippet'].strip()[:120]})",
                "evidence_refs": refs}

    # 临近窗口搜索
    s, e = _line_range(co_field["line"])
    near = tools.read_file_lines(co.data["cwd"], co_field["file"], max(1, s - 5), e + 5)
    if near.ok and expected in _norm_code(near.data["snippet"]):
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"行号漂移：邻近 ±5 行内能匹配，但 line {co_field['line']} 不匹配",
                "evidence_refs": refs + [
                    _ref_repo(co_field["file"], commit,
                              f"{max(1, s-5)}-{e+5}",
                              near.data["snippet"]),
                ]}

    # 用 grep 兜底
    grep = tools.grep_code(co.data["cwd"], co_field["file"], re.escape(co_field["code"].strip()))
    if grep.ok and grep.data["hits"]:
        first = grep.data["hits"][0]
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": f"行号错误：实际匹配行 {first['line']}，标注 {co_field['line']}（{first['text'][:80]}）",
                "evidence_refs": refs + [
                    _ref_repo(co_field["file"], commit, first["line"], first["text"]),
                ]}

    return {"status": "incorrect", "confidence": 0.85,
            "evidence": f"代码片段不匹配：actual={actual[:80]} expected={expected[:80]}",
            "evidence_refs": refs}


def check_commit(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    advisory: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a vulnerable commit using only local git and advisory evidence.

    安全规则（T1Data 资料包核心约束）：

    * ``commit`` 字段首先是**源码快照引用**：对象能在条目声明的仓库中只读解析，
      且没有明确修复反证时，可判定该引用正确；
    * 「目标 commit 可读」仍**不等于**「已证明某个发布版本受影响」。发布版本归属
      仅在「可解析的受影响版本范围」+「commit 到版本的精确关联」齐备时附加确认；
      缺少 tag 只降低该附加结论的置信度，不能让全部源码快照引用自动变成
      ``uncertain``；
    * 精确关联优先使用**本地精确 tag**（``git tag --points-at``），从不从邻近历史
      猜测版本；
    * 公告 ``references`` / ``patch-index`` 中的 commit 属于**候选材料**，只有在
      公告自身显式给出修复提交字段（``fixed_commit*``）时才用于反证，绝不把
      公开引用链接自动当作修复事实。
    """
    commit = entry.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        return {"status": "uncertain", "confidence": 0.20,
                "evidence": f"commit 不是可验证的 40 位小写 hex：{commit!r}；需要有效 commit 后才能核验",
                "evidence_refs": []}

    facts = _facts(advisory) if advisory is not None else None
    handle, co = _checkout_entry(entry, tools)
    if not co.ok:
        if getattr(co, "error_code", None) == "commit_missing" and handle:
            return {
                "status": "incorrect",
                "confidence": 0.98,
                "evidence": f"目标仓库可访问，但 commit {commit} 不存在于该仓库对象库中",
                "evidence_refs": [
                    _ref_git(handle, commit, "cat-file", co.error or "commit missing"),
                ],
            }
        # 仓库不可用 / 快照缺失 / 未映射：证据不足，不能伪造反证
        return {"status": "uncertain", "confidence": 0.30,
                "evidence": f"commit 无法在可访问的本地代码源中解析：{co.error}；需要完整仓库或快照",
                "evidence_refs": []}

    refs: List[Dict[str, str]] = [
        _ref_repo("<local-repository>", commit, "0", f"commit {commit} is locally readable"),
    ]
    gl = tools.git_log(handle, commit, limit=1)
    if gl.ok and gl.data:
        first = gl.data[0]
        refs.append(_ref_git(handle, commit, first["sha"], first.get("message", "")))

    if facts is None or not facts.get("valid"):
        return {"status": "correct", "confidence": 0.80,
                "evidence": f"commit {commit[:7]} 可在条目声明的本地仓库中读取；公告证据不可用，未做版本范围交叉验证，但不影响源码快照引用正确性。",
                "evidence_refs": refs}

    # ① 公告显式声明的修复/补丁提交 → 该 commit 不是漏洞版本。
    if commit in facts.get("fixed_commit_candidates", []):
        return {"status": "incorrect", "confidence": 0.98,
                "evidence": "公告显式将该 commit 标记为修复/补丁提交，不能作为漏洞版本提交",
                "evidence_refs": refs + [
                    _ref_advisory(facts["provenance"].get("fixed_commits", "advisory.json#fixed_commit"), commit),
                ]}

    ranges = facts.get("affected_version_ranges") or []
    if not ranges:
        return {
            "status": "correct",
            "confidence": 0.82,
            "evidence": (
                "commit " + commit[:7] + " 可在条目声明的本地仓库中读取，且公告未将其标记为修复提交；"
                "公告未提供可解析的受影响版本范围，未做版本范围交叉验证，但不影响源码快照引用正确性。"
            ),
            "evidence_refs": refs,
        }

    range_locator = facts.get("provenance", {}).get("vulnerabilities", "advisory.json#vulnerabilities")
    refs.append(_ref_advisory(range_locator, ",".join(ranges)))

    tag_result = tools.git_tags_at_commit(handle, commit)
    tags = list(tag_result.data) if tag_result.ok and isinstance(tag_result.data, list) else []
    if tags:
        undecidable = False
        for tag in tags:
            verdicts = [version_in_range(tag, spec) for spec in ranges]
            if any(v is True for v in verdicts):
                return {"status": "correct", "confidence": 0.92,
                        "evidence": (f"commit {commit[:7]} 对应本地精确 tag {tag}，"
                                     f"落在公告受影响范围 {ranges} 内"),
                        "evidence_refs": refs + [_ref_git(handle, commit, tag, "exact tag at commit")]}
            if any(v is None for v in verdicts):
                undecidable = True
        if not undecidable:
            return {"status": "incorrect", "confidence": 0.88,
                    "evidence": f"commit {commit[:7]} 对应本地精确 tag {tags}，均不落在公告受影响范围 {ranges} 内",
                    "evidence_refs": refs + [_ref_git(handle, commit, tags[0], "exact tag at commit")]}
        return {"status": "uncertain", "confidence": 0.45,
                "evidence": f"本地 tags {tags} 无法解析为公告受影响版本范围 {ranges}",
                "evidence_refs": refs}

    # ② 无精确 tag：commit 可读且无修复反证即判 correct，不再因缺 tag 降级
    if commit in (facts.get("reference_commits") or []):
        return {"status": "correct", "confidence": 0.85,
                "evidence": (f"commit {commit[:7]} 可在条目声明的本地仓库中读取，且公告未将其"
                             "标记为修复提交；它同时出现在公告公开引用候选中。"
                             "本地无精确版本 tag，未做版本范围交叉验证，但不影响源码快照引用正确性。"),
                "evidence_refs": refs + [
                    _ref_advisory(facts.get("provenance", {}).get("references", "advisory.json#references"), commit),
                ]}

    return {"status": "correct", "confidence": 0.85,
            "evidence": (f"commit {commit[:7]} 可在条目声明的本地仓库中读取，且没有公告明确的"
                         "修复提交反证；本地无精确版本 tag，未做版本范围交叉验证，但不影响源码快照引用正确性。"),
            "evidence_refs": refs}


def check_vuln_ids(
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
) -> Dict[str, Any]:
    """Deterministically compare normalized CVE/GHSA identifiers to advisory data."""
    raw_ids = entry.get("vuln_ids", [])
    if not isinstance(raw_ids, list) or not all(isinstance(value, str) for value in raw_ids):
        return {"status": "uncertain", "confidence": 0.20,
                "evidence": "vuln_ids 不是可验证的字符串列表，需要修复输入格式",
                "evidence_refs": []}
    ids = [value.strip().upper() for value in raw_ids]
    invalid = [value for value in ids if not re.fullmatch(r"CVE-\d{4}-\d{4,}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", value)]
    if invalid:
        return {"status": "incorrect", "confidence": 0.98,
                "evidence": f"vuln_ids 包含无效 CVE/GHSA 格式：{invalid}", "evidence_refs": []}
    if len(ids) != len(set(ids)):
        return {"status": "incorrect", "confidence": 0.98,
                "evidence": "vuln_ids 存在重复标识符；SCHEMA 要求去重", "evidence_refs": []}
    if raw_ids != ids:
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": "vuln_ids 必须使用去除空白后的大写 CVE/GHSA 规范形式", "evidence_refs": []}

    facts = _facts(advisory)
    refs = [
        _ref_advisory(facts.get("provenance", {}).get("identifiers", "advisory.json#identifiers"), identifier)
        for identifier in facts.get("identifiers", [])
    ]
    if not facts.get("valid"):
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": f"本地公告不可用，无法校验 vuln_ids：{facts.get('reason')}",
                "evidence_refs": refs}
    invalid_advisory_ids = facts.get("invalid_identifiers") or []
    if invalid_advisory_ids:
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": f"本地公告包含不可验证的 CVE/GHSA 标识符 {invalid_advisory_ids}，需修复公告缓存",
                "evidence_refs": refs}
    expected = list(dict.fromkeys(facts.get("identifiers", [])))
    if not expected:
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": "本地公告未提供可比较的 CVE/GHSA 标识符", "evidence_refs": refs}
    # ``report_id`` already carries the GHSA identifier.  The T1 input example
    # legitimately supplies only a CVE in ``vuln_ids``.  Verify every submitted
    # ID against the advisory; do not demand duplication of every advisory ID.
    unknown_ids = [identifier for identifier in ids if identifier not in expected]
    if unknown_ids:
        return {"status": "incorrect", "confidence": 0.93,
                "evidence": (f"vuln_ids={unknown_ids} 未在公告规范标识符 {expected} 中找到；"
                             "SCHEMA.md 要求 vuln_ids 是『本公告的全部已知标识符』"),
                "evidence_refs": refs}
    return {"status": "correct", "confidence": 0.98,
            "evidence": f"vuln_ids 中的规范标识符均由本地公告支持：{ids}", "evidence_refs": refs}


def check_vuln_title(
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """vuln_title 语义判定。

    I4 契约：
      - 必须走 `parse_structured_response`，让 schema/confidence/脱敏/非空 evidence
        校验生效
      - LLM 失败（非法 JSON / 超时 / HTTP 错误）一律 semantic uncertain，
        禁止通过关键词启发式回退为 correct
      - 使用 prompts.VULN_TITLE_PROMPT（带 [PROMPT_VERSION=...] 前缀）走版本化模板

    P0-4：标题事实来自 :class:`AdvisoryAdapter`——原始公告用 ``summary``，
    demo fixture 用 ``title``；evidence ref 指向真实来源字段。
    """
    facts = _facts(advisory)
    expected = facts.get("summary") or ""
    actual = entry.get("vuln_title", "")
    refs: List[Dict[str, str]] = []
    if expected:
        locator = facts.get("summary_locator") or "advisory.json#summary"
        refs.append(_ref_advisory(locator, expected))
    if not expected:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": "公告没有可用的标题事实（summary/title 均缺失），无法做语义比对",
                "evidence_refs": refs}
    prompt = VULN_TITLE_PROMPT.format(expected=expected, actual=actual)
    return _semantic_llm_result(llm, prompt, refs)


def check_category(
    level: str,
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """vuln_category_l1 / l2 语义判定。

    I4 契约：LLM 失败一律 uncertain；走 `parse_structured_response`；
    使用 prompts.vuln_category_prompt() 版本化模板。

    P0-4：分类信号来自 :class:`AdvisoryAdapter`——

      * 原始公告 → ``cwes`` 经**可审计** taxonomy 映射得到唯一类别；
      * demo fixture → ``vuln_category_*_hint``；
      * 映射不唯一/未登记 → 无信号 → ``uncertain``（禁止猜测，禁止从 entry 抄答案）。
    """
    facts = _facts(advisory)
    actual = entry.get(f"vuln_category_{level}", "")
    signal = facts.get("category_signal")
    if not signal:
        reason = facts.get("reason") or "公告没有可无歧义映射的分类信号（cwes/hint 缺失）"
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": f"无法从公告得到 l{level[-1]} 分类事实：{reason}",
                "evidence_refs": []}
    expected = signal.get("label") or ""
    refs: List[Dict[str, str]] = [
        _ref_advisory(signal.get("locator") or "advisory.json#cwes", signal.get("quote") or expected),
    ]
    taxonomy = load_category_taxonomy()
    if level == "l1":
        actual_category = taxonomy.resolve(actual, "")
    else:
        actual_category = taxonomy.resolve("", actual)
    expected_category = None
    if signal.get("taxonomy_id"):
        # CWE 路径：用**同一版本**的 taxonomy 按 identifier 精确取类别对象，
        # 不再按 label 文本二次解析（避免 l1 标签在 l2 别名里查不到）。
        expected_category = next(
            (c for c in taxonomy.categories if c.identifier == signal["taxonomy_id"]), None,
        )
    elif expected:
        expected_category = taxonomy.resolve(expected, "") if level == "l1" else taxonomy.resolve("", expected)
    overlap_note = ""
    if actual_category and expected_category and actual_category.identifier != expected_category.identifier:
        if _categories_overlap(actual_category.identifier, expected_category.identifier):
            # 落在同一重叠簇内：证据不足以确定性反证，交给 LLM（无模型 → uncertain）。
            overlap_note = (
                "（两者属于同一语义重叠簇 "
                "{}↔{}，CWE 粗映射不足以确定性反证，转为语义复核）".format(
                    actual_category.label, expected_category.label,
                )
            )
        else:
            return {"status": "incorrect", "confidence": 0.94,
                    "evidence": (
                        f"分类本体 {taxonomy.version} 将实际值映射为 {actual_category.label}，"
                        f"将公告分类事实映射为 {expected_category.label}，两者不同"
                    ), "evidence_refs": refs}
    prompt = vuln_category_prompt(
        level, expected, actual, taxonomy_version=taxonomy.version,
        actual_category=actual_category.identifier if actual_category else "unresolved",
        expected_category=expected_category.identifier if expected_category else "unresolved",
        allowed_pairs=taxonomy.prompt_allowed_pairs(),
    )
    result = _semantic_llm_result(llm, prompt, refs)
    if overlap_note:
        result["evidence"] = (result.get("evidence") or "") + overlap_note
    return result


def check_trace(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """trace 校验：每节点文件/行号/代码片段是否存在，再让 LLM 判断整体合理性。"""
    trace = entry.get("trace", []) or []
    if not trace:
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": "trace 为空（可能合理，但无法验证）",
                "evidence_refs": []}

    _handle, co = _checkout_entry(entry, tools)
    if not co.ok:
        return {"status": "uncertain", "confidence": 0.35,
                "evidence": f"trace 校验缺少可访问的本地代码源：{co.error}",
                "evidence_refs": []}

    bad_nodes = []
    unavailable_nodes = []
    refs: List[Dict[str, str]] = []
    for idx, node in enumerate(trace):
        reads = tools.read_file_lines(co.data["cwd"], node["file"],
                                      *_line_range(node["line"]))
        if not reads.ok:
            if getattr(reads, "error_code", None) in _SOURCE_CONTRADICTION_CODES:
                bad_nodes.append(f"#{idx} {reads.error or reads.error_code}")
                refs.append(_ref_repo(
                    node["file"], entry["commit"], node["line"],
                    reads.error or reads.error_code,
                ))
            else:
                unavailable_nodes.append(
                    f"#{idx} {reads.error or getattr(reads, 'error_code', None) or 'unknown tool failure'}"
                )
            continue
        actual = _norm_code(reads.data["snippet"])
        expected = _norm_code(node["code"])
        refs.append(_ref_repo(node["file"], entry["commit"], node["line"],
                              reads.data["snippet"]))
        if expected not in actual and actual not in expected:
            bad_nodes.append(f"#{idx} {node['file']}:{node['line']} 代码片段不匹配")

    if bad_nodes:
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": "trace 节点异常：" + "; ".join(bad_nodes[:3]),
                "evidence_refs": refs}
    if unavailable_nodes:
        return {
            "status": "uncertain",
            "confidence": 0.30,
            "evidence": "trace 节点源码证据不可用：" + "; ".join(unavailable_nodes[:3]),
            "evidence_refs": refs,
        }

    # 节点级都对，再让 LLM 判断"整体合理性"
    prompt = TRACE_OVERALL_PROMPT.format(
        entry_id=entry.get("entry_id", ""),
        node_count=len(trace),
        trace_summary=_trace_summary_for_prompt(trace),
    )
    return _semantic_llm_result(llm, prompt, refs)


# ============================================================
# Semantic bundle（P1-A）：title/L1/L2/trace 合并为一次 LLM 调用
# ============================================================

#: bundle 覆盖的语义字段名
BUNDLE_FIELDS = ("vuln_title", "vuln_category_l1", "vuln_category_l2", "trace")


def _bundle_deterministic_title(
    entry: Dict[str, Any], facts: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """title 确定性前置检查。返回 (result_if_decided, llm_context_if_needed)。"""
    expected = facts.get("summary") or ""
    actual = entry.get("vuln_title", "")
    refs: List[Dict[str, str]] = []
    if expected:
        locator = facts.get("summary_locator") or "advisory.json#summary"
        refs.append(_ref_advisory(locator, expected))
    if not expected:
        return {
            "status": "uncertain", "confidence": 0.50,
            "evidence": "公告没有可用的标题事实（summary/title 均缺失），无法做语义比对",
            "evidence_refs": refs,
        }, None
    return None, {
        "field": "vuln_title",
        "expected": expected,
        "actual": actual,
        "refs": refs,
    }


def _bundle_deterministic_category(
    level: str, entry: Dict[str, Any], facts: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """category L1/L2 确定性前置检查。"""
    actual = entry.get(f"vuln_category_{level}", "")
    signal = facts.get("category_signal")
    if not signal:
        reason = facts.get("reason") or "公告没有可无歧义映射的分类信号（cwes/hint 缺失）"
        return {
            "status": "uncertain", "confidence": 0.50,
            "evidence": f"无法从公告得到 l{level[-1]} 分类事实：{reason}",
            "evidence_refs": [],
        }, None
    expected = signal.get("label") or ""
    refs: List[Dict[str, str]] = [
        _ref_advisory(signal.get("locator") or "advisory.json#cwes", signal.get("quote") or expected),
    ]
    taxonomy = load_category_taxonomy()
    if level == "l1":
        actual_category = taxonomy.resolve(actual, "")
    else:
        actual_category = taxonomy.resolve("", actual)
    expected_category = None
    if signal.get("taxonomy_id"):
        expected_category = next(
            (c for c in taxonomy.categories if c.identifier == signal["taxonomy_id"]), None,
        )
    elif expected:
        expected_category = taxonomy.resolve(expected, "") if level == "l1" else taxonomy.resolve("", expected)
    overlap_note = ""
    if actual_category and expected_category and actual_category.identifier != expected_category.identifier:
        if _categories_overlap(actual_category.identifier, expected_category.identifier):
            overlap_note = (
                "（两者属于同一语义重叠簇 "
                f"{actual_category.label}↔{expected_category.label}，CWE 粗映射不足以确定性反证，转为语义复核）"
            )
        else:
            return {
                "status": "incorrect", "confidence": 0.94,
                "evidence": (
                    f"分类本体 {taxonomy.version} 将实际值映射为 {actual_category.label}，"
                    f"将公告分类事实映射为 {expected_category.label}，两者不同"
                ),
                "evidence_refs": refs,
            }, None
    return None, {
        "field": f"vuln_category_{level}",
        "expected": expected,
        "actual": actual,
        "taxonomy_version": taxonomy.version,
        "actual_category": actual_category.identifier if actual_category else "unresolved",
        "expected_category": expected_category.identifier if expected_category else "unresolved",
        "allowed_pairs": taxonomy.prompt_allowed_pairs(),
        "overlap_note": overlap_note,
        "refs": refs,
    }


def _bundle_deterministic_trace(
    entry: Dict[str, Any], tools: Any,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """trace 节点级确定性检查。"""
    trace = entry.get("trace", []) or []
    if not trace:
        return {
            "status": "uncertain", "confidence": 0.40,
            "evidence": "trace 为空（可能合理，但无法验证）",
            "evidence_refs": [],
        }, None
    _handle, co = _checkout_entry(entry, tools)
    if not co.ok:
        return {
            "status": "uncertain", "confidence": 0.35,
            "evidence": f"trace 校验缺少可访问的本地代码源：{co.error}",
            "evidence_refs": [],
        }, None
    bad_nodes = []
    unavailable_nodes = []
    refs: List[Dict[str, str]] = []
    for idx, node in enumerate(trace):
        reads = tools.read_file_lines(co.data["cwd"], node["file"], *_line_range(node["line"]))
        if not reads.ok:
            if getattr(reads, "error_code", None) in _SOURCE_CONTRADICTION_CODES:
                bad_nodes.append(f"#{idx} {reads.error or reads.error_code}")
                refs.append(_ref_repo(node["file"], entry["commit"], node["line"], reads.error or reads.error_code))
            else:
                unavailable_nodes.append(f"#{idx} {reads.error or getattr(reads, 'error_code', None) or 'unknown tool failure'}")
            continue
        actual = _norm_code(reads.data["snippet"])
        expected = _norm_code(node["code"])
        refs.append(_ref_repo(node["file"], entry["commit"], node["line"], reads.data["snippet"]))
        if expected not in actual and actual not in expected:
            bad_nodes.append(f"#{idx} {node['file']}:{node['line']} 代码片段不匹配")
    if bad_nodes:
        return {
            "status": "incorrect", "confidence": 0.85,
            "evidence": "trace 节点异常：" + "; ".join(bad_nodes[:3]),
            "evidence_refs": refs,
        }, None
    if unavailable_nodes:
        return {
            "status": "uncertain", "confidence": 0.30,
            "evidence": "trace 节点源码证据不可用：" + "; ".join(unavailable_nodes[:3]),
            "evidence_refs": refs,
        }, None
    return None, {
        "field": "trace",
        "entry_id": entry.get("entry_id", ""),
        "node_count": len(trace),
        "trace_summary": _trace_summary_for_prompt(trace),
        "refs": refs,
    }


def _build_bundle_context(contexts: List[Dict[str, Any]]) -> str:
    """把各字段的 LLM 上下文拼成 bundle prompt 用的文本。"""
    lines = []
    for ctx in contexts:
        field = ctx["field"]
        if field == "vuln_title":
            lines.append(f"[vuln_title]\n  advisory title: {ctx['expected']}\n  actual: {ctx['actual']}")
        elif field.startswith("vuln_category_"):
            level = field.split("_")[-1]
            lines.append(
                f"[{field}]\n"
                f"  advisory_hint_{level[-1]}: {ctx['expected']}\n"
                f"  actual: {ctx['actual']}\n"
                f"  taxonomy_version: {ctx['taxonomy_version']}\n"
                f"  taxonomy_actual_category: {ctx['actual_category']}\n"
                f"  taxonomy_expected_category: {ctx['expected_category']}\n"
                f"  taxonomy_allowed_l1_l2_pairs: {ctx['allowed_pairs']}"
            )
            if ctx.get("overlap_note"):
                lines.append(f"  note: {ctx['overlap_note']}")
        elif field == "trace":
            lines.append(
                f"[trace]\n"
                f"  entry_id: {ctx['entry_id']}\n"
                f"  trace 节点数: {ctx['node_count']}\n"
                f"  <trace_data>\n{ctx['trace_summary']}\n</trace_data>"
            )
    return "\n".join(lines)


def check_semantic_bundle(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    facts: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """将 title/L1/L2/trace 的语义判断合并为一次 LLM 调用。

    每个字段先做确定性前置检查；无法确定性判定的字段进入 bundle。
    bundle 失败时，只有 bundle 覆盖的字段降为 uncertain；已确认的确定性
    字段结果保留。

    ``facts`` 必须是已经过 AdvisoryAdapter 适配的公告事实视图（与
    check_all_fields 中传入各字段检查器的 facts 同源）。
    """
    if facts is None:
        facts = _ADAPTER.invalid("advisory.json", "no advisory")
    results: Dict[str, Dict[str, Any]] = {}
    llm_contexts: List[Dict[str, Any]] = []

    # title
    decided, ctx = _bundle_deterministic_title(entry, facts)
    if decided is not None:
        results["vuln_title"] = decided
    elif ctx is not None:
        llm_contexts.append(ctx)

    # L1 / L2
    for level in ("l1", "l2"):
        decided, ctx = _bundle_deterministic_category(level, entry, facts)
        if decided is not None:
            results[f"vuln_category_{level}"] = decided
        elif ctx is not None:
            llm_contexts.append(ctx)

    # trace
    decided, ctx = _bundle_deterministic_trace(entry, tools)
    if decided is not None:
        results["trace"] = decided
    elif ctx is not None:
        llm_contexts.append(ctx)

    # 没有字段需要 LLM → 直接返回
    if not llm_contexts:
        return results

    # 构造 bundle prompt 并调用一次 LLM
    prompt = SEMANTIC_BUNDLE_PROMPT.format(bundle_context=_build_bundle_context(llm_contexts))
    try:
        raw = llm.chat([LLMMessage("user", prompt)])
        parsed = parse_json_object(raw)
    except Exception:
        parsed = {}

    # 解析每个需要 LLM 的字段结果
    for ctx in llm_contexts:
        field = ctx["field"]
        field_result = parsed.get(field) if isinstance(parsed, dict) else None
        refs = ctx.get("refs", [])
        if isinstance(field_result, dict) and field_result.get("status") in ("correct", "incorrect", "uncertain"):
            try:
                conf = max(0.0, min(1.0, float(field_result.get("confidence", 0.0))))
            except (TypeError, ValueError):
                conf = 0.0
            evidence = redact_text(str(field_result.get("evidence", "") or "").strip())
            if not evidence:
                evidence = "LLM gave empty evidence; treating as uncertain."
                if field_result.get("status") == "correct":
                    field_result = dict(field_result)
                    field_result["status"] = "uncertain"
            # 合并 LLM 返回的 refs 与确定性 refs
            llm_refs = field_result.get("evidence_refs") or []
            if isinstance(llm_refs, list):
                all_refs = _merge_refs(llm_refs, refs)
            else:
                all_refs = refs
            results[field] = {
                "status": field_result["status"],
                "confidence": conf,
                "evidence": evidence,
                "evidence_refs": all_refs,
            }
        else:
            # bundle 解析失败 → 该字段安全降级为 uncertain
            results[field] = {
                "status": "uncertain",
                "confidence": 0.20,
                "evidence": f"semantic bundle failed or missing field '{field}'; cannot perform semantic judgement.",
                "evidence_refs": refs,
            }
    return results


# ============================================================
# 汇总：跑一条 entry 的全部字段
# ============================================================
def check_all_fields(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    *,
    advisory_provider: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """返回 fields dict + summary。

    ``advisory_provider``：可选的 ``entry -> advisory facts`` 注入点。T1Data 路径
    由 :class:`T1PackageContext` 提供（含 ``advisories/`` 边界约束与来源引用）；
    缺省时仍使用 ``tools.read_advisory`` + 本地适配层，保持 demo 行为不变。

    无论是否注入 provider，都**始终**调用 ``tools.read_advisory``：这保证
    ``tool_trace`` 里存在真实的 advisory 类工具调用（Standard §2.1 第 4 条要求
    一次完整核验至少三类工具），而不是靠注入数据绕过工具层。
    """
    advisory_result = tools.read_advisory(entry["report_id"])
    facts = None
    if advisory_provider is not None:
        try:
            candidate = advisory_provider(entry)
        except Exception:
            candidate = None
        if isinstance(candidate, dict) and candidate.get("valid"):
            facts = candidate
    if facts is None:
        if advisory_result.ok:
            facts = _ADAPTER.adapt(advisory_result.data, locator_prefix="advisory.json")
        else:
            facts = _ADAPTER.invalid(
                "advisory.json",
                advisory_result.error or "advisory unavailable",
                code=advisory_result.error_code or "advisory_invalid",
            )

    fields: Dict[str, Dict[str, Any]] = {}
    fields["entry_point"] = check_entry_point(entry, tools, llm)
    fields["critical_operation"] = check_critical_operation(entry, tools, llm)
    # check_commit 接收 advisory facts，以启用公告版本范围 + 本地 git 证据判定。
    fields["commit"] = check_commit(entry, tools, advisory=facts)
    fields["vuln_ids"] = check_vuln_ids(entry, facts)
    # P1-A：title/L1/L2/trace 合并为一次 semantic-bundle LLM 调用。
    # 确定性字段（entry_point/critical_operation/commit/vuln_ids）不受 bundle 影响。
    bundle_results = check_semantic_bundle(entry, tools, llm, facts=facts)
    for field_name in BUNDLE_FIELDS:
        fields[field_name] = bundle_results.get(field_name, {
            "status": "uncertain", "confidence": 0.20,
            "evidence": f"semantic bundle did not produce result for {field_name}",
            "evidence_refs": [],
        })

    # 整体 verdict：有一个 incorrect -> incorrect；全 correct -> correct；否则 uncertain
    statuses = [f["status"] for f in fields.values()]
    if "incorrect" in statuses:
        verdict = "incorrect"
    elif all(s == "correct" for s in statuses):
        verdict = "correct"
    else:
        verdict = "uncertain"

    incorrect_fields = [k for k, v in fields.items() if v["status"] == "incorrect"]
    summary = "整体判定为 {verdict}".format(verdict=verdict)
    if incorrect_fields:
        summary += f" — 异常字段: {', '.join(incorrect_fields)}"

    return {"verdict": verdict, "fields": fields, "summary": summary}
