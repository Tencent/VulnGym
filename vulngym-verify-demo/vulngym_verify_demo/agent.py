# -*- coding: utf-8 -*-
"""Agent 主循环（per entry）：

1. 规划阶段：列举本 entry 要核验的字段，列出将调用的工具
2. 工具调用阶段：执行 tools / 调 LLM 完成字段判定，并真实记录 tool_trace
3. 反思阶段：让 LLM 对全部字段判定做一次 self-check，必要时修正

返回结构对齐 VulnGym 考题要求 + I1 report_schema.json：
    {
      "report_id": ...,
      "entry_id": ...,
      "verdict":  correct | incorrect | uncertain,
      "fields": { field: {status, confidence, evidence, evidence_refs} },
      "summary": "...",
      "self_check": {status, agree, comment, checked_fields},
      "plan": {version, entry_id, report_id, tools_planned, fields_planned},
      "tool_trace": [{seq, tool, input, ok, error, evidence_refs}, ...]
    }

I5 契约（来自 I5_START_HANDBOOK §3）：
  * plan.version 必须 "1"
  * 正常完整路径覆盖 advisory / repository / git 三类；降级路径只记录实际调用
  * self_check 四键：status/agree/comment/checked_fields；
    status=skipped|failed 时 agree 强制 false
  * tool_trace 失败也记录（ok=false + error），不抛未处理异常
  * 不修改 field_checkers / llm_client / prompts / tools / schema / report_schema
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .field_checkers import check_all_fields
from .llm_client import BaseLLMClient, LLMMessage, ProvenancedResult, parse_json_object, redact_text
from .prompts import SELF_CHECK_PROMPT
from .tools import TOOL_ERROR_CODES, ToolResult, VulnGymTools


# ============================================================
# Constants
# ============================================================

#: I1 schema 定义的 8 个必填字段名（与 ALL_EIGHT_FIELDS 同源，但 agent.py 不 import
#: schema.py 以避免循环导入；保持本地常量便于测试 import）
EIGHT_FIELDS: List[str] = [
    "entry_point",
    "critical_operation",
    "commit",
    "vuln_ids",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "trace",
]

#: 置信度阈值：status 为 correct/incorrect 但 confidence 低于此值时，
#: 自动降级为 uncertain，避免 LLM 在低置信时硬下结论。
CONFIDENCE_FLOOR = 0.75

#: 工具所属类别（用于构建 tool_trace 时分类审计）
_TOOL_CATEGORY = {
    "read_advisory": "advisory",
    "checkout": "git",
    "read_file_lines": "repository",
    "grep_code": "repository",
    "git_log": "git",
    "git_tags_at_commit": "git",
}

_TOOL_EVIDENCE_SOURCES = {
    "read_advisory": {"advisory"},
    "checkout": {"repository"},
    "read_file_lines": {"repository"},
    "grep_code": {"repository"},
    "git_log": {"git"},
    "git_tags_at_commit": {"git"},
}


#: 兜底错误码：仅用于第三方/桩实现返回了不符合契约的 ToolResult 时，保证
#: ``tool_trace`` 仍然是 schema-valid 的。真实工具分支在 tools.py 中显式分类。
_FALLBACK_ERROR_CODE = "tool_internal_error"


def _safe_error_code(result: ToolResult) -> Optional[str]:
    """返回合法错误码；失败调用绝不允许写出 ``None``（P0-3 根因）。"""
    code = getattr(result, "error_code", None)
    if code in TOOL_ERROR_CODES:
        return code
    if getattr(result, "ok", False):
        return None
    return _FALLBACK_ERROR_CODE


# ============================================================
# Internal helpers
# ============================================================


def _short_commit(commit: str, limit: int = 12) -> str:
    """截断 commit 用于 trace.input（脱敏 + 防长 hex 触发 redact）。"""
    if not commit:
        return ""
    if len(commit) <= limit:
        return commit
    return commit[:limit] + "…"


# ============================================================
# plan_for_entry
# ============================================================


def plan_for_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """返回规划结果：列出要调用的工具和要核验的字段。

    I5 契约：必须含 version="1" + tools_planned + fields_planned 三键；
    tools_planned 至少覆盖 advisory/repository/git 三类。
    """
    return {
        "version": "1",
        "entry_id": entry.get("entry_id"),
        "report_id": entry.get("report_id"),
        "tools_planned": [
            "read_advisory",      # advisory
            "checkout",           # git
            "read_file_lines",    # repository
            "grep_code",          # repository
            "git_log",            # git
            "git_tags_at_commit", # git: commit 到公告版本范围的精确映射
        ],
        "fields_planned": list(EIGHT_FIELDS),
    }


# ============================================================
# tool_trace：记录真实调用
# ============================================================


def _record(seq_ref: List[int], tool: str, input_payload: Dict[str, Any], result: ToolResult) -> Dict[str, Any]:
    """记录一次工具调用并递增 seq。

    P0-3：失败调用必须写出合法的 ``error`` + ``error_code``；``ok=True`` 时两者
    必须为空。这里做最后一道归一化，确保任何来源的 ToolResult 都不会污染整条
    报告的 ``tool_trace``。
    """
    seq_ref[0] += 1
    ok = bool(getattr(result, "ok", False))
    raw_error = getattr(result, "error", None)
    if ok:
        return {
            "seq": seq_ref[0],
            "tool": tool,
            "input": input_payload,
            "ok": True,
            "error": None,
            "error_code": None,
            "evidence_refs": [],
        }
    message = redact_text(str(raw_error)) if raw_error else f"{tool} failed without a diagnostic message"
    return {
        "seq": seq_ref[0],
        "tool": tool,
        "input": input_payload,
        "ok": False,
        "error": message,
        "error_code": _safe_error_code(result),
        "evidence_refs": [],
    }


class _RecordingTools:
    """Transparent tools proxy that records calls made by field checkers.

    The proxy deliberately does not execute an extra "audit" call.  This makes
    ``tool_trace`` a replayable record of the evidence path actually used to
    derive field verdicts, including failures.

    P1-A：per-entry 只读 cache。对同一 (repo, commit, file, range) 的重复读取，
    底层工具只调用一次；cache hit 不伪造 tool_trace。cache 只复用真实工具调用
    的成功结果，不写入目标仓库，不执行目标仓库代码。
    """

    def __init__(self, tools: VulnGymTools) -> None:
        self._tools = tools
        self.trace: List[Dict[str, Any]] = []
        self._seq_ref = [0]
        #: per-entry 只读 cache：key 为 (tool, normalized_args)，value 为 ToolResult。
        #: 只缓存成功（ok=True）的结果；失败不缓存以便重试。
        self._cache: Dict[str, ToolResult] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tools, name)

    def _cache_key(self, tool: str, *args: Any, **kwargs: Any) -> Optional[str]:
        """构造 cache key。返回 None 表示该工具不缓存。"""
        if tool == "checkout":
            # args: (project, commit)
            return f"checkout:{args[0]}:{args[1]}"
        if tool == "read_file_lines":
            # args: (cwd, file, start, end) — cwd 已含 repo/commit 信息
            return f"read_file_lines:{args[0]}:{args[1]}:{args[2]}:{args[3]}"
        if tool == "git_log":
            # args: (project, commit), kwargs: limit
            limit = kwargs.get("limit", 5)
            return f"git_log:{args[0]}:{args[1]}:{limit}"
        if tool == "git_tags_at_commit":
            # args: (project, commit)
            return f"git_tags_at_commit:{args[0]}:{args[1]}"
        # read_advisory / grep_code 不缓存
        return None

    def _invoke(self, tool: str, input_payload: Dict[str, Any], *args: Any, **kwargs: Any) -> ToolResult:
        # 检查 per-entry cache（只缓存成功结果）
        key = self._cache_key(tool, *args, **kwargs)
        if key is not None and key in self._cache:
            # cache hit：直接返回缓存结果，不记录 tool_trace
            return self._cache[key]

        try:
            result = getattr(self._tools, tool)(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - defensive adapter boundary
            result = ToolResult(
                tool, False, None, f"{tool} raised: {type(exc).__name__}",
                "tool_internal_error",
            )
        self.trace.append(_record(self._seq_ref, tool, input_payload, result))
        # 只缓存成功结果；失败不缓存（可能是瞬时错误，允许后续重试）
        if key is not None and getattr(result, "ok", False):
            self._cache[key] = result
        return result

    @staticmethod
    def _text(value: Any) -> str:
        return redact_text(str(value))

    def read_advisory(self, report_id: str) -> ToolResult:
        return self._invoke("read_advisory", {"report_id": self._text(report_id)}, report_id)

    def checkout(self, project: str, commit: str) -> ToolResult:
        return self._invoke(
            "checkout", {"project": self._text(project), "commit": _short_commit(commit)}, project, commit,
        )

    def read_file_lines(self, cwd: str, file: str, start: int, end: int) -> ToolResult:
        return self._invoke(
            "read_file_lines", {"file": self._text(file), "start": start, "end": end},
            cwd, file, start, end,
        )

    def grep_code(self, cwd: str, file: str, pattern: str) -> ToolResult:
        return self._invoke("grep_code", {"file": self._text(file)}, cwd, file, pattern)

    def git_log(self, project: str, commit: str, limit: int = 5) -> ToolResult:
        return self._invoke(
            "git_log", {"project": self._text(project), "commit": _short_commit(commit), "limit": limit},
            project, commit, limit=limit,
        )

    def git_tags_at_commit(self, project: str, commit: str) -> ToolResult:
        return self._invoke(
            "git_tags_at_commit", {"project": self._text(project), "commit": _short_commit(commit)},
            project, commit,
        )


# ============================================================
# trace.evidence_refs 回填
# ============================================================


def _link_trace_to_fields(
    trace: List[Dict[str, Any]],
    fields_result: Dict[str, Dict[str, Any]],
) -> None:
    """Link a real tool call only to fields citing its evidence source."""
    if not trace or not fields_result:
        return

    for call in trace:
        sources = _TOOL_EVIDENCE_SOURCES.get(call.get("tool", ""), set())
        refs: List[str] = []
        for field_name, field_result in fields_result.items():
            evidence_refs = field_result.get("evidence_refs", [])
            if any(isinstance(ref, dict) and ref.get("source") in sources for ref in evidence_refs):
                refs.append("fields.{}.evidence".format(field_name))
        call["evidence_refs"] = refs


# ============================================================
# self-check
# ============================================================


def self_check(
    entry: Dict[str, Any],
    fields_result: Dict[str, Dict[str, Any]],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """反思层：让 LLM 反向复核本条 entry 的全部字段判定。

    I5 契约（对齐 I1 schema SelfCheck）：
      - 必须含 status/agree/comment/checked_fields 四键
      - status ∈ {completed, skipped, failed}
      - status ∈ {skipped, failed} → agree 必须 false
      - comment 必须非空（I1 schema 隐式约束：comment 是 string）
      - completed 路径下 agree 由 LLM 决定（不得人为强制 true）

    P2 改善：使用 chat_with_provenance 区分 primary 真实返回与 Safe fallback。
    fallback / 超时 / 非法 JSON 时固定输出 skipped + agree=false，不得伪装成
    completed。
    """
    checked_fields = list(fields_result.keys())
    prompt = SELF_CHECK_PROMPT.format(
        fields_dump=(
            f"entry_id: {entry.get('entry_id')}\n"
            f"fields: {json.dumps(fields_result, ensure_ascii=False)}"
        ),
    )
    try:
        provenanced = llm.chat_with_provenance([LLMMessage("user", prompt)])
    except Exception as exc:
        return {
            "status": "skipped",
            "agree": False,
            "comment": f"self-check skipped: {redact_text(str(exc))[:120]}",
            "checked_fields": checked_fields,
        }

    # Safe fallback：无论返回什么 JSON，都视为 skipped + agree=false。
    if provenanced.used_fallback:
        return {
            "status": "skipped",
            "agree": False,
            "comment": "self-check skipped: LLM unavailable; used safe fallback (no real model judgement).",
            "checked_fields": checked_fields,
        }

    try:
        parsed = parse_json_object(provenanced.content)
    except Exception as exc:
        return {
            "status": "skipped",
            "agree": False,
            "comment": f"self-check skipped: unparseable response: {redact_text(str(exc))[:120]}",
            "checked_fields": checked_fields,
        }

    agree_raw = parsed.get("agree", False)
    if not isinstance(agree_raw, bool):
        return {
            "status": "skipped",
            "agree": False,
            "comment": f"self-check skipped: agree is not bool: {type(agree_raw).__name__}",
            "checked_fields": checked_fields,
        }
    comment_raw = parsed.get("comment", "")
    if not isinstance(comment_raw, str):
        comment_raw = str(comment_raw)
    return {
        "status": "completed",
        "agree": agree_raw,
        "comment": redact_text(comment_raw.strip()) or "self-check completed",
        "checked_fields": checked_fields,
    }


# ============================================================
# 受限复核：self-check disagree 时仅复核 title/L1/L2/trace
# ============================================================

#: 复核只允许修改的语义字段（确定性字段不可被复核改写）
REVISABLE_FIELDS = ("vuln_title", "vuln_category_l1", "vuln_category_l2", "trace")

REVISIT_PROMPT_TEMPLATE = (
    "[PROMPT_VERSION=self_check_revisit@1]\n"
    "self-check 不同意初判。请仅对以下四个语义字段做一次有界复核，"
    "基于已有证据判断是否需要修正 status / confidence / evidence。\n"
    "不得修改 entry_point、critical_operation、vuln_ids、commit 的确定性结论。\n"
    "只使用下方提供的字段证据，不得自行补造引用。\n"
    "entry_id: {entry_id}\n"
    "{fields_context}\n"
    "仅返回一个 JSON 对象，键为四个字段名，每个值为 {{status, confidence, evidence}}；"
    "若维持原判则返回原 status 和 confidence。不要 Markdown 或额外文字。"
)


def _build_revisit_context(fields_result: Dict[str, Dict[str, Any]]) -> str:
    """构造复核用的字段上下文（只含可复核字段的已有证据）。"""
    lines = []
    for name in REVISABLE_FIELDS:
        field = fields_result.get(name)
        if not isinstance(field, dict):
            continue
        lines.append(
            f"[{name}]\n"
            f"  status: {field.get('status')}\n"
            f"  confidence: {field.get('confidence')}\n"
            f"  evidence: {field.get('evidence', '')[:500]}\n"
            f"  evidence_refs: {json.dumps(field.get('evidence_refs', [])[:3], ensure_ascii=False)}"
        )
    return "\n".join(lines)


def _revisit_semantic_fields(
    entry: Dict[str, Any],
    fields_result: Dict[str, Dict[str, Any]],
    llm: BaseLLMClient,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """对 title/L1/L2/trace 做一次受限复核。

    返回 (updated_fields, revisit_record)。revisit_record 包含复核前后的 status
    差异和原因。复核 LLM 调用失败 / fallback / 非法 JSON 时保留原初判。
    """
    original = {name: dict(fields_result.get(name, {})) for name in REVISABLE_FIELDS}
    prompt = REVISIT_PROMPT_TEMPLATE.format(
        entry_id=entry.get("entry_id", ""),
        fields_context=_build_revisit_context(fields_result),
    )
    try:
        provenanced = llm.chat_with_provenance([LLMMessage("user", prompt)])
    except Exception as exc:
        return fields_result, {
            "status": "skipped",
            "reason": f"revisit LLM call raised: {type(exc).__name__}",
            "changes": [],
        }

    if provenanced.used_fallback:
        return fields_result, {
            "status": "skipped",
            "reason": "revisit used safe fallback; original judgements preserved",
            "changes": [],
        }

    try:
        parsed = parse_json_object(provenanced.content)
    except Exception as exc:
        return fields_result, {
            "status": "skipped",
            "reason": f"revisit unparseable response: {type(exc).__name__}",
            "changes": [],
        }

    changes = []
    updated = dict(fields_result)
    for name in REVISABLE_FIELDS:
        revision = parsed.get(name)
        if not isinstance(revision, dict):
            continue
        new_status = revision.get("status")
        if new_status not in ("correct", "incorrect", "uncertain"):
            continue
        orig = original.get(name, {})
        old_status = orig.get("status")
        old_conf = orig.get("confidence")
        if new_status != old_status or revision.get("confidence") != old_conf:
            changes.append({
                "field": name,
                "old_status": old_status,
                "new_status": new_status,
                "old_confidence": old_conf,
                "new_confidence": revision.get("confidence"),
            })
        # 只更新 status/confidence/evidence；保留原 evidence_refs（不得补造引用）
        new_field = dict(orig)
        new_field["status"] = new_status
        if "confidence" in revision:
            try:
                new_field["confidence"] = max(0.0, min(1.0, float(revision["confidence"])))
            except (TypeError, ValueError):
                pass
        rev_evidence = revision.get("evidence")
        if isinstance(rev_evidence, str) and rev_evidence.strip():
            new_field["evidence"] = redact_text(rev_evidence.strip())[:1000]
        updated[name] = new_field

    if not changes:
        return updated, {
            "status": "completed",
            "reason": "revisit completed; no status changes (original judgements maintained)",
            "changes": [],
        }
    return updated, {
        "status": "completed",
        "reason": "revisit completed; status changes applied",
        "changes": changes,
    }


# ============================================================
# verify_entry / verify_entries
# ============================================================


def verify_entry(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    verbose: bool = False,
    advisory_provider: Optional[Any] = None,
) -> Dict[str, Any]:
    """跑完一条 entry，返回报告 dict。

    I5 契约：
      - 返回 dict 必含 report_id / entry_id / verdict / fields / summary /
        self_check / plan / tool_trace（与 I1 schema 对齐）
      - tool_trace 至少含 advisory / repository / git 三类工具
      - self_check 必含 status/agree/comment/checked_fields 四键
      - plan.version == "1"
      - 坏 commit / 缺 report_id 等异常输入也生成报告，不抛未处理异常

    ``advisory_provider``：可选的 ``entry -> advisory facts`` 注入点（T1Data 路径），
    缺省时行为与 demo 完全一致。
    """
    plan = plan_for_entry(entry)
    if verbose:
        print(f"  [plan] {plan}")

    # 第一阶段：字段检查器经由 recording proxy 调用工具。此时 trace 只会
    # 记录实际执行的工具调用，绝不为凑类别在检查结束后重新调用工具。
    recording_tools = _RecordingTools(tools)
    try:
        if advisory_provider is not None:
            fields_result_bundle = check_all_fields(
                entry, recording_tools, llm, advisory_provider=advisory_provider,
            )
        else:
            fields_result_bundle = check_all_fields(entry, recording_tools, llm)
    except Exception as exc:
        # I5 契约：坏输入不能阻塞主流程；已发生的调用仍保留审计记录。
        return _fallback_error_report(
            entry=entry,
            plan=plan,
            phase="check_all_fields",
            exc=exc,
            trace=recording_tools.trace,
        )

    fields_result = fields_result_bundle["fields"]

    # 第二阶段：回填真实调用与字段证据的精确关联。
    trace = recording_tools.trace
    _link_trace_to_fields(trace, fields_result)

    # 第三阶段：把初判结果交给 self_check 做二次复核
    review = self_check(entry, fields_result, llm)

    # 第三阶段半：self-check 正常完成且不同意时，对 title/L1/L2/trace 做一次受限复核。
    # 确定性字段（entry_point/critical_operation/vuln_ids/commit）不可被改写。
    revisit_record = None
    if review.get("status") == "completed" and review.get("agree") is False:
        fields_result, revisit_record = _revisit_semantic_fields(entry, fields_result, llm)
        # 复核后重新聚合 verdict（只受字段 status 影响）
        statuses = [f.get("status") for f in fields_result.values()]
        if "incorrect" in statuses:
            new_verdict = "incorrect"
        elif all(s == "correct" for s in statuses):
            new_verdict = "correct"
        else:
            new_verdict = "uncertain"
        fields_result_bundle = dict(fields_result_bundle)
        fields_result_bundle["verdict"] = new_verdict
        if revisit_record and revisit_record.get("changes"):
            changed = ", ".join(
                f"{c['field']}: {c['old_status']}->{c['new_status']}"
                for c in revisit_record["changes"]
            )
            fields_result_bundle["summary"] = (
                fields_result_bundle.get("summary", "") +
                f" [self-check revisit applied: {changed}]"
            )

    # 第三阶段¾：置信度阈值降级——低置信的 correct/incorrect 自动降为 uncertain
    degraded_fields = _apply_confidence_floor(fields_result)
    if degraded_fields:
        # 降级后重新聚合 verdict
        statuses = [f.get("status") for f in fields_result.values()]
        if "incorrect" in statuses:
            new_verdict = "incorrect"
        elif all(s == "correct" for s in statuses):
            new_verdict = "correct"
        else:
            new_verdict = "uncertain"
        fields_result_bundle = dict(fields_result_bundle)
        fields_result_bundle["verdict"] = new_verdict
        fields_result_bundle["summary"] = (
            fields_result_bundle.get("summary", "") +
            f" [confidence-floor: {', '.join(degraded_fields)} 降级为 uncertain]"
        )

    # 第四阶段：聚合 verdict / fields / summary / self_check / plan / tool_trace
    report = {
        "report_id": entry.get("report_id"),
        "entry_id": entry.get("entry_id"),
        "verdict": fields_result_bundle["verdict"],
        "fields": fields_result,
        "summary": fields_result_bundle["summary"],
        "self_check": review,
        "plan": plan,
        "tool_trace": trace,
    }
    if revisit_record is not None:
        report["self_check_revisit"] = revisit_record
    return report


def _fallback_error_report(
    entry: Dict[str, Any],
    plan: Dict[str, Any],
    phase: str,
    exc: BaseException,
    trace: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """当 check_all_fields 抛异常时构造的标准 uncertain 报告。

    - 8 字段全 uncertain + 解释缺口
    - 仅保留在失败前已经实际发生的工具调用；不能伪造占位调用
    - self_check 走 skipped 路径，agree=false
    """
    fields = {
        name: {
            "status": "uncertain",
            "confidence": 0.0,
            "evidence": (
                f"agent-level fallback: {phase} raised "
                f"{type(exc).__name__}; all 8 fields inherit uncertain."
            ),
            "evidence_refs": [],
        }
        for name in EIGHT_FIELDS
    }

    trace = list(trace or [])
    _link_trace_to_fields(trace, fields)

    return {
        "report_id": entry.get("report_id"),
        "entry_id": entry.get("entry_id"),
        "verdict": "uncertain",
        "fields": fields,
        "summary": f"agent-level fallback: {phase} raised {type(exc).__name__}",
        "self_check": {
            "status": "skipped",
            "agree": False,
            "comment": f"self-check skipped due to agent-level error: {redact_text(str(exc))[:120]}",
            "checked_fields": list(EIGHT_FIELDS),
        },
        "plan": plan,
        "tool_trace": trace,
    }


def _make_empty_fields(evidence: str) -> Dict[str, Dict[str, Any]]:
    """生成 8 个空字段，全部 uncertain。"""
    # 复用 EIGHT_FIELDS 常量，避免硬编码重复
    return {
        name: {
            "status": "uncertain",
            "confidence": 0.0,
            "evidence": evidence,
            "evidence_refs": []
        }
        for name in EIGHT_FIELDS
    }


def _apply_confidence_floor(fields: Dict[str, Dict[str, Any]]) -> List[str]:
    """对低置信度的 correct/incorrect 判定自动降级为 uncertain。

    返回被降级的字段名列表。降级时保留原 evidence 并追加说明，
    confidence 保留原值（反映原始置信度），evidence_refs 不变。
    """
    degraded: List[str] = []
    for name, field in fields.items():
        status = field.get("status")
        conf = field.get("confidence", 0.0)
        if isinstance(conf, str):
            try:
                conf = float(conf)
            except (ValueError, TypeError):
                conf = 0.0
        if status in ("correct", "incorrect") and conf < CONFIDENCE_FLOOR:
            old_status = status
            field["status"] = "uncertain"
            field["evidence"] = (
                f"{field.get('evidence', '')} "
                f"[confidence-floor: 原始判定 {old_status} (conf={conf:.2f}) "
                f"低于阈值 {CONFIDENCE_FLOOR:.2f}，自动降级为 uncertain]"
            ).strip()
            degraded.append(name)
    return degraded


def verify_entries(
    entries: List[Dict[str, Any]],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    verbose: bool = False,
    advisory_provider: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """逐条 entry 跑 verify_entry，汇总成报告列表。

    - 顺序处理（I5 不并发）
    - 任何一条失败不中断后续
    - verbose=True 时打印进度与判定摘要
    - I6：坏 JSON / 缺字段生成 __invalid_input__ 报告
    """
    reports: List[Dict[str, Any]] = []
    for i, entry in enumerate(entries):
        # ---- I6: 检测解析错误 ----
        if entry.get("__parse_error__"):
            line_no = entry.get("__line_no__", i)
            report = {
                "report_id": f"__invalid_input__:{line_no}",
                "entry_id": f"__invalid_input__:{line_no}",
                "verdict": "uncertain",
                "input_error": {
                    "line_no": line_no,
                    "kind": "json_parse_error",
                    "message": entry.get("__error_message__", "unknown")
                },
                "fields": _make_empty_fields("输入行解析失败"),
                "summary": f"输入行 {line_no} JSON 解析失败",
                "self_check": {"status": "skipped", "agree": False, "comment": "输入无效", "checked_fields": []},
                "plan": {},
                "tool_trace": []
            }
            reports.append(report)
            if verbose:
                print(f"  [skip] line {line_no}: parse error")
            continue
        
        # ---- I6: 检测缺字段 ----
        # 使用完整的 14 个必填字段（与 schema.py ENTRY_REQUIRED_FIELDS 对齐）
        required = [
            "entry_id", "report_id", "source_link", "vuln_ids", "origin",
            "project", "repo_url", "commit", "vuln_title", "vuln_category_l1",
            "vuln_category_l2", "entry_point", "critical_operation", "trace"
        ]
        missing = [k for k in required if k not in entry]
        if missing:
            entry_id = entry.get("entry_id", f"__invalid_input__:{i+1}")
            report = {
                "report_id": entry.get("report_id", f"__invalid_input__:{i+1}"),
                "entry_id": entry_id,
                "verdict": "uncertain",
                "input_error": {
                    "line_no": i + 1,
                    "kind": "missing_required_field",
                    "message": f"缺少必填字段: {missing}"
                },
                "fields": _make_empty_fields(f"缺少必填字段: {missing}"),
                "summary": f"缺少必填字段: {', '.join(missing)}",
                "self_check": {"status": "skipped", "agree": False, "comment": "输入不完整", "checked_fields": []},
                "plan": {},
                "tool_trace": []
            }
            reports.append(report)
            if verbose:
                print(f"  [skip] {entry_id}: missing fields {missing}")
            continue
        
        # ---- 原有正常处理逻辑 ----
        if verbose:
            print(f"\n=== entry {i + 1}/{len(entries)}: {entry.get('entry_id')} / {entry.get('report_id')} ===")
        try:
            rep = verify_entry(entry, tools, llm, verbose=verbose, advisory_provider=advisory_provider)
        except Exception as exc:
            # 兜底：即使 verify_entry 自己抛了也不中断主流程
            rep = _fallback_error_report(
                entry=entry or {},
                plan=plan_for_entry(entry or {}),
                phase="verify_entry",
                exc=exc,
            )
        if verbose:
            print(f"  [verdict] {rep['verdict']}")
            print(f"  [summary] {rep['summary']}")
            for k, v in rep["fields"].items():
                v.setdefault("confidence", 0.50)
                v.setdefault("evidence", "")
                conf = v["confidence"]
                if isinstance(conf, str):
                    try:
                        conf = float(conf)
                    except (ValueError, TypeError):
                        conf = 0.50
                print(f"    - {k:22s} {v['status']:10s} conf={conf:.2f}  {v['evidence'][:100]}")
        print(f"  [self-check] {rep['self_check']}")
        reports.append(rep)
    return reports


# ============================================================
# Internal accessor：允许 tests / 上层扩展
# ============================================================


def get_eight_fields() -> List[str]:
    """返回 I1 schema 定义的 8 字段名列表（供测试/调用方复用）。"""
    return list(EIGHT_FIELDS)


def get_tool_category(tool_name: str) -> Optional[str]:
    """返回工具所属的 source 类别（advisory/repository/git）。"""
    return _TOOL_CATEGORY.get(tool_name)
