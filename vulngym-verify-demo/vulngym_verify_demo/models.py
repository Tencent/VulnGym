# -*- coding: utf-8 -*-
"""VulnGym VerificationReport 数据模型（I1 范围）。

本模块为 §4.1 冻结的 VerificationReport 契约提供 dataclass 视图，并保留
向后兼容的导出名（§4.2 Python 边界）。

向后兼容导出：
- 从 ``tools`` 重导出 ``VulnGymTools``、``ToolResult``、``normalize_project_from_repo``
- 从 ``llm_client`` 重导出 ``BaseLLMClient``、``ResilientLLMClient`` 等
- 从 ``field_checkers`` 重导出 ``check_all_fields``
- 从 ``agent`` 重导出 ``verify_entry``、``verify_entries``
- 从 ``eval`` 重导出 ``evaluate``、``load_gold``、``format_metrics``、``ALL_FIELDS``

新增契约 dataclass：
- ``EvidenceRef``: ``{source, locator, quote}``
- ``FieldResult``: ``{status, confidence, evidence, evidence_refs}``
- ``ToolCall``: ``{seq, tool, input?, ok, error?, evidence_refs?}``
- ``SelfCheck``: ``{status, agree, comment, checked_fields}``
- ``Plan``: ``{version, entry_id?, report_id?, tools_planned, fields_planned}``
- ``InputError``: ``{line_no, kind, message}``
- ``FieldName`` / ``StatusValue`` 等枚举字面量
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# 枚举 / 字面量
# ============================================================
class StatusValue(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    UNCERTAIN = "uncertain"


class VerdictValue(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    UNCERTAIN = "uncertain"


class SelfCheckStatus(str, Enum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class EvidenceSource(str, Enum):
    ADVISORY = "advisory"
    REPOSITORY = "repository"
    GIT = "git"


class FieldName(str, Enum):
    ENTRY_POINT = "entry_point"
    CRITICAL_OPERATION = "critical_operation"
    COMMIT = "commit"
    VULN_IDS = "vuln_ids"
    VULN_TITLE = "vuln_title"
    VULN_CATEGORY_L1 = "vuln_category_l1"
    VULN_CATEGORY_L2 = "vuln_category_l2"
    TRACE = "trace"


#: 8 个必填字段名（顺序与 §4.1 一致）
ALL_EIGHT_FIELDS: Tuple[str, ...] = (
    "entry_point",
    "critical_operation",
    "commit",
    "vuln_ids",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "trace",
)


# ============================================================
# 证据引用
# ============================================================
@dataclass
class EvidenceRef:
    """字段证据引用：source/locator/quote 三元组。"""
    source: str  # advisory | repository | git
    locator: str  # JSON 路径或文件路径
    quote: str  # 引用内容片段

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceRef":
        return cls(
            source=d["source"],
            locator=d["locator"],
            quote=d["quote"],
        )


# ============================================================
# 字段结果
# ============================================================
@dataclass
class FieldResult:
    """单个字段的三态判定结果。"""
    status: str  # correct | incorrect | uncertain
    confidence: float
    evidence: str
    evidence_refs: List[EvidenceRef] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FieldResult":
        refs = [EvidenceRef.from_dict(r) for r in d.get("evidence_refs", []) or []]
        return cls(
            status=d["status"],
            confidence=float(d["confidence"]),
            evidence=d["evidence"],
            evidence_refs=refs,
        )


# ============================================================
# 工具调用审计
# ============================================================
@dataclass
class ToolCall:
    """``tool_trace`` 中的一条记录。

    ``input`` 必须是脱敏后的摘要；``evidence_refs`` 使用 JSON 路径（如
    ``fields.vuln_ids.evidence``），不能记录 API key 或完整本地绝对路径。
    """
    seq: int
    tool: str
    ok: bool
    input: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "tool": self.tool,
            "input": self.input,
            "ok": self.ok,
            "error": self.error,
            "error_code": self.error_code,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ToolCall":
        return cls(
            seq=int(d["seq"]),
            tool=d["tool"],
            ok=bool(d["ok"]),
            input=d.get("input"),
            error=d.get("error"),
            error_code=d.get("error_code"),
            evidence_refs=list(d.get("evidence_refs", []) or []),
        )


# ============================================================
# 自检
# ============================================================
@dataclass
class SelfCheck:
    """self_check 对象。"""
    status: str  # completed | skipped | failed
    agree: bool
    comment: str
    checked_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "agree": self.agree,
            "comment": self.comment,
            "checked_fields": list(self.checked_fields),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SelfCheck":
        return cls(
            status=d["status"],
            agree=bool(d["agree"]),
            comment=d["comment"],
            checked_fields=list(d.get("checked_fields", []) or []),
        )


# ============================================================
# 计划
# ============================================================
@dataclass
class Plan:
    """plan 对象（version 固定为 "1"）。"""
    tools_planned: List[str]
    fields_planned: List[str]
    version: str = "1"
    entry_id: Optional[str] = None
    report_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "version": self.version,
            "tools_planned": list(self.tools_planned),
            "fields_planned": list(self.fields_planned),
        }
        if self.entry_id is not None:
            d["entry_id"] = self.entry_id
        if self.report_id is not None:
            d["report_id"] = self.report_id
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Plan":
        return cls(
            version=str(d.get("version", "1")),
            tools_planned=list(d.get("tools_planned", []) or []),
            fields_planned=list(d.get("fields_planned", []) or []),
            entry_id=d.get("entry_id"),
            report_id=d.get("report_id"),
        )


# ============================================================
# 输入错误
# ============================================================
@dataclass
class InputError:
    """坏输入行的错误描述（§4.1 可选字段）。"""
    line_no: int
    kind: str  # json_parse_error | schema_violation | missing_field | forbidden_field
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "InputError":
        return cls(
            line_no=int(d["line_no"]),
            kind=d["kind"],
            message=d["message"],
        )


# ============================================================
# 完整报告
# ============================================================
@dataclass
class VerificationReport:
    """VerificationReport dataclass 视图。

    提供 ``to_dict`` / ``from_dict`` 用于 JSON round-trip。
    ``input_error`` 仅在坏输入行上有值。
    """
    report_id: str
    entry_id: str
    verdict: str
    fields: Dict[str, FieldResult]
    summary: str
    self_check: SelfCheck
    plan: Plan
    tool_trace: List[ToolCall] = field(default_factory=list)
    input_error: Optional[InputError] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "report_id": self.report_id,
            "entry_id": self.entry_id,
            "verdict": self.verdict,
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
            "summary": self.summary,
            "self_check": self.self_check.to_dict(),
            "plan": self.plan.to_dict(),
            "tool_trace": [c.to_dict() for c in self.tool_trace],
        }
        if self.input_error is not None:
            d["input_error"] = self.input_error.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VerificationReport":
        return cls(
            report_id=d["report_id"],
            entry_id=d["entry_id"],
            verdict=d["verdict"],
            fields={
                k: FieldResult.from_dict(v) for k, v in d["fields"].items()
            },
            summary=d["summary"],
            self_check=SelfCheck.from_dict(d["self_check"]),
            plan=Plan.from_dict(d["plan"]),
            tool_trace=[ToolCall.from_dict(c) for c in d.get("tool_trace", []) or []],
            input_error=InputError.from_dict(d["input_error"])
            if "input_error" in d else None,
        )


# ============================================================
# 向后兼容导出（§4.2 Python 边界）
# ============================================================
# 这些 re-export 在 ``models.py`` 里提供，``__init__.py`` 也会再次导入，
# 既保证 ``vulngym_verify_demo.VulnGymTools`` 可用，也保证
# ``vulngym_verify_demo.models.VulnGymTools`` 可用。
from .tools import VulnGymTools, ToolResult, normalize_project_from_repo  # noqa: E402,F401
from .llm_client import (  # noqa: E402,F401
    BaseLLMClient,
    ResilientLLMClient,
    SafeLLMClient,
    ScriptedMockLLMClient,
    MockLLMClient,
    QwenClient,
    DeepSeekClient,
    GLMClient,
    LLMMessage,
    LLMError,
    make_client,
)
from .field_checkers import check_all_fields  # noqa: E402,F401
from .agent import verify_entry, verify_entries  # noqa: E402,F401
from .eval import evaluate, load_gold, format_metrics  # noqa: E402,F401

# 兼容 eval.ALL_FIELDS（旧的 8 字段名列表，保持引用一致）
ALL_FIELDS = ALL_EIGHT_FIELDS  # noqa: F811  (intentional alias for back-compat)
