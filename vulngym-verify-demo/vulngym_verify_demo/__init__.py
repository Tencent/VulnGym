# -*- coding: utf-8 -*-
"""VulnGym 字段级验证 Demo。

目录：
- tools.py        智能体工具集（公告读取、checkout、读代码片段、grep、git log）
- llm_client.py   Qwen 客户端 + mock fallback
- field_checkers.py 单字段三态判定（确定性规则 + LLM 语义补强）
- agent.py        单轮规划 + 工具调用 + 反思 闭环
- cli.py          JSONL -> JSONL 报告 + 终端摘要
- schema.py       I1：SCHEMA.md 输入校验、报告校验、坏输入报告协议（§4.1/§5 I1）
- models.py       I1：VerificationReport dataclass + §4.2 向后兼容导出
- report_schema.json  I1：唯一规范 JSON Schema（§4.1）
- taxonomy.py      I1：版本化 12 类分类本体及历史标签规范化

公共符号（I1 起从包根直接可用）：

    # §4.2 向后兼容导出
    from vulngym_verify_demo import (
        VulnGymTools, BaseLLMClient, ResilientLLMClient,
        check_all_fields, verify_entry, verify_entries, evaluate,
    )

    # I1 新增契约
    from vulngym_verify_demo import (
        ValidationReport, EvidenceRef, FieldResult, ToolCall,
        SelfCheck, Plan, InputError,
        ALL_EIGHT_FIELDS,
        iter_jsonl_safe, read_jsonl_with_reports,
        validate_entry, validate_report, validate_field_result,
        build_invalid_input_report, invalid_input_id,
    )
"""
from __future__ import annotations

# §4.2 向后兼容导出
from .tools import VulnGymTools, ToolResult, load_repo_catalog, normalize_project_from_repo
from .llm_client import (
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
from .field_checkers import check_all_fields
from .agent import verify_entry, verify_entries
from .eval import evaluate, load_gold, format_metrics, ALL_FIELDS

# I1 新增契约（dataclass）
from .models import (
    ALL_EIGHT_FIELDS,
    EvidenceRef,
    FieldName,
    FieldResult,
    InputError,
    Plan,
    SelfCheck,
    SelfCheckStatus,
    StatusValue,
    ToolCall,
    VerificationReport,
    VerdictValue,
)

# I1 schema 校验与坏输入报告工厂
from .schema import (
    COMMIT_RE,
    EVIDENCE_SOURCE_VALUES,
    ENTRY_REQUIRED_FIELDS,
    FORBIDDEN_INTERNAL_FIELDS,
    ORIGIN_CONSTANT,
    REPORT_REQUIRED_TOP_FIELDS,
    REPORT_AUDIT_FIELDS,
    SELF_CHECK_STATUS_VALUES,
    STATUS_VALUES,
    TOOL_NAMES,
    VERDICT_VALUES,
    build_invalid_input_field,
    build_invalid_input_report,
    invalid_input_id,
    iter_jsonl_safe,
    normalize_line,
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
)
from .taxonomy import (
    CategoryTaxonomy,
    TaxonomyCategory,
    load_category_taxonomy,
    validate_taxonomy_data,
)

# P0-2 / P0-4：T1Data 适配层（仓库解析、公告适配、资料包上下文）
from .repository_resolver import (
    RepoResolutionError,
    RepositoryResolver,
    canonical_repo_url,
    canonical_key,
    load_repo_map,
)
from .advisory_adapter import (
    AdvisoryAdapter,
    CWE_CATEGORY_MAP,
    parse_version_range,
    version_in_range,
)
from .package_context import T1PackageContext
from .tools import TOOL_ERROR_CODES

# 兼容别名：便于调用方使用历史命名
ValidationReport = VerificationReport  # noqa: F811  (legacy name alias)

__all__ = [
    # §4.2 向后兼容导出
    "VulnGymTools",
    "ToolResult",
    "load_repo_catalog",
    "normalize_project_from_repo",
    "BaseLLMClient",
    "ResilientLLMClient",
    "SafeLLMClient",
    "ScriptedMockLLMClient",
    "MockLLMClient",
    "QwenClient",
    "DeepSeekClient",
    "GLMClient",
    "LLMMessage",
    "LLMError",
    "make_client",
    "check_all_fields",
    "verify_entry",
    "verify_entries",
    "evaluate",
    "load_gold",
    "format_metrics",
    "ALL_FIELDS",
    # I1 契约 dataclass
    "EvidenceRef",
    "FieldName",
    "FieldResult",
    "InputError",
    "Plan",
    "SelfCheck",
    "SelfCheckStatus",
    "StatusValue",
    "ToolCall",
    "VerificationReport",
    "ValidationReport",
    "VerdictValue",
    "ALL_EIGHT_FIELDS",
    # I1 schema 校验与工厂
    "COMMIT_RE",
    "EVIDENCE_SOURCE_VALUES",
    "ENTRY_REQUIRED_FIELDS",
    "FORBIDDEN_INTERNAL_FIELDS",
    "ORIGIN_CONSTANT",
    "REPORT_REQUIRED_TOP_FIELDS",
    "REPORT_AUDIT_FIELDS",
    "SELF_CHECK_STATUS_VALUES",
    "STATUS_VALUES",
    "TOOL_NAMES",
    "VERDICT_VALUES",
    "build_invalid_input_field",
    "build_invalid_input_report",
    "invalid_input_id",
    "iter_jsonl_safe",
    "normalize_line",
    "read_jsonl_with_reports",
    "validate_entry",
    "validate_evidence_ref",
    "validate_field_result",
    "validate_line",
    "validate_node",
    "validate_plan",
    "validate_report",
    "validate_self_check",
    "validate_tool_call",
    # I1 分类本体
    "CategoryTaxonomy",
    "TaxonomyCategory",
    "load_category_taxonomy",
    "validate_taxonomy_data",
]
