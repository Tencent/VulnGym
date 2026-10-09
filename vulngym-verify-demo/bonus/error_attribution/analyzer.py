"""单报告错误分析器

解析 VerificationReport 中的 incorrect/uncertain 字段、工具调用失败和证据链断裂。
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class FieldError:
    """单个字段的错误信息"""
    field_name: str
    status: str  # incorrect | uncertain
    confidence: float
    evidence: str
    has_evidence_refs: bool
    evidence_chain_broken: bool  # evidence_refs=[] 但 status=incorrect


@dataclass
class ToolFailure:
    """工具调用失败信息"""
    seq: int
    tool: str
    error: Optional[str]
    affected_fields: List[str]  # 从 evidence_refs 推断


@dataclass
class AnalysisResult:
    """单条报告的分析结果"""
    entry_id: str
    report_id: str
    verdict: str
    field_errors: List[FieldError]
    tool_failures: List[ToolFailure]
    low_confidence_fields: List[str]  # confidence < 0.6
    empty_trace: bool
    llm_provider: Optional[str] = None  # 从 tool_trace 推断


class ErrorAnalyzer:
    """单报告错误分析器"""
    
    FIELD_NAMES = [
        "entry_point", "critical_operation", "commit", "vuln_ids",
        "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace"
    ]
    
    def analyze(self, report: Dict[str, Any]) -> AnalysisResult:
        """分析单条报告，提取错误信息"""
        entry_id = report.get("entry_id", "unknown")
        report_id = report.get("report_id", "unknown")
        verdict = report.get("verdict", "uncertain")
        
        # 分析字段错误
        field_errors = self._analyze_fields(report.get("fields", {}))
        
        # 分析工具失败
        tool_failures = self._analyze_tools(report.get("tool_trace", []))
        
        # 低置信度字段
        low_confidence = self._find_low_confidence_fields(report.get("fields", {}))
        
        # 检查 trace 是否为空
        empty_trace = self._check_empty_trace(report.get("fields", {}))
        
        # 推断 LLM provider（从 tool_trace 或其他线索）
        llm_provider = self._infer_llm_provider(report)
        
        return AnalysisResult(
            entry_id=entry_id,
            report_id=report_id,
            verdict=verdict,
            field_errors=field_errors,
            tool_failures=tool_failures,
            low_confidence_fields=low_confidence,
            empty_trace=empty_trace,
            llm_provider=llm_provider
        )
    
    def _analyze_fields(self, fields: Dict[str, Any]) -> List[FieldError]:
        """分析所有字段，提取错误和不确定项"""
        errors = []
        
        for field_name in self.FIELD_NAMES:
            field_data = fields.get(field_name, {})
            status = field_data.get("status", "uncertain")
            confidence = field_data.get("confidence", 0.0)
            evidence = field_data.get("evidence", "")
            evidence_refs = field_data.get("evidence_refs", [])
            
            # 只关注 incorrect 或 uncertain
            if status in ["incorrect", "uncertain"]:
                has_refs = len(evidence_refs) > 0
                chain_broken = (status == "incorrect" and not has_refs)
                
                errors.append(FieldError(
                    field_name=field_name,
                    status=status,
                    confidence=confidence,
                    evidence=evidence,
                    has_evidence_refs=has_refs,
                    evidence_chain_broken=chain_broken
                ))
        
        return errors
    
    def _analyze_tools(self, tool_trace: List[Dict[str, Any]]) -> List[ToolFailure]:
        """分析工具调用失败"""
        failures = []
        
        for call in tool_trace:
            if not call.get("ok", True):
                seq = call.get("seq", 0)
                tool = call.get("tool", "unknown")
                error = call.get("error")
                evidence_refs = call.get("evidence_refs", [])
                
                # 从 evidence_refs 推断受影响的字段
                affected_fields = self._extract_affected_fields(evidence_refs)
                
                failures.append(ToolFailure(
                    seq=seq,
                    tool=tool,
                    error=error,
                    affected_fields=affected_fields
                ))
        
        return failures
    
    def _find_low_confidence_fields(self, fields: Dict[str, Any]) -> List[str]:
        """找出低置信度字段（< 0.6）"""
        low_conf = []
        
        for field_name in self.FIELD_NAMES:
            field_data = fields.get(field_name, {})
            confidence = field_data.get("confidence", 0.0)
            
            if confidence < 0.6:
                low_conf.append(field_name)
        
        return low_conf
    
    def _check_empty_trace(self, fields: Dict[str, Any]) -> bool:
        """检查 trace 字段是否为空或证据不足"""
        trace_data = fields.get("trace", {})
        evidence_refs = trace_data.get("evidence_refs", [])
        return len(evidence_refs) == 0
    
    def _infer_llm_provider(self, report: Dict[str, Any]) -> Optional[str]:
        """推断 LLM 提供商（当前简化实现，可通过 tool_trace 扩展）"""
        # 简化版本：从 summary 或其他字段推断
        # 实际可从 tool_trace 中 LLM 相关调用推断
        summary = report.get("summary", "")
        if "qwen" in summary.lower():
            return "qwen"
        elif "deepseek" in summary.lower():
            return "deepseek"
        elif "glm" in summary.lower():
            return "glm"
        return None
    
    def _extract_affected_fields(self, evidence_refs: List[str]) -> List[str]:
        """从 evidence_refs JSON 路径中提取字段名"""
        fields = set()
        
        for ref in evidence_refs:
            if isinstance(ref, str) and "fields." in ref:
                # 解析 "fields.vuln_ids.evidence" -> "vuln_ids"
                parts = ref.split(".")
                if len(parts) >= 2 and parts[0] == "fields":
                    fields.add(parts[1])
        
        return list(fields)
