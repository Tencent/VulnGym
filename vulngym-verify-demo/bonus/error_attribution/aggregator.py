"""跨报告错误聚合器

按字段、工具、LLM 维度聚合错误，识别公共根因。
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict

from .analyzer import AnalysisResult, ErrorAnalyzer


@dataclass
class FieldErrorStats:
    """字段级错误统计"""
    field_name: str
    incorrect_count: int
    uncertain_count: int
    low_confidence_count: int
    evidence_chain_broken_count: int
    sample_entries: List[str]  # 最多保留 5 个样本


@dataclass
class ToolErrorStats:
    """工具级错误统计"""
    tool_name: str
    failed_count: int
    total_invocations: int
    failure_rate: float
    common_errors: List[str]
    sample_entries: List[str]


@dataclass
class RootCause:
    """公共根因模式"""
    pattern: str
    description: str
    count: int
    affected_fields: List[str]
    sample_entries: List[str]
    evidence_sample: Optional[Dict[str, Any]] = None


class ErrorAggregator:
    """跨报告错误聚合器"""
    
    def __init__(self):
        self.analyzer = ErrorAnalyzer()
    
    def aggregate(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """聚合多条报告的错误模式"""
        # 第一步：分析所有报告
        analyses = [self.analyzer.analyze(report) for report in reports]
        
        # 第二步：按维度聚合
        field_stats = self._aggregate_by_field(analyses)
        tool_stats = self._aggregate_by_tool(analyses, reports)
        llm_stats = self._aggregate_by_llm(analyses)
        root_causes = self._identify_root_causes(analyses, reports)
        
        return {
            "total_reports": len(reports),
            "total_errors": sum(len(a.field_errors) for a in analyses),
            "by_field": [asdict(s) for s in field_stats],
            "by_tool": [asdict(s) for s in tool_stats],
            "by_llm": llm_stats,
            "root_causes": [asdict(rc) for rc in root_causes]
        }
    
    def _aggregate_by_field(self, analyses: List[AnalysisResult]) -> List[FieldErrorStats]:
        """按字段聚合错误"""
        field_counters = defaultdict(lambda: {
            "incorrect": 0,
            "uncertain": 0,
            "low_confidence": 0,
            "chain_broken": 0,
            "samples": []
        })
        
        for analysis in analyses:
            # 统计字段错误
            for field_error in analysis.field_errors:
                field_name = field_error.field_name
                counter = field_counters[field_name]
                
                if field_error.status == "incorrect":
                    counter["incorrect"] += 1
                elif field_error.status == "uncertain":
                    counter["uncertain"] += 1
                
                if field_error.evidence_chain_broken:
                    counter["chain_broken"] += 1
                
                # 保留样本（最多 5 个）
                if len(counter["samples"]) < 5:
                    counter["samples"].append(analysis.entry_id)
            
            # 统计低置信度
            for field_name in analysis.low_confidence_fields:
                counter = field_counters[field_name]
                counter["low_confidence"] += 1
        
        # 转换为 FieldErrorStats
        stats = []
        for field_name, counter in field_counters.items():
            stats.append(FieldErrorStats(
                field_name=field_name,
                incorrect_count=counter["incorrect"],
                uncertain_count=counter["uncertain"],
                low_confidence_count=counter["low_confidence"],
                evidence_chain_broken_count=counter["chain_broken"],
                sample_entries=counter["samples"]
            ))
        
        # 按错误总数排序
        stats.sort(key=lambda s: s.incorrect_count + s.uncertain_count, reverse=True)
        return stats
    
    def _aggregate_by_tool(self, analyses: List[AnalysisResult], 
                          reports: List[Dict[str, Any]]) -> List[ToolErrorStats]:
        """按工具聚合错误"""
        tool_counters = defaultdict(lambda: {
            "failed": 0,
            "total": 0,
            "errors": [],
            "samples": []
        })
        
        # 统计所有工具调用
        for report in reports:
            tool_trace = report.get("tool_trace", [])
            for call in tool_trace:
                tool = call.get("tool", "unknown")
                ok = call.get("ok", True)
                
                tool_counters[tool]["total"] += 1
                if not ok:
                    tool_counters[tool]["failed"] += 1
                    error = call.get("error", "unknown error")
                    tool_counters[tool]["errors"].append(error)
        
        # 收集失败样本
        for analysis in analyses:
            for failure in analysis.tool_failures:
                tool = failure.tool
                counter = tool_counters[tool]
                if len(counter["samples"]) < 5:
                    counter["samples"].append(analysis.entry_id)
        
        # 转换为 ToolErrorStats
        stats = []
        for tool_name, counter in tool_counters.items():
            total = counter["total"]
            failed = counter["failed"]
            failure_rate = failed / total if total > 0 else 0.0
            
            # 提取常见错误（去重并统计频次）
            error_freq = defaultdict(int)
            for err in counter["errors"]:
                error_freq[err] += 1
            common_errors = sorted(error_freq.items(), key=lambda x: x[1], reverse=True)
            common_errors = [f"{err} (x{count})" for err, count in common_errors[:3]]
            
            stats.append(ToolErrorStats(
                tool_name=tool_name,
                failed_count=failed,
                total_invocations=total,
                failure_rate=failure_rate,
                common_errors=common_errors,
                sample_entries=counter["samples"]
            ))
        
        # 按失败率排序
        stats.sort(key=lambda s: s.failure_rate, reverse=True)
        return stats
    
    def _aggregate_by_llm(self, analyses: List[AnalysisResult]) -> Dict[str, Any]:
        """按 LLM 提供商聚合统计"""
        llm_counters = defaultdict(lambda: {
            "total": 0,
            "uncertain_count": 0,
            "low_confidence_count": 0
        })
        
        for analysis in analyses:
            provider = analysis.llm_provider or "unknown"
            counter = llm_counters[provider]
            counter["total"] += 1
            
            # 统计 uncertain 和低置信度
            for field_error in analysis.field_errors:
                if field_error.status == "uncertain":
                    counter["uncertain_count"] += 1
            
            counter["low_confidence_count"] += len(analysis.low_confidence_fields)
        
        # 计算比率
        result = {}
        for provider, counter in llm_counters.items():
            total = counter["total"]
            result[provider] = {
                "total_reports": total,
                "uncertain_rate": counter["uncertain_count"] / (total * 8) if total > 0 else 0.0,
                "low_confidence_rate": counter["low_confidence_count"] / (total * 8) if total > 0 else 0.0
            }
        
        return result
    
    def _identify_root_causes(self, analyses: List[AnalysisResult],
                             reports: List[Dict[str, Any]]) -> List[RootCause]:
        """识别公共根因"""
        root_causes = []
        
        # 根因 1: advisory 404 或缺失
        advisory_404_pattern = self._find_advisory_404_pattern(analyses, reports)
        if advisory_404_pattern:
            root_causes.append(advisory_404_pattern)
        
        # 根因 2: checkout 失败导致的连锁错误
        checkout_failure_pattern = self._find_checkout_failure_pattern(analyses)
        if checkout_failure_pattern:
            root_causes.append(checkout_failure_pattern)
        
        # 根因 3: 空 trace 高频出现
        empty_trace_pattern = self._find_empty_trace_pattern(analyses)
        if empty_trace_pattern:
            root_causes.append(empty_trace_pattern)
        
        # 根因 4: 证据链断裂（incorrect 但无 evidence_refs）
        broken_chain_pattern = self._find_broken_chain_pattern(analyses, reports)
        if broken_chain_pattern:
            root_causes.append(broken_chain_pattern)
        
        return root_causes
    
    def _find_advisory_404_pattern(self, analyses: List[AnalysisResult],
                                   reports: List[Dict[str, Any]]) -> Optional[RootCause]:
        """查找 advisory 404 模式"""
        affected_entries = []
        affected_fields_set = set()
        
        for i, report in enumerate(reports):
            tool_trace = report.get("tool_trace", [])
            for call in tool_trace:
                if call.get("tool") == "read_advisory" and not call.get("ok", True):
                    error = call.get("error", "")
                    if "404" in error or "not found" in error.lower():
                        affected_entries.append(analyses[i].entry_id)
                        # 提取受影响的字段
                        for field_error in analyses[i].field_errors:
                            affected_fields_set.add(field_error.field_name)
        
        if len(affected_entries) >= 2:  # 至少 2 条才认为是模式
            return RootCause(
                pattern="advisory_404",
                description="公告缓存缺失或 404 错误",
                count=len(affected_entries),
                affected_fields=list(affected_fields_set),
                sample_entries=affected_entries[:5],
                evidence_sample={"error_type": "read_advisory failed", "status_code": "404"}
            )
        return None
    
    def _find_checkout_failure_pattern(self, analyses: List[AnalysisResult]) -> Optional[RootCause]:
        """查找 checkout 失败模式"""
        affected_entries = []
        affected_fields_set = set()
        
        for analysis in analyses:
            for failure in analysis.tool_failures:
                if failure.tool == "checkout":
                    affected_entries.append(analysis.entry_id)
                    affected_fields_set.update(failure.affected_fields)
        
        if len(affected_entries) >= 2:
            return RootCause(
                pattern="checkout_failure",
                description="代码 checkout 失败导致源码字段无法验证",
                count=len(affected_entries),
                affected_fields=list(affected_fields_set),
                sample_entries=affected_entries[:5]
            )
        return None
    
    def _find_empty_trace_pattern(self, analyses: List[AnalysisResult]) -> Optional[RootCause]:
        """查找空 trace 模式"""
        empty_trace_entries = [a.entry_id for a in analyses if a.empty_trace]
        
        if len(empty_trace_entries) >= 3:
            return RootCause(
                pattern="empty_trace",
                description="trace 字段普遍为空或证据不足",
                count=len(empty_trace_entries),
                affected_fields=["trace"],
                sample_entries=empty_trace_entries[:5]
            )
        return None
    
    def _find_broken_chain_pattern(self, analyses: List[AnalysisResult],
                                   reports: List[Dict[str, Any]]) -> Optional[RootCause]:
        """查找证据链断裂模式"""
        broken_entries = []
        broken_fields = defaultdict(int)
        
        for analysis in analyses:
            has_broken = False
            for field_error in analysis.field_errors:
                if field_error.evidence_chain_broken:
                    has_broken = True
                    broken_fields[field_error.field_name] += 1
            
            if has_broken:
                broken_entries.append(analysis.entry_id)
        
        if len(broken_entries) >= 2:
            # 找出最常断裂的字段
            top_fields = sorted(broken_fields.items(), key=lambda x: x[1], reverse=True)
            top_fields = [f for f, _ in top_fields[:3]]
            
            return RootCause(
                pattern="evidence_chain_broken",
                description="字段判定为 incorrect 但缺少 evidence_refs",
                count=len(broken_entries),
                affected_fields=top_fields,
                sample_entries=broken_entries[:5]
            )
        return None
