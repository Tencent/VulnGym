"""归因报告生成器

输出结构化的 JSON 格式归因报告。
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime


class AttributionReport:
    """归因报告生成器"""
    
    @staticmethod
    def generate(aggregation: Dict[str, Any], 
                 output_path: Optional[str] = None,
                 add_recommendations: bool = True) -> Dict[str, Any]:
        """生成归因报告
        
        Args:
            aggregation: ErrorAggregator 输出的聚合数据
            output_path: 可选，输出 JSON 文件路径
            add_recommendations: 是否生成修复建议
        
        Returns:
            完整的归因报告字典
        """
        report = {
            "analysis_id": f"error_attribution_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "total_reports": aggregation.get("total_reports", 0),
            "total_errors": aggregation.get("total_errors", 0),
            "error_summary": {
                "by_field": AttributionReport._format_field_summary(aggregation.get("by_field", [])),
                "by_tool": AttributionReport._format_tool_summary(aggregation.get("by_tool", [])),
                "by_llm": aggregation.get("by_llm", {}),
                "by_root_cause": aggregation.get("root_causes", [])
            }
        }
        
        # 添加修复建议
        if add_recommendations:
            report["recommendations"] = AttributionReport._generate_recommendations(aggregation)
        
        # 写入文件
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    @staticmethod
    def _format_field_summary(field_stats: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """格式化字段级汇总"""
        summary = {}
        
        for stat in field_stats:
            field_name = stat["field_name"]
            summary[field_name] = {
                "incorrect": stat["incorrect_count"],
                "uncertain": stat["uncertain_count"],
                "low_confidence": stat["low_confidence_count"],
                "evidence_chain_broken": stat["evidence_chain_broken_count"],
                "samples": stat["sample_entries"]
            }
        
        return summary
    
    @staticmethod
    def _format_tool_summary(tool_stats: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """格式化工具级汇总"""
        summary = {}
        
        for stat in tool_stats:
            tool_name = stat["tool_name"]
            summary[tool_name] = {
                "failed": stat["failed_count"],
                "total": stat["total_invocations"],
                "failure_rate": round(stat["failure_rate"], 4),
                "common_errors": stat["common_errors"],
                "samples": stat["sample_entries"]
            }
        
        return summary
    
    @staticmethod
    def _generate_recommendations(aggregation: Dict[str, Any]) -> List[str]:
        """基于聚合数据生成修复建议"""
        recommendations = []
        
        # 基于根因生成建议
        root_causes = aggregation.get("root_causes", [])
        for rc in root_causes:
            pattern = rc.get("pattern", "")
            count = rc.get("count", 0)
            affected_fields = rc.get("affected_fields", [])
            
            if pattern == "advisory_404":
                recommendations.append(
                    f"修复公告缓存缺失问题 (影响 {count} 条记录，涉及字段: {', '.join(affected_fields)})"
                )
            elif pattern == "checkout_failure":
                recommendations.append(
                    f"排查代码 checkout 失败原因 (影响 {count} 条记录，涉及字段: {', '.join(affected_fields)})"
                )
            elif pattern == "empty_trace":
                recommendations.append(
                    f"改进 trace 字段提取逻辑，当前 {count} 条记录 trace 为空"
                )
            elif pattern == "evidence_chain_broken":
                recommendations.append(
                    f"补充 incorrect 字段的证据引用 (影响 {count} 条记录，高频字段: {', '.join(affected_fields)})"
                )
        
        # 基于工具失败率生成建议
        tool_stats = aggregation.get("by_tool", [])
        for stat in tool_stats:
            tool_name = stat.get("tool_name", "")
            failure_rate = stat.get("failure_rate", 0.0)
            
            if failure_rate > 0.2:  # 失败率超过 20%
                recommendations.append(
                    f"改进 {tool_name} 工具鲁棒性 (当前失败率 {failure_rate*100:.1f}%)"
                )
        
        # 基于字段错误率生成建议
        field_stats = aggregation.get("by_field", [])
        for stat in field_stats:
            field_name = stat.get("field_name", "")
            incorrect = stat.get("incorrect_count", 0)
            uncertain = stat.get("uncertain_count", 0)
            total_errors = incorrect + uncertain
            
            if total_errors >= 3:  # 错误数 >= 3 才提建议
                recommendations.append(
                    f"重点改进 {field_name} 字段验证 (incorrect={incorrect}, uncertain={uncertain})"
                )
        
        # 基于 LLM 不确定率生成建议
        llm_stats = aggregation.get("by_llm", {})
        for provider, stats in llm_stats.items():
            uncertain_rate = stats.get("uncertain_rate", 0.0)
            if uncertain_rate > 0.15:  # 不确定率超过 15%
                recommendations.append(
                    f"优化 {provider} 模型的 prompt 或增加语义验证逻辑 (uncertain_rate={uncertain_rate*100:.1f}%)"
                )
        
        # 去重并限制数量
        recommendations = list(dict.fromkeys(recommendations))  # 保持顺序去重
        return recommendations[:10]  # 最多 10 条建议
    
    @staticmethod
    def format_text_summary(report: Dict[str, Any]) -> str:
        """生成人类可读的文本摘要"""
        lines = []
        lines.append(f"=== 错误归因分析报告 ===")
        lines.append(f"分析 ID: {report.get('analysis_id', 'unknown')}")
        lines.append(f"时间戳: {report.get('timestamp', 'unknown')}")
        lines.append(f"总报告数: {report.get('total_reports', 0)}")
        lines.append(f"总错误数: {report.get('total_errors', 0)}")
        lines.append("")
        
        # 字段级汇总
        lines.append("## 字段级错误分布")
        by_field = report.get("error_summary", {}).get("by_field", {})
        for field_name, stats in by_field.items():
            lines.append(f"  {field_name}:")
            lines.append(f"    - incorrect: {stats.get('incorrect', 0)}")
            lines.append(f"    - uncertain: {stats.get('uncertain', 0)}")
            lines.append(f"    - 低置信度: {stats.get('low_confidence', 0)}")
            lines.append(f"    - 证据链断裂: {stats.get('evidence_chain_broken', 0)}")
            samples = stats.get('samples', [])
            if samples:
                lines.append(f"    - 样本: {', '.join(samples[:3])}")
        lines.append("")
        
        # 工具级汇总
        lines.append("## 工具失败率")
        by_tool = report.get("error_summary", {}).get("by_tool", {})
        for tool_name, stats in by_tool.items():
            failed = stats.get('failed', 0)
            total = stats.get('total', 1)
            rate = stats.get('failure_rate', 0.0)
            lines.append(f"  {tool_name}: {failed}/{total} ({rate*100:.1f}%)")
            errors = stats.get('common_errors', [])
            if errors:
                lines.append(f"    常见错误: {', '.join(errors)}")
        lines.append("")
        
        # 根因分析
        lines.append("## 公共根因")
        root_causes = report.get("error_summary", {}).get("by_root_cause", [])
        for rc in root_causes:
            pattern = rc.get('pattern', 'unknown')
            desc = rc.get('description', '')
            count = rc.get('count', 0)
            affected = rc.get('affected_fields', [])
            lines.append(f"  [{pattern}] {desc}")
            lines.append(f"    - 影响记录数: {count}")
            lines.append(f"    - 涉及字段: {', '.join(affected)}")
        lines.append("")
        
        # 修复建议
        recommendations = report.get("recommendations", [])
        if recommendations:
            lines.append("## 修复建议")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"  {i}. {rec}")
        
        return "\n".join(lines)
