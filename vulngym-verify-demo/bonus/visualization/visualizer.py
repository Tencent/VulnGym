"""推理链路可视化主类

提供高级 API，整合 ChainBuilder 和 MermaidRenderer。
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from .chain_builder import ChainBuilder, ReasoningChain
from .mermaid_renderer import MermaidRenderer, ComparisonRenderer


class ChainVisualizer:
    """推理链路可视化器"""
    
    def __init__(self):
        self.builder = ChainBuilder()
        self.renderer = MermaidRenderer()
        self.comparison_renderer = ComparisonRenderer()
    
    def visualize_report(self, report: Dict[str, Any], 
                        output_format: str = "mermaid") -> str:
        """可视化单条报告
        
        Args:
            report: VerificationReport 字典
            output_format: 输出格式 (mermaid | markdown | json)
        
        Returns:
            可视化结果字符串
        """
        chain = self.builder.build(report)
        
        if output_format == "mermaid":
            return self.renderer.render(chain)
        elif output_format == "markdown":
            return self.renderer.render_to_markdown(chain)
        elif output_format == "json":
            return self._chain_to_json(chain)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def visualize_multiple(self, reports: List[Dict[str, Any]], 
                          output_format: str = "comparison") -> str:
        """可视化多条报告
        
        Args:
            reports: VerificationReport 列表
            output_format: 输出格式 (comparison | individual)
        
        Returns:
            可视化结果字符串
        """
        chains = [self.builder.build(report) for report in reports]
        
        if output_format == "comparison":
            return self.comparison_renderer.render_comparison(chains)
        elif output_format == "individual":
            sections = []
            for i, chain in enumerate(chains, 1):
                sections.append(f"{'='*60}")
                sections.append(f"Report {i}/{len(chains)}: {chain.entry_id}")
                sections.append(f"{'='*60}\n")
                sections.append(self.renderer.render_to_markdown(chain))
                sections.append("")
            return "\n".join(sections)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def save_visualization(self, report: Dict[str, Any], 
                          output_path: str,
                          output_format: str = "markdown"):
        """保存可视化结果到文件"""
        result = self.visualize_report(report, output_format)
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result)
    
    def save_multiple(self, reports: List[Dict[str, Any]], 
                     output_dir: str,
                     output_format: str = "markdown"):
        """保存多条报告的可视化"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 保存单独的文件
        for report in reports:
            entry_id = report.get("entry_id", "unknown")
            filename = f"{entry_id}.md" if output_format == "markdown" else f"{entry_id}.mermaid"
            
            chain = self.builder.build(report)
            
            if output_format == "markdown":
                content = self.renderer.render_to_markdown(chain)
            else:
                content = self.renderer.render(chain)
            
            with open(output_path / filename, "w", encoding="utf-8") as f:
                f.write(content)
        
        # 保存汇总对比
        chains = [self.builder.build(report) for report in reports]
        comparison = self.comparison_renderer.render_comparison(chains)
        
        with open(output_path / "comparison.md", "w", encoding="utf-8") as f:
            f.write(comparison)
    
    def filter_by_verdict(self, reports: List[Dict[str, Any]], 
                         verdict: str) -> List[Dict[str, Any]]:
        """按 verdict 过滤报告"""
        return [r for r in reports if r.get("verdict") == verdict]
    
    def filter_by_failed_tools(self, reports: List[Dict[str, Any]], 
                              min_failures: int = 1) -> List[Dict[str, Any]]:
        """按失败工具数量过滤"""
        filtered = []
        for report in reports:
            tool_trace = report.get("tool_trace", [])
            failed_count = sum(1 for call in tool_trace if not call.get("ok", True))
            if failed_count >= min_failures:
                filtered.append(report)
        return filtered
    
    def get_chain_statistics(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取推理链路统计信息"""
        chains = [self.builder.build(report) for report in reports]
        
        return {
            "total_reports": len(chains),
            "verdict_distribution": {
                "correct": sum(1 for c in chains if c.verdict == "correct"),
                "incorrect": sum(1 for c in chains if c.verdict == "incorrect"),
                "uncertain": sum(1 for c in chains if c.verdict == "uncertain")
            },
            "avg_tools_per_report": sum(c.metadata.get('total_tools', 0) for c in chains) / len(chains),
            "avg_failed_tools": sum(c.metadata.get('failed_tools', 0) for c in chains) / len(chains),
            "reports_with_plan": sum(1 for c in chains if c.metadata.get('has_plan')),
            "reports_with_self_check": sum(1 for c in chains if c.metadata.get('has_self_check')),
            "total_incorrect_fields": sum(c.metadata.get('incorrect_fields', 0) for c in chains)
        }
    
    def _chain_to_json(self, chain: ReasoningChain) -> str:
        """将推理链路转换为 JSON"""
        data = {
            "entry_id": chain.entry_id,
            "report_id": chain.report_id,
            "verdict": chain.verdict,
            "nodes": [
                {
                    "id": node.node_id,
                    "type": node.node_type.value,
                    "label": node.label,
                    "status": node.status.value,
                    "confidence": node.confidence,
                    "metadata": node.metadata
                }
                for node in chain.nodes
            ],
            "edges": [
                {
                    "from": edge.from_node,
                    "to": edge.to_node,
                    "label": edge.label
                }
                for edge in chain.edges
            ],
            "metadata": chain.metadata
        }
        return json.dumps(data, indent=2, ensure_ascii=False)
