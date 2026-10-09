"""Mermaid 流程图渲染器

将推理链路渲染为 Mermaid 格式的流程图。
"""

from typing import Dict, List, Set
from .chain_builder import ReasoningChain, ChainNode, NodeType, NodeStatus


class MermaidRenderer:
    """Mermaid 渲染器"""
    
    # 节点样式类
    STYLE_SUCCESS = "fill:#d4edda,stroke:#28a745,stroke-width:2px"
    STYLE_FAILED = "fill:#f8d7da,stroke:#dc3545,stroke-width:2px"
    STYLE_UNCERTAIN = "fill:#fff3cd,stroke:#ffc107,stroke-width:2px"
    STYLE_CORRECT = "fill:#d1ecf1,stroke:#17a2b8,stroke-width:2px"
    STYLE_INCORRECT = "fill:#f8d7da,stroke:#dc3545,stroke-width:2px"
    STYLE_PLAN = "fill:#e7f3ff,stroke:#0066cc,stroke-width:2px"
    STYLE_VERDICT = "fill:#e0e0e0,stroke:#666,stroke-width:3px"
    
    def render(self, chain: ReasoningChain, include_metadata: bool = True) -> str:
        """渲染为 Mermaid 流程图"""
        lines = ["graph TD"]
        
        # 1. 渲染节点
        node_definitions = self._render_nodes(chain.nodes)
        lines.extend(node_definitions)
        
        # 2. 渲染边
        edge_definitions = self._render_edges(chain.edges)
        lines.extend(edge_definitions)
        
        # 3. 渲染样式
        style_definitions = self._render_styles(chain.nodes)
        lines.extend(style_definitions)
        
        # 4. 添加元数据注释（可选）
        if include_metadata:
            metadata_comment = self._render_metadata_comment(chain)
            lines.insert(1, metadata_comment)
        
        return "\n".join(lines)
    
    def render_to_markdown(self, chain: ReasoningChain, 
                          include_title: bool = True,
                          include_summary: bool = True) -> str:
        """渲染为完整的 Markdown 文档"""
        sections = []
        
        # 标题
        if include_title:
            sections.append(f"# Reasoning Chain: {chain.entry_id}")
            sections.append(f"\n**Report ID**: {chain.report_id}")
            sections.append(f"**Verdict**: `{chain.verdict}`\n")
        
        # 摘要
        if include_summary:
            summary = self._generate_summary(chain)
            sections.append("## Summary\n")
            sections.append(summary)
        
        # Mermaid 图
        sections.append("## Reasoning Flow\n")
        sections.append("```mermaid")
        sections.append(self.render(chain, include_metadata=False))
        sections.append("```")
        
        # 详细信息
        sections.append("\n## Details\n")
        sections.append(self._generate_details(chain))
        
        return "\n".join(sections)
    
    def _render_nodes(self, nodes: List[ChainNode]) -> List[str]:
        """渲染节点定义"""
        definitions = []
        
        for node in nodes:
            node_shape = self._get_node_shape(node)
            label = self._escape_label(node.get_display_label())
            
            if node_shape == "diamond":
                definitions.append(f"    {node.node_id}{{{{{label}}}}}")
            elif node_shape == "round":
                definitions.append(f"    {node.node_id}([{label}])")
            elif node_shape == "stadium":
                definitions.append(f"    {node.node_id}([{label}])")
            elif node_shape == "hexagon":
                definitions.append(f"    {node.node_id}{{{{{{{label}}}}}}}")
            else:  # rectangle
                definitions.append(f"    {node.node_id}[{label}]")
        
        return definitions
    
    def _render_edges(self, edges: List) -> List[str]:
        """渲染边定义"""
        definitions = []
        
        for edge in edges:
            if edge.label:
                label = self._escape_label(edge.label)
                definitions.append(f"    {edge.from_node} -->|{label}| {edge.to_node}")
            else:
                definitions.append(f"    {edge.from_node} --> {edge.to_node}")
        
        return definitions
    
    def _render_styles(self, nodes: List[ChainNode]) -> List[str]:
        """渲染样式定义"""
        definitions = []
        
        for node in nodes:
            style = self._get_node_style(node)
            if style:
                definitions.append(f"    style {node.node_id} {style}")
        
        return definitions
    
    def _get_node_shape(self, node: ChainNode) -> str:
        """获取节点形状"""
        if node.node_type == NodeType.PLAN:
            return "stadium"
        elif node.node_type == NodeType.TOOL:
            return "rectangle"
        elif node.node_type == NodeType.FIELD:
            return "round"
        elif node.node_type == NodeType.VERDICT:
            return "hexagon"
        elif node.node_type == NodeType.SELF_CHECK:
            return "diamond"
        else:
            return "rectangle"
    
    def _get_node_style(self, node: ChainNode) -> str:
        """获取节点样式"""
        if node.node_type == NodeType.PLAN:
            return self.STYLE_PLAN
        elif node.node_type == NodeType.VERDICT:
            return self.STYLE_VERDICT
        elif node.status == NodeStatus.SUCCESS:
            return self.STYLE_SUCCESS
        elif node.status == NodeStatus.FAILED:
            return self.STYLE_FAILED
        elif node.status == NodeStatus.CORRECT:
            return self.STYLE_CORRECT
        elif node.status == NodeStatus.INCORRECT:
            return self.STYLE_INCORRECT
        elif node.status == NodeStatus.UNCERTAIN:
            return self.STYLE_UNCERTAIN
        else:
            return ""
    
    def _escape_label(self, label: str) -> str:
        """转义特殊字符"""
        # Mermaid 需要转义的字符
        label = label.replace('"', '#quot;')
        label = label.replace('[', '#91;')
        label = label.replace(']', '#93;')
        return label
    
    def _render_metadata_comment(self, chain: ReasoningChain) -> str:
        """渲染元数据注释"""
        meta = chain.metadata
        return (
            f"    %% Entry: {chain.entry_id} | "
            f"Tools: {meta.get('total_tools', 0)} | "
            f"Failed: {meta.get('failed_tools', 0)} | "
            f"Incorrect Fields: {meta.get('incorrect_fields', 0)}"
        )
    
    def _generate_summary(self, chain: ReasoningChain) -> str:
        """生成摘要文本"""
        meta = chain.metadata
        lines = []
        
        lines.append(f"- **Total Tools**: {meta.get('total_tools', 0)}")
        lines.append(f"- **Failed Tools**: {meta.get('failed_tools', 0)}")
        lines.append(f"- **Total Fields**: {meta.get('total_fields', 0)}")
        lines.append(f"- **Incorrect Fields**: {meta.get('incorrect_fields', 0)}")
        lines.append(f"- **Has Plan**: {'Yes' if meta.get('has_plan') else 'No'}")
        lines.append(f"- **Has Self-Check**: {'Yes' if meta.get('has_self_check') else 'No'}")
        
        return "\n".join(lines)
    
    def _generate_details(self, chain: ReasoningChain) -> str:
        """生成详细信息"""
        sections = []
        
        # 失败的工具
        failed_tools = chain.get_failed_tools()
        if failed_tools:
            sections.append("### Failed Tools\n")
            for tool in failed_tools:
                error = tool.metadata.get("error", "Unknown error")
                sections.append(f"- **{tool.label}**: {error}")
            sections.append("")
        
        # 错误的字段
        incorrect_fields = chain.get_incorrect_fields()
        if incorrect_fields:
            sections.append("### Incorrect Fields\n")
            for field in incorrect_fields:
                evidence = field.metadata.get("evidence", "")
                sections.append(f"- **{field.label}** (conf: {field.confidence:.2f})")
                if evidence:
                    sections.append(f"  - Evidence: {evidence}")
            sections.append("")
        
        return "\n".join(sections)


class ComparisonRenderer:
    """多报告对比渲染器"""
    
    def render_comparison(self, chains: List[ReasoningChain]) -> str:
        """渲染多个推理链路的对比"""
        if not chains:
            return "No chains to compare"
        
        sections = []
        sections.append("# Reasoning Chains Comparison\n")
        sections.append(f"**Total Reports**: {len(chains)}\n")
        
        # 统计信息
        sections.append("## Statistics\n")
        sections.append(self._generate_comparison_stats(chains))
        
        # 每个链路的简要信息
        sections.append("\n## Individual Chains\n")
        for i, chain in enumerate(chains, 1):
            sections.append(f"### {i}. {chain.entry_id}")
            sections.append(f"- Verdict: `{chain.verdict}`")
            sections.append(f"- Failed Tools: {chain.metadata.get('failed_tools', 0)}")
            sections.append(f"- Incorrect Fields: {chain.metadata.get('incorrect_fields', 0)}")
            sections.append("")
        
        return "\n".join(sections)
    
    def _generate_comparison_stats(self, chains: List[ReasoningChain]) -> str:
        """生成对比统计"""
        total = len(chains)
        correct_count = sum(1 for c in chains if c.verdict == "correct")
        incorrect_count = sum(1 for c in chains if c.verdict == "incorrect")
        uncertain_count = sum(1 for c in chains if c.verdict == "uncertain")
        
        avg_tools = sum(c.metadata.get('total_tools', 0) for c in chains) / total
        avg_failed = sum(c.metadata.get('failed_tools', 0) for c in chains) / total
        
        lines = []
        lines.append(f"- **Correct**: {correct_count} ({correct_count/total*100:.1f}%)")
        lines.append(f"- **Incorrect**: {incorrect_count} ({incorrect_count/total*100:.1f}%)")
        lines.append(f"- **Uncertain**: {uncertain_count} ({uncertain_count/total*100:.1f}%)")
        lines.append(f"- **Avg Tools per Report**: {avg_tools:.1f}")
        lines.append(f"- **Avg Failed Tools**: {avg_failed:.1f}")
        
        return "\n".join(lines)
