"""推理链路构建器

从 VerificationReport 中提取 tool_trace、evidence_refs 和字段验证结果，
构建有向推理图。
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """节点类型"""
    TOOL = "tool"              # 工具调用
    FIELD = "field"            # 字段验证
    VERDICT = "verdict"        # 最终判定
    PLAN = "plan"              # 规划节点
    SELF_CHECK = "self_check"  # 反思节点


class NodeStatus(Enum):
    """节点状态"""
    SUCCESS = "success"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    CORRECT = "correct"
    INCORRECT = "incorrect"


@dataclass
class ChainNode:
    """推理链路节点"""
    node_id: str
    node_type: NodeType
    label: str
    status: NodeStatus
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_display_label(self) -> str:
        """获取显示标签（用于渲染）"""
        if self.node_type == NodeType.TOOL:
            status_icon = "✓" if self.status == NodeStatus.SUCCESS else "✗"
            return f"{status_icon} {self.label}"
        elif self.node_type == NodeType.FIELD:
            status_map = {
                NodeStatus.CORRECT: "✓",
                NodeStatus.INCORRECT: "✗",
                NodeStatus.UNCERTAIN: "?"
            }
            icon = status_map.get(self.status, "")
            conf = f"{self.confidence:.2f}" if self.confidence > 0 else ""
            return f"{icon} {self.label} {conf}".strip()
        else:
            return self.label


@dataclass
class ChainEdge:
    """推理链路边"""
    from_node: str
    to_node: str
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReasoningChain:
    """完整的推理链路"""
    entry_id: str
    report_id: str
    verdict: str
    nodes: List[ChainNode]
    edges: List[ChainEdge]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_node_by_id(self, node_id: str) -> Optional[ChainNode]:
        """根据 ID 获取节点"""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None
    
    def get_field_nodes(self) -> List[ChainNode]:
        """获取所有字段节点"""
        return [n for n in self.nodes if n.node_type == NodeType.FIELD]
    
    def get_tool_nodes(self) -> List[ChainNode]:
        """获取所有工具节点"""
        return [n for n in self.nodes if n.node_type == NodeType.TOOL]
    
    def get_failed_tools(self) -> List[ChainNode]:
        """获取失败的工具"""
        return [n for n in self.get_tool_nodes() 
                if n.status == NodeStatus.FAILED]
    
    def get_incorrect_fields(self) -> List[ChainNode]:
        """获取错误的字段"""
        return [n for n in self.get_field_nodes() 
                if n.status == NodeStatus.INCORRECT]


class ChainBuilder:
    """推理链路构建器"""
    
    FIELD_NAMES = [
        "entry_point", "critical_operation", "commit", "vuln_ids",
        "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace"
    ]
    
    def build(self, report: Dict[str, Any]) -> ReasoningChain:
        """从验证报告构建推理链路"""
        entry_id = report.get("entry_id", "unknown")
        report_id = report.get("report_id", "unknown")
        verdict = report.get("verdict", "uncertain")
        
        nodes: List[ChainNode] = []
        edges: List[ChainEdge] = []
        
        # 1. 创建规划节点
        plan_node = self._create_plan_node(report.get("plan", {}))
        if plan_node:
            nodes.append(plan_node)
        
        # 2. 创建工具节点
        tool_nodes, tool_evidence_map = self._create_tool_nodes(
            report.get("tool_trace", [])
        )
        nodes.extend(tool_nodes)
        
        # 3. 创建字段节点
        field_nodes = self._create_field_nodes(report.get("fields", {}))
        nodes.extend(field_nodes)
        
        # 4. 创建 self-check 节点
        self_check_node = self._create_self_check_node(
            report.get("self_check", {})
        )
        if self_check_node:
            nodes.append(self_check_node)
        
        # 5. 创建 verdict 节点
        verdict_node = self._create_verdict_node(verdict)
        nodes.append(verdict_node)
        
        # 6. 构建边：plan -> tools
        if plan_node:
            for tool_node in tool_nodes:
                edges.append(ChainEdge(
                    from_node=plan_node.node_id,
                    to_node=tool_node.node_id,
                    label="plan"
                ))
        
        # 7. 构建边：tools -> fields (based on evidence_refs)
        edges.extend(self._create_tool_field_edges(
            tool_nodes, field_nodes, tool_evidence_map
        ))
        
        # 8. 构建边：fields -> verdict
        for field_node in field_nodes:
            edges.append(ChainEdge(
                from_node=field_node.node_id,
                to_node=verdict_node.node_id
            ))
        
        # 9. 构建边：self_check -> verdict
        if self_check_node:
            edges.append(ChainEdge(
                from_node=self_check_node.node_id,
                to_node=verdict_node.node_id,
                label="validate"
            ))
        
        metadata = {
            "has_plan": plan_node is not None,
            "has_self_check": self_check_node is not None,
            "total_tools": len(tool_nodes),
            "failed_tools": len([n for n in tool_nodes if n.status == NodeStatus.FAILED]),
            "total_fields": len(field_nodes),
            "incorrect_fields": len([n for n in field_nodes if n.status == NodeStatus.INCORRECT])
        }
        
        return ReasoningChain(
            entry_id=entry_id,
            report_id=report_id,
            verdict=verdict,
            nodes=nodes,
            edges=edges,
            metadata=metadata
        )
    
    def _create_plan_node(self, plan: Dict[str, Any]) -> Optional[ChainNode]:
        """创建规划节点"""
        if not plan or not plan.get("tools_planned"):
            return None
        
        tools_planned = plan.get("tools_planned", [])
        fields_planned = plan.get("fields_planned", [])
        
        label = f"Plan\\n{len(tools_planned)} tools"
        
        return ChainNode(
            node_id="plan",
            node_type=NodeType.PLAN,
            label=label,
            status=NodeStatus.SUCCESS,
            metadata={
                "tools_planned": tools_planned,
                "fields_planned": fields_planned
            }
        )
    
    def _create_tool_nodes(self, tool_trace: List[Dict[str, Any]]) -> Tuple[List[ChainNode], Dict[str, List[str]]]:
        """创建工具节点，返回节点列表和工具->字段映射"""
        nodes = []
        evidence_map = {}  # tool_id -> [field_name]
        
        for call in tool_trace:
            seq = call.get("seq", 0)
            tool = call.get("tool", "unknown")
            ok = call.get("ok", True)
            error = call.get("error")
            input_data = call.get("input", {})
            evidence_refs = call.get("evidence_refs", [])
            
            # 提取简短的输入摘要
            input_summary = self._summarize_input(tool, input_data)
            
            # 构建标签
            if input_summary:
                label = f"{tool}\\n{input_summary}"
            else:
                label = tool
            
            # 确定状态
            status = NodeStatus.SUCCESS if ok else NodeStatus.FAILED
            
            node_id = f"tool_{seq}"
            
            nodes.append(ChainNode(
                node_id=node_id,
                node_type=NodeType.TOOL,
                label=label,
                status=status,
                metadata={
                    "seq": seq,
                    "tool": tool,
                    "ok": ok,
                    "error": error,
                    "input": input_data
                }
            ))
            
            # 提取受影响的字段
            affected_fields = self._extract_affected_fields(evidence_refs)
            evidence_map[node_id] = affected_fields
        
        return nodes, evidence_map
    
    def _create_field_nodes(self, fields: Dict[str, Any]) -> List[ChainNode]:
        """创建字段节点"""
        nodes = []
        
        for field_name in self.FIELD_NAMES:
            field_data = fields.get(field_name, {})
            status_str = field_data.get("status", "uncertain")
            confidence = field_data.get("confidence", 0.0)
            evidence = field_data.get("evidence", "")
            
            # 映射状态
            status_map = {
                "correct": NodeStatus.CORRECT,
                "incorrect": NodeStatus.INCORRECT,
                "uncertain": NodeStatus.UNCERTAIN
            }
            status = status_map.get(status_str, NodeStatus.UNCERTAIN)
            
            # 简化字段名显示
            label = field_name.replace("_", " ")
            
            nodes.append(ChainNode(
                node_id=f"field_{field_name}",
                node_type=NodeType.FIELD,
                label=label,
                status=status,
                confidence=confidence,
                metadata={
                    "field_name": field_name,
                    "evidence": evidence[:100] if evidence else ""
                }
            ))
        
        return nodes
    
    def _create_self_check_node(self, self_check: Dict[str, Any]) -> Optional[ChainNode]:
        """创建 self-check 节点"""
        if not self_check:
            return None
        
        status_str = self_check.get("status", "skipped")
        agree = self_check.get("agree", False)
        checked_fields = self_check.get("checked_fields", [])
        
        if status_str == "completed" and agree:
            status = NodeStatus.SUCCESS
        elif status_str == "completed" and not agree:
            status = NodeStatus.UNCERTAIN
        else:
            status = NodeStatus.FAILED
        
        label = f"Self Check\\n{len(checked_fields)} fields"
        
        return ChainNode(
            node_id="self_check",
            node_type=NodeType.SELF_CHECK,
            label=label,
            status=status,
            metadata={
                "agree": agree,
                "checked_fields": checked_fields
            }
        )
    
    def _create_verdict_node(self, verdict: str) -> ChainNode:
        """创建最终判定节点"""
        status_map = {
            "correct": NodeStatus.CORRECT,
            "incorrect": NodeStatus.INCORRECT,
            "uncertain": NodeStatus.UNCERTAIN
        }
        status = status_map.get(verdict, NodeStatus.UNCERTAIN)
        
        return ChainNode(
            node_id="verdict",
            node_type=NodeType.VERDICT,
            label=f"Verdict: {verdict}",
            status=status
        )
    
    def _create_tool_field_edges(
        self,
        tool_nodes: List[ChainNode],
        field_nodes: List[ChainNode],
        evidence_map: Dict[str, List[str]]
    ) -> List[ChainEdge]:
        """创建工具到字段的边"""
        edges = []
        
        for tool_node in tool_nodes:
            affected_fields = evidence_map.get(tool_node.node_id, [])
            
            for field_name in affected_fields:
                field_node_id = f"field_{field_name}"
                # 检查字段节点是否存在
                if any(n.node_id == field_node_id for n in field_nodes):
                    edges.append(ChainEdge(
                        from_node=tool_node.node_id,
                        to_node=field_node_id
                    ))
        
        return edges
    
    def _summarize_input(self, tool: str, input_data: Dict[str, Any]) -> str:
        """生成工具输入的简短摘要"""
        if tool == "read_advisory":
            report_id = input_data.get("report_id", "")
            if report_id:
                # 简化 ID 显示
                short_id = report_id.split("-")[-1] if "-" in report_id else report_id[-6:]
                return f"#{short_id}"
        
        elif tool == "checkout":
            project = input_data.get("project", "")
            commit = input_data.get("commit", "")
            if commit:
                return f"{project}:{commit[:7]}"
            elif project:
                return project
        
        elif tool == "read_file_lines":
            file_path = input_data.get("file", "")
            if file_path:
                filename = file_path.split("/")[-1] if "/" in file_path else file_path
                return filename
        
        return ""
    
    def _extract_affected_fields(self, evidence_refs: List[str]) -> List[str]:
        """从 evidence_refs 提取字段名"""
        fields = set()
        
        for ref in evidence_refs:
            if isinstance(ref, str) and "fields." in ref:
                parts = ref.split(".")
                if len(parts) >= 2 and parts[0] == "fields":
                    fields.add(parts[1])
        
        return list(fields)
