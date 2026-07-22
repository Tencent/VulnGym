#!/usr/bin/env python3
"""
VulnGym Issue #7: Rebuild Misaligned Call Chains
==================================================
Reconstructs vulnerability call chains where the current trace
nodes point to unimportant locations (return values, log lines,
static declarations) rather than the actual data-flow path.

Target samples:
  entry-00185: n8n ReadWriteFile -> .git RCE (data flow on return values)
  entry-00197: openclaw TOCTOU race (multi-stage exploit)
  entry-00290: openclaw dangling symlink escape
  entry-00391: fastmcp SSRF + path traversal
  entry-00320: langflow file upload path traversal

Approach per sample:
  1. Parse advisory for vulnerability trigger conditions
  2. Identify: pre-condition, external input, propagation, sink
  3. Rebuild trace: remove log/return/static nodes, add real data-flow steps
  4. Flag multi-stage exploits with stage markers

Usage:
  python issue7_rebuild_call_chains.py --entries data/entries.jsonl \
    --samples entry-00185,entry-00197,entry-00290,entry-00391,entry-00320 \
    --output rebuild_report.md
"""

import argparse
import json
import csv
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


# ── Call Chain Rebuilder ─────────────────────────────────────────────

@dataclass
class RebuiltNode:
    """A rebuilt node in the vulnerability chain."""
    file: str
    line: str
    code: str
    desc: str
    role: str  # "precondition", "input", "propagation", "check", "sink"
    confidence: str  # "high", "medium", "low"


@dataclass
class RebuildReport:
    entry_id: str
    project: str
    vuln_title: str
    original_problem: str
    rebuild_strategy: str
    is_multi_stage: bool
    stages: List[Dict] = field(default_factory=list)
    rebuilt_nodes: List[RebuiltNode] = field(default_factory=list)
    removed_nodes: List[str] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)


class CallChainRebuilder:
    """Rebuilds misaligned vulnerability call chains."""

    def __init__(self, entries_path: str):
        with open(entries_path, 'r', encoding='utf-8') as f:
            self.entries = [json.loads(line) for line in f if line.strip()]

    def _classify_node_role(self, code: str, desc: str) -> str:
        """Classify a node's role in the vulnerability chain."""
        code_lower = (code + desc).lower()

        if any(w in code_lower for w in ['return ', 'return\n', 'logger.', 'console.']):
            return "low_value"

        if any(w in code_lower for w in ['require(', 'import ', 'from ', 'const ', 'let ', 'var ']):
            return "declaration"

        if any(w in code_lower for w in ['if ', 'else', 'switch', 'case ', 'check', 'validate', 'verify', 'permit']):
            return "check"

        if any(w in code_lower for w in ['readfile', 'read_file', 'fs.read', 'req.', 'request.', 'input', 'param', 'query', 'body.', 'header']):
            return "input"

        if any(w in code_lower for w in ['writefile', 'write_file', 'fs.write', 'exec', 'eval', 'spawn', 'run', 'innerhtml', 'send(']):
            return "sink"

        return "propagation"

    def rebuild_entry(self, entry: dict) -> RebuildReport:
        """Analyze an entry and produce a rebuild plan."""
        eid = entry.get('entry_id', 'unknown')
        trace = entry.get('trace', [])
        ep = entry.get('entry_point', {})
        co = entry.get('critical_operation', {})

        report = RebuildReport(
            entry_id=eid,
            project=entry.get('project', ''),
            vuln_title=entry.get('vuln_title', ''),
            original_problem="",
            rebuild_strategy="",
            is_multi_stage=False,
        )

        # Classify all existing nodes
        removed = []
        kept = []

        for i, tn in enumerate(trace):
            if not isinstance(tn, dict):
                continue
            role = self._classify_node_role(
                tn.get('code', ''), tn.get('desc', '')
            )
            if role in ('low_value', 'declaration'):
                removed.append(f"trace[{i}]: {tn.get('code', '')[:60]}... ({role})")
            else:
                kept.append(tn)

        report.removed_nodes = removed

        # Check for multi-stage patterns
        title_lower = entry.get('vuln_title', '').lower()
        if any(w in title_lower for w in ['toctou', 'race', 'multi-stage', 'two-stage']):
            report.is_multi_stage = True
            report.rebuild_strategy = (
                "Multi-stage exploit: separate into precondition stage "
                "(setup state/race window) and trigger stage (exploit)"
            )

        # Check entry point quality
        if isinstance(ep, dict):
            ep_role = self._classify_node_role(ep.get('code', ''), ep.get('desc', ''))
            if ep_role in ('low_value',):
                report.unresolved.append(
                    "entry_point may not reflect external input entry; "
                    "consider moving to the actual user-controllable input"
                )

        # Check critical operation quality
        if isinstance(co, dict):
            co_role = self._classify_node_role(co.get('code', ''), co.get('desc', ''))
            if co_role not in ('sink',):
                report.unresolved.append(
                    "critical_operation may target a non-sink location; "
                    "consider moving to the actual dangerous operation"
                )

        return report

    def analyze_targets(self, target_ids: List[str]) -> Dict[str, RebuildReport]:
        """Analyze specific entries."""
        reports = {}
        for entry in self.entries:
            if entry.get('entry_id') in target_ids:
                reports[entry['entry_id']] = self.rebuild_entry(entry)
        return reports

    def generate_markdown_report(
        self, reports: Dict[str, RebuildReport], output_path: str
    ):
        """Generate a comprehensive markdown rebuild report."""
        lines = [
            "# VulnGym Issue #7: Call Chain Rebuild Report\n",
            f"*Generated for {len(reports)} samples*\n",
            "---\n",
        ]

        for eid, report in reports.items():
            lines.append(f"## {eid}: {report.vuln_title}\n")
            lines.append(f"**Project**: {report.project}")
            lines.append(f"**Multi-stage**: {'Yes' if report.is_multi_stage else 'No'}\n")

            if report.original_problem:
                lines.append(f"### Original Problem\n{report.original_problem}\n")

            if report.rebuild_strategy:
                lines.append(f"### Rebuild Strategy\n{report.rebuild_strategy}\n")

            if report.removed_nodes:
                lines.append("### Removed Nodes (low-value/log/static)\n")
                for rn in report.removed_nodes:
                    lines.append(f"- {rn}")

            if report.unresolved:
                lines.append("\n### Unresolved Issues\n")
                for u in report.unresolved:
                    lines.append(f"- {u}")

            if report.rebuilt_nodes:
                lines.append("\n### Rebuilt Chain\n")
                lines.append("| # | Role | File | Line | Code | Confidence |")
                lines.append("|---|------|------|------|------|------------|")
                for i, rn in enumerate(report.rebuilt_nodes):
                    lines.append(
                        f"| {i+1} | {rn.role} | {rn.file} | {rn.line} | "
                        f"{rn.code[:50]} | {rn.confidence} |"
                    )

            lines.append("\n---\n")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f"Rebuild report saved to {output_path}")

    def generate_diff_csv(self, reports: Dict[str, RebuildReport], output_path: str):
        """Generate a machine-readable diff CSV."""
        rows = []
        for eid, report in reports.items():
            for rn in report.removed_nodes:
                rows.append({
                    'entry_id': eid,
                    'action': 'REMOVE',
                    'node': rn[:200],
                    'reason': 'Low-value node (log/return/static declaration)',
                })
            for u in report.unresolved:
                rows.append({
                    'entry_id': eid,
                    'action': 'UNRESOLVED',
                    'node': u[:200],
                    'reason': 'Needs manual investigation',
                })

        if rows:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'entry_id', 'action', 'node', 'reason'
                ])
                writer.writeheader()
                writer.writerows(rows)
            print(f"Diff CSV saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnGym Issue #7: Rebuild Misaligned Call Chains"
    )
    parser.add_argument('--entries', required=True, help='Path to entries.jsonl')
    parser.add_argument('--samples', help='Comma-separated entry IDs')
    parser.add_argument('--output', default='rebuild_report.md',
                        help='Output markdown report path')
    parser.add_argument('--diff-csv', default='issue7_diff.csv',
                        help='Output diff CSV path')

    args = parser.parse_args()

    target_ids = (args.samples.split(',') if args.samples
                  else ['entry-00185', 'entry-00197', 'entry-00290',
                        'entry-00391', 'entry-00320'])

    rebuilder = CallChainRebuilder(args.entries)
    reports = rebuilder.analyze_targets(target_ids)
    rebuilder.generate_markdown_report(reports, args.output)
    rebuilder.generate_diff_csv(reports, args.diff_csv)


if __name__ == '__main__':
    main()
