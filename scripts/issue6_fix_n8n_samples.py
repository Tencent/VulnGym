#!/usr/bin/env python3
"""
VulnGym Issue #6: Fix n8n Sandbox Escape Sample Entry Points
==============================================================
Re-examines the entry_point, critical_operation, and trace for
n8n-related security vulnerabilities where the current annotations
may point to sanitizers, static lists, or non-execution points.

Target samples:
  entry-00099/00100: Workflow Expression Sandbox Escape (RCE sink on sanitizer?)
  entry-00103: Webhook XSS/CSP bypass (critical_operation re-confirm)
  entry-00176: Python Code node sandbox escape (crit op on static list)
  entry-00511/00512: VM expression engine sandbox escape

Approach:
  1. Load advisory + entry metadata
  2. Check each node against known vulnerability patterns
  3. Flag suspicious nodes: sanitizers, static lists, log lines, non-exec lines
  4. Provide recommended replacements with reasoning

Usage:
  python issue6_fix_n8n_samples.py --entries data/entries.jsonl \
    --samples entry-00099,entry-00100,entry-00103,entry-00176,entry-00511
"""

import argparse
import json
import csv
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


# ── Vulnerability Pattern Matchers ───────────────────────────────────

# Code patterns that suggest a node is NOT a valid critical_operation
SUSPICIOUS_SINK_PATTERNS = [
    (r'\bsanitiz', 'sanitizer/validation function (not a sink)'),
    (r'\bescape\b', 'escaping function (not a sink)'),
    (r'\bencode\b', 'encoding function (not a sink)'),
    (r'\bvalidate\b', 'validation function (not a sink)'),
    (r'console\.(log|error|warn|debug|info)', 'console logging (not a sink)'),
    (r'logger\.(info|debug|warn|error|trace)', 'logger call (not a sink)'),
    (r'\bassert\b', 'assertion (not a sink)'),
    (r'^\s*//|^\s*#|^\s*\*', 'comment line (not executable)'),
    (r'^\s*import\b|^\s*from\b|^\s*require\b', 'import statement (not a sink)'),
    (r'^\s*const\s+\w+\s*=\s*\[', 'static list/array declaration'),
    (r'^\s*const\s+\w+\s*=\s*\{', 'static object declaration'),
]

ENTRY_POINT_PATTERNS = [
    (r'\b(req\.|request\.|req\.body|req\.params|req\.query)', 'HTTP request input'),
    (r'\b(userInput|user_input|inputData|input_data)', 'User input variable'),
    (r'\b(postMessage|onmessage|addEventListener)', 'Event-based input'),
    (r'\b(readFile|read_file|fs\.read)', 'File system input'),
    (r'\b(process\.env|process\.argv)', 'Environment/CLI input'),
]

CRITICAL_OP_PATTERNS = [
    (r'\b(eval|Function\(|exec\(|spawn\(|execSync\()', 'Code execution'),
    (r'\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)', 'DOM injection'),
    (r'\b(vm\.run|vm\.compile|new vm\.Script)', 'VM sandbox execution'),
    (r'\b(child_process|subprocess|os\.system)', 'System command execution'),
    (r'\b(fs\.writeFile|fs\.unlink|fs\.rmdir)', 'File system modification'),
    (r'\b(\.send\(|\.json\(|res\.end\()', 'HTTP response output'),
]


@dataclass
class NodeAssessment:
    """Assessment of a single vulnerability node."""
    entry_id: str
    node_type: str          # "entry_point", "critical_operation", "trace[N]"
    current_code: str
    current_file: str
    current_line: str
    issues: List[str] = field(default_factory=list)
    confidence: str = "high"  # high, medium, low
    recommendation: str = ""
    suggested_code: str = ""
    suggested_file: str = ""
    suggested_line: str = ""
    reasoning: str = ""


class N8nSampleAnalyzer:
    """Analyzes and recommends fixes for n8n vulnerability samples."""

    def __init__(self, entries_path: str):
        with open(entries_path, 'r', encoding='utf-8') as f:
            self.entries = [json.loads(line) for line in f if line.strip()]
        self.assessments: List[NodeAssessment] = []

    def _match_patterns(self, code: str, patterns: List[Tuple[str, str]]) -> List[str]:
        """Check code against a list of patterns, return matching descriptions."""
        matches = []
        for pattern, description in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                matches.append(description)
        return matches

    def assess_node(
        self, entry_id: str, node_type: str, node: dict,
        vuln_category: str = ""
    ) -> NodeAssessment:
        """Assess a single node and generate recommendations."""
        code = node.get('code', '')
        file_path = node.get('file', '')
        line = str(node.get('line', ''))
        desc = node.get('desc', '')

        assessment = NodeAssessment(
            entry_id=entry_id,
            node_type=node_type,
            current_code=code[:200],
            current_file=file_path,
            current_line=line,
        )

        if node_type == 'entry_point':
            ep_matches = self._match_patterns(code, ENTRY_POINT_PATTERNS)
            if not ep_matches:
                assessment.issues.append(
                    "No recognizable entry point pattern found "
                    "(no request input, user input, event handler, or file read)"
                )
                assessment.confidence = "low"
            else:
                assessment.recommendation = (
                    f"Entry point confirmed: {', '.join(ep_matches)}"
                )
                assessment.confidence = "high"

        elif node_type == 'critical_operation':
            susp = self._match_patterns(code, SUSPICIOUS_SINK_PATTERNS)
            crit = self._match_patterns(code, CRITICAL_OP_PATTERNS)

            if susp and not crit:
                assessment.issues.append(
                    f"Code matches sanitizer/utility patterns: {', '.join(susp)}. "
                    "This may not be the actual vulnerability sink."
                )
                assessment.confidence = "low"
                assessment.recommendation = (
                    "Move critical_operation downstream to the actual "
                    "dangerous operation (code execution, file write, DOM injection)"
                )
            elif crit:
                assessment.recommendation = f"Sink confirmed: {', '.join(crit)}"
                assessment.confidence = "high"
            else:
                assessment.confidence = "medium"

        elif node_type.startswith('trace'):
            susp = self._match_patterns(code, SUSPICIOUS_SINK_PATTERNS)
            if susp and 'console' in str(susp).lower():
                assessment.issues.append(
                    f"Trace node appears to be a log/console statement, "
                    "not a meaningful data-flow step"
                )
                assessment.recommendation = "Consider removing from trace chain"
                assessment.confidence = "low"

        self.assessments.append(assessment)
        return assessment

    def analyze_entry(self, entry: dict) -> List[NodeAssessment]:
        """Analyze all nodes in an entry."""
        eid = entry.get('entry_id', 'unknown')
        cat = entry.get('vuln_category_l1', '')
        results = []

        # Entry point
        ep = entry.get('entry_point')
        if isinstance(ep, dict):
            results.append(self.assess_node(eid, 'entry_point', ep, cat))

        # Critical operation
        co = entry.get('critical_operation')
        if isinstance(co, dict):
            results.append(self.assess_node(eid, 'critical_operation', co, cat))

        # Trace nodes
        trace = entry.get('trace', [])
        if isinstance(trace, list):
            for i, tn in enumerate(trace):
                if isinstance(tn, dict):
                    results.append(self.assess_node(eid, f'trace[{i}]', tn, cat))

        return results

    def analyze_targets(self, target_ids: List[str]) -> Dict:
        """Analyze specific target entries."""
        results = {}
        for entry in self.entries:
            if entry.get('entry_id') in target_ids:
                assessments = self.analyze_entry(entry)
                results[entry['entry_id']] = {
                    'project': entry.get('project'),
                    'vuln_title': entry.get('vuln_title'),
                    'vuln_category': entry.get('vuln_category_l1'),
                    'assessments': [asdict(a) for a in assessments],
                }
        return results

    def save_report(self, target_ids: List[str], output_path: str):
        """Generate and save analysis report."""
        results = self.analyze_targets(target_ids)

        report = {
            'summary': {
                'total_samples_analyzed': len(results),
                'samples_with_issues': sum(
                    1 for r in results.values()
                    if any(
                        a['confidence'] == 'low'
                        for a in r['assessments']
                    )
                ),
            },
            'samples': results,
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Analysis report saved to {output_path}")

        # Print summary
        print(f"\n{'='*60}")
        print("Issue #6: n8n Sample Analysis Summary")
        print(f"{'='*60}")
        for eid, data in results.items():
            issues = sum(1 for a in data['assessments'] if a.get('issues'))
            print(f"  {eid} ({data['project']}): {len(data['assessments'])} nodes, "
                  f"{issues} with issues")
            for a in data['assessments']:
                if a.get('issues'):
                    print(f"    [{a['node_type']}] {a['issues'][0][:80]}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnGym Issue #6: Fix n8n Sandbox Escape Samples"
    )
    parser.add_argument('--entries', required=True, help='Path to entries.jsonl')
    parser.add_argument('--samples', help='Comma-separated entry IDs to analyze')
    parser.add_argument('--output', default='issue6_n8n_analysis.json',
                        help='Output report path')

    args = parser.parse_args()

    target_ids = (args.samples.split(',') if args.samples
                  else ['entry-00099', 'entry-00100', 'entry-00103',
                        'entry-00176', 'entry-00511', 'entry-00512'])

    analyzer = N8nSampleAnalyzer(args.entries)
    analyzer.save_report(target_ids, args.output)


if __name__ == '__main__':
    main()
