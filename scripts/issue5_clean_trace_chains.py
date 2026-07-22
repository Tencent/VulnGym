#!/usr/bin/env python3
"""
VulnGym Issue #5: Clean Up Trace Chain Ordering Anomalies
==========================================================
Detects and fixes structural issues in trace chains:
  - Duplicate nodes: {file, line, code} triples that repeat
  - Order anomalies: trace nodes outside [entry_point, critical_operation] range
  - Cross-file trace nodes (preserved as-is)

Two modes:
  - Conservative: detect and report only (default)
  - Fix: auto-remove out-of-bounds nodes, merge duplicates

Usage:
  python issue5_clean_trace_chains.py --entries data/entries.jsonl \
    --mode fix --output entries.trace_fixed.jsonl
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


# ── Data Structures ──────────────────────────────────────────────────

@dataclass
class TraceIssue:
    entry_id: str
    issue_type: str       # "duplicate", "before_entry", "after_critical", "cross_file"
    detail: str
    node_indices: List[int]  # Affected trace indices
    action: str            # "merged", "removed", "logged", "skipped"

@dataclass
class TraceReport:
    total_entries: int
    entries_with_issues: int
    duplicates_found: int
    before_entry_found: int
    after_critical_found: int
    auto_fixed: int
    manual_review: int


class TraceChainCleaner:
    """Detects and fixes trace chain ordering anomalies."""

    def __init__(self, entries_path: str):
        with open(entries_path, 'r', encoding='utf-8') as f:
            self.entries = [json.loads(line) for line in f if line.strip()]
        self.issues: List[TraceIssue] = []
        self.report = TraceReport(
            total_entries=len(self.entries),
            entries_with_issues=0, duplicates_found=0,
            before_entry_found=0, after_critical_found=0,
            auto_fixed=0, manual_review=0,
        )

    def _parse_line(self, line_val) -> int:
        """Parse line value (int or 'start-end' string) to integer start line."""
        if isinstance(line_val, int):
            return line_val
        if isinstance(line_val, str) and '-' in line_val:
            return int(line_val.split('-')[0])
        try:
            return int(line_val)
        except (ValueError, TypeError):
            return 0

    def _node_key(self, node: dict) -> str:
        """Generate a dedup key for a trace node."""
        return f"{node.get('file','')}:{node.get('line','')}:{node.get('code','')[:80]}"

    def _is_same_file(self, node1: dict, node2: dict) -> bool:
        return node1.get('file', '') == node2.get('file', '')

    def check_entry(self, entry: dict, mode: str = 'conservative') -> Tuple[dict, List[TraceIssue]]:
        """Check and optionally fix a single entry's trace chain."""
        entry_issues = []
        eid = entry.get('entry_id', 'unknown')
        trace = entry.get('trace', [])
        ep = entry.get('entry_point', {})
        co = entry.get('critical_operation', {})

        if not trace or not isinstance(trace, list):
            return entry, entry_issues

        entry_file = ep.get('file', '') if isinstance(ep, dict) else ''
        ep_line = self._parse_line(ep.get('line', 0)) if isinstance(ep, dict) else 0
        co_line = self._parse_line(co.get('line', 0)) if isinstance(co, dict) else float('inf')

        new_trace = []
        seen_keys = set()
        removed_indices = set()

        for i, node in enumerate(trace):
            if not isinstance(node, dict):
                new_trace.append(node)
                continue

            node_file = node.get('file', '')
            key = self._node_key(node)

            # Check 1: Duplicate detection
            if key in seen_keys:
                entry_issues.append(TraceIssue(
                    entry_id=eid, issue_type='duplicate',
                    detail=f"Duplicate node at trace[{i}]: {key[:60]}",
                    node_indices=[i], action='merged' if mode == 'fix' else 'logged',
                ))
                if mode == 'fix':
                    removed_indices.add(i)
                    continue

            seen_keys.add(key)

            # Check 2: Cross-file — skip order checking
            if node_file != entry_file:
                entry_issues.append(TraceIssue(
                    entry_id=eid, issue_type='cross_file',
                    detail=f"Cross-file node at trace[{i}]: {node_file}",
                    node_indices=[i], action='skipped',
                ))
                new_trace.append(node)
                continue

            node_line = self._parse_line(node.get('line', 0))

            # Check 3: Before entry_point (same file)
            if node_file == entry_file and node_line > 0 and node_line < ep_line:
                entry_issues.append(TraceIssue(
                    entry_id=eid, issue_type='before_entry',
                    detail=f"trace[{i}] at line {node_line} before entry_point at line {ep_line}",
                    node_indices=[i],
                    action='removed' if mode == 'fix' else 'logged',
                ))
                if mode == 'fix':
                    removed_indices.add(i)
                    continue

            # Check 4: After critical_operation (same file)
            if node_file == entry_file and co_line > 0 and node_line > co_line:
                entry_issues.append(TraceIssue(
                    entry_id=eid, issue_type='after_critical',
                    detail=f"trace[{i}] at line {node_line} after critical_operation at line {co_line}",
                    node_indices=[i],
                    action='removed' if mode == 'fix' else 'logged',
                ))
                if mode == 'fix':
                    removed_indices.add(i)
                    continue

            new_trace.append(node)

        # Update stats
        if entry_issues:
            self.report.entries_with_issues += 1
            for iss in entry_issues:
                if iss.issue_type == 'duplicate':
                    self.report.duplicates_found += 1
                elif iss.issue_type == 'before_entry':
                    self.report.before_entry_found += 1
                elif iss.issue_type == 'after_critical':
                    self.report.after_critical_found += 1
                if iss.action in ('merged', 'removed'):
                    self.report.auto_fixed += 1
                elif iss.action == 'logged':
                    self.report.manual_review += 1

        self.issues.extend(entry_issues)

        if mode == 'fix' and removed_indices:
            entry = dict(entry)
            entry['trace'] = new_trace

        return entry, entry_issues

    def process_all(self, mode: str = 'conservative') -> List[dict]:
        """Process all entries."""
        fixed_entries = []
        for entry in self.entries:
            fixed_entry, _ = self.check_entry(entry, mode)
            fixed_entries.append(fixed_entry)
        return fixed_entries

    def save_results(
        self, fixed_entries: List[dict],
        output_jsonl: str, log_csv: str, log_json: str,
    ):
        with open(output_jsonl, 'w', encoding='utf-8') as f:
            for entry in fixed_entries:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')

        with open(log_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'entry_id', 'issue_type', 'detail', 'node_indices', 'action'
            ])
            writer.writeheader()
            for iss in self.issues:
                writer.writerow(asdict(iss))

        with open(log_json, 'w', encoding='utf-8') as f:
            json.dump({
                'report': asdict(self.report),
                'issues': [asdict(i) for i in self.issues],
            }, f, indent=2, ensure_ascii=False)

        print(f"Fixed entries: {output_jsonl}")
        print(f"Issue log: {log_csv}, {log_json}")
        print(f"\nReport: {json.dumps(asdict(self.report), indent=2)}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnGym Issue #5: Clean Up Trace Chain Ordering Anomalies"
    )
    parser.add_argument('--entries', required=True, help='Path to entries.jsonl')
    parser.add_argument('--mode', choices=['conservative', 'fix'],
                        default='conservative', help='Processing mode')
    parser.add_argument('--output', default='entries.trace_fixed.jsonl')
    parser.add_argument('--log-csv', default='trace_fix_log.csv')
    parser.add_argument('--log-json', default='trace_fix_log.json')

    args = parser.parse_args()

    cleaner = TraceChainCleaner(args.entries)
    fixed = cleaner.process_all(args.mode)
    cleaner.save_results(fixed, args.output, args.log_csv, args.log_json)


if __name__ == '__main__':
    main()
