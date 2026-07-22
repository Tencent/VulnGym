#!/usr/bin/env python3
"""
VulnGym Issue #4: Fix Code Snippet Location Deviations
=======================================================
Automatically repair {file, line} mismatches in entries.jsonl by
searching the actual source code at the vulnerable commit.

For each node (entry_point, critical_operation, trace[*]):
  1. Check if {file, line, code} matches at the target commit.
  2. If mismatched, search for 'code' in expanding scope:
     - +/- 5 lines around original line
     - Full file search
     - Whole repo search
  3. Update file/line if unique match found.
  4. Log ambiguous or unfixable cases to needs_human.csv.

Usage:
  python issue4_fix_code_locations.py --entries data/entries.jsonl \
    --repos-dir /path/to/checked-out-repos \
    --output entries.fixed.jsonl
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


# ── Data Structures ──────────────────────────────────────────────────

@dataclass
class FixRecord:
    """Records a single {file, line} correction."""
    entry_id: str
    field_path: str          # e.g. "entry_point", "trace[2]"
    original_file: str
    original_line: str
    new_file: str
    new_line: str
    original_desc: str
    new_desc: str
    strategy: str            # "local_5", "full_file", "repo_search", "manual"

@dataclass
class HumanReviewItem:
    """Records a case that needs manual review."""
    entry_id: str
    field_path: str
    reason: str
    candidates: str


# ── Code Search Engine ───────────────────────────────────────────────

class CodeLocationFixer:
    """Fixes code snippet location mismatches in VulnGym entries."""

    def __init__(self, repos_dir: str, entries_path: str):
        self.repos_dir = repos_dir
        self.entries = self._load_entries(entries_path)
        self.fixes: List[FixRecord] = []
        self.needs_human: List[HumanReviewItem] = []

    def _load_entries(self, path: str) -> List[dict]:
        entries = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        return entries

    def _normalize_code(self, code: str) -> str:
        """Normalize code for comparison: strip whitespace, normalize tabs."""
        return '\n'.join(
            line.strip()
            for line in code.strip().split('\n')
        ).replace('\t', '    ')

    def _read_file_lines(self, repo_path: str, file_path: str) -> Optional[List[str]]:
        """Read a file from the checked-out repo."""
        full_path = os.path.join(repo_path, file_path)
        if not os.path.exists(full_path):
            return None
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                return f.readlines()
        except Exception:
            return None

    def _search_in_lines(
        self, lines: List[str], code: str, around_line: int = None
    ) -> List[int]:
        """Search for code in a list of lines. Returns matching line numbers (1-based)."""
        norm_code = self._normalize_code(code)
        code_lines = norm_code.split('\n')

        matches = []
        search_range = range(len(lines) - len(code_lines) + 1)

        if around_line is not None:
            # Narrow search: +/- 5 lines
            lo = max(0, around_line - 6)
            hi = min(len(lines), around_line + 5)
            search_range = range(lo, hi)

        for i in search_range:
            window = '\n'.join(
                l.strip() for l in lines[i:i + len(code_lines)]
            )
            if window == norm_code:
                matches.append(i + 1)  # 1-based

        return matches

    def _search_in_repo(
        self, repo_path: str, code: str
    ) -> List[Tuple[str, int]]:
        """Search for code across all files in a repo."""
        norm_code = self._normalize_code(code)
        matches = []

        for root, dirs, files in os.walk(repo_path):
            # Skip .git and large directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]

            for filename in files:
                if filename.endswith(('.py', '.js', '.ts', '.jsx', '.tsx',
                                      '.java', '.go', '.rs', '.c', '.cpp',
                                      '.h', '.hpp', '.rb', '.php', '.cs',
                                      '.vue', '.svelte', '.tf', '.yaml',
                                      '.yml', '.json', '.xml', '.sh',
                                      '.dockerfile', '.dockerfile', 'Dockerfile',
                                      '.toml', '.cfg', '.ini', '.conf')):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                            lines = f.readlines()
                        line_matches = self._search_in_lines(lines, code)
                        for lm in line_matches:
                            rel_path = os.path.relpath(filepath, repo_path)
                            matches.append((rel_path, lm))
                    except Exception:
                        continue

        return matches

    def fix_node(
        self,
        entry_id: str,
        field_path: str,
        node: dict,
        repo_path: str,
    ) -> Optional[dict]:
        """
        Attempt to fix a single node's {file, line} if it doesn't match.
        Returns corrected node or None if unfixable.
        """
        if not isinstance(node, dict):
            return None

        file_path = node.get('file', '')
        line = node.get('line', 0)
        code = node.get('code', '')

        if not file_path or not code:
            return None

        # Parse line (handle both int and "start-end" string)
        if isinstance(line, str) and '-' in line:
            line_num = int(line.split('-')[0])
        else:
            line_num = int(line) if line else 0

        lines = self._read_file_lines(repo_path, file_path)
        if lines is None:
            # File not found — search entire repo
            matches = self._search_in_repo(repo_path, code)
            if len(matches) == 1:
                new_file, new_line = matches[0]
                return self._build_fixed_node(
                    entry_id, field_path, node,
                    file_path, str(line), new_file, str(new_line),
                    'repo_search'
                )
            elif len(matches) > 1:
                self.needs_human.append(HumanReviewItem(
                    entry_id=entry_id,
                    field_path=field_path,
                    reason=f"Multiple matches in repo ({len(matches)} files)",
                    candidates=str(matches[:5])
                ))
                return None
            else:
                self.needs_human.append(HumanReviewItem(
                    entry_id=entry_id,
                    field_path=field_path,
                    reason=f"File not found: {file_path}",
                    candidates=""
                ))
                return None

        # Check if current location matches
        local_matches = self._search_in_lines(lines, code, around_line=line_num)
        if line_num in local_matches:
            return None  # Already correct

        # Strategy 1: Search +/- 5 lines
        nearby = self._search_in_lines(lines, code, around_line=line_num)
        if len(nearby) == 1:
            return self._build_fixed_node(
                entry_id, field_path, node,
                file_path, str(line), file_path, str(nearby[0]),
                'local_5'
            )

        # Strategy 2: Full file search
        full_file = self._search_in_lines(lines, code)
        if len(full_file) == 1:
            return self._build_fixed_node(
                entry_id, field_path, node,
                file_path, str(line), file_path, str(full_file[0]),
                'full_file'
            )

        # Strategy 3: Repo-wide search
        repo_matches = self._search_in_repo(repo_path, code)
        if len(repo_matches) == 1:
            new_file, new_line = repo_matches[0]
            return self._build_fixed_node(
                entry_id, field_path, node,
                file_path, str(line), new_file, str(new_line),
                'repo_search'
            )

        # Cannot fix
        reason = (f"Multiple matches ({len(full_file)} in file, "
                  f"{len(repo_matches)} in repo)")
        self.needs_human.append(HumanReviewItem(
            entry_id=entry_id,
            field_path=field_path,
            reason=reason,
            candidates=str(repo_matches[:5])
        ))
        return None

    def _build_fixed_node(
        self, entry_id, field_path, original_node,
        orig_file, orig_line, new_file, new_line, strategy
    ) -> dict:
        """Build a corrected node and record the fix."""
        fixed = dict(original_node)
        fixed['file'] = new_file
        fixed['line'] = int(new_line) if new_line.isdigit() else new_line

        self.fixes.append(FixRecord(
            entry_id=entry_id,
            field_path=field_path,
            original_file=orig_file,
            original_line=orig_line,
            new_file=new_file,
            new_line=new_line,
            original_desc=original_node.get('desc', ''),
            new_desc=original_node.get('desc', ''),
            strategy=strategy,
        ))
        return fixed

    def process_all(self, target_entry_ids: Optional[List[str]] = None) -> List[dict]:
        """Process all entries, optionally filtered by entry_id list."""
        fixed_entries = []

        for entry in self.entries:
            eid = entry.get('entry_id', '')
            if target_entry_ids and eid not in target_entry_ids:
                fixed_entries.append(entry)
                continue

            repo_path = os.path.join(
                self.repos_dir,
                entry.get('project', 'unknown'),
            )

            # Fix entry_point
            ep = entry.get('entry_point')
            if isinstance(ep, dict):
                fixed_ep = self.fix_node(eid, 'entry_point', ep, repo_path)
                if fixed_ep:
                    entry = dict(entry)
                    entry['entry_point'] = fixed_ep

            # Fix critical_operation
            co = entry.get('critical_operation')
            if isinstance(co, dict):
                fixed_co = self.fix_node(eid, 'critical_operation', co, repo_path)
                if fixed_co:
                    entry = dict(entry)
                    entry['critical_operation'] = fixed_co

            # Fix trace nodes
            trace = entry.get('trace', [])
            if isinstance(trace, list):
                new_trace = []
                for i, tn in enumerate(trace):
                    if isinstance(tn, dict):
                        fixed_tn = self.fix_node(eid, f'trace[{i}]', tn, repo_path)
                        new_trace.append(fixed_tn if fixed_tn else tn)
                    else:
                        new_trace.append(tn)
                if new_trace != trace:
                    entry = dict(entry)
                    entry['trace'] = new_trace

            fixed_entries.append(entry)

        return fixed_entries

    def save_results(
        self,
        fixed_entries: List[dict],
        output_jsonl: str,
        fix_diff_csv: str,
        human_review_csv: str,
    ):
        """Save all outputs."""
        # Fixed JSONL
        with open(output_jsonl, 'w', encoding='utf-8') as f:
            for entry in fixed_entries:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        print(f"Fixed entries saved to {output_jsonl}")

        # Fix diff CSV
        if self.fixes:
            with open(fix_diff_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'entry_id', 'field_path', 'original_file', 'original_line',
                    'new_file', 'new_line', 'original_desc', 'new_desc', 'strategy'
                ])
                writer.writeheader()
                for fix in self.fixes:
                    writer.writerow(asdict(fix))
            print(f"Fix diff saved to {fix_diff_csv} ({len(self.fixes)} fixes)")

        # Human review CSV
        if self.needs_human:
            with open(human_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'entry_id', 'field_path', 'reason', 'candidates'
                ])
                writer.writeheader()
                for item in self.needs_human:
                    writer.writerow(asdict(item))
            print(f"Human review items saved to {human_csv} ({len(self.needs_human)} items)")
        else:
            print("No human review items needed")


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VulnGym Issue #4: Fix Code Snippet Location Deviations"
    )
    parser.add_argument('--entries', required=True, help='Path to entries.jsonl')
    parser.add_argument('--repos-dir', required=True,
                        help='Directory containing checked-out repos')
    parser.add_argument('--entry-ids', nargs='*',
                        help='Specific entry IDs to process (default: all verify=0)')
    parser.add_argument('--output', default='entries.fixed.jsonl',
                        help='Output JSONL path')
    parser.add_argument('--fix-diff', default='fix_diff.csv',
                        help='Fix diff CSV path')
    parser.add_argument('--human-review', default='needs_human.csv',
                        help='Human review CSV path')

    args = parser.parse_args()

    fixer = CodeLocationFixer(args.repos_dir, args.entries)

    target_ids = args.entry_ids
    if not target_ids:
        # Default: process all verify=0 entries
        target_ids = [
            e['entry_id'] for e in fixer.entries
            if e.get('verify') == 0
        ]
        print(f"Processing {len(target_ids)} verify=0 entries: {target_ids}")

    fixed = fixer.process_all(target_ids)
    fixer.save_results(args.output, args.fix_diff, args.human_review)

    print(f"\nSummary: {len(fixer.fixes)} fixes applied, "
          f"{len(fixer.needs_human)} need human review")


if __name__ == '__main__':
    main()
