#!/usr/bin/env python3
"""
VulnGym Issue #8: Config-Type/Non-Taint Vulnerability Annotation Guide
=======================================================================
Provides annotation principles and automated fix suggestions for
configuration-type vulnerabilities (Dockerfile misconfigs, permission
issues, non-taint-class bugs) that don't fit the traditional
"input -> propagation -> sink" taint-flow model.

Target samples:
  entry-00241/00242/00243/00244: OpenClaw Dockerfile privilege issues

Key questions addressed:
  1. Where should entry_point point in a config vuln?
  2. Where should critical_operation point?
  3. Should trace express config-declaration-to-effect path?
  4. How to annotate when no traditional "flow" exists?

Usage:
  python issue8_config_vuln_annotation.py --entries data/entries.jsonl \
    --samples entry-00241,entry-00242,entry-00243,entry-00244 \
    --output config_vuln_annotation.md
"""

import argparse
import json
import csv
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


# ── Annotation Principles ────────────────────────────────────────────

CONFIG_VULN_ANNOTATION_GUIDE = """
# Config-Type / Non-Taint Vulnerability Annotation Guide

## When to Use These Guidelines

Use when the vulnerability:
1. Stems from a configuration file (Dockerfile, yaml, toml, json, env)
2. Is a permission/privilege issue (overly permissive, running as root)
3. Is a static misconfiguration (not depending on runtime input)
4. Has no traditional taint flow (input -> propagate -> sink)

## Annotation Principles

### entry_point
For config-type vulnerabilities, the entry_point SHOULD point to:
  - **Priority 1**: The configuration declaration that creates the vulnerability
    (e.g., the `USER root` line, the `chmod 777` line)
  - **Priority 2**: The build/initialization entry that activates the config
    (e.g., the `CMD` or `ENTRYPOINT` in a Dockerfile)
  - **NOT**: An unrelated function or runtime handler

For Dockerfile samples specifically:
  - Good: `USER root` (the config that grants unnecessary privilege)
  - Good: `CMD ["node", "server.js"]` (runs with excessive privilege)
  - Bad: An arbitrary JS function that is not the config entry point

### critical_operation
For config-type vulnerabilities, the critical_operation SHOULD point to:
  - **Priority 1**: The dangerous configuration directive itself
    (e.g., `USER root`, `RUN chmod 777 /`, `--privileged`)
  - **Priority 2**: The point where the configuration takes effect
    (e.g., the command that runs with elevated privileges)
  - **Priority 3**: The exploitable consequence
    (e.g., file write that enables code execution)

### trace
For config-type vulnerabilities, the trace MAY:
  - Express the chain from config declaration to config effect:
    `Dockerfile directive -> build process -> runtime activation -> exploit consequence`
  - Be SHORTER than taint-flow traces (often 1-3 nodes)
  - Be EMPTY if the config itself directly constitutes the vulnerability
  - Include EXPLANATORY desc values describing WHY each step matters

## Decision Tree

```
Is the vulnerability caused by a configuration file?
  YES -> Use config annotation guidelines
    Is it a Dockerfile/similar?
      YES -> entry_point = privileged config line
             critical_operation = dangerous directive or execution point
             trace = config -> effect chain (if helpful)
      NO  -> Adapt principles to config format
  NO  -> Is it a taint-flow vuln?
    YES -> Use standard entry -> propagation -> sink model
    NO  -> See non-taint annotation below

## Non-Taint, Non-Config Vulnerabilities

For vulns like TOCTOU races, permission bypasses, or logic errors:
- entry_point = where attacker-controlled state enters
- critical_operation = where the missing check/enforcement occurs
- trace = key state transitions (not necessarily data flow)
"""


@dataclass
class ConfigVulnFix:
    entry_id: str
    field: str  # entry_point, critical_operation, trace
    original_value: str
    suggested_value: str
    rationale: str
    confidence: str  # high, medium, low


class ConfigVulnAnnotator:
    """Applies config-type vulnerability annotation guidelines."""

    DOCKERFILE_PATTERNS = [
        (r'^USER\s+', 'User directive'),
        (r'^RUN\s+', 'Build-time command'),
        (r'^CMD\s+', 'Runtime command'),
        (r'^ENTRYPOINT\s+', 'Entrypoint'),
        (r'^FROM\s+', 'Base image'),
        (r'^COPY\s+|^ADD\s+', 'File copy'),
        (r'^EXPOSE\s+', 'Port exposure'),
        (r'^ENV\s+', 'Environment variable'),
        (r'^WORKDIR\s+', 'Working directory'),
    ]

    def __init__(self, entries_path: str):
        with open(entries_path, 'r', encoding='utf-8') as f:
            self.entries = [json.loads(line) for line in f if line.strip()]

    def is_dockerfile(self, entry: dict) -> bool:
        """Check if entry refers to a Dockerfile."""
        for node in ['entry_point', 'critical_operation']:
            n = entry.get(node, {})
            if isinstance(n, dict):
                f = n.get('file', '').lower()
                if 'dockerfile' in f:
                    return True
        # Check trace too
        trace = entry.get('trace', [])
        if isinstance(trace, list):
            for tn in trace:
                if isinstance(tn, dict):
                    f = tn.get('file', '').lower()
                    if 'dockerfile' in f:
                        return True
        return False

    def classify_dockerfile_line(self, code: str) -> str:
        """Classify a Dockerfile line."""
        for pattern, label in self.DOCKERFILE_PATTERNS:
            import re
            if re.match(pattern, code.strip()):
                return label
        return "Other"

    def analyze_entry(self, entry: dict) -> List[ConfigVulnFix]:
        """Analyze a config-type vulnerability entry."""
        fixes = []
        eid = entry.get('entry_id', 'unknown')
        is_df = self.is_dockerfile(entry)

        if not is_df:
            return fixes

        ep = entry.get('entry_point', {})
        co = entry.get('critical_operation', {})

        # Check entry_point
        if isinstance(ep, dict):
            ep_code = ep.get('code', '')
            ep_class = self.classify_dockerfile_line(ep_code)
            if ep_class not in ('User directive', 'Runtime command', 'Entrypoint'):
                fixes.append(ConfigVulnFix(
                    entry_id=eid, field='entry_point',
                    original_value=ep_code[:100],
                    suggested_value="",
                    rationale=(
                        f"Current entry_point classified as '{ep_class}'. "
                        "For Dockerfile privilege vulns, entry_point should "
                        "point to the privilege-granting directive (e.g., USER root) "
                        "or the runtime command that executes with excessive privilege."
                    ),
                    confidence='medium',
                ))

        # Check critical_operation
        if isinstance(co, dict):
            co_code = co.get('code', '')
            co_class = self.classify_dockerfile_line(co_code)
            if co_class not in ('User directive', 'Runtime command', 'Build-time command'):
                fixes.append(ConfigVulnFix(
                    entry_id=eid, field='critical_operation',
                    original_value=co_code[:100],
                    suggested_value="",
                    rationale=(
                        f"Current critical_operation classified as '{co_class}'. "
                        "Should be the dangerous directive (USER root, RUN chmod, "
                        "--privileged flag) or the execution point that enables "
                        "the privilege escalation."
                    ),
                    confidence='medium',
                ))

        return fixes

    def analyze_targets(self, target_ids: List[str]) -> Dict:
        """Analyze specific target entries."""
        results = {}
        for entry in self.entries:
            if entry.get('entry_id') in target_ids:
                fixes = self.analyze_entry(entry)
                results[entry['entry_id']] = {
                    'project': entry.get('project'),
                    'is_dockerfile': self.is_dockerfile(entry),
                    'vuln_title': entry.get('vuln_title'),
                    'fixes': [asdict(f) for f in fixes],
                }
        return results

    def generate_guide(self, output_path: str):
        """Write the annotation guide to a file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(CONFIG_VULN_ANNOTATION_GUIDE)
        print(f"Annotation guide saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnGym Issue #8: Config-Type Vulnerability Annotation"
    )
    parser.add_argument('--entries', required=True, help='Path to entries.jsonl')
    parser.add_argument('--samples', help='Comma-separated entry IDs')
    parser.add_argument('--output', default='config_vuln_annotation.md',
                        help='Output guide path')
    parser.add_argument('--fixes-json', default='issue8_fixes.json',
                        help='Fix recommendations JSON')

    args = parser.parse_args()

    target_ids = (args.samples.split(',') if args.samples
                  else ['entry-00241', 'entry-00242', 'entry-00243', 'entry-00244'])

    annotator = ConfigVulnAnnotator(args.entries)
    annotator.generate_guide(args.output)

    results = annotator.analyze_targets(target_ids)
    with open(args.fixes_json, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Fix recommendations saved to {args.fixes_json}")

    # Summary
    print(f"\nAnalyzed {len(results)} samples:")
    for eid, data in results.items():
        print(f"  {eid} ({data['project']}): {len(data['fixes'])} fix suggestions, "
              f"is_dockerfile={data['is_dockerfile']}")


if __name__ == '__main__':
    main()
