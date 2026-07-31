#!/usr/bin/env python3
"""
VulnGym entries.jsonl data quality fixer.

For each entry_point / critical_operation / trace[*] node, verifies
{file, line, code} against the actual source repo at the specified commit,
and fixes line numbers / file paths / desc fields where unambiguous.

Usage:
    python tools/fix_entries.py --dry-run          # precheck only, no repos needed
    python tools/fix_entries.py                    # full check + fix
    python tools/fix_entries.py --all               # process all entries (not just verify=0)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from collections import Counter
from collections import defaultdict
from pathlib import Path
from typing import Any

# Add tools/ to path so fixlib imports work
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))

from fixlib.loader import load_jsonl, save_jsonl, collect_all_nodes, normalize_line, format_line
from fixlib.matcher import CodeMatcher
from fixlib.desc_updater import DescUpdater
from fixlib.models import FixRecord, HumanRecord, StructuralRecord
from fixlib.repo_manager import RepoManager
from fixlib.reporter import Reporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("fix_entries")

# Default paths
REPO_ROOT = _THIS_DIR.parent
DEFAULT_ENTRIES = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "output"
DEFAULT_CACHE = Path.home() / ".cache" / "vulngym" / "repos"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fix VulnGym entries.jsonl data quality issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--entries", type=Path, default=DEFAULT_ENTRIES,
        help=f"Path to entries.jsonl (default: {DEFAULT_ENTRIES})",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--repo-cache", type=Path, default=DEFAULT_CACHE,
        help=f"Git bare-clone cache directory (default: {DEFAULT_CACHE})",
    )
    parser.add_argument(
        "--all", dest="process_all", action="store_true",
        help="Process all entries (default: only verify=0)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Precheck only — skip repo cloning and matching (no network needed)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Phase 1: Load data
    # ------------------------------------------------------------------
    logger.info("Loading entries from %s", args.entries)
    entries = load_jsonl(args.entries)
    logger.info("Loaded %d entries", len(entries))

    # Filter to target entries
    if args.process_all:
        target_entries = entries
        logger.info("Processing ALL %d entries", len(target_entries))
    else:
        target_entries = [e for e in entries if e.get("verify") == 0]
        logger.info("Processing %d verify=0 entries (use --all for all entries)",
                     len(target_entries))

    # ------------------------------------------------------------------
    # Phase 2: Precheck + structural analysis (always runs, fast, no repos)
    # ------------------------------------------------------------------
    logger.info("Phase 2: Precheck and structural analysis ...")
    matcher = CodeMatcher(None)  # No repo needed for precheck

    precheck_human: list[HumanRecord] = []
    structural_records: list[StructuralRecord] = []

    # Build index of all entries for structural checks
    entries_map: dict[str, dict] = {e["entry_id"]: e for e in entries}

    # Track which entries have self-referencing traces
    for entry in entries:
        entry_id = entry.get("entry_id", "?")
        ep = entry.get("entry_point", {})
        co = entry.get("critical_operation", {})
        trace = entry.get("trace", [])

        has_ref, ref_type = matcher.check_self_reference(ep, co, trace)
        if has_ref:
            structural_records.append(StructuralRecord(
                entry_id=entry_id,
                issue_type=ref_type,
                detail=f"trace[0]==entry_point and/or trace[-1]==critical_operation",
            ))

    # Precheck: detect unmatchable/empty/truncated code
    for entry in target_entries:
        entry_id = entry.get("entry_id", "?")
        repo_url = entry.get("repo_url", "")
        commit = entry.get("commit", "")

        for node_path, node in collect_all_nodes(entry):
            code = node.get("code", "")
            reason = matcher._precheck(code)
            if reason:
                precheck_human.append(HumanRecord(
                    entry_id=entry_id,
                    node_path=node_path,
                    reason_code=reason,
                    detail=f"Precheck failed: {reason}",
                    original_file=node.get("file", ""),
                    original_line=str(node.get("line", "")),
                    original_code_preview=code[:80],
                ))

    logger.info("Precheck: %d nodes need human review (unmatchable/empty/truncated)",
                len(precheck_human))
    logger.info("Structural: %d entries have self-referencing traces",
                len(structural_records))

    if args.dry_run:
        # Write dry-run outputs and exit
        reporter = Reporter(args.output_dir)
        reporter.write_needs_human(precheck_human)
        reporter.write_structural_report(structural_records)
        reporter.write_readme(
            total_entries=len(entries),
            verify0_count=len(target_entries),
            fix_records=[],
            human_records=precheck_human,
            structural_records=structural_records,
        )
        logger.info("Dry-run complete. Output written to %s", args.output_dir)
        logger.info("  needs_human.csv: %d records", len(precheck_human))
        logger.info("  structural_report.csv: %d records", len(structural_records))
        return 0

    # ------------------------------------------------------------------
    # Phase 3: Clone repos
    # ------------------------------------------------------------------
    logger.info("Phase 3: Ensuring repositories are available ...")
    repo_mgr = RepoManager(args.repo_cache)
    matcher = CodeMatcher(repo_mgr)  # Recreate with real repo manager
    desc_updater = DescUpdater()

    # Collect unique repos needed
    needed_repos: dict[str, set[str]] = defaultdict(set)  # repo_url → {commit, ...}
    for entry in target_entries:
        needed_repos[entry["repo_url"]].add(entry["commit"])

    repo_success: dict[str, bool] = {}
    t0 = time.time()
    for repo_url in sorted(needed_repos):
        ok = repo_mgr.ensure_repo(repo_url)
        repo_success[repo_url] = ok
        if not ok:
            logger.warning("Failed to clone %s — entries from this repo will be skipped",
                           repo_url)
    elapsed = time.time() - t0
    n_ok = sum(1 for v in repo_success.values() if v)
    logger.info("Repo setup: %d/%d repos available (%.1fs)", n_ok, len(repo_success), elapsed)

    # ------------------------------------------------------------------
    # Phase 4: Match and fix
    # ------------------------------------------------------------------
    logger.info("Phase 4: Matching and fixing nodes ...")
    fix_records: list[FixRecord] = []
    match_human: list[HumanRecord] = []
    fixed_entries = []  # All 408 entries, some modified

    # Build a dict of entry_id → entry for all entries
    all_entries_map = {e["entry_id"]: e for e in entries}

    # Process target entries only
    for i, entry in enumerate(target_entries):
        entry_id = entry.get("entry_id", "?")
        repo_url = entry.get("repo_url", "")
        commit = entry.get("commit", "")

        if i % 10 == 0 or i == len(target_entries) - 1:
            logger.info("  Processing entry %d/%d: %s ...", i + 1, len(target_entries), entry_id)

        # Check repo availability
        if not repo_success.get(repo_url, False):
            for node_path, node in collect_all_nodes(entry):
                match_human.append(HumanRecord(
                    entry_id=entry_id,
                    node_path=node_path,
                    reason_code="REPO_UNAVAILABLE",
                    detail=f"Repository {repo_url} could not be cloned",
                    original_file=node.get("file", ""),
                    original_line=str(node.get("line", "")),
                    original_code_preview=node.get("code", "")[:80],
                ))
            continue

        for node_path, node in collect_all_nodes(entry):
            result = matcher.check_node(entry_id, node_path, node, repo_url, commit)

            if result.status == "needs_human":
                match_human.append(HumanRecord(
                    entry_id=entry_id,
                    node_path=node_path,
                    reason_code=result.needs_human_reason,
                    detail=result.detail if hasattr(result, 'detail') and result.detail else "",
                    original_file=result.original_file,
                    original_line=str(result.original_line_raw),
                    original_code_preview=result.original_code[:80],
                ))
                continue

            # Apply fixes
            if result.status in ("exact_match",):
                # No change needed
                pass

            elif result.status in ("fixed_line", "fixed_file"):
                new_start, new_end = result.new_line_range
                new_file = result.new_file
                old_line_raw = result.original_line_raw
                new_line_raw = format_line(new_start, new_end)

                # Update node in entry dict
                if result.status == "fixed_file" and new_file:
                    node["file"] = new_file
                    fix_records.append(FixRecord(
                        entry_id=entry_id, node_path=node_path,
                        field="file",
                        old_value=result.original_file,
                        new_value=new_file,
                        strategy=result.strategy,
                    ))

                if new_line_raw != old_line_raw:
                    node["line"] = new_line_raw
                    fix_records.append(FixRecord(
                        entry_id=entry_id, node_path=node_path,
                        field="line",
                        old_value=str(old_line_raw),
                        new_value=str(new_line_raw),
                        strategy=result.strategy,
                    ))

                # Update desc if location changed
                old_start, old_end = result.original_line_range
                new_desc = desc_updater.update_desc(
                    result.original_desc,
                    result.original_file, old_start, old_end,
                    node.get("file", result.original_file),
                    new_start, new_end,
                )
                if new_desc is not None:
                    node["desc"] = new_desc
                    fix_records.append(FixRecord(
                        entry_id=entry_id, node_path=node_path,
                        field="desc",
                        old_value=(result.original_desc or "")[:80],
                        new_value=new_desc[:80],
                        strategy="desc_sync",
                    ))

        # Update entry in the map
        all_entries_map[entry_id] = entry

    # Build final entries list (sorted by entry_id)
    final_entries = [all_entries_map[eid] for eid in sorted(all_entries_map.keys())]

    # ------------------------------------------------------------------
    # Phase 5: Merge human records
    # ------------------------------------------------------------------
    # Precheck results go first, then match results
    all_human = precheck_human + match_human

    # ------------------------------------------------------------------
    # Phase 6: Write outputs
    # ------------------------------------------------------------------
    logger.info("Phase 6: Writing outputs ...")
    reporter = Reporter(args.output_dir)

    reporter.write_fixed_jsonl(final_entries)
    logger.info("  entries.fixed.jsonl: %d entries", len(final_entries))

    reporter.write_fix_diff(fix_records)
    logger.info("  fix_diff.csv: %d changes", len(fix_records))

    reporter.write_needs_human(all_human)
    logger.info("  needs_human.csv: %d records", len(all_human))

    reporter.write_structural_report(structural_records)
    logger.info("  structural_report.csv: %d records", len(structural_records))

    reporter.write_readme(
        total_entries=len(entries),
        verify0_count=len(target_entries),
        fix_records=fix_records,
        human_records=all_human,
        structural_records=structural_records,
    )
    logger.info("  README.md: written")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    logger.info("=" * 50)
    logger.info("Summary:")
    logger.info("  Total entries:        %d", len(entries))
    logger.info("  Processed (verify=0): %d", len(target_entries))
    logger.info("  Auto-fixes:           %d", len(fix_records))
    logger.info("  Needs human review:   %d", len(all_human))
    logger.info("  Structural warnings:  %d", len(structural_records))

    if fix_records:
        strat_counts = Counter(r.strategy for r in fix_records)
        logger.info("  Fix strategies: %s",
                     ", ".join(f"{k}={v}" for k, v in strat_counts.most_common()))

    if all_human:
        reason_counts = Counter(r.reason_code for r in all_human)
        logger.info("  Human-review reasons: %s",
                     ", ".join(f"{k}={v}" for k, v in reason_counts.most_common()))

    logger.info("Output written to %s", args.output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
