#!/usr/bin/env python3
"""Evaluate a tool's findings against the VulnGym ground truth.

Run from the repo root:
    python3 examples/evaluate.py examples/example_result.jsonl

What this script measures
-------------------------
VulnGym annotates every advisory with one or more (entry_point,
critical_operation[, trace]) tuples. This script reports how many
advisories a tool covers:

  - Advisory-level recall (primary):
        covered_advisories / total_usable_advisories
    An advisory is "covered" if the tool produces at least one finding that
    matches any one of the advisory's entries.

  - Entry-level recall (secondary):
        matched_entries / total_usable_entries
    A finer-grained view: it rewards tools that flag multiple distinct
    (entry_point, critical_operation) entries for the same advisory.

Both are recall-only. They do NOT penalize over-reporting; a tool can inflate
recall by emitting many low-confidence findings. Use this as a coverage /
recall study, not as a full precision-aware benchmark.

Matching policy
---------------
A single tool finding F = (entry_point_F, critical_operation_F) is said to
match a ground-truth entry E = (entry_point_E, critical_operation_E) iff
BOTH of the following hold:

  1. Paths are equal after normalization (strip leading './', unify '\\' to
     '/', collapse repeated slashes, case-sensitive).
  2. |line_F - line_E| <= tolerance, default 5.

Direction is strict: F.entry_point is compared to E.entry_point,
F.critical_operation to E.critical_operation.
If the tool reports the roles swapped, it counts as a miss. Use your tool's
configuration to align semantics before evaluating.

`line == 0` in ground truth means "unknown" (see SCHEMA.md); any entry
whose entry_point or critical_operation has line == 0 is dropped from both
numerator AND denominator (neither "usable" nor "covered"). Findings are NOT compared
across repo/commit — only entries sharing the same (repo_url, commit) as
the finding are candidates.

Input format (tool findings, JSONL)
-----------------------------------
Each line is a self-contained JSON object:

    {
      "repo_url": "https://github.com/org/repo",
      "commit":   "<40-hex sha>",
      "entry_point":          {"file": "...", "line": 123},
      "critical_operation":   {"file": "...", "line": 456},
      "trace":    [ ... ]        // optional; ignored by the matcher
    }

Optional extra keys (e.g. "finding_id", "note", "confidence") are allowed
and round-tripped into the per-finding detail report.

Output
------
A human-readable summary is written to stdout. When --json-out is supplied,
a structured report is also written to that path, including per-advisory
and per-finding detail.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENTRIES = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_TOLERANCE = 5


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------
_LEADING_DOT_SLASH = re.compile(r"^(?:\./)+")
_MULTI_SLASH = re.compile(r"/+")


def normalize_path(p: str) -> str:
    """Canonicalize a path for equality comparison.

    - Convert backslashes to forward slashes.
    - Strip one or more leading './'.
    - Collapse repeated slashes.
    - Do NOT lowercase — we target case-sensitive filesystems (Linux) which
      are the norm for server-side code.
    """
    if not isinstance(p, str):
        return ""
    p = p.replace("\\", "/")
    p = _LEADING_DOT_SLASH.sub("", p)
    p = _MULTI_SLASH.sub("/", p)
    return p


def normalize_commit(c: str) -> str:
    return c.strip().lower() if isinstance(c, str) else ""


def normalize_repo(r: str) -> str:
    """Normalize a repo URL to a key.

    We strip a trailing '.git', trailing '/', and lowercase the host portion
    only (owner/name stay case-sensitive since GitHub treats them that way
    at the API level even though URLs are redirected case-insensitively).
    """
    if not isinstance(r, str):
        return ""
    r = r.strip()
    if r.endswith(".git"):
        r = r[:-4]
    if r.endswith("/"):
        r = r[:-1]
    return r


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"{path}:{i}: invalid JSON: {e}") from None
    return rows


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def _endpoint_match(
    f_ep: dict, e_ep: dict, tolerance: int
) -> bool:
    """Match a single endpoint (entry_point-vs-entry_point or
    critical_operation-vs-critical_operation)."""
    if not f_ep or not e_ep:
        return False
    f_file = normalize_path(f_ep.get("file", ""))
    e_file = normalize_path(e_ep.get("file", ""))
    if not f_file or f_file != e_file:
        return False
    try:
        f_line = int(f_ep.get("line", 0))
        e_line = int(e_ep.get("line", 0))
    except (TypeError, ValueError):
        return False
    # line == 0 on the ground-truth side is handled upstream (that entry is
    # excluded). Defense-in-depth: reject a zero line here too.
    if e_line == 0:
        return False
    return abs(f_line - e_line) <= tolerance


def finding_matches_entry(
    finding: dict, entry: dict, tolerance: int
) -> bool:
    """Strict-direction match: entry_point↔entry_point AND
    critical_operation↔critical_operation within tolerance."""
    return (
        _endpoint_match(finding.get("entry_point", {}), entry.get("entry_point", {}), tolerance)
        and _endpoint_match(finding.get("critical_operation", {}), entry.get("critical_operation", {}), tolerance)
    )


# ---------------------------------------------------------------------------
# Evaluation core
# ---------------------------------------------------------------------------
def evaluate(
    entries: list[dict],
    findings: list[dict],
    tolerance: int,
) -> dict[str, Any]:
    # 1. Split ground-truth entries into usable / skipped.
    usable_entries: list[dict] = []
    skipped_entries: list[dict] = []
    for e in entries:
        src_line = e.get("entry_point", {}).get("line", 0)
        sink_line = e.get("critical_operation", {}).get("line", 0)
        if src_line == 0 or sink_line == 0:
            skipped_entries.append(e)
        else:
            usable_entries.append(e)

    # 2. Index usable entries by (repo, commit) for O(1) candidate lookup.
    by_repo_commit: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in usable_entries:
        key = (normalize_repo(e["repo_url"]), normalize_commit(e["commit"]))
        by_repo_commit[key].append(e)

    # 3. Group by report for advisory-level accounting.
    report_to_entries: dict[str, list[dict]] = defaultdict(list)
    for e in usable_entries:
        report_to_entries[e["report_id"]].append(e)

    # 4. Walk findings, record matches.
    matched_entry_ids: set[str] = set()
    finding_details: list[dict] = []  # per-finding record for the JSON report

    for i, f in enumerate(findings):
        rk = (normalize_repo(f.get("repo_url", "")), normalize_commit(f.get("commit", "")))
        matches: list[str] = []
        if rk[0] and rk[1]:
            for e in by_repo_commit.get(rk, ()):
                if finding_matches_entry(f, e, tolerance):
                    matches.append(e["entry_id"])
                    matched_entry_ids.add(e["entry_id"])
        finding_details.append(
            {
                "index": i,
                "finding_id": f.get("finding_id"),
                "repo_url": f.get("repo_url"),
                "commit": f.get("commit"),
                "entry_point": f.get("entry_point"),
                "critical_operation": f.get("critical_operation"),
                "matched_entry_ids": matches,
                "matched_report_ids": sorted(
                    {e["report_id"] for e in by_repo_commit.get(rk, ()) if e["entry_id"] in matches}
                ),
            }
        )

    # 5. Per-advisory detail.
    advisory_details: list[dict] = []
    covered_reports: set[str] = set()
    for rid, es in sorted(report_to_entries.items()):
        hit_entry_ids = sorted(e["entry_id"] for e in es if e["entry_id"] in matched_entry_ids)
        all_entry_ids = sorted(e["entry_id"] for e in es)
        covered = bool(hit_entry_ids)
        if covered:
            covered_reports.add(rid)
        advisory_details.append(
            {
                "report_id": rid,
                "num_usable_entries": len(es),
                "matched_entries": hit_entry_ids,
                "all_usable_entries": all_entry_ids,
                "covered": covered,
            }
        )

    # 6. Aggregate.
    total_usable_reports = len(report_to_entries)
    covered_advisories = len(covered_reports)
    total_usable_entries = len(usable_entries)
    matched_entries = len(matched_entry_ids)

    adv_recall = covered_advisories / total_usable_reports if total_usable_reports else 0.0
    entry_recall = matched_entries / total_usable_entries if total_usable_entries else 0.0

    return {
        "config": {
            "line_tolerance": tolerance,
            "match_path": "normalized_exact",
            "direction": "strict",
            "line_zero_policy": "skip",
        },
        "totals": {
            "ground_truth_entries": len(entries),
            "skipped_entries_line_zero": len(skipped_entries),
            "usable_entries": total_usable_entries,
            "usable_advisories": total_usable_reports,
            "findings": len(findings),
        },
        "recall": {
            "advisory_level": {
                "numerator": covered_advisories,
                "denominator": total_usable_reports,
                "value": adv_recall,
            },
            "entry_level": {
                "numerator": matched_entries,
                "denominator": total_usable_entries,
                "value": entry_recall,
            },
        },
        "advisories": advisory_details,
        "findings": finding_details,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_summary(report: dict, verbose: bool) -> None:
    cfg = report["config"]
    tot = report["totals"]
    adv = report["recall"]["advisory_level"]
    ent = report["recall"]["entry_level"]

    print("VulnGym evaluation")
    print("==================")
    print(
        f"policy: line_tolerance=±{cfg['line_tolerance']} | "
        f"path={cfg['match_path']} | direction={cfg['direction']} | "
        f"line=0 policy={cfg['line_zero_policy']}"
    )
    print()
    print(
        f"ground truth:  {tot['usable_advisories']} advisories / "
        f"{tot['usable_entries']} entries (skipped "
        f"{tot['skipped_entries_line_zero']} entries with line=0)"
    )
    print(f"findings:      {tot['findings']} reported by the tool")
    print()
    print(
        f"Advisory-level recall (primary): "
        f"{adv['numerator']} / {adv['denominator']} = "
        f"{adv['value']*100:.2f}%"
    )
    print(
        f"Entry-level recall    (secondary): "
        f"{ent['numerator']} / {ent['denominator']} = "
        f"{ent['value']*100:.2f}%"
    )

    unmatched_findings = [
        f for f in report["findings"] if not f["matched_entry_ids"]
    ]
    if unmatched_findings:
        print()
        print(
            f"note: {len(unmatched_findings)} of {tot['findings']} findings did "
            f"not match any ground-truth entry under this policy."
        )

    if verbose:
        print()
        print("per-advisory detail")
        print("-------------------")
        for a in report["advisories"]:
            flag = "HIT " if a["covered"] else "miss"
            hits = ",".join(a["matched_entries"]) if a["matched_entries"] else "-"
            print(
                f"  [{flag}] {a['report_id']}  "
                f"{len(a['matched_entries'])}/{a['num_usable_entries']} entries  "
                f"matched=[{hits}]"
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Evaluate a VulnGym tool submission (coverage / recall only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "findings",
        type=Path,
        help="Path to a JSONL file of tool findings.",
    )
    p.add_argument(
        "--entries",
        type=Path,
        default=DEFAULT_ENTRIES,
        help=f"Ground-truth entries.jsonl (default: {DEFAULT_ENTRIES.relative_to(REPO_ROOT)}).",
    )
    p.add_argument(
        "--line-tolerance",
        type=int,
        default=DEFAULT_TOLERANCE,
        help="Max |Δline| allowed on entry_point or critical_operation (default: %(default)s).",
    )
    p.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write the full structured report as JSON.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print per-advisory hit/miss table.",
    )
    args = p.parse_args(argv)

    if args.line_tolerance < 0:
        p.error("--line-tolerance must be >= 0")

    entries = load_jsonl(args.entries)
    findings = load_jsonl(args.findings)

    report = evaluate(entries, findings, tolerance=args.line_tolerance)
    print_summary(report, verbose=args.verbose)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        with args.json_out.open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\nwrote JSON report → {args.json_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
