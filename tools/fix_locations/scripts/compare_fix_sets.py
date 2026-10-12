# -*- coding: utf-8 -*-
"""Compare our fix_diff/needs_human against competitor PR CSVs (local analysis)."""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
OUT = HERE / "out"
COMP = OUT / "competitor_diffs"
OURS_FIX = OUT / "fix_diff.csv"
OURS_HUMAN = OUT / "needs_human.csv"


def load_keys(path: Path, *, fixed_only: bool = False) -> dict[tuple[str, str], dict]:
    rows: dict[tuple[str, str], dict] = {}
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            eid = (r.get("entry_id") or "").strip()
            fp = (r.get("field_path") or r.get("node_path") or "").strip()
            if not eid or not fp or fp == "*":
                continue
            status = (r.get("status") or "").strip().lower()
            if fixed_only and status and status not in {"fixed", "repaired", "ok_fixed"}:
                # some CSVs omit status and are fix-only
                if "new_line" not in r and "new_file" not in r:
                    continue
            key = (eid, fp)
            rows[key] = r
    return rows


def load_fix_set(path: Path) -> dict[tuple[str, str], dict]:
    """Treat every data row as a fix record (competitor fix_diff.csv)."""
    rows: dict[tuple[str, str], dict] = {}
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            eid = (r.get("entry_id") or "").strip()
            fp = (r.get("field_path") or r.get("node_path") or "").strip()
            if not eid or not fp or fp == "*":
                continue
            rows[(eid, fp)] = r
    return rows


def classify_our_fix(row: dict) -> str:
    old = str(row.get("old_line") or "")
    new = str(row.get("new_line") or "")
    old_f = str(row.get("old_file") or "")
    new_f = str(row.get("new_file") or "")
    if old_f and new_f and old_f != new_f:
        return "file_changed"
    # range expansion from single int to a-b starting at same line
    if old.isdigit() and "-" in new:
        start = new.split("-", 1)[0]
        if start == old:
            return "range_expand_same_start"
    if old != new:
        return "line_moved"
    return "other"


def main() -> None:
    ours = load_fix_set(OURS_FIX)
    comps = {
        "pr35": load_fix_set(COMP / "pr35_fix_diff.csv"),
        "pr39": load_fix_set(COMP / "pr39_fix_diff.csv"),
        "pr41": load_fix_set(COMP / "pr41_fix_diff.csv"),
    }

    lines: list[str] = []
    lines.append("# Fix-set overlap analysis (ours vs #35 / #39 / #41)\n\n")
    lines.append(
        "Purpose: explain why our auto-fix count (~102) can differ from "
        "conservative PRs (~14–19) without implying those PRs are 'wrong'.\n\n"
    )

    our_classes = Counter(classify_our_fix(r) for r in ours.values())
    lines.append("## Our fix_diff composition\n\n")
    lines.append(f"- total fix rows: **{len(ours)}**\n")
    for k, v in our_classes.most_common():
        lines.append(f"- `{k}`: {v}\n")
    lines.append("\n")

    for name, other in comps.items():
        inter = set(ours) & set(other)
        only_us = set(ours) - set(other)
        only_them = set(other) - set(ours)
        lines.append(f"## vs {name}\n\n")
        lines.append(f"- their fix rows: **{len(other)}**\n")
        lines.append(f"- intersection: **{len(inter)}**\n")
        lines.append(f"- only us: **{len(only_us)}**\n")
        lines.append(f"- only them: **{len(only_them)}**\n\n")

        # sample only-us by class
        class_only_us = Counter(classify_our_fix(ours[k]) for k in only_us)
        lines.append("### Only-us breakdown (by our classification)\n\n")
        for k, v in class_only_us.most_common():
            lines.append(f"- `{k}`: {v}\n")
        lines.append("\n### Examples only-us (up to 5)\n\n")
        for k in sorted(only_us)[:5]:
            r = ours[k]
            lines.append(
                f"- `{k[0]}` `{k[1]}`: {r.get('old_line')} → {r.get('new_line')} "
                f"({r.get('strategy') or r.get('reason')})\n"
            )
        lines.append("\n### Examples only-them (up to 5)\n\n")
        for k in sorted(only_them)[:5]:
            r = other[k]
            ol = r.get("old_line") or r.get("old_line_number") or ""
            nl = r.get("new_line") or r.get("new_line_number") or ""
            strat = r.get("strategy") or r.get("reason") or r.get("fix_strategy") or ""
            lines.append(f"- `{k[0]}` `{k[1]}`: {ol} → {nl} ({strat})\n")
        lines.append("\n")

    # Hypothesis section
    lines.append("## Working hypothesis (for PR narrative)\n\n")
    lines.append(
        "1. A large share of our fixes are **range expansions** "
        "(`N` → `N-M` with same start): the annotated `code` is multi-line, "
        "but `line` was a single start line. Conservative PRs may treat "
        "start-aligned spans as already acceptable, or normalize differently.\n"
        "2. We mark **degenerate snippets** (`}` etc.) as `needs_human` even "
        "when the line currently matches — reducing false confidence.\n"
        "3. Overlap with #41 (similar ~100 fixes) should be high if both expand "
        "ranges aggressively; overlap with #35/#39 should be smaller and "
        "concentrated on true line moves.\n"
        "4. This analysis does **not** prove our extras are all correct — "
        "human spot-check of `range_expand_same_start` is mandatory.\n"
    )

    # machine JSON summary
    summary = {
        "ours_total": len(ours),
        "ours_classes": dict(our_classes),
        "comparisons": {},
    }
    for name, other in comps.items():
        summary["comparisons"][name] = {
            "theirs": len(other),
            "intersection": len(set(ours) & set(other)),
            "only_us": len(set(ours) - set(other)),
            "only_them": len(set(other) - set(ours)),
            "only_us_classes": dict(
                Counter(classify_our_fix(ours[k]) for k in set(ours) - set(other))
            ),
        }

    out_md = OUT / "OVERLAP_ANALYSIS.md"
    out_json = OUT / "overlap_summary.json"
    out_md.write_text("".join(lines), encoding="utf-8")
    out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out_md}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
