# -*- coding: utf-8 -*-
"""Compare PR1 fix_diff vs repo_wide run; export repo_wide_unique only."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PR1 = ROOT / "tools" / "fix_locations" / "out"
RW = PR1 / "repo_wide"


def load_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> int:
    pr1 = load_rows(PR1 / "fix_diff.csv")
    rw = load_rows(RW / "fix_diff.csv")
    nh = load_rows(RW / "needs_human.csv")
    pr1_keys = {(r["entry_id"], r["field_path"]) for r in pr1}
    rw_keys = {(r["entry_id"], r["field_path"]) for r in rw}
    only_rw = [r for r in rw if (r["entry_id"], r["field_path"]) not in pr1_keys]
    only_pr1 = [r for r in pr1 if (r["entry_id"], r["field_path"]) not in rw_keys]
    strat = Counter(r.get("strategy") for r in rw)
    reasons = Counter(r.get("reason") for r in nh)
    unique_rows = [r for r in rw if r.get("strategy") == "repo_wide_unique"]

    out_csv = RW / "repo_wide_only.csv"
    if unique_rows:
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=unique_rows[0].keys())
            w.writeheader()
            w.writerows(unique_rows)

    deg_pr1 = sum(
        1
        for r in load_rows(PR1 / "needs_human.csv")
        if r.get("reason") == "degenerate_snippet"
    )
    deg_rw = reasons.get("degenerate_snippet", 0)

    md = [
        "# DELTA — PR1 vs repo-wide full run\n\n",
        f"- PR1 fix_diff: **{len(pr1)}**\n",
        f"- repo_wide fix_diff: **{len(rw)}**\n",
        f"- strategies: `{dict(strat)}`\n",
        f"- `repo_wide_unique`: **{len(unique_rows)}**\n",
        f"- keys only in repo_wide run: **{len(only_rw)}**\n",
        f"- keys only in PR1 (missing in RW): **{len(only_pr1)}**\n",
        f"- needs_human (RW): **{len(nh)}** reasons=`{dict(reasons)}`\n",
        f"- degenerate PR1→RW: {deg_pr1} → {deg_rw} "
        f"{'OK (not eaten)' if deg_rw >= deg_pr1 else 'WARN dropped'}\n",
    ]
    (RW / "DELTA.md").write_text("".join(md), encoding="utf-8")
    summary = {
        "pr1_fixes": len(pr1),
        "rw_fixes": len(rw),
        "strategies": dict(strat),
        "repo_wide_unique": len(unique_rows),
        "only_rw": len(only_rw),
        "only_pr1": len(only_pr1),
        "needs_human": len(nh),
        "needs_human_reasons": dict(reasons),
        "degenerate_pr1": deg_pr1,
        "degenerate_rw": deg_rw,
    }
    (RW / "DELTA.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
