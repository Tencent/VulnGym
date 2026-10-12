# -*- coding: utf-8 -*-
"""Export high-confidence fix subsets (Diff Pack item 6). Rules in DIFF_PACK_NIGHT_PLAN §4."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
from _diffpack_lib import (  # noqa: E402
    COMP,
    OUT,
    ROOT,
    apply_fix_to_entry,
    classify_our_fix,
    load_fix_csv,
    load_fix_mod,
    parse_line,
)

OURS = OUT / "fix_diff.csv"
HUMAN = OUT / "needs_human.csv"


def human_blocked() -> set[tuple[str, str]]:
    bad: set[tuple[str, str]] = set()
    if not HUMAN.is_file():
        return bad
    with HUMAN.open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            reason = r.get("reason") or ""
            eid = r.get("entry_id") or ""
            fp = r.get("field_path") or ""
            if "degenerate" in reason or reason.startswith("repo_fetch"):
                if fp and fp != "*":
                    bad.add((eid, fp))
                else:
                    # whole-entry fetch fail: block all keys for that entry from HC via entry set
                    bad.add((eid, "*"))
    return bad


def main() -> int:
    mod = load_fix_mod()
    ours = load_fix_csv(OURS)
    pr35 = set(load_fix_csv(COMP / "pr35_fix_diff.csv"))
    pr39 = set(load_fix_csv(COMP / "pr39_fix_diff.csv"))
    pr41 = set(load_fix_csv(COMP / "pr41_fix_diff.csv"))
    blocked = human_blocked()
    blocked_entries = {eid for eid, fp in blocked if fp == "*"}

    inter_conservative = (set(ours) & pr35) | (set(ours) & pr39)
    inter_41 = set(ours) & pr41

    r2a: list[tuple[tuple[str, str], dict]] = []
    r2b_candidates: list[tuple[tuple[str, str], dict]] = []

    for key, row in ours.items():
        eid, fp = key
        if eid in blocked_entries or key in blocked:
            continue
        cls = classify_our_fix(row)
        if cls == "line_moved" and key in inter_conservative and key in inter_41:
            r2a.append((key, row))
        elif cls == "range_expand_same_start" and key in inter_41:
            r2b_candidates.append((key, row))

    # R2b: idempotency check against cache (may skip if fetch fails)
    originals = {}
    with (ROOT / "data" / "entries.jsonl").open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                originals[e["entry_id"]] = e

    cache = ROOT / ".repo_cache"
    r2b: list[tuple[tuple[str, str], dict, str]] = []
    r2b_skip = 0
    for key, row in r2b_candidates:
        eid, fp = key
        e = originals[eid]
        node = None
        for path, n in mod.iter_nodes(e):
            if path == fp:
                node = n
                break
        if not node:
            r2b_skip += 1
            continue
        try:
            repo = mod.ensure_repo(e["repo_url"], e["commit"], cache)
        except Exception:
            r2b_skip += 1
            continue
        check = {
            "file": row.get("new_file") or row["old_file"],
            "line": parse_line(row.get("new_line") or row["old_line"]),
            "code": node["code"],
        }
        result = mod.repair_node(repo, check, allow_repo_wide=False)
        if result.status == "ok":
            r2b.append((key, row, "idempotent_ok"))
        else:
            r2b_skip += 1

    # Write CSVs
    fields = [
        "rule",
        "entry_id",
        "field_path",
        "class",
        "old_file",
        "old_line",
        "new_file",
        "new_line",
        "strategy",
        "note",
    ]

    def write_csv(path: Path, rows: list[dict]) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    hc_rows = []
    for key, row in sorted(r2a, key=lambda x: x[0]):
        hc_rows.append(
            {
                "rule": "R2a",
                "entry_id": key[0],
                "field_path": key[1],
                "class": "line_moved",
                "old_file": row.get("old_file"),
                "old_line": row.get("old_line"),
                "new_file": row.get("new_file"),
                "new_line": row.get("new_line"),
                "strategy": row.get("strategy"),
                "note": "line_moved ∩ (#35∪#39) ∩ #41",
            }
        )
    write_csv(OUT / "high_confidence_fixes.csv", hc_rows)

    range_rows = []
    for key, row, note in sorted(r2b, key=lambda x: x[0]):
        range_rows.append(
            {
                "rule": "R2b",
                "entry_id": key[0],
                "field_path": key[1],
                "class": "range_expand_same_start",
                "old_file": row.get("old_file"),
                "old_line": row.get("old_line"),
                "new_file": row.get("new_file"),
                "new_line": row.get("new_line"),
                "strategy": row.get("strategy"),
                "note": note,
            }
        )
    write_csv(OUT / "high_confidence_ranges.csv", range_rows)

    # JSONL: only entries touched by R2a (merge-friendly small set)
    fix_map = {k: v for k, v in ((key, row) for key, row in r2a)}
    touched_ids = sorted({k[0] for k in fix_map})
    with (OUT / "entries.high_confidence.jsonl").open("w", encoding="utf-8") as out:
        for eid in touched_ids:
            e = apply_fix_to_entry(originals[eid], fix_map, mod)
            # only apply R2a keys for this entry
            e2 = json.loads(json.dumps(originals[eid]))
            for path, node in mod.iter_nodes(e2):
                r = fix_map.get((eid, path))
                if not r:
                    continue
                if r.get("new_file"):
                    node["file"] = r["new_file"]
                if r.get("new_line") not in (None, ""):
                    node["line"] = parse_line(r["new_line"])
            out.write(json.dumps(e2, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "r2a_line_moved_count": len(r2a),
        "r2b_range_candidates": len(r2b_candidates),
        "r2b_range_passed_idempotency": len(r2b),
        "r2b_skipped": r2b_skip,
        "entries_in_high_confidence_jsonl": len(touched_ids),
        "inter_conservative_size": len(inter_conservative),
        "inter_41_size": len(inter_41),
        "too_small": len(r2a) == 0,
    }
    (OUT / "high_confidence_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = [
        "# High-confidence fix subsets\n\n",
        "Rules: `DIFF_PACK_NIGHT_PLAN.md` §4 (not relaxed).\n\n",
        f"- **R2a** `high_confidence_fixes.csv`: **{len(r2a)}** "
        f"(line_moved ∩ (#35∪#39) ∩ #41)\n",
        f"- **R2b** `high_confidence_ranges.csv`: **{len(r2b)}** passed idempotency "
        f"(of {len(r2b_candidates)} candidates; skipped={r2b_skip})\n",
        f"- `entries.high_confidence.jsonl`: **{len(touched_ids)}** entries "
        f"(R2a only — merge-friendly)\n\n",
        "R2b is optional accounting; do not treat as must-merge.\n",
    ]
    if summary["too_small"]:
        md.append("\n⚠️ R2a empty — see QUEUE_YELLOW; **do not relax rules at night**.\n")
    (OUT / "HIGH_CONFIDENCE.md").write_text("".join(md), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not summary["too_small"] else 2


if __name__ == "__main__":
    sys.exit(main())
