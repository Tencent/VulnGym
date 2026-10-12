# -*- coding: utf-8 -*-
"""Build a stratified ≥20-row human spot-check sheet from existing CSVs."""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parents[1]
OUT = HERE / "out"
ENTRIES = ROOT / "data" / "entries.jsonl"
FIX = OUT / "fix_diff.csv"
HUMAN = OUT / "needs_human.csv"
TARGET = 22  # ≥20 with a little spare


def load_entries() -> dict[str, dict]:
    m = {}
    with ENTRIES.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            m[e["entry_id"]] = e
    return m


def cache_dir(repo_url: str) -> str:
    parts = repo_url.rstrip("/").split("/")
    org, name = parts[-2], parts[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return f".repo_cache/{org}__{name}"


def main() -> None:
    entries = load_entries()
    fix_rows = list(csv.DictReader(FIX.open(encoding="utf-8")))
    human_rows = list(csv.DictReader(HUMAN.open(encoding="utf-8")))

    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in fix_rows:
        strat = (r.get("strategy") or r.get("reason") or "").strip()
        old = str(r.get("old_line") or "")
        new = str(r.get("new_line") or "")
        if old.isdigit() and "-" in new and new.split("-", 1)[0] == old:
            buckets["fixed_range_expand"].append(r)
        elif strat == "neighborhood_pm5":
            buckets["fixed_neighborhood"].append(r)
        elif strat == "whole_file":
            buckets["fixed_whole_file"].append(r)
        else:
            buckets["fixed_other"].append(r)

    for r in human_rows:
        reason = r.get("reason") or ""
        if reason.startswith("repo_fetch"):
            buckets["human_fetch_failed"].append(r)
        elif "degenerate" in reason:
            buckets["human_degenerate"].append(r)
        elif "no_unique" in reason:
            buckets["human_no_unique"].append(r)
        else:
            buckets["human_other"].append(r)

    # quota plan totaling TARGET
    plan = [
        ("fixed_neighborhood", 6),
        ("fixed_range_expand", 6),
        ("fixed_whole_file", 4),
        ("human_no_unique", 3),
        ("human_degenerate", 2),
        ("human_fetch_failed", 1),
    ]

    chosen: list[tuple[str, dict]] = []
    seen: set[tuple[str, str]] = set()
    for bucket, n in plan:
        rows = buckets.get(bucket) or []
        # diversify by entry_id
        by_eid: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            by_eid[r["entry_id"]].append(r)
        picked = 0
        for eid in sorted(by_eid):
            if picked >= n:
                break
            for r in by_eid[eid]:
                key = (r["entry_id"], r.get("field_path") or "")
                if key in seen:
                    continue
                seen.add(key)
                chosen.append((bucket, r))
                picked += 1
                break

    # ensure official priority ids appear if present in CSVs
    priority = {"entry-00103", "entry-00320", "entry-00511", "entry-00185"}
    for r in human_rows + fix_rows:
        if r["entry_id"] in priority:
            key = (r["entry_id"], r.get("field_path") or "")
            if key not in seen and len(chosen) < TARGET + 4:
                reason = r.get("reason") or r.get("strategy") or "priority"
                chosen.append((f"priority:{reason[:40]}", r))
                seen.add(key)

    out_csv = OUT / "SPOTCHECK_SHEET.csv"
    fields = [
        "bucket",
        "entry_id",
        "field_path",
        "repo_url",
        "commit",
        "cache_path",
        "checkout_cmd",
        "old_file",
        "old_line",
        "new_file",
        "new_line",
        "status_or_reason",
        "strategy",
        "pass",
        "notes",
    ]
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for bucket, r in chosen:
            e = entries.get(r["entry_id"], {})
            repo = e.get("repo_url", "")
            commit = e.get("commit", "")
            cache = cache_dir(repo) if repo else ""
            w.writerow(
                {
                    "bucket": bucket,
                    "entry_id": r["entry_id"],
                    "field_path": r.get("field_path", ""),
                    "repo_url": repo,
                    "commit": commit,
                    "cache_path": cache,
                    "checkout_cmd": (
                        f'git -C "{cache}" checkout --force {commit}' if cache and commit else ""
                    ),
                    "old_file": r.get("old_file", ""),
                    "old_line": r.get("old_line", ""),
                    "new_file": r.get("new_file", ""),
                    "new_line": r.get("new_line", ""),
                    "status_or_reason": r.get("reason") or r.get("status") or "",
                    "strategy": r.get("strategy", ""),
                    "pass": "",
                    "notes": "",
                }
            )

    md = OUT / "SPOTCHECK_SHEET.md"
    md_lines = [
        "# 人工抽查表（分层 ≥20）\n\n",
        f"生成自当前 `fix_diff.csv` / `needs_human.csv`，共 **{len(chosen)}** 行。\n\n",
        "## 怎么验\n\n",
        "1. 对每一行执行 `checkout_cmd`（**换 entry 必 checkout**）\n",
        "2. 打开 `cache_path` 下对应文件\n",
        "3. 用标注 `code`（见 entries.jsonl 该节点）对照源码行；**勿用 IDE Ctrl+Z 历史**\n",
        "4. `pass` 填 `yes`/`no`；`range_expand` 重点看：扩成 N-M 后是否整段等于 code\n\n",
        "## 行清单\n\n",
        "| # | bucket | entry | field | old→new | strategy/reason |\n",
        "|---|--------|-------|-------|---------|------------------|\n",
    ]
    for i, (bucket, r) in enumerate(chosen, 1):
        md_lines.append(
            f"| {i} | {bucket} | `{r['entry_id']}` | `{r.get('field_path')}` | "
            f"{r.get('old_line')}→{r.get('new_line') or '-'} | "
            f"{r.get('strategy') or r.get('reason')} |\n"
        )
    md_lines.append(f"\n详细可编辑表：[`SPOTCHECK_SHEET.csv`](./SPOTCHECK_SHEET.csv)\n")
    md.write_text("".join(md_lines), encoding="utf-8")
    print(f"Wrote {out_csv} rows={len(chosen)}")
    print(f"Wrote {md}")
    for bucket, _ in plan:
        print(f"  available {bucket}: {len(buckets.get(bucket) or [])}")


if __name__ == "__main__":
    main()
