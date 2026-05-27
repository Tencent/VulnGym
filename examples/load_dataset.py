#!/usr/bin/env python3
"""Minimal loader examples for the VulnGym dataset.

Run from the repo root:
    python3 examples/load_dataset.py

The dataset ships as two JSONL files under data/:
    data/reports.jsonl   — one row per GitHub Advisory (report-level)
    data/entries.jsonl   — one row per entry point (can be >1 per advisory)

entries.report_id ↔ reports.report_id is the join key.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


# ---------------------------------------------------------------------------
# 1. Pure stdlib — stream a JSONL file line by line.
# ---------------------------------------------------------------------------
def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def demo_stdlib() -> None:
    reports = list(iter_jsonl(DATA / "reports.jsonl"))
    entries = list(iter_jsonl(DATA / "entries.jsonl"))
    print(f"[stdlib] {len(reports)} reports / {len(entries)} entries")

    # Human-audit subset (verify == 1).
    verified = [e for e in entries if e.get("verify") == 1]
    verified_reports = {e["report_id"] for e in verified}
    print(f"[stdlib] human-audited: {len(verified)} entries / "
          f"{len(verified_reports)} advisories (verify == 1)")

    # Join entries under their report_id.
    by_report: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        by_report[e["report_id"]].append(e)

    # Show the report with the most entry points.
    biggest = max(reports, key=lambda r: r["num_entries"])
    print(f"[stdlib] biggest report: {biggest['report_id']}  "
          f"num_entries={biggest['num_entries']}  title={biggest['vuln_title']!r}")
    for e in by_report[biggest["report_id"]][:2]:
        ep, co = e["entry_point"], e["critical_operation"]
        print(f"  - {e['entry_id']}:  {ep['file']}:{ep['line']}  "
              f"→  {co['file']}:{co['line']}  verify={e.get('verify')}")


# ---------------------------------------------------------------------------
# 2. pandas — optional convenience loader.
# ---------------------------------------------------------------------------
def demo_pandas() -> None:
    try:
        import pandas as pd  # type: ignore
    except ImportError:
        print("[pandas] skipped (not installed)")
        return
    reports_df = pd.read_json(DATA / "reports.jsonl", lines=True)
    entries_df = pd.read_json(DATA / "entries.jsonl", lines=True)
    print(f"[pandas] reports_df.shape={reports_df.shape}  "
          f"entries_df.shape={entries_df.shape}")

    # Top vulnerability categories.
    print("[pandas] top vuln_category_l1:")
    print(entries_df["vuln_category_l1"].value_counts().head(5).to_string())

    # Join example.
    joined = entries_df.merge(
        reports_df[["report_id", "num_entries"]],
        on="report_id",
        how="left",
    )
    print(f"[pandas] joined rows={len(joined)}  "
          f"columns={len(joined.columns)}")


# ---------------------------------------------------------------------------
# 3. HuggingFace `datasets` — optional.
# ---------------------------------------------------------------------------
def demo_hf_datasets() -> None:
    try:
        from datasets import load_dataset  # type: ignore
    except ImportError:
        print("[datasets] skipped (pip install datasets)")
        return
    # reports.jsonl 与 entries.jsonl 的 schema 不同（前者是报告级，后者是入口点级，
    # 通过 report_id 关联），不能作为同一个 dataset 的两个 split 加载——那样
    # `datasets` 会用第一个文件推断出的 Arrow schema 去 cast 第二个文件，导致
    # CastError。这里分别加载为两个独立 dataset。
    reports = load_dataset(
        "json", data_files=str(DATA / "reports.jsonl"), split="train"
    )
    entries = load_dataset(
        "json", data_files=str(DATA / "entries.jsonl"), split="train"
    )
    print(f"[datasets] reports rows={len(reports)}  entries rows={len(entries)}")
    print(f"[datasets] entries.features={list(entries.features)}")


if __name__ == "__main__":
    demo_stdlib()
    demo_pandas()
    demo_hf_datasets()
