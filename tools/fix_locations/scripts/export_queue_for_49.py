# -*- coding: utf-8 -*-
"""Export needs_human.csv for PR #49 location_review init.

- Requires entry_id + field_path (also mirrored as node_path).
- Drops repo_fetch_failed / fetch_failed rows (Windows long-path false positives).
- Keeps extra columns; #49 allows them.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
from _diffpack_lib import OUT  # noqa: E402

FETCH_MARKERS = ("fetch_failed", "repo_fetch_failed")


def is_fetch_failed(row: dict) -> bool:
    blob = " ".join(
        str(row.get(k) or "") for k in ("status", "reason", "strategy", "field_path")
    ).lower()
    return any(m in blob for m in FETCH_MARKERS)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input",
        type=Path,
        default=OUT / "needs_human.csv",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=OUT / "needs_human.for_49.csv",
    )
    ap.add_argument(
        "--report",
        type=Path,
        default=OUT / "needs_human.for_49_export_report.json",
    )
    args = ap.parse_args()

    with args.input.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    kept: list[dict] = []
    dropped: list[dict] = []
    for r in rows:
        eid = (r.get("entry_id") or "").strip()
        fp = (r.get("field_path") or r.get("node_path") or "").strip()
        if not eid or not fp or fp == "*":
            dropped.append({**r, "_drop_reason": "missing_id_or_path"})
            continue
        if is_fetch_failed(r):
            dropped.append({**r, "_drop_reason": "fetch_failed_excluded"})
            continue
        kept.append(r)

    out_fields = list(fieldnames)
    if "node_path" not in out_fields:
        # place after field_path if present
        if "field_path" in out_fields:
            i = out_fields.index("field_path") + 1
            out_fields.insert(i, "node_path")
        else:
            out_fields.insert(0, "node_path")
    if "field_path" not in out_fields:
        out_fields.insert(0, "field_path")

    with args.output.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_fields, extrasaction="ignore")
        w.writeheader()
        for r in kept:
            row = dict(r)
            fp = (row.get("field_path") or row.get("node_path") or "").strip()
            row["field_path"] = fp
            row["node_path"] = fp
            w.writerow(row)

    report = {
        "input": str(args.input),
        "output": str(args.output),
        "input_rows": len(rows),
        "kept": len(kept),
        "dropped": len(dropped),
        "dropped_reasons": {},
        "note": (
            "fetch_failed / repo_fetch_failed rows are excluded by default; "
            "see out/FETCH_FAILED_NOTE.md and out/COMPAT_WITH_49.md."
        ),
    }
    for d in dropped:
        reason = d.get("_drop_reason") or "other"
        report["dropped_reasons"][reason] = (
            report["dropped_reasons"].get(reason, 0) + 1
        )

    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
