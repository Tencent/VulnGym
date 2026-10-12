# -*- coding: utf-8 -*-
"""Apply mechanical desc sync for would_update rows only.

Reads entries.fixed.jsonl + fix_diff.csv; writes entries.fixed.desc_synced.jsonl
without overwriting entries.fixed.jsonl. Scope: only status==would_update
(this batch: 10 nodes on entry-00458).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
from _diffpack_lib import OUT, load_fix_csv, load_fix_mod  # noqa: E402
from desc_sync_lib import try_sync  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--fixed",
        type=Path,
        default=OUT / "entries.fixed.jsonl",
        help="Input fixed JSONL (location repairs already applied)",
    )
    ap.add_argument(
        "--fix-diff",
        type=Path,
        default=OUT / "fix_diff.csv",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=OUT / "entries.fixed.desc_synced.jsonl",
    )
    ap.add_argument(
        "--applied-csv",
        type=Path,
        default=OUT / "desc_sync_applied.csv",
    )
    args = ap.parse_args()

    mod = load_fix_mod()
    fixes = load_fix_csv(args.fix_diff)

    # Precompute which (entry, path) would_update using ORIGINAL desc from fixed jsonl
    # (fixed jsonl still has original desc; only file/line changed).
    applied: list[dict] = []
    entries: list[dict] = []
    with args.fixed.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entries.append(json.loads(line))

    # Map for mutation: only would_update
    plan: dict[tuple[str, str], str] = {}
    for e in entries:
        eid = e["entry_id"]
        for path, node in mod.iter_nodes(e):
            fr = fixes.get((eid, path))
            if not fr:
                continue
            new_desc, status = try_sync(
                node.get("desc") or "", fr.get("old_line"), fr.get("new_line")
            )
            if status != "would_update" or not new_desc:
                continue
            plan[(eid, path)] = new_desc
            applied.append(
                {
                    "entry_id": eid,
                    "field_path": path,
                    "old_line": fr.get("old_line"),
                    "new_line": fr.get("new_line"),
                    "old_desc": node.get("desc") or "",
                    "new_desc": new_desc,
                }
            )

    out_rows = []
    for e in entries:
        e2 = json.loads(json.dumps(e))  # deep copy
        for path, node in mod.iter_nodes(e2):
            nd = plan.get((e2["entry_id"], path))
            if nd is not None:
                node["desc"] = nd
        out_rows.append(e2)

    with args.output.open("w", encoding="utf-8", newline="\n") as f:
        for e in out_rows:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    with args.applied_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "entry_id",
                "field_path",
                "old_line",
                "new_line",
                "old_desc",
                "new_desc",
            ],
        )
        w.writeheader()
        for r in applied:
            w.writerow(r)

    summary = {
        "input_fixed": str(args.fixed),
        "output": str(args.output),
        "applied_count": len(applied),
        "entries": len(out_rows),
        "note": "Does not overwrite entries.fixed.jsonl; only would_update rows.",
    }
    (OUT / "desc_sync_apply_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
