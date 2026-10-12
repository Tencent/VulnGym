# -*- coding: utf-8 -*-
"""Dry-run mechanical desc line-anchor sync. Does not write entries."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
from _diffpack_lib import OUT, ROOT, load_fix_csv, load_fix_mod  # noqa: E402
from desc_sync_lib import try_sync  # noqa: E402


def main() -> int:
    mod = load_fix_mod()
    fixes = load_fix_csv(OUT / "fix_diff.csv")
    originals: dict[str, dict] = {}
    with (ROOT / "data" / "entries.jsonl").open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                originals[e["entry_id"]] = e

    rows = []
    counts: dict[str, int] = {}
    for (eid, fp), fr in fixes.items():
        e = originals[eid]
        node = None
        for path, n in mod.iter_nodes(e):
            if path == fp:
                node = n
                break
        if not node:
            continue
        desc = node.get("desc") or ""
        new_desc, status = try_sync(desc, fr.get("old_line"), fr.get("new_line"))
        counts[status] = counts.get(status, 0) + 1
        rows.append(
            {
                "entry_id": eid,
                "field_path": fp,
                "status": status,
                "old_line": fr.get("old_line"),
                "new_line": fr.get("new_line"),
                "old_desc_preview": (desc[:80] + "…") if len(desc) > 80 else desc,
                "new_desc_preview": (
                    (
                        (new_desc[:80] + "…")
                        if new_desc and len(new_desc) > 80
                        else new_desc
                    )
                    or ""
                ),
            }
        )

    out = OUT / "desc_sync_dryrun.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "entry_id",
                "field_path",
                "status",
                "old_line",
                "new_line",
                "old_desc_preview",
                "new_desc_preview",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(r)

    summary = {"counts": counts, "would_update": counts.get("would_update", 0)}
    (OUT / "desc_sync_dryrun_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
