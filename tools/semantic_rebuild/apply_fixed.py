# -*- coding: utf-8 -*-
"""Optionally merge out/entries.fixed.jsonl into data/entries.jsonl (does not run by default)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXED = ROOT / "tools" / "semantic_rebuild" / "out" / "entries.fixed.jsonl"
ENTRIES = ROOT / "data" / "entries.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="overwrite data/entries.jsonl")
    ap.add_argument("--out", type=Path, default=None, help="write merged copy elsewhere")
    args = ap.parse_args()

    fixed = {}
    for line in FIXED.read_text(encoding="utf-8").splitlines():
        o = json.loads(line)
        fixed[o["entry_id"]] = o

    out_lines = []
    replaced = 0
    for line in ENTRIES.read_text(encoding="utf-8").splitlines():
        o = json.loads(line)
        eid = o["entry_id"]
        if eid in fixed:
            # preserve alphabetical field order of original keys, overlay annotation fields
            merged = dict(o)
            for k in ("entry_point", "critical_operation", "trace", "verify"):
                if k in fixed[eid]:
                    merged[k] = fixed[eid][k]
            merged["verify"] = 0
            out_lines.append(json.dumps(merged, ensure_ascii=False, separators=(",", ":")))
            replaced += 1
        else:
            out_lines.append(line)

    text = "\n".join(out_lines) + "\n"
    target = args.out
    if args.write:
        target = ENTRIES
    if target is None:
        print(f"dry-run: would replace {replaced} entries; pass --write or --out PATH")
        return 0
    target.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {target} (replaced {replaced})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
