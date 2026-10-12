"""Apply the n8n semantic annotation patch fragment.

This script applies the 6 fixed entries to the baseline and produces
a full 408-row JSONL for the issue #6 deliverable.
"""
from __future__ import annotations
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASELINE_JSONL = ROOT / "data" / "entries.jsonl"
PATCH_JSONL = ROOT / "data" / "entries.n8n_semantic_fixed.jsonl"
FULL_JSONL = ROOT / "data" / "entries.fixed.jsonl"

TARGET_IDS = (
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00511",
    "entry-00512",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def dump_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )


def apply_patch_rows(
    baseline_rows: list[dict[str, Any]], patch_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Replace baseline rows with patched rows for the target IDs."""
    patch_by_id = {row["entry_id"]: row for row in patch_rows}
    result = []
    for row in baseline_rows:
        entry_id = row["entry_id"]
        if entry_id in patch_by_id:
            result.append(deepcopy(patch_by_id[entry_id]))
        else:
            result.append(row)
    return result


def main() -> None:
    baseline_rows = load_jsonl(BASELINE_JSONL)
    patch_rows = load_jsonl(PATCH_JSONL)

    patch_ids = {row["entry_id"] for row in patch_rows}
    missing = sorted(set(TARGET_IDS) - patch_ids)
    if missing:
        raise KeyError(f"Missing patch rows: {missing}")

    fixed_rows = apply_patch_rows(baseline_rows, patch_rows)

    if len(fixed_rows) != len(baseline_rows):
        raise AssertionError(
            f"Row count changed: baseline={len(baseline_rows)}, fixed={len(fixed_rows)}"
        )

    dump_jsonl(FULL_JSONL, fixed_rows)

    print(f"patch rows: {len(patch_rows)}")
    print(f"full rows: {len(fixed_rows)}")
    print(f"full JSONL: {FULL_JSONL}")


if __name__ == "__main__":
    main()
