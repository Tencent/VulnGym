# Issue #4 — Conservative Code Location Repair

## What this change adds

This patch adds a conservative repair workflow for `data/entries.jsonl`:

- verify existing `{file, line, code}` locations
- search within `line ± 5`
- search the full original file
- search the full repository snapshot and repair `file + line` on unique match
- record uncertain cases in `needs_human.csv`

## Why this is conservative

The script only modifies data when it finds **exactly one** normalized match. If the code is missing, ambiguous, or the repository snapshot cannot be fetched reliably, the node is left unchanged and recorded for manual review.

## Outputs

- `entries.fixed.jsonl`
- `fix_diff.csv`
- `needs_human.csv`

## Run

```bash
python fix_entries.py --input data/entries.jsonl --output entries.fixed.jsonl --workers 6
```
