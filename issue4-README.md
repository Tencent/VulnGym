# Issue #4 — Conservative Code Location Repair

## What this change adds

- **fix_entries.py** — Conservative repair workflow for `data/entries.jsonl` with a 4-tier verification strategy:
  1. In-place verification at declared `file:line`
  2. Nearby search within `line +/- 5`
  3. Full-file search
  4. Repository-wide search (repair `file + line` on unique match)
- **tests/test_fix_entries.py** — 21 unit tests covering all core functions
- **scripts/verify_fix.py** — Independent verification suite (schema / diff / code integrity / idempotency)
- **Degenerate snippet detection** — Single closing braces/parens (`}`, `)`, `];`) are never auto-fixed
- **Desc sync** — When file is unchanged, line-number references in `desc` are updated conservatively
- **Fix diff now includes desc** — `fix_diff.csv` tracks `original_desc` → `new_desc` changes

## Why this is conservative

Only data is modified when the script finds **exactly one** normalized match. Any ambiguity (missing code, multiple hits, fetch failure, degenerate snippet) leaves the node untouched and records it for human review.

## Outputs

| File | Description |
|------|-------------|
| `entries.fixed.jsonl` | Repaired entries |
| `fix_diff.csv` | Per-field diff (incl. desc sync) |
| `needs_human.csv` | Nodes requiring manual review |

## Run

```bash
# Main repair (recommended)
python fix_entries.py --input data/entries.jsonl --output entries.fixed.jsonl --workers 6

# Dry-run (no files written)
python fix_entries.py --input data/entries.jsonl --output /tmp/out.jsonl --dry-run

# Run tests
python -m unittest tests.test_fix_entries -v

# Run verification suite
python scripts/verify_fix.py
```
