# Issue #4 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Repair file/line locations only when the code snippet has a unique source match | `scripts/fix_code_locations.py`, `reports/fix_diff.csv` |
| Keep ambiguous, generic, or missing matches out of automatic fixes | `reports/needs_human.csv` |
| Preserve row count, entry order, and schema compatibility | `scripts/verify_code_location_outputs.py` |
| Make automatic changes auditable | `reports/fix_diff.csv`, `reports/code_location_summary.md` |
| Provide a full fixed JSONL artifact | `data/entries.fixed.jsonl` |
| Keep reviewer-facing summary concise | `reports/code_location_summary.md` |

## Verification Commands

```bash
python -m unittest discover -s tests
python scripts/verify_code_location_outputs.py
```
