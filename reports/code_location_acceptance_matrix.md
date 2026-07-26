# Issue #4 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Repair file/line locations only when the code snippet has a unique source match | `scripts/fix_code_locations.py`, `reports/fix_diff.csv` |
| Keep ambiguous, generic, or missing matches out of automatic fixes | `reports/needs_human.csv` |
| Preserve row count, entry order, schema, and all non-location fields | strengthened offline verifier and artifact tests |
| Prove repaired locations against pinned source commits | `scripts/verify_code_location_outputs.py --check-source` |
| Reject stale or mismatched source caches | canonical repo/commit validation and cache-origin check |
| Avoid noisy multiline range expansion | integer locations remain valid start anchors |
| Prevent generated artifacts from becoming stale | `reports/code_location_manifest.json` SHA-256 checks |
| Make automatic changes auditable | `reports/fix_diff.csv`, summary, and manifest |
| Provide a full fixed JSONL artifact | `data/entries.fixed.jsonl` |
| Keep reviewer-facing summary concise | `reports/code_location_summary.md` |

## Verification Commands

```bash
python -m unittest discover -s tests
python scripts/verify_code_location_outputs.py
GITHUB_TOKEN="$(gh auth token)" python scripts/verify_code_location_outputs.py --check-source
```
