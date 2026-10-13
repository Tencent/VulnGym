# Issue #5 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Detect duplicate trace nodes and order anomalies | `scripts/trace_cleanup.py`, `reports/trace_fix_report.json` |
| Keep cross-file call chains in original order | default cross-file skip policy and `scripts/README_trace_cleanup.md` |
| Apply only conservative automatic fixes | `duplicate_fix_policy=safe`, `order_fix_policy=entry-before-only` |
| Preserve schema compatibility and all non-trace data | tests plus `scripts/verify_trace_cleanup_artifacts.py` |
| Never reorder or add trace nodes | ordered-subsequence invariant in the artifact verifier |
| Log every applied modification with before/after content | `reports/trace_fix_diff.csv` |
| Keep retained findings reviewable | grouped `reports/trace_review_queue.csv` |
| Prevent stale generated output | input/output SHA-256 plus byte-for-byte artifact regeneration |
| Make review burden manageable | compact diff/review CSVs are committed; verbose event log remains reproducible and ignored |
| Provide a fixed JSONL artifact | `data/entries.trace_fixed.jsonl` |

## Verification Commands

```bash
python -m unittest discover -s tests
python scripts/trace_cleanup.py --mode fix
python scripts/verify_trace_cleanup_artifacts.py
```
