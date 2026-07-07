# Issue #5 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Detect duplicate trace nodes and order anomalies | `scripts/trace_cleanup.py`, `reports/trace_fix_report.json` |
| Keep cross-file call chains in original order | default cross-file skip policy and `scripts/README_trace_cleanup.md` |
| Apply only conservative automatic fixes | `duplicate_fix_policy=safe`, `order_fix_policy=entry-before-only` |
| Preserve schema compatibility | `python -m unittest discover -s tests` and report `output_schema_errors: 0` |
| Make review burden manageable | concise JSON/Markdown report is committed; verbose event log is reproducible but not checked in |
| Provide a fixed JSONL artifact | `data/entries.trace_fixed.jsonl` |

## Verification Commands

```bash
python -m unittest discover -s tests
python scripts/trace_cleanup.py --mode fix
```
