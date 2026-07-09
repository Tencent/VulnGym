# Issue #6 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Repaired rows match vulnerable source commits | `python scripts/verify_n8n_semantic_annotations.py --check-upstream` |
| `entry_point` reflects external input, user config, request, or workflow parameter entry | repaired `entry_point` fields in `data/entries.n8n_semantic_fixed.jsonl` |
| `critical_operation` points to the real execution, decision, or bypass point | repaired `critical_operation` fields and `reports/n8n_semantic_fix_notes.md` |
| `trace` keeps important data-flow/control-flow nodes and removes irrelevant nodes | repaired `trace` arrays and field-level diff CSV |
| Repair reasoning is clear for human review | `reports/n8n_semantic_fix_notes.md` |
| Data still satisfies `SCHEMA.md` constraints | `python -m unittest discover -s tests` and verifier validation |

## Verification Commands

```bash
python scripts/apply_n8n_semantic_patches.py
python -m unittest discover -s tests
python scripts/verify_n8n_semantic_annotations.py --check-upstream
```
