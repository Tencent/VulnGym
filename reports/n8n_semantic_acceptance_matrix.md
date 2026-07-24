# Issue #6 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Repaired rows match vulnerable source commits | raw-source comparison for every `{file,line,code}` node |
| `entry_point` reflects external input, user config, request, or workflow parameter entry | repaired `entry_point` fields in `data/entries.n8n_semantic_fixed.jsonl` |
| `critical_operation` points to the vulnerability-specific execution, decision, or mutable guard | exact semantic-anchor checks and `reports/n8n_semantic_fix_notes.md` |
| `trace` keeps important data-flow/control-flow nodes and removes irrelevant nodes | repaired `trace` arrays and field-level diff CSV |
| Vulnerable snapshot is directly tied to the reviewed fix | four fix commits must have the recorded vulnerable commit as first parent |
| Fix semantics match the selected annotations | expected upstream patch markers for AST checks, trimming, `__objclass__`, unsafe properties, and immutable `__sanitize` |
| Advisory identity and affected versions are present | GitHub global advisory API checks for all four GHSA records |
| Rows are human reviewed | all six patch rows are generated with `verify=1` and `verify` appears in the diff |
| Text has no repeated-`?` or replacement-character damage | recursive patch-text check plus Markdown/CSV integrity check |
| Data still satisfies `SCHEMA.md` constraints | generator validation, unit tests, reproducibility check, and upstream verifier |

## Verification Commands

```bash
python scripts/apply_n8n_semantic_patches.py
python -m unittest discover -s tests
python scripts/verify_n8n_semantic_annotations.py --check-upstream
```

`GITHUB_TOKEN` or `GH_TOKEN` is used automatically when present, which raises
the API rate limit for the advisory and fix-commit checks.
