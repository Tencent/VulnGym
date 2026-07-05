# Issue #7 Acceptance Matrix

This matrix maps each acceptance requirement from issue #7 to the artifacts in this PR.

| Requirement | Evidence in this PR | Status |
| --- | --- | --- |
| Each `{file,line,code}` must match the vulnerable commit | `scripts/verify_rebuilt_chains.py --use-remote` validates all rebuilt nodes against GitHub raw sources | Covered |
| Report explains the complete chain from entry to critical operation | `reports/rebuild_report.md` has one section per target entry and explains entry, propagation, root cause, and sink | Covered |
| Multi-stage scenarios must identify prerequisite and trigger stages | `entry-00197` describes check/use TOCTOU; `entry-00290` separates fail-open check from final write sink | Covered |
| Irrelevant trace nodes should be removed or replaced | `reports/rebuild_fix_diff.csv` records replacement/removal of stale logger, declaration, return-value, and brace nodes | Covered |
| Uncertain changes must go to manual review | `reports/rebuild_manual_review.csv` is kept as the audit artifact; this pass has no unresolved rows | Covered |
| Rebuilt data must satisfy SCHEMA.md basics | `scripts/verify_rebuilt_chains.py` validates required entry/node fields, line spans, non-empty code, and non-empty desc | Covered |

## Distinctive Choices Versus Other Submissions

- Patch-first review: `data/entries.rebuilt_chains.jsonl` contains only the 5 changed entries.
- Full-data delivery: `data/entries.fixed.jsonl` contains all 408 entries after applying the patch.
- Sink-oriented critical operations: final dangerous operations are used as `critical_operation` for n8n, openclaw apply_patch, and langflow; root-cause checks remain visible in `trace`.
- Reproducible local tooling: `scripts/apply_rebuild_patches.py` regenerates full output and diff from the patch file.
- Independent verification: `scripts/verify_rebuilt_chains.py` can run schema-only or remote source matching.
