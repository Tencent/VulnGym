# Issue #7 Acceptance Matrix

This matrix maps each acceptance requirement from issue #7 to the artifacts in this PR.

| Requirement | Evidence in this PR | Status |
| --- | --- | --- |
| Each `{file,line,code}` must match the vulnerable commit | `scripts/verify_rebuilt_chains.py --use-remote` validates all rebuilt nodes against GitHub raw sources; `--check-upstream` also checks fix-parent and patch evidence | Covered |
| Report explains the complete chain from entry to critical operation | `reports/rebuild_report.md` has one section per target entry and explains entry, propagation, root cause, and sink | Covered |
| Multi-stage scenarios must identify prerequisite and trigger stages | `entry-00197` records normalization, the symlink-retarget window, attachment hydration, stale `sandboxValidated` trust, and the final unscoped read | Covered |
| Irrelevant trace nodes should be removed or replaced | `reports/rebuild_fix_diff.csv` records replacement/removal of stale logger, declaration, return-value, and brace nodes | Covered |
| Uncertain changes must go to manual review | `reports/rebuild_manual_review.csv` contains `entry-00290`; its recorded revision appears fail-closed and the advisory fix is test-only | Covered |
| Rebuilt data must satisfy SCHEMA.md basics | `scripts/verify_rebuilt_chains.py` validates required entry/node fields, line spans, non-empty code/desc, text-integrity markers, target semantic anchors, and manual-review coverage | Covered |

## Distinctive Choices Versus Other Submissions

- Patch-first review: `data/entries.rebuilt_chains.jsonl` contains only the 5 changed entries.
- Full-data delivery: `data/entries.fixed.jsonl` contains all 408 entries after applying the patch.
- Evidence-aware confidence: a candidate sink is not treated as a proven chain when the recorded revision and advisory fix do not support the claimed bypass; `entry-00290` is explicitly `verify=0`.
- Reproducible local tooling: `scripts/apply_rebuild_patches.py` regenerates full output and diff from the patch file.
- Independent verification: `scripts/verify_rebuilt_chains.py` supports local semantics, remote source matching, advisory-fix evidence checks, and rejection of obvious natural-language encoding damage.
