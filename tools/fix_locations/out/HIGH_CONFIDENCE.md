# High-confidence fix subsets

Rules: `DIFF_PACK_NIGHT_PLAN.md` §4 (not relaxed).

- **R2a** `high_confidence_fixes.csv`: **12** (line_moved ∩ (#35∪#39) ∩ #41)
- **R2b** `high_confidence_ranges.csv`: **82** passed idempotency (of 82 candidates; skipped=0)
- `entries.high_confidence.jsonl`: **5** entries (R2a only — merge-friendly)

R2b is optional accounting; do not treat as must-merge.
