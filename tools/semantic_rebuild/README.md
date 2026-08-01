# semantic_rebuild (#6)

Re-annotation pack for the six priority n8n entries. See `CRITICAL_RULE.md` and `VERIFY_POLICY.md`.

## Check

```bash
python tools/semantic_rebuild/run_all.py
```

Lint + code alignment against the vuln commit + refresh `out/` and the six rows in `data/entries.jsonl`. Does not prove the semantic choice.

## Layout

Per entry: `BEFORE.json`, `AFTER.json`, `CANDIDATES.md`, `PATCH_NOTES.md`, `DECISION.md`.

PR-oriented notes: `out/NOTES.md`, `out/PR_BODY.md`, `out/semantic_diff.csv`.
