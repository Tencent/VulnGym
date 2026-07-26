# Code Location Fix Summary

- Entries selected: 408
- Repo/commit groups: 166
- OK nodes: 2802
- Fixed nodes: 12
- Manual-review nodes: 75
- Schema errors: 0
- Fixed JSONL: `data/entries.fixed.jsonl`
- Diff CSV: `reports/fix_diff.csv`
- Needs-human CSV: `reports/needs_human.csv`
- Artifact manifest: `reports/code_location_manifest.json`
- Verifier: `scripts/verify_code_location_outputs.py`
- Acceptance matrix: `reports/code_location_acceptance_matrix.md`

## Automatic fixes by strategy

| Value | Count |
| --- | ---: |
| nearby_plus_minus_5 | 10 |
| same_file_unique | 2 |

## Manual review by reason

| Value | Count |
| --- | ---: |
| no_match | 56 |
| multiple_matches | 19 |

## Desc rewrite status

| Value | Count |
| --- | ---: |
| unchanged_needs_review | 12 |
