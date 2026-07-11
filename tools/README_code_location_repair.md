# Code location repair

`code_location_repair.py` validates every `entry_point`,
`critical_operation`, and `trace[*]` node against the repository and commit
recorded in `data/entries.jsonl`. It uses Python's standard library and Git.

Run the complete dataset:

```bash
python3 tools/code_location_repair.py
```

For a quick pass over entries that have not been human-reviewed:

```bash
python3 tools/code_location_repair.py --verify unverified
```

The command writes:

- `entries.fixed.jsonl`: all input rows with uniquely located nodes repaired.
- `fix_diff.csv`: before/after values and the strategy for every repair.
- `needs_human.csv`: ambiguous or missing nodes and up to five candidates.
- `location_fix_report.json`: counts, strategies, reasons, and elapsed time.

## Matching policy

Code is compared as contiguous lines after trimming line edges and collapsing
tabs/spaces. Empty lines inside a multi-line snippet remain significant. A
failed node is handled in this order:

1. Accept an integer location at the annotated start line, or a range only
   when both annotated boundaries match the snippet.
2. Repair a unique match within `--nearby-lines` (default: 5).
3. Repair a unique match in the original file.
4. Repair a unique match across the commit and update both file and line.
5. Send multiple or missing matches to `needs_human.csv` without modifying the
   node.

When a location changes, structured references such as `第 10 行`, `line 10`,
or `L10` and changed filenames are updated in `desc`. Other prose is preserved.

## Source cache

Repositories are stored as bare Git object caches under
`~/.cache/vulngym/source-repos`. Missing commits are fetched in batches and no
working trees are created. Use `--offline` to prohibit network fetches after
the cache has been populated. Repository-wide matching streams `git archive`
and skips binary files and files larger than 5 MiB by default; adjust with
`--max-file-bytes` when necessary.

Run tests with:

```bash
python3 -m unittest discover -s tests -v
```
