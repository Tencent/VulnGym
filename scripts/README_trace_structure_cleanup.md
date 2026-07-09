# Trace structure cleanup

`trace_structure_cleanup.py` scans `data/entries.jsonl` for structural issues
inside each entry's `trace` chain and can optionally write a cleaned JSONL file
plus review logs.

## What It Checks

- Duplicate trace nodes whose `{file, line, code}` fields are identical.
- Same-file trace nodes that appear before `entry_point`.
- Same-file trace nodes that appear after `critical_operation`.
- Integer line numbers and range line numbers such as `"163-166"`.
- Cross-file trace hops. These keep their original order and are not compared
  by line number.

## Usage

Run a read-only scan:

```bash
python scripts/trace_structure_cleanup.py --mode check
```

Run the conservative fixer:

```bash
python scripts/trace_structure_cleanup.py --mode fix
```

By default, fix mode only applies automatic changes to `verify = 0` entries. It
removes safe duplicate nodes and same-file trace nodes that end before the
entry point starts. Same-file nodes after the critical operation are logged for
manual review unless `--order-policy bounds` is selected.

Useful options:

```bash
python scripts/trace_structure_cleanup.py --mode fix --fix-verify all
python scripts/trace_structure_cleanup.py --mode fix --order-policy bounds
python scripts/trace_structure_cleanup.py --mode fix --duplicate-policy drop-all
python scripts/trace_structure_cleanup.py --mode check --log-cross-file
```

## Outputs

- `data/entries.trace_fixed.jsonl`: cleaned dataset emitted in fix mode.
- `reports/trace_structure_fix_log.csv`: readable field-level change/review log.
- `reports/trace_structure_fix_log.jsonl`: machine-readable log.
- `reports/trace_structure_report.md`: summary report with counts, changed
  entries, and manual-review entries.

## Safety Notes

- The script never reorders trace nodes.
- Cross-file trace steps are kept unchanged.
- Duplicate nodes with conflicting `desc` values are kept for manual review
  under the default `safe` duplicate policy.
- Range line comparisons use the full span: a node is only automatically
  removed before the entry point when its end line is before the entry point's
  start line.
