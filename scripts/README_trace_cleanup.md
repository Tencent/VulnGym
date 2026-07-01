# Trace cleanup tool

`tools/clean_trace_chains.py` scans `data/entries.jsonl` for structural
problems in `trace`:

- duplicate trace nodes where `{file, line, code}` are identical;
- same-file trace nodes wholly before `entry_point`;
- same-file trace nodes wholly after `critical_operation`;
- range nodes that overlap a boundary and need manual review;
- cross-file trace nodes, which are kept in original order and are not compared
  by line number.

## Run

Check-only mode is the default:

```bash
python tools/clean_trace_chains.py
```

Fix mode writes `data/entries.trace_fixed.jsonl` plus a JSON log and JSON/Markdown
reports:

```bash
python tools/clean_trace_chains.py --mode fix
```

By default, fix mode changes only `verify=0` entries. Use
`--fix-verify all` to allow all entries, or `--fix-verify 1` to target only
human-verified entries.

## Strategy

- Duplicate merge: keep the first trace node and remove later identical
  `{file, line, code}` nodes. If the first node has no `desc` and the duplicate
  has one, fix mode copies that `desc` to the first node. Different non-empty
  descriptions are logged for manual review.
- Line parsing: both integer lines and `"start-end"` ranges are normalized to
  `(start, end)` for comparison.
- Same-file order checks:
  - `trace.end < entry_point.start` is classified as wholly before the entry.
  - `trace.start < entry_point.start <= trace.end` is a boundary overlap and is
    kept for manual review.
  - `trace.start > critical_operation.end` is classified as wholly after the
    critical operation.
  - `trace.start <= critical_operation.end < trace.end` is a boundary overlap
    and is kept for manual review.
- Cross-file checks: when a trace node is in a different file from the boundary
  being checked, the script records a cross-file skip and preserves the trace
  order.

## Fix policy

The default fix policy is conservative:

```bash
python tools/clean_trace_chains.py --mode fix --order-fix-policy entry-before-only
```

This removes duplicate nodes and wholly pre-entry nodes for the selected
`verify` bucket. Same-file nodes after `critical_operation` are logged for
manual review because helper functions can appear later in the same source file.

For stricter cleanup, use:

```bash
python tools/clean_trace_chains.py --mode fix --order-fix-policy bounds
```

This also removes trace nodes wholly after `critical_operation`. Boundary
overlaps are always retained for review.

## Outputs

- `data/entries.trace_fixed.jsonl`: fixed data, written only in fix mode unless
  `--output` is provided.
- `data/trace_fix_log.json`: event log with `entry_id`, field path, before/after
  content, action, and reason.
- `data/trace_fix_report.json`: structured counts for duplicates, order
  anomalies, automatic fixes, cross-file skips, and schema validation.
- `data/trace_fix_report.md`: short human-readable report.

The script does not reorder cross-file call chains and does not infer semantic
call order from source code. It only performs structural checks over the JSONL
annotations.
