# Trace cleanup

`trace_cleanup.py` scans `data/entries.jsonl` for duplicate trace nodes and
nodes that fall outside same-file entry/critical-operation boundaries. It uses
only the Python standard library.

Report only (the default and recommended first pass):

```bash
python3 tools/trace_cleanup.py
```

Write a repaired copy, a JSONL audit log, and a JSON summary:

```bash
python3 tools/trace_cleanup.py \
  --mode fix \
  --output data/entries.trace_fixed.jsonl \
  --log-output trace_fix_log.jsonl \
  --report-output trace_fix_report.json
```

The input file is never overwritten. Each audit event includes `entry_id`, the
original `trace[index]` field path, before/after values, and a reason.

## Policy

- Line values are normalized to inclusive `(start, end)` intervals.
- A node is before the entry point only when its interval ends before the
  same-file entry-point interval starts.
- A node is after the critical operation only when its interval starts after
  the same-file critical-operation interval ends.
- Cross-file boundaries are logged and are never compared by line number.
- Duplicate candidates use the exact `{file, line, code}` key and retain the
  first occurrence.
- If duplicate descriptions are equal, or only one node has a description,
  fix mode merges them without losing description text.
- Different non-empty descriptions may represent repeated execution of the
  same source location. They are retained for manual review unless
  `--dedupe-desc-conflicts` is explicitly supplied.
- Human-reviewed entries (`verify=1`) are always scanned but are protected in
  fix mode. Pass `--fix-verified` only after reviewing the report if those
  entries also need to be changed.

The generated dataset is validated against the relevant `SCHEMA.md`
invariants before it is written. Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```
