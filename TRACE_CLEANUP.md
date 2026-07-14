# Trace structure cleanup

`scripts/trace_structure_cleanup.py` detects structural noise in every
`trace` from `data/entries.jsonl`. It uses only the Python standard library.

## Usage

Detection is the default and never modifies a trace:

```shell
python scripts/trace_structure_cleanup.py --mode check
```

Conservative repair mode scans all entries but modifies only `verify=0` rows:

```shell
python scripts/trace_structure_cleanup.py --mode fix
```

Use `--fix-verify all` only after reviewing the report when verified entries
must also be cleaned. Output paths can be changed with `--output`, `--log`, and
`--report`.

## Rules

- Nodes with identical `{file, line, code}` are duplicate candidates. Repair
  mode keeps the first and removes later nodes only when their descriptions are
  also identical. Conflicting descriptions are retained for human review.
- A trace node is before the entry point only when both use the same file and
  the trace range ends before the entry range starts.
- A trace node is after the critical operation only when both use the same file
  and the trace range starts after the critical range ends.
- Integer and `"start-end"` line values are supported.
- Cross-file nodes retain their original order. Their line numbers are not
  compared or sorted.

Every anomaly is written to `reports/trace_fix_log.csv` with the original node,
resulting node, action, reason, and reference boundary. Aggregate counts are in
`reports/trace_structure_report.md`.

Run tests with:

```shell
python -m unittest discover -s tests -p "test_trace_structure_cleanup.py" -v
```
