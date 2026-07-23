# VulnGym trace cleanup

This standard-library-only tool detects structural anomalies in
`data/entries.jsonl` and can apply a deliberately small set of auditable
repairs for Issue #5.

## Usage

Run detection without producing a fixed dataset:

```bash
python -m tools.trace_cleanup check
python -m tools.trace_cleanup check --entry-id entry-00103
```

Create `data/entries.trace_fixed.jsonl`:

```bash
python -m tools.trace_cleanup fix
```

The default fix removes only safe internal trace duplicates in unverified
entries. Order findings remain report-only. Mechanical removal of definite
order candidates requires an explicit option:

```bash
python -m tools.trace_cleanup fix --order-action remove-definite
```

Do not use that option on the real dataset without reviewing the findings
first. Source line order is not proof of runtime order.

Common options:

- `--input`: input JSONL; defaults to `data/entries.jsonl`.
- `--entry-id`: limit scanning to one entry; repeat as needed.
- `--reports-dir`: defaults to `reports/trace_cleanup`.
- `--verbose`: print all summary fields.

Fix-only options:

- `--output`: defaults to `data/entries.trace_fixed.jsonl` and must differ
  from the input path.
- `--duplicate-action report|remove-safe`: defaults to `remove-safe`.
- `--order-action report|remove-definite`: defaults to `report`.

## Detection rules

An internal duplicate is a pair or group within one `trace` whose raw
`file`, `line`, and `code` values are exactly equal. Endpoint overlap is not
an internal duplicate, paths are not normalized for this rule, and integer
`97` differs from range string `"97-97"`.

A duplicate is safe to remove only in fix mode when:

- the entry has `verify == 0`;
- `--duplicate-action remove-safe` is active; and
- every duplicate has the same `desc`, or all duplicates omit `desc`.

The first occurrence is retained. Different or partially missing
descriptions are sent to human review and are never merged.

Line values are parsed as inclusive spans. A node is definitely before the
entry only when `trace.end < entry_point.start`, and definitely after the
critical operation only when `trace.start > critical_operation.end`.
Equality, containment, and overlap are not definite violations.

For file comparison only, backslashes become forward slashes and leading
`./` is removed. Case remains significant. A trace node whose file matches
neither boundary is counted as `cross_file_skipped`; its line is not
compared and its position is preserved.

## Safety boundaries

Entries with `verify == 1` are always protected from automatic changes.
Their findings use `protected_verified`. There is intentionally no CLI
option that enables verified-entry modification.

Detection, policy decisions, and trace reconstruction are separate stages.
Trace arrays are rebuilt from removal indexes, so index drift and
reordering cannot occur. The original input path is never accepted as a fix
output.

Source lines do not define execution order. A caller can be located below a
callee in the same file; loops, recursion, callbacks, asynchronous work,
and repeated execution can also make runtime lines move backwards. Line
numbers from different files are unrelated and are never ordered.

## Reports

Both modes write:

- `trace_findings.csv`
- `trace_needs_human.csv`
- `trace_summary.json`

Fix mode also writes `trace_fix_log.csv` and the fixed JSONL. Reports contain
no timestamps or random identifiers, use fixed ordering, and are stable for
the same input and arguments. The human-review CSV includes report-only,
ambiguous, and verified-protected findings; cross-file skip events are kept
in the complete findings CSV instead.

JSONL and report files are written through temporary files and atomically
replaced. The fixed JSONL is parsed and schema-checked before replacement.

## Limitations

The tool detects mechanical source-location relationships. It does not
build control-flow graphs, inspect vulnerable source checkouts, or prove
runtime execution order. Definite order findings therefore remain
report-only by default and may still need human review.

## Tests

From the repository root:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
