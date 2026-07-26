# Trace cleanup tool

`scripts/trace_cleanup.py` scans `data/entries.jsonl` for structural
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
python scripts/trace_cleanup.py
```

Fix mode writes `data/entries.trace_fixed.jsonl`, JSON/Markdown reports, and
compact audit CSVs:

```bash
python scripts/trace_cleanup.py --mode fix
```

By default, fix mode changes only `verify=0` entries. Use
`--fix-verify all` to allow all entries, or `--fix-verify 1` to target only
human-verified entries.

## Strategy

- Duplicate merge: keep the first trace node and remove later identical
  `{file, line, code}` nodes. If the first node has no `desc` and the duplicate
  has one, fix mode copies that `desc` to the first node. With the default
  `--duplicate-fix-policy safe`, different non-empty descriptions are logged for
  manual review and the duplicate node is retained.
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
  being checked, the script counts a cross-file skip and preserves the trace
  order. Per-node cross-file skip events are intentionally omitted by default
  to keep review artifacts small; use `--log-cross-file` when a full event log
  is needed for local debugging.

## Fix policy

The default fix policy is conservative:

```bash
python scripts/trace_cleanup.py --mode fix --order-fix-policy entry-before-only
```

This removes safely mergeable duplicate nodes and wholly pre-entry nodes for the
selected `verify` bucket. Same-file nodes after `critical_operation` are logged
for manual review because helper functions can appear later in the same source
file.

For stricter cleanup, use:

```bash
python scripts/trace_cleanup.py --mode fix --order-fix-policy bounds
```

This also removes trace nodes wholly after `critical_operation`. Boundary
overlaps are always retained for review.

Duplicate cleanup is also configurable:

```bash
python scripts/trace_cleanup.py --mode fix --duplicate-fix-policy safe
```

- `safe`: remove duplicate candidates only when no conflicting `desc` text would
  be lost.
- `drop-all`: remove every duplicate candidate after logging any `desc`
  conflict.
- `none`: only report duplicate candidates.

## Outputs

- `data/entries.trace_fixed.jsonl`: fixed data, written only in fix mode unless
  `--output` is provided.
- `reports/trace_fix_log.json`: generated event log with `entry_id`, field
  path, before/after content, action, and reason. This verbose log is
  reproducible from the script and is not intended to be checked in.
- `reports/trace_fix_diff.csv`: checked-in compact log containing only changes
  that were actually applied, with the original field path, structural
  before/after JSON, description SHA-256 fingerprints, action, and reason.
  Legacy descriptions are referenced by hash instead of copied into the audit
  CSV so unrelated encoding damage is not propagated.
- `reports/trace_review_queue.csv`: checked-in entry-level aggregation of
  findings retained for review or protected by the `verify` policy. Repeated
  node findings are grouped to keep the artifact readable.
- `reports/trace_fix_report.json`: structured counts for duplicates, order
  anomalies, automatic fixes, cross-file skips, schema validation, artifact
  format version, and canonical input/output SHA-256 fingerprints.
- `reports/trace_fix_report.md`: short human-readable report.

The script does not reorder cross-file call chains and does not infer semantic
call order from source code. It only performs structural checks over the JSONL
annotations.

## Artifact verification

The independent verifier regenerates every committed artifact in memory and
checks that:

- all 408 entry IDs and all non-`trace` fields remain unchanged;
- every output trace is an ordered subsequence of its original trace;
- only `entry-00103` and `entry-00320` change under the default policy;
- compact diff rows exactly match applied events;
- priority samples `entry-00185` and `entry-00511` remain in the review queue;
- JSONL, JSON, Markdown, and CSV artifacts are reproducible and match the
  SHA-256 fingerprints in the report.

```bash
python scripts/verify_trace_cleanup_artifacts.py
```

This freshness check deliberately complements the separate human
`plan -> decision -> apply` workflow: it verifies generated cleanup artifacts
without attempting to make semantic review decisions automatically.
