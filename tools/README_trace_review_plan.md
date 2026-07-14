# Trace cleanup review plan

`trace_review_plan.py` adds a stale-safe human review step to conservative trace
cleanup. It complements automatic check/fix scripts: it does not guess whether a
repeated source location represents redundant annotation or an intentional second
execution stage.

The workflow is deliberately split into `plan` and `apply` phases. A reviewer
must record every removal or keep decision before the dataset can change.

## Why a second phase is needed

Issue #5 defines duplicate `{file, line, code}` values as candidates rather than
unconditionally redundant nodes. In v0.1.4, all seven exact-key duplicate
candidates have different `desc` values. They describe separate execution stages
at the same source location. Removing them solely because the structural key is
repeated would discard reviewed semantics.

Line-number cleanup has a second risk: deleting one trace node shifts every later
array index. Applying a list of `trace[N]` edits sequentially can therefore remove
the wrong node. This tool binds decisions to the original entry and node, validates
the complete plan first, then removes all selected original indices in one pass.

### v0.1.4 observation

A full plan over the current dataset reports:

- 408 entries and 2,073 trace nodes scanned;
- 362 unique candidate rows;
- 7 duplicate-key candidates, all 7 with conflicting descriptions and 0 safe
  full-node duplicates;
- 139 before-entry and 237 after-critical observations;
- 382 cross-file nodes skipped from line comparison;
- 358 candidate rows in `verify=1` entries and only 4 in `verify=0` entries.

Consequently, the generated plan suggests keeping every current candidate. This
is intentional: structural heuristics identify review targets, but the current
data does not contain an automatically safe deletion under the stricter full-node
rule.

## 1. Create a decision plan

```bash
python tools/trace_review_plan.py plan \
  --input data/entries.jsonl \
  --plan reports/trace_review_plan.csv \
  --report reports/trace_review_plan_report.json
```

The plan detects:

- repeated trace nodes with exactly equal `{file, line, code}`;
- same-file nodes ending before the entry point starts;
- same-file nodes starting after the critical operation ends.

Cross-file nodes are counted in the report and skipped for line comparison. Their
original order is never changed.

Each candidate receives immutable evidence:

- `event_id`: stable short identifier for the candidate;
- `dataset_sha256`: byte digest of the complete input JSONL;
- `entry_sha256`: canonical digest of the complete entry;
- `node_sha256`: canonical digest of the original trace node;
- `expected_node_json`: the exact node that was reviewed;
- `references_json`: the first duplicate, entry point, and/or critical operation
  used to classify the candidate.

`suggested_decision` is advisory only. The generated `decision` is always blank.
An identical full node is suggested for removal; a duplicate with a different
description and every boundary anomaly are suggested for keeping.

## 2. Review candidates

For every candidate that has been reviewed, fill:

| column | value |
| --- | --- |
| `decision` | `remove` or `keep` |
| `reviewer` | reviewer identity |
| `rationale` | evidence supporting the decision |

Do not edit the fingerprint, expected-node, reference, suggestion, or reason
columns. Blank decisions remain pending.

## 3. Validate and apply

```bash
python tools/trace_review_plan.py apply \
  --input data/entries.jsonl \
  --plan reports/trace_review_plan.csv \
  --output data/entries.trace_reviewed.jsonl \
  --diff reports/trace_review_diff.csv \
  --audit reports/trace_review_audit.csv \
  --allow-pending
```

Without `--allow-pending`, any blank decision stops the operation. This makes a
fully reviewed plan the default contract while still allowing a reviewer to apply
one explicitly decided subset.

Before writing outputs, `apply`:

1. reloads and validates every entry and line range;
2. recomputes the complete candidate set;
3. requires exactly the same event IDs as the decision plan;
4. compares every immutable field against current data;
5. requires a reviewer and rationale for both `remove` and `keep`;
6. refuses removal from `verify=1` entries unless `--include-verified` is given;
7. groups removals by their original trace indices and applies them in one pass.

The full JSONL, removal-only diff, and complete audit are staged only after all
validation succeeds. The original input file is never modified in place, and all
input/output paths must be distinct.

## Outputs

- `trace_review_plan.csv`: complete fingerprinted candidate/decision sheet.
- `trace_review_plan_report.json`: aggregate detection counts and input digest.
- `entries.trace_reviewed.jsonl`: full dataset after reviewed removals.
- `trace_review_diff.csv`: only removed nodes, with reviewer and rationale.
- `trace_review_audit.csv`: every removed, kept, or pending candidate.

## Safety boundaries

- The tool never adds, edits, or reorders trace nodes. It can only remove an
  explicitly reviewed original node.
- A repeated source location with a different description is not automatically
  treated as redundant.
- Boundary anomalies are review candidates, not automatic deletions.
- A changed dataset, entry, candidate type, reference, node, or suggestion makes
  the plan stale and prevents all output writes.
- Removing a human-audited node requires both an explicit decision and the
  `--include-verified` command-line acknowledgement.

## Validation

```bash
python -m unittest discover -s tests -p "test_trace_review_plan.py" -v
python -m py_compile tools/trace_review_plan.py tests/test_trace_review_plan.py
python examples/load_dataset.py
git diff --check
```

The tests cover duplicate-description conflicts, closed line ranges, cross-file
skips, stable event IDs, deterministic plans, original-index removal, stale and
tampered plans, pending decisions, verified-entry protection, required review
metadata, output collisions, and the seven v0.1.4 recurrence candidates.
