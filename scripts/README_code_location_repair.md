# VulnGym code-location repair

This workflow implements the source-backed audit requested by Issue #4. It
checks every `entry_point`, `critical_operation`, and `trace[*]` node against
the exact repository commit recorded by that entry. The source commit—not the
current upstream branch—is the authority.

The checked-in input is never modified. Repairs are written to
`data/entries.fixed.jsonl`, and every decision is represented in a CSV or
summary artifact.

## Reproduce the artifacts

Python 3.10 or newer is sufficient; the workflow uses only the standard
library.

```bash
# Online run. Downloads raw files and only the commit snapshots needed by
# repository-wide fallback.
python3 scripts/repair_code_locations.py --mode fix

# Reproduce from the persistent source cache without network access.
python3 scripts/repair_code_locations.py --mode fix --offline

# Independently prove that the generated dataset and audit files agree.
python3 scripts/verify_code_location_outputs.py

# Run the focused regression suite.
python3 -m unittest discover -s tests -p "test_repair_code_locations.py" -v
```

The default cache is
`~/.cache/vulngym-code-location`. Raw files are keyed by
`(repo_url, commit, file)`, and complete snapshots are keyed by
`(repo_url, commit)`. Delete that directory to measure a cold run.

Useful options:

```bash
# Audit selected entries while developing.
python3 scripts/repair_code_locations.py \
  --mode fix \
  --entry entry-00103 \
  --entry entry-00185

# Protect every verify=1 node from automatic repair.
python3 scripts/repair_code_locations.py \
  --mode fix \
  --verified-policy protect

# List all paths and defaults.
python3 scripts/repair_code_locations.py --help
```

## Search and repair policy

The resolver normalizes CRLF/CR to LF and collapses horizontal whitespace per
line. It preserves line boundaries, so a multiline snippet must still occur
contiguously and in order.

For each node it performs this cascade:

1. Validate the recorded location.
2. Search for a unique match whose start is within ±5 lines.
3. Search the complete recorded file.
4. Search the complete repository snapshot at the pinned commit.
5. Queue any ambiguous, missing, unsafe, or unavailable case for review.

Only a unique and sufficiently informative match may change `file` or `line`.
No edit-distance, fuzzy-token, wildcard, or LLM guess is used.

Line values have two different schema meanings:

- an integer is the snippet's start anchor, even when `code` is multiline;
- a `"start-end"` string is an explicit span and must match both boundaries.

Consequently, a correct integer anchor is not converted to a range. When a
range is repaired, its new end is the natural end of the matched code rather
than the old range width.

## Annotation and verified-entry boundary

Exact matching always runs first. A second projection may remove only a
clearly annotator-authored CJK `//` or `#` suffix from the snippet side. Source
text is never stripped, ordinary source comments are preserved, and `...` or
`…` is never treated as a wildcard.

Under the default `strict` policy:

- a unique verbatim repair is allowed for both `verify=0` and `verify=1`;
- a projected repair in `verify=1` is sent to manual review;
- empty and low-information snippets cannot establish a shifted location.

The stricter `protect` policy sends every repair candidate in a verified entry
to manual review.

## Description synchronization

When a location changes, `desc` is updated only for explicit location anchors:

- `第 N 行` and `第 N-M 行`;
- `line N` and `lines N-M`;
- old file paths or basenames.

Numbers with other semantics, such as `第 1 步`, are not rewritten. A
description with no explicit location reference is retained byte-for-byte.

## Generated artifacts

| Artifact | Purpose |
| --- | --- |
| `data/entries.fixed.jsonl` | Complete repaired dataset; input order and schema retained. |
| `reports/fix_diff.csv` | Before/after node evidence, strategy, source URL, and source hash for every automatic repair. |
| `reports/needs_human.csv` | Stable manual-review IDs, original-node hashes, reasons, candidates, and source URLs. |
| `reports/code_location_sources.csv` | Per-commit raw-file and snapshot coverage. |
| `reports/code_location_report.json` | Machine-readable counts and input/output integrity hashes. |
| `reports/code_location_report.md` | Human-readable run summary. |

CSV files use RFC-compatible quoting, including for multiline code. Every
generated artifact uses UTF-8, LF line endings, deterministic row ordering,
and a final newline. Runtime duration is printed to the terminal but omitted
from artifacts so cached reruns remain byte-identical.

## Independent verification

`verify_code_location_outputs.py` does not rerun the repair decision logic. It
checks the outputs from the opposite direction:

- the original and fixed datasets both satisfy the dataset/report mapping;
- every mutation has exactly one `fix_diff.csv` row;
- applying only those rows recreates the fixed dataset exactly;
- no `code` field changed;
- every automatic fix is unique and verbatim;
- each repaired snippet exists at the recorded file/span and source hash;
- each human-review row still hashes to its original node;
- source coverage and report counts balance;
- all artifacts use deterministic LF encoding.

This separation catches both resolver mistakes and incomplete audit logs.

## Manual-review workflow

`review_id` is stable for an `(entry_id, field_path)` pair.
`expected_node_sha256` binds the review row to the exact original node. A
future review tool can therefore reject stale decisions after the dataset
changes instead of applying them to a different node.

The current baseline leaves 29 nodes unchanged for explicit review:

- 22 snippets not found anywhere in the pinned repository;
- 5 snippets containing an ellipsis that must not become a wildcard;
- 1 empty snippet, which cannot prove a source location;
- 1 projected match in a verified entry, where verbatim evidence is required.

These rows are unresolved data-quality questions, not failed automatic fixes.
