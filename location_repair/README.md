# Code-location repair workflow

`scripts/repair_entry_locations.py` checks every `entry_point`,
`critical_operation`, and `trace[*]` node in `data/entries.jsonl` against the
repository and commit recorded by that entry. It uses only the Python standard
library and the Git CLI.

## Requirements

- Python 3.10 or newer
- Git 2.19 or newer
- network access to the repositories on the first run

No Python packages need to be installed. Source repositories are cached as bare
partial clones under `.cache/location_repair_repos_v2/`; the cache is shared by
all entries and all commits from the same repository. The exact required commits
and their text-sized blobs are fetched together per repository, avoiding a later
network round trip for every repository-wide search.

## Run

From the VulnGym repository root:

```bash
python scripts/repair_entry_locations.py
python scripts/verify_entry_location_outputs.py
python -m unittest discover -s tests -v
```

The first command performs a complete 408-entry run and writes:

- `location_repair/entries.fixed.jsonl`
- `location_repair/fix_diff.csv`
- `location_repair/needs_human.csv`
- `location_repair/run_summary.json`

Useful options:

```bash
# Recheck one or more entries while developing.
python scripts/repair_entry_locations.py \
  --entry-id entry-00103 \
  --entry-id entry-00320 \
  --output-dir /tmp/location-repair-smoke

# Reproduce a run without any clone, fetch, or lazy blob download.
python scripts/repair_entry_locations.py --offline

# Select a persistent cache outside this checkout.
python scripts/repair_entry_locations.py --cache-dir /path/to/source-cache
```

The default worker count is at most four. `--jobs 1` is useful for diagnosing a
repository-specific network problem. `--git-protocol ssh` can be used when HTTPS
access is unavailable.

## Current full-dataset result

The checked-in artifacts were generated from `data/entries.jsonl` at VulnGym
commit `cd69f7e163e08485ab5496115ae03439cda6e27e`:

| Metric | Result |
|---|---:|
| Entries | 408 |
| Nodes checked | 2,889 |
| Repository/commit groups | 166 |
| Exact locations already correct | 2,724 |
| Conservative automatic fixes | 109 |
| Human-review rows | 56 |
| Repository errors | 0 |
| Schema errors | 0 |
| Cold-cache runtime | 309.469 s |
| Offline cached runtime | 89.484 s |

Automatic strategies: 95 `current_start_span_repair`, 12
`nearby_plus_minus_5`, and 2 `same_file_unique`. The span repairs primarily
correct ranges that counted a trailing newline as another source line or stored
multiline code under a single-line location. The human queue contains 55
`no_match` rows and one empty snippet; these remain unchanged.

An offline rerun produced byte-identical `entries.fixed.jsonl`, `fix_diff.csv`,
and `needs_human.csv`. The verifier also rechecked all 2,833 non-human nodes at
their exact repository commit; the remaining 56 nodes are explicitly present in
the human queue.

The four samples prioritized by issue #4 were covered explicitly:

| Entry | Result |
|---|---|
| `entry-00103` | two location fixes (`605-614 → 606-614`, `146-155 → 146-154`) with desc line references synchronized |
| `entry-00185` | one location fix (`75-82 → 76-82`) |
| `entry-00320` | all six nodes already matched the recorded commit |
| `entry-00511` | all seven nodes already matched the recorded commit |

## Matching and repair policy

Whitespace normalization is deliberately narrow:

- leading and trailing whitespace on each line is ignored;
- runs of spaces and tabs are treated as one space;
- CRLF and LF are treated identically;
- code remains line-structured, so unrelated tokens are not joined across lines;
- multiline snippets are supported and produce a schema-compatible line range.

If the annotated file, start/end line, and normalized code already agree, the
node is accepted without searching. Otherwise the script uses the required
ordered strategy:

1. search the original start line ±5 in the original file;
2. search the complete original file;
3. search the repository tree at the exact commit.

The first scope with exactly one match wins. Multiple matches stop automatic
processing immediately and enter `needs_human.csv`; the script never picks the
nearest candidate from an ambiguous set. Empty snippets and low-information
mismatches such as a lone `}` also enter the human queue. A low-information
snippet that matches its original file and exact span is accepted, because no
inference is required.

Repository-wide search uses the longest normalized source line as a Git-grep
prefilter and then verifies the complete multiline snippet. This reduces blob
reads without weakening the final match.

## Description handling

When `file` or `line` changes, the script checks `desc` for explicit location
references. Full paths, changed basenames, Chinese `第 N 行`, English `line N` /
`lines N-M`, and `filename:N` forms are rewritten. `fix_diff.csv` records one of:

- `updated_location_references` — an explicit reference was synchronized;
- `checked_no_location_reference` — the description had no location literal and
  remained semantically applicable;
- `missing_desc` — the optional field was absent.

The script does not attempt to rewrite vulnerability semantics. A location that
cannot be established uniquely remains unchanged and is sent to human review.

## Audit outputs

`fix_diff.csv` contains the entry id, node path, repository/commit, unchanged
code snippet, complete old/new file-line-description values, strategy, description
status, and unique-match evidence.

`needs_human.csv` contains the unchanged node and a machine-readable reason such
as `multiple_matches_in_nearby`, `multiple_matches_in_original_file`,
`multiple_matches_in_repository`, `no_match`, `low_information_code`, or
`repository_unavailable`. Candidate locations are included when available.

`run_summary.json` binds the run to SHA-256 hashes of the input and fixed JSONL
using canonical LF newlines, so verification is stable on Windows and Linux. It
also records the number of entries/nodes/repository-commit groups, strategy and
reason counts, runtime, and repository errors. The verifier cross-checks all four
artifacts, the original dataset, and `data/reports.jsonl`.

## Limits

- Normalization does not parse programming languages or infer renamed symbols.
- Inline explanatory comments or `...` placeholders added by an annotator are
  not silently stripped; they normally produce `no_match` for human review.
- Generated, submodule, Git-LFS, binary, or files larger than 8 MiB are not
  automatically repaired unless their text is directly available within the
  configured limit.
- `--offline` succeeds only after the necessary commits and lazily requested blobs
  have been populated in the cache by an online run.
