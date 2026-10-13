# Code location repair tool

`scripts/fix_code_locations.py` checks VulnGym annotation nodes against the
source repository and commit recorded in each entry. It uses each node's `code`
snippet as the primary anchor and repairs `file` / `line` only when there is a
single unambiguous match.

## Run

The default run audits all 408 entries:

```bash
python scripts/fix_code_locations.py
```

Use a verify bucket for a focused rerun:

```bash
python scripts/fix_code_locations.py --verify 0
```

If HTTPS access to GitHub is unstable but SSH authentication is available:

```bash
python scripts/fix_code_locations.py --verify 0 --git-protocol ssh
```

Useful focused run:

```bash
python scripts/fix_code_locations.py --entry-id entry-00103 --entry-id entry-00320
```

## Outputs

- `data/entries.fixed.jsonl`: JSONL with automatic repairs applied.
- `reports/fix_diff.csv`: every automatic modification, including old/new
  `file`, `line`, `desc`, strategy, and source evidence.
- `reports/needs_human.csv`: nodes with multiple matches, no match, invalid
  metadata, or checkout failures.
- `reports/code_location_summary.md`: reviewer-friendly summary with selected
  entries, fixed/manual counts, strategy counts, and manual-review reasons.
- `reports/code_location_manifest.json`: platform-independent SHA-256
  fingerprints for the input rows, fixed rows, diff rows, and human queue.
- `reports/code_location_acceptance_matrix.md`: mapping from issue acceptance
  criteria to committed artifacts and verification commands.

## Matching Strategy

The script normalizes snippets and candidate source slices by:

- stripping leading/trailing blank lines from snippets;
- stripping leading/trailing whitespace on each line;
- collapsing runs of spaces/tabs to a single space;
- preserving line order and supporting multi-line snippets.

For mismatched nodes, repair attempts are conservative and ordered:

1. Search the original file within `--nearby-lines` before/after the original
   start line. Default is 5.
2. Search the original file.
3. Search all tracked files in the checked-out repository.

Only a unique match is repaired. Multiple matches or no matches are written to
`needs_human.csv` and left unchanged.

An integer `line` is treated as the start anchor of a multi-line snippet. It is
not mechanically expanded into a range when the snippet already starts at that
line. A string `"start-end"` location must match both boundaries. This avoids
turning valid start anchors into noisy automatic repairs.

Very low-information snippets such as a standalone `}`, `);`, or `return;` are
also sent to `needs_human.csv` even if they have a unique textual match. These
snippets are too generic to safely prove a semantic code location by themselves.

## Source Cache

Repositories are cloned under `.cache/source_repos` by default. For each
`repo_url` / `commit`, the script fetches and checks out the exact commit, then
uses `git ls-files` to decide which files to scan.

Before using a cache, the tool requires a canonical GitHub repository URL, a
40-character commit SHA, and an `origin` URL that resolves to the recorded
repository. A cache directory from another repository is rejected instead of
silently reused.

Use `--offline` to require the cache to already contain the needed repos and
commits.

When `--offline` is used and a repo or commit is missing from the cache, the
affected nodes are written to `reports/needs_human.csv` instead of blocking on
network access.

## Desc Handling

When a node location changes, the script performs a narrow text rewrite on
`desc`:

- exact old file path to new file path;
- old basename to new basename when the file changes;
- contextual line references such as `第 123 行`, `line 123`, or `lines 123-125`.

If no safe rewrite is found, `desc_status` is recorded as
`unchanged_needs_review` in `fix_diff.csv`.

## Delivered Artifacts

The checked-in output artifacts were generated from the current issue #4 repair
set:

- entries scanned: 408
- automatic repairs: 12
- manual-review rows: 75

The CSVs and summary are intended to make the automatic changes auditable while
keeping ambiguous nodes out of the fixed JSONL.

Verify the committed artifacts without network access:

```bash
python scripts/verify_code_location_outputs.py
```

Verify all 12 repaired nodes against raw source files at their pinned commits:

```bash
GITHUB_TOKEN="$(gh auth token)" python scripts/verify_code_location_outputs.py --check-source
```

The verifier also proves that only `file`, `line`, and narrowly synchronized
`desc` fields changed, human-queue nodes stayed unchanged, and every committed
artifact still matches the manifest fingerprints.

## Limits

This tool does not infer semantic call order and does not rewrite ambiguous
descriptions. It also skips files larger than `--max-file-bytes` during text
search. The intended policy is to prefer `needs_human.csv` over risky repairs.
