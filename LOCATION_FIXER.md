# Code location repair tool

`tools/fix_code_locations.py` checks the `entry_point`, `critical_operation`,
and `trace[*]` nodes in `data/entries.jsonl` against the repository and commit
recorded by each entry. It applies only unambiguous repairs and produces the
three artifacts required by issue #4.

## Requirements

- Python 3.9 or newer
- Git with network access to the public repositories referenced by the data
- No third-party Python packages

Repositories are stored as reusable bare partial clones under
`.cache/vulngym-location-fixer/`. When a node requires repository-wide search,
the exact commit tarball is cached alongside the clone so the complete source
tree is downloaded once and scanned locally. The cache contains upstream source
objects and must not be committed.

## Run

From the VulnGym repository root:

```shell
python tools/fix_code_locations.py
```

The default outputs are:

- `entries.fixed.jsonl` — all 408 input entries with safe repairs applied.
- `fix_diff.csv` — old/new file, line, and description for every repair.
- `needs_human.csv` — ambiguous, missing, invalid, or unavailable nodes.

Useful focused runs:

```shell
python tools/fix_code_locations.py --verify 0
python tools/fix_code_locations.py --entry-id entry-00103 --entry-id entry-00320
python tools/fix_code_locations.py --offline
```

Filtering limits which entries are checked. Unselected entries are still
copied unchanged to `entries.fixed.jsonl`, so every output remains a complete
dataset.

All options:

```text
--input PATH          input JSONL (default: data/entries.jsonl)
--output PATH         repaired JSONL (default: entries.fixed.jsonl)
--diff PATH           repair audit CSV (default: fix_diff.csv)
--needs-human PATH    manual-review CSV (default: needs_human.csv)
--cache-dir PATH      reusable bare Git cache
--verify all|0|1      select entries by human-audit status
--entry-id ID         select an entry; repeat for multiple entries
--offline             prohibit clone, fetch, and lazy-object downloads
--jobs N              repositories/commits processed concurrently (default: 4)
--git-timeout SEC     per-command Git timeout (default: 120)
```

Standard Git proxy settings and URL rewrite settings are honored. This is
useful in networks where GitHub must be reached through a proxy or an SSH
transport.

## Matching policy

Code is compared as contiguous whole lines. The matcher normalizes CRLF/LF,
removes blank lines at the outer edges of a snippet, trims each line, and
collapses runs of spaces and tabs. Internal blank lines, tokens, comments, and
line order remain significant.

If an exact normalized match fails, the matcher may project away a `//` or `#`
suffix only when it is outside a quoted string and contains CJK text, matching
the schema's allowance for annotator-added Chinese inline comments. The
unmodified snippet is always attempted first, and the projected snippet is
still subject to the same unique-match requirement.

Each non-matching node is handled in this order:

1. Find a unique match whose start is within five lines of the recorded start.
2. Find a unique match in the recorded file.
3. Find a unique match in the full repository tree at the pinned commit.

The recorded position itself is checked before those repair stages. Integer
line values remain integers and identify a snippet's start. Range values remain
`"start-end"` strings and are adjusted to the actual matched span.

The tool never chooses the nearest of several matches. Multiple matches stop
the search at that stage and enter `needs_human.csv`. Missing repositories,
commits, files, code, and invalid values are also recorded rather than guessed.

## Description synchronization

When a location changes, the tool updates only explicit references such as a
repository path, filename, `第 20 行`, or `line 20`. Bare numbers are not
globally replaced. If an old location appears to remain in a description but
cannot be rewritten safely, the complete node repair is withheld and placed in
the manual-review queue with its proposed file and line.

The tool never changes `code`, `verify`, vulnerability categories, or other
top-level semantics.

## Output and failure behavior

- JSONL is UTF-8, newline-delimited, and written with stable sorted object keys.
- CSV is UTF-8 with a BOM for spreadsheet compatibility and correctly quotes
  multiline code and descriptions.
- Outputs are replaced atomically only after processing and schema validation
  succeed.
- `candidates` in `needs_human.csv` is a JSON array. At most 100 candidates are
  displayed, while `candidate_count` retains the full count.
- A repository failure affects only its nodes; malformed input or an unexpected
  processing failure exits nonzero without replacing existing outputs.

## Verification

Run the test suite:

```shell
python -m unittest discover -s tests -v
```

After a full run, rerunning against `entries.fixed.jsonl` should produce zero
new fixes (unresolved manual-review rows may remain):

```shell
python tools/fix_code_locations.py \
  --input entries.fixed.jsonl \
  --output entries.fixed.rerun.jsonl \
  --diff fix_diff.rerun.csv \
  --needs-human needs_human.rerun.csv \
  --offline
```

## Issue #4 run results

The checked-in artifacts were generated on 2026-07-22 from all 408 entries
(2,889 code nodes):

- 20 nodes were repaired: 17 by a unique match within five lines and 3 by a
  unique match elsewhere in the recorded file.
- 28 nodes were left unchanged for manual review: 27 snippets were absent from
  the complete pinned source tree and 1 snippet was empty after normalization.
- The source-archive cache completion run took 112.48 seconds with the bare Git
  metadata cache already populated. A subsequent fully offline warm-cache,
  idempotence run took 112.61 seconds.
- The idempotence run produced zero new repairs, retained the same 28 review
  rows, and reproduced `entries.fixed.jsonl` byte for byte.

Times are environment and network dependent. Both measured full runs were
below the ten-minute target.

## Limitations

- Matching is deliberately not AST-, token-, edit-distance-, or AI-based.
- Only clearly identifiable CJK annotation-comment suffixes are projected;
  other annotation or placeholder text remains unresolved for human review.
- The first full run depends on upstream availability and may download many Git
  objects. Warm-cache runs are faster and deterministic.
- Human decisions are not automatically applied back to the dataset.
