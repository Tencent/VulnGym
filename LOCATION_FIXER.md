# Code location repair tool

`tools/fix_code_locations.py` checks every `entry_point`, `critical_operation`,
and `trace[*]` node against the repository and commit recorded in
`data/entries.jsonl`. It requires Python 3.9+ and Git; no third-party Python
packages are needed.

## Run

From the repository root:

```shell
python tools/fix_code_locations.py
```

This writes the issue deliverables to the current directory:

- `entries.fixed.jsonl`: all input rows with safe location repairs applied.
- `fix_diff.csv`: old/new location and description plus the repair strategy.
- `needs_human.csv`: ambiguous, missing, invalid, or unavailable nodes.

Repositories are partial-cloned under `.cache/vulngym-location-fixer`. Exact
and same-file checks read individual Git blobs; a reusable commit worktree is
created lazily only when repository-wide search is required. Use `--cache-dir
PATH` to move the cache or `--offline` to prohibit network access after warming
it. Useful focused runs:

```shell
python tools/fix_code_locations.py --verify 0
python tools/fix_code_locations.py --entry-id entry-00103 --entry-id entry-00320
```

All output files are still complete: filtering controls which rows are checked,
while unchecked input rows are copied unchanged to `entries.fixed.jsonl`.

## Repair strategy

Matching strips leading/trailing whitespace from each line, collapses tabs and
spaces, and supports contiguous multi-line snippets. A node is checked in this
order:

1. Its recorded location and span.
2. A unique match starting within five lines of the recorded start.
3. A unique match in the original file.
4. A unique match in the complete repository tree at the pinned commit.

Only unique matches are applied. The last three strategies are recorded as
`nearby`, `same_file`, and `repository`. Multiple matches and no matches are
never guessed; their candidates and reason are written to `needs_human.csv`.

Descriptions preserve their vulnerability semantics. If a description
explicitly contains the old line number or range, that reference is updated to
the new value (including Unicode dash variants). Other prose is not generated
or rewritten. Old and new descriptions are logged in `fix_diff.csv`.

## Limits

- Snippets must match whole normalized lines; token-, AST-, and fuzzy matching
  are intentionally omitted to avoid false repairs.
- Internal blank lines are matched exactly after trimming the snippet's blank
  leading and trailing lines.
- The first run downloads pinned Git objects and depends on upstream repository
  availability. Later runs reuse the cache.
- Repository-wide searches read text files from the pinned worktree. Very common
  snippets are capped at 101 reported candidates to bound work and CSV size.

Run the unit tests with:

```shell
python -m unittest discover -s tests -v
```
