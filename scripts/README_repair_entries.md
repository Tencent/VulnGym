# repair_entries.py

Repair VulnGym `data/entries.jsonl` positions by re-matching each
`entry_point` / `critical_operation` / `trace[i]` code snippet against the
repository snapshot at the entry's pinned commit.

The script is conservative: only code that matches **uniquely** at one of
four escalating locations is rewritten. Everything else lands in
`needs_human.csv` for manual review.

## Pipeline

Per node (`entry_point`, `critical_operation`, each `trace[i]`):

```
original position match
  → nearby ±5 lines unique   → STRATEGY_NEARBY
  → original file unique      → STRATEGY_FILE
  → current commit unique     → STRATEGY_REPO
  → needs_human.csv
```

A match at the original annotated line is a no-op (entry left unchanged).
Original-file searches that surface multiple candidates short-circuit to
needs_human — repo-wide cannot reduce multiple to one.

## Code normalization

Snippets and source files are normalized the same way before comparison:

- `CRLF` / `CR` → `LF`
- Strip leading and trailing empty lines of the snippet
- Collapse runs of whitespace to a single space per line
- Per-line outer strip

Multi-line snippets must match **consecutively and in order** starting from
the candidate line.

No fuzzy matching (no edit distance, no symbol similarity, no LLM guessing).

## Outputs

| File | Description |
|---|---|
| `data/entries.fixed.jsonl` | Repaired dataset. 408 rows, UTF-8, sorted keys, `\n`-terminated. Order matches input. |
| `data/fix_diff.csv` | One row per applied repair. Captures old/new `file`, `line`, `desc`, strategy, and evidence (concrete `(file:start_line)` location the code was matched at). |
| `data/needs_human.csv` | One row per node that could not be auto-repaired. Captures reason, candidate count, and concrete candidates. |

### `fix_diff.csv` columns

`entry_id, field_path, old_file, old_line, old_desc, new_file, new_line, new_desc, strategy, match_mode, evidence`

`strategy` ∈ `{nearby_unique, file_unique, repository_unique}`
`match_mode` ∈ `{single, multiline}`

### `needs_human.csv` columns

`entry_id, field_path, file, line, code, desc, reason, candidate_count, candidates`

`reason` ∈
`{repository_or_commit_unavailable, invalid_node, empty_code, file_not_found, multiple_nearby_matches, multiple_file_matches, multiple_repository_matches, code_not_found, desc_location_conflict}`

## CLI

```bash
# Default — full dataset, offline (use only existing cache snapshots)
python scripts/repair_entries.py --offline

# Only the unverified subset (verify != 1)
python scripts/repair_entries.py --only-unverified --offline

# Allow fetching missing commits
python scripts/repair_entries.py --cache-dir tmp_v0

# Custom output paths
python scripts/repair_entries.py \
    --input data/entries.jsonl \
    --output-jsonl data/entries.fixed.jsonl \
    --fix-diff-csv data/fix_diff.csv \
    --needs-human-csv data/needs_human.csv \
    --cache-dir tmp_v0 \
    --offline --verbose
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--input` | `data/entries.jsonl` | Source entries file. |
| `--output-jsonl` | `data/entries.fixed.jsonl` | Repaired JSONL output. |
| `--fix-diff-csv` | `data/fix_diff.csv` | Per-fix audit row. |
| `--needs-human-csv` | `data/needs_human.csv` | Per-unmatched-node audit row. |
| `--cache-dir` | `tmp_v0` | Root of the per-commit worktree cache. |
| `--only-unverified` | off | Restrict to `verify != 1` entries. |
| `--offline` | off | Never fetch; missing commits go to `needs_human`. |
| `--nearby-window` | `5` | Line window for `nearby_unique`. |
| `--verbose` | off | Emit progress lines to stderr. |

## Cache layout

The script mirrors VulnGym's existing `tmp_v0/` layout:

```
tmp_v0/
├── <org>__<repo>/                       # base repo (bare-ish, has `origin`)
└── <org>__<repo>__<commit8>/            # detached worktree at the commit
```

Each worktree is verified with `git rev-parse HEAD` before use. A mismatch
or missing worktree causes:

- **offline mode** — record `repository_or_commit_unavailable` and move on
- **online mode** — `git fetch` the commit and `git worktree add --detach`

Online mode never falls back to a "nearby" commit when the exact SHA is
unavailable; an unavailable commit stays in needs_human.

## `line` representation preservation

The script preserves the **form** of each node's `line`:

- `int` inputs (`97`) stay as `int` (`98` after a +1 shift)
- `"a-b"` range inputs (`"605-614"`) stay as ranges (`"606-615"`)

The code-block's natural end is `start + len(code_norm) - 1`. If the
original range spanned more lines than the code block (rare — happens when
the annotator captured surrounding context), the trailing offset is
preserved.

## `desc` rewriting

After a position repair, the script inspects `desc` for explicit positional
anchors:

- Chinese line anchors: `第 N 行`, `第 N–M 行` (also matches ASCII hyphen,
  en-dash, em-dash, Unicode minus)
- English line anchors: `line N`, `lines N-M`
- Bare ranges: `N-M 行`
- File anchors: any old-file basename or suffix (e.g. `webhook-helpers.ts`
  or `webhooks/webhook-helpers.ts`)

Anchored numbers are shifted by the same delta as the position; file
anchors are rewritten to the new path when the basename matches.

If the new file has a **different basename**, the rewrite cannot map the
old anchor to a new path with confidence — the position fix is kept but a
`desc_location_conflict` row is appended to `needs_human.csv`.

`第 N 步` ("step N") and similar non-line mentions are **not** touched.

## Determinism

The script is deterministic:

- Targets are sorted by `entry_id` internally before processing.
- Outputs are written in original-entry order (for the JSONL) and in
  processing order (for the CSVs).
- All caches (file content, inverted index) are keyed by canonical paths.

Two consecutive runs produce byte-identical `entries.fixed.jsonl`,
`fix_diff.csv`, and `needs_human.csv`. Verified by
`tests/test_repair_entries.py::TestDeterminism`.

## Known limitations

- Snippets containing human-added comments not present in the source
  (common for annotated `code` blocks with 中文 inline notes) cannot match
  and land in `needs_human.csv` (`reason = code_not_found`).
- Extremely short snippets (`}`, `return`, `else`) usually trigger
  `multiple_*` and stay in `needs_human.csv`.
- `desc` semantics cannot be verified beyond explicit positional anchors.
- Missing commits, uninitialized submodules, or Git LFS issues are not
  papered over with adjacent versions.

## Testing

```bash
python -m pytest tests/test_repair_entries.py -v
```

The suite covers:

- Normalization (CRLF, tabs, whitespace, leading/trailing blanks)
- Single-line and multi-line matchers
- Original-position, nearby, file-wide, and repo-wide strategies
- Multiple-candidate (nearby / file / repo) needs_human paths
- `line` int and range preservation
- `desc` rewrite for Chinese / English / bare-range / file anchors
- `desc` conflict detection on unmappable file anchors
- CSV escaping for multi-line code, Chinese, and embedded quotes
- A two-commit temporary git repository verifying the script reads the
  pinned commit, not HEAD
- Byte-level determinism across two consecutive runs
- UTF-8 and key-sort preservation in JSONL output

## Performance

On the full 408-entry dataset (166 unique `(repo, commit)` pairs):

- ~580 seconds end-to-end on Windows / Python 3.10
- Most nodes match at original position — the inverted per-commit index is
  built lazily only when a node falls through to repo-wide search
- File contents are cached per `(repo, commit, file)`; repeated reads hit
  the in-memory cache
