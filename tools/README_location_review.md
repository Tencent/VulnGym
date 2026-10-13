# Human location-review round trip

`location_review.py` turns the unresolved output from a conservative code-location
repair into an auditable human decision workflow. It is intentionally separate
from automatic matching: an ambiguous or missing match is never selected by this
tool.

This fills the gap between writing `needs_human.csv` and safely applying a
reviewer's decision back to `entries.jsonl`.

## Workflow

### 1. Initialize a decision sheet

The input queue may contain extra columns, but it must contain `entry_id` and
either `field_path` or the `node_path` alias used by some existing repair
scripts (`entry_point`, `critical_operation`, or `trace[N]`). A `reason` column
is copied when present.

```bash
python tools/location_review.py init \
  --input data/entries.jsonl \
  --queue reports/needs_human.csv \
  --decisions reports/location_review_decisions.csv
```

Each row receives two immutable identifiers:

- `expected_node_sha256` binds the decision to the entry id, repository URL,
  commit, field path, and complete node content.
- `review_id` is a short stable identifier derived from that fingerprint.

If the dataset or annotation changes after initialization, `apply` rejects the
old decision instead of silently rebasing it.

### 2. Record the human decision

Fill the following columns without changing the generated identity columns:

| column | value |
| --- | --- |
| `decision` | `apply` or `keep` |
| `new_file` | exact repository-relative path for `apply`; blank for `keep` |
| `new_line` | positive line or `start-end` range for `apply`; blank for `keep` |
| `reviewer` | reviewer identity |
| `rationale` | evidence for selecting the location or keeping it unresolved |

Blank `decision` values remain pending. The apply phase fails closed while any
row is pending unless `--allow-pending` is explicitly supplied.

### 3. Validate and apply

```bash
python tools/location_review.py apply \
  --input data/entries.jsonl \
  --decisions reports/location_review_decisions.csv \
  --output data/entries.reviewed.jsonl \
  --diff reports/location_review_diff.csv \
  --audit reports/location_review_audit.csv
```

For every `apply` decision, the tool:

1. rechecks the node fingerprint and original location;
2. reads the selected file directly from a URL-isolated bare Git cache at the
   entry's exact 40-character commit;
3. requires an exact-case, regular Git blob path and rejects path traversal,
   symlinks, submodules, binaries, and oversized blobs;
4. verifies the selected line against the node's code with whitespace-tolerant
   multiline matching;
5. supports a narrow projection for CJK explanatory comments appended outside
   quoted strings, while rejecting annotation-only snippets;
6. updates explicit file/line anchors in `desc` when present;
7. writes the JSONL, decision diff, and complete audit through atomic file
   replacement only after every row passes.

`verify=1` entries are protected by default. A deliberate review of an already
audited entry must use `--include-verified`.

## Outputs

- `entries.reviewed.jsonl`: full dataset with accepted human decisions applied.
- `location_review_diff.csv`: only applied changes, including reviewer,
  rationale, match mode, Git blob object id, and source SHA-256.
- `location_review_audit.csv`: every `apply`, `keep`, and optionally pending
  decision with its final status.

The original `data/entries.jsonl` is never modified in place.

## Offline and cache behavior

The default cache is `.cache/location-review`. Cache directories include the
GitHub owner, repository name, and a URL digest, so repositories with the same
name under different owners remain isolated. Existing caches are rejected when
their configured origin does not match the entry's `repo_url`.

After the required commits have been fetched once, use:

```bash
python tools/location_review.py apply \
  --decisions reports/location_review_decisions.csv \
  --offline
```

The tool uses Git objects rather than a checkout. It therefore does not execute
repository hooks or follow source-tree symlinks. A successful online fetch also
creates a cache-local provenance ref for the exact commit. Offline mode requires
that ref; merely copying an unrelated commit object into a same-named cache is
not accepted as evidence that the declared origin served it.

## Validation

```bash
python -m unittest discover -s tests -v
python -m py_compile tools/location_review.py tests/test_location_review.py
git diff --check
```

The tests create local Git repositories and run without network access. They
cover fingerprint stability, stale-decision rejection, atomic output behavior,
`verify=1` protection, exact path casing, repository-name collisions, CJK
annotation comments, ranges, source mismatches, and `keep`/pending decisions.

## Limits

- The tool validates a reviewer's selected location; it does not rank or choose
  candidates.
- It does not infer semantic changes to free-form descriptions. Only explicit
  file and line anchors are synchronized.
- Annotation comment projection is deliberately narrow. A pure explanatory
  comment or a snippet that loses most of its source tokens remains invalid.
- Git must be installed. Only GitHub HTTPS repository URLs accepted by the
  VulnGym schema are supported.
