# Issue #4 acceptance matrix

## Full-dataset result

| Metric | Result |
| --- | ---: |
| Entries read | 408 |
| Code-location nodes checked | 2,889 |
| Repository/commit pairs | 166 |
| Source commits complete | 166 |
| Automatic repairs | 19 |
| Already correct | 2,841 |
| Manual-review rows | 29 |
| Repository-wide fallback nodes | 27 |
| Measured full online run | 71.876 seconds |
| Cached offline run | 30.270 seconds |
| Required maximum runtime | 600 seconds |

The measured duration is recorded here as benchmark evidence, not in generated
artifacts, because wall-clock time would make otherwise identical reruns
produce different files.

## Requirement mapping

| Issue requirement | Implementation and evidence |
| --- | --- |
| Read JSONL as JSON objects | `load_jsonl` parses and validates every row; output is re-serialized, never edited as raw text. |
| Check all node types | `iter_nodes` covers `entry_point`, `critical_operation`, and every `trace[*]`; baseline test asserts 2,889 nodes. |
| Use the recorded vulnerable revision | Raw files and snapshots are keyed by the full 40-character commit; all 166 source manifest rows are complete. |
| Original → ±5 → file → repository | Resolver stages are explicit and reported for each fix or manual row. |
| Tolerate whitespace, tabs, multiline snippets | Per-line horizontal whitespace normalization retains multiline order and boundaries. |
| Repair only unique matches | Every applied row has `candidate_count=1`; the independent verifier rechecks the exact source span. |
| Do not guess ambiguous/missing cases | 29 unchanged nodes are emitted with stable review IDs, reasons, candidates, and source links. |
| Keep repaired JSONL valid | Both original and fixed datasets pass schema and report-ID mapping validation. |
| Keep `desc` consistent | Explicit file/line anchors are synchronized; non-location prose and step numbers are preserved. |
| Provide an audit trail | Diff CSV includes complete old/new values, strategy, match mode, source URL, and source SHA-256. |
| Run within ten minutes | Full online run completed in 71.876 seconds; cached offline reproduction completed in 30.270 seconds. |
| Be reproducible | Standard-library-only runner, persistent cache, offline mode, deterministic LF artifacts, and independent verifier. |

## Priority samples

| Entry | Result |
| --- | --- |
| `entry-00103` | `trace[1]` repaired `605-614 → 606-614`; `trace[2]` repaired `146-155 → 146-154`; explicit description anchors synchronized. |
| `entry-00185` | `trace[1]` repaired `75-82 → 76-82`; natural matched range used. |
| `entry-00320` | All six nodes already matched their recorded locations. |
| `entry-00511` | All seven nodes already matched their recorded locations. |

## Conservative boundary

The automatic set contains 17 unique nearby repairs and 2 unique same-file
repairs. All 19 are verbatim matches. Sixteen occur in `verify=1` entries but
still have exact source evidence; the three `verify=0` repairs include the
priority drift examples.

Three rows explain why this workflow has 29 manual items while one competing
implementation reports 26:

| Node | Why this workflow retains it |
| --- | --- |
| `entry-00274 trace[3]` | `code` is empty. An empty string matching a blank source line is not location evidence. |
| `entry-00298 trace[0]` | Removing a CJK annotator suffix yields a candidate at line 196, but this is a `verify=1` entry and the complete snippet is not verbatim. |
| `entry-00498 trace[1]` | The suffix is an ordinary English source-style comment. Removing every `//...` suffix would over-normalize real code. |

The competing 26-row result excludes the empty node, applies the projected
verified repair, and strips all `//` suffixes. The smaller number is therefore
not stronger evidence. This workflow deliberately prefers an explicit,
reviewable uncertainty over a silent false positive.

## Regression guards

The focused test suite covers:

- integer-anchor and exact-range semantics;
- natural range ends after shifts;
- CRLF, tab, whitespace, and multiline normalization;
- CJK annotation projection and ordinary-comment preservation;
- ellipsis and low-information rejection;
- unique/ambiguous nearby, file, and repository searches;
- strict and protect policies for verified entries;
- location-only `desc` synchronization;
- stable review IDs and original-node hashes;
- deterministic UTF-8/LF serialization;
- offline repository-snapshot search;
- full baseline shape and schema mapping;
- independent artifact/source verification.
