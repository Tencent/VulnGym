# VulnGym chain rebuild report

Target entries: `entry-00185`, `entry-00197`, `entry-00290`, `entry-00320`, `entry-00391`.

This follow-up keeps the scope to the five semantic-misalignment samples. The canonical `data/entries.jsonl` and the snapshot `data/entries.fixed.jsonl` now contain the same parsed content for the rebuilt data, and the verification scripts fail on malformed JSONL instead of silently skipping rows.

## Verification summary

| entry_id | project | entry_point | critical_operation | trace nodes | verify |
|---|---|---|---|---:|:---:|
| entry-00185 | n8n | `write.operation.ts:70` | `file-system-helper-functions.ts:61` | 3 | 1 |
| entry-00197 | openclaw | `server.ts:35-36` | `server.ts:57` | 5 | 1 |
| entry-00290 | openclaw | `apply-patch.ts:94` | `boundary-path.ts:196` | 5 | 1 |
| entry-00320 | langflow | `files.py:122` | `local.py:116` | 5 | 1 |
| entry-00391 | fastmcp | `director.py:23-28` | `director.py:213` | 5 | 1 |

The 33 repaired `{file, line, code}` nodes are intended to be checked with:

```text
scripts/verify_patched_entries.py
scripts/runtime_audit.py --use-remote
```

## entry-00185

Before: the entry point was anchored on the static `append` default and the critical operation was a closing brace in `resolvePath()`. The trace stopped around return-value and syntax-boundary nodes instead of following attacker-controlled `fileName` into the write path.

After: the entry point is `write.operation.ts:70`, where `fileName` is read from node parameters. The trace follows the write operation into `isFilePathBlocked`, then to `fsWriteFile`. The critical operation is the allowlist-only branch in `file-system-helper-functions.ts:61`, which lacks a `.git/` deny rule and therefore lets `.git/config` reach the write sink.

## entry-00197

Before: the sample was marked as a TOCTOU race, but the trace did not clearly separate the request entry, syntax validation, boundary check/open, intermediate checks, and use phase.

After: the entry point is the Express route and `req.params.id` capture at `server.ts:35-36`. The trace records `isValidMediaId`, `openFileWithinRoot`, the post-check TTL decision, and the final `handle.readFile()` use at `server.ts:57`.

Multi-stage note: this entry can stay as a single entry point, but the trace must explicitly describe the check/use phases. The final desc now avoids claiming that replacing a path after a `FileHandle` is returned changes the live handle; the use node is described as consuming the handle produced by the upstream check/open sequence without fresh boundary validation.

## entry-00290

Before: the old chain blurred the root-cause check with the final write sink and included misaligned nodes such as branch syntax or unrelated lines.

After: the entry point is the `apply_patch` tool execution handler at `apply-patch.ts:94`. The critical operation remains `boundary-path.ts:196`, where `resolveSymlinkHopPath(lexicalCursor)` embodies the fail-open dangling-symlink decision. The final write sink `fileOps.writeFile(target.resolved, hunk.contents)` is preserved at the end of the trace so the check-vs-sink distinction is explicit.

Multi-stage note: no extra entry point is needed, but the trace must include both the fail-open boundary check and the downstream write sink.

## entry-00320

Before: the entry point was too low in the filename manipulation logic, after attacker-controlled multipart filename data had already entered the API flow.

After: the entry point is `files.py:122`, where `file.filename` is assigned to `file_name`. The trace follows extension splitting and deduplication, then crosses into local storage where `folder_path / file_name` at `local.py:116` converts the unvalidated filename into a path. The terminal `async_open(str(file_path), mode)` write remains in the trace.

## entry-00391

Before: the critical operation was anchored on the `_build_url` declaration or broad method body, and old trace nodes included declaration/logging-style locations instead of the splice site.

After: the entry point is `RequestDirector.build()` at `director.py:23-28`. The critical operation is now the exact splice line `director.py:213`:

```python
url_path = url_path.replace(placeholder, str(param_value))
```

The trace keeps the call into `_build_url`, the loop that reaches replacement, the single-line splice, and the following `urljoin(...)` normalisation that collapses traversal segments.

## Manual review

`manual_review.csv` is an empty-header file for this round. No target entry is intentionally left unresolved.
