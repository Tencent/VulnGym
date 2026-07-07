# Multi-Stage Chain Rebuild Report

This PR rebuilds the five issue #7 targets: `entry-00185`, `entry-00197`, `entry-00290`, `entry-00320`, and `entry-00391`.
The goal is not a line-offset repair. Each entry is rebuilt around the attacker-controlled input, the intermediate propagation or missing check, and the operation where the vulnerability becomes actionable.

## Artifacts

- `data/entries.rebuilt_chains.jsonl`: patch-first view containing only the five rebuilt entries.
- `data/entries.fixed.jsonl`: full 408-entry JSONL after applying the patch file.
- `reports/rebuild_fix_diff.csv`: node-level old/new diff with rebuild rationale.
- `reports/rebuild_manual_review.csv`: manual-review audit file. This pass has no unresolved rows.
- `reports/rebuild_acceptance_matrix.md`: issue #7 acceptance criteria mapped to concrete evidence.
- `scripts/apply_rebuild_patches.py`: regenerates full fixed JSONL and diff from the patch file.
- `scripts/verify_rebuilt_chains.py`: validates schema basics, checks natural-language text for corruption markers, and can compare every `{file,line,code}` against GitHub raw sources.

## Design Choice

This submission intentionally uses a sink-oriented `critical_operation` where that makes the chain easier to review:

- `entry-00185`: critical operation is the final `fsWriteFile` call, while path-blocking logic remains in `trace`.
- `entry-00290`: critical operation is the final `fileOps.writeFile` call, while the dangling-symlink fail-open decision remains in `trace`.
- `entry-00320`: critical operation is the final `async_open` write, while the unsafe path join remains in `trace`.

This keeps root-cause checks visible without hiding the concrete operation that materializes the impact.

## Summary

| entry_id | project | entry point | critical operation | trace nodes | main rebuild |
| --- | --- | --- | --- | ---: | --- |
| entry-00185 | n8n | `write.operation.ts:70` | `file-system-helper-functions.ts:128-132` | 5 | Move from static option/default nodes to attacker-controlled filename, path resolution, policy decision, and final write sink |
| entry-00197 | openclaw | `server.ts:35-36` | `server.ts:57` | 6 | Express the check/use TOCTOU stages with the real `fs-safe.ts` boundary and open handoff |
| entry-00290 | openclaw | `apply-patch.ts:94` | `apply-patch.ts:152` | 6 | Separate the alias assertion, dangling-symlink fail-open check, and final write sink |
| entry-00320 | langflow | `files.py:162` | `local.py:120` | 6 | Move entry to route-level filename capture and follow it to storage write |
| entry-00391 | fastmcp | `director.py:23-28` | `director.py:194-216` | 6 | Track argument unflattening, path parameter capture, raw replacement, and `urljoin` normalization |

## entry-00185: n8n ReadWriteFile writing `.git/config`

The previous chain was anchored on a static `append` default and path helper boundaries, so it did not show where the attacker-controlled filename entered the write flow.
The rebuilt chain starts at `getNodeParameter('fileName', itemIndex)`, follows the write helper handoff, path canonicalization, and path policy decision, and ends at `fsWriteFile(resolvedFilePath, content, ...)`.
The important distinction is that `.git` is not specially denied by the access-control decision, so the final write can materialize malicious Git configuration on disk.

## entry-00197: openclaw media TOCTOU

This is a multi-stage vulnerability. The rebuilt chain keeps a single external entry point but makes the check/use split explicit.
The route captures `req.params.id`, `isValidMediaId` performs only syntactic filtering, `openFileWithinRoot` performs the lexical boundary check, and `openVerifiedLocalFile` opens the checked path.
The critical operation is `handle.readFile()`, the use phase that reads from a handle after the race window.

## entry-00290: openclaw dangling symlink sandbox escape

The root cause is the fail-open symlink resolution path, but the vulnerability is completed by a write operation.
The rebuilt chain starts at the apply_patch tool `execute`, flows through `applyPatch`, `resolvePatchPath`, `assertNoPathAliasEscape`, and `resolveSymlinkHopPath`, then ends at `fileOps.writeFile(target.resolved, hunk.contents)`.
This expresses both why the boundary check can be wrong and where the attacker-controlled patch content is written.

## entry-00320: langflow upload filename traversal

The previous entry point was too far downstream. The rebuilt chain now starts in the upload route where `file.filename` is first copied into `new_filename`.
The trace then shows extension splitting, deduplication, `save_file_routine` handoff, local path assembly, and the final async write.
The critical operation is `async_open(str(file_path), mode)` because that is where the preserved traversal payload becomes a filesystem write.

## entry-00391: fastmcp OpenAPIProvider SSRF and path traversal

The old trace included logger and declaration-level nodes. The rebuilt chain starts at `RequestDirector.build`, follows the handoff into `_build_url`, and highlights raw path-parameter replacement.
It now also includes argument unflattening and path parameter bucket assignment, which makes the data path from `flat_args` to `url_path.replace(...)` explicit.
The critical operation is the `_build_url` block that performs raw `replace` and then `urljoin`, allowing traversal segments in path parameters to affect the final outbound URL.

## Verification

The rebuilt patch contains five entries and 39 nodes. `scripts/verify_rebuilt_chains.py` validates required fields, line spans, non-empty `code`, non-empty `desc`, and natural-language text integrity.
With `--use-remote`, it fetches GitHub raw files at the recorded commits and compares each node's source slice to the recorded `code`.

Recommended commands:

```bash
python -m unittest discover -s tests
python scripts/apply_rebuild_patches.py
python scripts/verify_rebuilt_chains.py
python scripts/verify_rebuilt_chains.py --use-remote
```
