# Multi-Stage Chain Rebuild Report

This PR rebuilds the five issue #7 targets: `entry-00185`, `entry-00197`, `entry-00290`, `entry-00320`, and `entry-00391`.
The goal is not a line-offset repair. Each entry is rebuilt around the attacker-controlled input, the intermediate propagation or missing check, and the operation where the vulnerability becomes actionable.

## Artifacts

- `data/entries.rebuilt_chains.jsonl`: patch-first view containing only the five rebuilt entries.
- `data/entries.fixed.jsonl`: full 408-entry JSONL after applying the patch file.
- `reports/rebuild_fix_diff.csv`: node-level old/new diff with rebuild rationale.
- `reports/rebuild_manual_review.csv`: manual-review audit file. `entry-00290` remains unresolved because the advisory fix changes tests but not production code.
- `reports/rebuild_acceptance_matrix.md`: issue #7 acceptance criteria mapped to concrete evidence.
- `scripts/apply_rebuild_patches.py`: regenerates full fixed JSONL and diff from the patch file.
- `scripts/verify_rebuilt_chains.py`: validates schema basics and semantic anchors, checks natural-language text for corruption markers, compares every `{file,line,code}` against GitHub raw sources, and can verify advisory-fix parent/patch evidence.

## Design Choice

This submission intentionally uses a sink-oriented `critical_operation` where that makes the chain easier to review:

- `entry-00185`: critical operation is the final `fsWriteFile` call, while path-blocking logic remains in `trace`.
- `entry-00290`: `fileOps.writeFile` is retained only as a candidate impact sink; the recorded revision appears fail-closed, so this entry is marked `verify=0` and sent to manual review.
- `entry-00320`: critical operation is the final `async_open` write, while the unsafe path join remains in `trace`.

This keeps root-cause checks visible without hiding the concrete operation that materializes the impact.

## Summary

| entry_id | project | entry point | critical operation | trace nodes | main rebuild |
| --- | --- | --- | --- | ---: | --- |
| entry-00185 | n8n | `write.operation.ts:70` | `file-system-helper-functions.ts:128-132` | 5 | Move from static option/default nodes to attacker-controlled filename, path resolution, policy decision, and final write sink |
| entry-00197 | openclaw | `message-action-params.ts:288` | `web/media.ts:360` | 8 | Rebuild the actual normalize/retarget/hydrate sequence and the stale `sandboxValidated` trust boundary |
| entry-00290 | openclaw | `apply-patch.ts:94` | `apply-patch.ts:152` | 6 | Preserve the candidate chain while recording that the checked revision appears fail-closed (`verify=0`) |
| entry-00320 | langflow | `files.py:162` | `local.py:120` | 6 | Move entry to route-level filename capture and follow it to storage write |
| entry-00391 | fastmcp | `director.py:23-28` | `director.py:208-213` | 6 | Track argument unflattening and isolate the raw path-parameter substitution changed by the security fix |

## entry-00185: n8n ReadWriteFile writing `.git/config`

The previous chain was anchored on a static `append` default and path helper boundaries, so it did not show where the attacker-controlled filename entered the write flow.
The rebuilt chain starts at `getNodeParameter('fileName', itemIndex)`, follows the write helper handoff, path canonicalization, and path policy decision, and ends at `fsWriteFile(resolvedFilePath, content, ...)`.
The important distinction is that `.git` is not specially denied by the access-control decision, so the final write can materialize malicious Git configuration on disk.

## entry-00197: openclaw media TOCTOU

This is a multi-stage vulnerability. The rebuilt chain keeps a single external entry point but makes the check/use split explicit.
`normalizeSandboxMediaParams` reads the caller-controlled path, resolves it while a symlink still points inside the sandbox, and stores that normalized path for later use.
After the symlink is retargeted, attachment hydration passes the stored path with `sandboxValidated: true` and an unscoped `fs.readFile` callback. `loadWebMedia` therefore skips a fresh root check and invokes `readFileOverride(mediaUrl)`.
This is the same two-stage sequence exercised by the regression test added in fix commit `c823a85302119044bc26763644c15fe35dd04f4a`, whose first parent is the recorded vulnerable commit.

## entry-00290: openclaw dangling symlink sandbox escape

The candidate chain starts at the apply_patch tool `execute`, flows through `applyPatch`, `resolvePatchPath`, and `assertNoPathAliasEscape`, then reaches the candidate `fileOps.writeFile` sink.
However, the recorded revision canonicalizes the symlink hop and rejects it when it leaves the sandbox. Advisory fix `4fd29a35bb85a1898ebff518364c467058b50e14` has the recorded commit as its parent but changes only two test files, so it does not identify a missing production guard.
The entry is therefore retained as `verify=0` with an explicit manual-review row instead of claiming a proven fail-open path.

## entry-00320: langflow upload filename traversal

The previous entry point was too far downstream. The rebuilt chain now starts in the upload route where `file.filename` is first copied into `new_filename`.
The trace then shows extension splitting, deduplication, `save_file_routine` handoff, local path assembly, and the final async write.
The critical operation is `async_open(str(file_path), mode)` because that is where the preserved traversal payload becomes a filesystem write.

## entry-00391: fastmcp OpenAPIProvider SSRF and path traversal

The old trace included logger and declaration-level nodes. The rebuilt chain starts at `RequestDirector.build`, follows the handoff into `_build_url`, and highlights raw path-parameter replacement.
It now also includes argument unflattening and path parameter bucket assignment, which makes the data path from `flat_args` to `url_path.replace(...)` explicit.
The critical operation is narrowed to lines 208-213, where raw `str(param_value)` is substituted into the path template. Fix commit `40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71` changes this exact operation to an encoded `safe_value`; the following `urljoin` remains in the trace as the downstream URL-construction effect.

## Verification

The rebuilt patch contains five entries and 41 nodes. `scripts/verify_rebuilt_chains.py` validates required fields, line spans, non-empty `code`, non-empty `desc`, natural-language text integrity, target-specific semantic anchors, and manual-review coverage.
With `--use-remote`, it fetches GitHub raw files at the recorded commits and compares each node's source slice to the recorded `code`.
With `--check-upstream`, it verifies fix-parent relationships and patch evidence for the three entries whose interpretation depends on the upstream security fix.

Recommended commands:

```bash
python -m unittest discover -s tests
python scripts/apply_rebuild_patches.py
python scripts/verify_rebuilt_chains.py
python scripts/verify_rebuilt_chains.py --use-remote
python scripts/verify_rebuilt_chains.py --use-remote --check-upstream
```
