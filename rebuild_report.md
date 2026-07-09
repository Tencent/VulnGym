# Issue #7 vulnerability-chain rebuild report

This report documents the manual rebuild for the five entries prioritized in
Tencent/VulnGym#7. For each entry, the referenced vulnerable source was checked
at the recorded commit, and each updated `{file, line, code}` node was selected
from code that exists at that commit.

## Summary

| Entry | Project | Result |
|---|---|---|
| `entry-00185` | n8n | Rebuilt misplaced chain around the user-controlled file path and actual write sink. |
| `entry-00197` | openclaw | Clarified the multi-stage TOCTOU chain and check/use split. |
| `entry-00290` | openclaw | Moved the critical operation from the guard helper to the final write primitive. |
| `entry-00320` | langflow | Moved the entry point up to the multipart filename source. |
| `entry-00391` | fastmcp | Moved the critical operation to direct path-parameter substitution and removed the logger node. |

No entry was left for manual review. No `manual_review.csv` is emitted because
all five samples were resolved with source/advisory evidence.

## `entry-00185` - n8n ReadWriteFile `.git` write RCE

### Problem before rebuild

The original entry point was `default: false` for the `append` option, and the
critical operation was the closing brace of `resolvePath()`. Both locations are
related to the write path but neither represents the attacker-controlled input
or the final dangerous operation. The trace also emphasized return/normalization
points rather than the actual write into `.git` metadata.

### Rebuilt chain

The entry point is now `fileName = this.getNodeParameter('fileName', itemIndex)`
in `write.operation.ts`, where the workflow-controlled target path enters the
node execution. The trace follows the write flag selection, the
`writeContentToFile(await resolvePath(fileName), fileContent, flag)` call, the
missing `.git` block in `isFilePathBlocked()`, and finally the actual
`fsWriteFile(resolvedFilePath, content, ...)` sink.

### Evidence

The GHSA states that an authenticated workflow author can chain the
Read/Write Files from Disk node with Git operations by writing specific Git
configuration files. The n8n fix adds `N8N_BLOCK_FILE_PATTERNS` with a default
`.git` blocking regex and checks it in `isFilePathBlocked()`, confirming that
the vulnerable data-flow is path parameter -> file helper block decision ->
write sink.

## `entry-00197` - openclaw sandbox media TOCTOU

### Problem before rebuild

The original chain had plausible line locations but described the issue like a
single normal request path. The issue note asks for multi-stage handling because
the exploit requires a prepared/retargeted media path and then a separate read
trigger.

### Rebuilt chain

The entry point remains the externally reachable `GET /media/:id` route, but
its description now explicitly records the prerequisite media-path preparation
stage. The trace expands through `isValidMediaId(id)`, `openFileWithinRoot`,
the lexical and canonical root checks in `fs-safe.ts`, the size/TTL checks that
sit between validation and use, and the final `handle.readFile()` call.

### Evidence

The advisory describes a time-of-check/time-of-use gap in media handling where
media paths were validated first and read later through a separate path. The
fix commit replaces direct `openFileWithinRoot()` handle exposure in
`server.ts` with `readFileWithinRoot({ rootDir, relativePath, maxBytes })` and
adds root-scoped read helpers for sandbox media call sites. That supports the
updated wording: the model can still express one entry point, but the trace must
name the prerequisite stage and the check/use split.

## `entry-00290` - openclaw dangling symlink sandbox escape

### Problem before rebuild

The original critical operation was
`const linkCanonical = await resolveSymlinkHopPath(lexicalCursor);`, which is a
key guard decision but not the final dangerous operation. The issue note
explicitly called out that the critical operation may have been only a check
instead of the final sink.

### Rebuilt chain

The critical operation is now
`await fileOps.writeFile(target.resolved, hunk.contents);` in `apply-patch.ts`.
The trace keeps the guard chain as supporting evidence: `execute`, `applyPatch`,
`resolvePatchPath`, `assertSandboxPath`, `assertNoPathAliasEscape`, and the
`resolveSymlinkHopPath()` fallback for missing symlink targets.

### Evidence

The advisory and fix commit identify broken final symlink targets outside the
workspace as the vulnerable case. The patch adds tests that expect `applyPatch`
to reject a broken symlink named `jump` that points to an outside `owned.txt`;
without the fix, the write primitive in the add-file path is the operation that
would create or modify that outside file.

## `entry-00320` - langflow v2 upload path traversal

### Problem before rebuild

The original entry point was the `rsplit(".", 1)` filename parsing block. That
block propagates the filename but is not where attacker-controlled input first
enters the API.

### Rebuilt chain

The entry point is now `new_filename = file.filename` in `upload_user_file`,
which reads the multipart `Content-Disposition` filename. The trace then follows
the unchanged traversal string through `rsplit`, `unique_filename`, the
`save_file_routine` call, `storage_service.save_file`, local path concatenation
with `folder_path / file_name`, and the final `async_open(str(file_path), mode)`
write sink.

### Evidence

The GHSA explicitly names `src/backend/base/langflow/api/v2/files.py:162` as the
API-layer source and `LocalStorageService` path concatenation as the storage
layer root cause. `ValidatedFileName` protects URL path parameters, but the v2
upload endpoint receives the filename from multipart metadata, so the entry
point must be above the parsing/splitting block.

## `entry-00391` - fastmcp OpenAPIProvider SSRF + path traversal

### Problem before rebuild

The original trace included a logger/comment step and the critical operation
was the method declaration of `_build_url()`. The issue note asks to locate the
critical operation at the concatenation/substitution point and remove unrelated
logger nodes.

### Rebuilt chain

The critical operation is now
`url_path = url_path.replace(placeholder, str(param_value))`, where raw path
parameters are substituted into the OpenAPI path template without URL encoding.
The trace follows `build()`, `_unflatten_arguments(...)`,
`path_params[openapi_name] = value`, the call to `_build_url(...)`, the direct
replacement loop, and the final `urljoin(...)` normalization.

### Evidence

The advisory identifies the root cause as direct path-parameter substitution
without URL encoding followed by `urljoin()`, which interprets `../` traversal
segments. The updated chain reflects both parts: the direct substitution is the
core critical operation, and `urljoin()` is kept as the next trace node that
turns the substituted payload into an escaped backend URL.
