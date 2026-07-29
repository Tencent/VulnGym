# Issue #7 — multistage and semantically misplaced chain rebuild

## Scope and result

This patch covers all five priority samples named by Issue #7 and one directly
fix-backed FastMCP sibling:

| Entry | Vulnerability | Result | Confidence |
|---|---|---|---|
| `entry-00185` | n8n `.git/config` write chained to Git RCE | rebuilt | `verify=1` |
| `entry-00197` | OpenClaw media TOCTOU sandbox escape | rebuilt as two stages | `verify=1` |
| `entry-00290` | OpenClaw dangling-symlink write escape | candidate chain rebuilt | `verify=0`, manual review |
| `entry-00320` | Langflow v2 upload path traversal | rebuilt | `verify=1` |
| `entry-00391` | FastMCP RequestDirector SSRF/path traversal | rebuilt | `verify=1` |
| `entry-00394` | FastMCP OpenAPITool end-to-end path | rebuilt | `verify=1` |

The result contains 52 annotated node occurrences and 22 field-level changes.
Every node matches its pinned vulnerable commit. Five distinct fix commits are
direct children of their corresponding vulnerable snapshots. The separate
upstream check also validates advisory identity, fix paths, and patch-specific
markers.

## Evidence matrix

| Advisory | Vulnerable snapshot | Direct child fix | Evidence used |
|---|---|---|---|
| `GHSA-X2MW-7J39-93XQ` | `n8n@538181c` | `e22acaab` | advisory references the fix; patch adds default `.git` blocking through `N8N_BLOCK_FILE_PATTERNS` and `isFilePatternBlocked` |
| `GHSA-7XMQ-G46G-F8PV` | `openclaw@4320cde` | `c823a853` | advisory describes check/use drift; patch replaces unscoped `fs.readFile` with `createRootScopedReadFile` |
| `GHSA-QCC4-P59M-P54M` | `openclaw@8b5ebff` | `4fd29a35` | advisory references the fix, but the direct child changes only two tests |
| `GHSA-G2J9-7RJ2-GM6C` | `langflow@e8bbae8` | `d50eda2a` | advisory identifies both vulnerable lines; patch sanitizes multipart names and adds storage containment |
| `GHSA-VV7Q-7JX5-F767` | `fastmcp@c861862` | `40bdfb6b` | advisory references the fix; patch URL-encodes path parameters before substitution |

The OpenClaw TOCTOU and Langflow fix commits were independently correlated by
their direct-parent relationship and patch semantics even though the global
advisory reference list does not expose those commit URLs.

## Rebuilt chains

### `entry-00185` — n8n file write plus external Git prerequisite

```text
getNodeParameter("fileName")
  -> resolvePath(fileName)
  -> isFilePathBlocked returns false
  -> fsWriteFile(resolvedFilePath, content)
  -> prerequisite outside this entry: trigger a Git operation
```

The previous entry and critical anchors were unimportant values or closing
braces. The rebuilt entry starts where the workflow controls `fileName`, records
the missing `.git` policy decision, and ends at the actual file-write sink.
The report does not pretend that writing alone executes a command: the advisory
requires a later Git operation, which is an explicit external prerequisite.

### `entry-00197` — OpenClaw two-stage TOCTOU

```text
Stage 1 (check)
  raw media argument
  -> resolveSandboxedMediaSource(...)
  -> save normalized path

attacker retargets symlink

Stage 2 (use)
  reload saved media path
  -> loadWebMedia(..., sandboxValidated=true, unscoped fs.readFile)
  -> skip fresh local-root check
  -> readFileOverride(mediaUrl)
```

The original `/media/:id` chain opened a file handle before the read; retargeting
a symlink does not change an already-open handle. The rebuilt chain follows the
actual check/use gap fixed by `c823a853`. Source definition order is deliberately
not confused with runtime order.

### `entry-00290` — conservative candidate, not forced ground truth

```text
apply_patch execute(args)
  -> applyPatch(input, sandbox policy)
  -> resolvePatchPath(hunk.path)
  -> assertNoPathAliasEscape(...)
  -> resolveSymlinkHopPath + isPathInside guard
  -> candidate fileOps.writeFile sink
```

The advisory says dangling symlink hops could escape the boundary, but the
recorded vulnerable snapshot appears to canonicalize the hop and fail closed.
More importantly, direct child fix `4fd29a35` modifies only
`apply-patch.test.ts` and `path-alias-guards.test.ts`; it contains no production
code delta from which to identify the missing guard. The candidate chain is
therefore useful for review but remains `verify=0`.

### `entry-00320` — Langflow upload filename to storage sink

```text
new_filename = file.filename
  -> extension split preserves traversal text
  -> unique_filename reconstruction
  -> save_file_routine(..., file_name=unique_filename)
  -> file_path = folder_path / file_name
  -> async_open(file_path)
```

The entry is moved one line upward to the actual multipart input. The previous
trace included an unrelated empty-content branch from a helper. The rebuilt
chain follows the advisory's two-layer explanation and the direct child fix:
input validation at the API layer plus canonical containment in the storage
layer.

### `entry-00391` and `entry-00394` — FastMCP OpenAPI URL construction

```text
flat_args / OpenAPITool arguments
  -> _unflatten_arguments
  -> path_params[openapi_name] = value
  -> url_path.replace(placeholder, str(param_value))
  -> urljoin(...)
  -> httpx.Request
  -> OpenAPITool only: authenticated client send
```

The critical operation is the raw path-parameter substitution at
`director.py:208-213`, not the `_build_url` declaration or the generic network
send. Fix `40bdfb6b` replaces the raw value with URL-encoded `safe_value`.
Logger-only nodes are removed.

## Confidence boundaries and manual review

Three cases appear in `issue-7-multistage-chains.manual_review.csv`:

- `entry-00290`: rebuilt candidate, kept `verify=0` because the named fix is
  test-only.
- `entry-00392` and `entry-00395`: the FastMCP resource path contains a similar
  unencoded substitution in `components.py`, but fix `40bdfb6b` changes only
  `director.py` and its tests. These records remain unchanged until a
  resource-path reproduction proves the exploit path.

This distinction is intentional: structural similarity is evidence for a
candidate, not permission to manufacture verified ground truth.

## Reproducibility and verification

The generator preserves non-target JSONL lines byte-for-byte, merges prior
field history into a deterministic diff, writes the manual-review artifact,
and emits a SHA-256 manifest. The independent verifier does not import the
generator; it reconstructs the 393-verified-entry pre-patch state from the CSV,
reapplies all 22 changes, validates semantic anchors and confidence boundaries,
and checks artifact hashes.

```bash
python3 scripts/apply_issue7_multistage_chain_patch.py
python3 scripts/verify_issue7_multistage_outputs.py
python3 -m unittest tests.test_issue7_multistage_chains -v
GITHUB_TOKEN="$(gh auth token)" \
  python3 scripts/apply_issue7_multistage_chain_patch.py --check-upstream
```

Expected results:

- canonical dataset: 408 entries;
- rebuilt targets: 6;
- verified rebuilt targets: 5;
- annotated node occurrences: 52;
- field-level diff rows: 22;
- manual-review boundaries: 3;
- global audit state: 397 / 408 entries, 178 fully verified advisories,
  0 partially verified advisories.
