# Complex chain rebuild report

## Method

Each replacement node is extracted from the entry's pinned vulnerable commit.
Entry points represent attacker-controlled input or the main trigger; critical
operations represent the final security-impacting use. Guards and failed checks
belong in `trace`, not in `critical_operation`. Pure logger, comment, return,
closing-brace, and method-declaration anchors are removed.

## entry-00185: n8n Git configuration write

The old annotations focused on append defaults and helper return boundaries.
The rebuilt chain starts at workflow-controlled `fileName`, follows resolution
and `isFilePathBlocked`, and ends at `fsWriteFile`. Exploitation has two stages:
the node first writes Git configuration/metadata, then a later Git operation
interprets it and executes the configured command. The current schema can
represent the write stage and document the Git trigger prerequisite in `desc`.

## entry-00197: OpenClaw media TOCTOU

This is explicitly multi-stage. A media path/symlink is prepared and retargeted
between validation and use; a separate `/media/:id` request is the main trigger.
The single `entry_point` remains that route, while its description records the
prerequisite stage. The trace includes lexical and canonical root checks and the
intervening size/TTL work before the handle read. A backward-compatible future
schema could add optional `prerequisites[]` or `stages[]`; adding a second
mandatory entry point would break existing consumers and is not proposed here.

## entry-00290: OpenClaw dangling symlink

The previous critical operation was a guard call. The rebuilt chain begins with
agent-supplied patch text, follows lexical/alias validation and the dangling
symlink ENOENT fallback, and ends at `fileOps.writeFile`. This distinguishes the
root-cause check from the actual out-of-workspace write.

## entry-00320: Langflow multipart filename traversal

The old source began at `rsplit`, after attacker input was already present. The
new source captures `file.filename`, follows uniqueness reconstruction and
`save_file_routine`, then records `folder_path / file_name` and `async_open` as
the final arbitrary-write operation.

## entry-00391: FastMCP OpenAPI path parameter

Method declarations and logger calls are not evidence of propagation. The
rebuilt chain starts with `flat_args`, records classification into `path_params`,
then raw placeholder replacement and `urljoin`. The critical range contains
both unencoded substitution and normalization because together they permit
backend-path escape and SSRF.

## Review status

All selected locations are source-backed and no unresolved candidate remains,
so `rebuild_manual_review.csv` contains only its header. Entries remain
`verify=0` pending maintainer review. No schema field is added.
