# n8n Semantic Annotation Repair Notes

Scope: issue #6, six n8n samples:

| entry_id | focus |
|---|---|
| `entry-00099` | workflow expression sandbox escape, evaluator execution point |
| `entry-00100` | workflow expression sandbox escape, evaluator execution point |
| `entry-00103` | webhook `Content-Type` whitespace bypass and CSP sandbox decision |
| `entry-00176` | Python Code node `__objclass__` escape reaching `exec` |
| `entry-00511` | VM expression `extend.ts` native function dispatch |
| `entry-00512` | VM runtime writable `__sanitize` slot in `reset.ts` |

## Comparison With Existing PRs

This PR was prepared after reviewing the open duplicate work for issue #6:

- #12 provides a strong patch fragment, review notes, and source verifier, but
  keeps the repaired rows in sidecar JSONL files instead of updating
  `data/entries.jsonl`.
- #13 covers the same six entries with per-entry notes, but keeps the delivery
  split across output directories.
- #21 updates the canonical dataset directly, but does not include the same
  review artifacts or source-backed verifier.

This PR keeps the useful semantic improvements from that review trail while
changing the delivery shape to a smaller canonical data patch plus reusable
review artifacts. In particular, the existing PRs correctly identify that:

- `entry-00099` and `entry-00100` should not end at `PrototypeSanitizer` or
  `sanitizer` definitions; the malicious expression must reach the evaluator.
- `entry-00176` should not use the static `BLOCKED_ATTRIBUTES` list as the
  final critical operation; the bypass matters because the code reaches Python
  `exec`.
- `entry-00511` should distinguish native function resolution from the later
  native `apply` call.
- `entry-00512` should keep `reset.ts` as the critical defect but explain why a
  writable `__data.__sanitize` slot is reachable from user expression code.

This PR applies the repaired rows directly to `data/entries.jsonl`, keeps a
six-row patch JSONL for focused review, and includes an upstream-aware verifier
and unit tests. It also sharpens `entry-00103`: the entry point is moved to the
`RespondToWebhook` node code that reads user-configured response headers, which
better matches issue #6's requirement that `entry_point` reflect external input
or user configuration entering the chain.

## Repair Principles

1. `entry_point` should be externally meaningful: an HTTP trigger, workflow
   parameter, node setting, or user-controlled code string entering the chain.
2. `critical_operation` should be the operation that makes the vulnerability
   hold: evaluator execution, CSP sandbox decision, Python `exec`, native
   function invocation, or writable sanitizer initialization.
3. `trace` should keep the important data-flow/control-flow nodes and drop
   static declarations, wrappers, repeated helper definitions, or unrelated
   defensive background.
4. Every `{file,line,code}` snippet is checked against the vulnerable n8n
   commit by `scripts/verify_n8n_semantic_annotations.py --check-upstream`.
5. No schema change is required. The repair uses only existing `SCHEMA.md`
   fields.

## Per-Entry Summary

### `entry-00099`

Old problem: the original critical operation stopped at
`PrototypeSanitizer`, which is a defensive AST hook and patch location, not the
point where a malicious workflow expression is evaluated.

New shape: keep the workflow execution HTTP route as the external trigger, then
trace expression detection, syntax extension, `renderExpression`, and
`evaluateExpression` until the evaluator call in
`packages/workflow/src/expression-evaluator-proxy.ts`.

### `entry-00100`

Old problem: the critical operation pointed at the `sanitizer` function
definition, and the trace included static constants and defensive setup nodes.

New shape: keep `resolveSimpleParameterValue` as the parameter entry point and
end at the same evaluator call used by `entry-00099`, while retaining
`PrototypeSanitizer` only as a control-flow explanation node for the incomplete
checks.

### `entry-00103`

Old problem: the old critical operation highlighted `toLowerCase()` in
`isHtmlRenderedContentType()`, which explains the trim bug but not the security
decision that omits CSP sandboxing.

New shape: start where the `RespondToWebhook` node reads user-configured
response headers, then follow header writing, HTML content-type classification,
and the `needsSandbox` decision that controls whether
`Content-Security-Policy` is set.

### `entry-00176`

Old problem: `BLOCKED_ATTRIBUTES` is only a static denylist. It explains why
`__objclass__` was missed, but it is not the operation where attacker-supplied
Python code runs.

New shape: trace the user Python code from the Code node parameter through
`PythonTaskRunnerSandbox`, `TaskAnalyzer.validate`, `visit_Attribute`, process
creation, compilation, and finally `exec(compiled_code, globals)`.

### `entry-00511`

Old problem: `data.extend = extend` is helper exposure, not external input, and
the old critical operation stopped at native function lookup rather than
invocation.

New shape: start at `resolveSimpleParameterValue`, follow VM expression
evaluation into expression-runtime, keep native fallback as a trace node, and
mark the native `foundFunction.function.apply(input, args)` call as the
critical operation.

### `entry-00512`

Old problem: `renderExpression` was too internal for an entry point, while the
critical operation needed more explanation about why `__sanitize` is writable
and reachable.

New shape: start at the manual workflow execution HTTP route, trace the saved
workflow into expression evaluation, show AST sanitizer insertion, bridge
execution, `resetDataProxies`, and keep
`globalThis.__data.__sanitize = __sanitize` as the critical writable runtime
slot.

## Artifacts

| artifact | purpose |
|---|---|
| `data/entries.jsonl` | canonical dataset updated with the six repaired rows |
| `data/entries.n8n_semantic_fixed.jsonl` | six-row patch fragment |
| `reports/n8n_semantic_fix_diff.csv` | field-level diff for entry, critical, trace |
| `reports/n8n_semantic_acceptance_matrix.md` | issue #6 acceptance mapping |
| `scripts/apply_n8n_semantic_patches.py` | idempotent patch applier for `data/entries.jsonl` |
| `scripts/verify_n8n_semantic_annotations.py` | local and optional upstream verifier |
| `tests/test_n8n_semantic_annotations.py` | unit tests for patch validity and semantic anchors |
