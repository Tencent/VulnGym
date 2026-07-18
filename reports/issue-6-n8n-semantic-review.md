# Issue #6: n8n semantic review

## Scope

This review corrects the six entries named in Issue #6 and adds two independently
audited n8n entries whose annotations have the same semantic failure mode:

- Required baseline: `entry-00099`, `entry-00100`, `entry-00103`,
  `entry-00176`, `entry-00511`, `entry-00512`
- Additional findings: `entry-00182`, `entry-00191`

All eight entries remain or become `verify=0`. A correction should not inherit a
previous human-review bit before maintainers review the new evidence chain.

## Review method

For every entry, the source snippets were checked against the exact vulnerable
commit recorded in `data/entries.jsonl`. Advisory text, the vulnerable snapshot,
the upstream security patch, and regression tests were compared before choosing
the input boundary, security decision, and impact point.

The selection rule is:

1. `entry_point` must receive a request, workflow parameter, node option, or other
   attacker-controlled value.
2. `critical_operation` must execute code, make the security decision that is
   bypassed, or perform the unsafe transformation that makes exploitation possible.
3. `trace` must describe an executable data/control path; declarations and policy
   constants may appear only as supporting root-cause evidence.

## Required entries

### entry-00099 / entry-00100

The old critical operations were `PrototypeSanitizer` or `sanitizer` declarations.
Those declarations describe defenses but do not execute the expression. Both
entries now end at `expression-evaluator-proxy.ts:19-20`, where the transformed
attacker expression is passed to the Tournament evaluator. `entry-00099` retains
the externally reachable workflow-run route; `entry-00100` starts at the
`parameterValue` boundary in `resolveSimpleParameterValue`.

Rejected candidates:

- `expression-sandboxing.ts:244`: relevant missing visitor/root-cause context,
  but a function declaration is not the RCE execution point.
- `expression-sandboxing.ts:330-336`: the intended property guard, but the
  exploit succeeds by preventing this function from protecting the dangerous access.

### entry-00103

The old entry point was a lone closing brace. The new chain starts where workflow
response headers are written, reads `content-type`, calls
`isHtmlRenderedContentType`, and ends at `html-sandbox.ts:20`. Lowercasing without
trimming preserves leading whitespace, so both HTML `startsWith` checks fail and
the CSP sandbox header is skipped.

Rejected candidate:

- `webhook-helpers.ts:615`: a block boundary that neither receives the malicious
  header nor makes the CSP decision.

### entry-00176

The static `BLOCKED_ATTRIBUTES` declaration is retained as root-cause evidence,
but the critical operation is now `task_analyzer.py:66`, where the analyzer
checks each literal AST attribute. The vulnerable snapshot both omits
`__objclass__` from the denylist and fails to cover dynamic `getattr(obj, name)`
access in this visitor. The trace continues through the normal `exec` sink to
distinguish the bypass decision from its impact.

Rejected candidates:

- `constants.py:126`: root-cause configuration, but it does not inspect an AST node.
- `task_executor.py:213`: impact point shared by all accepted Python tasks, not the
  vulnerability-specific bypass decision.

### entry-00511

The entry now begins at the user-controlled `parameterValue`. The old critical
operation returned `inputAny[functionName]`; it resolved the Function constructor
but did not invoke it. The new critical operation is `extend.ts:132-134`, where
`.apply(input, args)` calls that constructor with attacker-controlled arguments.

Rejected candidate:

- `extend.ts:82-84`: necessary unsafe lookup and retained in trace, but execution
  occurs only when the returned function is applied.

### entry-00512

The entry is moved from an internal render-method declaration to the
`parameterValue` input boundary. `reset.ts:46` remains the critical operation:
`__sanitize` is installed on expression-reachable `__data` by ordinary writable
assignment, allowing the expression to replace the guard and defeat every dynamic
property check inserted by `PrototypeSanitizer`.

## Additional findings

### entry-00182

This entry was marked `verify=1`, but its entry point, critical operation, and all
trace nodes were static constants in `constants.py`; the trace never reached a
validator or executor. The upstream patch adds `__objclass__` to
`BLOCKED_ATTRIBUTES` and regression cases for direct slot-wrapper access. The
broader audit also needs to account for dynamic `getattr(obj, name)` access,
which the vulnerable visitor does not inspect. The corrected chain therefore
mirrors the concrete Python Code-node path at this entry's own vulnerable commit:
node parameter -> Python task -> analyzer -> incomplete attribute decision ->
`exec`.

### entry-00191

This entry was also marked `verify=1`, yet its trace followed an unrelated
`hiddenField` branch and ended at the declaration of `sanitizeCustomCss`. The
security patch identifies the actual defect: `textFilter` decoded `&lt;` back to
`<` after sanitize-html encoded it, allowing a payload to recreate
`</style><script>` boundaries. The corrected chain follows
`options.customCss` -> `renderForm` -> `sanitizeCustomCss` -> the unsafe decode at
`utils.ts:149`.

## Compatibility and validation

- No schema or top-level field changes.
- All line locations use positive integers or supported `start-end` ranges.
- JSON objects remain alphabetically keyed and the file remains UTF-8 JSONL.
- The diff CSV is generated against the clean base checkout and lists every
  changed semantic field.
- `tests/test_n8n_semantic_annotations.py` provides offline regression checks for
  the eight target entries, schema invariants, semantic anchors, trace endpoints,
  and an optional cached-source check for all 61 nodes.
