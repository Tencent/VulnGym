# Issue #6: n8n semantic review

## Scope

This review corrects the six entries named in Issue #6 and adds one independently
audited n8n entry whose annotation has the same semantic failure mode:

- Required baseline: `entry-00099`, `entry-00100`, `entry-00103`,
  `entry-00176`, `entry-00511`, `entry-00512`
- Additional finding: `entry-00182`

All seven entries remain or become `verify=0`. A correction should not inherit a
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

The independent verifier also binds every target advisory to a concrete upstream
security change:

| Advisory | Vulnerable snapshot | Direct fix | Patch evidence |
|---|---|---|---|
| `GHSA-5XRP-6693-JJX9` | `8ab4492e` | `30383d86` | reserved names and `WithStatement` handling |
| `GHSA-825Q-W924-XHGX` | `57d6015f` | `ced34c0f` | normalized Content-Type comparison |
| `GHSA-MMGG-M5J7-F83H` | `3af90952` | `062644ef` | `__objclass__` added to the denylist |
| `GHSA-VPCF-GVG4-6QWR` | `8e81f3e3` | `9e5212ec` | `__objclass__` added at this release snapshot |
| `GHSA-6CQR-8CFR-67F8` | `09e2c2b5` | `1acdafe6` | unsafe property rejection and immutable guard binding |

For every row, the vulnerable snapshot is the direct fix commit's first parent.
The advisory identity, affected-package metadata, parent relationship, and
security-specific patch markers are checked online rather than inferred from a
commit message.

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

The old entry point was a lone closing brace. The new chain starts where the
Webhook node's `responseHeaders` configuration is evaluated, follows the
resulting `WebhookStaticResponse`, and writes the attacker-controlled
`Content-Type` to the Express response. The missing trim in
`html-sandbox.ts:19-25` remains in the trace as the failed guard; the chain now
ends at `webhook-request-handler.ts:153-157`, where that false result makes
`needsSandbox` false and skips the CSP sandbox header.

Rejected candidates:

- `webhook-helpers.ts:615`: a block boundary that neither receives the malicious
  header nor makes the CSP decision.
- `html-sandbox.ts:20`: the root-cause transformation and a necessary trace node,
  but not the final control-flow decision that omits CSP.

### entry-00176

The static `BLOCKED_ATTRIBUTES` declaration is retained as root-cause evidence,
but the critical operation is now `task_analyzer.py:66`, where the analyzer
checks each AST attribute. The vulnerable snapshot omits `__objclass__` from the
denylist, so direct slot-wrapper access passes this visitor. The trace continues
through the normal `exec` sink to distinguish the bypass decision from its
impact.

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
corrected chain therefore mirrors the concrete Python Code-node path at this
entry's own vulnerable commit: node parameter -> Python task -> analyzer ->
incomplete attribute decision -> `exec`.

### Confidence boundary: entry-00191

`entry-00191` was examined but is deliberately not changed by this PR. The
advisory's direct fix changes Form HTML-field expression handling; it does not
modify `sanitizeCustomCss` or its `textFilter`. A `customCss` rewrite would
therefore lack direct patch support and is excluded instead of being presented as
a verified additional finding.

## Compatibility and validation

- No schema or top-level field changes.
- All line locations use positive integers or supported `start-end` ranges.
- JSON objects remain alphabetically keyed and the file remains UTF-8 JSONL.
- The diff CSV is generated against the clean base snapshot and lists every
  changed semantic field plus the one verification-state change.
- `tests/test_n8n_semantic_annotations.py` provides offline regression checks for
  the seven target entries, schema invariants, semantic anchors, trace endpoints,
  documented verification statistics, and an optional cached-source check for
  all 58 nodes.
- `scripts/verify_issue6_n8n_semantic_annotations.py` independently checks the
  committed dataset, report mapping, field-level diff, mutation scope, text
  integrity, all 58 pinned source spans, five advisories, five direct security
  fixes, and five vulnerable-parent relationships without relying on the test
  module.

```bash
python scripts/verify_issue6_n8n_semantic_annotations.py
python scripts/verify_issue6_n8n_semantic_annotations.py \
  --base /path/to/clean/entries.jsonl \
  --check-upstream
```
