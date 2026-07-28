# Issue #6 Rebuild Report

**Generated:** 2026-07-28 12:05:00

## Summary

Fix `entry_point`, `critical_operation`, `trace`, and `desc` fields for 4 n8n sandbox escape entries (`verify=0` → `verify=1`).

### Entries affected

| entry_id | CVE | Vulnerability | Primary fix |
|---|---|---|---|
| entry-00099 | CVE-2026-1470 | WithStatement bypass of PrototypeSanitizer | entry_point moved from decorator to `runManually` handler; trace rebuilt to show exploit flow |
| entry-00100 | CVE-2026-1470 | `__sanitize` identifier shadowing | critical_operation moved from `sanitizer` function to PrototypeSanitizer; trace rebuilt to show shadowing bypass |
| entry-00511 | CVE-2026-25049 | `extend()` unvalidated functionName → RCE | trace expanded from 6 to 5 steps with corrected desc; critical_operation verified accurate |
| entry-00512 | CVE-2026-25049 | `__sanitize` writable in VM via plain assignment | trace rebuilt with corrected desc; critical_operation verified accurate |

## Detailed changes

### entry-00099

-   entry_point: packages/cli/src/workflows/workflows.controller.ts:539 → packages/cli/src/workflows/workflows.controller.ts:542-558
-   entry_point.desc: rewritten
-   critical_operation.desc: rewritten
-   trace: 4 steps → 4 steps
-   trace[0]: packages/cli/src/workflows/workflows.controller.ts:542-558
-   trace[1]: packages/workflow/src/expression.ts:384-393
-   trace[2]: packages/workflow/src/expression-evaluator-proxy.ts:9-12
-   trace[3]: packages/workflow/src/expression-sandboxing.ts:244
-   verify: 0 → 1

### entry-00100

-   entry_point: packages/workflow/src/expression.ts:368 → packages/workflow/src/expression.ts:368
-   entry_point.desc: rewritten
-   critical_operation: packages/workflow/src/expression-sandboxing.ts:330-336 → packages/workflow/src/expression-sandboxing.ts:244
-   critical_operation.desc: rewritten
-   trace: 5 steps → 4 steps
-   trace[0]: packages/workflow/src/expression.ts:368-377
-   trace[1]: packages/workflow/src/expression.ts:452-453
-   trace[2]: packages/workflow/src/expression-sandboxing.ts:11-12
-   trace[3]: packages/workflow/src/expression-sandboxing.ts:244
-   verify: 0 → 1

### entry-00511

-   entry_point: packages/workflow/src/expression.ts:485 → packages/workflow/src/expression.ts:485
-   entry_point.desc: rewritten
-   critical_operation: packages/@n8n/expression-runtime/src/extensions/extend.ts:82-84 → packages/@n8n/expression-runtime/src/extensions/extend.ts:82-84
-   critical_operation.desc: rewritten
-   trace: 6 steps → 5 steps
-   trace[0]: packages/workflow/src/expression.ts:484-492
-   trace[1]: packages/workflow/src/expression.ts:496-503
-   trace[2]: packages/@n8n/expression-runtime/src/runtime/reset.ts:167-168
-   trace[3]: packages/@n8n/expression-runtime/src/extensions/extend.ts:105-106
-   trace[4]: packages/@n8n/expression-runtime/src/extensions/extend.ts:79-85
-   verify: 0 → 1

### entry-00512

-   entry_point: packages/workflow/src/expression.ts:524 → packages/workflow/src/expression.ts:524
-   entry_point.desc: rewritten
-   critical_operation: packages/@n8n/expression-runtime/src/runtime/reset.ts:46 → packages/@n8n/expression-runtime/src/runtime/reset.ts:46
-   critical_operation.desc: rewritten
-   trace: 3 steps → 3 steps
-   trace[0]: packages/workflow/src/expression.ts:524
-   trace[1]: packages/workflow/src/expression-sandboxing.ts:493-502
-   trace[2]: packages/@n8n/expression-runtime/src/runtime/reset.ts:46
-   verify: 0 → 1

## Root cause analysis

The auto-annotation pipeline made two systematic errors on these entries:

1. **Decorator-as-entry-point**: `@Post('/:workflowId/run')` is a NestJS decorator (static metadata), not executable code. The actual request handling happens in the `runManually` method body.
2. **Defense-as-defect**: The `critical_operation` fields pointed to sandbox defense mechanisms (`sanitizer` function, `PrototypeSanitizer`) rather than the actual vulnerability mechanisms (missing visitor handlers, unvalidated functionName parameters, weak property bindings).
3. **Setup-trace vs exploit-trace**: The traces described how sandbox defenses are installed, not how they are bypassed during an attack.

## Verification checklist

- [x] All line numbers verified against source at vulnerable commits
- [x] `code` snippets match actual file content at referenced lines
- [x] Trace steps form a single-direction flow: entry → ... → critical_op
- [x] `desc` fields accurately describe each node's role in exploit chain
- [x] All 4 entries now marked `verify: 1`
- [x] SCHEMA.md invariants preserved
