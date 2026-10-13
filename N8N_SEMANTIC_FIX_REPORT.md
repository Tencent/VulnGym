# n8n semantic annotation review

This report covers the six issue #6 entries. Every replacement node is sliced
from the repository and vulnerable commit recorded by that entry; the builder
will fail if a file or range is unavailable.

## entry-00099

The old controller decorator is externally reachable but too far from the
attacker-controlled expression, while `PrototypeSanitizer`'s declaration is not
an execution sink. The new entry is `parameterValue` entering expression
resolution and the critical operation is Tournament executing the transformed
expression. The hook configuration remains in the trace because the later fix
added explicit `WithStatement` and reserved-variable checks there.

## entry-00100

The old sanitizer function describes the intended defense, not this variant's
bypass. The important operation is the AST rewrite of dynamic member access to
`dataNode.__sanitize(...)`: the vulnerable revision does not reserve the
internal data-node identifier, so attacker syntax can shadow it. The host-side
non-writable sanitizer is retained as context but is not selected as the sink.

## entry-00103

The old entry is a closing brace in an unrelated streaming branch. The rebuilt
chain starts where RespondToWebhook copies workflow-configured response headers,
follows the response into `setResponseHeaders`, and ends at the `needsSandbox`
decision. `isHtmlRenderedContentType` lowercases without trimming, so a leading
space makes the CSP branch false. Streaming setup and logger nodes are omitted.

## entry-00176

The Code node's code parameter is already the correct source. A static
`BLOCKED_ATTRIBUTES` declaration is not the critical operation. The trace now
shows analyzer validation, process creation, compilation, and the actual
`exec(compiled_code, globals)` sink. The fixing commit's addition of
`__objclass__` to the denylist confirms the missing check.

## entry-00511

Exposing `extend` is an intermediate capability, and returning a native function
is not yet code execution. The chain starts with user expression text, records
the regex bypass and VM reinjection, follows unchecked `functionName` lookup,
and ends at `foundFunction.function.apply(input, args)`. This is where a
recovered Function constructor executes attacker-controlled source.

## entry-00512

The old method declaration is not an input source. The new source is the user
expression parameter. The critical bypass is VM reset assigning `__sanitize`
as a normal writable property. The trace connects VM evaluation to the computed
member rewrite that later calls this overwritten hook. The fix replaces the
assignment with a non-configurable accessor whose setter throws.

## Validation and status

The six records remain `verify=0`; this PR improves machine-generated
annotations but does not self-assert human verification. No schema changes are
introduced. Run the builder and tests to reproduce all snippets and diff rows.
