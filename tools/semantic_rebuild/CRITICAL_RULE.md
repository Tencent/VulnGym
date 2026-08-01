# critical_operation rule (this PR)

Used for all six entries below.

## Meaning

`critical_operation` is the first place in the vuln tree where the security property fails in a way you can point at with `{file,line,code}`. Prefer the locus that the fix patch changes.

Do not use:

- static policy literals alone (e.g. `BLOCKED_* = {`) — called out in #6
- route decorators only, bare `}`, or wrappers with no decision
- a generic exec sink for every RCE — only when #6 forbids putting RCE critical on sanitizer hooks (then put the gap in `trace`)

## Order

1. Read the fix patch; find what check was added or changed.
2. If that statement exists in the vuln commit → mark it critical.
3. If the fix only *adds* missing logic (no line in vuln, e.g. `visitWithStatement`) → do not invent a line; put the nearest incomplete guard in `trace`, then step 4.
4. If #6 forbids RCE critical on sanitizer hooks → critical = first place escaped user code runs; say so in desc / PATCH_NOTES.
5. Pure impact sites (`.apply` / `exec`) go in `trace` unless they are also the patch locus.

## Applied here

| entry | patch locus | #6 forbids sanitizer critical? | critical | steps |
|-------|-------------|--------------------------------|----------|-------|
| 00103 | add `trim()` | no | `toLowerCase` without trim | 1–2 |
| 00176 | add `__objclass__` to set | static set forbidden | `in BLOCKED_*` test | 1–2 |
| 00511 | `UNSAFE_PROPERTY_NAMES` at function entry | no | first unchecked native return | 1–2 |
| 00512 | lock `__sanitize` | no | writable assignment | 1–2 |
| 00099 / 00100 | add `visitWithStatement` | yes | `evaluateExpression` + gap in trace | 3–4 |

## 00511 vs function entry

The fix inserts the name check at the top of `findExtendedFunction`. In the vuln tree that spot is only the function prologue. Critical is `82-84` (first return of `input[functionName]` as native). The missing guard is documented in PATCH_NOTES / CANDIDATES.
