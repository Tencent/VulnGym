# n8n Semantic Annotation Repair Notes

Scope: issue #6 and its six n8n samples.

| entry_id | reviewed vulnerability boundary |
|---|---|
| `entry-00099` | workflow-run request to expression evaluator execution |
| `entry-00100` | workflow expression parameter to evaluator execution |
| `entry-00103` | configured response header to CSP sandbox decision |
| `entry-00176` | Python source to the incomplete attribute-policy decision |
| `entry-00511` | VM expression parameter to native function invocation |
| `entry-00512` | VM expression parameter to writable `__sanitize` installation |

## Comparison And Distinctive Approach

The current issue #6 submissions provide useful independent checks. PR #55 has
the most compact end-to-end chains, PR #54 correctly distinguishes the Python
attribute-policy gap from the later `exec` impact, and PR #46 provides useful
automation and reasoning artifacts.

This repair incorporates those semantic lessons without adopting another PR's
delivery structure. Its distinctive guarantees are:

1. A six-row patch JSONL remains the single source of truth.
2. The full 408-row dataset and 24-row field diff are generated locally.
3. Every source snippet is compared with the recorded vulnerable commit.
4. Four direct upstream fix commits are checked for expected patch semantics.
5. Each recorded vulnerable commit must be the first parent of its direct fix.
6. Advisory metadata and affected-version records are checked through GitHub's
   API before the six rows are marked `verify=1`.

The parent relationship matters because it proves that each patch describes
the exact vulnerable snapshot recorded by VulnGym, rather than a similar fix
from another release branch.

## Repair Principles

1. `entry_point` identifies external input or workflow configuration entering
   the vulnerable path.
2. `critical_operation` identifies the vulnerability-specific execution,
   security decision, or mutable guard. Generic impact remains in `trace` when
   it is not the root security failure.
3. `trace` contains only the important data-flow and control-flow transitions.
4. Descriptions explain why each node belongs to the chain and are checked for
   replacement-character and repeated-question-mark encoding damage.
5. The repair uses only fields already defined by `SCHEMA.md`.

## Per-Entry Decisions

### `entry-00099`

The authenticated workflow-run route remains the external trigger. The trace
then follows parameter resolution, expression-prefix removal, syntax
expansion, and evaluator dispatch. The critical operation is the Tournament
evaluator call, not an AST sanitizer declaration.

Direct fix evidence: commit
`30383d86139f3279a698df8d229eadfefe8627f4` has the recorded vulnerable commit
as its first parent and adds reserved-name and `with`-statement AST checks.

### `entry-00100`

The entry point is the direct workflow expression parameter rather than an
HTTP wrapper. The trace retains the immutable host `__sanitize` binding because
the escape bypasses that guard, then ends at evaluator execution.

Direct fix evidence is shared with `entry-00099`.

### `entry-00103`

The entry point now covers evaluation of workflow-controlled
`responseHeaders`, including the unchanged header value. The chain follows the
static webhook response, header writer, whitespace-sensitive HTML classifier,
and the `needsSandbox` branch that omits CSP.

Direct fix commit `ced34c0f93ab4c759a56065965986094d8ef7323`
has the recorded vulnerable commit as its first parent and changes
`contentType.toLowerCase()` to `contentType.trim().toLowerCase()`.

### `entry-00176`

The critical operation is the AST analyzer's membership test against
`BLOCKED_ATTRIBUTES`. This is the vulnerability-specific policy decision:
`__objclass__` is missing, so the slot-wrapper traversal is accepted. Python
`exec` remains the final trace node because it realizes impact after the
incomplete check.

Direct release-branch fix commit
`062644ef786b6af480afe4a0f12bc6d70040534a` has the recorded vulnerable commit
as its first parent and adds `__objclass__` plus regression coverage.

### `entry-00511`

The entry point is the user expression parameter. The compact trace shows the
insufficient dot-constructor regex, VM exposure of `extend`, unchecked native
property lookup, and the final native `apply` call. The call is critical
because it invokes the resolved `Function` constructor with attacker input.

### `entry-00512`

The direct expression parameter replaces the remote workflow-run wrapper. The
trace shows AST rewriting to depend on `__data.__sanitize` and ends at the
ordinary writable assignment that lets expression code replace the guard.

Direct fix commit `1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6`
has the recorded vulnerable commit as its first parent. It blocks unsafe native
property names and installs `__sanitize` with a non-configurable getter and a
throwing setter, directly confirming both VM-engine annotations.

## Artifacts

| artifact | purpose |
|---|---|
| `data/entries.n8n_semantic_fixed.jsonl` | six reviewed patch rows |
| `data/entries.fixed.jsonl` | generated 408-row dataset |
| `reports/n8n_semantic_fix_diff.csv` | 24 entry/critical/trace/verify diffs |
| `reports/n8n_semantic_acceptance_matrix.md` | issue #6 acceptance mapping |
| `scripts/apply_n8n_semantic_patches.py` | deterministic artifact generator |
| `scripts/verify_n8n_semantic_annotations.py` | local, source, advisory, and direct-fix verifier |
| `tests/test_n8n_semantic_annotations.py` | semantic, integrity, evidence, and retry tests |
