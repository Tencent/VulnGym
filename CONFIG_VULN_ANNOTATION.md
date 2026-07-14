# Configuration and non-taint vulnerability annotations

## Scope

Configuration vulnerabilities describe an unsafe effective state rather than
attacker data flowing through functions. Existing VulnGym fields can represent
them without a breaking schema change if their semantics are applied
consistently.

## Annotation rules

### Entry point

Choose the start of the relevant configuration scope or inheritance source. For
a Dockerfile privilege issue this is normally `FROM`, because the base image
establishes the effective default user. If the unsafe state is introduced by an
explicit option later, that declaration can instead be the entry point.

### Critical operation

Choose the dangerous declaration itself when it exists, such as a passwordless
sudoers rule. For an omitted hardening directive such as a missing `USER`, do
not invent a code location. Select the narrow build/runtime instruction range
where inherited root privilege becomes effective, and explain the missing
transition in `desc`.

### Trace

Trace configuration precedence and lifecycle, not taint. Useful nodes are:

- inherited defaults or stage boundaries;
- explicit privilege/capability declarations;
- user transitions that do or do not neutralize privilege;
- build or runtime instructions where the state takes effect.

Exclude ordinary file copies and build steps unless they demonstrate the
security-relevant effective state. Preserve source order within one
configuration artifact.

### Description quality

Descriptions must state the effective security property, why the selected line
establishes or consumes it, and the consequence of compromise. Merely restating
`FROM`, `USER`, or `ENTRYPOINT` is insufficient.

## OpenClaw decisions

- `entry-00241`: inherited root reaches dependency builds and `CMD ["bash"]`.
- `entry-00242`: dependency installation and any derived runtime remain root
  because the stage never changes users.
- `entry-00243`: the test entrypoint launches as inherited root.
- `entry-00244`: `USER app` exists, but `NOPASSWD:ALL` allows immediate root
  recovery; the sudoers rule is therefore the critical operation.

These are valid benchmark entries rather than candidates for removal: each has
a concrete source-backed configuration state and a direct excessive-privilege
impact. They should be evaluated as configuration reasoning, not taint recall.

## Optional compatible extension

A future minor schema version could add optional fields such as
`annotation_kind: "taint" | "control" | "configuration"` and
`evidence_relation: "flows_to" | "enables" | "inherits" | "takes_effect_at"`.
Consumers that ignore unknown optional fields remain compatible. This PR does
not add those fields, so current `SCHEMA.md` and evaluation code are unchanged.
