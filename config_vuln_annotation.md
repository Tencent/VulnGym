# Configuration and non-taint vulnerability annotations

This document defines how VulnGym should represent vulnerabilities whose root
cause is a static configuration or a missing configuration rather than
attacker-controlled data flowing through a call chain. It accompanies the
Issue #8 corrections for `entry-00241` through `entry-00244`.

## Purpose

The existing `entry_point`, `critical_operation`, and `trace` fields remain
useful for configuration vulnerabilities when they are interpreted as
configuration scope, security-relevant state changes, and activation points.
They must not be made to resemble a taint flow when no data flow exists.

Use this model when all or most of the following apply:

- the vulnerable artifact is declarative, such as a Dockerfile, YAML, TOML,
  deployment manifest, policy, or permission file;
- the unsafe property exists before untrusted input is processed;
- exploitation depends on an unsafe privilege, default, or missing restriction;
- the important relationship is declaration-to-effect rather than
  source-to-sink propagation.

## Two configuration models

### Explicit dangerous configuration

The repository contains a directive that directly creates the unsafe state,
for example `NOPASSWD:ALL`, `chmod 777`, a public bind address, or a
`--privileged` flag.

- `entry_point` identifies the configuration block in which the unsafe state
  is introduced.
- `critical_operation` identifies the narrowest directive that grants the
  dangerous capability.
- `trace` contains only later state transitions or execution points needed to
  explain how the directive takes effect.

### Missing safety configuration

The unsafe state is caused by the absence of an expected restriction, such as
a Dockerfile that never switches from the base image's root user.

- `entry_point` anchors the start of the relevant configuration scope. For a
  single-stage Dockerfile, this can be its `FROM` instruction.
- `critical_operation` anchors where the inherited unsafe default is activated.
  Prefer an explicit `CMD` or `ENTRYPOINT`. If none exists, use the final
  explicit instruction as the end-of-scope evidence and say clearly that the
  instruction itself is not the missing directive.
- `trace` should be empty unless an explicit directive changes or demonstrates
  the security state. Ordinary `RUN`, `COPY`, and `WORKDIR` instructions are
  not propagation nodes merely because they appear between two anchors.

Negative evidence requires inspection of the complete relevant scope. A
single line cannot prove that a directive is absent, so the description must
name the inspected boundary and the expected restriction.

## Field selection

### `entry_point`

Choose the earliest source location that establishes the relevant
configuration context:

1. an explicit dangerous configuration block;
2. the start of a scope whose inherited default remains unsafe;
3. an initialization or policy declaration that makes later behavior possible.

Do not claim that a safe or neutral directive is itself the defect. For
example, selecting `FROM node:22-bookworm` is acceptable as a scope anchor,
but its description must say that the defect is the lack of a later `USER`
override.

### `critical_operation`

Choose the location that most directly represents the core defect:

1. the dangerous directive itself;
2. the runtime command where an unsafe inherited setting becomes effective;
3. for a missing directive with no runtime command, the explicit end boundary
   that demonstrates the scope closed without the expected restriction.

Descriptions must distinguish the evidence location from the absent
configuration. A last `RUN` instruction may demonstrate that a Dockerfile
ended without `USER`, but must not be described as if it were syntactically
equivalent to the missing `USER` instruction.

### `trace`

`trace` represents meaningful configuration state transitions, not file order.
It may be empty.

Include a node only if it:

- changes identity, privileges, policy, ownership, or another relevant state;
- directly demonstrates that the dangerous configuration is usable; or
- activates the configured state at build or runtime.

Exclude routine package installation, copying, directory selection, logging,
and compilation unless that operation is independently security-relevant.

### `desc`

Every description should explain:

- what security state exists before and after the node;
- why that state matters to the vulnerability;
- whether the node is the defect, contextual evidence, or an activation point;
- whether the effect occurs during image build or container runtime.

Avoid source/sink, taint propagation, and call-stack terminology when no such
mechanism exists. Do not overstate impact: root inside a container increases
the consequences of compromise and can make breakout attempts more damaging,
but it does not by itself prove host compromise.

## Issue #8 sample decisions

The four samples reference OpenClaw commit
`c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1` and GitHub Advisory
[GHSA-W7J5-J98M-W679](https://github.com/advisories/GHSA-w7j5-j98m-w679).

### `entry-00241`

`scripts/e2e/Dockerfile` begins with a base image whose default user is root
and ends with `CMD ["bash"]`. There is no `USER` directive in the intervening
scope. `FROM` is retained as context, `CMD` is the runtime activation point,
and the trace is empty because the intermediate build instructions do not
change the user configuration.

### `entry-00242`

`scripts/e2e/Dockerfile.qr-import` has no `CMD`, `ENTRYPOINT`, or `USER`
directive. The base-image `FROM` instruction anchors the start of the scope,
and the final `RUN pnpm install --frozen-lockfile` anchors its end. The final
`RUN` executes as root and shows that no user transition occurred, but its
description explicitly treats the missing `USER` as the root cause. No
pseudo-flow trace is retained.

### `entry-00243`

`scripts/docker/install-sh-e2e/Dockerfile` inherits root from
`node:22-bookworm-slim` and reaches an explicit `ENTRYPOINT` without a `USER`
override. The entry and critical operation therefore form a direct
scope-to-activation explanation; package installation, copying, and `chmod`
are not needed in the trace.

### `entry-00244`

`scripts/docker/install-sh-nonroot/Dockerfile` does contain `USER app`, so it
must not be described as directly running the entrypoint as root. Its explicit
defect is:

```dockerfile
RUN useradd -m -s /bin/bash app \
  && echo "app ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/app
```

The configuration grants app unrestricted passwordless sudo. `USER app` is a
visible identity change but not an effective privilege boundary; the later
`RUN sudo chmod ...` demonstrates that sudo is usable after the switch, and
the `ENTRYPOINT` starts as app while retaining that unrestricted escalation
capability.

## Current schema limitation

The current node shape requires `{file, line, code}`. This works well for
positive evidence but cannot directly locate an instruction that does not
exist. Anchoring the inspected scope in existing nodes and explaining the
negative condition in `desc` is the compatible approach used by these fixes.

For a future minor schema version, two optional fields could make the intent
machine-readable without changing existing fields:

```json
{
  "annotation_type": "configuration",
  "missing_condition": {
    "file": "scripts/e2e/Dockerfile",
    "scope": "1-23",
    "expected": "USER <non-root>",
    "desc": "No USER directive appears before the runtime command."
  }
}
```

`annotation_type` would default to the existing flow interpretation when
absent. `missing_condition` would be optional and used only for negative
configuration evidence. These fields are proposals only: Issue #8 does not add
them to `SCHEMA.md` or to the dataset.

## Review checklist

- Verify every `{file, line, code}` against the entry's pinned commit.
- Confirm that an absence claim covers the complete relevant scope.
- Keep `trace` empty or short unless each node changes security-relevant state.
- Check that the description separates context, root cause, and activation.
- Distinguish build-time identity from runtime identity.
- Preserve all unrelated entry fields and the original `verify` value.
