# Config And Non-Taint Vulnerability Annotation Guide

Scope: issue #8, GHSA-W7J5-J98M-W679, OpenClaw commit
`c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1`.

This repair covers:

| entry_id | file | defect model |
|---|---|---|
| `entry-00241` | `scripts/e2e/Dockerfile` | missing `USER`; runtime `CMD ["bash"]` remains root |
| `entry-00242` | `scripts/e2e/Dockerfile.qr-import` | missing `USER`; package install runs root |
| `entry-00243` | `scripts/docker/install-sh-e2e/Dockerfile` | missing `USER`; installer `ENTRYPOINT` remains root |
| `entry-00244` | `scripts/docker/install-sh-nonroot/Dockerfile` | ineffective non-root boundary; `app` has `NOPASSWD:ALL` |

## Why The Old Shape Was Mismatched

The current schema was designed around a taint-flow mental model:
`entry_point` introduces data, `trace` follows propagation, and
`critical_operation` is the sink. Dockerfile privilege bugs are different.
The vulnerable state is configuration state, not user-controlled data. In the
first three files, the root cause is the absence of a `USER` boundary across a
file. In `entry-00244`, the root cause is an invalid boundary: `USER app`
exists, but the adjacent sudoers grant gives `app` passwordless full-root
escalation.

## Annotation Principles

1. `entry_point` should be the first instruction that introduces the vulnerable
   configuration state.

   For a missing-`USER` Dockerfile this is normally `FROM`, because the base
   image default root identity enters the image state there. For an ineffective
   non-root boundary, the entry point may be the first line of the boundary
   block, such as `RUN useradd ...`, because the issue starts where the false
   boundary is constructed.

2. `critical_operation` should mark the narrowest dangerous declaration or
   effect point.

   A missing declaration has no honest source line, so it must not be invented
   or represented by making the whole file a critical block. Record the
   absence in `desc` and the state lifecycle in `trace`, then select the
   narrowest real instruction where the inherited privilege produces impact:
   `pnpm install`, `CMD`, or `ENTRYPOINT`. For the sudoers variant, select the
   exact `NOPASSWD:ALL` declaration.

3. `trace` should describe configuration-state propagation, not pretend this is
   taint propagation.

   A compact trace is preferred: `inherits` or `declares`, optional
   `fails_to_neutralize`, and `takes_effect_at`. Current schema has no relation
   field, so these meanings are stated in `desc`. Unrelated `WORKDIR`, `ENV`,
   and `COPY` instructions are not added merely to imitate a taint flow.

4. `desc` must explain the security role of the configuration.

   It should not merely restate code. It must answer why the line or interval is
   vulnerable: missing `USER`, unbroken root state, passwordless sudo, or
   ineffective privilege separation.

## Target Decisions

| entry_id | state origin | critical operation | lifecycle trace |
|---|---|---|---|
| `entry-00241` | `FROM` inherits root | `CMD ["bash"]` starts the root runtime | inherit root -> root install/build -> root default process |
| `entry-00242` | `FROM` inherits root | `pnpm install` runs lifecycle scripts as uid 0 | inherit root -> root dependency install |
| `entry-00243` | `FROM` inherits root | installer `ENTRYPOINT` starts as uid 0 | inherit root -> prepare system-path executable -> root entrypoint |
| `entry-00244` | user creation plus sudoers block | exact `NOPASSWD:ALL` rule | declare full sudo -> nominal `USER app` -> demonstrated sudo use -> runtime |

## Backward-Compatible Schema Guidance

No schema-breaking change is required for this repair. The existing
`entry_point`, `critical_operation`, `trace`, `line`, `code`, and `desc` fields
can express these Dockerfile samples when ranges are used carefully.

Future releases could add optional fields without breaking old consumers:

| optional field | purpose |
|---|---|
| `annotation_kind` | e.g. `taint_flow`, `configuration_state`, `authorization_boundary` |
| `config_effect` | short machine-readable effect, such as `runs_as_root` |
| `state_transition` | e.g. `root_default -> no_user_override -> root_runtime` |

These fields are suggestions only. The fixed data in this PR intentionally
stays within `SCHEMA.md`.

## Evidence Model

The four rows are marked `verify=1` after a human review backed by four
independent checks:

1. Every annotated source slice matches vulnerable commit
   `c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1`.
2. GHSA-W7J5-J98M-W679 lists all four affected Dockerfiles and distinguishes
   the `install-sh-nonroot` passwordless-sudo variant.
3. Security fix `84281abd4bd1c717bb37a2de12694fe203827eee`
   adds `USER appuser` to exactly the three missing-`USER` Dockerfiles.
4. The GitHub compare API proves the vulnerable commit is an ancestor of that
   fix (`behind_by=0` and matching merge base).

The fourth Dockerfile is deliberately not attributed to the three-file fix
delta. Its evidence is the explicit `NOPASSWD:ALL` declaration, the subsequent
`USER app`, and the later successful `sudo chmod` use.

## Produced Artifacts

| artifact | role |
|---|---|
| `data/entries.config_vuln_fixed.jsonl` | four-row patch fragment for issue #8 |
| `data/entries.fixed.jsonl` | full 408-row dataset with the four patch rows applied |
| `reports/config_vuln_fix_diff.csv` | field-level diff for `entry_point`, `critical_operation`, and `trace` |
| `reports/config_vuln_acceptance_matrix.md` | mapping from issue acceptance criteria to artifacts |
| `scripts/apply_config_vuln_patches.py` | reproducible generator |
| `scripts/verify_config_vuln_annotations.py` | local verifier plus vulnerable-source, advisory, fix-patch, and ancestry checks |
| `tests/test_config_vuln_annotations.py` | unittest coverage for line spans, semantic anchors, evidence rules, retries, row count, and schema-compatible nodes |
