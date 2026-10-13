# Issue #8 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Consistent and explainable annotations for the Dockerfile samples | `reports/config_vuln_annotation.md`, repaired rows in `data/entries.config_vuln_fixed.jsonl` |
| Fixed `{file,line,code}` matches the vulnerable commit | `scripts/verify_config_vuln_annotations.py --check-upstream` compares all four complete Dockerfiles with the pinned commit |
| `desc` explains why the configuration is vulnerable | English `desc` fields in all repaired nodes; verifier rejects damaged or too-short descriptions |
| Spec can guide future configuration vulnerabilities | `reports/config_vuln_annotation.md` principles and optional extension suggestions |
| No breaking schema changes | Repaired rows only use existing `entry_point`, `critical_operation`, `trace`, `line`, `code`, `desc`, and `verify` fields |
| Data satisfies `SCHEMA.md` constraints | `python -m unittest discover -s tests` and `python scripts/verify_config_vuln_annotations.py` |
| Human-audit status is evidence-backed | Four rows use `verify=1`; verifier checks advisory scope, fix patch, commit ancestry, and target-specific semantic anchors |

## Distinct Repair Choices

This PR keeps the four-row patch fragment from the original #14 shape and adds
a full fixed JSONL for reviewer convenience. It also uses a compact
configuration-state trace rather than a single all-purpose trace node. It also
keeps missing declarations in `desc` instead of treating an entire file as one
critical operation:

| entry_id | trace shape |
|---|---|
| `entry-00241` | root inheritance, root build range, and `CMD` runtime materialization |
| `entry-00242` | root inheritance and `pnpm install` build-time materialization |
| `entry-00243` | root inheritance, system-path preparation, and `ENTRYPOINT` runtime materialization |
| `entry-00244` | explicit sudoers declaration, nominal downgrade, sudo proof, and runtime materialization |

The upstream mode additionally verifies that fix commit `84281abd` is a
descendant of the vulnerable commit and adds `USER appuser` to exactly the
three missing-`USER` files. `entry-00244` remains a distinct explicit
`NOPASSWD:ALL` configuration defect rather than being incorrectly folded into
that three-file fix delta.
