# Issue #8 Acceptance Matrix

| acceptance item | covered by |
|---|---|
| Consistent and explainable annotations for the Dockerfile samples | `reports/config_vuln_annotation.md`, repaired rows in `data/entries.config_vuln_fixed.jsonl` |
| Fixed `{file,line,code}` matches the vulnerable commit | `scripts/verify_config_vuln_annotations.py --check-upstream`, embedded source slices in `scripts/apply_config_vuln_patches.py` |
| `desc` explains why the configuration is vulnerable | English `desc` fields in all repaired nodes; verifier rejects damaged or too-short descriptions |
| Spec can guide future configuration vulnerabilities | `reports/config_vuln_annotation.md` principles and optional extension suggestions |
| No breaking schema changes | Repaired rows only use existing `entry_point`, `critical_operation`, `trace`, `line`, `code`, `desc`, and `verify` fields |
| Data satisfies `SCHEMA.md` constraints | `python -m unittest discover -s tests` and `python scripts/verify_config_vuln_annotations.py` |

## Distinct Repair Choices

This PR keeps the four-row patch fragment from the original #14 shape and adds
a full fixed JSONL for reviewer convenience. It also uses a compact
configuration-state trace rather than a single all-purpose trace node:

| entry_id | trace shape |
|---|---|
| `entry-00241` | full-file root state plus `CMD` runtime materialization |
| `entry-00242` | full-file root state plus `pnpm install` build-time materialization |
| `entry-00243` | full-file root state plus `ENTRYPOINT` runtime materialization |
| `entry-00244` | ineffective boundary interval plus sudo proof and runtime materialization |
