# Changelog

All notable changes to VulnGym are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Data correction — refine n8n semantic annotations for Issue #6.

### Changed
- Rebuilt the evidence chains for the six required n8n entries and one
  independently audited entry.
- Returned `entry-00182` to `verify = 0` pending maintainer review of its
  corrected annotation.
- Current audited coverage is **392 / 408** entries across **178 / 184**
  advisories.

### Added
- A field-level review report and diff CSV for the seven corrected entries.
- Independent online validation of each target advisory, direct fix commit,
  vulnerable parent commit, and fix-specific patch marker.
- Offline regression tests for schema invariants, semantic anchors, trace
  endpoints, diff CSV coverage, documented verification statistics, and
  optional source matching.

## [0.1.4] — 2026-06-26

Data refresh — further expansion of human-audited coverage.

### Changed
- Human-audited entries grew from **350 → 393 / 408** (96.3 %),
  covering **178 / 184** advisories (96.7 %).
- Updated human-audit status flags only; row counts, schema, `desc`
  coverage, and vulnerability-type distribution are unchanged.

### Stats
- reports: **184** (unchanged)
- entries: **408** (unchanged)
- human-audited entries (verify = 1): **393** (was 350)
- human-audited advisories (≥ 1 verified entry): **178** (was 163)

## [0.1.3] — 2026-06-18

Data refresh — further expansion of human-audited coverage and broad annotation refinements.

### Changed
- Human-audited entries grew from **274 → 350 / 408** (85.8 %),
  covering **163 / 184** advisories (88.6 %).

### Added
- `desc` field on the `entry_point`, `critical_operation`, and `trace`
  nodes of **400** entries — a natural-language explanation of each
  node's role in the vulnerability chain.

### Stats
- reports: **184** (unchanged)
- entries: **408** (unchanged)
- human-audited entries (verify = 1): **350** (was 274)
- human-audited advisories (≥ 1 verified entry): **163** (was 137)

## [0.1.2] — 2026-05-31

Data refresh — significant expansion of human-audited coverage and annotation refinements.

### Changed
- Human-audited entries grew from **113 → 274 / 408** (67.2 %),
  covering **137 / 184** advisories (74.5 %).
- Refined `entry_point`, `critical_operation`, and `trace` annotations
  on **80** entries for improved accuracy.

### Stats
- reports: **184** (unchanged)
- entries: **408** (unchanged)
- human-audited entries (verify = 1): **274** (was 113)
- human-audited advisories (≥ 1 verified entry): **137** (was 61)

## [0.1.1] — 2026-05-15

Data refresh — adds a human-audit flag and additional human-verified entries.

### Added
- `verify` field on every row in `data/entries.jsonl` (`int`, `0` or `1`):
  `1` marks entries that have been reviewed and confirmed by a human
  annotator (high-confidence ground truth); `0` marks automatically
  annotated entries that have not yet been human-confirmed.
- **113 / 408** entries (≈ 27.7 %) are now flagged `verify = 1`,
  covering **61 / 184** advisories (≈ 33.2 %; **50** advisories have all
  of their entries verified, **11** are partially verified).

### Changed
- Refined values of selected `entry_point`, `critical_operation`, `trace`,
  and other annotation fields in `data/entries.jsonl`. Row counts and the
  `report_id` ↔ `entry_id` join structure are unchanged.
- `SCHEMA.md` now documents `verify`; `human_confirmed` is removed from
  the "intentionally omitted internal fields" invariant since the audit
  status is exposed publicly via `verify`.

### Stats
- reports: **184** (unchanged)
- entries: **408** (unchanged)
- human-audited entries (verify = 1): **113**
- human-audited advisories (≥ 1 verified entry): **61**

## [0.1.0] — 2026-05-07

Initial open-source release.

### Added
- `data/reports.jsonl` — 184 GitHub Advisories (report-level aggregates).
- `data/entries.jsonl` — 408 per-entry-point records with
  `entry_point` / `critical_operation` / `trace` annotations.
- `SCHEMA.md` — full field reference and invariants.
- `examples/load_dataset.py` — stdlib / pandas / HuggingFace `datasets`
  loaders.
- `examples/evaluate.py` — coverage / recall evaluator.
- `examples/example_result.jsonl` — illustrative tool-findings submission.
- CC-BY-4.0 license.

### Stats
- reports: **184**
- entries: **408**
- projects: 38
- repositories: 23
