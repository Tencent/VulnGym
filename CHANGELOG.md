# Changelog

All notable changes to VulnGym are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-05-xx

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
