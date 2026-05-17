<p align="center">
  <h1 align="center">VulnGym</h1>
</p>

<h4 align="center">
    <p>
        <a href="./README_zh.md">中文</a> |
        <a href="#">English</a>
    </p>
</h4>

<p align="center">
  <a href="https://github.com/Tencent/VulnGym/stargazers">
    <img alt="GitHub Stars" src="https://img.shields.io/github/stars/Tencent/VulnGym?color=gold">
  </a>
  <a href="https://github.com/Tencent/VulnGym/network/members">
    <img alt="GitHub Forks" src="https://img.shields.io/github/forks/Tencent/VulnGym?color=gold">
  </a>
  <a href="./LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-CC--BY--4.0-blue.svg">
  </a>
</p>

<p align="center">
  <b>A Real-World, Project-Level Vulnerability Benchmark for White-Box Vulnerability-Hunting Agents</b>
</p>

<p align="center">
  <a href="https://github.com/Tencent/VulnGym">
    <img src="https://img.shields.io/badge/⭐-Give VulnGym a Star-yellow?style=flat&logo=github" alt="Give VulnGym a Star">
  </a>
</p>

**VulnGym** is a project-level benchmark for white-box vulnerability-hunting agents, designed to evaluate an agent's vulnerability detection capabilities within **real-world engineering contexts**, with **verifiable vulnerability trigger paths and code-semantic evidence chains**.

**Three core design principles:**
- **🏗️ Real project-level evaluation units** — every sample is bound to a specific vulnerable commit of a real repository, evaluating an agent's ability to discover and locate vulnerabilities inside real multi-file, multi-module engineering projects.
- **🧠 Comprehensive vulnerability-type coverage** — the benchmark covers both business-logic defects that demand cross-module code-semantic reasoning (e.g., authorization bypass, broken authentication) and traditional security flaws (e.g., injection, path traversal), providing a comprehensive assessment of an agent's ability to discover diverse vulnerability classes.
- **✅ Verifiable vulnerability paths** — each sample ships with a human-reviewed **reachable entry point** (`entry_point`), **critical operation** (`critical_operation`), and **cross-module reasoning chain** (`trace`), enabling reproducible, explainable, and deterministic evaluation.

---

## 📢 What's New
- **2026-05-17** — 🔧 v0.1.1 data refresh: added a `verify` field on every entry to mark human-audit status; **113 / 408 entries** (covering **61 / 184 advisories**) are now human-verified. Selected `entry_point` / `critical_operation` / `trace` values were also refined.
- **2026-05-15** — 🎉 VulnGym v0.1.0 officially open-sourced!



## Table of Contents

- [🔍 Why VulnGym](#-why-vulngym)
- [✨ Dataset overview](#-dataset-overview)
- [📈 Baseline evaluation results](#-baseline-evaluation-results)
- [📦 Repository layout](#-repository-layout)
- [🚀 Quick start](#-quick-start)
- [📊 Evaluating your tool](#-evaluating-your-tool)
- [📖 Citation](#-citation)
- [🤝 Contribution Guide](#-contribution-guide)
- [🙏 Acknowledgements](#-acknowledgements)
- [📄 License](#-license)

---

## 🔍 Why VulnGym

Existing vulnerability benchmarks have the following limitations when
evaluating the real-world vulnerability-hunting capabilities of AI agents:

| Limitation | Manifestation |
|---|---|
| **Insufficient evaluation granularity** | Most benchmarks use functions or diff snippets as the evaluation unit, failing to reflect an agent's ability to locate vulnerabilities within complete engineering projects |
| **Narrow vulnerability types** | Over-emphasis on pattern-matchable CWE flaws such as SQL injection and buffer overflow, with little coverage of categories requiring deep contextual reasoning |
| **Coarse-grained ground truth** | Typically binary labels (vulnerable / not vulnerable) or patch diffs, unable to precisely verify whether the agent locates the correct entry point and defect site |


## ✨ Dataset overview

This is the **v0.1.1 release** of VulnGym. Data is provided
as two JSONL files under the `data/` directory:

- `reports.jsonl` — aggregated records at the GitHub Advisory granularity
- `entries.jsonl` — annotated records at the reachable entry point granularity

Each record contains `repo_url` and `commit`, allowing you to check out the
full vulnerable source tree for the corresponding version.

### Data scale

| Metric | Value |
|---|---|
| Advisories (reports) | **184** |
| Reachable entry points (entries) | **408** |
| Distinct projects | 38 |
| Distinct repositories | 23 |
| Human-audited entries (`verify = 1`) | **113 / 408 (27.7 %)** |
| Human-audited advisories (≥ 1 verified entry) | **61 / 184 (33.2 %)** |

### Human audit status

Starting in v0.1.1, every row in `entries.jsonl` carries a `verify` field
(`int`, `0` or `1`):

- `verify == 1` — the entry's `entry_point`, `critical_operation`, and
  `trace` have been reviewed and confirmed by a human annotator. These
  rows form a high-confidence ground-truth subset and are recommended
  for strict, reproducible benchmarking.
- `verify == 0` — automatically annotated; not yet human-confirmed.
  Useful for scale and recall studies, but values may still be refined
  in future releases.

Of the **184** advisories, **50** have all of their entries verified and
**11** are partially verified, for a total of **61** advisories with at
least one human-audited entry. Future releases will continue to expand
the verified subset.

### Vulnerability type distribution

Every entry carries a two-level classification: `vuln_category_l1`
(coarse type) and `vuln_category_l2` (fine-grained sub-type). **71.2 %** of
advisories are business-logic vulnerabilities, classified with a
**12-class + 1 fallback** taxonomy (see below). The remaining 28.8 %
cover traditional vulnerability types. Full data model and field
definitions are in [`SCHEMA.md`](SCHEMA.md).

The initial release (v0.1.0) draws primarily from recent high-star open-source projects and focuses on frequently occurring business-logic vulnerabilities; future releases will continue expanding vulnerability categories and project coverage.

> Note: one advisory may map to multiple entries — the counts below
> are by **advisory (vulnerability)**, not by entry.

**Business-logic advisories (131 / 184, 71.2 %) — `vuln_category_l2` breakdown:**

| Sub-category | Advisories | % of BL |
|---|---|---|
| BL-AUTHZ-BROKEN — broken authorization logic | 31 | 23.7 % |
| BL-AUTHZ-MISSING — missing authorization | 23 | 17.6 % |
| BL-AGENT-CAPABILITY — AI / Agent capability boundary bypass | 20 | 15.3 % |
| BL-PRIV-ESC — privilege escalation | 13 | 9.9 % |
| BL-AUTH-BYPASS — authentication bypass | 11 | 8.4 % |

<details>
<summary>7 more sub-categories (33 advisories, 25.2 % of BL)</summary>

| Sub-category | Advisories | % of BL |
|---|---|---|
| BL-ORIGIN-INTEGRITY — origin / signature / integrity check missing | 8 | 6.1 % |
| BL-WORKFLOW-VIOLATION — workflow / state-machine violation | 7 | 5.3 % |
| BL-INSECURE-DEFAULT — insecure default configuration | 6 | 4.6 % |
| BL-RACE-LOGIC — business-layer race condition | 4 | 3.1 % |
| BL-MULTI-TENANT — multi-tenant / isolation failure | 3 | 2.3 % |
| BL-MASS-ASSIGNMENT — mass assignment / parameter pollution | 3 | 2.3 % |
| BL-TRUST-BOUNDARY — implicit trust in internal input | 2 | 1.5 % |

</details>

<br>

**Traditional vulnerability advisories (53 / 184, 28.8 %) — top `vuln_category_l1`:**

| Category | Advisories | % of Trad. |
|---|---|---|
| Code Injection | 12 | 22.6 % |
| Path Traversal / File ops | 9 | 17.0 % |
| Command Injection | 8 | 15.1 % |
| XSS | 5 | 9.4 % |
| Sandbox Escape | 5 | 9.4 % |

<details>
<summary>4 more categories (14 advisories, 26.4 % of Trad.)</summary>

| Category | Advisories | % of Trad. |
|---|---|---|
| SSRF | 4 | 7.5 % |
| Authentication Bypass | 3 | 5.7 % |
| Deserialization | 2 | 3.8 % |
| Other (Template Injection, RCE, Supply Chain, etc.) | 5 | 9.4 % |

</details>

> Future releases will continue expanding vulnerability categories and project coverage.



## 📈 Baseline evaluation results

> 🚧 **Coming soon** — We are systematically evaluating mainstream tools and AI agents. Results will be published alongside the technical report.


## 📦 Repository layout

```
VulnGym/
├── README.md                    # English version
├── README_zh.md                 # 中文版
├── SCHEMA.md                    # field reference & validation invariants
├── CHANGELOG.md
├── CITATION.cff
├── LICENSE                      # CC-BY-4.0
├── data/
│   ├── reports.jsonl            # 184 rows — one GitHub Advisory per row
│   └── entries.jsonl            # 408 rows — one entry point per row, with human-audit flag (verify)
└── examples/
    ├── load_dataset.py          # stdlib / pandas / HuggingFace datasets loader
    ├── example_result.jsonl     # illustrative tool-findings submission
    └── evaluate.py              # coverage / recall evaluator
```

---

## 🚀 Quick start

```bash
git clone https://github.com/Tencent/VulnGym.git
cd VulnGym
python3 examples/load_dataset.py
```

Or load directly in Python:

```python
import json
with open("data/entries.jsonl", encoding="utf-8") as f:
    entries = [json.loads(line) for line in f if line.strip()]

xss = [e for e in entries if e["vuln_category_l1"] == "XSS"]
print(len(xss), "XSS entries")
print(xss[0]["entry_point"], "→", xss[0]["critical_operation"])

# Restrict to the human-audited high-confidence subset
verified = [e for e in entries if e["verify"] == 1]
print(len(verified), "human-audited entries")
```

Pandas:

```python
import pandas as pd
reports = pd.read_json("data/reports.jsonl", lines=True)
entries = pd.read_json("data/entries.jsonl", lines=True)
```

HuggingFace `datasets`:

```python
from datasets import load_dataset
ds = load_dataset("json", data_files={
    "reports": "data/reports.jsonl",
    "entries": "data/entries.jsonl",
})
```


## 📊 Evaluating your tool

Write your tool's findings to a JSONL file (one finding per line) and run:

```bash
python3 examples/evaluate.py path/to/your_findings.jsonl -v
```

Each finding must carry at least `repo_url`, `commit`, `entry_point`
(reachable entry point), and `critical_operation` (core defect location).
`trace` (cross-module reasoning chain) is optional and ignored by the
matcher. See `examples/example_result.jsonl` for a working sample.

The script reports two metrics:

- **Advisory-level recall** (primary) — `covered_advisories /
  usable_advisories`. An advisory is covered if **at least one** of its
  entries is matched.
- **Entry-level recall** (secondary) — `matched_entries / usable_entries`.

**Default matching policy**

| Aspect | Default |
|---|---|
| Path match | normalized, exact |
| Line tolerance | `\|Δline\| ≤ 5` on entry_point **and** critical_operation |
| Direction | strict (entry_point-to-entry_point, critical_operation-to-critical_operation) |
| `line == 0` in ground truth | excluded from numerator and denominator |

All policies are documented and configurable via CLI arguments
(`--line-tolerance`, etc.).

> **Note:** The current evaluator **only computes recall / coverage** and
> cannot penalize over-reporting. The resulting numbers should be
> interpreted as coverage metrics, not a full precision-aware benchmark.


## 📖 Citation

> 📚 **A companion paper is in preparation.** Until it is released, please cite VulnGym using the dataset entry below; we will update this section once the paper is publicly available.

```bibtex
@misc{vulngym2026,
  title        = {VulnGym: A Real-World, Project-Level Vulnerability Benchmark
                  for White-Box Vulnerability-Hunting Agents},
  author       = {{Tencent Wukong Code Security Team and contributors}},
  year         = {2026},
  version      = {0.1.1},
  howpublished = {\url{https://github.com/Tencent/VulnGym}},
  note         = {Dataset. A companion paper is in preparation; please check
                  the repository for the latest citation.}
}
```

Once the paper is public, the entry below will be filled in and should be preferred:

```bibtex
@inproceedings{vulngym2026paper,
  title     = {TBA — A companion paper for VulnGym is in preparation.},
  author    = {{To be announced}},
  year      = {TBA},
  note      = {Placeholder; will be replaced once the paper is publicly available.}
}
```

See `CITATION.cff` for the machine-readable form.

---

## 🤝 Contribution Guide

VulnGym aims to be an **open, reproducible, and continuously evolving**
community benchmark. Contributions from both academia and industry are
warmly welcomed:

- 🧠 **Dataset contributions** — new advisories, additional reachable
  entry points for existing advisories, corrections to `entry_point` /
  `critical_operation` / `trace`.
- 🔧 **Evaluator improvements** — precision / F1, per-category
  breakdowns, statistical significance (bootstrap CI), alternative
  matching policies.
- 📊 **Evaluation result submissions** — submit your tool's evaluation
  results via PR to be included in the baseline comparison.
- 💬 **Discussions & feedback** — file an
  [Issue](https://github.com/Tencent/VulnGym/issues) or start a
  [Discussion](https://github.com/Tencent/VulnGym/discussions).

Please read `SCHEMA.md` before proposing data changes — all invariants
listed there are enforced at release time.

---

## 🙏 Acknowledgements

VulnGym is jointly built by the **Tencent Wukong Security Team**
together with the following academic partners (listed in no particular
order, final order TBD):

- Systems Software & Security Lab, Fudan University
- JC STEM Lab of Intelligent Cybersecurity, The University of Hong Kong
- Prof. Li Hui's Team, Peking University Shenzhen Graduate School
- Network Threat Analysis Lab, Institute of Information Engineering, Chinese Academy of Sciences

Many thanks to all partners for their outstanding contributions to
VulnGym.

---

## 📄 License

The dataset is released under **CC-BY-4.0** — see [`LICENSE`](LICENSE).
You may use it for commercial and academic purposes with attribution.
Source code paths and commit hashes referenced in `entry_point` /
`critical_operation` / `trace` fields belong to their respective upstream
projects under their original licenses; consult the referenced
repositories before reusing any quoted code fragment.
