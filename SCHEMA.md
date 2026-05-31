# SCHEMA.md — VulnGym data format reference (v0.1.2)

The dataset ships two line-delimited JSON files under `data/`. Every line is
a single self-contained JSON object (no trailing comma, `\n`-terminated,
UTF-8). Field order in each row is stable (sorted alphabetically) so
`diff` is useful across releases.

- `data/reports.jsonl` — 184 rows, one per GitHub Advisory (report-level).
- `data/entries.jsonl` — 408 rows, one per reachable entry point.

Join key: `entries.report_id == reports.report_id`.

---

## `entries.jsonl` row

| field | type | required | description |
|---|---|---|---|
| `entry_id` | `string` | ✅ | Stable per-entry id. Format: `entry-{id:05d}`, e.g. `entry-00057`. |
| `report_id` | `string` | ✅ | GHSA id (upper-case) derived from `source_link`, e.g. `GHSA-W7XJ-8FX7-WFCH`. |
| `source_link` | `string` | ✅ | Canonical advisory URL, `https://github.com/advisories/GHSA-…`. |
| `vuln_ids` | `string[]` | ✅ | All known identifiers for this advisory. `CVE-*` first, then `GHSA-*`, upper-cased, deduped. May be empty. |
| `origin` | `string` | ✅ | Constant `"GitHub Advisory Database (reviewed)"` in this release. |
| `project` | `string` | ✅ | Short project name (e.g. `open-webui`). |
| `repo_url` | `string` | ✅ | Source repository, starts with `https://github.com/`. |
| `commit` | `string` | ✅ | Vulnerable commit SHA — 40 lowercase hex chars. Consumers should `git checkout` this commit before analysis. |
| `vuln_title` | `string` | ✅ | Per-entry title. Annotators sometimes append ` - <filename>` to disambiguate entries of the same advisory; the report-level `vuln_title` has this suffix stripped. |
| `vuln_category_l1` | `string` | ✅ | Coarse category. **Bilingual** — e.g. `XSS`, `权限绕过`, `代码注入`. |
| `vuln_category_l2` | `string` | ✅ | Sub-category. Bilingual. |
| `entry_point` | `object` | ✅ | Reachable entry point — `{file, line, code}`. See below. |
| `critical_operation` | `object` | ✅ | Critical operation (core defect location) — `{file, line, code}`. See below. |
| `trace` | `object[]` | ✅ | Ordered taint-flow steps. Each item is `{file, line, code}`. May be empty. |
| `verify` | `int` | ✅ | Human-audit flag. `1` = the entry has been reviewed and confirmed by a human annotator (high-confidence ground truth); `0` = automatically annotated, not yet human-confirmed. Added in v0.1.1. |

### `entry_point` / `critical_operation` / `trace[*]` object

| field | type | description |
|---|---|---|
| `file` | `string` | Repository-relative path at the vulnerable commit. |
| `line` | `int` | 1-based line number (always integer — upstream string values are coerced). `0` means unknown. |
| `code` | `string` | Verbatim code snippet. May span multiple lines via `\n` and may contain 中文 inline comments when the annotator added them. |

### Example

```json
{
  "entry_id": "entry-00057",
  "report_id": "GHSA-W7XJ-8FX7-WFCH",
  "source_link": "https://github.com/advisories/GHSA-w7xj-8fx7-wfch",
  "vuln_ids": ["CVE-2025-64495", "GHSA-W7XJ-8FX7-WFCH"],
  "origin": "GitHub Advisory Database (reviewed)",
  "project": "open-webui",
  "repo_url": "https://github.com/open-webui/open-webui",
  "commit": "9942de8011d4b5a141ac507c974c061c0cdad59a",
  "vuln_title": "Open WebUI Stored DOM XSS via Prompt Insertion Rich Text Feature",
  "vuln_category_l1": "XSS",
  "vuln_category_l2": "Stored XSS",
  "entry_point": {
    "file": "src/lib/components/chat/MessageInput/CommandSuggestionList.svelte",
    "line": 97,
    "code": "insertTextHandler(data.content);"
  },
  "critical_operation": {
    "file": "src/lib/components/common/RichTextInput.svelte",
    "line": 348,
    "code": "tempDiv.innerHTML = htmlContent;"
  },
  "trace": [
    {"file": "…", "line": 42, "code": "…"}
  ],
  "verify": 1
}
```

---

## `reports.jsonl` row

Aggregates one or more entries that share a `source_link`. The repeated
fields (`project`, `repo_url`, `commit`, `vuln_title`, `source_link`,
`origin`, `vuln_ids`) are the canonical value for the advisory, computed as
follows:

- `vuln_title` — stripped of any trailing `" - <filename.ext>"` disambiguator
  added per entry.
- scalar fields — majority value across entries (ties broken by smallest
  `entry_id`). In practice every advisory in v0.1.0 is internally
  consistent; the export script would log a warning if it were not.
- `vuln_ids` — union of the per-entry lists, re-normalized.

| field | type | description |
|---|---|---|
| `report_id` | `string` | Same GHSA id as the entries it aggregates. |
| `source_link` | `string` | Advisory URL. |
| `vuln_ids` | `string[]` | Union across entries, normalized. |
| `origin` | `string` | `"GitHub Advisory Database (reviewed)"`. |
| `project` | `string` | |
| `repo_url` | `string` | |
| `commit` | `string` | |
| `vuln_title` | `string` | With `- filename` suffix stripped. |
| `num_entries` | `int` | Length of `entry_ids`. |
| `entry_ids` | `string[]` | All `entry_id`s that belong to this report, sorted ascending. |

### Example

```json
{
  "report_id": "GHSA-W7XJ-8FX7-WFCH",
  "source_link": "https://github.com/advisories/GHSA-w7xj-8fx7-wfch",
  "vuln_ids": ["CVE-2025-64495", "GHSA-W7XJ-8FX7-WFCH"],
  "origin": "GitHub Advisory Database (reviewed)",
  "project": "open-webui",
  "repo_url": "https://github.com/open-webui/open-webui",
  "commit": "9942de8011d4b5a141ac507c974c061c0cdad59a",
  "vuln_title": "Open WebUI Stored DOM XSS via Prompt Insertion Rich Text Feature",
  "num_entries": 1,
  "entry_ids": ["entry-00057"]
}
```

---

## Invariants (enforced pre-release)

Every release must satisfy these before tagging:

1. Row counts match the numbers in `README.md` and `CHANGELOG.md`.
2. Every `entry.report_id` appears in `reports.jsonl` and vice versa.
3. `report.entry_ids` equals the sorted set of `entry_id`s grouped by
   `report_id` in `entries.jsonl`.
4. `origin` is the constant `"GitHub Advisory Database (reviewed)"` on every
   row.
5. `commit` is 40 lowercase hex chars; `repo_url` starts with
   `https://github.com/`.
6. `source_link` contains `github.com/advisories/` and its embedded GHSA id
   equals `report_id`.
7. `entry_point`, `critical_operation`, and every `trace[i]` have exactly the keys
   `{file, line, code}`; `line` is a non-negative integer.
8. No row contains any of the internal fields we intentionally omit
   (`description`, `human_remark`, `pipeline_id`, `annotated_by`,
   `is_active`, `created_at`, `generality`,
   `detection_type`, `ground_truth`, `taint_source`, `taint_sink`,
   `vuln_category_l3`).
9. Every `entry` row has a `verify` field whose value is exactly `0` or `1`.

---

## Forward compatibility

- New **optional** top-level fields may be added in minor versions; existing
  fields will not be removed or re-typed without a major version bump.
- `verify` was introduced in v0.1.1 as an integer flag (`0` / `1`); it may be
  generalized to a richer status code (e.g. multiple audit levels) in a
  future minor version while keeping backward-compatible truthy semantics
  for `1`.
- An English translation of `vuln_category_l1/l2` is a likely future
  addition as `vuln_category_l1_en` / `_l2_en`.
- The JSONL ordering (entries by `entry_id` asc, reports by `report_id`
  asc) is part of the contract — consumers can depend on it.
