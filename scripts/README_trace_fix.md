# VulnGym Trace Anomaly Detection and Cleanup Tool

This tool detects and cleans structural anomalies within the `trace` calling sequences in VulnGym dataset entries. It targets two main types of issues:
1. **Duplicate Trace Nodes**: Trace nodes within the same entry that have identical `{file, line, code}` fields.
2. **Sequential Trace Order Anomalies**: Trace nodes in the same file as `entry_point` or `critical_operation` that violate chronological flow boundaries:
   - **Before Entry Point**: The trace node occurs before the entry point line number in the entry point file.
   - **After Critical Operation**: The trace node occurs after the critical operation line number in the critical operation file.

---

## Processing Strategies

### 1. Duplicate Nodes Deduplication
- When duplicate nodes are found, the **first occurrence** is retained.
- The descriptions (`desc` field) of the duplicates are checked and synchronized:
  - If the first occurrence has no description but a duplicate does, the description is copied over.
  - If both have descriptions, the script ensures the most complete information is retained. If the descriptions differ, they are merged cleanly using a pipe (` | `) separator.

### 2. Sequential Order Anomalies
The script processes sequential anomalies differently depending on their location:
- **Before Entry Point (`trace_start < ep_start` in the same file)**: Since the entry point is where the taint flow begins, any trace step occurring before it in the file is invalid. In `repair` mode, these nodes are **automatically deleted**.
- **After Critical Operation (`trace_start > co_end` in the same file)**: The critical operation represents the sink of the vulnerability. Nodes appearing below it in the same file might be intermediate steps in call-return structures. Deleting them automatically could break the logical call sequence. By default, these nodes are **retained and flagged for manual review** in the log files.

---

## Installation & Requirements

The script uses only Python standard libraries and requires no external dependencies.
- Python 3.6+

---

## Usage Instructions

To run the script in the default **Conservative Mode** targeting only unverified (`verify=0`) entries:
```bash
python fix_traces.py -i data/entries.jsonl -o data/entries.trace_fixed.jsonl
```

### CLI Command Line Arguments

| Argument | Default Value | Description |
|---|---|---|
| `-i`, `--input` | `data/entries.jsonl` | Path to the source VulnGym JSONL entries file. |
| `-o`, `--output` | `data/entries.trace_fixed.jsonl` | Path to save the repaired entries file. |
| `--log-csv` | `data/trace_fix_log.csv` | Path to output the human-readable CSV modification log. |
| `--log-json` | `data/trace_fix_log.json` | Path to output the structured JSON modification log. |
| `--mode` | `repair` | Processing mode: `repair` (deletes out-of-bounds nodes) or `conservative` (only logs anomalies). |
| `--verify-filter` | `0` | Filter by `verify` field: `0` (unverified only), `1` (verified only), or `all` (all entries). |
| `--delete-after-co` | *False (flag)* | Force deletion of "After Critical Operation" nodes under repair mode instead of retaining them. |

---

## Log Output Formats

Every change or flagged issue is recorded in both JSON and CSV files. The fields include:
- `Entry ID`: The identifier of the entry (e.g. `entry-00103`).
- `Log Type`: The action taken, such as:
  - `desc_sync`: Deduplication-driven description update or merge.
  - `before_ep_deleted`: Deleted a node appearing before the entry point in repair mode.
  - `before_ep_flagged`: Logged a node appearing before the entry point in conservative mode.
  - `after_co_deleted`: Deleted a node appearing after the critical operation when `--delete-after-co` is enabled.
  - `after_co_flagged`: Retained and flagged a node appearing after the critical operation for manual review.
- `File Path`: The repository-relative path where the anomaly occurred.
- `Line(s)`: The line number or range string (e.g., `"605-614"`).
- `Detail Description`: Contextual details of the check or change.

---

## Design Limitations
- **Cross-File Line Comparisons**: The script adheres to the rule that trace orders across different files are not compared by line numbers and are kept in their original sequence.
- **Overlapping Line Ranges**: Line ranges (e.g., `"82-84"`) are compared by checking the start of the trace range against the bounds of the reference node range. If ranges overlap (e.g., `"79-85"` vs. `"82-84"`), they are not considered out-of-bounds.
