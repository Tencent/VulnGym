# Fix-set overlap analysis (ours vs #35 / #39 / #41)

Purpose: explain why our auto-fix count (~102) can differ from conservative PRs (~14–19) without implying those PRs are 'wrong'.

## Executive finding（选拔者摘要）

| 类型 | 数量 | 含义 |
|------|------|------|
| `range_expand_same_start` | **90** | 起点不变，`N`→`N-M`（多行 code） |
| `line_moved` | **12** | 真行号偏移 |

- vs **#35/#39**：交集 **12**；仅我们多出的 90 **全部是 range**
- vs **#41**：交集 **94**（同档高计数）
- **高置信 R2a**（line_moved ∩ 保守派 ∩ #41）：见 `HIGH_CONFIDENCE.md`（**12** 条）

结论：计数差距主要是记账差异，不是多猜 90 个位置。

## Our fix_diff composition

- total fix rows: **102**
- `range_expand_same_start`: 90
- `line_moved`: 12

## vs pr35

- their fix rows: **19**
- intersection: **12**
- only us: **90**
- only them: **7**

### Only-us breakdown (by our classification)

- `range_expand_same_start`: 90

### Examples only-us (up to 5)

- `entry-00125` `critical_operation`: 218 → 218-221 (neighborhood_pm5)
- `entry-00125` `trace[4]`: 278 → 278-281 (neighborhood_pm5)
- `entry-00125` `trace[5]`: 302 → 302-316 (whole_file)
- `entry-00127` `critical_operation`: 447 → 447-456 (whole_file)
- `entry-00127` `trace[1]`: 431 → 431-434 (neighborhood_pm5)

### Examples only-them (up to 5)

- `entry-00090` `trace[3]`: 174-183 → 174-182 (nearby_unique)
- `entry-00103` `trace[1]`: 605-614 → 606-614 (nearby_unique)
- `entry-00103` `trace[2]`: 146-155 → 146-154 (nearby_unique)
- `entry-00105` `trace[0]`: 69-75 → 69-74 (nearby_unique)
- `entry-00185` `trace[1]`: 75-82 → 76-82 (nearby_unique)

## vs pr39

- their fix rows: **14**
- intersection: **12**
- only us: **90**
- only them: **2**

### Only-us breakdown (by our classification)

- `range_expand_same_start`: 90

### Examples only-us (up to 5)

- `entry-00125` `critical_operation`: 218 → 218-221 (neighborhood_pm5)
- `entry-00125` `trace[4]`: 278 → 278-281 (neighborhood_pm5)
- `entry-00125` `trace[5]`: 302 → 302-316 (whole_file)
- `entry-00127` `critical_operation`: 447 → 447-456 (whole_file)
- `entry-00127` `trace[1]`: 431 → 431-434 (neighborhood_pm5)

### Examples only-them (up to 5)

- `entry-00103` `trace[1]`: 605-614 → 606-615 (nearby_unique)
- `entry-00185` `trace[1]`: 75-82 → 76-83 (nearby_unique)

## vs pr41

- their fix rows: **101**
- intersection: **94**
- only us: **8**
- only them: **7**

### Only-us breakdown (by our classification)

- `range_expand_same_start`: 8

### Examples only-us (up to 5)

- `entry-00402` `critical_operation`: 458 → 458-470 (whole_file)
- `entry-00402` `entry_point`: 77 → 77-90 (whole_file)
- `entry-00402` `trace[0]`: 256 → 256-271 (whole_file)
- `entry-00402` `trace[1]`: 265 → 265-269 (neighborhood_pm5)
- `entry-00402` `trace[2]`: 567 → 567-582 (whole_file)

### Examples only-them (up to 5)

- `entry-00090` `trace[3]`: 174-183 → 174-182 (nearby)
- `entry-00103` `trace[1]`: 605-614 → 606-614 (nearby)
- `entry-00103` `trace[2]`: 146-155 → 146-154 (nearby)
- `entry-00105` `trace[0]`: 69-75 → 69-74 (nearby)
- `entry-00185` `trace[1]`: 75-82 → 76-82 (nearby)

## Working hypothesis (for PR narrative)

1. A large share of our fixes are **range expansions** (`N` → `N-M` with same start): the annotated `code` is multi-line, but `line` was a single start line. Conservative PRs may treat start-aligned spans as already acceptable, or normalize differently.
2. We mark **degenerate snippets** (`}` etc.) as `needs_human` even when the line currently matches — reducing false confidence.
3. Overlap with #41 (similar ~100 fixes) should be high if both expand ranges aggressively; overlap with #35/#39 should be smaller and concentrated on true line moves.
4. This analysis does **not** prove our extras are all correct — human spot-check of `range_expand_same_start` is mandatory.
