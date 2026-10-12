# 人工抽查表（分层 ≥20）

生成自当前 `fix_diff.csv` / `needs_human.csv`，共 **20** 行。

## 怎么验

1. 对每一行执行 `checkout_cmd`（**换 entry 必 checkout**）
2. 打开 `cache_path` 下对应文件
3. 用标注 `code`（见 entries.jsonl 该节点）对照源码行；**勿用 IDE Ctrl+Z 历史**
4. `pass` 填 `yes`/`no`；`range_expand` 重点看：扩成 N-M 后是否整段等于 code

## 行清单

| # | bucket | entry | field | old→new | strategy/reason |
|---|--------|-------|-------|---------|------------------|
| 1 | fixed_neighborhood | `entry-00251` | `trace[3]` | 325→326 | neighborhood_pm5 |
| 2 | fixed_neighborhood | `entry-00312` | `critical_operation` | 125→128 | neighborhood_pm5 |
| 3 | fixed_neighborhood | `entry-00405` | `entry_point` | 619→614-624 | neighborhood_pm5 |
| 4 | fixed_range_expand | `entry-00125` | `critical_operation` | 218→218-221 | neighborhood_pm5 |
| 5 | fixed_range_expand | `entry-00127` | `critical_operation` | 447→447-456 | whole_file |
| 6 | fixed_range_expand | `entry-00134` | `entry_point` | 1444→1444-1449 | neighborhood_pm5 |
| 7 | fixed_range_expand | `entry-00148` | `entry_point` | 148→148-150 | neighborhood_pm5 |
| 8 | fixed_range_expand | `entry-00229` | `entry_point` | 80→80-82 | neighborhood_pm5 |
| 9 | fixed_range_expand | `entry-00248` | `critical_operation` | 159→159-167 | whole_file |
| 10 | fixed_whole_file | `entry-00300` | `trace[0]` | 134→196 | whole_file |
| 11 | fixed_whole_file | `entry-00398` | `trace[5]` | 413-421→407-413 | whole_file |
| 12 | human_no_unique | `entry-00164` | `trace[0]` | 7→- | no_unique_match_in_file_or_missing_file |
| 13 | human_no_unique | `entry-00193` | `entry_point` | 84→- | no_unique_match_in_file_or_missing_file |
| 14 | human_no_unique | `entry-00298` | `trace[0]` | 134→- | no_unique_match_in_file_or_missing_file |
| 15 | human_degenerate | `entry-00082` | `trace[1]` | 205→- | degenerate_snippet |
| 16 | human_degenerate | `entry-00103` | `entry_point` | 615→- | degenerate_snippet |
| 17 | human_fetch_failed | `entry-00097` | `*` | →- | repo_fetch_failed:Command '['git', 'checkout', '--force', 'f0c25036082a5e53650ae7230bcfcf9309bbb5d5']' returned non-zero exit status 128. |
| 18 | priority:degenerate_snippet | `entry-00103` | `trace[0]` | 615→- | degenerate_snippet |
| 19 | priority:degenerate_snippet | `entry-00185` | `critical_operation` | 48→- | degenerate_snippet |
| 20 | priority:degenerate_snippet | `entry-00185` | `trace[3]` | 48→- | degenerate_snippet |

详细可编辑表：[`SPOTCHECK_SHEET.csv`](./SPOTCHECK_SHEET.csv)
