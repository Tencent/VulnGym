# COMPAT #49 冒烟报告（L3）

日期：2026-07-21  
目标：验证我们的 `needs_human.for_49.csv` 可被 [#49](https://github.com/Tencent/VulnGym/pull/49) 的 `location_review.py init` 消费。

## 步骤

1. `git fetch origin pull/49/head:refs/tmp/pr-49`
2. 抽出 `tools/location_review.py` → `out/_pr49_smoke/`（**不入库**）
3. 使用本仓库 `data/entries.jsonl` + `out/needs_human.for_49.csv`

```text
python out/_pr49_smoke/location_review.py init \
  --input data/entries.jsonl \
  --queue out/_pr49_smoke/reports/needs_human.for_49.csv \
  --decisions out/_pr49_smoke/reports/location_review_decisions.csv
```

（实际命令路径以本机冒烟目录为准。）

## 结果

| 项 | 值 |
|----|-----|
| init 退出码 | **0** |
| 队列输入行 | 73（已剔除 fetch_failed；本批 dropped=0） |
| 决策表行 | **73** (+ header → 74 lines) |
| 样例列 | `review_id,entry_id,field_path,expected_node_sha256,original_file,original_line,reason,decision,...` |

结论：**兼容通过**。后续由审阅者填写 `decision/new_file/new_line/reviewer/rationale` 后在 #49 工具侧 `apply`。

## 不入库说明

`out/_pr49_smoke/` 含他人 PR 脚本副本与本地决策草稿，已加入 `.gitignore`，不随本 PR 提交。
