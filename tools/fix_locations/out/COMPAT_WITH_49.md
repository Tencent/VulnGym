# 与 PR #49（人审写回闭环）的兼容说明

> 本工具只做自动定位与队列导出；**不重复实现** [#49](https://github.com/Tencent/VulnGym/pull/49) 的 `location_review.py`。  
> 决策：desc 机械同步由本仓库产出；#49 apply 仍可再做锚点同步（两者都做，产物分文件）。

## 列映射

| 我们的 `needs_human.csv` | #49 `init --queue` |
|--------------------------|--------------------|
| `entry_id` | 必需 |
| `field_path` | 必需（或别名 `node_path`） |
| `reason` | 可选，会复制 |
| 其它列（`old_file` 等） | 允许保留 |

导出脚本会同时写出 `field_path` 与 `node_path`（同值），避免别名差异。

## 推荐命令

```bash
# 1) 从本仓库产物导出给 #49 的队列（默认剔除 fetch_failed）
python tools/fix_locations/scripts/export_queue_for_49.py

# 2) 在已 checkout 的 #49 分支 / 工作树中：
python tools/location_review.py init \
  --input data/entries.jsonl \
  --queue path/to/needs_human.for_49.csv \
  --decisions reports/location_review_decisions.csv
```

我们仓库内冒烟记录见 `out/COMPAT_49_SMOKE.md`。

## 假阳性剔除（fetch_failed）

Windows 下部分 `repo_fetch_failed` 实为路径长度 / `core.longpaths` 问题（见 `FETCH_FAILED_NOTE.md`），**不是**「代码找不到」。

`export_queue_for_49.py` **默认剔除** `reason`/`status` 含 `fetch_failed` / `repo_fetch_failed` 的行，并写入 `needs_human.for_49_export_report.json`。当前主队列若已无此类行，则 `dropped=0`。

## 边界（我们不做）

- 不根据审阅者选择自动猜位置
- 不原地改 `data/entries.jsonl`
- 不替代 #49 的 fingerprint / blob 校验写回

## desc 双轨

| 产物 | 谁改 desc |
|------|-----------|
| `entries.fixed.jsonl` | 仅 file/line |
| `entries.fixed.desc_synced.jsonl` | 本仓库机械锚点（本批 10 处） |
| #49 `entries.reviewed.jsonl` | 人审 apply 时再同步锚点 |

若维护者只走 #49 写回，仍可用未同步 desc 的 fixed + for_49 队列；若只要自动产物，可用 `desc_synced`。
