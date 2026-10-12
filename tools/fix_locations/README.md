# VulnGym Issue #4 — code location repair

保守修复 `entry_point` / `critical_operation` / `trace[*]` 的 `file`/`line`，
使它们与对应 commit 上的 `code` 对齐。规则见 [CONSTRAINTS.md](./CONSTRAINTS.md)。

## 快速开始

在仓库根目录：

```bash
# 只跑官方点名的 4 条（默认）
python tools/fix_locations/fix_code_locations.py --priority

# 写出修复后的 JSONL
python tools/fix_locations/fix_code_locations.py --priority --apply

# 全量（可断点：进度在 out/progress.jsonl）
python -u tools/fix_locations/fix_code_locations.py --all --apply

# 或 PowerShell 包装（带日志）
powershell -File tools/fix_locations/run_full.ps1

# 启用全仓唯一搜索（更慢，默认先别开）
python tools/fix_locations/fix_code_locations.py --all --repo-wide --apply
```

先读半页理解卡：[UNDERSTANDING.md](./UNDERSTANDING.md)。

## 测试（本地）

```bash
python -m unittest discover -s tools/fix_locations/tests -v
```

质量/竞争分析（可选）：

```bash
python tools/fix_locations/scripts/compare_fix_sets.py
python tools/fix_locations/scripts/verify_location_outputs.py
python tools/fix_locations/scripts/export_high_confidence.py
python tools/fix_locations/scripts/make_spotcheck_sheet.py
```

desc 机械同步（仅明确行号锚点；不覆盖 `entries.fixed.jsonl`）：

```bash
python tools/fix_locations/scripts/desc_sync_dryrun.py
python tools/fix_locations/scripts/desc_sync_apply.py
```

对接 [#49](https://github.com/Tencent/VulnGym/pull/49) 人审队列（剔除 `fetch_failed`）：

```bash
python tools/fix_locations/scripts/export_queue_for_49.py
```

说明见 `out/COMPAT_WITH_49.md`、冒烟见 `out/COMPAT_49_SMOKE.md`。

产物在 `tools/fix_locations/out/`：

- `fix_diff.csv` — 自动修复记录
- `needs_human.csv` — 无法唯一确定的节点
- `needs_human.for_49.csv` — 供 #49 `init` 的队列
- `entries.fixed.jsonl` — 仅 file/line 修复
- `entries.fixed.desc_synced.jsonl` — 另含机械 desc 锚点同步（本批 10 处）

上游仓库缓存目录：`.repo_cache/`（已加入 `.gitignore`）。

## 手验笔记：entry-00103（n8n @ 57d6015）

| 节点 | 标注 | 源码核对 |
|------|------|----------|
| `entry_point` L615 `}` | 行上确实是 `}` | **位置匹配，但语义差**（#4 不会改；属语义题） |
| `critical_operation` L20 `toLowerCase` | 完全命中 | ok |
| `trace[1]` `605-614` streaming 块 | 实质内容在 606–614 | 可能需微调 range |
| `trace[2]` `146-155` setResponseHeaders | 146–154 基本吻合 | 接近 ok |
| `trace[3]` `19-25` 函数体 | 吻合 | ok |

结论：#4 要解决的是 **code 与行对不上**；**对得上但选点荒谬** 应进 `needs_human` 或留给 #6/#7，不要为刷修复率硬改。

## 人工把关（每轮 10 分钟）

1. 打开 `fix_diff.csv` 抽 3 条「fixed」
2. 在 `.repo_cache/...` 对应文件核对 `code`
3. 打开 `needs_human.csv` 抽 2 条，确认没有被误自动修
4. 不通过则只改策略，不盲目扩 `--repo-wide` 覆盖率
