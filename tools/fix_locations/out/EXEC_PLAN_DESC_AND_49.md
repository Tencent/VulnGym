# 执行清单：desc 机械同步 + 对接 #49（追加到 PR #61）

> 决策已锁定（2026-07-21）。本清单执行完再 push。

## 决策固化

| # | 选择 |
|---|------|
| 1 | **B** — 追加 commit 到 [#61](https://github.com/Tencent/VulnGym/pull/61)（分支 `feat/issue-4-location-fix`） |
| 2 | **B** — 产出 `entries.fixed.desc_synced.jsonl`，**不覆盖** `entries.fixed.jsonl` |
| 3 | **A** — 仅对 dry-run 的 **10** 条 `would_update` 写入（本批全部 `entry-00458`） |
| 4 | **C** — L1 文档 + L2 导出 + L3 拉 #49 `init` 冒烟 |
| 5 | 导出给 #49 前 **剔除** `repo_fetch_failed` / `fetch_failed` 并说明 |
| 6 | 我们机械同步 **与** #49 apply 内 desc 同步 **两者都做**；产物分文件 |

## 分支注意

- 工作在 `feat/issue-4-location-fix`（勿写进 `feat/issue-4-repo-wide`）。
- `feat/issue-4-repo-wide` 已有独立 commit，留给 PR2。

## 文件级动作

### 轨 A — desc

1. `scripts/desc_sync_lib.py` — 抽出 `try_sync` 等
2. `scripts/desc_sync_dryrun.py` — 改为调用 lib
3. `scripts/desc_sync_apply.py` — 读 `entries.fixed.jsonl` + `fix_diff.csv`，只应用 `would_update`，写出：
   - `out/entries.fixed.desc_synced.jsonl`
   - `out/desc_sync_applied.csv`
   - `out/desc_sync_apply_summary.json`
4. `tests/test_desc_sync.py` — 锚点替换 / 无锚点 / 范围 / 幂等
5. 更新 `README.md`、`out/PR_BODY.md`

### 轨 B — #49

1. `out/COMPAT_WITH_49.md` — 列映射、命令、边界、假阳性剔除说明
2. `scripts/export_queue_for_49.py` — 输入 `needs_human.csv` → `out/needs_human.for_49.csv`（剔 fetch_failed；保留 `field_path`，可选镜像 `node_path`）
3. L3：`git fetch` #49 head → 临时目录或 worktree 跑 `location_review.py init` → `out/COMPAT_49_SMOKE.md`

### 提交

- 不改 `data/entries.jsonl`
- 不提交 `.repo_cache/`、个人 night 文档
- push 需你确认后再执行

## 验收

- [x] 10 条 desc 仅锚点变化（规则复核：第 N 行 → 第 N-M 行）
- [x] unittest 全绿（27）
- [x] `needs_human.for_49.csv` 无 fetch_failed（kept=73 dropped=0）
- [x] #49 init 冒烟成功（73 decisions）→ `COMPAT_49_SMOKE.md`
- [ ] 本地 commit 追加 #61（待确认后 push）
