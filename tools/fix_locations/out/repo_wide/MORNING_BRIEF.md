# 晨间摘要 — PR2 `--repo-wide`（2026-07-21）

## 今晚做了什么（YELLOW_SCOPED）

- `GO_NIGHT=true`；分支 `feat/issue-4-repo-wide`
- 单测 21/21（含 `repo_wide_unique` / `ambiguous` / `no_match`）
- 小样本 3 entry → **G1 PASS**（0 unique；4×`no_match`+1×degenerate 分类正确）
- 全量 `--all --repo-wide --apply` → `out/repo_wide/`（408 entries）
- **未** push / **未**开 PR / **未**改 `data/entries.jsonl`
- **未**放宽唯一性 / degenerate

## 关键结果

| 检查 | 结果 |
|------|------|
| fix_diff | **102**（与 PR1 完全同集合：64 邻域 + 38 全文） |
| `repo_wide_unique` 增量 | **0** |
| needs_human | **73**（18 degenerate + **55** `repo_wide_no_match`） |
| degenerate | 18→18（未被「修没」） |
| `repo_wide_ambiguous` | 0 |
| verifier | **ok**（schema 0；diff 一致；幂等 24/24） |
| 单元测试 | **21/21** |

解读：第 3 级已全量执行；本数据集在「文件内失败」的 55 处上，全仓亦**无唯一命中**（多为带注释尾巴的标注片段）。诚实报告 0 增量，不编造修复。

## 请你批 0–2 项

1. 是否仍开 **PR2**（叙事：开关跑通 + 分级 reason + 0 增量证据）？approve / defer  
2. push fork？approve / defer（默认你白天做）

## 路径

- `out/repo_wide_sample/GATE1.md`
- `out/repo_wide/DELTA.md` / `VERIFY_REPORT.md`
- `out/repo_wide/PR2_DRAFT.md`
- `MORNING_CHECKLIST_REPO_WIDE.md`
