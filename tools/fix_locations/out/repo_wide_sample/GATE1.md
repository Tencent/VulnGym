# GATE1 — repo-wide sample（2026-07-20）

## 样本

`entry-00164` / `entry-00193` / `entry-00298`  
产物：`out/repo_wide_sample/`  
机器复核：`scripts/gate1_repo_wide_sample.py` → `GATE1.json`

## 结果

| 指标 | 值 |
|------|-----|
| `repo_wide_unique` | **0** |
| `repo_wide_no_match` | 4（复检 hit_count=0，分类正确） |
| `degenerate_snippet` | 1（`entry-00298` entry_point `};`，未自动修） |
| 误自动修 | **无** |

## 裁决

**PASS**（计划规则：0 条 unique 但 no_match/degenerate 分类正确 → 策略合格，允许全量）

## 备注

三样本均落在 openclaw 系；标注 `code` 含注释尾巴，全仓搜不到精确归一化匹配属预期，**不**因此放宽唯一性。
