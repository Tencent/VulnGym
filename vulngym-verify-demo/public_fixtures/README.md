# VulnGym public smoke fixtures

此目录只包含可公开的输入，不含任何 gold 标签。CI 用它确认离线 CLI
能够读取 JSONL、隔离异常行并生成可提交的报告；它不会计算分数，也不能
作为训练或阈值评测的依据。

## 当前内容和边界

- `entries.jsonl`：11 条公开冒烟输入（10 条正常输入、1 条故意损坏输入）。
- 输出由 CLI 在每次运行中生成，例如 `/tmp/reports_ci.jsonl`；提交时只能提交
  本次运行产生的报告，不能附带 gold。
- 本子集只有 11 条，**不是**课题 Standard 所要求的 20 条公开测试集。其余
  9 条真实公开样本尚未提供，补齐前不得把它称作完整公开测试集或发布其指标。

历史上与这批输入同目录的 `gold.jsonl` 已移除，避免公开测试金标泄露。
仓库中的 `mock_data/` 是单独标记的开发回归 fixture，不能替代 50 条训练集
或隐藏评测集。

## 离线生成公开输出

在 `vulngym-verify-demo` 目录执行：

```bash
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --manifest mock_repo/manifest.json \
  --out /tmp/reports.jsonl \
  --llm mock
```

该命令刻意不传入 `--gold` 或 `--bench`。若要开发评测器，使用有明确许可的
开发回归 gold，并将评测结果与公开输出分开保存。
