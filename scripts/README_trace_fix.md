# Trace 结构清理脚本说明

`scripts/trace_fix.py` 用于扫描 `data/entries.jsonl` 中的 `trace` 结构问题，并按运行模式输出日志、报告和修复结果。

## 检查范围

脚本关注的是 `trace` 的结构性问题，而不是漏洞语义本身，主要检查：

- `trace` 内部重复节点：`{file, line, code}` 完全相同
- 同一文件内的顺序异常：
  - `trace` 节点出现在 `entry_point` 之前
  - `trace` 节点出现在 `critical_operation` 之后
- 跨文件节点：
  不参与同文件行号比较，只记录为跳过

同时支持两种 `line` 格式：

- 单行整数，如 `97`
- 区间字符串，如 `"605-614"`

## 命令

```bash
python scripts/trace_fix.py
python scripts/trace_fix.py --mode fix
```

- `python scripts/trace_fix.py`
  以 `dry-run` 模式运行。
  会全量检测重复节点和同文件顺序异常，但不会修改原始数据。
  适合先看问题分布，再决定是否执行修复。

- `python scripts/trace_fix.py --mode fix`
  以修复模式运行。
  会直接删除重复节点和“明显越界”的同文件顺序异常节点。
  对紧邻 `entry_point` / `critical_operation` 的模糊节点，仅记录到日志并保留在结果中，便于人工复核。

## 输出产物

- `reports/trace_fix_log.json`
  异常或修改日志。
  - `dry-run`：精简问题清单
  - `fix`：包含自动修复项和人工复核项，记录修改前后内容及原因

- `reports/trace_fix_report.json`
  统计报告，包含：
  - 重复节点数
  - 顺序异常数
  - 自动修复数量
  - 人工复核数量

- `data/entries.trace_fixed.jsonl`
  仅在 `--mode fix` 下生成，保存修复后的数据副本。

## 处理策略

- `dry-run` 默认保守：先完整检测，再输出日志和报告
- `fix` 只自动处理确定性问题：
  - 重复节点：直接删除后续重复项
  - 明显越界节点：直接删除
  - 近邻模糊节点：仅记录，不自动删除

## 基础校验

脚本会对输入和修复结果执行本次 issue 要求范围内的基础校验，包括：

- 顶层必需字段存在
- `entry_point` / `critical_operation` / `trace[*]` 具备 `{file, line, code}`
- `line` 为正整数或 `"start-end"`
- `verify` 只能是 `0/1`
- 输出结果仍为合法 JSONL

## 限制说明

- 脚本只基于文件路径和行号判断结构异常，不理解 AST 和真实调用语义
- 紧邻锚点的同文件节点是否应删除，仍可能需要人工判断
- `trace` 中包含 `entry_point` 或 `critical_operation` 本身时，默认视为合法锚点，不直接报错
