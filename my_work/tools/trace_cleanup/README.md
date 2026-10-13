# VulnGym Trace Cleanup

调用链重复节点与顺序异常清理工具，对应 [Issue #5](https://github.com/Tencent/VulnGym/issues/5)。

## 功能

| 模块 | 功能 |
|------|------|
| 重复节点检测 | 检测 trace 中 `{file, line, code}` 三元组完全相同的节点 |
| before-entry 检测 | 检测同文件内 trace 节点行号落在 entry_point 之前 |
| after-critical 检测 | 检测同文件内 trace 节点行号落在 critical_operation 之后 |
| 跨文件保护 | 不同文件的节点之间不做任何行号比较或排序 |
| 修复执行 | 对 verify=0 的明确异常执行自动删除 |

## 两种模式

| 模式 | 行为 |
|------|------|
| `conservative`（默认） | 仅检测和报告，不做任何修改 |
| `fix` | 对 verify=0 条目的明确异常执行自动删除；verify=1 条目完全保护 |

## 用法

```bash
# 进入 my_work 目录
cd my_work

# 保守模式（仅检测）
python -m tools.trace_cleanup.cleanup --input ../VulnGym/data/entries.jsonl --output data/entries.trace_fixed.jsonl --reports-dir reports

# 修复模式
python -m tools.trace_cleanup.cleanup --input ../VulnGym/data/entries.jsonl --output data/entries.trace_fixed.jsonl --reports-dir reports --mode fix
```

## 输出文件

| 文件 | 说明 |
|------|------|
| `data/entries.trace_fixed.jsonl` | 修复后的 JSONL 数据文件 |
| `reports/trace_findings.csv` | 每个 trace 节点的详细检测结果 |
| `reports/trace_fix_log.csv` | 修改日志（条目、字段、修改前后、原因） |
| `reports/trace_needs_human.csv` | 需要人工复核的条目清单 |
| `reports/trace_structure_report.json` | 汇总统计 JSON |

## 设计原则

1. **源码行号 != 执行顺序** — 行号表示声明顺序，不等于运行时调用关系
2. **保守优于激进** — 不确定的节点保留原样，标记人工复核
3. **跨文件是高压线** — 仅在同一文件内做行号比较
4. **verify=1 完全保护** — 已人工审核的数据不做任何自动修改
5. **可追溯性** — 每条修改都有完整日志

## 检测统计

| 类型 | 数量 |
|------|------|
| 总 entries | 408 |
| 总 trace 节点 | 2073 |
| 重复节点 | 7（全部 desc 冲突，需人工复核） |
| before-entry 异常 | 139（88 明确 + 51 模糊） |
| after-critical 异常 | 217（187 明确 + 30 模糊） |
| 跨文件节点 | 382 |

## 已知限制

- 行号比较无法替代代码语义理解，模糊异常需要人工判断
- 重复节点的 desc 合并策略在冲突时保守处理（进入人工复核）
- 仅对 verify=0 的条目执行自动修复
