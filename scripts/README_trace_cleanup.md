# Trace 结构检查与保守清理

`trace_cleanup.py` 用于完成 Issue #5 要求的重复节点、同文件边界异常和跨文件
比较检查。工具只把源码行号当作结构线索，不把它等同于运行时调用顺序。

## 核心原则

1. 默认 `check` 模式只报告，不改变数据。
2. `fix` 模式只删除策略明确允许、且不属于 `verify=1` 的节点。
3. `{file, line, code}` 完全相同才是重复候选。
4. 重复节点的 `desc` 不同时不拼接、不删除，进入人工复核。
5. 区间节点只有完全位于入口之前或关键操作之后才算边界 finding；相交区间保留。
6. 跨文件节点不按行号比较，也不重排。
7. `trace` 与 entry point / critical operation 相同不构成“trace 内部重复”。
8. 源码定义顺序不等于运行时顺序，因此 order finding 默认进入人工复核。

## 使用方式

```bash
# 默认：生成完整检测报告，不修改任何 trace
python3 scripts/trace_cleanup.py

# 保守 fix：只移除 verify=0 且描述一致的精确重复节点
python3 scripts/trace_cleanup.py --mode fix

# 显式采用纯结构边界删除；已人工审阅的例外仍会保留
python3 scripts/trace_cleanup.py --mode fix --order-policy structural

# 将四条未审核边界 finding 与各自固定提交逐字核对
python3 scripts/trace_cleanup.py --check-upstream
```

## 产物

- `data/entries.trace_fixed.jsonl`：保守策略的完整输出。
- `reports/trace_findings.csv`：全部结构 finding。
- `reports/trace_fix_diff.csv`：实际自动修改；无安全修改时只有表头。
- `reports/trace_needs_human.csv`：未审核且需要语义判断的 finding。
- `reports/trace_structure_report.json`：机器可读统计、哈希与策略。
- `reports/trace_structure_report.md`：面向 reviewer 的结果摘要。

## 为什么默认不删除四条未审核边界 finding

当前 `verify=0` 数据只有四个完全越界的同文件节点，但逐条检查表明它们不是可靠的
自动删除候选：

- `entry-00103`：当前入口只是第 615 行闭合括号；此前 streaming 分支是有效上下文。
- `entry-00185`：第 65 行 `return false` 是路径阻断判断，当前 critical anchor 本身可疑。
- `entry-00320`：`save_file_routine` 定义在同文件前部，但运行时由后部 API 逻辑调用。
- `entry-00511`：`extend()` 定义在 helper 后面，但执行时由它调用 helper。

简单删除会把“源码声明位置”误当成“运行时调用顺序”。默认产物因此保留四条节点，
并写入 `trace_needs_human.csv`。工具仍通过 `--order-policy structural` 提供题目要求的
可配置机械删除能力，但不会覆盖已经记录的人工审阅例外。

## 限制

结构检查不能证明 caller/callee、数据流或控制流语义。它适合发现候选和执行确定性去重，
不能替代针对漏洞提交的语义重建。`verify=1` 数据始终受保护；若维护者决定重新审核，
应先调整审核状态或使用单独的人工修复流程，而不是扩大默认自动删除范围。
