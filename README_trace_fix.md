# VulnGym trace fix

## 任务背景

Issue #5 需要清理 `data/entries.jsonl` 中 VulnGym 调用链 trace 的确定性异常：同一 entry 内重复出现的 trace 节点，以及与 entry point 或 critical operation 位于同一文件时明显落在边界外的顺序异常节点。脚本不会修改原始 `data/entries.jsonl`，所有检测和修复结果都写入 `outputs/`。

## 运行方式

默认 check 模式：

```bash
python3 scripts/fix_trace.py
```

显式 fix 模式：

```bash
python3 scripts/fix_trace.py --mode fix
```

自定义路径：

```bash
python3 scripts/fix_trace.py \
  --input data/entries.jsonl \
  --output outputs/entries.trace_fixed.jsonl \
  --log outputs/trace_fix_log.csv \
  --report outputs/trace_fix_report.json \
  --mode check
```

脚本输出：

- `outputs/entries.trace_fixed.jsonl`
- `outputs/trace_fix_log.csv`
- `outputs/trace_fix_report.json`

## check/fix 模式区别

`check` 是默认模式，只检测并记录问题，不删除 trace 节点。此模式下 `outputs/entries.trace_fixed.jsonl` 是通过 schema 校验后的未修改副本，日志中的可删除项动作为 `would_remove`。

`fix` 模式会删除确定性的异常 trace 节点，包括重复节点和同文件顺序异常节点。日志中的删除项动作为 `remove`，报告中会统计实际删除数量。

## 重复节点判断策略

同一 entry 的 trace 中，节点的 `{file, line, code}` 三个字段完全相同即视为重复。脚本保留第一次出现的节点，后续重复节点写入 `trace_fix_log.csv`；`fix` 模式下删除后续重复节点。

如果重复节点的 `desc` 与第一次出现的节点不同，日志字段 `need_manual_review` 会标记为 `true`，对应 entry 也会进入报告的 `manual_review_entries`。

## 同文件顺序异常判断策略

脚本不会对 trace 做全局排序，只按原始顺序逐项检测。

当 trace 节点与 `entry_point.file` 相同，并且该 trace 节点的结束行号小于 entry point 的起始行号时，标记为 `trace_before_entry_point`。

当 trace 节点与 `critical_operation.file` 相同，并且该 trace 节点的起始行号大于 critical operation 的结束行号时，标记为 `trace_after_critical_operation`。

上述节点在 `check` 模式只记录，在 `fix` 模式删除。

## 跨文件 trace 为什么不参与行号比较

跨文件调用链中的行号属于不同文件的独立坐标系，不能用大小关系表达调用先后。对跨文件节点强行按行号排序或删除会破坏原始调用链语义。因此脚本对既不属于 `entry_point.file`、也不属于 `critical_operation.file` 的 trace 节点只记录 `cross_file_skip_line_compare`，不排序、不删除。

## line int 和 "start-end" 的处理方式

`parse_line_range(line)` 统一解析行号：

- `97` 解析为 `(97, 97)`
- `"348-352"` 解析为 `(348, 352)`

合法行号必须从 1 开始。字符串范围必须满足 `start <= end`。布尔值、0、负数、空字符串、单行数字字符串和非法范围都会触发校验错误。

## 基础 schema 校验

脚本会校验输入和输出 JSONL：

- 每行必须是一个 JSON object，不能是 JSON 数组。
- `entry_point`、`critical_operation`、`trace[*]` 必须包含 `file`、`line`、`code`。
- `file` 和 `code` 必须是字符串。
- `line` 必须是合法 int 或 `"start-end"`。
- `verify` 必须是整数 `0` 或 `1`，JSON 布尔值 `true`/`false` 不合法。

为保护原始数据，`--output`、`--log`、`--report` 均不能与 `--input` 指向同一路径，三个输出路径之间也不能重复。

## 当前限制

- 脚本只删除确定性异常，不尝试推断跨文件调用顺序。
- 脚本不会重写、补全或合并 `desc`。
- 脚本不做 trace 全局排序，以保留原始调用链顺序。
- `need_manual_review=true` 的重复节点只表示说明文本不一致，需要人工判断是否存在语义差异。
