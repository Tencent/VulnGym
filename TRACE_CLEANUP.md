# Trace 结构检查与清理工具

`tools/trace_cleanup.py` 扫描 `data/entries.jsonl` 中的 `trace`，检测内部重复节点、
同文件边界异常和需要跳过行号比较的跨文件节点。工具只使用 Python 标准库。

## 快速开始

默认是保守的 `report` 模式：完整扫描、生成日志和报告，但输出 JSONL 与输入文件
保持字节级一致。

```bash
python tools/trace_cleanup.py
```

默认保守运行写入 `data/entries.trace_reported.jsonl`、`trace_report_log.csv` 和
`trace_report.json`，不会覆盖下方修复模式的交付物。

显式启用修复模式：

```bash
python tools/trace_cleanup.py \
  --mode fix \
  --input data/entries.jsonl \
  --output data/entries.trace_fixed.jsonl \
  --log trace_fix_log.csv \
  --report trace_cleanup_report.json
```

修复模式默认只自动修改 `verify=0` 的记录。`verify=1` 中的候选仍会出现在日志中，
但动作标记为 `manual_review`。只有明确接受风险时才使用 `--include-verified`：

```bash
python tools/trace_cleanup.py --mode fix --include-verified
```

运行测试：

```bash
python -m unittest discover -s tests -v
```

## 处理策略

### 1. Trace 内部重复

只有两个 `trace` 元素的 `{file, line, code}` 三元组完全相同时，才视为重复候选。
不会将 `trace` 与 `entry_point` 或 `critical_operation` 比较，因此入口点/关键操作
本身出现在 trace 中并不构成重复。

修复时保留第一次出现的节点：

- 第一个节点缺少 `desc`、后续重复节点有非空 `desc`：把描述同步到第一个节点。
- 两个非空 `desc` 不同：保留第一个描述，记录 `duplicate_description_conflict`，
  交由人工复核。

### 2. 同文件边界异常

整数行号 `n` 会归一化为闭区间 `[n, n]`；`"start-end"` 会归一化为
`[start, end]`。

- trace 的起始行小于同文件 `entry_point` 的起始行：记录
  `trace_before_entry_point`。
- trace 的结束行大于同文件 `critical_operation` 的结束行：记录
  `trace_after_critical_operation`。
- 只有 trace 区间**完全位于边界之外**时，修复模式才会自动删除。
- 区间跨越边界时只记录 `manual_review`，不会自动删除。
- 同文件的入口边界本身晚于关键操作边界时，记录 `boundary_inversion`，该文件的
  trace 节点不自动修复。

工具从不按行号重新排序 trace。

### 3. 跨文件调用链

节点文件与对应边界文件不同时，不进行行号比较，不改变节点位置，并在 CSV 中记录：

```text
跨文件，不参与行号比较；原始 trace 顺序保持不变
```

一个节点仍可只和相同文件的边界比较。例如节点与 `entry_point` 同文件、与
`critical_operation` 不同文件时，只执行入口边界检查。

## 输出

### `data/entries.trace_fixed.jsonl`

与输入保持相同的行式 JSON 结构、字段排序和 entry 顺序。写出前后都会执行
`SCHEMA.md` 的 entry 级基础约束检查，包括必需字段、行号类型、ID、commit、
`verify`、节点结构和 entry 排序。

### `trace_fix_log.csv`

每条发现均包含：

- `entry_id`
- `field_path`（例如 `trace[2]`）
- `finding` 和 `action`
- JSON 编码的 `before` / `after`
- `reason`
- 实际比较的行号区间或被跳过的边界

`action` 可能为 `remove`、`sync_description`、`manual_review`、`report_only`、
`already_removed_duplicate` 或 `skip`。

### `trace_cleanup_report.json`

报告记录输入/输出 SHA-256、Schema 校验状态以及以下统计：重复候选、入口前异常、
关键操作后异常、区间重叠、跨文件跳过、自动修复、修改 entry、人工复核项等。

## 限制

源码行号只是调用链结构的近似信号，不能证明真实运行时调用顺序。不同函数即使位于
同一文件，调用顺序也可能与行号相反。因此默认采用保守模式；修复模式也只删除完全
越界且允许自动修改的节点，边界重叠、描述冲突和已人工验证记录均保留复核证据。
