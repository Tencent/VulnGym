# Trace Fixer — VulnGym 调用链清理工具

根据 [Issue #5](https://github.com/Tencent/VulnGym/issues/5) 要求，
自动检测并清理 `data/entries.jsonl` 中 `trace` 字段的结构性问题。

## 检测的问题类型

| 类型 | 说明 | 处理方式 |
|---|---|---|
| **DUPLICATE_INTERNAL** | trace 数组内部出现完全相同的 `{file, line, code}` | fix 模式：移除重复项，保留首次出现 |
| **CROSS_FIELD_DUPLICATE** | trace 节点与 `entry_point` 或 `critical_operation` 完全相同 | 仅记录，不自动修改（这不一定是错误） |
| **ORDER_ANOMALY** | 同一文件内 trace 节点行号早于 `entry_point` 或晚于 `critical_operation` | fix 模式：仅对 `verify=0` 条目移除；`verify=1` 条目保留（人工已确认） |

## 快速开始

```bash
# 保守模式：仅检测并记录异常，不修改任何数据
python tools/trace_fixer.py --mode conservative

# 修复模式：移除确定有问题的节点，生成修复后数据
python tools/trace_fixer.py --mode fix

# 仅处理未人工校验的条目（推荐用于安全修复）
python tools/trace_fixer.py --mode fix --verify-filter 0
```

## 参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--mode` | `conservative` | `conservative` = 仅检测；`fix` = 检测并修复 |
| `--verify-filter` | `all` | `0` = 仅处理未校验条目；`1` = 仅处理已校验条目；`all` = 处理全部 |
| `--input` | `data/entries.jsonl` | 输入 JSONL 文件路径 |
| `--output` | `data/entries.trace_fixed.jsonl` | 修复后输出路径（仅 fix 模式生效） |
| `--log` | `data/trace_fix_log.csv` | 逐条修改日志输出路径 |
| `--report` | `data/trace_fix_report.json` | 统计摘要报告输出路径 |

## 输出文件

### 修复后数据 (`entries.trace_fixed.jsonl`)

与原始数据格式完全一致，每行一个 JSON 对象，满足 `SCHEMA.md` 的所有约束。

### 修改日志 (`trace_fix_log.csv`)

每行记录一次检测或修复操作，包含字段：

| 字段 | 说明 |
|---|---|
| `entry_id` | 受影响的 entry 标识 |
| `field_path` | 受影响的字段路径（如 `trace[2]`） |
| `action` | 操作类型（见上方表格） |
| `reason` | 详细的检测/修复原因 |
| `before` | 修改前的节点 JSON |
| `after` | 修改后的结果 |
| `mode` | 执行时的运行模式 |

### 统计报告 (`trace_fix_report.json`)

包含按类型汇总的统计数据、受影响的 entry 列表、运行模式等。

## 处理策略与限制

### 行号比较规则

- 支持整数行号 (`97`) 和区间行号 (`"348-352"`) 两种格式
- 同一文件内的顺序比较：
  - "早于 entry_point"：trace 节点的结束行 < entry_point 的起始行
  - "晚于 critical_operation"：trace 节点的起始行 > critical_operation 的结束行
- **跨文件 trace 不做行号重排**，原始顺序始终保留

### 对 verify 状态的处理

- `verify=0`（未人工校验）：fix 模式下自动移除确定有问题的节点
- `verify=1`（已人工校验）：order anomaly 仅记录不修改，因为"越界"节点可能
  是跨函数调用的正确语义结构（如辅助函数定义在前、调用在后）

### 已知限制

- 不分析代码语义——仅基于文件路径和行号进行结构检测
- `CROSS_FIELD_DUPLICATE`（trace 中包含 entry_point / critical_operation 本身）
  在很多条目中是有意为之的（将入口/关键操作作为调用链的首/尾节点），工具不会
  自动移除，需人工判断
- 修复后的数据建议人工抽查，尤其是 `verify=0` 的条目

## 本次修复结果摘要

| 指标 | 数值 |
|---|---|
| 扫描 entry 总数 | 408 |
| DUPLICATE_INTERNAL（内部重复，已移除） | 7 |
| ORDER_ANOMALY_REMOVED（顺序异常，已移除） | 4 |
| ORDER_ANOMALY_DETECTED（顺序异常，保留——人工已确认） | 351 |
| CROSS_FIELD_DUPLICATE（跨字段重复，保留——不一定是错误） | 563 |
| 受影响的 verify=0 条目 | 14 / 15 |
| 受影响的 verify=1 条目 | 357 / 393 |
| 修复后数据通过 SCHEMA.md 验证 | OK |
