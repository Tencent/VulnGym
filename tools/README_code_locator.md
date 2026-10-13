# Code Locator — VulnGym 代码片段定位偏差修复工具

根据 [Issue #4](https://github.com/Tencent/VulnGym/issues/4) 要求，
自动检测并修复 `data/entries.jsonl` 中 `{file, line, code, desc}`
节点的定位偏差。

## 检测的问题类型

| 类型 | 说明 | 修复策略 |
|---|---|---|
| **`fixed_nearby`** | 代码在原始行号 ±5 行范围内找到唯一匹配 | 自动修正 `line` |
| **`fixed_file`** | 代码在原始文件全文找到唯一匹配 | 自动修正 `line` |
| **`fixed_repo`** | 代码在整个仓库找到唯一匹配 | 自动修正 `file` 和 `line` |
| **`needs_human`** | 代码在仓库中未找到唯一匹配（多处命中或完全找不到） | 写入 `needs_human.csv`，需人工判断 |

## 修复策略

对每个 `entry_point` / `critical_operation` / `trace[*]` 节点：

1. **验证原始位置** — 检查 `code` 是否在 `file:line` 处匹配
2. **±5 行搜索** — 在原始行号 ±5 行范围内搜索
3. **全文件搜索** — 在原始文件全文搜索
4. **全仓库搜索** — 使用 `git grep` 在整个仓库搜索
5. **人工复核** — 多处命中或完全找不到的节点进入人工队列

### 代码匹配规则

- 忽略首尾空白
- 忽略制表符/空格差异（1 tab ≈ 4 spaces）
- 忽略连续空格数量差异
- 支持多行代码片段（`\n` 分隔）

### desc 更新策略

当节点的 `file` 或 `line` 发生变化时，工具会保守地更新 `desc` 中
明确出现的旧位置引用（如 `filename.ts:97` → `filename.ts:105`）。
不尝试理解语义或改写句子——复杂的情况留给人工复核。

## 快速开始

```bash
# 干运行模式：仅检测并生成报告，不修改数据
python tools/code_locator.py --mode dry-run

# 修复模式：检测并修复
python tools/code_locator.py --mode fix

# 仅处理未人工校验的条目（推荐用于安全修复）
python tools/code_locator.py --mode fix --verify-filter 0

# 仅处理特定 entry（用于调试）
python tools/code_locator.py --mode fix --entry-id entry-00103

# 自定义缓存目录
python tools/code_locator.py --mode fix --cache-dir /data/vulngym-cache

# 离线模式：仅使用已缓存的仓库，跳过 clone
python tools/code_locator.py --mode fix --skip-clone
```

## 参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--mode` | `dry-run` | `dry-run` = 仅检测；`fix` = 检测并修复 |
| `--verify-filter` | `all` | `0` = 仅处理 verify=0；`1` = 仅处理 verify=1；`all` = 全部 |
| `--input` | `data/entries.jsonl` | 输入 JSONL 文件路径 |
| `--output` | `data/entries.fixed.jsonl` | 修复后输出路径（仅 fix 模式） |
| `--fix-diff` | `data/fix_diff.csv` | 修改对比 CSV 输出路径 |
| `--needs-human` | `data/needs_human.csv` | 人工复核 CSV 输出路径 |
| `--cache-dir` | `~/.cache/vulngym-repos/` | 仓库缓存目录 |
| `--skip-clone` | `false` | 跳过 clone，仅使用已缓存的仓库 |
| `--entry-id` | (无) | 仅处理指定的 entry_id（调试用） |

## 输出文件

### 修复后数据 (`entries.fixed.jsonl`)

与原始数据格式完全一致，每行一个 JSON 对象，满足 `SCHEMA.md` 的所有约束。

### 修改日志 (`fix_diff.csv`)

| 字段 | 说明 |
|---|---|
| `entry_id` | 受影响的 entry 标识 |
| `field_path` | 受影响的字段路径（如 `trace[2]`） |
| `change_type` | 修复策略（`fixed_nearby` / `fixed_file` / `fixed_repo`） |
| `old_file` | 原始文件路径 |
| `old_line` | 原始行号 |
| `new_file` | 修正后的文件路径 |
| `new_line` | 修正后的行号 |
| `fix_reason` | 修复原因说明 |
| `desc_updated` | 是否同步更新了 desc 字段 |
| `old_code` | 原始代码片段（截断） |
| `new_code` | 代码片段（未变） |

### 人工复核 (`needs_human.csv`)

| 字段 | 说明 |
|---|---|
| `entry_id` | entry 标识 |
| `field_path` | 字段路径 |
| `file` | 当前文件路径 |
| `line` | 当前行号 |
| `code` | 当前代码片段（截断） |
| `reason` | 无法自动修复的原因 |

## 处理策略与限制

### 缓存机制

- 仓库缓存在 `--cache-dir` 目录下
- 同一仓库的不同 commit 共享同一个 clone
- 首次使用需要网络访问以 clone 仓库
- 后续运行使用 `--skip-clone` 可离线运行

### 已知限制

- **不分析语义** — 仅基于文本匹配，不执行代码语义分析
- **仓库过大** — 对于超大型仓库，`git grep` 可能较慢
- **模板/生成代码** — 对于动态生成的代码片段无法匹配
- **desc 更新保守** — 只替换明确出现的旧位置引用，不重写语义
- **跨文件重命名** — 当仓库中文件名变更时可能误判
- **二进制文件** — 自动跳过非文本文件

### 性能预估

- 首次运行（需 clone 23 个仓库）：5-10 分钟（取决于网络）
- 后续运行（已有缓存）：1-3 分钟
- 仅处理 `verify=0`（15 条，约 5 个仓库）：30 秒-2 分钟

## 依赖

- Python ≥ 3.9
- Git ≥ 2.30（需在 PATH 中可用）
- 网络访问（首次运行时用于 clone 仓库）
- 磁盘空间约 5-10 GB（用于缓存仓库）

## 与其它工具的协作

本工具侧重于修复 **代码片段与位置的对应关系**，建议在以下工具之后运行：

1. 先运行 `trace_fixer.py` — 清理 trace 调用链的结构性问题（重复节点、顺序异常）
2. 再运行 `code_locator.py` — 修复代码片段定位偏差
3. 最后人工审查 `needs_human.csv` — 处理无法自动修复的节点
