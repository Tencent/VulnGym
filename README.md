# VulnGym entries.jsonl 自动修复工具

对 `data/entries.jsonl` 中的 `entry_point`、`critical_operation`、`trace[*]` 节点执行数据质量检查与自动修复。

## 快速开始

```bash
# 预检（无需网络，不需要仓库）— 检测无法自动修复的节点
python tools/fix_entries.py --dry-run

# 完整运行（需要网络，首次需 clone 仓库）
python tools/fix_entries.py

# 全量处理（包括 verify=1 的条目）
python tools/fix_entries.py --all
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--entries PATH` | entries.jsonl 路径 | `data/entries.jsonl` |
| `--output-dir DIR` | 输出目录 | `output/` |
| `--repo-cache DIR` | 仓库缓存目录 | `~/.cache/vulngym/repos/` |
| `--all` | 处理全部条目（默认仅 verify=0） | 否 |
| `--dry-run` | 仅预检，不访问仓库 | 否 |
| `--verbose` / `-v` | 详细日志 | 否 |

## 输出文件

| 文件 | 说明 |
|------|------|
| `entries.fixed.jsonl` | 修复后的数据（408 行 JSONL） |
| `fix_diff.csv` | 每处修改的前后对比 |
| `needs_human.csv` | 需人工复核的节点 |
| `structural_report.csv` | Trace 结构性问题报告 |
| `README.md` | 运行摘要 |

## 修复策略

对每个节点按以下优先级尝试匹配：

| 步骤 | 策略 | 操作 |
|------|------|------|
| Step 0 | 预检 | 检测空 code、通用代码、截断签名、Docker 指令 |
| Step 1 | 精确匹配 | 在声称的 file:line 处读取，对比 code |
| Step 2 | 近邻搜索 | 在 ±5 行范围内搜索 |
| Step 3 | 文件级搜索 | 在整个文件中搜索 |
| Step 4 | 上下文消歧 | 利用同 entry 其他节点信息消歧 |
| Step 5 | 仓库级搜索 | 在整个仓库中搜索 |

匹配成功时：
- 唯一命中 → 自动修复 `line` 或 `file`
- desc 中有行号/文件引用 → 同步更新

匹配失败时 → 写入 `needs_human.csv`：
- `UNMATCHABLE_CODE`：代码过于通用（如 `}`、`return false;`、Docker 指令）
- `EMPTY_CODE`：code 为空
- `TRUNCATED_CODE`：code 被截断（如 `def build(`）
- `MULTIPLE_MATCHES`：多处命中无法消歧
- `NO_MATCH`：找不到匹配
- `FILE_NOT_FOUND`：源文件不存在
- `REPO_UNAVAILABLE`：仓库无法访问

## 依赖

- Python 3.9+（仅标准库，无第三方包依赖）
- `git` CLI（在 PATH 中，用于仓库操作）
- 网络连接（首次需 clone GitHub 仓库）

## 已知限制

1. 无法处理语义重构（代码逻辑相同但变量名被重命名）
2. 首次运行需 clone 23 个 GitHub 仓库（~5-10 分钟）
3. 跨仓库文件重命名且 code 也变化时无法追踪
4. 过于通用的代码（如裸 `}`）必须人工复核
