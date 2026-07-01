# 入口位置修复脚本说明

本文档说明 `tools/fix_entry_locations.py` 的运行方式、依赖、输出文件、
修复策略和已知限制。

## 功能概述

脚本会读取 `data/entries.jsonl`，逐条检查每个漏洞样本中的
`entry_point`、`critical_operation` 和 `trace[*]` 节点。

每个节点会根据 `{file, line, code, desc}` 中的 `file`、`line` 和
`code`，在该 entry 对应仓库的对应 `commit` 快照中进行定位校验。若原始
位置无法匹配，脚本会以 `code` 字段为主要依据，尝试保守修复 `file` 和
`line`。无法确定的节点不会被自动修改，而是写入人工复核清单。

## 运行方式

在 VulnGym 仓库根目录执行：

```bash
python3 tools/fix_entry_locations.py --workers 4
```

如果只想处理 `verify=0` 的未校验样本：

```bash
python3 tools/fix_entry_locations.py --only-unverified --workers 4
```

如果只处理指定样本：

```bash
python3 tools/fix_entry_locations.py \
  --entry-id entry-00103 \
  --entry-id entry-00320 \
  --entry-id entry-00511 \
  --entry-id entry-00185 \
  --workers 4
```

脚本默认会在终端打印实时进度，例如当前完成的 entry、检查节点数、自动
修改数、进入人工队列数和累计耗时。如果不需要进度输出，可以加：

```bash
python3 tools/fix_entry_locations.py --workers 4 --quiet
```

## 默认输入和输出

默认输入：

- `data/entries.jsonl`
- `repo/{owner}__{repo}` 本地仓库缓存

默认输出目录：

- `outputs/location_fix/`

主要交付物：

- `entries.fixed.jsonl`：修复后的 JSONL 数据文件。
- `fix_diff.csv`：自动修改记录，包含 `entry_id`、节点路径、原始
  `file/line/desc`、新 `file/line/desc` 和修复策略。
- `needs_human.csv`：无法自动确定的节点及原因。
- `logs/*.log`：每个 entry 的详细检查日志。每个样本处理完成后会立即写入
  独立 log 文件。

如需显式指定输出路径：

```bash
python3 tools/fix_entry_locations.py \
  --workers 4 \
  --output outputs/location_fix/entries.fixed.jsonl \
  --diff-csv outputs/location_fix/fix_diff.csv \
  --needs-human-csv outputs/location_fix/needs_human.csv \
  --log-dir outputs/location_fix/logs
```

## 依赖

脚本只依赖 Python 标准库和本地 `git` 命令。

不需要联网，也不会自动 clone 仓库。目标仓库需要已经存在于本地缓存：

```text
repo/{owner}__{repo}
```

例如：

```text
repo/n8n-io__n8n
repo/langflow-ai__langflow
```

每条 entry 会使用自身的 `commit` 字段进行检查。脚本读取源码时使用的是
对应 commit 的快照，而不是当前工作区文件或某个分支的 HEAD。

## 修复策略

脚本以节点的 `code` 字段为主要依据。若原始 `file:line` 无法匹配，会按
以下顺序尝试修复：

1. 在原始文件的原始行号上下 5 行范围内搜索 `code`，唯一命中则修正
   `line`。
2. 在原始文件全文搜索 `code`，唯一命中则修正 `line`。
3. 在整个仓库的对应 commit 快照中搜索 `code`，唯一命中则同时修正
   `file` 和 `line`。

只有唯一且信息量足够的命中结果才会自动写入 `entries.fixed.jsonl`。如果
出现多处命中、完全找不到、仓库缺失、commit 缺失、文件缺失、行号非法或
判断依据不足，节点会写入 `needs_human.csv`。

## 匹配容错

匹配时会做保守的空白归一化：

- 忽略代码片段前后的空白。
- 忽略 tab 和空格差异。
- 忽略连续空白数量差异。
- 支持连续多行代码片段匹配。

多行代码片段会作为连续源码行进行匹配，不会跨越不连续位置拼接。

## desc 处理

`desc` 是自然语言说明，不能像源码一样直接在仓库中匹配。脚本的处理方式是：

- 当节点位置发生自动修复时，如果 `desc` 中出现明确的旧行号、旧文件路径
  或旧文件名，会进行确定性替换。
- 如果文件发生变化，或旧行号引用可能仍然残留，节点会额外写入
  `needs_human.csv`，原因是 `desc_review_required`。
- 脚本不会自动生成新的漏洞链路说明。

## 限制

脚本整体策略偏保守，宁可进入人工复核，也不强行修改。

以下情况不会自动修复：

- `code` 在多个位置命中。
- `code` 完全找不到。
- 本地仓库不存在。
- entry 指定的 commit 不存在。
- 原始文件不存在或文件过大、疑似二进制文件。
- `line` 不是合法的正整数或合法范围。
- `code` 为空或归一化后为空。
- 低信息锚点，例如单独的 `}`、`);`、`)` 等。

## 校验

运行完成后，可以执行基础 schema 校验：

```bash
python3 run_t2_agent.py --validate-only outputs/location_fix/entries.fixed.jsonl
```

脚本不会覆盖 `data/entries.jsonl`，只会写出新的
`outputs/location_fix/entries.fixed.jsonl`。
