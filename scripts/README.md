# 代码定位修复工具

## 功能

修复 `data/entries.jsonl` 中 entry_point、critical_operation、trace[*] 节点的
file/line 定位偏差。以 code 字段为依据，在对应仓库的对应 commit 源码中
搜索匹配位置，只在唯一匹配时自动修复。

## 运行方式

```bash
# 修复全部 entries（默认读取 data/entries.jsonl）
python3 scripts/fix_entries.py

# 指定输入文件（用于幂等性验证）
python3 scripts/fix_entries.py --input data/entries.fixed.jsonl
```

依赖：Python 3.8+、git 命令行工具

## 修复策略

按以下顺序依次尝试，只有唯一匹配才自动修复：

1. **原位检查**：在原始 file/line 处验证 code 是否匹配
2. **±5行搜索**（`nearby_unique`）：在原始行号上下5行范围搜索
3. **原文件搜索**（`same_file_unique`）：在原始文件全文搜索
4. **全仓库搜索**（`repo_unique`）：在整个仓库搜索，同时修正 file 和 line

匹配时做以下容错处理：
- 统一 tab 为4空格
- 去除行尾空白
- 去除 `//` 或 `#` 后的中文注释
- 支持多行代码片段（搜索范围自动扩展以容纳多行代码）

多处命中、完全找不到、或代码片段太短无法唯一确定时，写入 `needs_human.csv`
交由人工复核，不强行修改。

## 输出文件

| 文件 | 说明 |
|------|------|
| `data/entries.fixed.jsonl` | 修复后的数据文件 |
| `reports/fix_diff.csv` | 每处修改的对比记录（entry_id、节点、新旧file/line/desc、策略） |
| `reports/needs_human.csv` | 人工复核清单（entry_id、节点、原因、file、line、code） |

## 幂等性验证

对修复后的文件重新运行脚本，应产生 0 个新修复：

```bash
python3 scripts/fix_entries.py --input data/entries.fixed.jsonl
```

## 测试

```bash
python3 -m unittest tests.test_fix_entries -v
```

## 限制

- 需要网络访问 GitHub（首次 clone 仓库时）
- 仓库缓存在 `.cache/repos/` 下，重复运行不会重新 clone
- 代码片段去空白后不足10字符或含省略号时，如果全仓库有多个匹配，
  会被标记为 `low_information_multiple`，建议人工确认
- commit 不存在或 fetch 超时（60秒）的组会跳过，写入 `needs_human.csv`