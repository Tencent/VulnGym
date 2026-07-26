# Entry 节点位置自动修复

`scripts/fix_entry_locations.py` 根据节点的 `code` 检查并保守修复
`entry_point`、`critical_operation` 和 `trace[*]` 的文件及行号。

## 运行方式

从仓库根目录执行完整检查：

```bash
python3 scripts/fix_entry_locations.py
```

默认生成：

- `entries.fixed.jsonl`：保留全部 entry，只修改唯一确定的节点；
- `fix_diff.csv`：自动修改前后的字段和采用的策略；
- `needs_human.csv`：多处命中、找不到或源码不可用的节点；
- `.cache/vulngym-source/`：按仓库复用的 Git 源码缓存。

只检查未验证数据或指定样本：

```bash
python3 scripts/fix_entry_locations.py --only-unverified
python3 scripts/fix_entry_locations.py --entry-id entry-00103 --entry-id entry-00320
```

已有完整缓存时可使用 `--offline`，确保运行期间不访问网络。其他路径可通过
`--input`、`--output`、`--diff`、`--needs-human` 和 `--cache-dir` 修改。

## 修复策略

脚本先将每行代码去除首尾空白并折叠连续空白，从而容忍缩进及 tab/空格差异，
同时按连续的非空代码行匹配多行片段。匹配失败后依次尝试：

1. 原行号上下 5 行内唯一命中；
2. 原文件内唯一命中；
3. 整个 commit 中唯一命中。

只有唯一命中才会修改。路径或行号变化后，脚本会同步更新 `desc` 中明确出现的
旧路径和行号引用。所有修改写入 `fix_diff.csv`。

多处命中、完全找不到、代码过短而无法安全搜索、候选范围过大或源码获取失败时，
节点保持原样并写入 `needs_human.csv`。

## 限制

- 脚本只修复位置以及 `desc` 中明确的旧位置引用，不自动重写漏洞语义；
- 极短片段（例如单独的 `}`）通常无法支持可靠的跨仓库定位；
- 首次运行需要下载目标 commit，速度取决于网络和仓库大小；后续运行会复用缓存；
- `needs_human.csv` 中的结果必须由人工结合漏洞上下文判断。
