# VulnGym 代码片段定位修复

`scripts/fix_code_locations.py` 会检查 `data/entries.jsonl` 中每个
`entry_point`、`critical_operation` 和 `trace[*]` 节点，并以 `code` 为依据修复
错误的 `file` 或 `line`。脚本只接受唯一匹配，无法确定的节点会进入人工复核清单。

## 环境与依赖

- Python 3.9 或更高版本
- Git
- 可访问 GitHub 的网络（首次运行需要下载样本对应 commit）
- 不依赖第三方 Python 包

## 运行

在 VulnGym 仓库根目录执行：

```bash
python3 scripts/fix_code_locations.py --verbose
```

脚本默认读取 `data/entries.jsonl`，并在仓库根目录生成：

- `entries.fixed.jsonl`：修复后的完整数据集
- `fix_diff.csv`：每处自动修改的前后值和修复策略
- `needs_human.csv`：多处命中、找不到或源码不可用的节点

若数据文件不在默认位置，可显式指定：

```bash
python3 scripts/fix_code_locations.py \
  --entries entries.jsonl \
  --output entries.fixed.jsonl \
  --diff fix_diff.csv \
  --needs-human needs_human.csv \
  --verbose
```

只检查 issue 建议优先关注的 `verify=0` 样本：

```bash
python3 scripts/fix_code_locations.py --only-verify-zero --verbose
```

复用已有源码缓存且禁止联网：

```bash
python3 scripts/fix_code_locations.py --no-clone --verbose
```

成功运行后会打印类似结果：

```text
processed_entries=408
automatic_fixes=3
needs_human=0
```

## 修复策略

脚本先验证原位置，失败后按以下顺序搜索：

1. 原行号上下 5 行；
2. 原文件全文；
3. 整个仓库。

每一步都只有在 `code` 唯一命中时才修改。匹配会忽略每行前后空白以及 tab/空格差异，
支持多行代码和 `"start-end"` 行号范围。仓库按 `repo_url + commit` 缓存在
`.cache/repos/`，避免重复下载。

位置变化后，脚本会检查 `desc`：仅行号变化时，代码语义未变，因此保留原描述；文件变化时，
会同步替换描述中明确出现的旧路径或旧文件名。无法可靠判断的语义内容不会猜测修改。

## 校验与限制

输出前会检查 `SCHEMA.md` 中与 entries 相关的基础约束，包括 `entry_id` 顺序、commit、
repo URL、`verify`、节点必需字段和行号格式。校验失败时脚本会停止，不写出无效结果。

脚本会跳过 `.git`、`node_modules`、`dist`、`build`、`target` 和常见二进制文件。
多处命中、完全找不到、仓库下载失败或字段异常时不会强行修改，而是写入
`needs_human.csv`。
