# Trace 结构增量回归门禁

`check_trace_regressions.py` 比较一份基线 `entries.jsonl` 与候选数据，只在候选数据引入新的 trace 结构问题时返回失败。

## 为什么需要增量门禁

Issue #5 的全量扫描会发现一批需要人工判断的历史问题。如果直接把全量 finding 数量作为 CI 条件，仓库必须先一次性清零所有历史问题，否则每次数据修改都会失败。

本工具把“清理历史数据”和“阻止新增问题”拆开：

- 基线已有 finding 作为 legacy debt 记录，不阻断候选数据。
- 候选数据新增 finding 时返回退出码 `1`。
- 候选数据解决历史 finding 时记录为 resolved，不阻断。
- 数据或参数无法安全解析时返回退出码 `2`。

它不会修改或重排 trace，也不替代全量清理脚本和人工复核流程。

## 检测范围

- trace 内 `{file, line, code}` 完全相同的重复节点。
- 与 `entry_point` 同文件、且整个行号区间位于入口之前的节点。
- 与 `critical_operation` 同文件、且整个行号区间位于关键操作之后的节点。
- 整数和 `"start-end"` 两种行号格式。

跨文件节点保持原始顺序，不做行号比较。与入口或关键操作边界相交的区间也不会被当作明确越界。

## 稳定比较

每个 finding 使用以下信息生成 SHA-256 指纹：

- `entry_id`
- finding 类型
- 节点的 `file`、`line`、`code`
- 同一 finding 的出现序号

指纹不包含 `trace` 数组索引或 `desc`。因此只修改说明文本、在不改变问题集合的前提下移动数组索引，不会产生假回归；同一节点新增第三次、第四次重复仍会分别被检测。

## 使用方式

比较 Git 分支与当前工作区：

```bash
git fetch upstream main
python scripts/check_trace_regressions.py \
  --base-ref upstream/main \
  --candidate data/entries.jsonl
```

比较两个本地文件并生成机器和人工可读报告：

```bash
python scripts/check_trace_regressions.py \
  --baseline /path/to/base.entries.jsonl \
  --candidate data/entries.jsonl \
  --json-report reports/trace_regression.json \
  --markdown-report reports/trace_regression.md
```

## CI 语义

| 退出码 | 含义 |
| ---: | --- |
| `0` | 没有新增 trace 结构 finding |
| `1` | 候选数据引入了至少一个新 finding |
| `2` | 输入 JSONL、节点字段或行号格式无法安全解析 |

建议 CI checkout 完整历史或显式 fetch 基线分支后，再通过 `--base-ref` 运行门禁。

## 限制

- 重复节点严格遵循 Issue #5 的 `{file, line, code}` 完全相同定义，不做模糊代码匹配。
- 源码行号不等同于运行时调用顺序，本工具不会跨文件排序或推断调用关系。
- 工具只报告结构回归，不自动删除节点，也不判断重复节点在循环或递归语义中是否合理。
