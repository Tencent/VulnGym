## 关联 Issue

Fixes #6

## 做了什么

按 #6 要求，对官方优先的 6 条 n8n 样本重确认 `entry_point` / `critical_operation` / `trace`，对照各 entry 的 vuln commit（并参考修复补丁）。已更新 `data/entries.jsonl` 中这 6 行。`verify` 仍为 `0`。

## 与 #6 交付/验收的对应

| Issue 要求 | 本 PR |
|------------|--------|
| 修正后的 `{file, line, code, desc}` | `data/entries.jsonl`；另有 `tools/semantic_rebuild/out/entries.fixed.jsonl` |
| 每条：原问题、位置、为何选/不选 | 各 `entry-*/DECISION.md`、`CANDIDATES.md` |
| 便于 review 的 diff | `out/semantic_diff.csv` |
| 节点能在对应 commit 源码中对上 | `python tools/semantic_rebuild/run_all.py`（只做行号/code 对齐） |
| entry 体现输入如何进入；critical 非包装/静态/`}` | 见下表 |
| 满足 SCHEMA | 字段形态未改；`verify` 保持 0 |

## 逐条摘要

| entry | 原问题 | 现在 |
|-------|--------|------|
| 00099 | critical 在 PrototypeSanitizer 定义；entry 仅 `@Post` | entry：`executeManually(req.body, …)`；critical：`evaluateExpression`（sanitizer 缺口留在 trace，见 `CRITICAL_RULE.md`） |
| 00100 | critical 在 sanitizer 函数体 | critical 同 00099 |
| 00103 | entry 标在 `}` | entry：`setResponseHeaders`；critical 仍为缺 `trim`（补丁 `553b24458e`） |
| 00176 | critical 在静态 `BLOCKED_ATTRIBUTES = {` | critical：`node.attr in BLOCKED_ATTRIBUTES` |
| 00511 | 「选出 Function」与 `.apply` 易混 | critical：无检查 native 返回 `82-84`；修复 `1acdafe6ac` 在入口拦名字，未改 `.apply` |
| 00512 | entry/desc 偏弱 | entry：`vmEvaluator.evaluate`；critical：可写 `__sanitize`（与修复同行） |

critical 选取规则：`tools/semantic_rebuild/CRITICAL_RULE.md`（优先补丁落点；仅 00099/00100 因 #6 不认可 RCE critical 落 sanitizer 钩子而退到执行出口）。

## 如何检查

```bash
python tools/semantic_rebuild/run_all.py
```

检查格式，以及引用的 `code` 是否与 checkout 一致。**不能**证明语义选择一定正确。

## 说明

- 更细的修复说明：`tools/semantic_rebuild/out/NOTES.md`
- `verify` 故意保持 `0`（见 `VERIFY_POLICY.md`）；若维护者认可，再 bump 即可
