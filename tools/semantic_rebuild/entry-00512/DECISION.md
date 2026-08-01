# entry-00512

## 采用

- entry_point：`expression.ts:534-536` `vmEvaluator.evaluate(...)`（相对原方法头更能体现 VM 入口）
- critical：`reset.ts:46` 可写 `__sanitize`（位置原正确）
- verify：0

## 不采用

- 方法签名 `renderExpression {` 单独作 entry
- 把 critical 改成 PrototypeSanitizer 改写点或其它执行 sink——本条讲过滤被废掉
- trace 与 entry/critical 完全重复同一节点

候选表见 `CANDIDATES.md`。
