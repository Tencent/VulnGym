# #6 修复说明（优先 6 条 n8n）

规则：`CRITICAL_RULE.md`。`verify` 策略：`VERIFY_POLICY.md`（保持 0）。

主数据：`data/entries.jsonl` 已更新。Review 用 diff：`out/semantic_diff.csv`。

`run_all.py` 只检查 `{file,line,code}` 与 vuln commit 一致，不验证语义对错。

## 逐条

### entry-00099

- 原问题：critical 在 PrototypeSanitizer 定义；entry 只有 `@Post`。
- 修改：entry → `executeManually(req.body, …)`；critical → `evaluateExpression`。
- 不选：sanitizer 类/钩子作 RCE critical（#6）；Tournament 构造。
- 补丁：`n8n@2.5.1` 增加 `visitWithStatement`（vuln 没有 → 写在 trace）。

### entry-00100

- 原问题：critical 在 sanitizer 函数体。
- 修改：critical 同 00099；entry 仍为 `resolveSimpleParameterValue`。
- trace 含只覆盖 MemberExpression 的缺口。

### entry-00103

- 原问题：entry 标在 `}`。
- 修改：entry → `setResponseHeaders`；critical 仍为未 `trim` 的 `toLowerCase`。
- 补丁：`553b24458e` → `trim().toLowerCase()`。
- trace 用 `sendStaticResponse` 调用点，避免与 entry 整段重复。

### entry-00176

- 原问题：critical 在静态 `BLOCKED_ATTRIBUTES = {`。
- 修改：critical → `visit_Attribute` 里的成员判断。
- 不选：静态集合作 critical；把 builtin `getattr` 当本 CVE 的 critical（修复补的是 `__objclass__`）。

### entry-00511

- 原问题：原文停在选出 `input[functionName]`；中间一度改到 `.apply`。
- 修改：critical 回到无检查 native 返回（`82-84`）；`.apply` 留在 trace。
- 补丁：`1acdafe6ac` 在 `findExtendedFunction` 入口加 `UNSAFE_PROPERTY_NAMES`（未改 `.apply`）。

### entry-00512

- 原问题：critical 行大致对，entry/desc/trace 偏弱。
- 修改：entry → `vmEvaluator.evaluate`；critical 仍为可写 `__sanitize`。
- 补丁：同一修复提交用 `defineProperty` 锁住该槽位。

## 候选与补丁

各 `entry-*/` 下有 `CANDIDATES.md`、`PATCH_NOTES.md`，对应 #6「理由 + 未采用候选」。
