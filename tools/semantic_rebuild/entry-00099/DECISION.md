# entry-00099

## 采用

- entry_point：`workflows.controller.ts:561-565` `executeManually(req.body, ...)`（相对原 `@Post` 更能体现输入进入）
- critical：`expression-evaluator-proxy.ts:19-21` `evaluateExpression`
- verify：0

## 不采用（详见 CANDIDATES.md）

- `@Post` 单独作 entry：只是路由标记 → 降到 trace
- `PrototypeSanitizer` 定义：Issue 不认可 RCE critical 落 sanitizer
- `visitMemberExpression` 作 critical：缺陷位点，但仍属 sanitizer 钩子族 → trace
- Tournament 构造：只挂钩子

## sink vs 缺陷

按 `CRITICAL_RULE.md` 步 3–4：补丁在 sanitizer，但 Issue 禁 RCE critical 落 sanitizer 钩子 → critical 降级为 `evaluateExpression`；缺口留 trace。
