# CANDIDATES — entry-00099

对照 Issue #6：无法自动唯一确定时，列出候选位置 + 取舍。

## entry_point

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| E1 | `workflows.controller.ts:539` `@Post('/:workflowId/run')` | 原标注；路由装饰器 | **不选作 entry**（只标记路由，不体现 body 进入）→ 放入 trace |
| E2 | `workflows.controller.ts:541` `async runManually(...)` | 处理函数签名 | 弱于 E3 |
| E3 | `workflows.controller.ts:561-565` `executeManually(req.body, ...)` | 外部 body 进入执行链 | **采用** |

## critical_operation（sink vs 缺陷位点）

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| C1 | `expression-sandboxing.ts` `PrototypeSanitizer` 类/`sanitizer` 定义 | 原标注 | **拒绝**：Issue 明示 RCE critical 不要落在 sanitizer 定义/静态钩子 |
| C2 | `expression-sandboxing.ts:264-279` `visitMemberExpression` | 保护只覆盖 MemberExpression；with 里 Identifier 漏检 | **缺陷位点**，进 trace；不作 critical（仍属 sanitizer 钩子族） |
| C3 | （缺失）`visitWithStatement` | 补丁 `n8n@2.5.1` 新增并直接抛错 | 无法钉到「有代码的行」；在 Tournament 挂载 desc 中说明 |
| C4 | `expression-evaluator-proxy.ts:19-21` `evaluateExpression` | 逃逸后用户表达式真正执行 | **采用**（表现位点 / sink） |
| C5 | Tournament 构造 `new Tournament(... PrototypeSanitizer ...)` | 仅挂钩子 | **拒绝**作 critical |

**争议怎么消**：Issue「真正成立」可读成「保护失效」或「危害发生」。对 RCE，Issue 又禁止 sanitizer 定义当 critical → 选 C4，把 C2/C3 写进 trace + 本表，避免假装只有一个答案。

## 补丁证据

`n8n@2.5.1`：`expression-sandboxing` 增加 `visitWithStatement()` 直接拒绝 `with`。
