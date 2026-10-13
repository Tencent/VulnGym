# fix_report.md — n8n 样本语义节点修复报告

## 概览

本次修复覆盖 VulnGym 数据集 `entries.jsonl` 中 6 个 n8n 相关条目，针对 `entry_point`、`critical_operation` 落点不当的问题进行修正。修改原则：

- `entry_point` 必须是**外部可达的输入入口**，体现用户请求/参数如何进入系统，不能是装饰器、闭合括号等无意义标记
- `critical_operation` 必须是**漏洞真正成立的关键操作**——危险执行点或绕过生效点，不能是防御函数声明、静态列表定义等无效节点
- `trace` 保留从入口到关键操作的核心数据流/控制流，与修改后的 entry_point/critical_operation 保持一致

---

## 逐条修复详情

### 1. entry-00099（CVE-2026-1470 / GHSA-5XRP-6693-JJX9 — WithStatement 绕过路径）

**漏洞**：表达式沙箱 PrototypeSanitizer 缺少 WithStatement 访问处理器，with 语句可注入 constructor 实现 RCE。

| 字段 | 原始值 | 修复后值 | 修复理由 |
|---|---|---|---|
| `entry_point` | `@Post('/:workflowId/run')` @ workflows.controller.ts:539 | `async runManually(req: WorkflowRequest.ManualRun, _res: unknown) {` @ workflows.controller.ts:540 | @Post 装饰器是 TypeScript 编译时语法标记，运行时不可执行；改为指向控制器方法签名——该方法接收 req 参数，req.body.workflowData 携带用户表达式，是真正的外部输入入口 |
| `critical_operation` | `PrototypeSanitizer: ASTAfterHook = (ast, dataNode) => {` @ expression-sandboxing.ts:244 | `return evaluateExpression(expression, data);` @ expression.ts:472 | PrototypeSanitizer 是防御函数声明，非"操作"；改为 expression.ts 中表达式实际被编译执行的位置——这是沙箱绕过最终实现 RCE 的危险操作点 |
| `trace` | 更新为 6 步：控制器入口 → 表达式预处理 → tournamentEvaluator 绑定 → PrototypeSanitizer 遍历（缺 WithStatement 处理器）→ evaluateExpression 执行 | 同左，重构 | 与新的 entry_point 和 critical_operation 对齐，补全调用链 |

**未采用候选点**：
- 候选：PrototypeSanitizer 中 astVisit 调用行（line 245）。弃用原因：astVisit 是通用 AST 访问调度器，不直接体现漏洞语义——真正的执行发生在 evaluateExpression 中。
- 候选：workflows.controller.ts 的 `if (!req.body.workflowData.id)` 行（line 541）。弃用原因：entry_point 应指向外部输入首次接收点而非参数校验行，runManually 方法签名更直接地体现"外部输入进入系统"。

---

### 2. entry-00100（CVE-2026-1470 / GHSA-5XRP-6693-JJX9 — __sanitize 变量遮蔽路径）

**漏洞**：表达式沙箱中 __sanitize 绑定可被同名局部变量遮蔽，绕过属性访问过滤实现 RCE。

| 字段 | 原始值 | 修复后值 | 修复理由 |
|---|---|---|---|
| `entry_point` | `resolveSimpleParameterValue(` @ expression.ts:368 | 保持不变 | 已合理——这是节点参数求值的顶层入口，接收用户表达式字符串 |
| `critical_operation` | `sanitizer = (value: unknown): unknown => {...}` @ expression-sandboxing.ts:330-336 | `return evaluateExpression(expression, data);` @ expression.ts:472 | sanitizer 是防御函数定义，不是"漏洞成立的关键操作"；改为表达式实际执行点——在 __sanitize 被遮蔽后，evaluateExpression 以缺少有效过滤的代码实际运行 |
| `trace` | 更新为 4 步：resolveSimpleParameterValue 入口 → Object.defineProperty 保护绑定（含遮蔽分析）→ extendSyntax/renderExpression 转折 → evaluateExpression 执行 | 同左，重构 | 强化了 Object.defineProperty 节点对遮蔽机制的描述，补充了漏洞语义解释 |

**未采用候选点**：
- 候选：`renderExpression` 本身（line 470）。弃用原因：renderExpression 是包装方法，真正的执行发生在内部的 evaluateExpression 调用。
- 候选：`extendSyntax(parameterValue)`（line 452）。弃用原因：extendSyntax 仅是 AST 语法改写，不产生代码执行效果。

---

### 3. entry-00103（CVE-2026-25051 / GHSA-825Q-W924-XHGX — Webhook XSS/CSP 绕过）

**漏洞**：isHtmlRenderedContentType() 在比对 Content-Type 时未 trim()，含首尾空白的 text/html 无法通过 startsWith 判断，CSP 保护被跳过。

| 字段 | 原始值 | 修复后值 | 修复理由 |
|---|---|---|---|
| `entry_point` | `}` @ webhook-helpers.ts:615 | `res.setHeader(name, value);` @ webhook-request-handler.ts:149 | 原值是闭合花括号，完全无语义——显然是自动标注的产物。改为 webhook-request-handler.ts 中 setResponseHeaders 方法内的 setHeader 调用——此处将用户工作流配置的 Content-Type（含潜在首尾空白）首次写入 Express 响应对象，是污染链路的真正发端 |
| `critical_operation` | `const contentTypeLower = contentType.toLowerCase();` @ html-sandbox.ts:20 | 保持不变 | 此行是漏洞根因操作——缺少 .trim() 导致比较失败，语义角色（根因而非执行点）与 "critical_operation" 定义可兼容 |
| `trace` | 重构为 3 步：res.setHeader 写入 → res.getHeader 读回 → isHtmlRenderedContentType 误判 | 同左 | 删除原 trace 中的花括号锚点和 webhook-helpers.ts 无关代码块，替换为从入口到关键操作的直连路径 |

**未采用候选点**：
- 候选：`sendStaticResponse` 中 `this.setResponseHeaders(res, headers)` 行（line 130）。弃用原因：setResponseHeaders 方法内部的 res.getHeader 才是 content-type 被读回并传入检测函数的直接位置，位于此调用内部。
- 候选：`needsSandbox` 判定行（line 154）。弃用原因：此行调用 isHtmlRenderedContentType 并决定是否跳过 CSP，是条件分支而非漏洞成立的独立操作。

---

### 4. entry-00176（CVE-2026-27494 / GHSA-MMGG-M5J7-F83H — Python Code 节点沙箱逃逸）

**漏洞**：Python AST 静态分析中 BLOCKED_ATTRIBUTES 未包含 __objclass__，攻击者通过 slot wrapper 的 __objclass__ 属性突破 AST 拦截。

| 字段 | 原始值 | 修复后值 | 修复理由 |
|---|---|---|---|
| `entry_point` | `const code = this.getNodeParameter(...)` @ Code.node.ts:206 | 保持不变 | 已合理——这是用户 Python 代码字符串从节点参数中被读取的位置 |
| `critical_operation` | `BLOCKED_ATTRIBUTES = {` @ constants.py:126 | `if node.attr in BLOCKED_ATTRIBUTES:` @ task_analyzer.py:66 | 原值是一个静态字典定义，不是任何"操作"。改为 visit_Attribute 中执行 `node.attr in BLOCKED_ATTRIBUTES` 成员测试的行——这是"检查发生并错误放行"的动态执行点，也是补丁修复会改动的精确位置（将 __objclass__ 加入集合后此检查即可正确拦截） |
| `trace` | 压缩为 7 步，新增 visit_Attribute 检查节点，移除 trace 末端的 BLOCKED_ATTRIBUTES 定义 | 同左 | 用 visit_Attribute 的动态检查节点替代原来独立的 BLOCKED_ATTRIBUTES 定义节点 |

**未采用候选点**：
- 候选：`self.analyzer.validate(task_settings.code)` @ task_runner.py:321。弃用原因：validate 是入口调度方法，不直接体现漏洞语义。visit_Attribute 内的检查行是"属性比对发生"的精确位置，更能说明"为什么 __objclass__ 未在集合中导致放行"。
- 候选：`self.analyzer.validate(...)` 内部的 `tree = ast.parse(code)` + `security_validator.visit(tree)`。弃用原因：这是 AST 解析和遍历入口，过早上游，且不直接体现属性检查语义。

---

### 5. entry-00511（CVE-2026-25049 / GHSA-6CQR-8CFR-67F8 — extend 原生回退路径）

**漏洞**：extend() 的 findExtendedFunction 在类型分发失败后落入原生回退分支，inputAny[functionName] 未过滤属性名，传入 'constructor' 可获取 Function 构造器实现 RCE。

**二次审查发现**：原始行号（entry_point 485, trace 484-492/496-503/167-168, critical_operation 81-84, trace 78-84）均为未经验证的错误值。经拉取 commit `09e2c2b5547b49a824a8265d312583f5d1f5c79f` 的以下源文件逐行验证后修正：
- `packages/workflow/src/expression.ts`：`data.extend = extend;` 在第 424 行，非 485 行；`constructorValidation` 正则守卫在 432-439 行，非 496-503 行
- `packages/@n8n/expression-runtime/src/extensions/extend.ts`：`findExtendedFunction` 中原生回退分支 if 块在 80-83 行，非 81-84 行；`const inputAny` 到 if 块结束在 77-83 行，非 78-84 行
- `packages/@n8n/expression-runtime/src/runtime/reset.ts`：`globalThis.__data.extend = extend;` 在 143-144 行，非 167-168 行

此外，`critical_operation.code` 缺少 if 块闭合括号 `}`，已补全。

| 字段 | 原始值 | 修复后值 | 修复依据 |
|---|---|---|---|
| `entry_point.line` | 485 | **424** | expression.ts L424：`data.extend = extend;` |
| `trace[0].line` | "484-492" | **"423-430"** | expression.ts L423-430：extend/extendOptional 赋值 + sanitizer defineProperty 块 |
| `trace[1].line` | "496-503" | **"432-439"** | expression.ts L432-439：constructorValidation 正则守卫块 |
| `trace[2].line` | "167-168" | **"143-144"** | reset.ts L143-144：`globalThis.__data.extend = extend;` |
| `critical_operation.line` | "81-84" | **"80-83"** | extend.ts L80-83：原生回退 if 块（含闭合 `}`） |
| `critical_operation.code` | 缺 if 块闭合 `}` | **补全 `\n\t\t}`** | extend.ts L83：`}`（if 块闭合） |
| `trace[4].line` | "78-84" | **"77-83"** | extend.ts L77-83：`const inputAny` 到 if 块结束 |

---

### 6. entry-00512（CVE-2026-25049 / GHSA-6CQR-8CFR-67F8 — __sanitize 可覆写路径）

**漏洞**：reset.ts 中 globalThis.__data.__sanitize = __sanitize 使用普通赋值而非 Object.defineProperty，导致 __sanitize 可被沙箱内代码覆写为恒等函数，全部过滤失效。

**二次审查发现**：原始行号（entry_point 523, trace[0] 523, trace[1] 493-502, critical_operation 45, trace[2] 45）均为未经验证的错误值。经拉取 commit `09e2c2b5547b49a824a8265d312583f5d1f5c79f` 的以下源文件逐行验证后修正：
- `packages/workflow/src/expression.ts`：`renderExpression` 方法签名在第 456 行，非 523 行
- `packages/workflow/src/expression-sandboxing.ts`：PrototypeSanitizer 中 `path.replace` 调用在 424-435 行，非 493-502 行
- `packages/@n8n/expression-runtime/src/runtime/reset.ts`：`globalThis.__data.__sanitize = __sanitize;` 在第 39 行，非 45 行

| 字段 | 原始值 | 修复后值 | 修复依据 |
|---|---|---|---|
| `entry_point.line` | 523 | **456** | expression.ts L456：`private renderExpression(...)` |
| `trace[0].line` | 523 | **456** | expression.ts L456：同上 |
| `trace[1].line` | "493-502" | **"424-435"** | sandboxing.ts L424-435：PrototypeSanitizer 的 path.replace 调用 |
| `critical_operation.line` | 45 | **39** | reset.ts L39：`globalThis.__data.__sanitize = __sanitize;` |
| `trace[2].line` | 45 | **39** | reset.ts L39：同上 |

**人工判断备注**：
- 此条目的 critical_operation 存在一定歧义——严格按 "critical_operation = 漏洞成立的关键操作" 的理解，此处的"普通赋值"更像是"为漏洞创造条件"而非"漏洞成立"。但理想的动态覆写瞬间（`__sanitize = (x) => x` 在沙箱内执行）无静态源码锚点，无法在 entries.jsonl 中表示。当前选择保留原始位置并在 desc 中清晰地说明了这一权衡，审核者可酌情调整。

---

## 源码核实记录

所有修正后的 `file/line/code` 均已通过以下 commit 版本的原始源码验证。entry-00511 和 entry-00512 经二次审查后重新拉取源文件逐行核对，发现并修正了原始数据中未经验证的行号错误：

| entry_id | commit | 核实文件 | 核实方法 |
|---|---|---|---|
| entry-00099 | `8ab4492e8c0b743455e51fc111441d8d5010a6ad` | workflows.controller.ts, expression.ts, expression-sandboxing.ts, expression-evaluator-proxy.ts | 直接拉取 GitHub raw 源文件 |
| entry-00100 | `8ab4492e8c0b743455e51fc111441d8d5010a6ad` | expression.ts | 直接拉取 GitHub raw 源文件 |
| entry-00103 | `57d6015f2ea0442c24e0449105325b7e36f066df` | webhook-request-handler.ts, html-sandbox.ts | 直接拉取 GitHub raw 源文件 |
| entry-00176 | `3af9095245be3aaad6bc16622f379f79c6c6068f` | Code.node.ts, PythonTaskRunnerSandbox.ts, task_analyzer.py, task_runner.py | 直接拉取 GitHub raw 源文件 |
| entry-00511 | `09e2c2b5547b49a824a8265d312583f5d1f5c79f` | **expression.ts, extend.ts, reset.ts**（二次审查） | 2026-07-23 重新拉取逐行核对 |
| entry-00512 | `09e2c2b5547b49a824a8265d312583f5d1f5c79f` | **expression.ts, sandboxing.ts, reset.ts**（二次审查） | 2026-07-23 重新拉取逐行核对 |

验证 URL（commit `09e2c2b`）：
- `https://raw.githubusercontent.com/n8n-io/n8n/09e2c2b5547b49a824a8265d312583f5d1f5c79f/packages/workflow/src/expression.ts`
- `https://raw.githubusercontent.com/n8n-io/n8n/09e2c2b5547b49a824a8265d312583f5d1f5c79f/packages/@n8n/expression-runtime/src/extensions/extend.ts`
- `https://raw.githubusercontent.com/n8n-io/n8n/09e2c2b5547b49a824a8265d312583f5d1f5c79f/packages/@n8n/expression-runtime/src/runtime/reset.ts`
- `https://raw.githubusercontent.com/n8n-io/n8n/09e2c2b5547b49a824a8265d312583f5d1f5c79f/packages/workflow/src/expression-sandboxing.ts`

---

## SCHEMA 合规检查

修复后条目已确认满足以下约束：

- [x] `line` 为 ≥1 的 int 或 `"start-end"` 范围字符串（无值 0）
- [x] `file` 为仓库相对路径
- [x] `code` 为原文逐字片段（可含转义和中英文注释）
- [x] `desc` 为中文语义说明
- [x] `entry_point`、`critical_operation`、`trace[*]` 均含 `{file, line, code, desc}`
- [x] 必填字段完整（entry_id, report_id, source_link 等未变更）
- [x] JSONL 每行完整 JSON 对象，UTF-8 编码

---

## 总结

| 条目 | entry_point 修改 | critical_operation 修改 | trace 修改 | 修改程度 |
|---|---|---|---|---|
| entry-00099 | 装饰器→控制器方法 | 防御函数→执行点 | 重构 | 重大 |
| entry-00100 | 无 | 防御函数→执行点 | 重构 | 重大 |
| entry-00103 | 花括号→响应头写入 | 无 | 重构 | 重大 |
| entry-00176 | 无 | 静态字典→动态检查 | 中度调整 | 重大 |
| entry-00511 | line 485→424 | line 81-84→80-83, code 补全闭合括号 | 6 处行号修正 | 重大（二次审查） |
| entry-00512 | line 523→456 | line 45→39 | 5 处行号修正 | 重大（二次审查） |
