# entry-00100 修复说明

## 基本信息

- `entry_id`: `entry-00100`
- 项目：`n8n`
- Advisory：`GHSA-5XRP-6693-JJX9`
- 漏洞类型：Workflow Expression Sandbox Escape leading to RCE
- vulnerable commit：`8ab4492e8c0b743455e51fc111441d8d5010a6ad`
- fix commit：`aa4d1e5825829182afa0ad5b81f602638f55fa04`

本条样本的 `entry_point` 已按任务要求保留在 `packages/workflow/src/expression.ts:368`。该位置是节点参数求值方法 `resolveSimpleParameterValue`，接收用户在 workflow 节点参数中配置的 `parameterValue`，能体现用户控制的表达式进入求值链路。

原始 `critical_operation` 标在 `sanitizer` 函数定义处。经复核，`sanitizer` 是动态属性访问的防护函数，不是恶意 expression 被执行的位置。CVE-2026-1470 的补丁确实修改了 `PrototypeSanitizer`，新增对 `with` 语句和 `__sanitize` / `___n8n_data` 保留变量遮蔽的阻断，但这些属于 sandbox 防护缺口；漏洞最终成立的位置仍是绕过检查后的 expression 被 Tournament evaluator 求值。因此本次将 `critical_operation` 收窄到 `packages/workflow/src/expression-evaluator-proxy.ts:20` 的实际 evaluator 调用。

## 原问题

原始 `critical_operation` 为：

`packages/workflow/src/expression-sandboxing.ts:330-336`

```ts
export const sanitizer = (value: unknown): unknown => {
	const propertyKey = String(value);
	if (!isSafeObjectProperty(propertyKey)) {
		throw new ExpressionError(`Cannot access "${propertyKey}" due to security concerns`);
	}
	return propertyKey;
};
```

该函数负责在动态属性访问被 AST 改写后检查属性名是否安全。它与漏洞背景相关，但语义上是防线函数，不是 RCE sink。把它标为 `critical_operation` 会把“本应阻断攻击的防护函数”和“恶意表达式最终被执行的位置”混在一起。

原 trace 也存在类似问题：包含 `sanitizerName = '__sanitize'` 静态常量、`Object.defineProperty(data, sanitizerName, ...)` 防护装配和重复的 `sanitizer` 定义。这些节点能解释防护机制，但不能构成从用户表达式到执行点的精炼数据流/控制流链路。

## 修复位置

修复后的 `critical_operation` 为：

`packages/workflow/src/expression-evaluator-proxy.ts:20`

```ts
	return evaluator(expr, data);
```

`evaluator` 在同文件中由 `tournamentEvaluator.execute.bind(tournamentEvaluator)` 得到，因此该语句是将 expression 和 data 上下文交给 Tournament 表达式引擎执行的直接调用点。对于本漏洞，`with` 语句和保留变量遮蔽绕过未被漏洞版本的 sandbox hooks 拒绝后，恶意 expression 会在这里进入最终求值流程并造成沙箱逃逸/RCE。

## 选择该位置的理由

1. 该位置是实际执行调用点，而不是防护函数、静态声明、日志或初始化配置。
2. 该位置与漏洞影响直接相关：漏洞要求用户控制的 workflow expression 在 sandbox 检查不完整时仍被求值。
3. 该位置在 vulnerable commit 中可稳定匹配，源码为 `return evaluator(expr, data);`。
4. trace 末端可以自然对齐到该节点，便于人工复核从 `parameterValue` 到最终 evaluator 调用的链路。

## Trace 修复说明

修复后的 trace 保留 7 个关键节点，顺序为 `parameterValue` 进入后一路到 `evaluateExpression`，再标明 evaluator 内部会依赖但未充分覆盖的 `PrototypeSanitizer` 缺口，最后落到实际求值调用：

1. `packages/workflow/src/expression.ts:368-377`
   `parameterValue` 作为节点参数表达式进入 `resolveSimpleParameterValue`。
2. `packages/workflow/src/expression.ts:393`
   去掉表达式前缀 `=`，用户控制的表达式主体继续传递。
3. `packages/workflow/src/expression.ts:442-449`
   仅用正则拦截显式 `.constructor`，无法覆盖 `with` 作用域解析和动态属性组合等绕过。
4. `packages/workflow/src/expression.ts:452-453`
   表达式经过 `extendSyntax` 后进入 `renderExpression`。
5. `packages/workflow/src/expression.ts:472`
   `renderExpression` 调用 `evaluateExpression(expression, data)`。
6. `packages/workflow/src/expression-sandboxing.ts:244-245`
   `PrototypeSanitizer` 是 evaluator 内部使用的 AST hook 入口；漏洞版本缺少 `WithStatement` 和保留变量遮蔽检查。
7. `packages/workflow/src/expression-evaluator-proxy.ts:20`
   `evaluateExpression` 调用绑定到 `Tournament.execute` 的 evaluator，和新的 `critical_operation` 对齐。

## 未采用候选点的原因

- `packages/workflow/src/expression-sandboxing.ts:330-336` 的 `sanitizer`
  这是运行时防护函数定义，不是恶意 expression 被执行的位置，因此不适合作为 `critical_operation`，也不保留为 trace 末端。
- `packages/workflow/src/expression-sandboxing.ts:11-12` 的 `sanitizerName`
  这是静态常量声明，只说明内部保留变量名称，不是关键数据流或控制流节点。
- `packages/workflow/src/expression.ts:434-438` 的 `Object.defineProperty(data, sanitizerName, ...)`
  这是防护装配上下文，和 reserved variable shadowing 背景有关，但不是必要链路节点；为保持 trace 精炼，本次删除。
- `packages/workflow/src/expression-evaluator-proxy.ts:9-13` 的 Tournament 初始化和 evaluator 绑定
  该位置解释 evaluator 来源，但属于静态配置/绑定，不是某个用户 expression 的运行时处理节点；已在说明中解释，不放入 trace。
