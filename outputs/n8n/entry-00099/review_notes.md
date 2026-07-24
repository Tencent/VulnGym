# entry-00099 修复说明

## 基本信息

- `entry_id`: `entry-00099`
- 项目：`n8n`
- Advisory：`GHSA-5XRP-6693-JJX9`
- 漏洞类型：Workflow Expression Sandbox Escape leading to RCE
- vulnerable commit：`8ab4492e8c0b743455e51fc111441d8d5010a6ad`
- fix commit：`aa4d1e5825829182afa0ad5b81f602638f55fa04`

本条样本的原标注将 `critical_operation` 放在 `PrototypeSanitizer` 定义处。经复核，该位置应被视为 sandbox 防护失败点和补丁修复点，而不是用户控制的 workflow expression 被实际求值执行的位置。因此，本次修复将 `critical_operation` 调整到表达式进入 Tournament evaluator 执行流程的调用点，并同步补齐 trace 末端的运行时调用链。trace 仅保留用户输入进入、表达式识别、表达式渲染/求值委派等关键数据流或控制流节点，删除 sanitizer 定义和 evaluator 静态配置这类不属于运行时流转的节点。

## 原问题

原始 `critical_operation` 为：

`packages/workflow/src/expression-sandboxing.ts:244`

```ts
export const PrototypeSanitizer: ASTAfterHook = (ast, dataNode) => {
```

该节点确实与漏洞根因相关。fix commit 在 `PrototypeSanitizer` 中新增了对 `with` 语句和保留变量遮蔽的检测，说明漏洞成因包括 sandbox sanitizer 覆盖不完整，导致恶意 expression 可以绕过属性访问限制。

但从语义标注角度看，`PrototypeSanitizer` 是防护逻辑本身，不是 RCE / 沙箱逃逸链路中的实际执行点。该函数的职责是在编译阶段遍历 AST 并尝试阻断危险语法；漏洞成立的最终条件是绕过这些检查后的 workflow expression 被表达式引擎求值。因此，将 `critical_operation` 标注在 sanitizer 定义处会把“防护失败位置”和“安全关键执行位置”混为一谈，不符合本条样本的 RCE sink 语义。

原 trace 也存在同类问题：trace 末端停在 `PrototypeSanitizer`，只能说明防护缺陷存在，未体现恶意表达式从参数解析继续进入 `renderExpression`、`evaluateExpression` 并最终调用 evaluator 的执行路径。

## 修复位置

修复后的 `critical_operation` 为：

`packages/workflow/src/expression-evaluator-proxy.ts:20`

```ts
	return evaluator(expr, data);
```

该位置是 `evaluateExpression` 对外暴露的统一求值代理中实际调用 evaluator 的语句。`evaluator` 在同文件第 13 行通过如下代码绑定到 `Tournament.execute`：

```ts
const evaluator: Evaluator = tournamentEvaluator.execute.bind(tournamentEvaluator);
```

因此，`return evaluator(expr, data);` 是本仓库源码中将 workflow expression 和数据上下文交给 Tournament expression engine 的直接调用点。对于本漏洞而言，绕过不完整 sandbox checks 的恶意 expression 会在该调用进入求值流程，并进一步触发沙箱逃逸 / RCE 影响。

## 选择该位置的理由

选择 `packages/workflow/src/expression-evaluator-proxy.ts:20` 作为 `critical_operation`，主要依据如下：

1. 该位置是实际求值调用点，而不是配置、包装或静态声明。`evaluateExpression(expr, data)` 收到上游传入的 expression 后，在此处调用已绑定到 `Tournament.execute` 的 evaluator。
2. 该位置与漏洞影响直接相关。漏洞利用链要求用户控制的 workflow expression 在 sandbox 检查未能完整阻断的情况下被执行；`return evaluator(expr, data);` 正是表达式进入执行引擎的关键边界。
3. 该位置能够与 trace 末端自然对齐。修复后的 trace 从 HTTP workflow 执行入口出发，经过表达式识别、语法转换、`renderExpression`、`evaluateExpression`，最终落到该 evaluator 调用点。
4. 该位置在 vulnerable commit 中可稳定定位。已确认本地仓库 HEAD 为 `8ab4492e8c0b743455e51fc111441d8d5010a6ad`，且 `packages/workflow/src/expression-evaluator-proxy.ts:20` 的代码与修复后标注完全匹配。

## Trace 修复说明

修复后的 trace 保留外部输入进入点，并补齐原 trace 缺失的表达式求值桥接路径。为满足“保留关键数据流或控制流节点，删除明显无关节点”的要求，未将 `new Tournament(...)` 配置语句或 `const evaluator = tournamentEvaluator.execute.bind(...)` 绑定声明作为 trace 节点；这些信息只在说明中用于解释最终 evaluator 的来源。

1. `packages/cli/src/workflows/workflows.controller.ts:539`
   `@Post('/:workflowId/run')` 暴露手动执行 workflow 的 HTTP POST 入口。请求体中的 `workflowData.nodes.parameters` 可携带用户配置的表达式字符串，是外部可控 workflow expression 进入后端执行链路的位置。
2. `packages/workflow/src/expression.ts:384-393`
   `resolveSimpleParameterValue` 识别以 `=` 开头的节点参数为 expression，并剥离前缀 `=`。该步骤只做格式识别和预处理，不会阻断 `with` 语句等恶意语法。
3. `packages/workflow/src/expression.ts:451-453`
   预处理后的 expression 经 `extendSyntax(parameterValue)` 转换后传入 `this.renderExpression(extendedExpression, data)`。该节点是从参数解析阶段进入表达式渲染 / 求值阶段的关键调用桥。
4. `packages/workflow/src/expression.ts:470-472`
   `renderExpression` 调用 `evaluateExpression(expression, data)`，将 expression 和 `WorkflowDataProxy` 数据上下文继续传入统一求值代理。
5. `packages/workflow/src/expression-evaluator-proxy.ts:20`
   `return evaluator(expr, data);` 调用绑定到 `Tournament.execute` 的 evaluator 对 workflow expression 求值。该节点与新的 `critical_operation` 对齐，是 trace 的最终安全关键节点。

## 未采用候选点的原因

- `packages/workflow/src/expression-sandboxing.ts:244` 的 `PrototypeSanitizer`
  该位置是 sandbox 防护失败点，也是 fix commit 的主要修复位置之一，但它不是用户 expression 被执行的位置。将其作为 trace 末端会停留在防护逻辑层面，无法表达 RCE / 沙箱逃逸最终通过 evaluator 求值触发。
- `packages/workflow/src/expression-evaluator-proxy.ts:9-12` 的 `new Tournament(...)`
  该位置负责构造 Tournament 实例并注册 `ThisSanitizer`、`PrototypeSanitizer`、`DollarSignValidator` 等 hooks。它是表达式求值管道的配置点，不是运行时处理某个用户 expression 的执行点，因此不适合作为 `critical_operation`。
- `packages/workflow/src/expression-evaluator-proxy.ts:13` 的 evaluator 绑定
  该位置说明 `evaluator` 指向 `Tournament.execute`，对解释最终调用点的语义有价值，因此在修复说明和 `critical_operation.desc` 中提及。但它只是函数绑定声明，不会实际执行 expression；为避免 trace 混入静态配置节点，本次未将其保留为 trace 节点，也不作为 `critical_operation`。
- `packages/workflow/src/expression.ts:451-453` 和 `packages/workflow/src/expression.ts:470-472`
  这些位置分别调用 `renderExpression` 和 `evaluateExpression`，是从参数解析进入求值代理的必要中间节点，因此应保留在 trace 中。但最终将 expression 交给 Tournament evaluator 的调用发生在 `expression-evaluator-proxy.ts:20`，所以这些节点不作为最终 `critical_operation`。
