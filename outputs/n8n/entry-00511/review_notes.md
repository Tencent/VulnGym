# entry-00511 修复说明

## 基本信息

- `entry_id`: `entry-00511`
- 项目：`n8n`
- Advisory：`GHSA-6CQR-8CFR-67F8`
- 漏洞类型：n8n VM 表达式引擎沙箱逃逸导致 RCE
- vulnerable commit：`09e2c2b5547b49a824a8265d312583f5d1f5c79f`
- 关键补丁参考：`1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6`、`cf602ef71c5e3f25a6c507bf8c343ec29d612993`

GHSA 公告说明，具备创建或修改 workflow 权限的认证用户可通过 workflow 参数中的 crafted expressions 触发宿主命令执行。源码复核显示，`extend.ts` 路径的核心问题不是 helper 被赋值这一单点，而是用户表达式可调用 `extend(input, functionName, args)`，并使 `functionName` 在 native fallback 中解析到危险属性名 `constructor`，随后由 `extend` 的 native 分支实际调用该函数。

## 原问题

原始 `entry_point` 标在：

`packages/workflow/src/expression.ts:485`

```ts
data.extend = extend;
```

该位置是宿主侧将 helper 放入 data 上下文的装配语句，能说明 `extend` 的可达性，但不能体现外部用户输入如何进入漏洞链路。并且后续补丁 `9931c4d055` 说明 VM 模式下宿主侧 `data.extend` 属于应当减少的 host-callable attack surface；真正的用户输入入口仍应是 workflow 节点参数表达式进入 `resolveSimpleParameterValue` 的参数位置。

原始 `critical_operation` 标在：

`packages/@n8n/expression-runtime/src/extensions/extend.ts:82-84`

```ts
if (inputAny && functionName && typeof inputAny[functionName] === 'function') {
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
	return { type: 'native', function: inputAny[functionName] };
```

该位置确实是危险属性解析点，补丁 `1acdafe6ac` 正是在 `findExtendedFunction` 开头增加 `UNSAFE_PROPERTY_NAMES` denylist 来阻断 `constructor`。但从语义上看，这里只完成“取到 Function 构造器并返回 native 函数”的解析动作，尚未调用该函数。漏洞成立的关键操作应下移到 `extend` 的 native 分支调用点。

## 修复位置

修复后的 `entry_point` 为：

`packages/workflow/src/expression.ts:451-455`

```ts
resolveSimpleParameterValue(
	parameterValue: NodeParameterValue,
	data: IWorkflowDataProxyData,
	returnObjectAsString = false,
```

该方法接收 workflow 节点参数中的原始 `parameterValue`，并通过 `isExpression` 判断、去除 `=`、`extendSyntax` 转换和 `renderExpression` 调用把表达式送入 VM evaluator。它比 `data.extend = extend` 更能表达 advisory 中的外部触发条件：有权限的用户在工作流参数中提交 crafted expression。

修复后的 `critical_operation` 为：

`packages/@n8n/expression-runtime/src/extensions/extend.ts:132-134`

```ts
if (foundFunction.type === 'native') {
	// eslint-disable-next-line @typescript-eslint/no-unsafe-return
	return foundFunction.function.apply(input, args);
```

当上一阶段把 `functionName` 解析为 native 函数后，此处实际调用该函数。若 `functionName` 为 `constructor` 且 `input` 为函数对象，`foundFunction.function` 即 `Function` 构造器，`args` 中的攻击者控制字符串会作为函数体传入。因此该节点是 `extend.ts` 路径中从危险属性解析进入可执行代码构造的关键操作。

## 选择该位置的理由

1. `entry_point` 选择 `resolveSimpleParameterValue` 的参数位置，是因为它直接接收用户在 workflow 节点参数中配置的表达式，符合“外部可达入口或用户输入进入点”的要求。
2. `critical_operation` 选择 native 分支的 `apply`，是因为它对已解析出的 native 函数执行调用，语义上比单纯的属性读取更接近漏洞成立点。
3. 补丁 `1acdafe6ac` 在 `findExtendedFunction` 开头新增 `UNSAFE_PROPERTY_NAMES`，明确将 `constructor`、`prototype`、`__proto__` 等列入拒绝列表，证明危险在于 expression extension 的属性名解析与 native 调用组合。
4. 补丁 `cf602ef71c` 又将 `functionName` 统一强制转换为稳定的 `name` 后再用于所有 lookup，说明修复方关注的是用户可控函数名在不同 lookup 分支中的一致性和安全性。

## Trace 修复说明

修复后的 trace 保留 10 个关键节点：

1. `packages/workflow/src/expression.ts:451-455`
   `parameterValue` 作为节点参数表达式进入求值流程。
2. `packages/workflow/src/expression.ts:465`
   去掉表达式前缀 `=`，用户表达式主体继续向下游传播。
3. `packages/workflow/src/expression.ts:496-503`
   说明漏洞版本仅用正则拦截显式 `.constructor`，无法覆盖把 `constructor` 作为 `extend` 参数传入的路径。
4. `packages/workflow/src/expression.ts:506-507`
   表达式经 `extendSyntax` 后传给 `renderExpression`。
5. `packages/workflow/src/expression.ts:534-536`
   VM 模式下调用 `Expression.vmEvaluator.evaluate`。
6. `packages/@n8n/expression-runtime/src/evaluator/expression-evaluator.ts:36-38`
   转换后的 JavaScript 交给 isolated-vm bridge 执行。
7. `packages/@n8n/expression-runtime/src/runtime/reset.ts:167-168`
   isolate 内把 `extend` 暴露到 `__data`，使表达式中的 `extend(...)` 可解析到 expression-runtime helper。
8. `packages/@n8n/expression-runtime/src/extensions/extend.ts:105-106`
   用户控制的 `functionName` 进入 `findExtendedFunction`。
9. `packages/@n8n/expression-runtime/src/extensions/extend.ts:79-85`
   native fallback 未过滤危险属性名，可能返回 `Function` 构造器。
10. `packages/@n8n/expression-runtime/src/extensions/extend.ts:132-134`
    native 分支调用 `foundFunction.function.apply(input, args)`，与新的 `critical_operation` 对齐。

## 未采用候选点的原因

- `packages/workflow/src/expression.ts:485` 的 `data.extend = extend`
  该语句是 helper 装配点，不是外部输入入口。它可作为可达性背景，但不足以表达 crafted workflow parameter 如何进入漏洞链路，因此不再作为 `entry_point`。
- `packages/workflow/src/expression-sandboxing.ts:137` 的 `ThisSanitizer`
  该 hook 处理 regular function 的 `this` 绑定，和本条 `extend.ts` 中 `functionName = "constructor"` 的 native fallback 数据流没有直接关系，删除以保持 trace 精炼。
- `packages/@n8n/expression-runtime/src/extensions/extend.ts:82-84` 的 native fallback
  该位置保留为 trace 中的关键解析节点，但不作为 `critical_operation`，因为它只是返回 native 函数；真正调用发生在 `extend.ts:132-134`。
- `packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts:483-486` 的 `script.runSync`
  该语句是通用 VM 执行点，对所有 VM 表达式均成立。若将其作为本条 critical operation，会弱化 `extend.ts` 漏洞的具体成因；因此 trace 只保留到 bridge 执行入口，不把通用执行 API 作为核心缺陷位置。
