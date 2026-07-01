# entry-00512 修复说明

## 基本信息

- `entry_id`: `entry-00512`
- 项目：`n8n`
- Advisory：`GHSA-6CQR-8CFR-67F8`
- 漏洞类型：n8n VM 表达式引擎沙箱逃逸导致 RCE
- vulnerable commit：`09e2c2b5547b49a824a8265d312583f5d1f5c79f`
- 关键补丁参考：`1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6`

GHSA 公告说明，具备创建或修改 workflow 权限的认证用户可通过 workflow 参数中的 crafted expression 触发宿主命令执行。源码复核显示，`reset.ts` 路径的核心问题不是 sanitizer 函数本身，也不是通用 VM 执行 API，而是 VM runtime 在每次执行前把 `__sanitize` 作为可写属性挂到 `globalThis.__data`，随后 bridge 又以 `.call(__data)` 运行用户表达式，使表达式可以通过 `this.__sanitize` 覆写该槽位。覆写后，PrototypeSanitizer 为动态属性访问插入的 `this.__sanitize(expr)` 调用不再执行危险属性过滤。

## 原问题

原始 `entry_point` 标在：

`packages/workflow/src/expression.ts:524`

```ts
private renderExpression(expression: string, data: IWorkflowDataProxyData) {
```

该位置是宿主层进入 VM evaluator 的直接边界，但它是私有方法，不是外部可达入口，也没有体现 workflow 参数如何被外部用户触发进入执行流程。根据任务口径，entry point 应体现网络请求、用户配置或 workflow 节点参数进入漏洞链路的位置；因此本次将入口上移到手动执行 workflow 的 HTTP 路由。

原始 `critical_operation` 标在：

`packages/@n8n/expression-runtime/src/runtime/reset.ts:46`

```ts
globalThis.__data.__sanitize = __sanitize;
```

该位置方向正确，但原描述没有充分解释为什么沙箱内表达式能够触达并覆写该属性。结合 `isolated-vm-bridge.ts:470` 的 `.call(__data)` 包装后，才能完整说明普通赋值如何转化为运行时 sanitizer 覆写点。因此保留该位置作为 `critical_operation`，但重写描述并补齐 trace。

## 修复位置

修复后的 `entry_point` 为：

`packages/cli/src/workflows/workflows.controller.ts:513`

```ts
@Post('/:workflowId/run')
```

该装饰器将 `runManually` 注册为认证用户可通过网络触发的 workflow 手动执行端点，并要求 `workflow:execute` 权限。利用链中，crafted expression 通常已通过 workflow 创建或更新流程写入节点参数；该端点随后加载数据库中的 workflow 并启动执行，使已保存的恶意表达式进入节点参数求值、VM evaluator 和 expression-runtime。该入口和 `entry-00511` 的 `resolveSimpleParameterValue` 不重复，同时满足“外部可达入口”的要求。

修复后的 `critical_operation` 仍为：

`packages/@n8n/expression-runtime/src/runtime/reset.ts:46`

```ts
globalThis.__data.__sanitize = __sanitize;
```

该赋值创建了可写的 `__data.__sanitize` 槽位。由于 `isolated-vm-bridge.ts:470` 将用户代码包装为 `.call(__data)` 执行，表达式内的 `this` 正是 `__data`；因此攻击表达式可先执行 `this.__sanitize = (v) => v`，再通过动态属性访问触发 `this.__sanitize(expr)`，使 sanitizer 调用被攻击者控制。补丁 `1acdafe6ac` 将该赋值改为 `Object.defineProperty`，并在 setter 中抛出 `Cannot override "__sanitize" due to security concerns`，直接证明该可写属性初始化是本路径的核心缺陷点。

## 选择该位置的理由

1. `entry_point` 选择 `@Post('/:workflowId/run')`，是因为它是外部认证用户触发已保存 workflow 执行的网络入口；漏洞只有在 workflow 执行并解析节点参数表达式时才会进入 `resetDataProxies`。
2. 不再使用 `renderExpression` 作为 entry point，因为它位于表达式求值内部，不能表达 advisory 中“用户通过 workflow 参数触发”的外部可达性。
3. 不复用 `entry-00511` 的 `resolveSimpleParameterValue` 作为 entry point，因为该方法是两条 VM 表达式漏洞都会经过的通用参数解析入口；本条选择更上游的 HTTP 触发点来区分样本。
4. `critical_operation` 保留 `reset.ts:46`，是因为修复补丁直接修改该语句的属性描述符语义，且该语句决定 PrototypeSanitizer 生成的运行时过滤调用是否可被用户表达式替换。
5. `isolated-vm-bridge.ts:470` 是必要 trace 节点，因为 `.call(__data)` 解释了用户表达式如何通过 `this` 触达 `__data.__sanitize`，但修复补丁没有移除该执行模型，因此不把它作为 `critical_operation`。

## Trace 修复说明

修复后的 trace 保留 14 个关键节点：

1. `packages/cli/src/workflows/workflows.controller.ts:513`
   外部 HTTP POST 端点触发已保存 workflow 手动执行。
2. `packages/cli/src/workflows/workflows.controller.ts:527-532`
   控制器将数据库中的 `dbWorkflow` 传入 `executeManually`。
3. `packages/cli/src/workflows/workflow-execution.service.ts:104-109`
   执行服务接收 workflowData 与手动执行 payload，进入运行时执行流程。
4. `packages/workflow/src/workflow-expression.ts:66`
   WorkflowExpression 将节点参数转交给 Expression 的通用求值实现。
5. `packages/workflow/src/expression.ts:451-454`
   `parameterValue` 作为节点参数表达式进入表达式解析流程。
6. `packages/workflow/src/expression.ts:506-507`
   表达式经 `extendSyntax` 转换后调用 `renderExpression`。
7. `packages/workflow/src/expression.ts:534-536`
   VM 模式下调用 `Expression.vmEvaluator.evaluate`。
8. `packages/@n8n/expression-runtime/src/evaluator/expression-evaluator.ts:80-81`
   Tournament 将表达式转换为可执行 JavaScript，并应用 AST hooks。
9. `packages/workflow/src/expression-sandboxing.ts:498-501`
   PrototypeSanitizer 为动态属性访问插入 `dataNode.__sanitize(...)` 调用。
10. `packages/@n8n/expression-runtime/src/evaluator/expression-evaluator.ts:36-38`
    转换后的 JavaScript 和 workflow data 进入 isolated-vm bridge。
11. `packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts:463-465`
    bridge 在执行前调用 `resetDataProxies`。
12. `packages/@n8n/expression-runtime/src/runtime/reset.ts:46`
    `__sanitize` 被以普通赋值写入 `__data`，与 `critical_operation` 对齐。
13. `packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts:470`
    用户代码通过 `.call(__data)` 执行，使 `this` 指向可写的 `__data`。
14. `packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts:483-486`
    VM 执行 wrapped code；若 sanitizer 已被覆写，后续动态属性过滤随之失效。

## 未采用候选点的原因

- `packages/cli/src/workflows/workflows.controller.ts:87` 的 `@Post('/')`
  该路由可接收新建 workflow 的节点参数，是 crafted expression 的落库入口之一；但漏洞触发发生在 workflow 执行阶段，不是在创建接口本身，因此不作为本条 trace 的起点。
- `packages/cli/src/workflows/workflows.controller.ts:293` 的 `@Patch('/:workflowId')`
  该路由同样可修改 workflow 并写入恶意节点参数，但它只覆盖修改场景，且不直接触发表达式求值；本条采用手动执行端点作为更贴近漏洞触发的外部入口。
- `packages/workflow/src/expression.ts:451-454` 的 `resolveSimpleParameterValue`
  该位置准确体现节点参数表达式进入求值流程，但已被 `entry-00511` 用作 entry point。为避免两个样本入口重复，本条将其保留为 trace 节点而非 entry point。
- `packages/workflow/src/expression.ts:524` 的 `renderExpression`
  该位置是 VM evaluator 的内部入口，不是外部可达入口。它仍然是重要中间节点，但不足以满足本任务对 entry point 的定义。
- `packages/workflow/src/expression-sandboxing.ts:493-502` 的 `path.replace`
  该位置说明防护如何插入 runtime sanitizer 调用，但它本身不是缺陷；真正的问题在于插入调用所依赖的 `__data.__sanitize` 在 VM runtime 中可被用户表达式覆写。因此保留更精确的调用构造行作为 trace，不作为 `critical_operation`。
- `packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts:470` 的 `.call(__data)`
  该位置解释了可达性：用户表达式中的 `this` 绑定到 `__data`。但 `.call(__data)` 是表达式引擎的通用执行模型，修复补丁并未移除此模型，而是保护 `__sanitize` 属性不可被覆写，因此该节点只作为 trace。
