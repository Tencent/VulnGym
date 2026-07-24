# entry-00103 修复说明

## 基本信息

- `entry_id`: `entry-00103`
- 项目：`n8n`
- Advisory：`GHSA-825Q-W924-XHGX`
- 漏洞类型：Webhook HTML response stored XSS / CSP sandbox bypass
- vulnerable commit：`57d6015f2ea0442c24e0449105325b7e36f066df`
- 对照修复版本：`n8n@1.123.3`

本条样本复核范围按任务补充要求限定为 `critical_operation` 和 `trace`，`entry_point` 保持原值不变。经复核，原始 `critical_operation` 标在 `packages/core/src/html-sandbox.ts:20` 的 `contentType.toLowerCase()`，该位置是补丁根因检测点，但不是漏洞最终成立的安全决策点。本次将 `critical_operation` 调整到 `packages/cli/src/webhooks/webhook-request-handler.ts:153-158`，即读回响应 `content-type`、计算 `needsSandbox` 并条件性设置 CSP sandbox 的位置。

修复后的 trace 按数据集约定从 `entry_point` 起步，并以 `critical_operation` 结束。中间仅保留用户配置的响应头进入、响应头写入和 HTML Content-Type 检测误判等必要节点。

## 原问题

原始 `critical_operation` 为：

`packages/core/src/html-sandbox.ts:20`

```ts
	const contentTypeLower = contentType.toLowerCase();
```

该语句确实是漏洞补丁直接修改的位置。对比 `n8n@1.123.3` 可见修复将其改为：

```ts
	const contentTypeLower = contentType.trim().toLowerCase();
```

并在 `packages/core/src/__tests__/html-sandbox.test.ts` 新增了 extra spaces 测试，覆盖 `'  text/html'`、`'text/html  '`、`'  text/html  '`。

但是，从漏洞链路语义看，`toLowerCase()` 只是 HTML Content-Type 识别失败的局部根因。漏洞真正成立需要上游安全决策使用该错误识别结果，并因此跳过 `Content-Security-Policy` sandbox 头设置。因此，原始 `critical_operation` 没有定位到 CSP sandbox 被绕过的决策点。

原 trace 还包含：

- `packages/cli/src/webhooks/webhook-helpers.ts:615`
- `packages/cli/src/webhooks/webhook-helpers.ts:605-614`

这两个节点描述 streaming 分支和 `runData.httpResponse = res`，但未解释用户配置的 `Content-Type` 如何写入响应头、如何被读回检测、如何导致 `needsSandbox` 为 false，以及 CSP sandbox 分支如何被跳过。它们不适合作为本条静态 HTML webhook 响应链路的 trace 节点。

## 修复位置

修复后的 `critical_operation` 为：

`packages/cli/src/webhooks/webhook-request-handler.ts:153-158`

```ts
		const contentType = res.getHeader('content-type') as string | undefined;
		const needsSandbox = !contentType || isHtmlRenderedContentType(contentType);

		if (needsSandbox && !isWebhookHtmlSandboxingDisabled()) {
			res.setHeader('Content-Security-Policy', getWebhookSandboxCSP());
		}
```

选择该位置的理由：

1. `setResponseHeaders()` 已经将用户配置的响应头写入 `res`，此处读回 `content-type` 并将其传入 `isHtmlRenderedContentType()`。
2. `needsSandbox` 是是否设置 CSP sandbox 的直接安全决策变量。
3. 当带前导空白或包围空白的 HTML Content-Type 被误判为非 HTML 时，`needsSandbox` 为 false，`res.setHeader('Content-Security-Policy', getWebhookSandboxCSP())` 不会执行。
4. `getWebhookSandboxCSP()` 返回 CSP `sandbox` 指令；跳过该分支即构成 sandbox 保护绕过。

## Trace 修复说明

修复后的 trace 保留 5 个关键节点，首尾分别与 `entry_point` 和 `critical_operation` 对齐：

1. `packages/cli/src/webhooks/webhook-helpers.ts:615`
   与 `entry_point` 保持一致。该位置是当前样本固定的入口锚点，表示 webhook 执行进入后续响应处理流程。按任务要求，`entry_point` 不修改。
2. `packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts:393-401`
   从 `options.responseHeaders.entries` 读取用户配置响应头，并写入 `headers`。污染的 `Content-Type` 在这里进入 webhook 响应数据结构。
3. `packages/cli/src/webhooks/webhook-request-handler.ts:146-151`
   `setResponseHeaders()` 遍历 `WebhookResponseHeaders`，通过 `res.setHeader(name, value)` 将用户配置的响应头写入 Express response。
4. `packages/core/src/html-sandbox.ts:19-25`
   `isHtmlRenderedContentType()` 仅执行 `contentType.toLowerCase()`，没有先 `trim()`。因此 `' text/html'` 或 `'  text/html  '` 这类浏览器仍可能按 HTML 处理的值无法通过 `startsWith('text/html')` 检测。
5. `packages/cli/src/webhooks/webhook-request-handler.ts:153-158`
   与 `critical_operation` 保持一致。该节点读回 `content-type`、计算 `needsSandbox`，并决定是否设置 `Content-Security-Policy` sandbox；当前导空白导致检测返回 false 时，CSP sandbox 分支被跳过。

## 未采用位置说明

- `packages/core/src/html-sandbox.ts:20`
  该位置保留为 trace 中的根因检测节点，但不作为 `critical_operation`。它解释误判原因，但不能单独解释 CSP sandbox 头为何未设置。
- `packages/cli/src/webhooks/webhook-helpers.ts:615`
  按任务要求，顶层 `entry_point` 保持不变；为满足 trace 起点与 `entry_point` 对齐，本次将其作为 trace 首节点保留。
- `packages/cli/src/webhooks/webhook-helpers.ts:605-614`
  该 streaming 分支不是本条静态 HTML 响应体通过 `sendStaticResponse()` / `res.send(body)` 输出的主链，故删除。
- `packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts:477-479`
  该位置能说明 text 响应体来自 `responseBody` 参数，但最终输出点 `res.send(body)` 已覆盖响应体发送语义。为保持 trace 精炼，本次不单列。
- `packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts:558-565`、`packages/cli/src/webhooks/webhook-request-handler.ts:66-70`、`packages/cli/src/webhooks/webhook-request-handler.ts:99-105`、`packages/cli/src/webhooks/webhook-request-handler.ts:127-131`
  这些位置主要是响应对象组装、普通控制流分发或进入 `setResponseHeaders()` 的桥接调用，不直接写入污染值、执行 HTML 类型判断或做 CSP 安全决策，因此不保留为 trace 节点。
- `packages/cli/src/webhooks/webhook-request-handler.ts:133-137`
  该位置是最终响应体输出点，但不再作为 trace 终点。按本数据集复核约束，trace 终点应与 `critical_operation` 对齐；本漏洞的关键操作是 CSP sandbox 安全决策被跳过，而不是单纯发送响应体。
- `sendLegacyResponse()` / `sendStreamResponse()`
  两者也会调用 `setResponseHeaders()`，理论上共享同一检测缺陷；但本样本选择 `RespondToWebhook` 静态文本响应路径作为主链，能够更直接说明 HTML body 与用户配置 Content-Type 最终经 `res.send(body)` 输出。
