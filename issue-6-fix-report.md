# Issue #6 n8n 入口点与关键操作语义修复报告

本报告复核并修正以下 6 条记录：`entry-00099`、`entry-00100`、
`entry-00103`、`entry-00176`、`entry-00511`、`entry-00512`。

复核以每条 entry 记录的 `commit` 为源码基准，同时对照 GitHub Advisory、
安全修复 commit 和修复测试。所有新节点均使用漏洞 commit 中可精确定位的
`{file, line, code, desc}`；`verify` 暂时保持 `0`，等待维护者人工确认后再提升，
避免把机器辅助审计误标成已经完成人工复核。

## 结论摘要

| Entry | 新入口 | 新关键操作 | 核心调整 |
|---|---|---|---|
| `entry-00099` | `workflows.controller.ts:561-565` | `expression-evaluator-proxy.ts:20` | 从单独路由装饰器补到 `req.body` 执行交接，并把 RCE sink 从 sanitizer 声明移到 Tournament 执行调用。 |
| `entry-00100` | `expression.ts:368-382` | `expression-sandboxing.ts:288-299` | 保留节点参数入口语义，把关键点移到可被 `___n8n_data` 遮蔽的动态属性改写。 |
| `entry-00103` | `webhook-helpers.ts:882-892` | `webhook-request-handler.ts:153-157` | 删除无语义的右花括号/streaming 分支，重建 `responseHeaders` 参数到 CSP 跳过分支的链。 |
| `entry-00176` | `Code.node.ts:206` | `task_executor.py:213` | 入口已准确；把 critical operation 从静态集合声明移到 Python 子进程的实际 `exec`。 |
| `entry-00511` | `expression.ts:451-465` | `extend.ts:132-134` | 从内部 `data.extend` 注入上移到用户表达式参数，并把最终点从危险属性返回推进到 Function constructor 的 native `apply`。 |
| `entry-00512` | `expression.ts:451-465` | `reset.ts:41-46` | 上移到用户表达式参数；保留并扩展由修复 diff 直接证明的可写 `__sanitize` 绕过点，补齐 isolate 执行链。 |

## 复核依据

- `GHSA-5xrp-6693-jjx9` 的修复 commit
  [`aa4d1e5`](https://github.com/n8n-io/n8n/commit/aa4d1e5825829182afa0ad5b81f602638f55fa04)
  为 `PrototypeSanitizer` 增加 `visitWithStatement`，并禁止声明
  `___n8n_data` / `__sanitize` 等保留变量。新增回归测试分别覆盖 `with`
  访问 constructor 和 `___n8n_data` 遮蔽。
- `GHSA-825q-w924-xhgx` 的修复 commit
  [`ced34c0`](https://github.com/n8n-io/n8n/commit/ced34c0)
  将 `contentType.toLowerCase()` 改为 `contentType.trim().toLowerCase()`；后续安全包
  [`562d867`](https://github.com/n8n-io/n8n/commit/562d867483e871b0f1e31776252e23bd721df75b)
  进一步取消按 MIME 类型决定是否设置 CSP 的分支，改为始终设置 webhook sandbox CSP。
- `GHSA-mmgg-m5j7-f83h` 发布当天的安全包 `562d867` 只需向
  `BLOCKED_ATTRIBUTES` 增加 `__objclass__` 即可阻断记录中的 Python 链，说明
  `visit_Attribute` 是失效 guard；最终影响仍发生在 `task_executor.py` 的 `exec`。
- `entry-00511/00512` 的目标 SHA `09e2c2b` 紧邻
  [`1acdafe`](https://github.com/n8n-io/n8n/commit/1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6)
  之前。该 commit 标题明确为 “VM test Group G — RCE prevention”，并分别：
  在 `findExtendedFunction` 前增加危险属性名拒绝集合；把 `__data.__sanitize`
  改为不可配置 accessor，覆盖写入时抛错。由于 advisory 当前列出的 commit
  没有直接修改这组实验性 VM 文件，本报告采用这个与目标 SHA 相邻、且直接修改
  两个缺陷点的安全 commit 作为主要补丁证据。

## `entry-00099` — `with` 语句绕过

### 原问题

原入口只有 `@Post('/:workflowId/run')`，能说明路由可达，却没有表示请求数据如何
进入执行服务。原 critical operation 是 `PrototypeSanitizer` 的函数声明；该行既不
执行表达式，也不直接执行任何安全判断。

### 修复后的链

1. `workflows.controller.ts:561-565` 把含 `workflowData.nodes[*].parameters` 的
   `req.body` 交给 `executeManually`。
2. `expression.ts:368-393` 接收节点表达式，只检查表达式前缀并移除等号。
3. `expression.ts:451-453` 完成语法扩展并进入 `renderExpression`。
4. `expression-evaluator-proxy.ts:9-13` 注册 AST hooks 并绑定 Tournament executor。
5. `expression-sandboxing.ts:264-267` 表明危险属性门禁从 MemberExpression visitor
   开始；`with(function(){})` 的词法绑定不经过该访问类型。
6. `expression-evaluator-proxy.ts:20` 调用 Tournament executor，缺少
   WithStatement guard 的载荷在此被编译和执行。

### 未采用候选

- `expression-sandboxing.ts:244` 只是 hook 函数声明。
- `expression-sandboxing.ts:330-336` 的 sanitizer 在 `with` 词法绑定路径中没有被调用。
- `visitMemberExpression` 保留为 trace 中的失效防线证据，但它本身不是最终 RCE sink。

## `entry-00100` — 保留变量遮蔽

### 原问题

入口方向基本正确，但只标了方法名，缺少完整参数边界。原关键点是 sanitizer
函数体；利用成功时真实 sanitizer 恰恰没有被调用，所以不能把它当作缺陷操作。

### 修复后的链

1. `expression.ts:368-382` 接收用户控制的 `parameterValue`。
2. `expression.ts:434-438` 只保护真实 `data.__sanitize`；无法阻止局部变量遮蔽。
3. `expression.ts:451-453` 把表达式交给转换和求值。
4. `expression-evaluator-proxy.ts:9-13` 注册缺少保留变量检查的后置 hook。
5. `expression-sandboxing.ts:288-299` 把动态属性访问改写为
   `dataNode.__sanitize(property)`；用户声明 `___n8n_data` 后，该引用绑定到攻击者对象。
6. `expression-evaluator-proxy.ts:20` 运行过滤已失效的表达式。

### 未采用候选

- sanitizer 函数体不采用：遮蔽路径不会进入它。
- `Object.defineProperty(data, ...)` 不采用为 critical：它正确保护了原对象，核心问题是
  AST 改写引用的标识符可被同名局部声明遮蔽。
- Tournament evaluator 已作为 `entry-00099` 的执行 sink；本条选择更能区分第二条
  exploit path 的 AST 绑定绕过点。

## `entry-00103` — Webhook Content-Type / CSP 绕过

### 原问题

原入口 `webhook-helpers.ts:615` 只是 streaming 分支的右花括号，且该分支不产生
被标注的 `responseHeaders` 数据。原 trace 因此把无关的 streaming state 与静态
响应 header 处理错误连接。原 critical 位于 `toLowerCase()`，能解释根因，却没有
锚定最终跳过 CSP 的安全决策。

### 修复后的链

1. `webhook-helpers.ts:882-892` 求值 Webhook 节点的 `responseHeaders` 参数；
   header value 原样进入 Map。
2. `webhook-helpers.ts:559-562` 把 headers 封装进 `WebhookStaticResponse`。
3. `webhook-request-handler.ts:65-76` 接收执行结果并进入统一响应发送分支。
4. `webhook-request-handler.ts:127-131` 解构 headers 并调用 `setResponseHeaders`。
5. `webhook-request-handler.ts:146-150` 把污染值写入 Express response。
6. `html-sandbox.ts:19-25` 对 Content-Type 只做 lowercase，不做 trim。
7. `webhook-request-handler.ts:153-157` 得到 `needsSandbox=false`，跳过 CSP sandbox。

### 未采用候选

- streaming 分支和 `runData.httpResponse` 与该静态响应 header 链无关，全部删除。
- `contentType.toLowerCase()` 作为根因 guard 保留在 trace；critical 移到真正改变
  安全控制流的 `needsSandbox` / CSP 分支。

## `entry-00176` — Python Code 节点 `__objclass__` 逃逸

### 原问题

入口 `Code.node.ts:206` 已能准确表示用户 Python 代码来源。原 critical operation
只是 `BLOCKED_ATTRIBUTES = {` 的静态声明，不执行判断，也不执行攻击代码。

### 修复后的链

1. `Code.node.ts:206-209` 读取代码、构造 sandbox 并启动 runner。
2. `PythonTaskRunnerSandbox.ts:50-66` 把源码写入 `taskSettings.code` 并跨进程提交。
3. `task_runner.py:321-329` 先调用 analyzer，再把同一源码交给 executor。
4. `task_analyzer.py:63-76` 只对 `BLOCKED_ATTRIBUTES` 做精确匹配；目标 commit
   缺少 `__objclass__`，因此 slot wrapper 链通过检查。
5. `task_executor.py:203-213` 包装、编译并最终 `exec(compiled_code, globals)`。

### 未采用候选

- `constants.py:126` 不采用：静态集合本身不是操作。
- `visit_Attribute` 是关键失效 guard，保留在 trace；critical 选择对通过验证的用户
  代码进行实际执行、并产生文件读取/RCE 影响的 `exec`。
- `compile()` 只生成 code object；真正运行载荷的是随后 `exec`。

## `entry-00511` — VM expression extension native fallback

### 原问题

原入口 `data.extend = extend` 是内部能力注入，不是用户输入来源。原 critical
`inputAny[functionName]` 能说明危险属性解析，但尚未把攻击者代码参数交给
Function constructor。

### 修复后的链

1. `expression.ts:451-465` 接收并规范化用户节点表达式。
2. `expression.ts:484-492` 向数据上下文暴露 `extend`。
3. `expression.ts:505-507` 转换扩展语法并进入 VM。
4. `expression.ts:524-536` 调用 VM evaluator。
5. `reset.ts:165-168` 在 isolate 内重新暴露 `extend`。
6. `extend.ts:105-106` 把字符串函数名传给 `findExtendedFunction`。
7. `extend.ts:79-85` 无过滤读取 `inputAny['constructor']` 并返回 Function constructor。
8. `extend.ts:132-134` 以攻击者 `args` 调用该 constructor，生成随后被外层表达式调用的函数。

### 未采用候选

- `data.extend = extend` 不采用为 entry：它不含外部输入。
- constructor 正则和 `ThisSanitizer` 是被规避的防线，不属于关键数据流，已从 trace 删除。
- `inputAny[functionName]` 保留为核心传播节点；critical 前移到实际调用危险构造器的
  native `apply`。

## `entry-00512` — 可写 `__sanitize` 槽位

### 原问题

原入口是 `renderExpression` 方法声明，未体现节点参数如何进入求值。原 critical
`globalThis.__data.__sanitize = __sanitize` 与紧邻修复 diff 完全一致，判断正确；
本次扩大代码范围以显示新建 `__data` 和普通赋值语义，并重建前后执行链。

### 修复后的链

1. `expression.ts:451-465` 接收用户节点表达式。
2. `expression.ts:505-507` 完成转换并进入 VM。
3. `expression-sandboxing.ts:493-504` 把动态成员访问绑定到 `dataNode.__sanitize`。
4. `isolated-vm-bridge.ts:454-470` reset 数据代理，并以 `this===__data` 包装代码。
5. `reset.ts:41-46` 用普通可写赋值安装 `__sanitize`；攻击表达式可覆盖该槽位。
6. `isolated-vm-bridge.ts:482-486` 运行过滤槽位已失效的 isolate script。

### 未采用候选

- `renderExpression` 方法声明不采用为 entry；用户输入更早在
  `resolveSimpleParameterValue(parameterValue, ...)` 进入。
- `script.runSync` 是最终执行节点，保留在 trace；critical 仍选择补丁直接改为
  不可写 accessor 的运行时绕过点，而不是所有正常表达式都会经过的通用执行器。

## 验证计划

- 解析全部 `data/entries.jsonl` 行，保持 408 行、entry id 顺序和 JSONL 格式。
- 按 `SCHEMA.md` 校验 line 类型、必需节点键、commit/repo/source_link 和 report 关联。
- 对 6 条目标 entry，在各自漏洞 commit 的源文件中精确核对每个
  `file/line/code`。
- 运行 `examples/load_dataset.py` 与 `git diff --check`。
- 保留工作区中先前存在的 Issue #7 变更，不修改或重写其 5 条 entry 和交付物。
