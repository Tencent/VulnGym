# n8n 语义修复说明

本文件记录对 6 条 n8n 相关样本的 entry_point、critical_operation 和 trace 的修正。

## 修复摘要

| entry_id | 原 critical_operation 问题 | 修复后 critical_operation |
|-----------|--------------------------|-------------------------|
| entry-00099 | 指向 PrototypeSanitizer 函数定义 (L244) | expression-evaluator-proxy.ts L9-12 |
| entry-00100 | 指向 sanitizer 函数定义 (L330-336) | expression-evaluator-proxy.ts L9-12 |
| entry-00103 | 指向单个语句 (L20) | html-sandbox.ts L16-21 完整函数逻辑 |
| entry-00176 | 指向 BLOCKED_ATTRIBUTES 静态列表 | task_analyzer.py L63-68 判断逻辑 |
| entry-00511 | 保留，语义合理 | extend.ts L77-85 原生属性回退 |
| entry-00512 | 保留，语义合理 | reset.ts L44-46 普通赋值 |

## 重点修正

### entry-00099/00100
- **原问题**：critical_operation 指向防护机制的函数定义，而非漏洞触发点
- **修复**：统一指向 Tournament evaluator 构造和钩子注册位置
- **理由**：漏洞在 evaluator.execute 执行时真正触发

**候选点分析：**

| 候选位置 | 文件:行号 | 未采用原因 |
|----------|-----------|-----------|
| PrototypeSanitizer 函数定义 | expression-sandboxing.ts:244 | 函数声明本身无害，漏洞触发依赖 Tournament 实际执行 AST 遍历时缺少 visitWithStatement 处理器 |
| sanitizer 函数定义 | expression-sandboxing.ts:330-336 | 同上，静态函数声明不能体现漏洞运行时触发条件 |
| Object.defineProperty(data, sanitizerName, ...) | expression.ts:434-438 | 此处是防护绑定点，但 __sanitize 可被局部声明遮蔽的关键在于 Tournament 执行时绕过了防护 |

### entry-00103
- **原问题**：entry_point 指向无语义的代码块结束节点
- **修复**：改为 evaluateResponseHeaders 函数（L882-892）
- **理由**：真正体现用户响应头配置如何进入漏洞链路

**源码锚点修正历史：**
- 原 critical_operation 行号 18-23 → 修正为 16-21（对应 isHtmlRenderedContentType 函数实际行号）

**候选点分析：**

| 候选位置 | 文件:行号 | 未采用原因 |
|----------|-----------|-----------|
| 代码块结束节点 | webhook-helpers.ts:615 | 无语义，无法体现外部输入进入漏洞链路的路径 |
| res.setResponseHeaders(...) | webhook-request-handler.ts:160+ | 此处是最终执行点，但缺少用户输入来源说明 |
| evaluateComplexWebhookDescriptionExpression 调用 | webhook-helpers.ts:882-885 | ✅ **已采用**，直接体现用户配置的 responseHeaders 表达式在此被求值 |

### entry-00176
- **原问题**：critical_operation 指向静态列表定义
- **修复**：改为 BLOCKED_ATTRIBUTES 成员判断（L63-68）
- **理由**：漏洞真正成立的位置是判断逻辑，而非数据定义

**源码锚点修正历史：**
- 移除 python_runner.py:95（该文件在 vulnerable commit 不存在，trace 末端已删除）
- 修正代码片段中 `this._add_violation` → `self._add_violation`（Python 应使用 self）
- 修正 trace 节点 ast.parse 行号 189-191 → 237-239

**候选点分析：**

| 候选位置 | 文件:行号 | 未采用原因 |
|----------|-----------|-----------|
| BLOCKED_ATTRIBUTES 静态列表定义 | constants.py:126-135 | 纯数据定义，漏洞成立依赖黑名单不完整被检查逻辑使用 |
| visit_Attribute 方法签名 | task_analyzer.py:60-62 | 只说明方法存在，未体现核心缺陷在黑名单成员判断 |
| if (node.attr in BLOCKED_ATTRIBUTES) | task_analyzer.py:63-68 | ✅ **已采用**，黑名单成员判断是漏洞成立的关键节点 |

### entry-00511/00512
- **原问题**：entry_point 指向不准确
- **修复**：统一改为表达式处理位置（L451-453）
- **理由**：直接体现用户输入进入沙箱的起点

**源码锚点修正历史：**
- entry-00511：critical_operation 行范围 77-84 → 77-85（包含闭合花括号）
- entry-00512：critical_operation 行号 43-46 → 44-46（对应源码实际位置）

**候选点分析：**

| 候选位置 | 文件:行号 | 未采用原因 |
|----------|-----------|-----------|
| @Post('/:workflowId/run') | workflows.controller.ts:539 | HTTP 入口过于外层，未直接体现表达式进入沙箱的处理 |
| renderExpression 方法定义 | expression.ts:524 | 方法签名无具体实现，无法体现 extendSyntax 改写过程 |
| extendSyntax + renderExpression | expression.ts:451-453 | ✅ **已采用**，直接体现用户表达式送入 VM 沙箱的关键转折点 |

## 直接修复证据

| 漏洞 | 修复 commit | 关键修复内容 |
|------|-------------|-------------|
| CVE-2026-1470 | 30383d86139f3279a698df8d229eadfefe8627f4 | 添加 visitWithStatement 和 RESERVED_VARIABLE_NAMES |
| CVE-2026-25051 | ced34c0f93ab4c759a56065965986094d8ef7323 | 添加 trim() |
| CVE-2026-27494 | 3af9095245be3aaad6bc16622f379f79c6c6068f | 添加 "__objclass__" |
| CVE-2026-25049 | 1acdafe6ac862dfc4d04783a68c2bb065ab8c6a6 | 添加 UNSAFE_PROPERTY_NAMES 和 Object.defineProperty |

## 验证状态

- ✅ 6 条 entries 全部标记 verify=1
- ✅ 所有节点的 file/line/code 可在对应 commit 源码中找到匹配
- ✅ 408 条全量数据重建成功
- ✅ 已移除不存在的文件引用（python_runner.py）
- ✅ 已修正 Python 代码片段语法（self vs this）
- ✅ 已修正源码行号锚点
