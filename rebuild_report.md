# Issue #7 漏洞链重建报告

本报告记录 `entry-00185`、`entry-00197`、`entry-00290`、
`entry-00320` 与 `entry-00391` 的人工复核结果。所有新节点均以 entry
记录的 commit 为基准核对 `{file, line, code}`；判断同时参考 GitHub
Advisory、修复提交和回归测试。

## 结论摘要

| Entry | 结果 | 核心调整 |
|---|---|---|
| `entry-00185` | 已确认，`verify=1` | 入口移到工作流 `fileName`，危险操作移到 `fsWriteFile`。 |
| `entry-00197` | 已确认，`verify=1` | 从错误的 `/media/:id` 单请求链重建为“先校验、后读取”的两阶段 TOCTOU 链。 |
| `entry-00290` | 待人工复核，`verify=0` | 危险操作移到最终 `writeFile`；记录 commit 与 advisory 的漏洞语义冲突。 |
| `entry-00320` | 已确认，`verify=1` | 入口上移到 multipart `file.filename`，补齐 API 到存储层的传播。 |
| `entry-00391` | 已确认，`verify=1` | 危险操作移到未编码参数替换处，删除 logger/声明节点并补齐 `urljoin`。 |

本轮将人工确认的 entry 数从 `393` 增至 `397 / 408`。四个已确认 entry
所属 advisory 原本已有其他 verified entry，因此至少包含一个已审计 entry 的
advisory 数仍为 `178 / 184`。`entry-00290` 的阻塞信息另见
`manual_review.csv`。

## 重建方法

1. 读取 entry 中的 `repo_url` 与 `commit`，只在该 SHA 上定位代码。
2. 对照 advisory 的前置条件、影响与修复说明。
3. 对照修复提交或回归测试，区分 source、传播节点、失效 guard 与最终 sink。
4. 删除纯日志、注释、默认配置、函数闭合括号和方法声明等弱相关节点。
5. 对源码证据与 advisory 不一致的样本保留 `verify=0`，并输出人工复核项。

## `entry-00185` — n8n `.git` 文件写入与 Git 操作组合 RCE

### 修复前问题

原入口是 `append` 的 `default: false`。它只决定覆盖/追加模式，不是攻击者
控制的目标路径来源。原危险操作是 `resolvePath()` 的闭合括号；该位置既不是
值产生点，也没有执行安全影响。原 trace 还包含 item 初始化和返回值等与漏洞
成立关系较弱的节点。

### 修复后链路

1. `write.operation.ts:70` 从工作流参数读取攻击者可控的 `fileName`。
2. `write.operation.ts:72-74` 选择创建/截断或追加写入标志。
3. `write.operation.ts:96-100` 规范化路径并调用 `writeContentToFile`。
4. `file-system-helper-functions.ts:119` 调用 `isFilePathBlocked`。
5. 漏洞版本没有默认 `.git` 路径模式，检查最终在 `:65` 返回 `false`。
6. `file-system-helper-functions.ts:128` 调用 `fsWriteFile`，恶意 Git 配置落盘。

### 判断依据

[GHSA-x2mw-7j39-93xq](https://github.com/advisories/GHSA-x2mw-7j39-93xq)
说明具有工作流编辑权限的用户可把 Read/Write Files from Disk 节点与 Git
操作组合实现命令执行。修复提交
[`e22acaa`](https://github.com/n8n-io/n8n/commit/e22acaab3dcb2004e5fe0bf9ef2db975bde61866)
新增默认 `N8N_BLOCK_FILE_PATTERNS`，其默认正则专门阻断 `.git`，并在
`isFilePathBlocked` 中调用该规则。这与“可控路径 → 缺少 `.git` 门禁 →
真实磁盘写入”的重建链一致。

## `entry-00197` — OpenClaw 沙箱媒体 TOCTOU

### 修复前问题

原标注把 `/media/:id` 路由当成入口，并把同一路径中的
`handle.readFile()` 当成 TOCTOU use。该代码先打开文件，再从同一个 file
handle 读取；符号链接在打开后被重定向不会让该 handle 改指另一个文件。
因此原链没有表达修复提交中回归测试所覆盖的真实“两阶段”场景。

### 修复后链路

前置阶段（check）：

1. `message-action-params.ts:288` 从消息工具参数读取 `media/path/filePath`。
2. `:296` 调用 `resolveSandboxedMediaSource`，当时符号链接指向沙箱内并通过边界检查。
3. `:298` 把规范化结果保存回 `args`。

阶段间状态变化：攻击者把同一符号链接从沙箱内目标重定向到沙箱外目标。
这一步是文件系统状态变化，没有单一源码行可表示。

主触发阶段（use）：

4. `message-action-params.ts:338` 再次从 `args` 取出旧媒体路径。
5. `:258-261` 调用 `loadWebMedia`。
6. `:215-216` 传入 `sandboxValidated: true` 与裸 `fs.readFile` 回调。
7. `web/media.ts:353-355` 因 `sandboxValidated` 跳过本地根目录检查。
8. `web/media.ts:360` 调用读取回调，跟随已重定向的链接读取沙箱外文件。

### 判断依据

[GHSA-7xmq-g46g-f8pv](https://github.com/advisories/GHSA-7xmq-g46g-f8pv)
明确说明媒体路径先验证、后经另一条路径读取，链接可在两个阶段之间重定向。
修复提交
[`c823a85`](https://github.com/openclaw/openclaw/commit/c823a85302119044bc26763644c15fe35dd04f4a)
新增的回归测试按顺序调用 `normalizeSandboxMediaParams`、重定向符号链接、再调用
`hydrateAttachmentParamsForAction`；同时把裸 `fs.readFile` 换成
`createRootScopedReadFile`。这直接支持新的两阶段 trace。

### 数据模型建议

现有 schema 只有一个 `entry_point` 和线性 `trace`。为了兼容旧消费者，建议未来
新增可选字段而不替换现有字段：

```json
"stages": [
  {"name": "prerequisite", "entry_point": {...}, "trace": [...]},
  {"name": "trigger", "entry_point": {...}, "trace": [...]}
]
```

若不同阶段之间依赖文件系统状态变化，可再为 stage 增加可选的 `state_transition`
字符串。旧字段仍保存主入口/最终 sink，旧消费者无需改动。

## `entry-00290` — OpenClaw 悬空符号链接沙箱逃逸

### 可确认的调整

原危险操作 `boundary-path.ts:196` 是边界 guard 中的符号链接解析调用，不是产生
宿主文件完整性影响的操作。实际 add-file sink 是
`apply-patch.ts:152` 的 `fileOps.writeFile(target.resolved, hunk.contents)`。
因此危险操作已移到该写入 primitive，trace 也从工具入口、patch 调度、路径
解析、alias guard 延伸到候选写入 sink。

### 无法确认的部分

记录 SHA `8b5ebff67ba16bb68e26a2a0a22ed9556800009d` 中：

- `boundary-path.ts:487-496` 的 `resolveSymlinkHopPath` 在 `realpath` 返回
  `ENOENT` 后读取链接目标，并调用 `resolvePathViaExistingAncestor`；
- 对“链接指向已存在的沙箱外目录、最终文件不存在”的场景，该函数会得到沙箱外
  canonical path；
- `boundary-path.ts:197` 随后执行 `isPathInside`，应当 fail closed。

而 [GHSA-qcc4-p59m-p54m](https://github.com/advisories/GHSA-qcc4-p59m-p54m)
描述的正是“missing target 条件下错误放行悬空链接”。对比 advisory 指定的修复提交
[`4fd29a3`](https://github.com/openclaw/openclaw/commit/4fd29a35bb85a1898ebff518364c467058b50e14)
与记录 SHA，唯一差异是新增回归测试，没有生产代码变化。这表明记录 SHA 很可能已经
包含更早落地的修复逻辑，无法作为该漏洞的 vulnerable commit 复现。

因此本条不强行设置 `verify=1`。需要维护者确认真正的修复前 SHA，或确认该 entry
是否应改为固定版本的回归样本。候选位置和建议操作见 `manual_review.csv`。

## `entry-00320` — Langflow v2 上传路径穿越

### 修复前问题

原入口位于 `new_filename.rsplit(".", 1)`。这只是传播/拆分节点；攻击者控制的
multipart 文件名更早在 `file.filename` 进入 API。原 trace 还缺少
`storage_service.save_file` 和 `folder_path / file_name` 两个跨层关键节点。

### 修复后链路

1. `files.py:162` 读取 multipart `file.filename`。
2. `:163-166` 拆分扩展名但不净化路径分隔符。
3. `:214` 生成仍含 `../` 的 `unique_filename`。
4. `:218-220` 传给 `save_file_routine`。
5. `:125` 跨层传给 `StorageService.save_file`。
6. `local.py:114-116` 直接执行 `folder_path / file_name`。
7. `local.py:120` 通过 `async_open` 打开规范化后的沙箱外路径。

### 判断依据

[GHSA-g2j9-7rj2-gm6c](https://github.com/advisories/GHSA-g2j9-7rj2-gm6c)
逐行指出 API 层 `files.py:162` 的 multipart filename 来源，以及存储层
`local.py:114-116` 缺少 containment 检查。新的链路覆盖了这两个层次和最终写入。

## `entry-00391` — FastMCP OpenAPIProvider SSRF / 路径穿越

### 修复前问题

原危险操作是 `_build_url` 的方法声明，trace 还包含 logger 和注释。这些节点不能
解释未编码 path parameter 如何改变最终后端 URL。

### 修复后链路

1. `director.py:23-28` 的 `build` 接收 MCP 调用产生的 `flat_args`。
2. `:45-47` 调用 `_unflatten_arguments`。
3. `:114-115` 把原始 path value 写入 `path_params`。
4. `:54` 调用 `_build_url`。
5. `:213` 直接把未编码 value 替换进路径模板；这是核心缺陷位置。
6. `:216` 的 `urljoin` 解释 `../`，生成逃逸预期 API 前缀的后端 URL。

### 判断依据

[GHSA-vv7q-7jx5-f767](https://github.com/advisories/GHSA-vv7q-7jx5-f767)
明确把根因归纳为“未 URL encode 的直接替换 + `urljoin` 对 `../` 的解析”。
修复提交
[`40bdfb6`](https://github.com/PrefectHQ/fastmcp/commit/40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71)
对 path parameter 做编码，与新的 critical operation 和 trace 相符。

## 验证项目

- JSONL 可由 `examples/load_dataset.py` 成功加载。
- 行数保持 `184 reports / 408 entries`。
- 人工确认统计为 `397 entries / 178 advisories`。
- 所有更新节点均对记录 commit 执行文件、行号和代码文本精确匹配。
- `entry-00290` 保持 `verify=0` 并进入人工复核。
- `git diff --check` 无空白错误。
