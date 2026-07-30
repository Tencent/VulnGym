# Issue #7 漏洞链重建报告

## entry-00185：n8n ReadWriteFile 写入 .git 触发 RCE

### 结论

`entry-00185` 已按 commit `538181cbe32a92616df5e00d7ffaf4d568557f4f` 重建。原入口是 append 的静态默认值，原 critical operation 是 `resolvePath()` 的闭合括号，两者都没有表达攻击者控制的路径和真实写入。现已分别移动到 `write.operation.ts:70` 的 `fileName` 参数读取和 helper `128-131` 的 `fsWriteFile` 调用。

### 完整传播链

| 阶段 | 源码位置 | 语义 |
| --- | --- | --- |
| 路径 source | `write.operation.ts:70` | 从工作流参数读取攻击者控制的 `fileName` |
| 写入模式 | `write.operation.ts:71-74` | append=false 时使用创建、覆盖和截断 flags |
| 内容 source | `write.operation.ts:86-93` | 从二进制工作流数据构造 `fileContent` |
| 路径传播 | `write.operation.ts:96-100` | `resolvePath(fileName)` 后调用 `writeContentToFile` |
| guard 调用 | `file-system-helper-functions.ts:119` | 写入前执行 `isFilePathBlocked` |
| guard 缺失 | `file-system-helper-functions.ts:50-66` | 只检查固定 restrictedPaths/allowedPaths，没有 `.git` pattern 阻断 |
| 写入 sink | `file-system-helper-functions.ts:128-131` | `fsWriteFile` 将恶意 Git 配置实际写入磁盘 |

### 多阶段利用与修复依据

第一阶段，具有工作流编辑权限的攻击者使用 Read/Write Files from Disk 节点把恶意内容写入目标仓库的 `.git/config` 等 Git 控制文件；第二阶段再触发 Git 操作，使配置中的命令执行机制在 n8n 主机权限下运行。append 默认值只决定覆盖方式，并不是外部输入 source。

修复 commit `97365caf253978ba8e46d7bc53fa7ac3b6f67b32` 新增 `isFilePatternBlocked()`，并通过安全配置默认正则 `^(.*\\/)*\\.git(\\/.*)*$` 阻断任意层级的 `.git` 路径。这证明漏洞核心是通用路径 pattern guard 缺失。

entry point、critical operation 和 7 个 trace 节点均与目标 commit 精确匹配；`verify` 已设置为整数 `1`，无节点需要写入 `manual_review.csv`。

## entry-00197：OpenClaw media sandbox TOCTOU

### 结论

`entry-00197` 已按 vulnerable commit `4320cde91d9574d65dd240f8b033463cc723d6a6` 完成人工核验。现有 route、格式校验、root-scoped open、大小检查、TTL 检查和 `handle.readFile()` 行号均准确，本阶段主要重写其语义，明确 check/use 分离与多阶段利用关系。

安全公告将根因定义为 media 路径先验证、后通过独立路径读取的 TOCTOU gap。后续修复 commit `c823a85302119044bc26763644c15fe35dd04f4a` 将读取改为 `readFileWithinRoot(...)`，把边界检查、大小限制、读取和句柄关闭统一到 root-scoped helper。

### 多阶段利用

| 阶段 | 源码位置 | 语义 |
| --- | --- | --- |
| 前置准备 | 文件系统状态 | 攻击者准备可在检查后重定向的 media 路径或符号链接 |
| 主触发 source | `src/media/server.ts:35-36` | 请求 `GET /media/:id`，外部 `id` 进入处理链 |
| 格式 guard | `src/media/server.ts:37` | 只检查 media ID 格式，不保证文件系统状态稳定 |
| sandbox check | `src/media/server.ts:42-44` | `openFileWithinRoot` 返回 `handle`、`realPath` 和检查时 `stat` |
| 窗口阶段 | `src/media/server.ts:46-55` | 大小和 TTL 逻辑使用检查时快照，在最终读取前继续执行 |
| use sink | `src/media/server.ts:57` | `handle.readFile()` 执行最终内容读取 |

### 判断依据

- `isValidMediaId` 是字符与长度校验，不是文件系统状态锁定机制。
- `openFileWithinRoot` 承担 root 边界检查，调用方随后独立执行大小、TTL 和读取，形成跨步骤生命周期。
- 修复补丁用 `readFileWithinRoot` 替换调用方手工组合，证明修复目标是消除多个 media 调用点的 check/use drift。
- 本 entry 的 6 个节点均与目标 commit 源码精确匹配，`verify` 已设置为整数 `1`。
- 本条目没有无法确认的节点，不写入 `manual_review.csv`。

## entry-00290：OpenClaw dangling symlink 沙盒逃逸

### 结论

`entry-00290` 已按 commit `8b5ebff67ba16bb68e26a2a0a22ed9556800009d` 重建。原 `critical_operation` 位于 `boundary-path.ts:196`，只能解释检查为什么可能错误放行；现在已移动到 `apply-patch.ts:152` 的 `fileOps.writeFile(...)`，使 trace 最终落到实际越界写入。

### 完整传播链

| 角色 | 源码位置 | 语义 |
| --- | --- | --- |
| 工具入口 | `src/agents/apply-patch.ts:94` | `execute` 接收含目标路径的 patch 参数 |
| 调度传播 | `src/agents/apply-patch.ts:106` | 调用 `applyPatch(input, options)` |
| 路径解析 | `src/agents/apply-patch.ts:150` | Add File hunk 的路径进入 `resolvePatchPath` |
| guard 入口 | `src/agents/apply-patch.ts:282-289` | workspace-only 模式调用 `assertSandboxPath` |
| alias guard | `src/agents/sandbox-paths.ts:72-77` | 调用 `assertNoPathAliasEscape` 检查符号链接边界 |
| guard failure | `src/infra/boundary-path.ts:196-203` | missing-target 情况下的 canonical 结果可能被误判为仍在 root 内 |
| write sink | `src/agents/apply-patch.ts:152` | `fileOps.writeFile` 跟随危险路径写入补丁内容 |

### Guard Failure 与 Sink

`resolveSymlinkHopPath(...)` 和后续 `isPathInside(...)` 是安全决策点。它们决定危险路径是否被拒绝，但本身不会修改文件，因此只能作为 guard failure 保留在 trace 中。真正的完整性影响发生在 guard 返回之后：Add File 分支将 `target.resolved` 交给 `fileOps.writeFile`，底层文件系统沿符号链接创建或覆盖边界外文件。

### 修复依据

安全公告指出受影响版本会在 dangling symlink 的 missing-target 情况下错误接受路径。修复 commit `4fd29a35bb85a1898ebff518364c467058b50e14` 增加 fail-closed 回归测试，要求指向 root 外缺失目标的 broken final symlink 必须抛出 `Symlink escapes sandbox root`，且外部文件不得被创建。

所有 entry point、critical operation 和 7 个 trace 节点均与目标 commit 精确匹配；`verify` 已设置为整数 `1`，无节点需要写入 `manual_review.csv`。

## entry-00320：Langflow v2 上传路径穿越

### 结论

`entry-00320` 已按 Langflow vulnerable commit `e8bbae8eeb8729abd650f07bfc55957cbdbc1636` 完成人工重建。入口已从文件名拆分逻辑上移到 multipart 文件名读取位置，最终操作保留为本地存储层的实际文件打开写入。

GitHub Advisory 对漏洞的描述与源码一致：`POST /api/v2/files/` 直接使用 multipart 文件名，而 `LocalStorageService` 通过简单路径拼接生成写入目标，缺少规范化后的目录包含关系校验。

### 完整传播链

| 阶段 | 源码位置 | 语义 |
| --- | --- | --- |
| filename source | `src/backend/base/langflow/api/v2/files.py:162` | `file.filename` 直接进入 `new_filename` |
| 拆分未净化 | `src/backend/base/langflow/api/v2/files.py:163-166` | `rsplit` 只拆扩展名，保留 `../` 和路径分隔符 |
| 去重未净化 | `src/backend/base/langflow/api/v2/files.py:205-214` | 数字后缀去重和字符串重组保留穿越片段 |
| API 内部传参 | `src/backend/base/langflow/api/v2/files.py:218-220` | `unique_filename` 作为 `file_name` 传入 `save_file_routine` |
| API 到 storage | `src/backend/base/langflow/api/v2/files.py:125` | `file_name` 原样传给 `storage_service.save_file` |
| storage 路径拼接 | `src/backend/base/langflow/services/storage/local.py:114-116` | `folder_path / file_name` 未做规范化边界校验 |
| 实际写入 sink | `src/backend/base/langflow/services/storage/local.py:120` | `async_open(str(file_path), mode)` 打开越界目标，随后写入数据 |

### 穿越片段保留原因

- `rsplit(".", 1)` 只处理最后一个点号，不会把 `../` 当作需要拒绝的路径元素。
- 去重正则只查找文件名末尾的 `(数字)`，不会检查目录分隔符或父目录片段。
- `unique_filename` 通过字符串格式化重新组合，原有路径片段保持不变。
- storage 层直接使用 Path 的 `/` 运算符拼接，未对解析后的 `file_path` 验证其仍位于 `folder_path` 下。

### 验证结果

- 所有 `entry_point`、`critical_operation` 和 `trace` 节点均与目标 commit 源码精确匹配。
- trace 已覆盖 filename source、拆分/去重、跨层传参、路径拼接和实际写入。
- `critical_operation` 指向 `async_open` 实际文件操作。
- `verify` 已设置为整数 `1`。
- 本条目不存在未确认节点，因此未生成 `manual_review.csv`。

## entry-00391：FastMCP OpenAPI path parameter 未编码

### 结论

`entry-00391` 已按 commit `c861862aededc7294cea5634d77e6926444ca101` 重建。原 critical operation 仅指向 `_build_url` 方法声明，现已移动到 `director.py:213` 的直接字符串替换语句；原 trace 中的 logger、注释和 `_build_url` 声明均已替换为实际数据传播和 URL 构造节点。

### 完整传播链

| 阶段 | 源码位置 | 语义 |
| --- | --- | --- |
| 输入边界 | `src/fastmcp/utilities/openapi/director.py:23-28` | `build` 接收来自 LLM/MCP 的 `flat_args` 和后端 `base_url` |
| 参数分类调用 | `director.py:45-47` | 调用 `_unflatten_arguments(route, flat_args)` |
| path 参数传播 | `director.py:114-115` | 原始值直接写入 `path_params` |
| URL 构造调用 | `director.py:54` | 路径模板、`path_params` 和 `base_url` 进入 `_build_url` |
| 未编码替换 | `director.py:209-213` | `str.replace` 直接嵌入参数，保留 URL 结构字符语义 |
| 规范化 sink | `director.py:216` | `urljoin` 解析 `../` 并生成逃离预定 API 前缀的 URL |

### 漏洞成因

`path_params[openapi_name] = value` 保存的是外部原始值。第 213 行没有使用 `quote` 编码便将其替换到模板，所以斜杠、点目录、查询和片段分隔符仍被视为 URL 结构。随后 `urljoin` 会规范化 `../`，使最终请求越过 OpenAPI operation 的预定路径前缀；请求又继承 provider 的后端地址和认证上下文，因此能够访问未通过 OpenAPI 暴露的敏感后端端点。

### 修复依据

修复 commit `40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71` 在替换前执行 `quote(str(param_value), safe="")` 并编码点号，同时增加 traversal、slash、query、fragment、single-dot 和 double-dot 测试。这直接证明根因是 path parameter 未编码，而 `urljoin` 的路径规范化是危害形成的后续步骤。

entry point、critical operation 和 6 个 trace 节点均与目标 commit 精确匹配；`verify` 已设置为整数 `1`，无节点需要写入 `manual_review.csv`。
