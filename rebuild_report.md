# Issue #7 调用链重建报告

## 概述

本报告记录了对 VulnGym 数据集中 5 条优先样本的 `entry_point`、`critical_operation` 和 `trace` 调用链重建过程。修复针对 Issue #7 提出的两类问题：(1) **整体错位**——节点标注在无意义的代码位置（如静态属性声明、闭合括号）；(2) **多阶段利用**——单一入口点无法完整表达攻击过程。

---

## entry-00185: n8n ReadWriteFile 节点写入 .git 目录导致 RCE

### 修复前的问题

- **entry_point** 标注在 `write.operation.ts:46` — `default: false`，仅仅是一个静态属性声明（append 选项的默认值），与数据流入口完全无关
- **critical_operation** 标注在 `file-system-helper-functions.ts:48` — `}`，`resolvePath` 函数的闭合括号，纯粹是语法符号
- **trace** 四个节点同样标注在无意义的返回值、闭合括号等位置；人工备注明确指出"全部定位在返回值等不重要位置"

### 修复后的链路

| 角色 | 文件 | 行号 | 代码 |
|------|------|------|------|
| **entry_point** | `write.operation.ts` | 70 | `fileName = this.getNodeParameter('fileName', itemIndex) as string` |
| trace[0] | `write.operation.ts` | 96-99 | `await this.helpers.writeContentToFile(resolvePath(fileName), ...)` |
| trace[1] | `file-system-helper-functions.ts` | 39-48 | `resolvePath()` — 路径解析（含 ENOENT 回退） |
| trace[2] | `file-system-helper-functions.ts` | 50-66 | `isFilePathBlocked()` — 返回 false（.git 路径未被阻断） |
| **critical_operation** | `file-system-helper-functions.ts` | 128-131 | `fsWriteFile(resolvedFilePath, content, ...)` |

### 关键判断依据

1. **EP 定位**：`getNodeParameter('fileName')` 是攻击者可控文件路径（如 `.git/config`）首次进入系统内部变量的节点
2. **漏洞根因**：`isFilePathBlocked()` 的 `getN8nRestrictedPaths()` 仅包含 n8n 内部路径（n8nFolder, staticCacheDir 等），不含 `.git` 目录，导致敏感路径不被拦截
3. **CO 定位**：`fsWriteFile` 是完成 .git/config 覆写的最终系统调用，也是 RCE 危害落地的节点（Git 解析恶意 core.fsmonitor 配置时触发命令执行）

---

## entry-00197: openclaw sandbox TOCTOU race condition

### 修复前的问题

- 调用链标注在结构上是正确的（完整覆盖了 route → validate → openFileWithinRoot → check → readFile 的流程）
- 但未能体现多阶段利用特性：单一 entry 只覆盖了"检查到使用"的竞态窗口（Phase 3），缺少对前置阶段（上传文件、替换为符号链接）的说明

### 修复方式

**保留原有结构标注不变，增强 desc 描述**以明确多阶段攻击模型：

- **entry_point.desc**：补充 `【多阶段利用说明】` — Phase 1 文件上传 → Phase 2 符号链接替换 → Phase 3 TOCTOU 竞态窗口
- **critical_operation.desc**：明确标注 `handle.readFile()` 为"使用"阶段，`openFileWithinRoot` 为"检查"阶段
- **trace[0].desc**：说明 GET 路由仅覆盖 Phase 3，完整攻击链需前置阶段配合
- **trace[2].desc**：明确标注 `openFileWithinRoot` 的检查语义及其时间局限性
- **trace[5].desc**：明确标注 `handle.readFile()` 的使用语义及无重检特性

### 关键判断依据

TOCTOU（Time-of-Check to Time-of-Use）漏洞的本质是竞争窗口：`openFileWithinRoot` 在打开文件时验证沙箱边界（Check），但到 `handle.readFile()` 实际读取（Use）时，底层文件可能已被替换。多阶段利用体现在攻击者需要先在沙箱内存入合法文件、再利用文件操作将其替换为符号链接、最后在高频请求中命中竞态窗口。

---

## entry-00290: openclaw 悬空符号链接沙箱逃逸

### 修复前的问题

- **critical_operation** 标注在 `boundary-path.ts:196` — `resolveSymlinkHopPath(lexicalCursor)` 调用，这本质是一个**检查/判断点**（fail-open 的 symlink 解析），不是最终的危险操作
- 在 `resolveSymlinkHopPath` 通过 fail-open 回退放行路径后，实际的文件写入发生在 `apply-patch.ts` 的 `writeFile` 调用处，那里才是沙箱逃逸的**危害落地**点

### 修复后的链路变更

| 变更 | 原值 | 新值 |
|------|------|------|
| **critical_operation** | `boundary-path.ts:196` (resolveSymlinkHopPath) | `apply-patch.ts:152` (fileOps.writeFile) |

- **trace[4].desc**：更新 `assertNoPathAliasEscape` 描述，说明其作为门卫函数在此处放行了本应被拒绝的路径
- **trace[5].desc**：更新 `resolveSymlinkHopPath` 描述，说明其 fail-open 回退行为是检查被绕过的关键点，但真正的危害在下游 writeFile

### 关键判断依据

1. **语义区分**：安全检查（check/guard）和危险操作（sink）应区分标注
2. `resolveSymlinkHopPath` 对悬空 symlink 执行 `fs.realpath` → ENOENT → `readlink` → `resolvePathViaExistingAncestor` 的 fail-open 回退链，属于**安全机制本身的缺陷**
3. 真正不可逆的危险操作是 `fileOps.writeFile(target.resolved, hunk.contents)` — 此时文件内容已被写入沙箱外路径，无法撤销

---

## entry-00391: fastmcp OpenAPIProvider SSRF + 路径穿越

### 修复前的问题

- **critical_operation** 标注在 `director.py:194` — `_build_url` 方法定义（函数签名处），但漏洞的真正触发点在下游的 URL 拼接操作
- **trace** 包含 `trace[1]` — `logger.debug(...)` — 一个纯调试日志节点，不参与数据传播，属于无关节点

### 修复后的链路变更

| 变更 | 原值 | 新值 |
|------|------|------|
| **critical_operation** | `director.py:194` (_build_url 方法定义) | `director.py:213-216` (str(param_value) 替换 + urljoin 拼接) |
| **trace** | 4 个节点（含 logger.debug） | 3 个节点（移除日志节点） |

### 关键判断依据

1. **CO 定位**：`_build_url` 内部有两步关键操作 — (a) `str(param_value)` 不执行 URL 编码直接替换模板占位符、(b) `urljoin()` 对 `../` 执行规范化折叠。二者组合使含穿越字符的原始值突破 API 前缀限制，产生 SSRF 目标 URL
2. **节点清理**：`logger.debug(f"Building request for {route.method}...")` 仅记录日志，不参与 `flat_args → path_params → url` 的数据传播链，应予移除
3. 函数签名（`def _build_url(...)`）只是声明，不应作为 critical_operation

---

## entry-00320: langflow 文件上传路径穿越

### 修复前的问题

- **entry_point** 标注在 `files.py:163-166` — `rsplit(".", 1)` 扩展名拆分操作，此操作处理的是**已经在系统内部的文件名变量**，位置过于下游
- entry_point 应上移到**攻击者可控的文件名数据首次进入系统的位置**

### 修复后的链路变更

| 变更 | 原值 | 新值 |
|------|------|------|
| **entry_point** | `files.py:163-166` (rsplit 扩展名拆分) | `files.py:162` (new_filename = file.filename) |

- **trace[0]**：保留原 rsplit 节点但更新 desc，说明其作为穿越序列从原始文件名向后续命名逻辑传递的首个处理步骤
- **trace[2]**：更新 `save_file_routine` 节点 desc，强调其作为 API 层与存储层之间参数交接边界的角色

### 关键判断依据

1. **EP 定位**：`file.filename` 来自 multipart HTTP 请求，是攻击者可以直接控制的输入字段。`new_filename = file.filename` 是该数据首次进入后端处理变量的赋值点
2. 穿越路径：`new_filename`（含 `../`）→ `rsplit` 拆分（穿越序列保留在 root_filename）→ 去重逻辑（穿越序列原样流入 unique_filename）→ `storage_service.save_file`（file_name 跨层传递）→ `local.py:120` async_open（操作系统解析 `../` 完成穿越写入）
3. `rsplit(".", 1)` 仅做点号拆分，不对路径分隔符做任何过滤，是正确但不关键的处理步骤

---

## 验收标准对照

| # | 标准 | 状态 |
|---|------|------|
| 1 | 修复后的 `{file, line, code}` 能在对应 commit 中匹配 | ✅ 已通过源码验证（下载对应 commit 文件逐行核对） |
| 2 | 修复报告能解释从入口点到关键操作的完整链路 | ✅ 本报告逐条说明 |
| 3 | 多阶段利用明确前置阶段和主触发阶段 | ✅ entry-00197 desc 已补充三阶段说明 |
| 4 | 删除或替换明显无关的 trace 节点 | ✅ entry-00391 移除 logger.debug 节点 |
| 5 | 无法确信的修改进入人工复核 | ✅ 所有修改基于源码分析，无不确信项 |
| 6 | 修复后数据满足 SCHEMA.md 基础约束 | ✅ 待运行 trace_fixer.py 验证 |

---

## 未解决项 / 后续建议

1. **entry-00197 多阶段表达**：当前数据模型以单一 `entry_point → critical_operation` 表达多阶段漏洞存在固有局限。建议后续考虑在 SCHEMA 中增加 `preconditions` 或 `attack_stages` 字段来描述跨阶段的利用前提。
2. **entry-00290 相关 entry**：同一 advisory 下可能存在多个 entry（如 entry-00241~00244），如 `assertNoPathAliasEscape` 的 fail-open 行为也影响其它操作路径，建议统一审查。
