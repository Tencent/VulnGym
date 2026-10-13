# VulnGym 链路重建修复报告

**涉及条目**: entry-00185 / entry-00197 / entry-00290 / entry-00320 / entry-00391
**报告时间**: 2026-07-07
**完成者**: Xiu11111
**任务来源**: [GitHub Issue #7](https://github.com/Tencent/VulnGym/issues/7)
**目标文件**: `data/entries.fixed.jsonl`（5 个 entry）

本轮修复针对 5 个存在"整体错位"或"多阶段利用"的样本进行调用链重建，保持 SCHEMA.md 约束不变。

---

## 一、任务概述

本任务针对 GitHub Issue #7 指定的 5 个存在"整体错位"或"多阶段利用"的 VulnGym 样本进行调用链重建。这些样本的共同特征是：节点能找到代码，但链路语义错位——要么入口/sink 定位在无关位置，要么单一入口点难以表达完整的多阶段利用过程。

---

## 二、逐条修复说明

### entry-00185: n8n ReadWriteFile 节点写入 .git 目录导致 RCE

**项目**: n8n
**漏洞类型**: 命令注入 / Git 配置注入触发任意命令执行
**问题类型**: 整体错位

#### 修复前问题

| # | 字段 | 原标注 | 问题 |
|---|------|--------|------|
| P1 | entry_point | write.operation.ts L46 `default: false,` | 静态默认值声明（append 选项属性定义），非数据入口 |
| P2 | critical_operation | file-system-helper-functions.ts L48 `}` | resolvePath 函数闭合括号，纯语法非 sink |
| P3 | trace | 4 节点 [L46, L75-82, L65, L48] | L46=静态声明噪声；L75-82=execute 循环样板噪声；L48=闭合括号错误。缺少真实入口 L70、写盘调用 L96-100、resolvePath L41、sink L128-131 |

#### 修复后链路

```
entry_point (L70) — fileName = this.getNodeParameter('fileName', itemIndex)
  ↓
trace[0] (L70) — 攻击者路径 fileName 进入（污点起点）
  ↓
trace[1] (L96-100) — writeContentToFile(resolvePath(fileName), content, flag) 交接
  ↓
trace[2] (L41) — resolvePath 调用 fsRealpath 规范化为绝对路径
  ↓
trace[3] (L65) — isFilePathBlocked return false 放行（.git 未在受限列表）
  ↓
critical_operation (L128-131) — fsWriteFile 写盘 → RCE
```

#### 关键判断依据

- **J1 入口用 L70**: fileName 经 getNodeParameter 在 L70 进入，L62 execute def 头不捕获路径入口
- **J2 sink 用 L128-131**: 危害在写盘瞬间实现，fsWriteFile 是最深真正 sink
- **J3 resolvePath 单列 L41**: 路径规范化是真实数据流步骤，原作者有意纳入但错指 L48 闭合括号
- **J4 L65 保留**: `return false;` 是 isFilePathBlocked 的放行点，有语义意义（非噪声）

---

### entry-00197: openclaw sandbox TOCTOU race condition

**项目**: openclaw
**漏洞类型**: 越界文件读取 / 沙盒逃逸
**问题类型**: 多阶段利用（TOCTOU）

#### 修复前问题

| # | 问题 | 说明 |
|---|------|------|
| P1 | TOCTOU 位置标错 | 原标注主张 check→read 窗口，但 fd 在 open 时钉死到 inode，read 不重解析路径 |
| P2 | trace 未体现真实 Check/Use | 缺少 fs-safe.ts 中的词法检查(L104)和 open 操作(L47) |
| P3 | 包含无关节点 | 大小检查(L46-49)和 TTL 检查(L51-55)在 open 之后，不在 TOCTOU 窗口内 |

#### 修复后链路

```
entry_point (L36) — const id = req.params.id; 外部输入进入
  ↓
trace[0] (L36) — id 提取（污点起点）
  ↓
trace[1] (L37) — isValidMediaId(id) 格式校验（限制为单分量，挡穿越不挡符号链接）
  ↓
trace[2] (L42-45) — openFileWithinRoot 调用（路由层→helper 层交接）
  ↓
trace[3] (L104) — isPathInside 词法边界检查 [CHECK 阶段]
  ↓ ↓ ↓ TOCTOU 时间窗口 (L104 → L47) ↓ ↓ ↓
trace[4] (L47) — fs.open 打开文件 [USE 阶段]
  ↓
critical_operation (L57) — handle.readFile() 读越界 fd [SINK]
```

#### 关键判断依据

- **fd 钉死原理**: 操作系统保证 fd 在 open 时绑定到 inode，后续 read 不重解析路径
- **真正 TOCTOU 窗口**: check(L104 词法检查) → open(L47)，而非 open→read
- **O_NOFOLLOW 缓解**: 已在 OPEN_READ_FLAGS 中部署（Linux 下），但窗口仍存在
- **isValidMediaId 限制**: 正则 `^[\p{L}\p{N}._-]+$` 不含 `/`，挡住穿越但挡不住符号链接

---

### entry-00290: openclaw 悬空符号链接沙箱逃逸

**项目**: openclaw
**漏洞类型**: 路径遍历 / 沙箱逃逸（符号链接跟随）
**问题类型**: critical 定位争议 + 多阶段利用

#### 修复前问题

| # | 问题 | 说明 |
|---|------|------|
| P1 | critical 定位争议 | 原标在 boundary-path.ts:L196（检查内部），但 desc 称"令 writeFile 逃逸"，存在表述不一致 |
| P2 | trace 包含噪声 | L106（applyPatch 调用路由噪声）、L281（三元运算符片段） |
| P3 | commit 状态未明确 | desc 描述 pre-fix 行为，但未注明 commit 已修复 |

#### 修复后链路

```
entry_point (L94) — execute: async (_toolCallId, args, signal) => {
  ↓
trace[0] (L94) — execute 接收 patch 参数（含悬空符号链接路径）
  ↓
trace[1] (L150) — resolvePatchPath 将 hunk.path 映射为 target.resolved
  ↓
trace[2] (L72) — assertNoPathAliasEscape 边界检查门卫 [CHECK 阶段]
  ↓
trace[3] (L196) — resolveSymlinkHopPath ENOENT 回退 → fail-open 误判 [CHECK 内部]
  ↓
critical_operation (L152) — fileOps.writeFile 沿悬空链接写入沙箱外 [ESCAPE/SINK]
```

#### 关键判断依据

- **critical 定位说明**: 本修复将 critical_operation 定位在 writeFile(L152)，理由是此处为最终危害落地点；另一种理解是将 critical 标在 boundary-path.ts:196（fail-open 决策点），认为根因是检查逻辑缺陷。两种理解均合理，本修复选择前者以保持与其他样本（如 entry-00185 的 fsWriteFile）的一致性。
- **多阶段表达**: trace 显式表达 CHECK(L72/L196)→ESCAPE(L152) 两阶段，与 entry-00197(TOCTOU) 同型。
- **commit 8b5ebff6 已修复**: 测试 L53-82 证明已修复 dangling symlink 逃逸，desc 和 vuln_title 均注明 pre-fix 状态。

---

### entry-00320: langflow 文件上传路径穿越

**项目**: langflow
**漏洞类型**: 路径穿越 / 任意文件写入
**问题类型**: 整体错位

#### 修复前问题

| # | 问题 | 说明 |
|---|------|------|
| P1 | entry_point 错位 | 标在 L163-166（rsplit 块），是"第一次变换操作"而非"输入进入处" |
| P2 | trace 包含死分支 | L119-122（`if not file_name: file_name = file.filename`）永不执行 |
| P3 | trace 顺序颠倒 | 原序 163→205→119→local.py:120 与真实调用流相反 |

#### 修复后链路

```
entry_point (L162) — new_filename = file.filename 外部输入首次进入
  ↓
trace[0] (L162) — file.filename 绑定到 new_filename（污点起点）
  ↓
trace[1] (L163-166) — rsplit 拆分（穿越片段保留在 root_filename）
  ↓
trace[2] (L214) — unique_filename 拼接（穿越序列烘焙进最终文件名）
  ↓
trace[3] (L125) — storage_service.save_file 跨层交接（API→存储服务）
  ↓
trace[4] (L116) — file_path = folder_path / file_name 路径拼接（无 resolve/realpath）
  ↓
critical_operation (L120) — async_open 写盘到逃逸路径 [SINK]
```

#### 关键判断依据

- **entry_point 取 L162**: `new_filename = file.filename` 是攻击者可控路径首次进入处理变量处
- **死分支删除**: L119-122 的 `if not file_name` 分支永不执行（unique_filename 恒非空）
- **trace 顺序按调用序**: 214→125 在同文件内行号回退是正确的（125 属于 save_file_routine，被 upload_user_file 在 218 行调用）

---

### entry-00391: fastmcp OpenAPIProvider SSRF + 路径穿越

**项目**: fastmcp
**漏洞类型**: SSRF / 路径穿越辅助 SSRF
**问题类型**: 整体错位

#### 修复前问题

| # | 问题 | 说明 |
|---|------|------|
| P1 | sink 错位 | critical_operation = L194 `def _build_url(`（方法头），非真正危险语句 |
| P2 | trace 噪声节点 | trace[1] = L40-44（logger.debug + Step1 注释），调试日志非数据流步骤 |
| P3 | trace 缺口 | 从 L114-115 直接跳到 L194 方法头，缺调用点、注入点、真正 sink |

#### 修复后链路

```
entry_point (L23-28) — def build(route, flat_args, base_url) 接收外部参数
  ↓
trace[0] (L23-28) — build 方法签名（入口边界，flat_args 接管）
  ↓
trace[1] (L45-47) — _unflatten_arguments 调用（flat_args 跨方法边界）
  ↓
trace[2] (L114-115) — path_params[openapi_name] = value（原值入字典，无编码）
  ↓
trace[3] (L54) — _build_url 调用（path_params 跨方法到 URL 构造）
  ↓
trace[4] (L210-213) — url_path.replace(placeholder, str(param_value))（原值注入模板）
  ↓
critical_operation (L216) — urljoin 折叠 ../ → SSRF [SINK]
```

#### 关键判断依据

- **sink 取 L216 urljoin**: urljoin 对路径中的 `../` 做规范化折叠，SSRF 危害在此实现
- **删除 logger 噪声**: L40-44 的 logger.debug 不是数据流步骤
- **补全中间节点**: L54 调用点、L210-213 注入点、L216 sink 均新增

---

## 三、本次验收中发现的额外问题及修正

在 2026-07-07 的自动化验证中，发现并修正了 2 个额外问题：

### 问题 1: entry-00197 trace[2] line 范围不匹配

- **问题**: code 字段包含 4 行（L42-L45），但 line 标为 `42-44`
- **修正**: line `42-44` → `42-45`
- **验证**: 修正后源码匹配检查通过

### 问题 2: entry-00391 entry_point 与 trace[0] 不一致

- **问题**: entry_point line=23 (int)、code=`    def build(`（单行），与 trace[0] line="23-28" (range)、code=完整方法签名不一致
- **修正**: 将 entry_point 的 line 改为 `23-28`，code 改为完整方法签名（与 trace[0] 一致）
- **验证**: 修正后 entry_point==trace[0] 检查通过

---

## 四、无法确信的样本

所有 5 个样本均已完成修正，无无法确信的样本。所有修改均有源码验证和逻辑依据。

---

## 五、数据模型改进建议

在本次修正过程中，未发现当前数据模型无法表达的漏洞类型。现有的 `entry_point` + `trace` + `critical_operation` 模型能够充分表达：

- 单阶段漏洞（entry-00185, entry-00320, entry-00391）
- 多阶段利用（entry-00197 TOCTOU, entry-00290 CHECK→ESCAPE）

对于多阶段利用，通过在 desc 中标注阶段关键词（CHECK/ESCAPE/TOCTOU/时间窗口等）即可清晰表达，无需修改数据模型。

---

## 六、验收结论

### 自动化验证结果

```
总检查项: 474
通过: 474
失败: 0
警告: 0

最终判定: ALL PASS - 所有 entry 符合 GitHub Issue #7 验收标准
```

### 验收标准达标情况

| 验收标准 | 结果 |
|---------|------|
| 1. 源码匹配 + desc 准确 | ✅ 37 节点全部匹配 |
| 2. 链路完整性 | ✅ 所有链路完整闭环 |
| 3. 多阶段利用表达 | ✅ 2 个多阶段 entry 明确表达 |
| 4. 无关节点清理 | ✅ 无噪声节点 |
| 5. 人工复核标记 | ✅ 所有 verify=0 |
| 6. SCHEMA 约束 | ✅ 10 条 Invariants 全部满足 |

**所有 5 个 entry 均符合 GitHub Issue #7 的全部验收标准，可直接提交。**
