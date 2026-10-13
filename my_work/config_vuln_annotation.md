# 配置类/非污点类漏洞标注规范

> 本文档针对 VulnGym 中"纯配置文件、非污点类"漏洞的标注原则进行说明，适用于 Issue #8 涉及的 CWE-250（Execution with Unnecessary Privileges）等配置类样本。

---

## 1. 背景与问题

VulnGym 现有 schema 的 `entry_point`、`critical_operation`、`trace` 三元组结构天然适配污点流漏洞（外部输入 -> 传播 -> 危害落地）。但对于纯配置类漏洞，不存在传统意义上的"外部输入传播链"，漏洞根因是**配置项的结构性缺失或失效**，强行套用污点流模式会导致以下问题：

1. **critical_operation 误选危害落地单点**：原标注将 `CMD ["bash"]` 或 `ENTRYPOINT [...]` 选为 critical_operation，但这只是运行时入口，并非漏洞根因。配置类漏洞的根因是"缺少 USER 指令"或"USER 指令被 sudoers 架空"，不是某个具体命令的执行。
2. **trace 伪数据流**：原标注将 Dockerfile 中顺序声明的多条指令（FROM、RUN、WORKDIR、CMD 等）拆成多节点 trace，模拟出一条"数据流"，但这些指令之间不存在数据依赖，仅是声明顺序。
3. **desc 复述代码**：原标注的 trace desc 大量复述每条指令的功能（如"WORKDIR /app 在 root 身份下创建工作目录"），未解释配置项为何构成漏洞关键节点。

---

## 2. 标注原则

### 2.1 分类：缺失型 vs 无效降权型

配置类特权漏洞分为两种子型：

| 子型 | 特征 | 示例 |
|------|------|------|
| **缺失型** | Dockerfile 全程无 `USER` 指令，所有层以 root 执行 | entry-00241/242/243 |
| **无效降权型** | 有 `USER` 指令但被 sudoers NOPASSWD:ALL 等机制架空，降权形同虚设 | entry-00244 |

### 2.2 entry_point：选择配置声明入口

- **选择**：`FROM` 指令所在行（始终为 line 1）
- **理由**：`FROM` 确立了基础镜像及其默认用户上下文（root），是整个配置传播链的起点。对于配置类漏洞，"入口"不是用户输入点，而是**特权上下文的声明起点**。
- **line**：`1`（整数类型，因为 FROM 始终在第 1 行）
- **code**：`FROM <image>:<tag>`
- **desc**：说明基础镜像的默认用户为 root，以及该文件是否存在 USER 指令（缺失型）或 USER 指令是否被架空（无效降权型）

### 2.3 critical_operation：选择结构性缺陷范围

- **缺失型**：选择**整个 Dockerfile 的范围**（`line: "1-N"`，N 为文件总行数），code 为完整文件内容。因为缺陷不是某一行的命令，而是"整个文件缺失 USER 指令"这一结构性事实。
- **无效降权型**：选择**降权失败的紧凑段**（如 `line: "17-20"`），仅覆盖 `RUN useradd + echo sudoers + USER app`。因为缺陷集中在 sudoers 授权与 USER 切换的矛盾上，不需要覆盖无关的构建步骤。
- **desc**：必须使用 `[缺失型缺陷]` 或 `[无效降权型缺陷]` 前缀，解释为何这是 CWE-250 的结构性问题，而非简单复述代码。

### 2.4 trace：折叠为单节点配置传播链

- **节点数**：1（折叠为单节点）
- **file/line/code**：与 critical_operation 完全相同
- **desc**：使用 `[配置传播链]` 前缀，按三段式描述：
  1. **声明端**：FROM 指令确立 root 默认上下文
  2. **降权端/构建端**：缺失型描述"所有 RUN 指令在 root 上下文中执行，无 USER 中断"；无效降权型描述"USER app 切换身份但 sudoers 使降权失效"
  3. **运行时端**：CMD/ENTRYPOINT 启动的容器主进程以 root（或 root 等价）身份运行
- **理由**：配置类漏洞不存在多步骤数据流，配置从声明到生效的传播路径是语义层面的（声明 -> 上下文继承 -> 运行时），而非代码行级别的。折叠为单节点可以避免伪数据流，同时完整描述传播链路。

### 2.5 line 字段格式约定

| 场景 | 类型 | 示例 |
|------|------|------|
| 单行（FROM 指令） | `int` | `1` |
| 整文件范围（缺失型） | `string` | `"1-23"` |
| 紧凑段（无效降权型） | `string` | `"17-20"` |

### 2.6 code 字段格式约定

- 多行内容使用 `\n` 连接，**末尾不加 `\n`**
- 必须与 commit 中对应 line 范围的原始文件内容逐字一致（包括空行）

---

## 3. 标注流程

```
1. 读取 Dockerfile 全文，判断子型：
   - 无 USER 指令 -> 缺失型
   - 有 USER 指令 + sudoers/setuid 等架空机制 -> 无效降权型

2. 确定 entry_point：
   - line = 1
   - code = FROM 指令
   - desc = 说明 root 上下文起点 + 子型特征

3. 确定 critical_operation：
   - 缺失型: line = "1-N", code = 完整文件
   - 无效降权型: line = "紧凑段", code = 降权相关指令
   - desc = [子型前缀] + 结构性缺陷解释

4. 确定 trace：
   - 单节点，file/line/code = critical_operation
   - desc = [配置传播链] + 声明端/降权端/运行时端三段式

5. 验证：
   - code 逐字匹配 git show <commit>:<file>
   - line 范围与 code 行数一致
   - desc 不复述代码，解释配置项为何构成漏洞
```

---

## 4. 样本对照

### 4.1 缺失型样本

| entry_id | 文件 | 总行数 | critical_operation.line | trace 节点数 |
|----------|------|--------|------------------------|-------------|
| entry-00241 | scripts/e2e/Dockerfile | 23 | "1-23" | 1 |
| entry-00242 | scripts/e2e/Dockerfile.qr-import | 9 | "1-9" | 1 |
| entry-00243 | scripts/docker/install-sh-e2e/Dockerfile | 14 | "1-14" | 1 |

### 4.2 无效降权型样本

| entry_id | 文件 | 降权段 | critical_operation.line | trace 节点数 |
|----------|------|--------|------------------------|-------------|
| entry-00244 | scripts/docker/install-sh-nonroot/Dockerfile | line 17-20 | "17-20" | 1 |

---

## 5. SCHEMA 兼容性

本标注方案完全在 SCHEMA v0.1.4 现有字段范围内实现，不引入任何新字段或破坏性变更：

- `line` 的 `int | "start-end"` 双形态：SCHEMA v0.1.4 正式支持
- `code` 的多行 `\n` 连接：SCHEMA v0.1.4 正式支持
- `trace` 的单节点形式：SCHEMA 允许 0~N 个节点
- `desc` 的可选性：所有节点均填写 desc，超出了 SCHEMA 的最低要求

**无需修改 SCHEMA.md。**

### 5.1 SCHEMA 适应性评估（Issue #8 交付物第 4 项）

针对 Issue #8 "如认为某些样本不适合当前 schema，请给出明确理由和替代建议"这一要求，我们的评估结论如下：

**结论：当前 SCHEMA v0.1.4 完全适用于配置类/非污点类漏洞，无需修改或扩展。**

逐项评估：

| SCHEMA 字段 | 配置类漏洞需求 | 适应性 | 说明 |
|-------------|-------------|--------|------|
| `entry_point` | 配置声明入口（FROM） | ✅ 完全适配 | file/line/code 可精确定位 FROM 指令 |
| `critical_operation` | 结构性缺陷范围 | ✅ 完全适配 | line 的 `"start-end"` 范围格式可覆盖整文件或紧凑段 |
| `trace` | 配置传播链 | ✅ 完全适配 | 单节点 trace 可表达声明端->降权端->运行时端的语义链路 |
| `desc` | 结构性缺陷解释 | ✅ 完全适配 | 自由文本可承载任意深度的解释 |
| `verify` | 人工审核标记 | ✅ 完全适配 | 0=自动标注，1=人工确认，语义清晰 |

**不适合理由（不适用）**：所有 4 个样本均可在现有 SCHEMA 下准确表达，不存在"schema 无法覆盖"的场景。

**替代建议（无）**：不需要新增字段或修改现有字段类型。现有 `line` 的双形态（`int` / `"start-end"`）和 `trace` 的弹性节点数已经提供了足够的表达空间。

---

## 6. 对后续同类漏洞的指导意义

本规范适用于以下类型的配置类漏洞标注：

- CWE-250（Execution with Unnecessary Privileges）- Dockerfile/k8s manifest 以 root 运行
- CWE-732（Incorrect Permission Assignment for Critical Resource）- 配置文件权限过宽
- CWE-276（Incorrect Default Permissions）- 默认权限不安全

核心思路：**配置类漏洞的 critical_operation 应描述结构性缺陷（缺失或失效），而非危害落地单点；trace 应描述配置传播链，而非伪数据流。**

---

## 7. 标注规范与表达质量优先（回应 Issue 备注）

Issue #8 明确指出："本任务重点是标注规范和表达质量，不是传统调用链追踪。"

我们的方案在以下几个层面贯彻了这一原则：

| 维度 | 传统调用链追踪思路 | 本方案标注规范思路 |
|------|------------------|------------------|
| **critical_operation** | 选择危害落地单点（如 CMD/ENTRYPOINT） | 选择结构性缺陷范围（整文件缺失 USER 或降权失效段） |
| **trace** | 拆分多节点模拟数据流（FROM->RUN->...->CMD） | 折叠为单节点配置传播链（声明端->降权端->运行时端） |
| **desc 重点** | 复述每条指令的功能（"WORKDIR 创建工作目录"） | 解释配置项为何构成漏洞（"缺失 USER 导致所有层以 uid=0 执行"） |
| **表达质量** | 7 节点 trace 中 5 个节点的 desc 仅复述代码 | 1 节点 trace 的 desc 包含三段式语义分析 |

**具体改进指标**：

- trace 节点数：241 从 7->1、242 从 5->1、243 从 5->1、244 从 7->1
- desc 字段全部从"代码复述"改为"结构性缺陷分析"
- critical_operation 从"危害落地单点"改为"根因范围"

这些改进的核心目标不是追踪调用链的精确度，而是**提升标注对配置类漏洞根因的表达质量**，使标注结果对下游消费者（漏洞分析、修复建议生成）更具解释价值。

---

## 8. 样本移除评估（回应 Issue 备注）

Issue #8 指出："如果最终判断某些样本应从当前 benchmark 子集移除，也需要给出充分依据。"

**结论：4 个样本（entry-00241~244）均不应从 benchmark 子集移除，应保留并按本方案修复标注。**

逐项评估：

| entry_id | 是否移除 | 依据 |
|----------|---------|------|
| entry-00241 | **不移除** | scripts/e2e/Dockerfile 确实以 root 运行所有进程，CWE-250 成立，原标注仅需优化表达方式 |
| entry-00242 | **不移除** | scripts/e2e/Dockerfile.qr-import 以 root 执行 pnpm install，供应链攻击面真实存在 |
| entry-00243 | **不移除** | scripts/docker/install-sh-e2e/Dockerfile 以 root 运行 ENTRYPOINT 进程，CWE-250 成立 |
| entry-00244 | **不移除** | scripts/docker/install-sh-nonroot/Dockerfile 的 sudoers NOPASSWD:ALL 使 USER app 降权失效，是 CWE-250 的经典无效降权案例 |

**不移除的理由**：

1. **漏洞真实性**：4 个样本均对应 GHSA-W7J5-J98M-W679 安全公告，且 Dockerfile 内容在 commit `c56fb7f` 中可验证，漏洞客观存在。
2. **标注可修复性**：原标注的问题不在样本本身，而在于用污点流模式标注配置类漏洞导致的不适配。通过本方案的标注规范，4 个样本均可在现有 SCHEMA 下准确表达。
3. **benchmark 价值**：4 个样本覆盖了配置类特权漏洞的两个子型（缺失型 3 个 + 无效降权型 1 个），对 benchmark 的 CWE-250 覆盖度有实质贡献。移除将导致 benchmark 在配置类漏洞类别上出现空白。
4. **多样性贡献**：entry-00244（无效降权型）是 benchmark 中罕见的"有 USER 指令但降权失效"案例，对评估漏洞检测工具的语义理解能力具有独特价值。
