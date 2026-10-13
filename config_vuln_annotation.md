# config_vuln_annotation.md — 配置类 / 非污点类漏洞标注规范

> 适用对象：VulnGym 中根因为**配置缺陷**而非**外部输入经数据流传播至危险操作（污点类）**的样本。
> 典型场景：Dockerfile 以 root / 不必要特权运行（CWE-250）、危险配置项、缺失安全约束、不安全默认配置（BL-INSECURE-DEFAULT）等。
> 本规范**不新增、不删除任何字段**，完全在 `SCHEMA.md` 现有 `entry_point` / `critical_operation` / `trace` / `verify` 语义内工作，保证向后兼容。

---

## 1. 为什么需要单独规范

`SCHEMA.md` 的 `entry_point` 定义为 "Reachable entry point（可达入口）"，`critical_operation` 为 "Critical operation (core defect location)"。这套语义天然贴合**污点类漏洞**：entry_point = 外部输入进入系统的位置，critical_operation = 危险操作（sink），trace = 污点传播链。

但配置类漏洞通常**不存在可达的外部入口，也没有攻击者可控的污点**。例如 "容器以 root 运行"：没有 HTTP 端点、没有用户输入，漏洞是**配置声明本身**造成的状态缺陷。若仍机械地把 entry_point 理解为 "运行时可达入口"，会导致：

- entry_point 被迫指向一个并不"可达"的位置（如 `FROM` 指令），语义牵强；
- desc 容易退化成"该步骤以 root 运行"的复述，而非解释**为什么这是漏洞关键节点**。

因此需要在不破坏 schema 的前提下，明确配置类漏洞的字段映射原则。

---

## 2. 字段映射原则

### 2.1 `entry_point` — 配置基线锚点（配置生效入口）

- **选择**：确立漏洞特权 / 不安全上下文的**配置声明**，即整条配置链中"不安全状态由此开始"的那一行。
- **对"容器以 root 运行"**：选 `FROM <image>` 行。
  - 理由：基础镜像默认用户为 root（uid=0），且后续无 `USER` 指令覆盖（或被 sudo 架空），该行使整条镜像继承 root 特权上下文，是所有后续 RUN / CMD / ENTRYPOINT 的特权来源。
- **不要**选"缺失的 USER"——它无法指向具体行；缺失类缺陷通过 `trace` / `desc` 表达。
- **语义声明（关键）**：配置类漏洞的 `entry_point` **≠ 运行时可达入口**，而是**配置生效起点 / 特权基线锚点**。其 `desc` 必须显式声明这一语义，避免与污点类 entry_point 混淆。

### 2.2 `critical_operation` — 漏洞兑现点（缺陷落地点）

- **选择**：不必要特权被**具体兑现 / 被利用**的那一行配置指令，即"危险在此实际发生"的节点。
  - **运行时兑现**：`CMD` / `ENTRYPOINT` 以 root（或等效 root）启动进程。
  - **构建期兑现**：若 Dockerfile 无显式 CMD / ENTRYPOINT（沿用基础镜像默认进程），选**最具安全相关性的 root 特权操作**（如以 root 执行的依赖安装 `RUN pnpm install`——其 install 脚本即供应链攻击面）。
- **desc 必须解释"为什么这一行构成漏洞关键节点"**，例如：
  - 进程以 uid=0 运行 → 容器逃逸门槛降低、危害半径扩大；
  - root 安装 → 恶意依赖可借完整 root 写权限触达系统路径。
  而非复述"该指令以 root 运行"。

### 2.3 `trace` — 配置声明到生效的传播路径

- **表达**：从 `entry_point` 的特权基线，经各构建阶段，到 `critical_operation` 的**配置传播链**。
  - 类比污点流，但传播的是"特权 / 不安全状态"，而非"攻击者数据"。
- 每个节点 `desc` 解释该步骤对**特权状态的作用**（继承 / 传递 / 固化 / 兑现），而非仅"以 root 运行"。
- 对"看似降权却被架空"的样本（如 `USER app` + `NOPASSWD:ALL` sudo），**必须在 trace 中显式标注被架空的降权节点及其原因**（见 entry-00244）。

---

## 3. 向后兼容的补充建议（不强制，不破坏 `SCHEMA.md`）

当前字段足以表达配置类漏洞，但为提升可解释性与可检索性，建议在未来 minor 版本（保持向后兼容）考虑新增**可选**字段：

| 建议字段 | 作用 | 兼容性 |
|---|---|---|
| `analysis_type`: `"taint"` \| `"config"` | 区分分析类型，便于评测器 / 统计按类型拆分 | 可选新增，不影响现有字段 |
| `root_cause_line` | 直接指向根因配置行（如 sudoers 行），弥补"缺失 USER 无行可指"的表达缺口 | 可选新增；当前可用 trace 节点近似 |
| `entry_point.role` / `critical_operation.role`: `"config-anchor"` / `"realization"` | 消歧义，明确配置类下两字段的语义角色 | 可选子字段，不影响现有匹配逻辑 |

以上均为**可选扩展**，不改动现有字段类型与含义，现有评测器（`evaluate.py`）无需修改即可继续工作。

---

## 4. 验收自检清单（针对每条配置类样本）

- [ ] `entry_point` 指向配置基线锚点（`FROM`），`file/line/code` 在对应 commit 可匹配。
- [ ] `critical_operation` 指向特权兑现点（`CMD` / `ENTRYPOINT` 或最具安全相关性的 root 操作）。
- [ ] `trace` 完整表达 `FROM → … → critical_operation` 的特权传播。
- [ ] 所有 `desc` 解释"为什么"，不简单复述代码。
- [ ] 未新增 / 删除字段；`verify` 可置 `1` 标记人工审计通过。
- [ ] 满足 `SCHEMA.md` 全部基础约束（line ≥ 1、无被禁内部字段、verify ∈ {0,1}）。

---

## 5. 本次修复样本（entry-00241 ~ entry-00244，GHSA-W7J5-J98M-W679）

| entry_id | file | entry_point（锚点） | critical_operation（兑现点） | 根因 |
|---|---|---|---|---|
| entry-00241 | scripts/e2e/Dockerfile | `FROM node:22-bookworm` (L1) | `CMD ["bash"]` (L23) | 全程无 USER，root 贯穿至运行时 |
| entry-00242 | scripts/e2e/Dockerfile.qr-import | `FROM node:22-bookworm` (L1) | `RUN pnpm install` (L9) | 无 USER；root 跑依赖安装（构建期兑现） |
| entry-00243 | scripts/docker/install-sh-e2e/Dockerfile | `FROM node:22-bookworm-slim` (L1) | `ENTRYPOINT [...]` (L14) | 无 USER，root 运行安装脚本 |
| entry-00244 | scripts/docker/install-sh-nonroot/Dockerfile | `FROM ubuntu:24.04` (L1) | `ENTRYPOINT [...]` (L29) | `USER app` 被 `NOPASSWD:ALL` sudo 架空，形式降权失效 |

四者 `entry_point` 统一锚定 `FROM`（特权基线），`critical_operation` 统一锚定特权兑现点；`trace` 已正确表达特权传播（entry-00244 含 sudoers 架空节点）。本次仅重写 `entry_point.desc` / `critical_operation.desc` 以体现上述原则，并将 `verify` 置 `1`（人工审计通过）；`file/line/code` 与 `trace` 逐字保留，未引入任何 schema 变更。
