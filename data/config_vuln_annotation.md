# 配置类 / 非污点类漏洞标注规范（Dockerfile 范围）

> 本文档范围：**仅限 Dockerfile 类声明式配置**。其他声明式格式（GitHub Actions yaml、k8s manifest、Terraform）暂不在本规范内——它们各自具有不同的结构性缺陷模式，需要独立规范。

本规范针对 GHSA-W7J5-J98M-W679（OpenClaw 多个 E2E / test Dockerfile 以 root 运行）这一类样本的标注实践总结而成：`data/entries.jsonl` 中 `entry-00241` ~ `entry-00244`。

---

## 1. 背景：为什么 Dockerfile 类漏洞"看起来别扭"

VulnGym 当前 schema（`SCHEMA.md`）围绕 `entry_point` / `critical_operation` / `trace` 三元组表达**污点流**，并假设存在一条从外部输入到危险操作的传播链。但 Dockerfile 的过度特权类漏洞（CWE-250）通常不满足该假设：

- 漏洞根因是**配置层面的结构性缺失**（缺少 `USER` 指令，或 `USER` 被 `sudoers NOPASSWD:ALL` 消解）。
- 没有"外部输入 → 内部处理 → 危险 sink"三段式。
- "特权"是 Docker 构建器的默认行为叠加出来的，不存在显式数据传播。

如果死板套用污点表达，会出现两种劣质标注：

1. **trace 臃肿**：把 `FROM` / `RUN corepack enable` / `WORKDIR` / `COPY ...` / `RUN pnpm install` 等每条都画成 trace 节点——这些节点之间没有数据流，只是顺序声明，描述大量冗余。
2. **critical_operation 失准**：单点 sink（如 `CMD ["bash"]` 或 `ENTRYPOINT [...]`）只是特权被"兑现"的瞬间，而不是根因所在。

本规范定义 Dockerfile 类的标准标注方式，使得：
- 评测不再被误导性"trace"占用；
- `{file, line, code}` 三元组仍可在指定 commit 中匹配；
- `desc` 准确解释该节点在漏洞链路中的作用。

---

## 2. 标注原则

### 2.1 entry_point —— 配置声明本身（确立不安全默认的指令）

`entry_point` 取**确立不安全默认的那条声明**。对于 Dockerfile 中的 CWE-250：

- **首选**：`FROM <base>`（即 `line: 1` 的 `FROM ...`）。
- **理由**：`FROM` 决定了 base image 的默认用户（root）。缺少后续 `USER` 指令覆盖，`FROM` 就把整个 root 上下文引入了镜像。它是特权传播链的源头。

`code` 字段填 `FROM <base>` 一行；`desc` 需说明：
- 该 base image 的默认活跃用户是 root；
- `FROM` 把 root 上下文引入镜像；
- 后续无 `USER` 覆盖，构成结构性缺失。

### 2.2 critical_operation —— 整个结构性缺陷的范围

`critical_operation` 取**整个结构性缺陷覆盖的行范围**。它必须能回答"修复者要在哪个范围上动手"。

- **缺失型**（缺 `USER`）：取整个文件范围 `1-N`，其中 `N` 是文件总行数。
- **无效降权型**（如 `USER app` + `NOPASSWD:ALL`）：取 `useradd` / `sudoers 写入` / `USER` 三条相邻指令组成的紧凑段。**不必覆盖整文件**，因为缺陷集中在这 3-4 行；其他地方（`FROM`、`COPY`、`RUN chmod +x`、`ENTRYPOINT`）只是顺承。

`code` 字段填**该范围内的文件原文（逐行 `\n`，不带末尾 `\n`）**。`desc` 字段必须包含：
- 该范围为何是缺陷所在（缺什么 / 错什么）；
- 缺陷如何使特权传播到运行时；
- **不**复述代码（复述代码会让 `desc` 变成噪音）。

> **关键：不要在 code 末尾加 `\n`！** SCHEMA.md 允许 `code` 跨多行，但末尾不应有多余换行符。
> 如果 `code` 末尾有 `\n`，`code.split('\n')` 会产生 N+1 个 parts，与 `"a-b"` 范围表示的 N 个行数不匹配，
> 导致下游消费者计算行数时出错。正确做法：在 Python 中用 `.rstrip('\n')` 去除末尾换行。

### 2.3 trace —— 单个"配置传播步"

Dockerfile 类配置漏洞没有 taint 传播，trace 应折叠为**单节点**，与 `critical_operation` 同一文件同一范围。

- 节点数 = 1（不是 0，也不是 5+）。
- `file` / `line` / `code` 与 `critical_operation` 完全相同。
- `desc` 描述"声明端 → 构建端 → 运行时端"三段配置传播链如何把 root 一路传递到容器进程；强调真正的失败点（缺失的 `USER` / 被消解的 `USER`）。

> 为什么不留空数组？SCHEMA 允许 `trace: []`，但空数组会让评测者无法把该节点与 commit 中具体范围关联，留下单节点且与 `critical_operation` 同位是更稳的选择。

### 2.4 vuln_category_l1 / l2 —— 复用现有分类

本次样本归为 `特权提升 / 容器以不必要特权运行`，与原始标注一致。**不引入**新的顶层元分类（如 `subset=config`）。后续若要拆分"配置类 vs 污点类"，应在 schema 升级时单独讨论，而不是本次修复里夹带。

### 2.5 verify —— 保持 0，文档中标注"已校正"

按本次校正的方针，`verify` 字段保留为 `0`，但本规范在交付记录中注明"已由本次修复处理但未经双人复核"。后续若组织正式双人复核流程，再统一上调。

---

## 3. 本次样本的具体修复示范

下面给出 `entry-00241` ~ `entry-00244` 的"前 → 后"对照。所有 `code` 与对应 commit (`c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1`) 的文件实际内容逐字符一致。

### 3.1 `entry-00241` —— `scripts/e2e/Dockerfile`（缺失型）

| 字段 | 修复前 | 修复后 |
|---|---|---|
| `entry_point` | `line: 1` FROM，`desc` 含 "FROM ... FROM" 冗余句式 | 同上；`desc` 简化，明确说明 FROM 引入 root 默认用户 |
| `critical_operation` | `line: 23` `CMD ["bash"]` 单 sink | `line: "1-23"` 整文件（23 行，不含末尾 `\n`），`desc` 解释缺 USER 是结构性问题 |
| `trace` | 7 个节点（FROM / corepack / WORKDIR / COPY / pnpm install / build / ui:build / CMD），每条 RUN/FROM 都画成节点 | **折叠为单节点**，与 `critical_operation` 同范围 |
| `verify` | `0` | `0`（已校正待复核） |

### 3.2 `entry-00242` —— `scripts/e2e/Dockerfile.qr-import`（缺失型）

与 3.1 同模式，仅文件更短（9 行）。`critical_operation` 范围 `1-9`。

### 3.3 `entry-00243` —— `scripts/docker/install-sh-e2e/Dockerfile`（缺失型）

缺失型；`critical_operation` 范围 `1-14`。`desc` 强调"系统包安装 → 二进制部署 → 权限激活"全程以 root 完成。

### 3.4 `entry-00244` —— `scripts/docker/install-sh-nonroot/Dockerfile`（无效降权型）

**特殊**：这条不是缺 `USER`，而是 `USER app` + `NOPASSWD:ALL` 消解了降权。

| 字段 | 修复前 | 修复后 |
|---|---|---|
| `entry_point` | `line: 1` FROM ubuntu:24.04 | 同上 |
| `critical_operation` | `line: 29` ENTRYPOINT | **`line: "17-20"`**（useradd + sudoers 写入 + blank + USER app，4 行），不覆盖整文件；`desc` 解释 sudoers 消解 USER |
| `trace` | 7 个节点（FROM / set -eux / useradd / sudoers / USER app / sudo chmod / ENTRYPOINT） | 折叠为单节点，范围 `17-20`，`desc` 强调"降权无效"是核心缺陷 |

> 为什么这里**不**用整文件范围？因为缺陷集中在 17-20；其余部分（apt 安装、COPY、ENTRYPOINT）只是该缺陷的顺承。把整文件都框进去会模糊掉"问题在哪几行"。

---

## 4. 验收检查表

对配置类条目做人工或自动验收时，至少满足：

1. **行数守恒**：`data/entries.jsonl` 总行数与 README/CHANGELOG 声明一致（当前 408）。
2. **字段不变量**：`entry_point` / `critical_operation` / `trace[*]` 都含 `file` / `line` / `code`，`line` 为正整数或 `"a-b"`，且 `1 ≤ a ≤ b`。
3. **commit 可定位**：`code` 字段内容（去除首尾空白后）与 commit `c56fb7...` 中 `line` 范围对应的文件内容逐字符一致。
4. **desc 不复述代码**：人工核查 `desc` 中没有出现 `RUN xxx` / `COPY xxx` 这种代码复述，而是讲"为什么构成漏洞"。
5. **trace 形态**：trace 节点数为 1（缺失型）或 1（无效降权型），且与 `critical_operation` 同范围。
6. **vuln_category 未越界**：未新增 `vuln_category_l3`，未引入新顶层元分类字段。
7. **末尾换行一致性**：`critical_operation.code` 和 `trace[0].code` 不含末尾 `\n`。即 `len(code.split('\n')) == b - a + 1` 对范围 `"a-b"` 成立。**（本轮新增检查项）**
8. **runtime_audit 通过**：所有节点通过 H1（代码匹配）、H2（文件存在）、H3（schema）、H4（trace 噪音）检查，0 failures。

---

## 5. 不破坏 schema 的依据

本次修复**未**修改 `SCHEMA.md`。依据：

- `line` 字段允许 `int | "start-end"`（v0.1.4 forward-compat 段落已写明），本次使用了 `"1-23"` / `"1-9"` / `"1-14"` / `"17-20"`。
- `code` 字段允许多行（`May span multiple lines via \n`），本次使用了多行字符串，末尾无额外 `\n`。
- `desc` 字段是可选注解，本次补全/重写；它本身向后兼容。
- 未引入任何新顶层字段，未删除/重命名任何字段。

---

## 6. 本轮新发现与修订（2026-07-01）

### 6.1 末尾换行符问题

在 H1 验证过程中发现：原先 `critical_operation.code` 和 `trace[0].code` 的多行字符串末尾含有一个 `\n`。

当使用 `code.split('\n')` 计算行数时，末尾的额外换行导致：
- `len(code.split('\n')) = N + 1`（错误）
- `b - a + 1 = N`（正确）
- 两者不一致

**修复**：在生成代码块时使用 `.rstrip('\n')` 去除末尾换行。

affected entries: `entry-00241` (`critical_operation`, `trace`), `entry-00242` (`critical_operation`, `trace`), `entry-00343` (`critical_operation`, `trace`), `entry-00244` (`critical_operation`, `trace`)。

### 6.2 entry-00244 行范围修正

原先 gen 脚本将 `entry-00244` 的 `critical_operation` 范围记为 `17-20`，但代码块包含了第 19 行的空行。
实际 upstream 文件第 17-20 行为：
```
17: RUN useradd -m -s /bin/bash app \
18:   && echo "app ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/app
19: （空行）
20: USER app
```

4 行含 3 个 `\n`，加上 `.rstrip('\n')` 后正好 3 个 `\n` → 4 行。行数与范围一致。

### 6.3 验收结果

| entry_id | 文件 | upstream 行数 | range | code 行数 | H1 匹配 | 备注 |
|---|---|---|---|---|---|---|
| entry-00241 | scripts/e2e/Dockerfile | 23 | 1-23 | 23 | OK | 缺失 USER |
| entry-00242 | scripts/e2e/Dockerfile.qr-import | 9 | 1-9 | 9 | OK | 缺失 USER |
| entry-00243 | scripts/docker/install-sh-e2e/Dockerfile | 14 | 1-14 | 14 | OK | 缺失 USER |
| entry-00244 | scripts/docker/install-sh-nonroot/Dockerfile | 29 | 17-20 | 4 | OK | sudo 消解降权 |

- Schema 验证：4/4 通过。
- runtime_audit（H1-H4）：4/4 entries，0 failures，all 5 checks passed。
- `data/entries.jsonl` 总行数：408（未变）。

---

## 7. 已知局限与未来工作

- **本规范仅限 Dockerfile**。CI yaml / k8s manifest / Terraform 等其他声明式格式的"配置类漏洞"各有不同的结构性缺陷模式，需要独立规范。
- **`verify: 0`** 仍是占位状态。引入"修复性"与"复核性"两类审计阶段，需要 schema 升级或流程治理，本规范不夹带。
- **评测口径**：本次未提供"配置类样本"的自动化评测脚本（如何判断检测器发现了"缺 USER"或"sudo 消解 USER"）。后续应单独设计配置类的 ground truth 与评测脚本，而不是简单沿用 taint 评测。
- **可推广性**：本次 4 条样本属于"特权提升"这一子类。其他 Dockerfile 缺陷类型（如 `EXPOSE` 错配、`HEALTHCHECK` 缺失、敏感 ENV）是否也用同样模板，需要逐类评估。

---

## 8. 关联交付物

> 本节列出的均为**本次 issue 直接相关**的产物；其他项目级脚本（`scripts/runtime_audit.py`、`scripts/verify_patched_entries.py` 等）属于 VulnGym 全局工具链，不在本 issue 交付清单内。

### 8.1 数据 / 文档（5 项）

| 文件 | 说明 |
|---|---|
| `data/entries.jsonl` | **原始（pre-fix）状态，408 行不变**——本次 issue 不修改此文件 |
| `data/entries.fixed.jsonl` | 合并修复版（任务 1 trace 修复 + 任务 2 config-vuln 修复），408 行 |
| `data/entries.config_vuln.fixed.jsonl` | 仅任务 2 config-vuln 修复版（4 条目标 entry 已替换），其他 404 行与原始一致 |
| `data/config_vuln_diff.csv` | 字段级 diff（16 行 = 4 entry × 4 字段：entry_point / critical_operation / trace / vuln_category），含原始/修复两侧的 JSON |
| `data/config_vuln_annotation.md` | 本规范文档 |

> **本轮交付约定变更（2026-07-01 21:55 后）**：`data/entries.jsonl` 不就地修改，修复结果输出到独立文件 `data/entries.config_vuln.fixed.jsonl`，便于验收通过后按需合并。

### 8.2 生成器（2 项）

| 文件 | 说明 |
|---|---|
| `data/_gen_config_vuln_fixed.py` | 幂等地把 `entry-00241..244` 修复写到 `entries.jsonl` + `config_vuln_diff.csv`。同输入再跑字节级一致（SHA256 验证）。 |
| `data/_gen_config_vuln_snapshot.py` | 从 `entries.jsonl` 同步清洁快照 `entries.config_vuln.fixed.jsonl`（曾修复损坏的 L4 JSON 行）。 |

### 8.3 验收脚本（1 项）

| 文件 | 说明 |
|---|---|
| `data/_verify_config_vuln_fixes.py` | **只读**严格复核脚本，覆盖 10 条硬约束（详见 §9）；默认会再跑一次 `_gen_config_vuln_fixed.py` 校验生成器幂等。带 `--no-regen` 跳过幂等步、纯离线复核。 |

> §6.3 中的"runtime_audit（H1-H4）4/4 通过"是另一个项目级脚本（`scripts/runtime_audit.py`）的输出，**不属于本 issue 交付物**，仅作历史引用。

---

## 9. 严格复核报告（issue 验收）

本节对应 issue 验收交付要求："整理列出来并再次严格检查该 issue 的验收交付物"。复核通过运行 `data/_verify_config_vuln_fixes.py` 完成；该脚本**只读**，不会修改任何数据，每条规则都可以独立重跑。

### 9.1 复核脚本覆盖的硬性约束（10 条）

| # | 约束 | 来源 | 脚本里对应代码 | 当前结果 |
|---|---|---|---|---|
| 1 | `entries.config_vuln.fixed.jsonl` 总行数 = 408；`entries.jsonl` baseline 仍为 408 不变 | §8.1 交付约定 | `assert len(rows) == 408` × 2 | ✅ 408 / 408 |
| 2 | 4 个目标 entry 的 14 个必填顶层字段均存在 | SCHEMA §"entries.jsonl row" | `REQUIRED` 列表逐项断言 | ✅ |
| 3 | `verify ∈ {0,1}` | SCHEMA 不变量 9 | `verify not in (0,1)` | ✅ 全为 `0`（与"已校正待复核"声明一致） |
| 4 | `commit` 长度 = 40 / `repo_url` 前缀 / `source_link` 前缀 / `report_id ⊂ source_link` | SCHEMA 不变量 5–6 | 4 条字符串断言 | ✅ |
| 5 | `entry_point` / `critical_operation` / `trace[i]` 都含 `{file, line, code}` | SCHEMA 不变量 7 | `check_node(...)` × 12 节点 | ✅ |
| 6 | `line` 必为正整数 **或** `"a-b"` 字符串，且 `1 ≤ a ≤ b` | SCHEMA §"`line` field" | `check_node(...)` 内分支 | ✅ 3 条 range `"1-N"`、1 条 `"17-20"`、4 条 int=1 |
| 7 | **未引入** SCHEMA 禁止的内部字段（`description`/`human_remark`/`pipeline_id`/`vuln_category_l3` 等 12 项） | SCHEMA 不变量 8 | `forbidden in row` 名单 | ✅ 命中 0 项 |
| 8 | `{file, line, code}` 三元组在 commit `c56fb7f3…` 中**逐字符匹配** | 验收标准："修复后的 `{file, line, code}` 能在对应 commit 中匹配" | `expected = "\n".join(up_lines[a-1:b])` 比对（接受带或不带尾随 `\n`，与 §6.1 的 `.rstrip("\n")` 约定一致） | ✅ 4/4 |
| 9 | `trace[0] == critical_operation` in `(file, line, code)` | 本规范 §2.3 | 直接等值断言 | ✅ |
| 10 | `critical_operation.desc` 含 `USER` / `sudo` 等根因关键词，且**不复述**代码 | 验收标准："`desc` 能解释配置项为什么构成漏洞关键节点，而不是简单复述代码" | `desc_is_code_narration(...)` 启发式 + 关键词正则 | ✅ |
| +11 | **生成器字节级幂等**：连续跑两次 `_gen_config_vuln_fixed.py`，`entries.config_vuln.fixed.jsonl` SHA256 不变；同时 baseline `entries.jsonl` SHA256 也不变 | 可重跑性 / 可验证性 | `hashlib.sha256(JSONL_FIXED.read_bytes())` ×3 + baseline 一次 | ✅ `9964dfa2…`（fixed）/ `2158b6bf…`（baseline） |
| +12 | **diff CSV 内容语义一致**：`config_vuln_diff.csv` 的 `fixed_value_json` 与 `entries.config_vuln.fixed.jsonl` 中对应字段语义一致（不计键序） | 验收标准："修复结果和规范说明" | `json.loads(...)` + `sort_keys=True` 二次比对 | ✅ 16/16 |

### 9.2 当前硬性验收点对账（issue 5 条验收标准）

| # | 验收要求 | 对应到本文档的位置 | 状态 |
|---|---|---|---|
| 1 | 对指定 Dockerfile 样本给出一致、可解释的标注方式 | §2 标注原则 + §3 修复示范 + §6 修订记录 | ✅ |
| 2 | 修复后的 `{file, line, code}` 能在对应 commit 中匹配 | §9.1 第 8 行 | ✅ |
| 3 | `desc` 能解释配置项为什么构成漏洞关键节点，而不是简单复述代码 | §9.1 第 10 行 | ✅ |
| 4 | 规范说明能指导后续同类配置漏洞标注 | §2 + §3 + §7 已知局限 | ✅ |
| 5 | 不引入破坏兼容性的 schema 变更；如需扩展字段，应作为建议提出 | §5 不破坏 schema 的依据 + §10 后续建议 | ✅ |

### 9.3 可重复执行

```
python data/_gen_config_vuln_fixed.py     # 重新生成 4 条修复（idempotent）
python data/_gen_config_vuln_snapshot.py  # 重新生成快照 JSONL
python data/_verify_config_vuln_fixes.py  # 只读严格复核（默认会再跑 gen 校验幂等）
python data/_verify_config_vuln_fixes.py --no-regen  # 纯离线复核
```

三者均幂等：在已修复的状态下再跑不会修改任何字节（SHA256 校验，见 §9.1 第 11 行）。

---

## 10. 后续可选扩展（非本次范围，仅作为 schema 演进建议）

如未来需要把"配置类 / 非污点类漏洞"在数据中可被自动过滤/统计，建议新增**可选**顶层元字段：

```jsonc
{
  // …全部现有字段…
  "vuln_class": "config"   // "taint" | "config" | "hybrid"
  "vuln_defect_kind": "structural-absence"  // 或 "structural-override" / "taint-flow"
}
```

依据：
- `SCHEMA.md` Forward-compatibility 段落允许"新增可选顶层字段"作为 minor-version 兼容点。
- 增加后可使评测脚本按"taint 评测" vs "config 评测"分流，不再迫使配置类样本套用污点评测口径。
- 本次 4 条样本的 `vuln_class` 与 `vuln_defect_kind` 已经隐式确定（缺失型 / 消解型），可在 0.x → 0.x+1 升级时一次性回填，或等到下一次同类样本积累到一定数量时统一应用。

**该建议不进入本次 fix**，避免在 issue 修复中夹带 schema 演进。
