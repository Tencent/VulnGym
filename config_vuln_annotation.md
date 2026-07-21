# 配置类 / 非污点类漏洞在 VulnGym 中的标注方式

> 对应 [Tencent/VulnGym#8](https://github.com/Tencent/VulnGym/issues/8)。
>
> **说明**：本文档为本次会话中重新撰写的完整版本，而非对某份既有草稿的编辑——
> 提交者此前描述已准备好一份 `config_vuln_annotation.md` 草稿，但该草稿正文
> 未能实际传入本次分析上下文（消息中对应位置是未替换的占位符）。以下内容基于
> 提交者在 issue 描述中给出的分析结论（已就 entry-00241~244 的 `{file, line,
> code}` 与漏洞源 commit 核实、并识别出"静态缺失型 / 主动绕过型"两类子模式），
> 结合对 `data/entries.jsonl` 现有标注、`SCHEMA.md` 不变量、以及
> `openclaw/openclaw@c56fb7f` 源码的独立复核撰写而成。若提交者的原始草稿在遣词
% 造句上另有考量，请对照合并。

## 1. 问题背景

VulnGym 的 `entry_point` / `critical_operation` / `trace` 三元体系是为**污点流 /
调用链**类漏洞设计的：`trace` 的语义是"数据（或控制流）经过若干节点从入口传播
到危险操作"，每个中间节点理应代表一次有意义的状态转移。

但 GHSA-W7J5-J98M-W679（OpenClaw 多个 E2E/test Dockerfile 以 root 或不必要特权
运行）对应的 4 条 entry（entry-00241~00244）是**配置类漏洞**：风险不是"数据流
经某处才产生"，而是"某个必需的安全配置从一开始就缺失，或被后续操作架空"。把
这类漏洞硬套进污点流的 `trace` 语义，会产生一种具体的标注失真：中间节点被填入
了实际上什么都没改变的构建步骤（`WORKDIR`、依赖安装、编译等），desc 却仍然用
"沿着链路继续传递"这类措辞描述它们，制造出一种并不存在的因果推进感。

## 2. 两种子模式

对 4 条 entry 的源码核实（commit `c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1`，
四个 Dockerfile 均已逐行比对，位置准确无误）显示，它们并非同一种情况，而是两种
性质不同的配置类漏洞：

### 类型 A —— 静态缺失型（entry-00241 / 00242 / 00243）

三个 Dockerfile（`scripts/e2e/Dockerfile`、`scripts/e2e/Dockerfile.qr-import`、
`scripts/docker/install-sh-e2e/Dockerfile`）**全文自 `FROM` 起到文件结尾都没有
出现过一次 `USER` 指令**。风险在 `FROM` 那一行就已经 100% 成立，此后无论文件
里再写多少行 `RUN` / `WORKDIR` / `COPY`，都只是在已经确定的风险状态下继续执行
——没有任何一步"改变"了什么，因为从来没有过一个可以被改变的降权状态。

原有标注把这些中间步骤（如 `entry-00241` 的 `RUN corepack enable` →
`WORKDIR /app` → `RUN pnpm install` → `RUN pnpm build` → `RUN pnpm ui:build`）
逐一列为 trace 节点，每条 desc 都在换一种说法重复"仍然是 root"，这是**冗余**，
不是**传播**。

**判定标准**：整个文件中不存在任何 `USER` 指令（或其他会话内权限切换）。

**标注规则**：`trace` 精简为两个节点——`entry_point` 对应节点（`FROM`，风险
状态确立处）与 `critical_operation` 对应节点（`CMD`/`ENTRYPOINT`，风险状态被
运行时兑现处）。desc 明确写出"两点之间不存在状态变化"，并说明具体是哪些中间
步骤因为不改变状态而被省略，而不是用中性的"数据/权限沿链路传递"式措辞掩盖这一
事实。

### 类型 B —— 主动绕过型（entry-00244）

`scripts/docker/install-sh-nonroot/Dockerfile` 不同：它**确实执行了一次真实的
降权尝试**——`useradd` 创建 `app` 账户、`USER app` 切换会话身份。如果流程到此
为止，风险就已经被消除。但紧邻其后写入了
`echo "app ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/app`，为 `app` 授予免密
`sudo`，使得 `USER app` 造成的降权在语义上完全落空——最终 `ENTRYPOINT` 虽然
以 `app` 身份启动，却可以随时无成本地经 `sudo` 变回 `root`。

这是一条**真正有意义的因果链**：建号（准备降权）→ 授权（sudoers 免密，埋下
绕过点）→ 表面降权（`USER app`，产生"看起来安全"的假象）→ 实际仍为 root
（`ENTRYPOINT` 借 `sudo` 兑现）。每一步都改变了系统状态，且改变的方向恰恰构成
了漏洞——移除中间任何一步，结论都会不同。

**判定标准**：文件中存在至少一次实质性的权限切换尝试（`USER` 指令、`su`、
`gosu`、`setuid` 调用等），但该切换被后续配置（免密 `sudo`、错误的文件权限、
capability 保留等）架空。

**标注规则**：保持污点流式的完整 `trace`，因为这里确实存在传播——只是传播的
不是"数据"，而是"权限状态"本身，且每个节点都对应一次真实的状态转移。
entry-00244 现有标注（7 个节点）符合此规则，**本次不改动**，作为类型 B 的
对照样本。

## 3. 判断依据小结

| | 类型 A：静态缺失型 | 类型 B：主动绕过型 |
|---|---|---|
| 代表 entry | entry-00241 / 00242 / 00243 | entry-00244 |
| 是否存在权限切换尝试 | 否，全文无 `USER` | 是，`USER app` |
| 风险成立时刻 | `FROM` 那一行即成立 | 需要走到 sudoers 授权那一步才成立 |
| 中间步骤是否改变状态 | 否（重复同一状态） | 是（每步都是必要的状态转移） |
| trace 应有形态 | 精简为 entry/critical 两点 | 保留完整因果链 |
| 移除某中间节点是否影响结论 | 不影响（本就冗余） | 影响（链路会断裂） |

这个区分不是"配置类漏洞统一简化 trace"这么粗的规则——同属配置类，类型 B 依然
需要完整链路，因为它的语义确实是传播式的（权限状态被逐步操纵），只是传播的对象
不是数据流。真正决定 trace 该不该精简的，是"中间节点是否真的改变了任何状态"，
而不是"这是不是污点流漏洞"。

上表"移除某中间节点是否影响结论"这一行，对 entry-00241~244 这四条成立，但不是
一个能直接套用到其他 entry 上的通用检验——§6 扫描 entry-00332 时验证过，"去掉
某节点结论是否还成立"会给出误导性的判断。更根本的标准是**该节点是否触碰了漏洞
相关的状态维度本身**：无关的旁支操作即使发生在漏洞窗口期内，也不构成传播节点；
真正改变风险相关状态的操作才算，不管这一步是否是"最小攻击链"意义上的必需步骤。

## 4. 本次改动

按上述规则，对 entry-00241 / 00242 / 00243 的 `trace` 字段做了精简，`desc` 改写
为诚实反映"两个端点之间无状态变化"；`entry_point`、`critical_operation`、
`file`/`line`/`code` 均未改动，且已重新对照 openclaw 仓库该 commit 下的真实源码
逐行核对。entry-00244 未作任何修改，作为类型 B 的对照样本。

**`data/entries.jsonl` 这份共享 baseline 本身未被修改**——issue #8 同时有十余名
学员认领，直接改 baseline 会让所有人的 PR 互相冲突。改动改为通过脚本产出：

- [`scripts/data_fixes/gen_config_vuln_fixed.py`](scripts/data_fixes/gen_config_vuln_fixed.py)
  ——幂等生成器，只读 `data/entries.jsonl`，输出：
  - `data/entries.config_vuln.fixed.jsonl`（完整 408 行，仅 entry-00241/242/243
    的 `trace` 被替换，其余包括 entry-00244 原样透传）
  - `data/config_vuln_diff.csv`（`entry_id, field, before, after, changed` 五列，
    对 4 条目标 entry 的 `entry_point`/`critical_operation`/`trace`/`verify`
    四个字段逐一给出前后对比，`changed` 列标出哪些字段真的变了、哪些是复核后
    确认未改）
- [`scripts/data_fixes/verify_config_vuln_fixes.py`](scripts/data_fixes/verify_config_vuln_fixes.py)
  ——只读复核脚本，跑 6 项独立检查：baseline 未被污染、`SCHEMA.md` 全部不变量、
  4 条目标 entry 的 `{file, line, code}` 对照 openclaw 上游源码逐行核实、diff CSV
  与生成结果一致、生成器可重复运行且输出字节级相同（幂等）、`desc` 确实在解释
  原因而非复述代码。本地复核命令：

  ```bash
  python scripts/data_fixes/gen_config_vuln_fixed.py
  python scripts/data_fixes/verify_config_vuln_fixes.py
  ```

## 5. 是否应将样本从 benchmark 子集中移除

issue 验收标准要求：若判断某些样本不适合留在当前 benchmark 子集，需给出充分依据。
逐条评估如下：

**结论：四条 entry 均应保留，不建议移除。**

理由：

- **漏洞本身真实、可验证、非重复噪声。** 四条 entry 分别对应四个不同的 Dockerfile
  文件（`scripts/e2e/Dockerfile`、`scripts/e2e/Dockerfile.qr-import`、
  `scripts/docker/install-sh-e2e/Dockerfile`、
  `scripts/docker/install-sh-nonroot/Dockerfile`），是同一份 advisory 下四个
  独立的攻击面，而不是同一处代码被拆成多条冗余记录——移除任何一条都会让
  GHSA-W7J5-J98M-W679 在数据集里的入口覆盖不完整。
- **"缺少真正的传播链"不等于"缺少可验证的漏洞语义"。** VulnGym 的核心不变量
  （`SCHEMA.md` 不变量 7）只要求 `entry_point`/`critical_operation`/`trace`
  的每个节点满足 `{file, line, code}` 且可在对应 commit 定位，并未要求
  `trace` 必须体现多步传播——`trace` 允许为空（`SCHEMA.md`: "May be empty"）。
  类型 A 的四条 entry 在"入口可达、关键操作可定位、位置准确"这些核心语义上
  完全成立，只是原标注把"没有传播"错误地表达成了"有传播"，这是标注层面的
  失真，本次已通过精简 `trace` 修正——问题被修复了，不构成移除理由。
- **对下游评测没有负面影响。** `examples/evaluate.py` 的匹配只看
  `entry_point`/`critical_operation` 的 `{file, line}`，完全不读 `trace`
  （见 §7.3）；精简 `trace` 不会改变任何工具在这四条 entry 上的召回率计算。
  换言之，即使不修，这四条 entry 参与评测也不会产生错误结果，标注问题不传导
  为评测层面的正确性问题——移除的必要性因此进一步降低。
- **移除反而会制造新问题。** 若移除这四条，`GHSA-W7J5-J98M-W679` 对应的
  `report_id` 会在 `reports.jsonl` 中失去全部 `entry_ids`，需要连带处理整条
  advisory 记录（否则违反不变量 2/3：`report.entry_ids` 与
  `entries.jsonl` 分组不一致），影响范围超出这次任务本身，且没有必要——
  唯一促成移除的理由（"标注体系不适配"）已经通过 §2~4 的规则调整解决。

唯一需要持续关注的点：如果未来数据集里出现**更多**同类"静态缺失型"配置漏洞，
应优先复用本文 §2~3 的判断标准去修标注，而不是把它们当作"不适合 benchmark"
批量移除——移除应该是标注规则穷尽后仍无法表达时的最后手段，不是默认选项。

## 6. 数据集扫描：当前是否还有同类问题

为验证这次的修法不是"头痛医头"，对全部 408 条 entry（排除已处理的 4 条）做了
一次结构性排查，标准是：

1. 分类文本命中配置/默认值/完整性/信任类关键词（`BL-INSECURE-DEFAULT`、
   `BL-ORIGIN-INTEGRITY`、`BL-TRUST-BOUNDARY`、`BL-PRIV-ESC`、
   `BL-WORKFLOW-VIOLATION`、"容器以不必要特权运行"等），**或**
2. `entry_point`/`critical_operation`/`trace` 涉及的文件是配置类文件
   （`Dockerfile`、`docker-compose`、`*.yaml`/`*.yml`、`*.toml`、`*.ini`、
   `*.conf`、`*.env`、CI workflow 等）。

命中 80 条（占剩余 404 条的约 20%），按"是否单文件 + 是否命中文件模式"分三档：

- **Tier 1（强特征：整条 entry 只涉及一个配置文件，且 trace ≥ 3）：仅 1 条**
  ——`entry-00332`（`GHSA-69FQ-XP46-6X23`，aquasecurity/trivy，供应链攻击，
  `.github/workflows/reusable-release.yaml`）。三个 trace 节点：伪造的
  `checkout` action 建立污染入口（entry_point）→ `fetch-depth: 0` → `args:
  ... --skip=validate` 放行被篡改产物发布（critical_operation）。

  人工复核后**排除**，但排除依据需要澄清：用"去掉中间节点结论是否还成立"
  这个粗测试并不完全适用于这条——去掉 `fetch-depth: 0`，"伪造 action → 跳过
  校验放行"这条最小攻击链依然逻辑自洽，并不会像 entry-00241~243 那样"去掉
  任何一步都不影响结论"式地明显冗余。真正能区分两者的标准是**该节点是否
  触碰了漏洞相关的状态维度本身**：entry-00241~243 的中间步骤（`WORKDIR`、
  `pnpm install` 等）与"是否 root"这个风险维度完全无关，只是在已经固定
  不变的 root 状态下运行的旁支操作，对该状态零触碰；而 `fetch-depth: 0`
  直接作用在风险维度上——它决定了这个已失陷的 action 实际能读取多少仓库
  数据（全量历史 vs 默认浅克隆），是攻击影响面的一次真实放大，不是无关
  的旁支细节。按这个更准确的标准，entry-00332 仍然是有意义的因果链，只是
  恰好三步都落在同一个 YAML 文件里——这与 entry-00241~243"全程没有任何
  状态变化"的模式不是一回事，不需要按本文规则调整。
- **Tier 2（partial，15条）与 Tier 3（weak，64条）**：绝大多数是 openclaw
  项目下的业务逻辑漏洞（`BL-PRIV-ESC`/`BL-ORIGIN-INTEGRITY`/
  `BL-TRUST-BOUNDARY` 等），trace 横跨 2~4 个真实源码文件（如
  `webhook.ts` → `config-schema.ts`、`command-auth.ts` →
  `commands-allowlist.ts` → `chat.ts`），是被分类名字里的"默认/来源/信任"
  等字面关键词误命中——本质仍是跨模块调用链上的授权/校验缺陷，属于
  `vuln_pattern` 提案里的 `taint_flow`，不属于本文讨论的配置类问题。

**结论：当前数据集里，"静态缺失型"配置类标注失真是 GHSA-W7J5-J98M-W679
特有的，未发现其他需要用本文规则修复的样本。** 本文 §2~3 的判断标准作为
方法论保留，供未来数据集扩充、纳入更多 Dockerfile/CI 配置类样本时复用。

## 7. 向后兼容补充建议：`vuln_pattern` 可选字段

### 7.1 字段定义

在 `entry_point` / `critical_operation` / `trace` 三元体系之外，为每条 entry
新增一个**顶层、可选**字段：

```json
"vuln_pattern": "taint_flow" | "static_config" | "active_bypass"
```

- `taint_flow`（默认语义，向后兼容）——现有绝大多数样本：数据或控制流从
  `entry_point` 传播到 `critical_operation`，`trace` 中每个节点代表一次有意义
  的传播步骤。**不显式标注该字段的历史数据，消费者应视为 `taint_flow`**，因此
  这是一个纯增量字段，不改变任何现有行只是对现有行选择性追加值。
- `static_config`（对应本文类型 A）——风险在 `entry_point` 处一次性成立，
  `trace` 中间节点不代表状态传播，仅为完整性保留首尾两个端点。
- `active_bypass`（对应本文类型 B）——存在真实的安全控制被建立又被架空的过程，
  `trace` 语义上仍是传播式的，只是传播对象是"权限/信任状态"而非数据。

按 §4 的改动，entry-00241/242/243 应标 `"vuln_pattern": "static_config"`，
entry-00244 应标 `"vuln_pattern": "active_bypass"`。**本次改动暂未写入该字段**
——因为它是一个需要经维护者认可的 schema 级提案，不应该在未确认前静默出现在
数据里；这里只描述提案本身，具体写入留待 issue/PR 讨论达成一致后再执行。

### 7.2 与 `SCHEMA.md` 不变量的兼容性

- 符合"新增可选顶层字段"的前向兼容条款（`SCHEMA.md` §Forward compatibility）：
  不改变任何现有必填字段的类型或语义。
  不在不变量 8 的禁止字段黑名单（`description` / `human_remark` / … /
  `vuln_category_l3`）之内，属于全新命名，不冲突。
  不影响不变量 1-7、9 的任何一条（行数、report/entry 对应关系、`origin`、
  `commit`/`repo_url` 格式、`source_link`、`entry_point`/`critical_operation`/
  `trace` 结构、`verify` 取值）——它是与这些字段并列的独立顶层键。
- 建议同步更新 `SCHEMA.md` 的 `entries.jsonl` 字段表，新增一行并标注
  "Optional, added in vX.Y"，并在不变量 7 附近补一条可选的格式校验（枚举值
  校验：非空时必须是三者之一）。

### 7.3 对下游评测逻辑（`examples/evaluate.py`）的具体影响

当前 `evaluate.py` 的匹配逻辑（`finding_matches_entry`）**完全不读取 `trace`
字段**（文档字符串明确写着 "trace: optional; ignored by the matcher"），只用
`entry_point` 与 `critical_operation` 的 `{file, line}` 做匹配。这意味着：

1. **新增 `vuln_pattern` 字段对现有匹配算法零影响**——不需要改一行匹配代码，
   `load_jsonl` 会原样把这个新键读进 `dict`，未知字段不会导致解析失败或行为
   变化。这是选择"新增可选字段"而非"改变 trace 结构"作为提案形式的原因之一：
   前者对评测器是纯粹的加法，后者则可能需要评测器识别新的 trace 语义。
2. **可选的下游增强**（不属于本次改动范围，仅作为后续可能性记录）：
   - `evaluate.py` 可以增加一个 `--by-pattern` 开关，把 `advisory-level /
     entry-level recall` 按 `vuln_pattern` 分组输出，从而回答"某工具在纯污点流
     漏洞上召回率是多少、在配置类漏洞上又是多少"这类问题——这正是 issue #8
     想要解决的评测维度缺失问题的下一步。
   - `evaluate.py` 目前对 `trace` 完全不做验证；如果未来要求 `static_config`
     类型的 `trace` 长度必须 ≤ 2（呼应本文类型 A 的标注规则），这应该作为一条
     **独立的、可选开启的 lint 规则**（例如放进未来的数据校验脚本，而不是
     `evaluate.py` 本身），因为 `evaluate.py` 的职责是评测提交结果，不是校验
     ground truth 数据格式。
   - 对提交结果（`examples/example_result.jsonl` 格式）本身，`vuln_pattern`
     不需要工具方填写——匹配始终只看 `entry_point`/`critical_operation`，
     该字段只存在于 ground truth 一侧，用于分组统计，不是匹配条件的一部分。

### 7.4 为什么不直接改造 `trace` 的语义而是新增字段

曾考虑的替代方案是让 `trace` 本身支持"空数组表示无传播"这种语义（`SCHEMA.md`
已允许 `trace` 为空数组），从而类型 A 直接写 `"trace": []`。放弃这一方案的原因：

- 现有数据中 `trace` 的第一个 / 最后一个节点习惯性地与 `entry_point` /
  `critical_operation` 重复（见 entry-00241 原标注与 entry-00244），这是数据集
  已经形成的隐性约定；`trace: []` 会打破这个约定，让消费者无法从 `trace` 本身
  判断"这条 entry 到底是没有中间节点，还是标注遗漏了"。
- 保留两个端点节点、只是精简中间部分，是对现有约定的最小改动，向后兼容成本
  最低；而语义扩展（`vuln_pattern`）负责回答"为什么这条 trace 这么短"，两者
  分工明确，不需要靠猜测 `trace` 长度来反推漏洞类型。

## 8. 验证记录

以下由 `scripts/data_fixes/verify_config_vuln_fixes.py` 自动化执行，任何人可
本地重跑复现：

| 检查项 | 内容 | 结果 |
|---|---|---|
| `baseline-untouched` | `data/entries.jsonl` 与 `Tencent/VulnGym` 上游 main 分支逐字节一致 | ok |
| `schema-invariants` | `data/entries.config_vuln.fixed.jsonl` 满足 `SCHEMA.md` 全部不变量（行数 408、`entry_id` 升序、`origin`/`commit`/`repo_url` 格式、`verify∈{0,1}`、禁止字段黑名单、`entry_point`/`critical_operation`/`trace[*]` 结构） | ok |
| `upstream-source` | entry-00241/242/243 的 `{file, line, code}` 对照 `openclaw/openclaw@c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1` 逐行核实 | ok |
| `diff-csv-consistency` | `data/config_vuln_diff.csv` 与 `entries.config_vuln.fixed.jsonl` 字段级一致 | ok |
| `generator-idempotent` | `gen_config_vuln_fixed.py` 重复运行两次，输出 SHA-256 相同 | ok |
| `desc-not-just-code` | 重写后的 `trace[*].desc` 不是对 `code` 的复述，且包含风险推理关键词 | ok |
