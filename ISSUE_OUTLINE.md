# VulnGym T1 Issue 总纲（独立审查修订版）

## 1. 决策基线

- 目标仓库：`perhaps468/VulnGym`（当前 `origin`），集成目标为默认分支 `main`。
- 实现范围：以 `vulngym-verify-demo/` 为最终可运行交付物；根目录 `SCHEMA.md`、数据集和现有评测器保持兼容，仅在必要时扩展。
- 交付目标：完成题目 T1 Standard 档；Bonus 为独立、非阻塞增强项。
- 数据协议：课题规定的训练集（50 条，带 gold）可入仓库；公开测试集（20 条）只能入库输入和本次运行输出，**不提交其 gold**；隐藏测试集及金标不入仓库，只提交外部运行汇总。为单元测试而保留的带 gold 小型样本必须标为“开发回归 fixture”，不得称为公开测试集或用于对外宣称课题分数。
- LLM 协议：提供商无关适配层；默认离线 fixture/mock 可复现。Standard 只要求至少一种已配置的 LLM 接入能工作（题目允许任意 LLM），Qwen/DeepSeek/GLM 多提供商支持可保留为实现优势，但不作为 Standard 额外门槛；真实 LLM 失败只能降级为 `uncertain`，不得伪造正确证据；API key 不得入库。标识符、文件、行号和代码片段等可确定性验证的结论优先由本地工具产生，LLM 不得取代它们。
- GitHub 流程：总纲经独立 Agent 审查并由用户确认后，才创建父 Issue、子 Issue 和原生 `blocked by`/`blocks` 关系。

## 2. 成功标准（父 Issue 关闭门槛）

必须全部满足：

1. 字段级准确率 `>= 0.85`。
2. 错误条目找错召回率 `>= 0.90`。
3. 抽查 20 条报告时，证据可追溯且合理率 `>= 80%`。
4. 缺失字段、坏 commit、公告缓存缺失/404、目标文件不存在、LLM 超时/限流/非法 JSON 等题目列举的异常不崩溃，并按信息不足输出 `uncertain`；不得仅因本地缓存缺失把字段判为 `incorrect`。仅当可访问的公告或源码直接反证条目内容（例如同一 commit 内代码片段明确不匹配）时才可输出 `incorrect`，且证据必须说明原因。
5. JSONL 批处理可运行；每条报告至少包含 `report_id`、`entry_id`、`verdict`、8 个核心字段的三态/置信度/证据和 `summary`。`plan`、`self_check`、`tool_trace`、`evidence_refs` 是本实现用于展示和审计智能体过程的扩展，正常路径应输出，但不应被误表述为题目额外规定的对外字段。
6. README、1~3 页设计文档、公开测试集输出、5 分钟演示材料齐全且可复现。
7. 最终端到端验收记录已提交，能复现上述指标、异常行为和交付材料。

证据抽查必须使用固定 seed 的可复现抽样（默认 seed `20260902`，记录抽中的 20 个 `entry_id`），按“来源可定位、代码/公告内容支持结论、未编造、置信度与证据一致”四项 rubric 判定；抽查结果和未通过项写入验收报告。对可完整验证的正常输入，每条报告整体应覆盖公告与源码两类来源；单字段只需记录适合该字段的来源，不要求每个字段同时引用两类来源。输入损坏或本地来源不可用的降级报告应明确缺少的来源和所需补充信息。

评测口径须在首次基线评测前冻结：字段级准确率以带 gold 的 8 个字段为分母，预测状态必须与该字段 gold 的 `correct|incorrect|uncertain` 完全一致；缺失报告、缺失字段或非法状态均按该字段预测错误计。找错召回率为 entry 级指标：gold 中至少一个字段为 `incorrect` 的 entry 是“错误条目”，仅当该 entry 的 `verdict=incorrect` 时才算抓到；`uncertain` 不算抓到。无 gold 的公开测试集、损坏输入的降级 fixture 和隐藏集汇总不混入这两个指标，另行记录数量和行为。若日后采用不同口径，必须新增指标名，不得复用上述阈值。

## 3. 当前代码基线与已知缺口

当前原型已提供：

- `vulngym_verify_demo.tools.VulnGymTools`：公告读取、commit checkout、文件行读取、grep、git log。
- `field_checkers.py`：8 个核心字段检查器和 `check_all_fields`。
- `llm_client.py`：Qwen/DeepSeek/GLM、`SafeLLMClient`、`ResilientLLMClient`、脚本 Mock。
- `agent.py`：规划 -> 工具/LLM -> self-check 闭环。
- `cli.py`：JSONL 输入/输出、`--gold`、`--bench`、verbose。
- `eval.py`：字段准确率、错误召回、verdict 和字段分解。
- `mock_data/`、`mock_repo/`、`mock_advisories/` 和已有截图/日志。

需要在 Issue 中明确修正或验收的缺口：

- 输入 schema/类型/枚举/必填字段没有统一前置校验；单条坏记录不能拖垮批处理。
- 公告缓存字段与真实 GHSA/CVE 数据的映射、版本范围和修复 commit 语义、404/损坏 JSON 语义需要冻结。
- VulnGym 的 12 类业务漏洞分类及 l1/l2 合法组合、别名和判定规则尚未作为版本化资源冻结；仅依赖 LLM prompt 会使分类结论和 gold 评测不可复现。
- `vuln_ids` 需要公告 ID、格式、去重和对应关系的确定性规则；`vuln_title`、分类和 trace 整体判断需有可审计 prompt/结构化解析；LLM 输出必须校验 status/confidence/evidence。
- self-check 当前只返回意见，需确保不覆盖工具确认的事实，并在不成功时保留可追溯状态。
- CLI 的配置、退出码、日志、并发/超时策略和路径解析需要可复现并覆盖 Windows/Linux。
- 评测器需明确字段集合、gold 推断规则、异常样本计分和隐藏集汇总格式。
- 当前仓库已有 `pytest.ini`、CI 工作流和交付文档，但仍需核验其依赖安装、命令、样本类型、脚本链接和实际输出是否一致；不能因文件存在就视为满足 Standard。

对本轮审查意见的客观结论：commit 版本语义、缓存后端/并发模型、坏输入输出、未知字段兼容性和共享 JSON 结构属于真实契约缺口，已纳入 I1~I3/I6；证据“每字段双来源”属于过严表述，已改为报告级双来源；Standard 引入并发属于不必要的风险扩张，已降为 Bonus/后续 Issue。现有代码虽已实现顺序处理、快照式缓存和部分坏 JSON 隔离，但 CLI 尚未统一接入完整 schema 校验，`tool_trace` 也尚未保证只反映真实工具调用；这些行为由对应 Issue 修正或冻结。

## 4. 冻结共享接口

本节是仓库内部的兼容性契约，不新增题目 Standard 的评分要求。对外最小报告以题目所列的字段三态、置信度、文字证据和整体结论为准；审计扩展用于可追溯性和演示。

### 4.1 VerificationReport

每条输入记录输出一行 JSON：

```json
{
  "report_id": "...",
  "entry_id": "...",
  "verdict": "correct|incorrect|uncertain",
  "fields": {
    "entry_point": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "critical_operation": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "commit": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_ids": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_title": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_category_l1": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_category_l2": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "trace": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []}
  },
  "summary": "...",
  "self_check": {"status": "completed", "agree": true, "comment": "...", "checked_fields": []},
  "plan": {},
  "tool_trace": []
}
```

`report_id`、`entry_id`、`verdict`、8 个字段及其三态状态和 `summary` 为最小报告必填；每个字段对象必须有 `status`、`confidence`、`evidence`。若输出 `evidence_refs`，其格式为 `{source: advisory|repository|git, locator: string, quote: string}`；无证据时 `evidence` 必须解释缺口。`self_check`、`plan`、`tool_trace` 是本实现的审计扩展：正常输入应存在，以便演示智能体闭环；坏输入可省略或使用空结构。坏输入行必须生成报告：使用稳定占位符 `__invalid_input__:<line_no>` 填充缺失的 `report_id`/`entry_id`，并增加可选 `input_error`（`line_no`、`kind`、`message`）。若输出 `tool_trace`，它必须只记录实际调用的工具，不能只记录计划中的工具名。允许新增符合 SCHEMA 前向兼容规则的可选字段，不得加入 SCHEMA 明确禁止的内部字段或改名/改变既有语义。

最小 JSON 结构如下（唯一规范文件由 I1 放在 `vulngym-verify-demo/vulngym_verify_demo/report_schema.json`）：

```json
{
  "plan": {"version": "1", "tools_planned": ["read_advisory", "checkout", "read_file_lines"], "fields_planned": ["entry_point", "critical_operation"]},
  "self_check": {"status": "completed|skipped|failed", "agree": true, "comment": "...", "checked_fields": ["entry_point"]},
  "tool_trace": [{"seq": 1, "tool": "read_advisory", "input": {"report_id": "..."}, "ok": true, "error": null, "evidence_refs": ["fields.vuln_ids.evidence"]}]
}
```

`self_check.agree` 在 `status=failed|skipped` 时为 `false`；`tool_trace.input` 只允许脱敏后的摘要，`evidence_refs` 使用 JSON 路径，不能记录 API key 或完整本地绝对路径。上述扩展键名、枚举和类型由 I1 固化为唯一 JSON Schema 文件；该 schema 应接受题目最小报告和带审计扩展的完整报告。

### 4.2 Python 边界

冻结并向后兼容以下名称与职责：`VulnGymTools`、`BaseLLMClient`、`ResilientLLMClient`、`check_all_fields`、`verify_entry`、`verify_entries`、`evaluate`。

确定性工具结果不得被 LLM 覆盖。LLM 只负责语义字段和整体合理性；任何不可解析/不可用结果必须转成结构化 `uncertain`，并保留原因。结构化响应必须校验 `status` 枚举、`confidence` 在 `[0,1]`、`evidence` 非空并脱敏；真实 LLM 失败时禁止用关键词/启发式回退为 `correct`。

## 5. Issue DAG 与工作边界

编号在 GitHub 创建后回填；下列 `I1`~`I11` 是逻辑编号。

### I1 — 基线、输入校验与输出契约（Standard）

- 范围：按根目录 `SCHEMA.md` 校验全部必填字段（包括 `origin`、`verify` 等）及嵌套 `file/line/code`、line>0/合法 range、枚举和类型；允许未知的未来可选顶层字段，拒绝 SCHEMA 明确禁止的内部字段。当前发行版接受 `verify=0|1`；未来未知但类型兼容的 `verify` 状态不得导致批处理崩溃，应保留输入并降级说明。定义题目最小报告、可选审计扩展、错误模型和坏输入报告协议；冻结版本化的 12 类分类本体（合法 l1/l2 组合、别名、说明和版本）；补齐最小 fixture。
- 文件所有权：`vulngym-verify-demo/vulngym_verify_demo/schema*.py`、`models*.py`、`resources/category_taxonomy.v1.json`、根目录 `tests/test_schema.py`、`tests/test_taxonomy.py` 和契约文档。
- 依赖：无。被 I2、I3、I4、I5、I6、I7 阻塞。
- 验收：合法/非法/缺失/未知可选字段/禁止内部字段测试；单条坏记录产生结构化 uncertain，不中断批处理；坏 JSON 行使用 `__invalid_input__:<line_no>` 稳定 ID；最小报告与完整审计报告样例均可 JSON round-trip；分类本体覆盖 12 类及每个允许的 l1/l2 组合，别名映射和未知分类均有测试。

### I2 — 本地公告与仓库工具层（Standard）

- 范围：稳定 `VulnGymTools`；Standard 的权威代码来源是出题方提供的本地 clone，在不联网的前提下解析对象并读取指定 commit 的内容。实现可使用只读 `git show`/临时隔离 checkout，禁止共享可变工作树。预生成 `<project>/<commit>/` 只读快照仅可作为缓存优化：每份快照必须记录来源 `repo_url`、完整 commit、生成方式和校验值，并能由本地 clone 重建；不得在快照或 manifest 中预置 `vulnerable|fixed` 等结论性标签。`repo_url` 通过去除 `https://github.com/`、`.git` 并规范化 owner/name 后映射到 manifest 中的唯一 `project` key，禁止仅凭 basename 产生碰撞。版本范围、修复 commit 与“漏洞版本”的关系必须由公告原文和可定位的 git 证据推导，信息不足时返回 `uncertain`。绝对路径与 `..` 穿越拒绝；公告 404、权限错误、损坏 JSON 和坏 commit 均返回不泄漏敏感路径的 `ToolResult(ok=false)`，不得抛未处理异常。
- 文件所有权：`vulngym-verify-demo/vulngym_verify_demo/tools.py`、`vulngym-verify-demo/mock_repo/manifest.json`、根目录 `tests/test_tools.py`、fixture 生成脚本。
- 依赖：I1。被 I3、I4、I5、I6 阻塞。
- 验收：本地 clone 的指定 commit 读取、mock、manifest/目录结构和快照可重建性测试；路径穿越被拒绝；无网络运行；每类失败可预测且不抛出未处理异常；任何版本/角色结论均能回溯到公告或 git 证据，而非 manifest 标签。

### I3 — 确定性字段检查器（Standard）

- 范围：entry point、critical operation、commit、trace 节点的 checkout 后代码/行号/文件存在性、容错窗口和证据；以及 `vuln_ids` 与本地公告中的 GHSA/CVE 标识符、格式和去重规则的一致性检查。不得由 LLM 改写事实结果。题目列举的坏 commit、版本范围不可验证或本地缓存无法解析时必须保守输出 `uncertain`，而非把“无法取得证据”当作条目错误。
- 文件所有权：`field_checkers.py` 中确定性部分及根目录 `tests/test_field_checkers.py`；不得修改 `check_all_fields` 汇总器。
- 依赖：I1、I2。可与 I4 并行；被 I5、I7 阻塞。
- 验收：正确、行漂移、代码不匹配、文件缺失、坏 commit、空 trace、公告 ID 不匹配及 CVE/GHSA 重复/格式错误等 fixture；commit 判定必须分层：格式有效 -> 缓存/仓库中可解析 -> 与公告受影响版本范围相容；只有公告提供可验证范围且 commit 可映射时才能判 `correct`，无法映射版本、缓存不可用、格式不合规或公告仅给模糊范围时判 `uncertain`。若公告提供修复 commit/patch，必须区分修复 commit 与漏洞版本 commit，不能把修复 commit 当作引入 commit；状态、置信度和证据稳定。

### I4 — LLM 语义判定与安全降级（Standard）

- 范围：至少一种可配置 LLM 的适配、结构化响应解析、prompt 版本化、Safe/Resilient fallback；覆盖 title、基于 I1 分类本体的 category 语义匹配和 trace 整体判断。`vuln_ids` 的公告 ID、CVE/GHSA 格式、去重和对应关系属于确定性核验，由 I3/工具层提供事实；LLM 只能补充其语义说明，不得替代状态结论。Qwen/DeepSeek/GLM 的多提供商适配作为兼容性实现保留，不额外扩大 Standard 验收。
- 文件所有权：`llm_client.py`、语义 prompt/解析模块及根目录 `tests/test_llm.py`。
- 依赖：I1、I2。可与 I3 并行；被 I5、I7 阻塞。
- 验收：mock fixture 可复现；prompt 显式携带分类本体版本和允许的 l1/l2 组合；非法 JSON、超时、HTTP 错误、无 key 均输出 semantic `uncertain`，不得通过关键词启发式判 `correct`；响应 schema、证据非空和脱敏校验有效；API key 不出现在日志/报告。

### I5 — Agent 规划、工具调用与 self-check（Standard）

- 范围：在 I3/I4 合并后编排两者，保证“规划 -> 工具调用 -> 反思”闭环；标准完整验证路径应实际使用至少 3 类工具（例如读公告、解析/读取指定 commit、读取文件或 grep/git log），以体现课题要求。若某工具对该字段不适用、来源不可用，或已有直接证据足以避免冗余调用，可少于 3 类，但必须在 `tool_trace`/降级证据中记录原因，不能伪造调用。self-check 只提出修正建议，不覆盖确定性证据；保留 plan/self-check 审计信息。坏输入的降级路径可免除工具调用，但必须记录原因。I5 不改变 I3/I4 的核心实现文件，仅在其合并后接入适配层。
- 文件所有权：`agent.py` 中编排与汇总部分、`tests/test_agent.py`；只能在 I3/I4 合并后修改 `check_all_fields` 调用边界，不改 I3 的确定性检查逻辑。
- 依赖：I1、I2、I3、I4。完成后解除 I6、I7、I9、I10、I11。
- 验收：每条报告包含符合 I1 schema 的 plan/self_check/tool_trace；标准完整验证路径运行时确实调用至少 3 类工具，例外路径有可审计的少调用原因；`tool_trace` 逐项对应实际调用且记录证据引用（不得伪造未执行调用）；self-check 失败不阻塞；verdict 汇总遵循三态规则；正常输入报告整体覆盖公告与源码两类来源，字段按其适用来源引用证据。

### I6 — 批处理 CLI、配置、日志与可复现运行（Standard）

- 范围：JSONL 顺序流式处理、单条错误隔离、路径/环境变量配置、退出码、日志脱敏和超时；保持现有命令兼容。Standard 不引入并发；并发、重试和共享客户端线程安全作为 Bonus/后续 Issue，除非另行冻结隔离、顺序和超时协议。
- 文件所有权：`cli.py`、运行脚本、`tests/test_cli.py`；不得修改 `README.md`（由 I8 统一维护）、`tests/test_eval.py`、CI 配置或评测 fixture。
- 依赖：I1、I2、I5。可与 I7 并行；被 I8 阻塞。
- 验收：mock/安全 fallback smoke；空白行可跳过并计入日志，坏 JSON 与 schema 不合法行均产生稳定 `__invalid_input__:<line_no>` 报告并继续处理；Windows/Linux 命令示例；非零退出码仅用于不可恢复输入/配置错误。

### I7 — 评测器、公开 fixture、指标与鲁棒性测试（Standard）

- 范围：扩展 `evaluate` 与 `format_metrics`，固定 8 字段、支持逐字段三态显式 gold 与现有兼容格式，并实现第 2 节冻结的字段准确率、entry 级找错召回率、异常样本和缺失报告计分规则；补 pytest、CI 门禁、训练集（50 条、带 gold）评测，以及公开测试集（20 条、无 gold）的输出生成。当前仓库中 11 条带 gold 样本仅能作为开发回归 fixture，必须改名或在文档中明确其非公开测试集身份。
- 文件所有权：`eval.py`、根目录 `tests/test_eval.py`、`tests/test_robustness.py`、CI 配置、公开 fixture/报告；不得修改 `tests/test_cli.py`。所有 pytest 从仓库根目录运行，使用显式 `pythonpath`/包安装方式导入 `vulngym_verify_demo`。
- 依赖：I1、I2、I3、I4、I5。可与 I6 并行；被 I8 阻塞。
- 验收：训练集的字段准确率、entry 级错误召回、verdict、字段 breakdown 与第 2 节口径和题目阈值一致；公开测试集能生成且提交 JSONL 报告但不依赖/泄露 gold；显式 gold、兼容 gold、`uncertain`、缺失报告和异常样本规则均有测试；回归测试覆盖所有鲁棒性场景；CI 可离线通过。

### I8 — Standard 文档、公开输出与演示材料（Standard）

- 范围：README、1~3 页设计文档（架构图/工具/prompt/坑）、公开测试 JSONL、5 分钟演示脚本/截图；记录隐藏集汇总模板。
- 文件所有权：`vulngym-verify-demo/README.md`、`docs/`、`demo/`、公开输出和索引。
- 依赖：I6、I7。父 Issue 的 Standard 完成闸门。
- 验收：新环境按 README 一键运行；文档命令、依赖文件、CI 和实现一致；演示覆盖正常路径、异常 fallback、训练集指标与公开测试集输出；所有已发布指标均附可复现命令和样本范围；无 key/公开测试 gold/隐藏金标泄露。

### I9 — Bonus：系统性错误识别与归因

- 范围：跨 entry 聚合错误模式、工具/模型偏差统计、归因报告。
- 文件所有权：新增 `bonus/error_attribution/` 模块、报告模板和专属测试，不直接改 I3/I4 核心实现或共享索引。
- 依赖：I5、I7；非阻塞，可与 I10/I11 并行。
- 验收：对可控注入错误输出稳定归因，包含样本数、影响字段和证据链接。

### I10 — Bonus：错误字段修正建议

- 范围：在不改变 `status` 的前提下增加可选 `suggested_value`/`suggestion_evidence`，对 line、category、title 等给出可审计建议。
- 文件所有权：新增 `bonus/suggestions/` 模块和专属 schema 可选字段测试，不直接修改 I1 核心模型；通过可选扩展字段接入。
- 依赖：I5、I7；非阻塞，可与 I9/I11 并行。
- 验收：建议字段可选、向后兼容；无证据时不猜测并输出 uncertain/needs_manual_review。

### I11 — Bonus：多语言代码适配

- 范围：针对 Python/JS/Go/Java 的行读取、代码归一化、grep/语法辅助策略；不得引入被检查仓库内陌生二进制执行。
- 文件所有权：新增 `language/` 适配模块和跨语言 fixture/测试，不修改 I3 核心接口签名。
- 依赖：I2、I3、I5；非阻塞，可与 I9/I10 并行。
- 验收：四种语言 fixture 均能定位节点并给出证据；不支持语言安全降级 uncertain。

## 6. 依赖、并行和 Agent 分配规则

推荐拓扑：`I1 -> I2 -> (I3 || I4) -> I5 -> (I6 || I7) -> I8`；`I9/I10/I11` 在 I5（并建议 I7）完成后并行。

只有同时满足以下条件才分配独立 Codex Agent/worktree/分支：

- 所有 `blocked by` Issue 已关闭或明确解除；
- 目标文件所有权与其他运行中 Issue 不重叠；
- 分支从最新集成目标分支创建，命名 `codex/issue-<number>-<short-name>`；
- Agent 必须提交代码、测试、运行结果和 PR；不得直接合并。

集成工作按 DAG 顺序审阅 PR：先契约/工具，再字段与 LLM，再编排，再 CLI/评测，最后文档；每次合并前运行相关 pytest 和 CLI smoke，合并后运行全量离线测试。这是推荐交付流程，不是课题 Standard 的额外关闭门槛。

## 7. GitHub Issue/PR 模板要求

父 Issue 必须包含：目标、范围、成功标准、Issue 清单、依赖图、共享接口、并行分配规则、Standard/Bonus 闸门、隐藏集汇总位置和关闭清单。

每个子 Issue 必须包含：背景、非目标、文件所有权、输入/输出契约、`Blocked by`/`Blocks`、测试命令、验收标准、交付 PR 要求、风险与回滚点。

PR 必须链接对应子 Issue，说明变更文件、测试命令与结果、契约兼容性、是否引入新依赖/凭据；集成 Agent 在 PR 中记录审查结论和合并依据。

## 8. 执行前检查（不改变总纲）

- 执行 GitHub 写操作前运行 `gh auth status`，确认 `perhaps468/VulnGym` Issue/PR/依赖关系写权限。
- 创建 Issue 前确认公开 fixture 的最终数量和隐藏集汇总报告路径；默认使用 `reports/hidden_eval_summary.json`，不提交隐藏样本/金标。
- 若 GitHub 原生依赖关系 API 不可用，保留正文中的双向 `Blocked by`/`Blocks` 引用，并在父 Issue 记录限制。
