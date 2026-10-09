# VulnGym 验证系统

**VulnGym 字段级数据验证系统** — 基于 LLM + 确定性工具的混合验证引擎

[![Tests](https://github.com/perhaps468/VulnGym/actions/workflows/test.yml/badge.svg)](https://github.com/perhaps468/VulnGym/actions)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)

---

## 项目简介

VulnGym 验证系统对漏洞数据集进行字段级自动化审核，支持：

- ✅ **8 个核心字段验证**：entry_point、critical_operation、commit、vuln_ids、vuln_title、category_l1、category_l2、trace
- ✅ **三态输出**：correct / incorrect / uncertain，附带置信度和可追溯证据
- ✅ **Agent 闭环**：规划（Plan）→ 工具调用（Execute）→ 反思（Self-Check）
- ✅ **鲁棒容错**：坏输入、文件缺失、公告 404、LLM 失败均不崩溃
- ✅ **契约可验收**：T1Data 离线资料包契约（408 条输入 → 408 条 schema 合法报告，零 schema-invalid）
- ⚠️ **质量指标未在当地证明**：官方 0.85 字段准确率 / 0.90 找错召回率需要**独立 gold**，
  资料包不提供。README 后续出现的 0.950 / 1.000 均为 **mock fixture 的非评测性数字**，
  不能作为 T1Data 或隐藏集成绩。

---

## 官方 T1 CLI（T1Data 资料包契约）

T1Data 资料包声明的调用契约为 `python -B -m vulngym_agent`，由仓库根的 `vulngym_agent`
包提供（核心逻辑仍在 `vulngym_verify_demo`）。

从**仓库根目录**执行：

```bash
python -B -m vulngym_agent <entries.jsonl|packaged-candidates.jsonl> \
  --package-root <T1Data> \
  --repo-map <T1Data/repo-map.json> \
  --validation-output <validation.jsonl> \
  --evidence-output  <evidence.jsonl> \
  --manifest-output  <manifest.jsonl>
```

要点：

- 仓库身份的唯一键是**规范化 `repo_url`**（`RepositoryResolver`），不使用 basename；
  `jlowin/fastmcp` 与 `PrefectHQ/fastmcp` 因此不会串仓。
- 只使用只读 Git 子命令（`cat-file` / `show` / `log` / `tag` …），不执行受检仓库代码；
  默认启用运行期离线守卫，任何网络访问都会被阻断并记录。
- `--mode evaluation`（默认）**拒绝** `--llm mock`；控制流测试请显式使用
  `--mode test-mock --llm mock`，此时 manifest 带有 `non_evaluative_run=true`
  且拒绝计算正式指标。
- 提供 `--gold` 时只接受**独立** gold；位于资料包内部的任何文件（含输入的 `verify`
  字段）都会被拒绝。
- `--commit-gate` 会对全部 `(repo_url, commit)` 执行只读 `git cat-file -e` 校验。


---

## 快速开始

### 1. 环境要求

- Python 3.13+
- 依赖：`openai`、`pytest`、`jsonschema`

### 2. 安装依赖

```bash
pip install openai pytest jsonschema
```

### 3. 运行 Mock 模式（无需 API key）

```bash
cd vulngym-verify-demo

# Windows PowerShell
python -m vulngym_verify_demo `
  --entries public_fixtures/entries.jsonl `
  --repo-cache mock_repo `
  --advisories mock_advisories `
  --out out/reports.jsonl `
  --llm mock `
  --bench

# Linux/macOS
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --out out/reports.jsonl \
  --llm mock \
  --bench
```

**预期输出**：

```
Processing 11 entries...
[1/11] entry-00001: correct (8/8 fields correct)
[2/11] entry-00002: incorrect (entry_point mismatch)
...

=== Evaluation Metrics ===
field_accuracy: 0.950   # 仅 mock fixture 的非评测性数字，不是 T1Data/隐藏集成绩
error_recall: 1.000     # 同上
verdict_accuracy: 1.000
```

---

## 使用真实 LLM

### 配置环境变量

**Qwen (阿里通义千问)**:
```bash
# Windows PowerShell
$env:QWEN_API_KEY="sk-..."
$env:QWEN_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
$env:QWEN_MODEL="qwen-turbo"

# Linux/macOS
export QWEN_API_KEY="sk-..."
export QWEN_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
export QWEN_MODEL="qwen-turbo"
```

**DeepSeek**:
```bash
# Windows PowerShell
$env:DEEPSEEK_API_KEY="sk-..."
$env:DEEPSEEK_BASE_URL="https://api.deepseek.com"
$env:DEEPSEEK_MODEL="deepseek-chat"

# Linux/macOS
export DEEPSEEK_API_KEY="sk-..."
export DEEPSEEK_BASE_URL="https://api.deepseek.com"
export DEEPSEEK_MODEL="deepseek-chat"
```

**GLM (智谱)**:
```bash
# Windows PowerShell
$env:GLM_API_KEY="..."
$env:GLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
$env:GLM_MODEL="glm-4-flash"

# Linux/macOS
export GLM_API_KEY="..."
export GLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
export GLM_MODEL="glm-4-flash"
```

### 运行命令

```bash
# 使用 Qwen
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --out out/reports_qwen.jsonl \
  --llm qwen \
  --verbose

# 使用 DeepSeek
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --out out/reports_deepseek.jsonl \
  --llm deepseek \
  --verbose

# 使用 GLM
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --out out/reports_glm.jsonl \
  --llm glm \
  --verbose
```

---

## 项目结构

```
vulngym-verify-demo/
├── README.md                      本文档
├── docs/
│   └── DESIGN.md                  设计文档（架构、模块、陷阱）
├── demo/
│   └── DEMO_SCRIPT.md             5 分钟演示脚本
├── public_fixtures/               公开测试集
│   ├── README.md                  测试集说明
│   ├── entries.jsonl              11 条测试样本
│   └── gold.jsonl                 显式三态金标
├── mock_data/                     手工构造的 mock 样本
│   └── entries.jsonl              4 条样本（含脏数据）
├── mock_repo/                     预生成的仓库缓存
│   ├── manifest.json              项目 → commit 映射
│   └── <project>/<commit>/        只读快照目录
├── mock_advisories/               mock 公告缓存
│   └── GHSA-*.json                单个公告文件
├── out/                           输出目录
│   └── reports*.jsonl             验证报告
└── vulngym_verify_demo/           核心代码
    ├── __main__.py                CLI 入口
    ├── cli.py                     命令行处理
    ├── agent.py                   Agent 闭环（Plan → Execute → Self-Check）
    ├── tools.py                   VulnGymTools（5 个工具）
    ├── llm_client.py              LLM 客户端（Qwen/DeepSeek/GLM/Mock）
    ├── field_checkers.py          8 个字段检查器
    ├── eval.py                    评测器
    ├── schema.py                  输入校验 + 输出契约
    └── report_schema.json         VerificationReport JSON Schema
```

---

## 核心模块

### 1. VulnGymTools (`tools.py`)

提供 5 个只读工具：

| 工具 | 输入 | 输出 | 异常处理 |
|------|------|------|----------|
| `read_advisory` | `report_id` (GHSA-xxx) | 公告 JSON 对象 | 404 → `ok=false` |
| `checkout` | `project`, `commit` | 工作目录路径 | 坏 commit → `ok=false` |
| `read_file_lines` | `cwd`, `file`, `start`, `end` | 代码行列表 | 文件不存在 → `ok=false` |
| `grep_code` | `cwd`, `pattern`, `file` | 匹配行 | 无匹配 → `[]` |
| `git_log` | `cwd`, `since_commit`, `limit` | commit 历史 | 坏 commit → `ok=false` |

**特性**：
- 无网络依赖（Standard 使用预生成快照）
- 路径穿越防护（拒绝 `..`）
- 并发读取安全（只读缓存）

### 2. LLM 客户端 (`llm_client.py`)

三层容错架构：

```
ResilientLLMClient (重试 + 超时)
    ↓
SafeLLMClient (JSON 解析 + schema 校验)
    ↓
BaseLLMClient (Qwen / DeepSeek / GLM / Mock)
```

**关键特性**：
- 结构化输出校验（`status` ∈ {correct, incorrect, uncertain}）
- API Key 保护（从环境变量读取，不记录）
- 失败降级（LLM 失败 → `uncertain`，不编造答案）

### 3. 字段检查器 (`field_checkers.py`)

#### 确定性检查器

- `entry_point`: 代码匹配（±3 行容错窗口）
- `critical_operation`: 关键操作匹配
- `commit`: 格式 + 版本范围 + 修复 commit 区分
- `trace`: 数据流节点逐一验证

#### LLM 语义检查器

- `vuln_ids`: 对比公告中的 CVE/GHSA 列表
- `vuln_title`: 语义相似度
- `vuln_category_l1`: CWE Top 25 分类
- `vuln_category_l2`: 细粒度分类（如 Reflected XSS）

**原则**：确定性事实（文件存在性、代码匹配）不能被 LLM 覆盖

### 4. Agent 闭环 (`agent.py`)

三阶段流程：

1. **Plan（规划）**: 确定需要的工具和字段优先级
2. **Execute（执行）**: 调用工具 + 字段检查，记录 `tool_trace`
3. **Self-Check（反思）**: 交叉验证，不覆盖确定性结果

**输出**：符合 `VerificationReport` 契约的 JSON 对象

### 5. 评测器 (`eval.py`)

支持两种金标格式：

- **显式三态格式**：每个字段明确标记 correct/incorrect/uncertain
- **兼容格式**：只标注 verdict（向后兼容）

**指标**：
- `field_accuracy`: 字段级准确率（≥ 0.85）
- `error_recall`: 错误召回率（≥ 0.90）
- `verdict_accuracy`: 整体判定准确率
- 字段 breakdown：逐字段准确率

---

## 验证报告格式

每条 entry 输出一行 JSONL：

```json
{
  "report_id": "GHSA-xxxx-xxxx-xxxx",
  "entry_id": "entry-00001",
  "verdict": "correct",
  "fields": {
    "entry_point": {
      "status": "correct",
      "confidence": 0.95,
      "evidence": "Code found at src/render.js:23, matches expected pattern",
      "evidence_refs": [
        {
          "source": "repository",
          "locator": "web-app/abc123.../src/render.js:23",
          "quote": "document.innerHTML = userInput;"
        }
      ]
    }
  },
  "summary": "All 8 fields verified. Entry point confirmed via source code.",
  "self_check": {
    "status": "completed",
    "agree": true,
    "comment": "Evidence consistent",
    "checked_fields": ["entry_point", "critical_operation"]
  },
  "plan": {
    "version": "1",
    "tools_planned": ["read_advisory", "checkout", "read_file_lines"],
    "fields_planned": ["entry_point", "critical_operation", "commit"]
  },
  "tool_trace": [
    {"seq": 1, "tool": "read_advisory", "ok": true},
    {"seq": 2, "tool": "checkout", "ok": true},
    {"seq": 3, "tool": "read_file_lines", "ok": true}
  ]
}
```

**关键字段**：
- `verdict`: correct / incorrect / uncertain（整体判定）
- `fields.<field>.status`: 单字段三态判定
- `fields.<field>.confidence`: 置信度（0.0 ~ 1.0）
- `fields.<field>.evidence`: 人类可读的判定理由
- `fields.<field>.evidence_refs`: 结构化引用（来源 + 定位符 + 引用片段）

---

## 测试与 CI

### 运行测试

```bash
# 从仓库根目录运行全部测试
cd VulnGym
pytest tests/ -v

# 运行特定模块测试
pytest tests/test_agent.py -v
pytest tests/test_eval.py -v
pytest tests/test_robustness.py -v

# 覆盖率报告
pytest tests/ --cov=vulngym_verify_demo --cov-report=html
```

### 测试覆盖

- **368 个单元测试**（100% 通过）
- 模块：Schema、Tools、Field Checkers、LLM、Agent、CLI、Eval
- 场景：正常路径、异常容错、边界条件、安全检查

### CI 门禁

- GitHub Actions（`.github/workflows/test.yml`）
- Python 3.13
- 离线运行（无网络依赖）
- 自动触发：push 到 main、PR 合并

---

## 评测结果（Public Fixtures，非评测性）

> ⚠️ **这不是质量结论。** 下表来自 10~11 条 `public_fixtures/mock_data` 样本 + `--llm mock`
> 的剧本答案，只能验证流水线可跑通。它**不能**代表 T1Data、官方隐藏集或任何真实模型能力。
> `mock` 运行在正式 CLI 中被显式拒绝（`--mode evaluation`）或标记 `non_evaluative_run=true`。

| 指标 | 数值 | 阈值 | 状态 |
|------|------|------|------|
| 字段准确率（fixture+mock） | 0.950 | ≥ 0.85 | ⚠️ 非评测性 |
| 错误召回率（fixture+mock） | 1.000 | ≥ 0.90 | ⚠️ 非评测性 |
| Verdict 准确率（fixture+mock） | 1.000 | - | ⚠️ 非评测性 |

**字段分解**：

| 字段 | 准确率 | 正确 | 错误 | 不确定 |
|------|--------|------|------|--------|
| entry_point | 0.90 | 9 | 0 | 1 |
| critical_operation | 1.00 | 10 | 0 | 0 |
| commit | 0.90 | 9 | 0 | 1 |
| vuln_ids | 1.00 | 10 | 0 | 0 |
| vuln_title | 1.00 | 10 | 0 | 0 |
| vuln_category_l1 | 1.00 | 10 | 0 | 0 |
| vuln_category_l2 | 0.80 | 8 | 2 | 0 |
| trace | 1.00 | 10 | 0 | 0 |

---

## 常见问题

### Q1: 如果 LLM 不稳定怎么办？

A: 我们设计了三层容错（Resilient → Safe → Base），失败时自动降级为 `uncertain`，不会编造答案。Mock 模式可用于 CI 和演示。

### Q2: 如何处理大规模数据集？

A: Standard 版本是顺序处理。Bonus 方向包括多进程并发、增量评测、LLM batch API 优化。

### Q3: 证据引用会泄漏敏感信息吗？

A: 不会。我们对绝对路径做了脱敏，`evidence_refs` 使用相对路径；API key 从不记录到日志或报告。

### Q4: 支持哪些编程语言？

A: Standard 支持通用工具（文本匹配）。Bonus I11 计划扩展 Python/JS/Go/Java 的语法感知检查。

### Q5: 如何验证证据真实性？

A: 我们提供证据抽查脚本（`scripts/evidence_audit.py`），按 4 项 rubric（来源可定位、内容支持结论、未编造、置信度匹配）判定。目标通过率 ≥ 80%。

---

## 文档索引

- **设计文档**: [`docs/DESIGN.md`](docs/DESIGN.md) - 架构、模块详解、常见陷阱
- **演示脚本**: [`demo/DEMO_SCRIPT.md`](demo/DEMO_SCRIPT.md) - 5 分钟演示流程
- **测试集说明**: [`public_fixtures/README.md`](public_fixtures/README.md) - 公开测试集覆盖
- **隐藏集模板**: [`../reports/hidden_eval_summary_template.json`](../reports/hidden_eval_summary_template.json) - 隐藏测试集汇总格式
- **Schema 规范**: [`vulngym_verify_demo/report_schema.json`](vulngym_verify_demo/report_schema.json) - VerificationReport JSON Schema

---

## 贡献与反馈

欢迎提 Issue 和 PR！

- 仓库：https://github.com/perhaps468/VulnGym
- Issue 模板：请包含复现步骤、预期行为、实际行为
- PR 要求：通过全部测试、符合代码风格、更新相关文档

---

## 许可证

MIT License

---

**维护者**: VulnGym Team  
**最后更新**: 2026-09-03