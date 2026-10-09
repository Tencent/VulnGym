# VulnGym 验证系统设计文档

**版本**: 1.0  
**日期**: 2026-09-03  
**项目**: VulnGym T1 字段级数据验证系统

---

## 1. 系统概述

VulnGym 验证系统是一个基于 LLM + 确定性工具的混合验证引擎，用于对漏洞数据集（entries.jsonl）进行字段级自动化审核。

### 核心目标

- **字段准确率** ≥ 0.85
- **错误召回率** ≥ 0.90（对标注错误的 entry 能准确识别）
- **证据可追溯率** ≥ 80%（抽查 20 条报告）
- **鲁棒性**：缺失字段、坏 commit、公告 404、LLM 失败等异常不崩溃

### 验证字段（8 个核心字段）

1. `entry_point` - 漏洞入口点（文件路径、行号、代码片段）
2. `critical_operation` - 关键操作点（危险函数调用）
3. `commit` - 引入漏洞的 commit SHA
4. `vuln_ids` - 漏洞标识符（CVE/GHSA）
5. `vuln_title` - 漏洞标题
6. `vuln_category_l1` - 一级分类（CWE Top 25）
7. `vuln_category_l2` - 二级分类（具体漏洞类型）
8. `trace` - 数据流追踪路径

---

## 2. 架构设计

### 2.1 三层架构

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (cli.py)                   │
│  - JSONL 批处理                                          │
│  - 配置管理（--llm, --repo-cache, --advisories）        │
│  - 日志与退出码                                          │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                 Agent Layer (agent.py)                  │
│  - 规划（Plan）：识别需要检查的字段和工具                │
│  - 执行（Execute）：调用工具 + LLM                       │
│  - 反思（Self-Check）：交叉验证和置信度评估              │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│              Tool + LLM Layer                           │
│                                                         │
│  ┌─────────────────────┐   ┌──────────────────────┐   │
│  │  VulnGymTools       │   │   LLM Client         │   │
│  │  (tools.py)         │   │   (llm_client.py)    │   │
│  ├─────────────────────┤   ├──────────────────────┤   │
│  │ • read_advisory     │   │ • Qwen               │   │
│  │ • checkout          │   │ • DeepSeek           │   │
│  │ • read_file_lines   │   │ • GLM                │   │
│  │ • grep_code         │   │ • Mock (fallback)    │   │
│  │ • git_log           │   │ • SafeLLMClient      │   │
│  └─────────────────────┘   │ • ResilientLLMClient │   │
│                            └──────────────────────┘   │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │     Field Checkers (field_checkers.py)          │  │
│  │  - 确定性检查器（代码匹配、文件存在性）            │  │
│  │  - LLM 语义检查器（分类、标题、vuln_ids）         │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```
Input Entry (JSONL line)
    ↓
[Schema Validation] ← 14 必填字段校验
    ↓
[Plan Generation] ← 确定需要的工具和字段
    ↓
[Tool Execution] ← 并行调用工具（read_advisory + checkout）
    ↓
[Field Checking] ← 8 个字段独立检查
    ├─ Deterministic Checkers (entry_point, critical_operation, commit, trace)
    └─ LLM Semantic Checkers (vuln_ids, vuln_title, category_l1, category_l2)
    ↓
[Self-Check] ← 交叉验证和置信度调整
    ↓
[Verdict Aggregation] ← correct | incorrect | uncertain
    ↓
Output Report (JSONL line)
```

---

## 3. 核心模块详解

### 3.1 工具层（VulnGymTools）

**职责**：提供只读、无副作用的查询接口

| 工具 | 输入 | 输出 | 异常处理 |
|------|------|------|----------|
| `read_advisory` | `report_id` (GHSA-xxx) | JSON 对象（公告内容） | 404 → `ok=false` |
| `checkout` | `project`, `commit` (40位) | 临时工作目录路径 | 坏 commit → `ok=false` |
| `read_file_lines` | `cwd`, `file`, `start`, `end` | 代码行列表 | 文件不存在 → `ok=false` |
| `grep_code` | `cwd`, `pattern`, `file` | 匹配行列表 | 无匹配 → `[]` |
| `git_log` | `cwd`, `since_commit`, `limit` | commit 历史 | 坏 commit → `ok=false` |

**缓存策略**：
- Standard 模式：预生成只读快照（`mock_repo/<project>/<commit>/`）
- 无网络依赖，并发读取安全
- Bonus：可选 Git worktree 后端（独立工作树）

**安全性**：
- 拒绝路径穿越（`..` 检测）
- 拒绝短 commit（必须 40 位十六进制）
- 不泄漏绝对路径到日志/报告

### 3.2 LLM 客户端（llm_client.py）

**三层容错架构**：

```
User Input (--llm qwen)
    ↓
ResilientLLMClient (重试 + 超时)
    ↓
SafeLLMClient (JSON 解析 + schema 校验)
    ↓
BaseLLMClient (Qwen / DeepSeek / GLM)
    ↓
[成功] → 结构化响应
[失败] → Mock fallback (uncertain + 错误原因)
```

**关键特性**：
- **结构化输出校验**：`status` ∈ {correct, incorrect, uncertain}，`confidence` ∈ [0, 1]
- **API Key 保护**：从环境变量读取，不记录到 tool_trace
- **降级策略**：LLM 失败 → `uncertain`，禁止关键词启发式判 `correct`
- **Mock 模式**：用于 CI 和演示，无需真实 API key

### 3.3 字段检查器（field_checkers.py）

#### 确定性检查器

| 字段 | 检查逻辑 | 证据来源 |
|------|----------|----------|
| `entry_point` | ① checkout → ② 文件存在 → ③ 代码匹配（±3行容错窗口） | repository |
| `critical_operation` | ① checkout → ② 文件存在 → ③ 关键操作匹配 | repository |
| `commit` | ① 格式校验（40位hex）→ ② 缓存中存在 → ③ 版本范围匹配 | git + advisory |
| `trace` | ① 每个节点独立检查 → ② 全部通过 → `correct` | repository |

**容错窗口**：代码匹配允许 ±3 行漂移（应对格式化/注释变更）

**commit 语义分层**：
1. **格式有效**：40 位小写十六进制
2. **可解析**：缓存/仓库中存在
3. **语义匹配**：在受影响版本范围内，且非修复 commit

#### LLM 语义检查器

| 字段 | 检查逻辑 | Prompt 策略 |
|------|----------|-------------|
| `vuln_ids` | 对比公告中的 CVE/GHSA 列表 | 提取标识符 → 集合比较 |
| `vuln_title` | 语义相似度判断 | 关键词匹配 + 同义词 |
| `vuln_category_l1` | CWE Top 25 分类 | 枚举约束 + 描述对齐 |
| `vuln_category_l2` | 细粒度分类（如 XSS → Reflected XSS） | 层次化分类树 |

**Prompt 模板版本化**：每个字段的 prompt 固定在代码中，便于回溯和 A/B 测试

### 3.4 Agent 闭环（agent.py）

#### 三阶段流程

**① Plan（规划）**
- 输入：entry 的 8 个字段
- 输出：`tools_planned`（需要的工具列表）、`fields_planned`（优先级排序）
- 固定版本号：`plan.version = "1"`

**② Execute（执行）**
- 并行调用工具：`read_advisory` + `checkout`（无依赖关系）
- 顺序检查字段：按 `fields_planned` 顺序
- 记录 `tool_trace`：每次工具调用生成一条 trace（seq, tool, input, ok, evidence_refs）

**③ Self-Check（反思）**
- 交叉验证：entry_point 和 trace 是否一致？
- 置信度调整：多个字段 `incorrect` → 降低其他字段 `confidence`
- 不覆盖确定性结果：LLM 不能改变文件存在性、代码匹配等事实

**输出**：
```json
{
  "self_check": {
    "status": "completed",
    "agree": true,
    "comment": "All checks passed, evidence consistent",
    "checked_fields": ["entry_point", "critical_operation", "commit"]
  }
}
```

---

## 4. 关键设计决策

### 4.1 确定性优先原则

**规则**：能用工具确定的事实，不用 LLM 猜测

- ✅ 文件存在性 → `checkout` + `read_file_lines`
- ✅ 代码匹配 → `grep_code` + 字符串比较
- ✅ Commit 格式 → 正则表达式
- ❌ 分类语义 → LLM（CWE 分类需要语义理解）

### 4.2 三态输出模型

| 状态 | 含义 | 适用场景 |
|------|------|----------|
| `correct` | 高置信度正确 | 代码精确匹配、公告字段完全一致 |
| `incorrect` | 高置信度错误 | 文件不存在、行号超出范围、分类明显不符 |
| `uncertain` | 信息不足 | 公告 404、LLM 失败、版本范围模糊 |

**Verdict 汇总规则**：
- 任一字段 `incorrect` → verdict = `incorrect`
- 全部字段 `correct` → verdict = `correct`
- 其余 → verdict = `uncertain`

### 4.3 证据可追溯性

每个字段必须提供 `evidence` 和 `evidence_refs`：

```json
{
  "status": "correct",
  "confidence": 0.95,
  "evidence": "Code matches at line 42 in src/auth.js",
  "evidence_refs": [
    {
      "source": "repository",
      "locator": "auth-svc/444.../src/auth.js:42",
      "quote": "if (user.role !== 'admin') throw new Error('Unauthorized');"
    }
  ]
}
```

**引用来源**：
- `advisory`：公告内容（GHSA/CVE 描述、受影响版本）
- `repository`：源码（文件路径、代码片段）
- `git`：commit 历史（SHA、作者、时间）

**报告级双来源要求**：每条报告整体必须同时覆盖 advisory 和 repository 两类来源

### 4.4 坏输入容错

**问题**：批处理中单条坏 JSON 导致整个流程崩溃

**解决方案**：
- 坏 JSON 行 → 生成 `__invalid_input__:<line_no>` 报告
- 缺失必填字段 → 输出 `input_error` 对象
- verdict = `uncertain`，evidence 说明具体缺失项

示例：
```json
{
  "report_id": "__invalid_input__:5",
  "entry_id": "__invalid_input__:5",
  "verdict": "uncertain",
  "input_error": {
    "line_no": 5,
    "kind": "invalid_json",
    "message": "Expecting property name enclosed in double quotes: line 1 column 42"
  },
  "fields": { /* 8 个字段全部 uncertain */ }
}
```

---

## 5. 常见陷阱与解决方案

### 陷阱 1：LLM 幻觉覆盖事实

**问题**：文件不存在，但 LLM 判 `correct`

**解决**：
```python
# ❌ 错误做法
if llm_result.status == "correct":
    return llm_result

# ✅ 正确做法
if tool_result.ok == False:
    return FieldResult(status="incorrect", evidence="File not found")
# LLM 只在工具成功时参与语义判断
```

### 陷阱 2：修复 commit 当作引入 commit

**问题**：公告中 `patched_version` 的 commit 被误判为漏洞 commit

**解决**：
- manifest.json 增加 `role` 字段：`vulnerable | fixed | unknown`
- commit 检查器明确区分受影响版本 vs 修复版本

### 陷阱 3：路径穿越攻击

**问题**：恶意 entry 包含 `../../etc/passwd`

**解决**：
```python
def _validate_path(file_path: str) -> bool:
    if ".." in file_path:
        return False
    # 进一步规范化检查
    normalized = os.path.normpath(file_path)
    return not normalized.startswith("..")
```

### 陷阱 4：API Key 泄漏

**问题**：tool_trace 记录了完整的 LLM request（含 key）

**解决**：
- `tool_trace.input` 只记录脱敏摘要（如 `{"field": "vuln_title", "prompt_len": 1024}`）
- 不记录 `QWEN_API_KEY` 等环境变量值

### 陷阱 5：容错窗口过大导致误判

**问题**：±10 行容错导致匹配到无关代码

**解决**：
- 窗口固定为 ±3 行
- 代码必须去除空白后完全匹配（`strip()` + 字符串比较）
- 超出窗口 → `incorrect` + evidence 说明实际行号

---

## 6. 性能与可扩展性

### 当前性能（Standard）

- **吞吐量**：~10 entries/min（Mock 模式）
- **延迟**：单条 entry ~6 秒（含 LLM 调用）
- **并发**：顺序处理（单进程）

### Bonus 优化方向

1. **并发处理**：多进程 pool，共享只读缓存
2. **Git worktree 后端**：支持网络拉取，独立工作树隔离
3. **LLM batch API**：批量调用减少网络开销
4. **增量评测**：只重跑修改过的 entry

---

## 7. 测试策略

### 7.1 单元测试（368 个测试）

| 模块 | 测试文件 | 覆盖内容 |
|------|----------|----------|
| Schema | `test_schema.py` | 输入校验、坏 JSON、round-trip |
| Tools | `test_tools.py` | 每个工具的正常/异常路径、路径穿越 |
| Field Checkers | `test_field_checkers.py` | 8 个字段的 correct/incorrect/uncertain |
| LLM | `test_llm.py` | Mock、Safe、Resilient 三层 |
| Agent | `test_agent.py` | Plan/Execute/Self-Check 闭环 |
| CLI | `test_cli.py` | JSONL 批处理、配置、退出码 |
| Eval | `test_eval.py` | 字段准确率、错误召回、指标输出 |

### 7.2 集成测试

**Fixture**：`public_fixtures/` (11 条样本)
- 10 条正常样本（覆盖 8 种漏洞类型）
- 1 条异常输入（坏 JSON）

**CI 门禁**：`.github/workflows/test.yml`
- Python 3.13
- pytest + coverage
- 离线运行（无网络依赖）

### 7.3 端到端验收

**抽查方法**：
1. 固定 seed=20260902，随机抽取 20 条报告
2. 按 rubric 判定：来源可定位、内容支持结论、未编造、置信度一致
3. 通过率 ≥ 80%

---

## 8. 部署与运维

### 8.1 环境要求

- Python 3.13+
- 依赖：`openai`（兼容接口）、`pytest`、`jsonschema`
- 无需 GPU（LLM 通过 API 调用）

### 8.2 配置管理

环境变量：
```bash
# Qwen
export QWEN_API_KEY="sk-..."
export QWEN_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
export QWEN_MODEL="qwen-turbo"

# DeepSeek
export DEEPSEEK_API_KEY="sk-..."
export DEEPSEEK_BASE_URL="https://api.deepseek.com"
export DEEPSEEK_MODEL="deepseek-chat"

# GLM
export GLM_API_KEY="..."
export GLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
export GLM_MODEL="glm-4-flash"
```

### 8.3 运行命令

```bash
# Mock 模式（CI/演示）
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --out reports.jsonl \
  --llm mock \
  --bench

# 真实 LLM 模式
python -m vulngym_verify_demo \
  --entries path/to/entries.jsonl \
  --repo-cache path/to/cache \
  --advisories path/to/advisories \
  --out reports.jsonl \
  --llm qwen \
  --verbose
```

---

## 9. 未来规划

### Standard 完成后（本次交付）

- [x] I1-I5: 基础设施 + 字段检查器 + LLM 适配
- [x] I6-I7: CLI 批处理 + 评测器 + CI
- [ ] I8: 文档 + 演示材料

### Bonus 方向

- [ ] I9: 系统性错误归因（跨 entry 聚合）
- [ ] I10: 错误字段修正建议
- [ ] I11: 多语言代码适配（Python/JS/Go/Java）

---

**文档维护者**: VulnGym Team  
**最后更新**: 2026-09-03
