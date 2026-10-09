# I4 — LLM 语义判定与安全降级（证据填充）

**状态：解冻** — Issue #3 (I2) 已关闭（PR #14）、Issue #4 (I3) 已关闭（PR #15），可启动。

**前置条件**：
- Issue #2 (I1) CLOSED (PR #13 merged)
- Issue #3 (I2) CLOSED (PR #14 merged, 2026-09-02)
- Issue #4 (I3) CLOSED (PR #15 merged, 2026-09-02)
- `vulngym_verify_demo/llm_client.py` 基础已有：Qwen/DeepSeek/GLM、ScriptedMockLLMClient、SafeLLMClient、ResilientLLMClient、make_client
- `vulngym_verify_demo/field_checkers.py` 已支持 evidence_refs（I3 完成）
- main HEAD: `53daf5c`

---

## 1. 目标

让 `vulngym_verify_demo/llm_client.py` 的所有 LLM 输出结构对齐 §4.1：

1. **结构化响应**统一带 `evidence_refs` 字段
2. **真实 LLM** 与 **Mock fallback**、**Safe fallback** 都遵守 §4.2：
   - 非法 JSON / 超时 / HTTP 错误 → `uncertain`，**不得**回退为 `correct`
   - `evidence` 非空 + 脱敏（无 API key、无完整本地路径）
3. **prompt 版本化**：每个语义字段的 prompt 记录版本号，与字段证据一同审计

## 2. 文件所有权

**只改 / 新建**：
- `vulngym-verify-demo/vulngym_verify_demo/llm_client.py`（结构化响应 + 脱敏）
- 可选新建 `vulngym-verify-demo/vulngym_verify_demo/prompts.py`（prompt 版本化中心）
- `tests/test_llm.py`（新建，可参考 `tests/test_schema.py` 风格）

**不改**：
- `schema.py` / `models.py`（I1 已冻结；I4 不动契约）
- `field_checkers.py`（I3 负责）
- `tools.py` / `agent.py`（I2 / I5 负责）
- 真实 LLM 网络调用路径（I4 不修改 Qwen/DeepSeek/GLM 网络协议，仅修改它们解析结果的方式）

## 3. 实施清单

### 3.1 结构化响应协议（核心）

每个 LLM 调用返回统一 JSON 结构（字符串由 `llm.chat` 返回，内部解析由 `field_checkers.py` 解析）：

```json
{
  "status": "correct|incorrect|uncertain",
  "confidence": 0.0,
  "evidence": "non-empty, redacted",
  "evidence_refs": [
    {"source": "advisory|repository|git", "locator": "...", "quote": "..."}
  ]
}
```

新增 `parse_structured_response(raw: str) -> Dict[str, Any]` 工具函数：
- 合法 JSON → 校验四键（含 `evidence_refs`）；缺失则补 `[]`
- 非法 JSON → 返回 `{status: uncertain, confidence: 0.20, evidence: "<safe>", evidence_refs: []}`
- `evidence` 空 → 补 `"LLM gave empty evidence; treating as uncertain"`
- 任何脱敏正则触发 → 用 `"<redacted>"` 占位

### 3.2 脱敏规则

复用 `schema.py._sanitize_message` 的等价逻辑（提到 `llm_client.py` 的独立函数 `redact_text`），正则：
- Windows 绝对路径 `[A-Za-z]:\\...` → `<abspath>`
- POSIX 路径 `/home/...`, `/Users/...` → `<abspath>`
- 32+ 字符 hex/base64 → `<redacted>`
- `sk-...`, `Bearer xxx` 等 key 风格前缀 → `<redacted>`

### 3.3 Prompt 版本化

新建 `prompts.py`：

```python
PROMPT_VERSIONS = {
    "vuln_title_judge": "1",
    "vuln_category_l1_judge": "1",
    "vuln_category_l2_judge": "1",
    "trace_overall_judge": "1",
    "self_check_judge": "1",
}
```

每次 `llm.chat` 调用前在 prompt 中插入：

```
[PROMPT_VERSION=vuln_title_judge@1] ...
```

`ScriptedMockLLMClient` 解析这段前缀以路由到对应剧本。
`SafeLLMClient` 在响应 `evidence` 中也记录 prompt version（便于审计）。

### 3.4 测试扩 Mock 行为

`ScriptedMockLLMClient` 当 prompt 解析失败时，**不得**默认返回 `"correct"`——必须返回 `uncertain`。当前实现是 `default → uncertain`，这点保持；但需要新增测试锁定。

### 3.5 make_client 行为不变

`make_client(prefer)` 优先级、Mock/Safe 分支规则保持原样（ISSUE_OUTLINE.md I4 与 §4.2 已要求）。I4 只在每个 client 的 `chat` 输出末尾**追加 evidence_refs 字段**。

## 4. 测试覆盖

新建 `tests/test_llm.py`：

| 测试类 | 用例数 | 覆盖 |
|--------|-------|------|
| `TestParseStructured` | 8 | 合法 JSON 全 4 键；缺 evidence_refs 自动补 []；非法 JSON → uncertain；evidence 空 → 补默认；status 非法 → uncertain |
| `TestRedactText` | 5 | Windows/Posix 路径；API key 前缀；32+ hex；混合输入；unicode |
| `TestMockClient` | 6 | title/category/vuln_ids/trace 5 类剧本返回包含 evidence_refs；default → uncertain |
| `TestSafeClient` | 3 | 任何 prompt 返回 uncertain；evidence 非空含原因；self-check 路径 |
| `TestResilientClient` | 4 | primary 成功不走 fallback；primary 失败走 fallback；degraded=True 后不重试 primary；多次失败均降级 |
| `TestMakeClient` | 5 | prefer=mock/Safe/auto 各路径；缺 key 不抛异常；返回类型是 BaseLLMClient |
| `TestRealClientSmoke` | 3 | Qwen/DeepSeek/GLM 在缺 key 时构造报 LLMError；构造参数在 env 注入时正常 |
| `TestPromptVersioning` | 2 | prompy 含 `[PROMPT_VERSION=xxx@1]` 前缀；Mock/Safe 响应都记录 version |

**测试命令**：
```bash
python -m pytest tests/test_llm.py -v
```

## 5. 验收（对 ISSUE_OUTLINE.md §5 I4）

- [ ] mock fixture 可复现（脚本 mock 输出可 JSON round-trip）
- [ ] 非法 JSON / 超时 / HTTP 错误 / 无 key → `uncertain`（绝不回退为 `correct`）
- [ ] 响应 schema、证据非空、脱敏校验有效
- [ ] API key 不出现在日志、报告、fixture
- [ ] `parse_structured_response` 接入 I3 的 field checker 调用位（I3 不依赖 I4，但 I4 接入后 I3 的 LLM 路径自动获得 `evidence_refs`）
- [ ] `make_client` 在所有路径下不抛未处理异常

## 6. 风险与回滚

| 风险 | 缓解 | 回滚点 |
|------|------|--------|
| 真实 LLM 网络测试 CI 兜底断网 | 测试仅校验缺 key 抛错，不发起真实请求；CI 用 `prefer=mock` | 关闭 `TestRealClientSmoke` 的真实段 |
| Prompt version 改动影响 I3 | I3 尚未集成 LLM 路径；I4 仅在 schema 层补字段 | 升级版本号到 `@2` |
| 脱敏过度：误删合法 hex（如 commit 40 位字符串） | 正则加 `boundary`\b 仅在词边界触发；用 fixture 锁定 false positive | 调整 `_REDACT_RX` |

## 7. 完成后产物

- 1 个 PR
- ≥ 36 个新测试，全部 pass
- `python -m pytest tests/`（包括 I1 的 138 + I3 的 34 = 172+ 测试）仍 100% pass
- 已知风险同步进 PR body（特别是"真实 LLM 失败时 fallback 至 SafeLLMClient"的承诺）
