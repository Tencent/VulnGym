# I3 — 确定性字段检查器（证据填充）

**状态：解冻** — Issue #3 (I2) 已关闭（PR #14 merged），可启动。

**前置条件**：
- Issue #2 (I1) CLOSED (PR #13 merged)
- Issue #3 (I2) CLOSED (PR #14 merged, 2026-09-02)
- `vulngym_verify_demo/tools.py` 已升级（manifest 支持、path safety、无网络）
- `mock_repo/manifest.json` 已存在（8 items, 4 projects）
- `tests/test_tools.py` 已存在（39 cases pass）
- main HEAD: `e9becd4`

---

## 1. 目标

为 `vulngym_verify_demo/field_checkers.py` 中 8 个字段检查器返回的字典补齐 `evidence_refs` 字段。每个引用符合 §4.1 格式：

```json
{"source": "advisory|repository|git", "locator": "...", "quote": "..."}
```

- **确定性字段**（entry_point / critical_operation / commit / trace）：必须填 `repository` 或 `git` 引用
- **公告相关字段**（vuln_ids / vuln_title / vuln_category_l1 / vuln_category_l2）：必须填 `advisory` 引用
- LLM 判定（title / category）若 LLM 不可用，引用允许为空数组，但 `evidence` 必须解释缺口（schema.py 已校验）

## 2. 文件所有权

**只改**：
- `vulngym-verify-demo/vulngym_verify_demo/field_checkers.py`（确定部分）
- `tests/test_field_checkers.py`（新建，可参考 `tests/test_schema.py` 结构）

**不改**：
- `schema.py` / `models.py` / `__init__.py`（I1 已冻结）
- `check_all_fields` 汇总逻辑（ISSUE_OUTLINE.md I3 明确"不得修改"）
- LLM 部分（由 I4 负责）

## 3. 实施清单

### 3.1 在 field_checkers.py 顶部新增模块常量

```python
from .models import EvidenceRef

def _ref_repo(file: str, line_spec: str, quote: str, **extra) -> EvidenceRef:
    """构造 repository 类型引用。locator 格式: <commit[:7]>:<file>:<line>"""
    ...

def _ref_git(commit: str, sha: str, quote: str, **extra) -> EvidenceRef:
    """构造 git 类型引用。locator 格式: <commit>:<sha_or_message>"""
    ...

def _ref_advisory(advisory_path: str, locator: str, quote: str) -> EvidenceRef:
    """构造 advisory 类型引用。locator 用公告 JSON 路径（如 cve_id / title）"""
    ...
```

### 3.2 8 个字段的 evidence_refs 填充

| 字段 | 主要 source | locator 格式 | quote 内容 |
|------|-------------|-------------|------------|
| `entry_point` | repository | `<commit[:7]>:<file>:<line>` | 归一化后的代码片段（前 80 字符） |
| `critical_operation` | repository | `<commit[:7]>:<file>:<line>` | 同上 |
| `commit` | repository + git | `<project>/<commit>` + `git_log[-1].sha` | `commit exists in cache` 或 `no such commit` |
| `vuln_ids` | advisory | `advisory.json#cve_id` 或 `advisory.json#ghsa_id` | `CVE-XXX-YYYY` 或 `GHSA-...` |
| `vuln_title` | advisory | `advisory.json#title` | 公告 title 字符串 |
| `vuln_category_l1` | advisory | `advisory.json#vuln_category_l1_hint` | 提示字符串 |
| `vuln_category_l2` | advisory | `advisory.json#vuln_category_l2_hint` | 提示字符串 |
| `trace` | repository | 每节点一个 ref: `<commit[:7]>:<file>:<line>` | 每节点 snippet 前 80 字符 |

注意：trace 字段返回的 `evidence_refs` 是 list（多节点），不是单个 ref。

### 3.3 工厂函数集成

`check_entry_point` / `check_critical_operation` / `check_trace` 内部使用 `tools.checkout(...)` 的 `co.data["cwd"]` + `commit` 拼 locator。`tools.read_file_lines(...)` 得到的 `snippet` 直接当 quote。

### 3.4 数据：advisory JSON 路径

当前 mock 公告（如 `vulngym-verify-demo/mock_advisories/GHSA-DEMO-0001-XSS.json`）结构待确认。**前置检查**：在 I3 动工前，对一份 mock 公告做 `json.load` 查看字段：

```bash
cd vulngym-verify-demo
python -c "import json; print(json.dumps(json.load(open('mock_advisories/GHSA-DEMO-0001-XSS.json')), indent=2, ensure_ascii=False))"
```

如果 mock 公告结构与 I3 假设不一致，**先补一节** `mock_advisories` 重构工作（不阻塞主线）。

## 4. 测试覆盖（必须 100% 通过）

新建 `tests/test_field_checkers.py`，参考 `tests/test_schema.py` 的 class-grouped 风格：

| 测试类 | 用例数 | 覆盖 |
|--------|-------|------|
| `TestEvidenceRefsShape` | 6 | 8 字段返回值都含 `evidence_refs: list`；source 取值限于 frozenset；locator/quote 是 str |
| `TestEntryPointRefs` | 8 | 正确/行漂移/代码不匹配/文件缺失/无法 checkout 5 种场景下 evidence_refs 是否填充 |
| `TestCriticalOpRefs` | 4 | 匹配/不匹配/邻近漂移/grep 兜底 4 场景 |
| `TestCommitRefs` | 3 | 格式错误/缓存缺失/正常都填 git 引用 |
| `TestVulnIdsRefs` | 3 | 缺 CVE/缺 GHSA/正常 |
| `TestTitleRefs` | 2 | LLM 解析成功/失败 |
| `TestCategoryRefs` | 2 | 同上 |
| `TestTraceRefs` | 4 | 空 trace/单节点/多节点/异常节点 |
| `TestBackwardsCompat` | 2 | 汇总 `check_all_fields` 仍可用；verdict 规则不变 |
| `TestIntegrationWithI1Schema` | 2 | `validate_field_result` 对 I3 产出的字段对象全部 pass |

**测试命令**：
```bash
python -m pytest tests/test_field_checkers.py -v
```

## 5. 验收（对 ISSUE_OUTLINE.md §5 I3）

- [ ] 正确/行漂移/代码不匹配/文件缺失/无法 checkout 5 种 fixture 都有对应 case
- [ ] commit 判定分三层：格式有效 → 缓存可解析 → 与公告范围相容
- [ ] 公告仅给模糊范围时仍能正常跑（confidence 适当下调）
- [ ] 修复 commit 与引入 commit 通过 commit fixture 区分（若 I2 已提供 manifest）
- [ ] 状态/置信度/证据三件套稳定可复现
- [ ] `validate_field_result`（来自 I1）对全部字段对象 pass
- [ ] `check_all_fields` 行为不变（I5 集成 Agent 会做回归）

## 6. 风险与回滚

| 风险 | 缓解 | 回滚点 |
|------|------|--------|
| mock 公告缺少 I3 期望字段 | 已写前置检查（§3.4）；如缺，先补 mock | 仅本分支 |
| evidence_refs 增加后 `check_all_fields` 的 verdict 规则意外改变 | `TestBackwardsCompat` 锁定 verdict 规则 | 回滚 `check_all_fields` 调用前后即可 |
| LLM 输出解析仍走 try/except，evidence_refs 填充缺位 | LLM 路径由 I4 覆盖；I3 仅保证字段存在 | 允许 I3 阶段 LLM 路径 evidence_refs=[]，evidence 解释缺口 |

## 7. 完成后产物

- 1 个 PR
- ≥ 34 个新测试，全部 pass
- `python -m pytest tests/`（包括 I1 的 138 测试）仍 100% pass
- 已知风险同步进 PR body
