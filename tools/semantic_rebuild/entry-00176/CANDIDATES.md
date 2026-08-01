# CANDIDATES — entry-00176

## 已核实（vuln commit `3af9095245` = n8n 2.9.2）

- `BLOCKED_ATTRIBUTES` **不含** `__objclass__`；`n8n@2.10.1` 已补。
- 强制拦截：`visit_Attribute` 的 `if node.attr in BLOCKED_ATTRIBUTES`（约 L66–69）。
- name-mangle（L71–74）对纯 `__objclass__` **不触发**。

## entry_point

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| E1 | `Code.node.ts:206` `getNodeParameter(...)` | Python 分支读用户脚本 | **采用** |
| E2 | `Code.node.ts:207` sandbox 构造 | 偏中间 | trace |
| E3 | JS runner `L189` | 非 Python 路径 | **拒绝** |

## critical_operation

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| C1 | `constants.py:126` `BLOCKED_ATTRIBUTES = {` | 缺项的数据 | **拒绝**（Issue：非静态声明） |
| C2 | `task_analyzer.py:66-69` 成员判断 | 放行/拦截发生处 | **采用** |
| C3 | name-mangle L71–74 | 旁路也未挡住 | trace；不作单点 critical |
| C4 | `TaskAnalyzer.validate` / `visit(tree)` | 校验包装入口 | trace；不是属性级判定 |
| C5 | 真正 `exec` 用户代码处 | 危害发生偏晚 | **不选**（易标太晚） |
| C6 | builtin `getattr` / `BUILTINS_DENY` | deny 列表含 `getattr` | **不选作本 CVE critical**：主路径是属性 `__objclass__` AST 访问，不是调用 builtin `getattr()`；`__getattr__` 已在 `BLOCKED_ATTRIBUTES`，缺的是 `__objclass__` |

## REJECT 预写

- 拒 C1：补丁改列表 ≠ critical 应钉字面量。
- 拒把「getattr 覆盖缺口」升格为本条 critical：与 advisory/`__objclass__` 补丁不对齐；若另有动态属性 PoC，应另开样本。
