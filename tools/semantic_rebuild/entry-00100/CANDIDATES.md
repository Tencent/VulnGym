# CANDIDATES — entry-00100

与 entry-00099 同 GHSA / 同 commit；本条从「参数求值」路径进入。

## entry_point

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| E1 | `expression.ts:368` `resolveSimpleParameterValue(` | 原标注；节点参数求值入口 | **采用** |
| E2 | HTTP `@Post .../run` | 更上游 | 留给 00099；本条聚焦参数链 |

## critical_operation

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| C1 | `expression-sandboxing.ts:330-336` `sanitizer = (...)` | 原 critical | **拒绝**：属性键检查实现；逃逸时常调不到；且属 sanitizer 定义族 |
| C2 | `evaluateExpression` 19-21 | 与 00099 同一执行出口 | **采用** |
| C3 | `defineProperty(..., sanitizerName)` | 装配 `__sanitize` | **拒绝**升 critical；可留 trace |

争议处理同 00099：缺陷在 with/MemberExpression 覆盖不足，critical 钉执行出口，缺口进 trace（见 00099 CANDIDATES）。
