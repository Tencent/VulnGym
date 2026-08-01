# CANDIDATES — entry-00512

与 00511 同 GHSA；本条路径是可覆写 `__sanitize`。

## entry_point

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| E1 | `expression.ts:524` `renderExpression` 方法头 | 原标注 | **弱**：只是签名 |
| E2 | `expression.ts:534-536` `vmEvaluator.evaluate(...)` | VM 路径真正把表达式送进运行时 | **采用** |
| E3 | Tournament/`evaluateExpression` | 非本条 VM 覆写路径焦点 | 留给 00099/00100 |

## critical_operation

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| C1 | `reset.ts:46` `__data.__sanitize = __sanitize` | 可写槽位 → 过滤可被废掉 | **采用**（位置原正确，强化 desc） |
| C2 | `path.replace(... __sanitize ...)` | 编译期依赖该槽位 | trace；不是可写根因 |
| C3 | 宿主 `defineProperty(..., writable:false)` | 对照「宿主锁住、VM 未锁」 | trace；非漏洞点 |

位置几乎不变时，交付增量在：更准的 entry、对照 trace、候选表与 desc。
