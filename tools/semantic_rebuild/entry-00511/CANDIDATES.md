# CANDIDATES — entry-00511

## entry_point

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| E1 | `expression.ts:485` `data.extend = extend` | 原标注；用户可调到 extend | **采用** |
| E2 | `extend()` 函数入口 | 已在分发内部 | 偏晚 |

## critical_operation

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| C0 | `extend.ts:53` `function findExtendedFunction...` | 补丁在此插入 UNSAFE 检查 | **不选**：vuln 上仅为签名/序言，无错误逻辑可引用（见 CRITICAL_RULE） |
| C1 | `extend.ts:82-84` native 回退返回 | vuln 上首次交出 Function；补丁本应在更早拦住 | **采用** |
| C2 | `extend.ts:132-135` `.apply` | 随后执行；修复未改 | **trace**（曾误标为 critical，已撤回） |
| C3 | `.constructor` 正则 | 对参数形式无效 | trace |

相对 [#54](https://github.com/Tencent/VulnGym/pull/54)：若其 critical 仍为 `.apply`，本 PR 差异即 C1 vs C2，依据为 `1acdafe6ac`。
