# CANDIDATES — entry-00103

## entry_point

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| E1 | `webhook-helpers.ts:615` `}` | 原标注 | **拒绝**：不是有效语句 |
| E2 | `webhook-request-handler.ts:146-154` `setResponseHeaders` | 写头 + 读 content-type + 调判定 | **采用** |
| E3 | `sendStaticResponse` 调用 `setResponseHeaders` | 调用点 | 作 trace，避免与 entry 整段重复 |

## critical_operation

| ID | 位置 | 理由 | 裁决 |
|----|------|------|------|
| C1 | `html-sandbox.ts:20` `toLowerCase()`（无 trim） | 判定漏 trim → CSP 跳过 | **采用** |
| C2 | `setResponseHeaders` 内 `needsSandbox = ...` | 使用脏 content-type | **拒绝**：传脏值，根因在判定函数 |
| C3 | `startsWith('text/html')` | 被绕过的比较 | 可作同一函数内上下文；critical 钉缺 trim 的预处理行更贴近根因 |

## 说明

CSP/XSS：critical 落在校验缺陷合理，不与「RCE 勿标 sanitizer 定义」冲突。
