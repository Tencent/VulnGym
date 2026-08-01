# PATCH_NOTES — entry-00099 / 同 GHSA 的 00100

## Vuln snapshot

- Commit: `8ab4492e8c0b743455e51fc111441d8d5010a6ad`
- `PrototypeSanitizer` 仅有 `visitMemberExpression`；**无** `visitWithStatement`

## Patched reference

- Tag: `n8n@2.5.1`
- 在同一 sanitizer 钩子对象上新增：

```ts
visitWithStatement() {
  throw new ExpressionWithStatementError();
},
```

## 对标注的含义

| 读法 | 位置 | 本 PR |
|------|------|------|
| 补丁落点 / 保护缺口 | `visitWithStatement`（缺失）或仅 MemberExpression 覆盖 | **trace + CANDIDATES** |
| Issue：RCE 勿标 sanitizer 定义 | PrototypeSanitizer / sanitizer 函数体 | **拒绝作 critical** |
| 逃逸后执行 | `evaluateExpression` | **critical** |

补丁没有改 `evaluateExpression`；选 sink 是为满足 Issue 对 RCE critical 的约束，不是因为补丁改了那一行。
