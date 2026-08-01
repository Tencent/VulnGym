# PATCH_NOTES — entry-00511

## Vuln snapshot

- Commit: `09e2c2b5547b49a824a8265d312583f5d1f5c79f`
- `findExtendedFunction` native 回退：`input[functionName]` **无**名字黑名单

## Patched reference

- Commit: `1acdafe6ac` — VM RCE prevention（在 `findExtendedFunction` 入口增加）

```ts
const name = typeof functionName === 'string' ? functionName : String(functionName);
if (UNSAFE_PROPERTY_NAMES.has(name)) {
  throw new ExpressionExtensionError(
    `Cannot access "${name}" via expression extension due to security concerns`,
  );
}
```

`UNSAFE_PROPERTY_NAMES` 含 `'constructor'`。后续 `cf602ef71c` 继续统一用 coerced `name` 做查找。

## 对标注的含义

| 位置 | 角色 | 本 PR |
|------|------|------|
| `82-84` 无检查返回 native `input[functionName]` | 安全属性失效；补丁在查找前拦截 | **critical** |
| `132-135` `.apply` | 随后执行 | **trace**（修复未改此行） |

此前若选 `.apply` 作 critical，与补丁落点不一致；已按补丁证据改回选出点。
