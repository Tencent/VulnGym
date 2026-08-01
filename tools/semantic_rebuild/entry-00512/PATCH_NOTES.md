# PATCH_NOTES — entry-00512

## Vuln snapshot

- Commit: `09e2c2b5547b49a824a8265d312583f5d1f5c79f`
- `reset.ts`：`globalThis.__data.__sanitize = __sanitize`（可写）

## Patched reference

- Commit: `1acdafe6ac` — 改为不可写描述符：

```diff
-	globalThis.__data.__sanitize = __sanitize;
+	Object.defineProperty(globalThis.__data, '__sanitize', {
+		get: () => __sanitize,
+		set: () => {
+			throw new ExpressionError('Cannot override "__sanitize" due to security concerns');
+		},
+		enumerable: false,
+		configurable: false,
+	});
```

## 对标注的含义

补丁落点 = 原 critical 行 → **位置保留**正确。  
宿主侧 `defineProperty(..., writable:false)` 与 VM 侧可写赋值的不一致写在 trace。
