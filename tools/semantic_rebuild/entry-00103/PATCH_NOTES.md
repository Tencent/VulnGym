# PATCH_NOTES — entry-00103

## Vuln snapshot

- Commit: `57d6015f2ea0442c24e0449105325b7e36f066df`
- `isHtmlRenderedContentType`：仅 `contentType.toLowerCase()`，**无** `trim`

## Patched reference

- Commit: `553b24458e` — `fix(core): Fix html header check (#22713)`

```diff
-	const contentTypeLower = contentType.toLowerCase();
+	const contentTypeLower = contentType.trim().toLowerCase();
```

## 对标注的含义

补丁只改判定函数这一行 → critical 钉 `toLowerCase`（缺 trim）与补丁落点一致。  
`setResponseHeaders` 是脏 content-type 进入判定的入口，作 entry 而非 critical。
