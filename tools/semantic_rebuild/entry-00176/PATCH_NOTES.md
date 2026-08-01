# PATCH_NOTES — entry-00176

## Vuln snapshot

- Commit: `3af9095245be3aaad6bc16622f379f79c6c6068f`（Release 2.9.2）
- `BLOCKED_ATTRIBUTES`：**无** `__objclass__`

## Patched reference

- Tag: `n8n@2.10.1`
- 同文件集合中新增 `"__objclass__",`

## 对标注的含义

补丁改的是策略集合；运行时是否逃逸取决于 `visit_Attribute` 的 `node.attr in BLOCKED_ATTRIBUTES`。

- critical 钉成员判断 = 「校验如何失败」
- 静态 `BLOCKED_ATTRIBUTES = {` = 数据缺项，Issue 不认作 critical

## getattr

`BUILTINS_DENY` 已含 builtin `getattr`；`BLOCKED_ATTRIBUTES` 已含 `__getattr__`。本 CVE 补丁补的是 `__objclass__`，不是 getattr 路径。

## 命令

```text
git -C .cache/repos/n8n show 3af9095245:packages/@n8n/task-runner-python/src/constants.py
git -C .cache/repos/n8n show n8n@2.10.1:packages/@n8n/task-runner-python/src/constants.py
```
