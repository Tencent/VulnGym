# entry-00176

## 采用

- entry_point：`Code.node.ts:206`，Python 分支读 `pythonCode`
- critical：`task_analyzer.py:66-69`，`node.attr in BLOCKED_ATTRIBUTES`
- verify：0

## 不采用

- `BLOCKED_ATTRIBUTES = {` 静态列表作 critical（Issue 点名）
- 单独 name-mangle 作 critical
- builtin `getattr` / deny 列表作本条 critical：主路径是 `__objclass__` 属性 AST，不是 `getattr()` 调用；`__getattr__` 已在黑名单
- 仅 `validate()` 包装作 critical：太早

## 补丁对照

漏洞 commit（2.9.2）集合无 `__objclass__`；`n8n@2.10.1` 已加。

候选表见 `CANDIDATES.md`。
