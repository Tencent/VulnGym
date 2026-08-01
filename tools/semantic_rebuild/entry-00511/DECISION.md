# entry-00511

## 采用

- entry：`expression.ts:485`
- critical：`extend.ts:82-84`（无检查 native 返回）——见 `CRITICAL_RULE.md` 步 1–2
- verify：0（见 `VERIFY_POLICY.md`）

## 不采用

- 函数签名行（C0）：补丁插入点在 vuln 无语句可钉
- `.apply`（C2）：曾误标；补丁未改该行 → trace
- 单独正则

## 相对 #54

本条是与「钉 apply」方案的主要语义差分；以补丁 `1acdafe6ac` 为准。
