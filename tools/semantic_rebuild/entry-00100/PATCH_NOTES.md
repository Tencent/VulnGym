# PATCH_NOTES — entry-00100

与 entry-00099 同一 advisory / commit。补丁证据见 `../entry-00099/PATCH_NOTES.md`（`n8n@2.5.1` 增加 `visitWithStatement`）。

本条从 `resolveSimpleParameterValue` 进入；critical 与 00099 同为 `evaluateExpression`；原 `sanitizer` 函数体降为 trace。
