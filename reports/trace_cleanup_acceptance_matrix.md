# Issue #5 acceptance matrix

| 验收项 | 本方案覆盖 |
|---|---|
| 完整扫描 `data/entries.jsonl` | 扫描 408 entries / 2,073 trace nodes；统计写入 JSON 与 Markdown 报告 |
| 检测 trace 内部精确重复 | 仅以 `{file, line, code}` 完全相同判定；当前发现 7 个候选 |
| 处理重复节点 desc | desc 相同且 `verify=0` 时 fix 可删除；desc 冲突或 `verify=1` 时保留 |
| 检测同文件入口前节点 | 使用 span 结束位置与 entry point span 起点比较；当前发现 139 个 |
| 检测同文件关键操作后节点 | 使用 span 起点与 critical span 结束位置比较；当前发现 237 个 |
| 可配置处理方式 | 默认 `check` 只报告；`fix` 执行安全去重；`--order-policy structural` 显式启用机械边界删除 |
| 不误排跨文件调用链 | 不排序；跳过并汇总记录 1,658 次跨文件边界比较 |
| 支持整数和范围行号 | `Span.parse()` 支持正整数和 `"start-end"`，拒绝 0、反向及非法区间 |
| 修复数据文件 | `data/entries.trace_fixed.jsonl`；保守结果与 canonical 字节级一致 |
| 修改日志 | `trace_fix_diff.csv`；当前无安全自动修改，因此只有表头 |
| 人工复核清单 | `trace_needs_human.csv` 精确记录 4 条未审核语义 finding |
| 防过期人工决策 | 每条复核项绑定 dataset / entry / node / anchor 指纹与稳定 `review_id`；只接受 `keep` / `remove` 且要求 reviewer、rationale |
| 检测报告 | `trace_structure_report.json` 与 `.md`，含策略、计数、entry 列表和输入/输出哈希 |
| Schema 兼容 | 校验 entry 排序、report 映射、节点字段、line、commit、verify 和禁止字段 |
| 可复现性 | 生成器使用标准库、固定 LF 输出；测试验证默认输出字节稳定和 fix 幂等 |
| 独立产物验证 | `verify_trace_cleanup_outputs.py` 不导入生成器，独立重算 408 entries、2,073 nodes、383 findings 并核对所有产物 |
| 源码证据 | `--check-upstream` 将 4 条人工复核样本的入口、关键操作和 finding 节点与固定提交逐字匹配 |

## 零自动修改说明

本次没有自动修改 canonical 数据不是功能缺失。当前所有 7 个重复候选都位于
`verify=1` entry 且描述冲突；4 个 `verify=0` 顺序 finding 经语义复核后也都不能仅凭
源码行号安全删除。强行产生数据 diff 会违反 Issue 要求的保守处理原则。

工具通过合成回归用例证明确定性去重和显式结构删除能力，同时把真实数据中的歧义保留到
人工复核闭环。
