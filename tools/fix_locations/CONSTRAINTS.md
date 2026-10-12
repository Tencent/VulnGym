# Issue #4 — 开码前约束（cgflag）

写代码或让 AI 改代码前，以本文件为准。

## 五条硬约束

1. **输入**：`data/entries.jsonl` 中每个节点
   `entry_point` / `critical_operation` / `trace[*]` 的 `{file, line, code, desc?}`。
2. **成功**：在对应 `repo_url` + `commit` 的源码树上，`code` 能在修正后的
   `file`/`line`（或 range）处匹配（允许空白归一化）。
3. **失败**：0 个或 >1 个候选 → **禁止自动改**，写入 `needs_human.csv` 并说明原因。
4. **禁止**：字符串拼 JSON、破坏 `SCHEMA.md` 不变量、改无关顶层字段、
   为提高“修复率”而猜测唯一位置。
5. **验收**：先跑通官方点名
   `entry-00103` / `entry-00320` / `entry-00511` / `entry-00185`，
   再对自动修复结果人工抽查 ≥20 条。

## 匹配顺序（官方）

对匹配失败的节点，按序尝试，**仅当唯一命中时**才改 `line`/`file`：

1. 原 `file` 内、原行号邻域 ±5 搜 `code`
2. 原 `file` 全文搜 `code`
3. 全仓库搜 `code`（唯一时同时改 `file`+`line`）

## `line` 形态

- 单行：`int ≥ 1`
- 范围：字符串 `"start-end"`（`1 ≤ start ≤ end`）
- **不允许** `line == 0`

## `desc` 策略（保守）

- 默认：**不改** `desc`（避免语义幻觉）。
- 仅当 `file`/`line` 变化且旧 `desc` 明确引用旧行号、且能机械替换时，才可更新；
  否则把“需复核 desc”记入 `needs_human.csv`。

## 退化片段（仍记 needs_human）

若归一化后的 `code` 过短或仅为括号类（如 `}` / `{`），即使当前行能匹配，也记
`needs_human`，原因 `degenerate_snippet`——避免把「位置碰巧对」当成高质量标注。

## 非目标（不要用 #4 脚本解决）

- 语义上入口选错（选哪个 sink）→ 交给 #6/#7 类任务。
- 故意降低 `needs_human` 比例。
