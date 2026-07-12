# VulnGym 代码片段定位偏差修复 — README

对应 Issue：【2026犀牛鸟】修复 VulnGym 数据中的代码片段定位偏差
https://github.com/Tencent/VulnGym/issues/4

## 运行方式

```bash
# 第一步：原位置校验 + 注释误判过滤 + ±5 行邻域搜索 + 全文件搜索（第 1-4 级）
python3 fix_entries.py

# 第二步：仅针对第一步产出的 needs_human.csv，做"全仓库搜索"兜底（第 5 级前置）
python3 repo_wide_search.py
```

`fix_entries.py` 只用到标准库 `urllib`，需要能访问 raw.githubusercontent.com（用于按
repo_url + commit 拉取漏洞样本对应的真实源码）。运行时间：全量 408 条 entries、涉及 166
个 (repo, commit) 组合、约 566 个不同文件，实测约 30 秒（含网络请求）。

`repo_wide_search.py` 需要本机可执行 `git` 且能访问 github.com（不仅仅是
raw.githubusercontent.com）：它会对 `needs_human.csv` 里出现的每个 (repo, commit) 组合执行
一次 `git fetch --depth 1 origin <commit> && git checkout FETCH_HEAD`，把完整源码快照拉到
`repos/`（按 commit 缓存，重复运行不会重复克隆），然后在整个工作区范围内逐文件搜索
`code` 的唯一匹配。`repos/` 只是运行期缓存，体积较大（本次 9 个 (repo, commit) 组合约
900MB），不作为交付物，运行完可以直接删除。

## 修复策略

对每个 `entry_point` / `critical_operation` / `trace[*]` 节点，按以下顺序判定：

1. **原位置校验**：在给定 `file` 的给定 `line`（起点）处，取 `code` 自身的行数作为窗口长度，
   比较是否与源码一致（比较时忽略每行首尾空白，以兼容 tab/space 差异）。一致则判定 `OK`，不修改。
2. **注释误判过滤**：若原位置逐行去除结尾的 `//...` / `# 中文...` 注释后能够匹配，判定为
   `ANNOTATOR_COMMENT_ONLY`——这是标注员手动追加的说明性注释（SCHEMA.md 已注明此情况），
   不是真实的定位偏差，不修改。
3. **±5 行邻域搜索**：以原 `line` 为中心，在上下 5 行范围内滑动窗口搜索与 `code` 完全一致
   （允许前后空白差异）的位置。命中且唯一 → 自动修正 `line`（多行时改写为 `"start-end"` 范围
   字符串）。
4. **全文件搜索**：邻域搜索失败时，在整个文件范围内搜索唯一匹配。命中且唯一 → 自动修正。
5. **全仓库搜索**（`repo_wide_search.py`，见下）：对仍未解决的节点，在该 (repo, commit) 的
   完整源码快照（而不只是节点声明的那个 `file`）里搜索唯一匹配，覆盖"文件路径本身写错"的场景。
   命中且唯一 → 自动修正 `file` + `line`。
6. **人工复核**：多处命中、或全仓库范围内都找不到匹配，一律写入 `needs_human.csv`，不做任何
   自动修改，并附上该样本在 GitHub 上的源码链接方便人工核查。

第 3/4 级都各自有一次"忽略行尾注释"的兜底比较（对应标注员追加中文/`//`注释导致的误判），第
5 级同样复用这一逻辑，但对"整行本身就是注释"的节点（见下方 entry-00477 等的分析）做了保护，
避免去注释后变成空串而与仓库里任意注释行"误命中"。

## 已知限制 / 待确认事项

- **单行 `line` 搭配多行 `code` 的格式规范化问题**：部分节点（如 entry-00134、entry-00405）里，
  `line` 是一个单一整数，但 `code` 实际横跨多行。若把 `line` 单纯理解为"片段起始行"，这类节点
  的内容本身是对的，不需要移动位置；但按 SCHEMA.md 的字段定义，多行片段更规范的写法应该是
  `"start-end"` 范围字符串。这类"格式规范化"是否也算本 issue 要修复的范围，还是只处理真正的
  位置偏移，建议向导师确认后再决定是否批量转换。当前脚本采用**保守口径**：只有当"以给定单行
  为起点、按 code 行数扩展"仍然对不上（即出现真正的行号漂移）时才计入修复，纯格式问题不修改
  也不计入 needs_human。
- **`entry-00477 / 00483 / 00485 / 00486 / 00488` 不是 commit 引用错误，而是 `code` 字段本身
  不是源码逐字引用**。已核实：
  - 这 5 条样本分别所属的 2 个漏洞报告（`data/reports.jsonl` 里 `GHSA-6F7G-V4PP-R667` /
    `GHSA-3XX2-MQJM-HG9X`）记录的 `commit` 字段与 `entries.jsonl` 里完全一致，说明 commit 本身
    没有串号；对应 commit 在 GitHub 上也真实存在且可访问，涉及的 `file` 路径也都存在、行数远
    大于目标行号，file/commit 本身没有问题。
  - 用 `git` 克隆这两个 commit 的完整快照人工比对后发现：这几个节点的 `line` **实际上是对的**
    （指向正确的语句起始行），但 `code` 字段不是从源码逐字复制的，而是把跨越多行的语句人工/由
    模型"折叠"成了一行，例如：
    - entry-00477 trace[4]（`packages/server/src/services/chatflows/index.ts:366`）：真实源码是
      `findOneBy({\n    id: chatflowId\n})` 三行，`code` 里写成单行
      `findOneBy({ id: chatflowId })`；
    - entry-00477 trace[2]（`packages/server/src/index.ts:223`）：真实源码 `if (isWhitelisted) {`
      与 `next()` 是两行（`}` 又和下一个 `else if` 合并在同一行），`code` 里写成单行
      `if (isWhitelisted) { next() }`；
    - entry-00483/486 的 `critical_operation`/`trace[3]`（`server/src/services/agents.ts:595`）
      和 entry-00485/488 的同名节点（`:606`）：真实源码是跨 6~10 行的对象/箭头函数体，`code`
      里用 `db.select(...)` 这样的省略号把中间内容折叠成了一行；
    - entry-00483/485/486/488 的 `trace[2]`（`server/src/routes/agents.ts:2013` / `2041`）更特殊：
      `code` 是 `// 此处应有 assertCompanyAccess(req, agent.companyId) — 缺失，...` 这种描述"本应
      有但缺失的校验"的合成注释，源码里从未真实存在过这行文字，本质上是标注员对"缺陷本身"的
      文字说明，不是对代码的引用。
    
    这几类节点无论是 ±5 行、全文件还是全仓库搜索都不可能命中（因为目标字符串本身在源码里就不
    存在逐字匹配），**不属于"定位偏差"，而是"code 字段的采集/写法问题"**，超出了本 issue"修复
    位置偏移"的范围。建议：`line` 保留（已经是对的，多行的可以顺手改成 `"start-end"` 格式），
    `code` 是否要改写为源码逐字引用、"缺失校验"类节点要不要改用别的字段表达（而不是塞进
    `code`），需要向导师确认后再处理，本次先保守地都留在 `needs_human.csv` 里不做修改。
  - 另外顺带发现 entry-00483 与 entry-00486、entry-00485 与 entry-00488 两两内容完全相同
    （同一 report_id 下的重复样本），以及同一 entry 内 `critical_operation` 与某个 `trace[i]`
    引用同一行代码，这些是数据本身的重复/冗余问题，也超出本次"位置修复"的范围，一并记录以供
    参考，未做处理。

## 交付物

- `entries.fixed.jsonl` —— 修复后的完整数据文件（408 行，格式与原文件一致）
- `fix_diff.csv` —— 每处自动修复的前后对比（entry_id / 字段路径 / 原始位置 / 新位置 / 修复策略），
  含 `fix_entries.py`（第 1-4 级）与 `repo_wide_search.py`（第 5 级）两个阶段的修复记录
- `needs_human.csv` —— 两个阶段都无法自动判定的节点清单（26 条），附源码链接
- `repo_wide_search_log.csv` —— 全仓库搜索阶段对 27 条 needs_human 记录逐条的搜索结果（含被
  排除的 `MULTI_HIT_REPO_WIDE` / `STILL_NOT_FOUND_REPO_WIDE` 等原因），供复核参考
