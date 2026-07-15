# OpenClaw fs-bridge 分阶段写入链路重建报告

## 1. 范围与重复检查

本报告关联 [Tencent/VulnGym#7](https://github.com/Tencent/VulnGym/issues/7)。

现有 `#15`、`#20`、`#24`、`#29`、`#47` 均集中在 issue 优先列出的五条样本：
`entry-00185`、`entry-00197`、`entry-00290`、`entry-00320`、`entry-00391`。
检索全部开放及已关闭 PR 后，没有提交提及以下目标：

- `GHSA-MJ4P-RC52-M843`
- `entry-00301`
- `entry-00302`
- `fs-bridge` staged-write TOCTOU

因此本次不修改五条优先样本，也不改写已有 PR，而是修复同属“整体错位和多阶段利用”类型的两条未覆盖记录。

## 2. 公告与补丁证据

- 漏洞公告：[GHSA-MJ4P-RC52-M843](https://github.com/advisories/GHSA-MJ4P-RC52-M843)
- 数据集绑定的漏洞快照：`3caab9260cb0a0064e6a37b2de3bedc8a547e599`
- 修复提交：[`11924a7`](https://github.com/openclaw/openclaw/commit/11924a70264f235b2b1d47e3d32a5f0dae111bb1)
- 修复提交直接父节点：`702f6f3305653922548ed2f5c78228ef3c3573e7`

公告说明旧实现只在最终提交前重新校验目标，却没有把临时文件的创建和写入固定到已验证的父目录。
父路径别名在首次检查后被替换时，`mktemp` 和 `cat` 会先把攻击者控制的字节写到允许挂载之外；
后续即使拒绝最终 `mv`，也无法撤销已经物化的临时文件。

修复提交与这一成因逐项对应：

1. 删除 `writeFileToTempPath()` 和只保护最终 `mv` 的 `buildWriteCommitPlan()`。
2. 新增 `resolvePinnedWriteEntry()`，把目标拆为挂载根、相对父路径和 basename。
3. 使用目录 fd 逐段打开父目录。
4. 使用 `os.open(..., dir_fd=parent_fd)` 创建临时文件。
5. 使用 `os.replace(..., src_dir_fd=parent_fd, dst_dir_fd=parent_fd)` 完成原子替换。

## 3. 修复前的问题

### `entry-00301`

- `entry_point` 是 `readFile` 方法末尾的孤立 `}`，既不接收输入，也不调用写入逻辑。
- trace 把 `signal?: AbortSignal` 描述成攻击者控制竞态时序的手段，但公告和补丁均没有这一前提。
- `critical_operation` 指向 `resolveAnchoredSandboxEntry()` 内的路径规范化检查；该 helper 服务于其他文件操作，并不是旧 `writeFile` 的危险写入点。

### `entry-00302`

- 整条链错误地围绕只读 `stat()` 和 `buildStatPlan()` 展开。
- 公告描述的是 staged write，而非 `stat` 跟随符号链接造成的读取或路径穿越。
- `critical_operation` 是函数声明，不会创建文件、写入字节或改变安全状态。

## 4. 重建后的两个真实入口

### `entry-00301`：沙箱 write/edit 工具

`createSandboxWriteOperations()` 接收模型控制的 `absolutePath` 和 `content`，随后调用：

```text
write/edit tool
  -> bridge.writeFile({ filePath, data })
  -> resolveResolvedPath + assertPathSafety
  -> writeFileToTempPath
  -> dirname(target)
  -> mktemp "$dir/..."
  -> cat > "$tmp"
  -> final recheck + mv
```

### `entry-00302`：apply_patch 工具

`apply_patch.execute()` 接收模型控制的 patch input；add/update hunk 产生目标路径和内容，并经 sandbox fileOps 映射到同一个 bridge：

```text
apply_patch input
  -> parsed hunk path/content
  -> fileOps.writeFile
  -> bridge.writeFile({ filePath, data })
  -> resolveResolvedPath + assertPathSafety
  -> writeFileToTempPath
  -> mktemp + cat
  -> final recheck + mv
```

两条 entry 现在代表两个独立可达入口，而不是用无关的源码文件凑出两条记录；它们共享同一个真实危险操作是合理的多入口汇聚。

## 5. 多阶段利用语义

重建后的 trace 明确表达以下时序：

1. **输入阶段**：模型提供文件路径、写入内容或 patch。
2. **首次检查阶段**：`assertPathSafety()` 确认当时的目标位于可写挂载内。
3. **竞态状态变化**：检查结果没有绑定父目录 fd，父路径别名仍可被替换。
4. **危险使用阶段**：shell 重新执行 `dirname`，随后在可变目录执行 `mktemp` 和 `cat`。
5. **过晚的最终检查**：`buildWriteCommitPlan()` 只在 `mv` 前重新检查目标。

`critical_operation` 定位到第 4 阶段的 `mktemp + cat`，因为这是攻击者字节首次在边界外落盘的位置。
最终 `mv` 和它的 guard 仍保留在 trace 中，用于解释为什么旧防护没有覆盖完整事务。

## 6. 未采用的候选点

| 候选 | 未采用原因 |
| --- | --- |
| `readFile` 后的 `}` | 不接收输入，也不调用写入路径 |
| `signal?: AbortSignal` | 只是取消参数；不是公告所需的竞态原语 |
| `resolveAnchoredSandboxEntry()` | 未保护旧 staged-write temp materialization |
| `stat()` / `buildStatPlan()` | 只读元数据路径，与公告影响无关 |
| 最终 `mv` | 具有重新检查，但执行时越界临时文件已经写入 |

## 7. 审计状态

两条记录原为 `verify=1`，但本次改变了入口、关键操作和整条 trace 的语义。
因此暂时降为 `verify=0`，等待维护者确认后再恢复人工审计状态，不自行把重建结果声明为既有 ground truth。

当前统计相应调整为：

- `391 / 408` 条 verified entries
- `177 / 184` 条 advisories 至少包含一条 verified entry

历史版本 `v0.1.4` 的发布统计保持不变。

## 8. 复现

```bash
export GITHUB_TOKEN="$(gh auth token)"
python scripts/rebuild_openclaw_fs_bridge_write_chain.py --base-ref upstream/main --check-upstream
python -m unittest discover -s tests -p "test_openclaw_fs_bridge_write_chain.py" -v
python examples/load_dataset.py
python -m py_compile scripts/rebuild_openclaw_fs_bridge_write_chain.py tests/test_openclaw_fs_bridge_write_chain.py
git diff upstream/main...HEAD --check
```

验证器会完成以下检查：

- canonical 数据仅有两条目标 entry、八个字段发生变化。
- 字段级 CSV 能从旧值完整回放到当前 canonical JSONL。
- 所有新节点与漏洞 commit 的对应源码逐字匹配。
- 漏洞快照位于修复提交父节点之前。
- 修复确实将临时文件创建和最终 replace 固定到已验证的父目录 fd。
