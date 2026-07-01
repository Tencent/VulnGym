# entry-00176 修复说明

## 基本信息

- `entry_id`: `entry-00176`
- 项目：`n8n`
- Advisory：`GHSA-MMGG-M5J7-F83H`
- 漏洞类型：Python Code 节点沙箱逃逸，导致任意文件读取或 RCE
- vulnerable commit：`3af9095245be3aaad6bc16622f379f79c6c6068f`
- 对照修复提交：`062644ef786b6af480afe4a0f12bc6d70040534a`

本条样本复核范围为 `critical_operation` 和 `trace`，`entry_point` 按任务要求保持原值不变。原始入口点位于 `packages/nodes-base/nodes/Code/Code.node.ts:206`，该位置从 Code 节点参数中读取用户配置的 Python 代码字符串，能够体现认证用户通过 workflow 配置将不可信代码引入执行链路。

经复核，原始 `critical_operation` 标在 `packages/@n8n/task-runner-python/src/constants.py:126` 的 `BLOCKED_ATTRIBUTES = {`。该位置与补丁直接相关：修复提交向 `BLOCKED_ATTRIBUTES` 增加了 `__objclass__`，并新增 `str.__or__.__objclass__`、`str.__init__.__objclass__` 等测试用例。但从数据集语义看，静态 denylist 定义属于防护数据源和根因位置，不是用户代码实际执行的位置，也不是任意文件读取或 RCE 影响落地的操作点。因此本次将 `critical_operation` 调整为 Python runner 默认 all-items 执行路径中的 `exec(compiled_code, globals)`。

## 原问题

原始 `critical_operation` 为：

`packages/@n8n/task-runner-python/src/constants.py:126`

```py
BLOCKED_ATTRIBUTES = {
```

该节点只能说明漏洞版本的危险属性列表未覆盖 `__objclass__`。它可以解释 AST 防线为什么存在遗漏，但不能解释恶意 Python 代码通过校验后在哪里运行，也不能直接对应 advisory 中描述的文件读取或 RCE 影响。将其作为 `critical_operation` 会把“防护配置缺项”和“危险执行点”混为一谈。

原始 trace 也存在同类问题：链路在 `visit_Attribute` 和静态列表处结束，未覆盖 AST 校验通过后创建执行子进程、包装编译用户代码以及最终执行 `compiled_code` 的关键后续步骤。修复后的 trace 需要保留静态检查绕过点，同时补齐从放行到执行点的必要控制流。

## 修复位置

修复后的 `critical_operation` 为：

`packages/@n8n/task-runner-python/src/task_executor.py:213`

```py
            exec(compiled_code, globals)
```

选择该位置的理由：

1. Advisory 描述的影响是认证用户可通过 Python Code node 逃逸沙箱，读取文件或进一步实现 RCE；这些影响只有在用户 Python 代码被执行时才会成立。
2. `TaskRunner._execute_task` 在创建执行子进程前调用 `self.analyzer.validate(task_settings.code)`。若 `__objclass__` 访问未被 `visit_Attribute` 记录为违规，代码会继续进入执行器。
3. 在 Code 节点默认的 `Run Once for All Items` 模式下，用户代码由 `TaskExecutor._all_items` 接收，经 `_wrap_code()` 包装后通过 `compile(..., "exec")` 编译，随后在第 213 行由 `exec(compiled_code, globals)` 执行。
4. 该位置是漏洞链路中的实际执行 sink，能够与入口点和 AST 放行点形成完整的数据流/控制流说明。

## Trace 修复说明

修复后的 trace 保留 8 个关键节点，首节点与 `entry_point` 对齐，末节点与新的 `critical_operation` 对齐。节点选择原则是保留用户代码进入任务设置、跨层提交、AST 检查绕过、进入执行器、编译和执行等必要步骤，删除对象构造、简单桥接调用、nodeMode 分派和子进程启动参数截面等可由相邻节点推断的中间步骤。

1. `packages/nodes-base/nodes/Code/Code.node.ts:206`
   从 Python Code 节点参数中读取用户配置的代码字符串，作为不可信输入进入链路。
2. `packages/nodes-base/nodes/Code/PythonTaskRunnerSandbox.ts:50-52`
   将 `this.pythonCode` 写入 `taskSettings.code`，形成提交给 Task Runner 的任务设置。
3. `packages/nodes-base/nodes/Code/PythonTaskRunnerSandbox.ts:62-65`
   通过 `startJob('python', taskSettings, itemIndex)` 提交 Python 任务，使代码从节点层进入 Python runner 层。
4. `packages/@n8n/task-runner-python/src/task_runner.py:321`
   Python runner 调用 `TaskAnalyzer.validate(task_settings.code)` 执行 AST 静态检查。
5. `packages/@n8n/task-runner-python/src/task_analyzer.py:63-69`
   `visit_Attribute` 仅在 `node.attr` 命中 `BLOCKED_ATTRIBUTES` 时记录违规；漏洞版本未包含 `__objclass__`，因此相关属性访问不会在该检查点被阻断。
6. `packages/@n8n/task-runner-python/src/task_runner.py:323-328`
   AST 校验未发现违规后，`task_settings.code` 被传入 `TaskExecutor.create_process()`，进入子进程执行准备阶段。
7. `packages/@n8n/task-runner-python/src/task_executor.py:203-204`
   `_all_items` 将用户代码包装并编译为 `compiled_code`。
8. `packages/@n8n/task-runner-python/src/task_executor.py:213`
   `exec(compiled_code, globals)` 执行用户代码；该节点与新的 `critical_operation` 一致，是漏洞影响落地的位置。

## 未采用候选点的原因

- `packages/@n8n/task-runner-python/src/constants.py:126`
  该位置是静态 denylist 定义。补丁在此新增 `__objclass__`，说明其是根因位置，但它不是运行时执行点，因此不适合作为 `critical_operation` 或 trace 终点。
- `packages/@n8n/task-runner-python/src/task_analyzer.py:63-69`
  该位置是关键绕过检查点，已保留为 trace 节点。但它仍属于防护逻辑，不能单独解释文件读取或 RCE 的执行行为，因此不作为 `critical_operation`。
- `packages/@n8n/task-runner-python/src/task_runner.py:321`
  该位置是 AST 校验入口，能够说明漏洞代码为什么被放行，但不是用户代码执行位置。
- `packages/@n8n/task-runner-python/src/task_executor.py:256`
  per-item 模式下也存在同构的 `exec(compiled_code, globals)`。本样本主链按 Code 节点默认 `Run Once for All Items` 模式选取第 213 行；第 256 行作为同类候选执行点不单列。
- `packages/nodes-base/nodes/Code/Code.node.ts:207`、`packages/nodes-base/nodes/Code/Code.node.ts:209`
  这两个位置分别是 `PythonTaskRunnerSandbox` 对象构造和简单方法调用。`taskSettings.code` 构造与 `startJob()` 提交已覆盖用户脚本进入 Task Runner 的关键数据流，因此为保持 trace 精炼未保留。
- `packages/@n8n/task-runner-python/src/task_executor.py:66-70`、`packages/@n8n/task-runner-python/src/task_runner.py:335-339`
  这两个位置分别解释 nodeMode 分派和子进程启动包装。它们有助于理解执行机制，但不是本漏洞链路必须保留的关键节点；`create_process()` 与 `_all_items` 内的 `compile` / `exec` 已能覆盖校验放行后的执行路径。
- `packages/@n8n/task-runner-python/src/task_executor.py:424-438`
  `_filter_builtins()` 是运行时限制的一部分，负责过滤默认禁止的 builtins 并装配安全 import。本漏洞的核心在于 `__objclass__` 绕过 AST 属性访问检查后到达用户代码执行点，而不是 builtins 过滤逻辑自身失效。
