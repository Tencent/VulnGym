# 配置类及非污点类漏洞标注规范

本文档说明如何使用 VulnGym 现有的 `entry_point`、`critical_operation` 和
`trace` 表达配置类、缺失控制类及其他非污点类漏洞。本文不修改 `SCHEMA.md`，
也不增加必填字段。

## 1. 证据模型

配置漏洞通常没有“外部输入经过函数调用到达危险 sink”的传播过程。它们更适合表示为：

```text
配置状态的引入或声明 -> 状态的作用域、继承或覆盖 -> 危险效果的兑现
```

因此，配置类样本中的 `trace` 是有序的状态证据链，不应虚构污点、参数传递或调用关系。
只有改变安全状态、划定作用域或证明危险配置已经生效的节点才应进入 `trace`。

## 2. 字段选择原则

### 2.1 `entry_point`

选择危险状态进入当前配置作用域的最早、最小、可定位锚点：

1. 存在显式危险声明时，选择该配置块的入口或声明本身。
2. 配置需要加载或启用时，选择加载、注册或启用点。
3. 根因是缺失覆盖且错误行不存在时，选择引入默认状态的真实代码行。例如 Dockerfile
   缺少 `USER` 时，以 `FROM` 作为默认用户状态的起始锚点，并在 `desc` 中说明全文
   检查范围及缺失项。

不得为缺失项构造不存在的代码，也不得使用 `line: 0`。若配置块先建立主体、下一行才
赋予危险能力，应分别标注入口和核心缺陷。

### 2.2 `critical_operation`

选择核心缺陷或危险效果发生的最小真实位置：

- 显式危险配置优先标注配置本身，如 `NOPASSWD:ALL`，而不是任意后续执行命令。
- 缺失控制没有自身行号，应标注未覆盖状态产生安全影响的最小指令，如 `CMD`、
  `ENTRYPOINT`，或没有运行入口时的最后一个高风险构建指令。
- 不应仅为表示“影响整个文件”就把完整配置文件标成 `critical_operation`。全文件负面
  证据应写入 `desc`，避免用过宽范围降低定位精度。

配置类 `critical_operation` 不必是 `trace` 的最后一个节点。危险配置之后的实际使用
可以继续作为“配置已生效”的证据。

### 2.3 `trace`

`trace` 通常保留 2 到 5 个必要节点：

1. 状态引入或配置声明；
2. 可选的作用域建立、身份切换、覆盖或持久化；
3. 构建期或运行期效果，以及证明危险能力可用的操作。

节点必须来自漏洞提交中的真实代码，并遵循真实的文件顺序或执行顺序。普通
`WORKDIR`、`COPY`、包安装等指令只有在改变作用域、连接被执行对象或直接证明危险
效果时才应保留，不能为了补齐链路而枚举每一行。

## 3. 缺失控制与负面证据

缺少 `USER`、鉴权检查或安全响应头时，证据的一部分是“指定作用域内未出现某项控制”。
这种负面事实无法单独绑定代码行，应同时满足以下要求：

- `file`、`line` 和 `code` 仍锚定提交中的真实内容；
- `desc` 明确检查范围、缺失的控制以及平台默认值；
- 效果节点说明默认状态为何在该处仍然有效；
- advisory、平台语义和修复 diff 至少能共同支持该判断；
- 证据不足时保持 `verify: 0`，交由维护者复核，不猜测缺失链路。

## 4. GHSA-W7J5-J98M-W679 标注结果

所有代码节点均来自 OpenClaw 漏洞提交
`c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1`。安全提交
`84281abd4bd1c717bb37a2de12694fe203827eee` 在前三个 Dockerfile 末端新增
`USER appuser`（其中两处位于 `CMD`/`ENTRYPOINT` 前），进一步确认缺失用户切换是根因。

| entry | 配置根因 | `entry_point` | `critical_operation` | `trace` 行号 |
| --- | --- | --- | --- | --- |
| `entry-00241` | 默认 root 状态持续到运行期 | `scripts/e2e/Dockerfile:1` | `:23` `CMD` | 1 -> 19 -> 23 |
| `entry-00242` | 文件结束前未声明 `USER` | `scripts/e2e/Dockerfile.qr-import:1` | `:9` 最后一条 `RUN` | 1 -> 9 |
| `entry-00243` | 入口脚本默认以 root 启动 | `scripts/docker/install-sh-e2e/Dockerfile:1` | `:14` `ENTRYPOINT` | 1 -> 11 -> 14 |
| `entry-00244` | `app` 获得全量免密 sudo | `scripts/docker/install-sh-nonroot/Dockerfile:17` | `:18` sudoers 规则 | 17 -> 18 -> 20 -> 27 -> 29 |

前三个样本属于“缺失安全控制 + 默认状态继承”。`entry-00244` 已存在 `USER app`，并非
字面上的直接 root 运行；但第 18 行授予 `NOPASSWD:ALL`，第 27 行又实际使用 `sudo`
修改系统路径，证明非 root 边界可被无凭据恢复为 root 权限。它应按显式危险配置保留，
而不应把基础镜像或最终 `ENTRYPOINT` 继续标作根因。

四条记录保持 `verify: 0`。源码逐字核对能证明位置正确，但 `verify` 按 schema 表示维护者
确认的人工审计状态，不由一次贡献自动提升。

## 5. 向后兼容建议

现有 schema 足以表达本次样本，不需要立即扩展。如果后续需要机器区分链路语义，可在
minor version 中增加以下可选字段，旧消费者可以忽略：

- 顶层 `annotation_kind`：`taint_flow`、`config_state`、`control_flow` 或 `other`；
- `trace[*].role`：`state_origin`、`scope`、`override`、`materialization` 或 `effect`；
- 顶层 `missing_control`：记录缺失控制的类型、预期声明和检查作用域。

这些字段都不应替代现有的真实代码锚点，也不应改变
`{file, line, code, desc?}` 和 `trace` 数组的类型。

## 6. 提交检查清单

- `file` 在 entry 绑定的漏洞提交中存在；
- `line` 是 1-based 正整数或 schema 允许的范围；
- `code` 与对应行逐字一致，包括缩进、引号和续行反斜杠；
- `entry_point` 解释状态如何进入作用域；
- `critical_operation` 解释配置或效果为何危险；
- `trace` 表达状态演化，不虚构污点传播；
- 负面证据有明确检查范围和修复证据；
- 未经维护者确认不提升 `verify`。
