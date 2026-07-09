# 配置类/非污点类漏洞标注原则

本文说明在不扩展 `SCHEMA.md` 的前提下，如何使用现有
`entry_point`、`critical_operation` 和 `trace` 字段表达配置类或非污点类漏洞。
本次修复以 Tencent/VulnGym#8 中的 OpenClaw Dockerfile 样本为例：
`entry-00241`、`entry-00242`、`entry-00243`、`entry-00244`。

## 核心原则

1. `entry_point` 选择“配置开始生效”的最早可定位节点。
   对 Dockerfile 默认 root 用户问题，通常是 `FROM` 行，因为它引入了基础镜像的默认执行身份。若漏洞来自显式危险配置，则选择该配置项本身。

2. `critical_operation` 选择“危险配置转化为实际风险”的节点。
   若存在运行时入口，优先选择 `CMD` 或 `ENTRYPOINT`，因为它们决定容器主进程的实际权限。若样本只有构建阶段行为，则选择最能体现风险的构建执行点，例如包安装或脚本执行。若存在显式破坏隔离的配置项，例如 `NOPASSWD:ALL`，则应选择该危险配置本身。

3. `trace` 表达配置声明到生效的语义链路。
   配置类漏洞不强行伪造成污点流。trace 应按文件顺序展示“默认值/配置声明 -> 中间生效节点 -> 运行时或构建期落点”，并在 `desc` 中解释每个节点如何维持、放大或兑现危险状态。

4. 不引用不存在的修复点作为定位节点。
   例如缺少 `USER` 指令本身没有可定位行号，因此不能把“缺失的 USER”写成 `{file,line,code}`。应选择能证明该缺失影响的现有节点，如 `FROM`、`RUN`、`CMD`、`ENTRYPOINT` 或 sudoers 写入。

5. `desc` 解释安全语义，而不是复述代码。
   描述中应明确说明配置项为什么危险、何时生效、是否是构建期风险或运行时风险，以及为什么它适合作为入口、关键操作或 trace 节点。

## 本次样本处理

| Entry | 标注决策 |
|---|---|
| `entry-00241` | `FROM node:22-bookworm` 作为 root 默认身份入口，`CMD ["bash"]` 作为运行时 root shell 生效点。 |
| `entry-00242` | 无 `CMD`/`ENTRYPOINT`，因此以 `RUN pnpm install --frozen-lockfile` 作为构建期 root 执行的关键操作。 |
| `entry-00243` | `FROM node:22-bookworm-slim` 引入 root 默认身份，`ENTRYPOINT` 启动安装脚本时兑现 root 运行时风险。 |
| `entry-00244` | `FROM ubuntu:24.04` 作为权限配置链路入口，`NOPASSWD:ALL` sudoers 写入作为破坏 nonroot 隔离语义的核心危险配置。 |

## 向后兼容建议

现有 schema 可以表达本次样本，不需要破坏兼容性的字段变更。后续如需提升可读性，可考虑新增可选字段：

- `annotation_mode`: 例如 `taint_flow`、`config_effect`、`state_transition`，用于声明 trace 的语义类型。
- `missing_control`: 记录“缺少 USER 指令”“缺少校验”等不可直接定位的安全控制，仅作为解释性补充，不参与现有匹配逻辑。

这些字段应保持可选，现有消费者继续只依赖 `{file,line,code,desc}` 即可。
