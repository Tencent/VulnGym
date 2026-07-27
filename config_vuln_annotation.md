# 配置类／非污点类漏洞标注

## 1. 适用范围

适用于根因来自静态配置、危险默认值、权限声明或缺少安全控制，而不是不可信输入传播的漏洞，例如：

- Dockerfile 未声明 `USER`，容器继承基础镜像的 root 用户；
- sudoers、IAM 或文件权限配置过宽；
- 安全选项被关闭或必要限制缺失；
- 第三方构建脚本以不必要的高权限执行。

这类问题可以使用现有schema 表达，不应把配置关系强行标注为污点流或调用链。

## 2. 字段标注原则

### `entry_point`

选择引入危险配置状态的最早可定位声明：

- 不安全默认值未覆盖：选择引入默认值的位置，例如 `FROM`；
- 显式危险配置：选择配置声明本身，例如 `NOPASSWD:ALL`；
- 缺少配置项：不能伪造不存在的代码节点，应锚定真实声明，并在 `desc` 中注明检查范围和缺失项。

### `critical_operation`

选择核心缺陷或危险配置的生效位置：

1. 有显式危险配置时，选择配置声明本身；
2. 缺少安全覆盖项时，选择继承危险状态的 `CMD` 或 `ENTRYPOINT`；
3. 没有显式运行入口时，选择能够证明危险权限被使用的执行指令，并在 `desc` 中明确它只代表构建阶段。

必须区分“直接以 root 运行”和“非 root 用户可以通过 sudo 提权”。

### `trace`

`trace` 只记录配置状态的改变、激活或验证节点：

- 普通 `COPY`、`WORKDIR`、安装和编译步骤不应为了补全链路而加入；
- 两端已经能完整说明问题时，使用 `"trace": []`；
- `entry_point` 和 `critical_operation` 可以指向同一危险配置，trace 可记录后续生效证据。

## 3. `desc` 编写要求

`desc` 应说明：

1. 当前节点如何引入、保留或证明危险配置；
2. 该配置为什么违反最小权限等安全要求。

描述缺失项时应给出检查范围，例如：

> 检查本 Dockerfile 第 1 至 23 行，未发现 USER 指令覆盖基础镜像的 root 默认用户。

避免使用“权限沿 COPY 传播”“调用栈”等不符合配置语义的表述，也不能推断代码无法证明的运行状态。

## 4. OpenClaw 样本处理

| Entry | `entry_point` | `critical_operation` | `trace` |
|---|---|---|---|
| `entry-00241` | `FROM` 引入 root 默认值 | `CMD` 使配置在运行时生效 | 空 |
| `entry-00242` | `FROM` 引入 root 默认值 | 最后的 `RUN pnpm install`，仅代表构建阶段 | 空 |
| `entry-00243` | `FROM` 引入 root 默认值 | `ENTRYPOINT` 使配置在运行时生效 | 空 |
| `entry-00244` | `NOPASSWD:ALL` | 同一危险配置 | `USER app` 和后续 sudo 命令 |

四条样本均可由当前 schema 表达，不需要从 benchmark 删除。

## 5. 向后兼容建议

当前修复不增加字段。未来可考虑增加可选字段：

```json
{
  "analysis_kind": "configuration",
  "negative_evidence": {
    "file": "scripts/e2e/Dockerfile",
    "scope": "1-23",
    "expected": "USER <non-root-user>",
    "desc": "检查范围内未声明 USER。"
  }
}
```

可选字段不会改变现有字段类型，旧消费者可以直接忽略。

修正后的记录继续保留 `verify: 0`，人工确认代码、行号和语义后才能改为 `1`。
