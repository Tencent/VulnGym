# 配置类与非污点类漏洞标注规范

## 1. 适用范围

传统污点漏洞通常可以表达为“外部输入 → 传播 → 危险操作”。配置类漏洞不同：
风险来自一个在构建、部署或运行阶段持续生效的安全状态，例如默认 root 用户、
过宽 capability、开放调试模式或免密 sudo。此时不存在必须被追踪的攻击者字符串，
强行套用污点流会产生大量无关节点。

在不修改当前 schema 的前提下，VulnGym 仍可使用
`entry_point`、`critical_operation` 和 `trace` 表达这类漏洞，但三者应解释为：

| 字段 | 配置类语义 |
|---|---|
| `entry_point` | 危险配置状态进入相关作用域的位置：继承来源、配置块入口或显式配置声明 |
| `critical_operation` | 危险配置本身，或缺失加固无法定位时该状态实际产生安全影响的最窄操作 |
| `trace` | 配置的声明、继承、覆盖、权限转换及最终生效顺序，而非攻击者数据传播 |

## 2. Entry point 选择规则

### 2.1 继承型配置

当危险状态来自基础镜像、父配置或默认值，选择建立该配置作用域的声明。
例如 Dockerfile 没有 `USER` 时，`FROM` 是默认用户继承的起点。

`FROM` 本身通常不是缺陷；`desc` 必须说明真正的问题是后续没有覆盖默认状态，
不能简单写成“使用某基础镜像导致漏洞”。

### 2.2 显式危险配置

当危险状态在文件中被明确创建，应把入口下移到该配置块，而不是机械地选择文件首行。
例如创建 `app` 用户后立即写入 `NOPASSWD:ALL` 时，用户与授权配置块就是相关作用域入口。

### 2.3 不允许虚构缺失节点

“没有 `USER`”“没有鉴权开关”等缺失项没有对应源码行。不得创建 `line: 0`、
伪造代码或把注释当成实际节点。缺失事实应写入相邻真实节点的 `desc`，并由
`trace` 展示状态从声明到生效期间始终未被覆盖。

## 3. Critical operation 选择规则

优先级如下：

1. **显式危险配置声明**：例如 `NOPASSWD:ALL`、`privileged: true`。
2. **权限转换失效点**：例如表面切换到低权限用户，但仍保留完整提权能力。
3. **配置实际生效点**：当缺陷是缺少加固声明时，选择构建或运行时真正以危险状态执行的
   最窄指令，例如 root 身份下的依赖安装或容器 `ENTRYPOINT`。

不要把整个文件或多个普通步骤聚合为一个宽泛 critical block；关键操作应该尽量窄，
其余必要上下文放入 `trace`。

## 4. Trace 组织规则

配置 trace 使用以下关系：

- `inherits`：从基础镜像或父配置继承状态；
- `declares`：显式创建危险配置；
- `overrides`：后续配置覆盖既有状态；
- `fails_to_neutralize`：名义安全转换没有消除危险能力；
- `takes_effect_at`：构建或运行时操作消费该状态。

当前 schema 没有关系类型字段，因此这些关系通过 `desc` 说明。节点仍按配置生命周期顺序排列。

应保留：

- 配置继承或显式声明；
- 实际权限转换；
- 能证明配置可用的操作；
- 最终构建或运行时生效点。

应删除：

- 与安全属性无关的普通 `WORKDIR`、`ENV`、`COPY`；
- 仅重复“仍然是 root”但没有新增语义的每个构建步骤；
- 为了凑出传统污点链而加入的虚假 caller/callee 节点。

## 5. Issue #8 四条样本决策

所有节点均来自 OpenClaw 漏洞提交
`c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1`。后续修复提交
`84281abd4bd1c717bb37a2de12694fe203827eee` 在前三个缺少 `USER` 的
Dockerfile 中分别新增 `USER appuser`，直接证明默认 root 状态未被覆盖是这些样本的
安全根因。第四个 Dockerfile 已有 `USER app`，其问题应按显式
`NOPASSWD:ALL` 危险授权单独解释，不能套用“缺少 USER”的结论。

### `entry-00241`

- `entry_point`：`FROM node:22-bookworm`，表示默认 root 状态的继承入口。
- `critical_operation`：`CMD ["bash"]`，表示缺失 `USER` 后运行时 root 状态的实际生效点。
- `trace`：基础镜像继承 → root 下依赖安装/构建 → root 下默认进程。

### `entry-00242`

- `entry_point`：`FROM node:22-bookworm`。
- `critical_operation`：root 下执行 `pnpm install`，依赖生命周期脚本获得 uid 0。
- `trace`：基础镜像继承 → 依赖安装生效。普通目录和复制步骤不参与配置语义。

### `entry-00243`

- `entry_point`：`FROM node:22-bookworm-slim`。
- `critical_operation`：以未降权状态启动测试安装器的 `ENTRYPOINT`。
- `trace`：基础镜像继承 → 系统路径中的启动器准备 → root 运行时入口。

### `entry-00244`

- `entry_point`：创建 `app` 并写入 sudoers 的配置块，而不是无关的 `FROM`。
- `critical_operation`：精确到 `app ALL=(ALL) NOPASSWD:ALL`。
- `trace`：危险授权声明 → `USER app` 名义降权 → `sudo chmod` 证明授权可用 →
  运行时入口继承可恢复 root 的能力。

该样本与前三条不同：它存在 `USER app`，漏洞不是“完全没有 USER”，而是该用户拥有免密全量
sudo，使降权不构成真实安全边界。

## 6. Schema 兼容性

本次修改不新增字段，也不改变 `SCHEMA.md`。未来可考虑增加可选字段：

```json
{
  "annotation_kind": "configuration",
  "evidence_relation": "inherits | declares | fails_to_neutralize | takes_effect_at"
}
```

这些只能作为向后兼容的可选扩展；在 schema 正式升级前，评测器不得依赖它们。

## 7. 验证要求

- 每个 `{file, line, code}` 必须与 entry 固定的漏洞 commit 精确匹配。
- `desc` 必须解释有效安全状态和后果，不能只复述指令。
- 缺失配置只能通过真实邻接节点和说明表达。
- 修改后的 JSONL 必须继续满足现有 schema、行数、排序和 report 映射约束。
- 发生语义修改后保留 `verify=0`，等待维护者人工确认。

本次交付可用以下命令复现和校验：

```bash
# 从固定的 OpenClaw 漏洞提交重建四条标注与字段级对比 CSV
python3 scripts/apply_issue8_config_annotations.py

# 逐字核对漏洞节点，并验证修复提交为三个文件新增 USER appuser
python3 scripts/apply_issue8_config_annotations.py --check-upstream

# 校验四条样本、数据集映射、schema 形状和对比产物
python3 -m unittest discover -s tests -p "test_issue8_config_annotations.py" -v
```

离线复核时可通过 `--source-repo /path/to/openclaw` 指向包含该提交的本地仓库。
