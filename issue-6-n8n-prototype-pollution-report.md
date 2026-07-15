# n8n 原型污染样本：共同漏洞快照与语义链复核

本次复核覆盖 `GHSA-MXRG-77HM-89HV` 的 `entry-00359`、`entry-00360`、`entry-00361`。
它们不在 Issue #6 列出的六条优先样本中，且提交前检索到的 Issue #6 竞争 PR 均未触及这组 entry。

## 发现的问题

### 1. 同一 report 绑定到了“部分已修复”的提交

三条记录原先共同绑定 `732f2a3`：

- 它是 GSuiteAdmin 修复提交 [`2d9a2ec`](https://github.com/n8n-io/n8n/commit/2d9a2ec76e180b54e8091e31b1e0638c909abd99) 的直接父提交，因此两条 GSuiteAdmin 路径仍然可见；
- 但它已经位于 XML 修复提交 [`ba687da`](https://github.com/n8n-io/n8n/commit/ba687dad5eb7377b43882bcb404709935cadbe6c) 之后，`Xml.node.ts` 已包含 `attrkey/charkey` 危险键拦截。

因此，原提交不能同时作为三条 entry 的漏洞快照。`entry-00361` 的 trace 甚至把已经存在的修复 guard 当成了漏洞链的一部分。

本次改用 `ba687da` 的直接父提交 `f7c3684`。该提交同时保留：

- XML 路径中未校验的 `options.attrkey/options.charkey`；
- GSuiteAdmin 创建/更新路径中的动态 `customSchemas[schemaName][fieldName]` 写入。

### 2. GSuiteAdmin 的真实写入被截断在前一行

原 `critical_operation` 只标到：

```ts
customSchemas[schemaName] ??= {};
```

当 `schemaName === '__proto__'` 时，该读取会得到继承的 `Object.prototype`，其值并非 nullish，所以初始化赋值不会执行。真正的攻击者属性写入发生在下一行：

```ts
(customSchemas[schemaName] as IDataObject)[fieldName] = value;
```

新标注使用两行范围，既保留对象选择语义，也覆盖实际写入。

### 3. XML 的入口与关键操作均偏离漏洞语义

- 原入口 `dataPropertyName` 只决定从 item 的哪个字段读取 XML，不承载危险属性键；真实输入是 `options` 中的 `attrkey/charkey`。
- 原关键操作 `let item: INodeExecutionData` 只是变量声明，不读取输入、不改变控制状态，也不执行危险操作。
- 新链路为 `options` 读取 -> 合并 `parserOptions` -> 初始化 Parser -> `parseStringPromise` 触发结果对象构造与动态属性写入。

## 未采用的候选点

| 候选 | 未采用原因 |
| --- | --- |
| 原提交 `732f2a3` | XML guard 已存在，无法作为三条路径的共同漏洞快照 |
| XML `dataPropertyName` | 选择输入字段，但不是污染键名来源 |
| XML `let item` | 普通变量声明，无输入消费或安全影响 |
| XML `new Parser(parserOptions)` | 是重要配置边界，保留在 trace；实际污染在解析调用消费恶意键名时触发 |
| GSuiteAdmin 单独的 `??=` | `__proto__` 已解析为非空继承对象，实际攻击者属性写入发生在下一行 |

## 审计状态

三条 entry 的绑定提交和语义字段均发生变化，因此本 PR 将其统一降为 `verify=0`，等待维护者基于新证据重新确认；不把提交者复核冒充为项目的人工作业状态。

## 复现

```bash
python scripts/verify_n8n_prototype_pollution_snapshot.py --check-upstream
python -m unittest discover -s tests -p "test_n8n_prototype_pollution_snapshot.py" -v
python examples/load_dataset.py
git diff --check
```

上游校验会逐字核对新链路的全部源码节点，并确认 `ba687da` 的父提交是 `f7c3684`、`2d9a2ec` 的父提交是原快照 `732f2a3`。
