# 代码片段定位偏差修复脚本说明

文档对`src\config.py`和`src\main.py`进行说明，包含运行方式、依赖、修复策略和限制等。<br><br>


## 功能概述
本脚本读取 `data/entries.jsonl`，对每个 `entry_point`、`critical_operation`、`trace[*]` 节点依次检查 `{file, line, code, desc}` 是否能在对应仓库、对应 commit 中匹配。<br>
对匹配失败的节点，将依次在原始行号上下 5 行范围内、原始文件全文、整个目标仓库内尝试修正，输出修复后的数据文件 `entries.fixed.jsonl` 和修复记录文件 `fix_diff.csv`。多处命中、完全找不到、或无法判断的节点则写入 `needs_human.csv`。<br><br>

## 运行方式
### 命令行操作
在仓库根目录运行：
```bash
python src/main.py 
```
默认读取整个 `data/entries.jsonl` 文件

#### 如需读取部分数据进行测试：
在仓库根目录运行：
```bash
python src/main.py 200     #读取前200条jsonl
```
```bash
python src/main.py 50 150     #读取第50至第150条jsonl
```
<br>

### 结果输出
- 修复后的数据文件——`entries.fixed.jsonl`、
- 修改记录（前后的 `entry_id`、字段路径、原始 `file/line/desc`、新 `file/line/desc`、修复策略）文件——`fix_diff.csv`、
- 脚本无法解决，需要人工处理的节点列表——`needs_human.csv`

可通过在 `config.py` 中修改以下字段调整输出路径
```python
# 修复后输出新JSONL
FIXED_JSONL_OUTPUT_PATH = "outputs/entries.fixed.jsonl"

# 需要人工复核的csv清单
NEEDS_HUMAN_CSV_PATH = "outputs/needs_human.csv"

# 修改差异明细CSV
FIX_DIFF_CSV_PATH = "outputs/fix_diff.csv"
```

## 依赖
使用 Python 标准库 + requests（通过网络请求拉取 GitHub 上对应 commit 的源码文件，用于本地代码和线上真实代码比对匹配），无其他第三方库。<br>
推荐Python 3.8 及以上。

*★ 需要能够正常访问 GitHub raw*<br><br>

## 修复策略
### 前置校验逻辑
程序先主动下载原始 file 对应源码，对当前代码进行匹配；匹配成功直接放行，不进入修复流程。若线上源码和本地代码匹配失败，启动三级检索修复。

### 阶段 1：当前文件上下 N 行检索
- 在原始行号上下 N 行范围内滑动窗口匹配代码；
- 宽松匹配命中数量 = 1：自动修正行号，写入 diff；
- 命中 0 / 多条：进入阶段 2。

N 默认为5，可通过在 `config.py` 中修改 `LINE_SEARCH_OFFSET` 字段调整N大小。

### 阶段 2：当前完整文件全局检索
- 不限制行数，扫描整个原始文件所有行；
- 命中唯一，则自动修复行号；
- 当前文件存在任意命中（不管几条），终止流程。

### 阶段 3：同仓库跨文件检索（受控开关）
<font color="red">（本次运行试验时未能成功优化完善此部分代码，故将此功能关闭）</font>

触发前提：<br>
阶段 1 + 阶段 2 当前文件完全无任何命中；<br>
配置 `ENABLE_WHOLE_REPO_SCAN = True`。

执行逻辑：
- 获取原始文件后缀（如.ts、.py，无后缀匹配无后缀文件）；
- 调用 GitHub 接口拉取仓库所有文件，最多加载 `MAX_REPO_SCAN_FILES` 个；
- 只遍历后缀完全一致的文件，逐个下载 + 代码匹配；
- 命中唯一：自动修改 file+line，记录修复策略；
- 无命中 / 命中多条：归入人工 CSV。

### 匹配规则
- 统一换行、Tab / 多个空格压缩为单个空格、首尾去空白；
- 适配代码缩进、换行细微差异。
- 支持连续多行代码片段匹配。
<br><br>


## 限制
### 功能限制
- 自动修复仅支持「命中唯一」；多处命中一律人工复核，防止改错；
- 跨文件检索必须手动开启 `ENABLE_WHOLE_REPO_SCAN`，默认关闭；
- 跨文件仅匹配完全相同后缀，不会检索其他类型文件.
- desc 全程不会被修改，只有 file、line 可被程序改动。
- 代码匹配依赖换行符，极端换行错乱可能匹配失败。
<br><br>

脚本整体策略倾向于保守。对于不确定的节点，列入人工复核而不强行修改。

不会自动修复的情况包括但不限于：
- code 在多个位置命中。
- code 匹配失败。
- 无法找到目标仓库。
- 网络连接出现问题。
- 下载原文件时因超时等原因失败。
- code 为空。

<br>

## 运行输出
```
完成文件物理行 1，本条entry_id：entry-00057 校验处理
……
完成文件物理行 408，本条entry_id：entry-00513 校验处理

人工待处理 82 条，写入 outputs/needs_human.csv
自动修改 13 处，修改明细写入 outputs/fix_diff.csv
全文件处理完成，有效行数 408
修复文件输出：outputs/fixed_result.jsonl
```