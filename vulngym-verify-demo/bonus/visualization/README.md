# I10 Bonus 推理链路可视化 - 快速开始

## 立即试用

### 1. 查看统计信息

```bash
cd vulngym-verify-demo
python -m bonus.visualization.cli --reports out/reports_e2e.jsonl --stats
```

**输出示例**:
```
=== 推理链路统计 ===

总报告数: 4

Verdict 分布:
  - Correct:   1
  - Incorrect: 3
  - Uncertain: 0

平均指标:
  - 每报告工具数: 3.00
  - 每报告失败工具数: 1.00

覆盖率:
  - 包含 Plan: 4 (100.0%)
  - 包含 Self-Check: 4 (100.0%)

总错误字段数: 3
```

### 2. 可视化单条报告

```bash
python -m bonus.visualization.cli \
  --reports out/reports_e2e.jsonl \
  --report-id entry-00002 \
  --output chain.md
```

打开 `chain.md` 查看完整的 Mermaid 流程图。

### 3. 批量可视化错误报告

```bash
python -m bonus.visualization.cli \
  --reports out/reports_e2e.jsonl \
  --output-dir out/chains/ \
  --filter-verdict incorrect
```

生成的文件：
- `out/chains/entry-00002.md`
- `out/chains/entry-00003.md`
- `out/chains/entry-00004.md`
- `out/chains/comparison.md` (对比汇总)

### 4. 运行演示脚本

```bash
python demo/demo_visualization.py
```

查看 5 个完整演示场景的运行结果。

---

## 典型应用场景

### 调试失败的验证

当某条验证失败时，快速定位原因：

```bash
python -m bonus.visualization.cli \
  --reports out/reports.jsonl \
  --report-id entry-00003 \
  --output debug.md
```

查看流程图，回答：
- 哪个工具失败了？
- 哪个字段判定错误？
- 证据链是否完整？

### 审计 Agent 决策

检查 Agent 的推理过程是否合理：

```bash
python -m bonus.visualization.cli \
  --reports out/reports.jsonl \
  --output-dir audit/
```

检查每个报告：
- Plan 中的工具是否都执行了？
- 工具调用顺序是否合理？
- Self-Check 是否覆盖了关键字段？

### 生成报告附件

为错误分析生成可视化附件：

```bash
python -m bonus.visualization.cli \
  --reports out/reports.jsonl \
  --filter-verdict incorrect \
  --output-dir report_attachments/
```

---

## Python API 使用

```python
from bonus.visualization import ChainVisualizer
import json

# 加载报告
reports = []
with open("out/reports.jsonl", "r") as f:
    for line in f:
        reports.append(json.loads(line))

# 创建可视化器
visualizer = ChainVisualizer()

# 可视化单条报告
markdown = visualizer.visualize_report(reports[0], "markdown")
print(markdown)

# 获取统计
stats = visualizer.get_chain_statistics(reports)
print(f"总报告数: {stats['total_reports']}")
print(f"平均工具数: {stats['avg_tools_per_report']:.2f}")

# 过滤并保存
incorrect = visualizer.filter_by_verdict(reports, "incorrect")
visualizer.save_multiple(incorrect, "out/chains/")
```

---

## 完整文档

详见 [VISUALIZATION.md](docs/VISUALIZATION.md) (545 行完整文档)

## 测试

```bash
pytest tests/test_visualization.py -v
```

✅ 13/13 测试通过
