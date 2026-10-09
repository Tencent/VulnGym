# I9 Bonus: 系统性错误识别与归因

## 概述

错误归因分析模块用于跨多条验证报告聚合错误模式，识别工具偏差、LLM 系统性偏误和证据链缺口，输出可审计的归因报告和修复建议。

## 功能特性

### 1. 单报告错误分析
- 识别 `incorrect`/`uncertain` 字段
- 提取工具调用失败信息
- 检测低置信度模式（< 0.6）
- 标记证据链断裂（`status=incorrect` 但 `evidence_refs=[]`）

### 2. 跨报告聚合
- **按字段维度**: 统计每个字段的 incorrect/uncertain 频次
- **按工具维度**: 计算各工具的失败率和常见错误
- **按 LLM 维度**: 分析不同 LLM 提供商的不确定率
- **根因识别**: 自动识别公共错误模式

### 3. 根因模式

模块内置识别以下根因模式：

| 模式 | 描述 | 触发条件 |
|------|------|----------|
| `advisory_404` | 公告缓存缺失或 404 | ≥2 条记录 read_advisory 失败 |
| `checkout_failure` | 代码 checkout 失败 | ≥2 条记录 checkout 失败 |
| `empty_trace` | trace 字段普遍为空 | ≥3 条记录 trace 无证据引用 |
| `evidence_chain_broken` | 证据链断裂 | ≥2 条记录 incorrect 但无 evidence_refs |

### 4. 归因报告

生成结构化 JSON 报告，包含：
- 错误汇总（按字段/工具/LLM/根因）
- 样本 entry_id（每个模式最多 5 个）
- 自动生成的修复建议

## 使用方法

### 命令行工具

#### 分析单个报告文件

```bash
python -m bonus.error_attribution.cli \
  --reports out/reports_e2e.jsonl \
  --output analysis.json
```

#### 显示文本摘要

```bash
python -m bonus.error_attribution.cli \
  --reports out/reports_e2e.jsonl \
  --output analysis.json \
  --summary
```

#### 比较两次运行

```bash
python -m bonus.error_attribution.cli \
  --baseline run1.jsonl \
  --current run2.jsonl \
  --diff diff.json
```

### Python API

```python
from bonus.error_attribution import ErrorAggregator, AttributionReport

# 加载报告
import json
reports = []
with open("out/reports.jsonl", "r") as f:
    for line in f:
        reports.append(json.loads(line))

# 聚合分析
aggregator = ErrorAggregator()
aggregation = aggregator.aggregate(reports)

# 生成报告
report = AttributionReport.generate(
    aggregation=aggregation,
    output_path="attribution.json",
    add_recommendations=True
)

# 打印文本摘要
print(AttributionReport.format_text_summary(report))
```

## 输出格式

### 归因报告 JSON 结构

```json
{
  "analysis_id": "error_attribution_20260905_203800",
  "timestamp": "2026-09-05T20:38:00",
  "total_reports": 100,
  "total_errors": 25,
  "error_summary": {
    "by_field": {
      "commit": {
        "incorrect": 5,
        "uncertain": 3,
        "low_confidence": 2,
        "evidence_chain_broken": 1,
        "samples": ["entry-001", "entry-023"]
      }
    },
    "by_tool": {
      "checkout": {
        "failed": 8,
        "total": 100,
        "failure_rate": 0.08,
        "common_errors": ["commit not found (x5)", "timeout (x3)"],
        "samples": ["entry-010", "entry-042"]
      }
    },
    "by_llm": {
      "qwen": {
        "total_reports": 80,
        "uncertain_rate": 0.12,
        "low_confidence_rate": 0.15
      }
    },
    "by_root_cause": [
      {
        "pattern": "advisory_404",
        "description": "公告缓存缺失或 404 错误",
        "count": 7,
        "affected_fields": ["vuln_ids", "vuln_title"],
        "sample_entries": ["entry-010", "entry-023"],
        "evidence_sample": {
          "error_type": "read_advisory failed",
          "status_code": "404"
        }
      }
    ]
  },
  "recommendations": [
    "修复公告缓存缺失问题 (影响 7 条记录，涉及字段: vuln_ids, vuln_title)",
    "排查代码 checkout 失败原因 (影响 5 条记录，涉及字段: entry_point)",
    "重点改进 commit 字段验证 (incorrect=5, uncertain=3)"
  ]
}
```

### 差异报告结构（比较模式）

```json
{
  "baseline": {
    "total_reports": 100,
    "total_errors": 30
  },
  "current": {
    "total_reports": 100,
    "total_errors": 25
  },
  "changes": {
    "error_delta": -5,
    "field_changes": {
      "commit": {
        "before": 10,
        "after": 8,
        "delta": -2
      }
    },
    "new_root_causes": [],
    "resolved_root_causes": ["advisory_404"]
  }
}
```

## 测试

运行测试套件：

```bash
# 运行所有归因测试
pytest tests/test_error_attribution.py -v

# 运行单个场景
pytest tests/test_error_attribution.py::test_tool_bias_checkout_failure -v

# 使用真实数据测试
pytest tests/test_error_attribution.py::test_real_reports_analysis -v -s
```

### 注入场景测试

测试文件包含 5 个注入场景：

1. **工具偏差**: 3 条记录因 checkout 失败导致 entry_point=uncertain
2. **LLM 偏差**: 5 条记录的 vuln_category_l2 低置信度 uncertain
3. **证据链断裂**: 2 条记录 commit=incorrect 但 evidence_refs=[]
4. **公共根因**: 4 条记录涉及同一个 404 公告
5. **空 trace**: 3 条记录 trace 为空

每个场景验证：
- 聚合统计准确性
- 根因识别正确性
- 样本引用完整性

## 架构设计

### 模块职责

```
bonus/error_attribution/
├── __init__.py           # 包导出
├── analyzer.py           # 单报告分析器
│   ├── FieldError        # 字段错误数据类
│   ├── ToolFailure       # 工具失败数据类
│   ├── AnalysisResult    # 分析结果数据类
│   └── ErrorAnalyzer     # 分析器主类
├── aggregator.py         # 跨报告聚合器
│   ├── FieldErrorStats   # 字段级统计
│   ├── ToolErrorStats    # 工具级统计
│   ├── RootCause         # 根因数据类
│   └── ErrorAggregator   # 聚合器主类
├── report_template.py    # 报告生成器
│   └── AttributionReport # 报告生成与格式化
└── cli.py                # 命令行入口
    ├── load_reports()    # JSONL 加载
    ├── analyze_reports() # 分析模式
    └── compare_reports() # 比较模式
```

### 处理流程

```
JSONL 报告文件
    ↓
[ErrorAnalyzer] 逐条分析
    ↓
AnalysisResult[] 分析结果集
    ↓
[ErrorAggregator] 聚合统计
    ↓
聚合数据 (by_field/by_tool/by_llm/root_causes)
    ↓
[AttributionReport] 生成报告
    ↓
JSON 报告 + 文本摘要
```

## 扩展指南

### 添加新的根因模式

在 `aggregator.py` 中添加检测方法：

```python
def _find_new_pattern(self, analyses: List[AnalysisResult],
                      reports: List[Dict[str, Any]]) -> Optional[RootCause]:
    """检测新模式"""
    affected_entries = []
    affected_fields_set = set()
    
    for i, analysis in enumerate(analyses):
        # 检测逻辑
        if condition_met:
            affected_entries.append(analysis.entry_id)
            affected_fields_set.add("field_name")
    
    if len(affected_entries) >= threshold:
        return RootCause(
            pattern="new_pattern",
            description="模式描述",
            count=len(affected_entries),
            affected_fields=list(affected_fields_set),
            sample_entries=affected_entries[:5]
        )
    return None
```

然后在 `_identify_root_causes()` 中调用：

```python
new_pattern = self._find_new_pattern(analyses, reports)
if new_pattern:
    root_causes.append(new_pattern)
```

### 自定义修复建议

在 `report_template.py` 中扩展 `_generate_recommendations()`：

```python
# 添加自定义规则
if custom_condition:
    recommendations.append("自定义建议文本")
```

## 限制与约束

1. **只读分析**: 不修改核心模块（`field_checkers.py`、`llm_client.py`、`agent.py`）
2. **后处理**: 只分析已有报告，不重新运行验证
3. **Bonus 隔离**: 所有代码在 `bonus/` 目录，不影响 Standard 功能
4. **向后兼容**: 不修改 `VerificationReport` 契约或 `eval.py` 指标

## 性能考虑

- **内存**: O(N) 其中 N 为报告数，所有报告需同时加载
- **时间复杂度**: O(N×M) 其中 M 为平均字段/工具数（≈10）
- **建议**: 对超大数据集（>10000 条）可考虑分批处理

## 常见问题

### Q: 如何提高根因识别准确性？

调整检测阈值：
- `advisory_404`: 最少触发记录数（默认 2）
- `empty_trace`: 最少触发记录数（默认 3）
- 在对应的 `_find_*_pattern()` 方法中修改条件

### Q: 如何导出给定字段的所有错误样本？

```python
aggregation = aggregator.aggregate(reports)
commit_errors = [
    stat for stat in aggregation["by_field"]
    if stat["field_name"] == "commit"
][0]
print(commit_errors["sample_entries"])
```

### Q: 能否与 CI 集成？

可以。在 CI 中运行：

```bash
python -m bonus.error_attribution.cli \
  --reports $REPORTS_PATH \
  --output attribution.json

# 检查错误数阈值
python -c "
import json
with open('attribution.json') as f:
    report = json.load(f)
if report['total_errors'] > 10:
    exit(1)
"
```

## 贡献者

- I9 Bonus Issue 实现
- 不影响 Standard Issue (I1-I8) 交付
