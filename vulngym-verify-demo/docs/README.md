# VulnGym 验证系统 - 文档索引

本目录包含 VulnGym 验证系统的完整文档和演示材料。

---

## 📚 文档列表

### 1. 用户文档

- **[README.md](../README.md)** - 快速开始指南
  - 安装依赖
  - Mock 模式运行
  - 真实 LLM 配置
  - 项目结构
  - 常见问题

### 2. 设计文档

- **[DESIGN.md](DESIGN.md)** - 系统设计文档（1-3 页）
  - 系统概述与目标
  - 三层架构设计
  - 核心模块详解（Tools、LLM、Field Checkers、Agent）
  - 关键设计决策（确定性优先、三态输出、证据可追溯、坏输入容错）
  - 常见陷阱与解决方案
  - 性能与可扩展性
  - 测试策略
  - 部署与运维

### 3. 演示材料

- **[demo/DEMO_SCRIPT.md](../demo/DEMO_SCRIPT.md)** - 5 分钟演示脚本
  - 演示大纲
  - 快速启动（Mock 模式）
  - 正常路径演示（查看正确样本报告）
  - 异常容错演示（坏输入、文件缺失、LLM 失败）
  - 评测指标展示
  - Q&A 准备

- **[demo/demo_reports.jsonl](../demo/demo_reports.jsonl)** - 演示运行输出
  - 11 条验证报告
  - 包含 correct、incorrect、uncertain 三种 verdict
  - 完整的证据链和 tool_trace

### 4. 测试集说明

- **[public_fixtures/README.md](../public_fixtures/README.md)** - 公开测试集说明
  - 测试样本覆盖（10 条正常 + 1 条异常）
  - 金标格式（显式三态）
  - 使用方法
  - 评测指标

### 5. 隐藏集模板

- **[../reports/hidden_eval_summary_template.json](../../reports/hidden_eval_summary_template.json)** - 隐藏测试集汇总模板
  - 汇总格式定义
  - 核心指标（field_accuracy、error_recall）
  - 字段分解
  - 鲁棒性测试结果
  - 证据抽查结果
  - 性能统计

### 6. Schema 规范

- **[../vulngym_verify_demo/report_schema.json](../vulngym_verify_demo/report_schema.json)** - VerificationReport JSON Schema
  - 输出契约的唯一规范定义
  - 字段类型、枚举、必填约束
  - 用于自动化校验

### 7. Bonus 模块

- **[ERROR_ATTRIBUTION.md](ERROR_ATTRIBUTION.md)** - I9 Bonus: 错误归因分析
  - 跨报告聚合错误模式
  - 工具/LLM 偏差统计
  - 根因识别
  - 修复建议生成

- **[VISUALIZATION.md](VISUALIZATION.md)** - I10 Bonus: 推理链路可视化
  - 推理过程可视化为 Mermaid 流程图
  - 单报告/批量报告可视化
  - 统计分析和对比
  - 调试和审计工具

---

## 🎯 按使用场景导航

### 场景 1: 快速上手

1. 阅读 [README.md](../README.md) 的"快速开始"部分
2. 运行 Mock 模式命令
3. 查看 `demo/demo_reports.jsonl` 输出

### 场景 2: 理解系统设计

1. 阅读 [DESIGN.md](DESIGN.md) 的"系统概述"和"三层架构"
2. 查看"核心模块详解"了解各模块职责
3. 阅读"关键设计决策"了解设计原则

### 场景 3: 准备演示

1. 阅读 [demo/DEMO_SCRIPT.md](../demo/DEMO_SCRIPT.md)
2. 提前运行一次 Mock 模式，确保无报错
3. 准备文本编辑器和 `jq` 工具
4. 按脚本顺序演示 5 分钟

### 场景 4: 运行评测

1. 阅读 [public_fixtures/README.md](../public_fixtures/README.md) 了解测试集
2. 运行命令：
   ```bash
   python -m vulngym_verify_demo \
     --entries public_fixtures/entries.jsonl \
     --repo-cache mock_repo \
     --advisories mock_advisories \
     --out /tmp/reports.jsonl \
     --llm mock \
     --gold public_fixtures/gold.jsonl \
     --bench
   ```
3. 查看评测指标输出

### 场景 5: 排查问题

1. 查看 [DESIGN.md](DESIGN.md) 的"常见陷阱与解决方案"
2. 运行测试：`pytest tests/ -v`
3. 查看日志（使用 `--verbose` 参数）

---

## 📊 评测结果（Public Fixtures）

| 指标 | 数值 | 阈值 | 状态 |
|------|------|------|------|
| 字段准确率 | 0.950 | ≥ 0.85 | ✅ |
| 错误召回率 | 1.000 | ≥ 0.90 | ✅ |
| Verdict 准确率 | 1.000 | - | ✅ |

详见 [public_fixtures/README.md](../public_fixtures/README.md)

---

## 🔗 相关链接

- **GitHub 仓库**: https://github.com/perhaps468/VulnGym
- **根目录 SCHEMA.md**: `../../SCHEMA.md` - 输入数据格式规范
- **根目录 ISSUE_OUTLINE.md**: `../../ISSUE_OUTLINE.md` - 项目总纲和 Issue 清单
- **CI 配置**: `../../.github/workflows/test.yml` - GitHub Actions 配置

---

## 📝 文档维护

- 文档与代码同步更新
- 命令示例经过实际验证
- 演示脚本包含预期输出
- 所有路径使用相对路径

**最后更新**: 2026-09-03  
**维护者**: VulnGym Team
