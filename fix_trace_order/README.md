# VulnGym Trace Cleaner

用于清洗 VulnGym 数据集中调用链（trace）的结构异常问题。

## 功能
- 去除重复 trace 节点（基于 file/line/code）
- 检测同文件内 trace 行号越界
- 跨文件 trace 不参与行号比较
- 输出结构化修复日志

## 运行方式
'''bash
python scripts/run_cleaner.py
'''

## 测试
'''bash
pytest
'''

## 设计原则
- 保守修复（不随意删除数据）
- 明确边界条件
- 可审计、可复现