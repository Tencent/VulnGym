"""I9 Bonus: 系统性错误识别与归因

跨 entry 聚合错误模式、工具/模型偏差统计、归因报告。
"""

from .analyzer import ErrorAnalyzer
from .aggregator import ErrorAggregator
from .report_template import AttributionReport

__all__ = ["ErrorAnalyzer", "ErrorAggregator", "AttributionReport"]
