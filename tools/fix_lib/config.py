#!/usr/bin/env python3
"""
全局配置模块
定义所有常量、默认路径、忽略目录和文件扩展名。
所有路径均基于项目根目录（即 tools/ 的父目录）构建，因此脚本可从任意位置运行。
"""

from pathlib import Path

# ---------- 项目根目录 ----------
# __file__ 是 config.py 的路径，位于 tools/fix_lib/ 下
# .parent -> tools/fix_lib
# .parent.parent -> tools
# .parent.parent.parent -> 项目根目录（VulnGym-main）
PROJECT_ROOT = Path(__file__).parent.parent.parent

# ---------- 文件路径 ----------
DATA_FILE = PROJECT_ROOT / "data" / "entries.jsonl"          # 输入数据
OUTPUT_DIR = PROJECT_ROOT / "tools" / "outputs"              # 输出目录
OUTPUT_JSONL = OUTPUT_DIR / "entries.fixed.jsonl"            # 修复后数据
OUTPUT_DIFF = OUTPUT_DIR / "fix_diff.csv"                    # 自动修复记录
OUTPUT_HUMAN = OUTPUT_DIR / "needs_human.csv"                # 人工复核清单
OUTPUT_FULL = OUTPUT_DIR / "fix_full.csv"                    # 全量审计日志

CACHE_DIR = PROJECT_ROOT / "repo_cache"                      # 本地仓库缓存

# ---------- 修复参数 ----------
LINE_RANGE = 5                                               # 原始行号上下搜索范围
MAX_WORKERS = 8                                              # 并行处理线程数

# ---------- 忽略目录（加速仓库扫描） ----------
IGNORE_DIRS = {
    '.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__',
    'target', 'out', 'vendor', 'third_party', 'lib', 'libs', 'deps',
    'bower_components', 'test', 'tests', 'example', 'examples', 'docs'
}

# ---------- 常见源码扩展名（用于仓库搜索） ----------
COMMON_EXTS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.svelte', '.vue',
    '.go', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.rb',
    '.php', '.html', '.css', '.scss', '.less', '.json', '.xml',
    '.yaml', '.yml', '.toml', '.sh', '.bash', '.ps1'
}
