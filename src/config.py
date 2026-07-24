# src/config.py


ENTRIES_JSONL_FILE_PATH = "data/entries.jsonl"

# 修复后输出新JSONL
FIXED_JSONL_OUTPUT_PATH = "outputs/fixed_result.jsonl"
# 需要人工复核的csv清单
NEEDS_HUMAN_CSV_PATH = "outputs/needs_human.csv"
# 上下检索行数范围
LINE_SEARCH_OFFSET = 5

# 读取规则配置（二选一生效）
# 模式1：读取前N行，0=关闭此模式；READ_MAX_LINES=10代表读取前10行
READ_MAX_LINES = 0
# 模式2：读取起止行区间 [START_READ, END_READ]
# 两个都大于0才开启区间模式；区间优先级高于READ_MAX_LINES
READ_START_LINE = 0
READ_END_LINE = 0

# 网络请求通用配置
USE_GHPROXY = False
TIMEOUT = 25
# 请求UA
CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"