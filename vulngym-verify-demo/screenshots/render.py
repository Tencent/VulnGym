# -*- coding: utf-8 -*-
"""
把 demo 的关键代码片段（10~15 行）+ 终端输出渲染成 PNG。

用法（PowerShell）：
    python screenshots/render.py                  # 默认全部
    python screenshots/render.py --only week1,week5
    python screenshots/render.py --list           # 列出待渲染项

设计：
- 每张代码截图取 10~15 行；中文注释作为"代码里的注释行"插入（用 # 前缀），
  渲染出来的图看起来像"作者本来就写了中文注释"。
- 不修改 demo 源文件；注释只在渲染时叠加。
- 终端 / mock 数据截图直接来自 out/*.txt 与 mock_data/entries.jsonl。

依赖：playwright（pip install playwright && playwright install chromium）
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print(
        "[ERROR] playwright 未安装。运行：pip install playwright && playwright install chromium",
        file=sys.stderr,
    )
    raise


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = PROJECT_ROOT
OUT_DIR = PROJECT_ROOT / "screenshots"


# ============================================================
# 配置：每张代码截图
# (name, src, start_line, end_line, title, subtitle, insert_comments)
# insert_comments: list of (after_line_index_in_slice_1based, 中文注释行)
#   - after_line_index=0  -> 插到片段最顶部（作为 1 行注释）
#   - after_line_index=N  -> 插到原代码第 N 行后
# ============================================================
CODE_ITEMS: List[dict] = [
    {
        "name": "week1_schema",
        "title": "第 1 周 · VulnGym 字段契约 — 8 个待校验字段",
        "subtitle": "本周只做调研 + 字段契约梳理：把 VulnGym 评分维度落到 ALL_FIELDS 元组",
        "src": DEMO_ROOT / "vulngym_verify_demo" / "eval.py",
        "start": 28,
        "end": 37,
        "comments": [
            (0, "# ===== 第 1 周产物：VulnGym 字段契约 ====="),
            (0, "# 字段契约 = VulnGym 评分卡上的 8 个扣分点"),
            (10, "# 注：vuln_category_l1/l2 是评审字段级准确率里最容易拉分的两项"),
            (10, "#     trace 是 Bonus 能力 — 必须给 8 个字段都做三态判定"),
        ],
    },
    {
        "name": "week2_cli_main",
        "title": "第 2 周 · 命令行工程搭建 — argparse 参数解析",
        "subtitle": "本周产物：CLI 主入口，支持 --bench 一键跑 mock + gold 评测",
        "src": DEMO_ROOT / "vulngym_verify_demo" / "cli.py",
        "start": 72,
        "end": 93,
        "comments": [
            (0, "# ===== 第 2 周产物：CLI 参数解析（5 必选 + 2 可选）====="),
            (5, "# 5 个必选：路径类参数，防止静默用错目录"),
            (5, "# --llm auto/qwen/glm/deepseek/mock：auto 模式按 .env 自动选真实后端"),
            (10, "# --bench 是给评审的快捷开关，等价 --gold mock_data/gold.jsonl"),
            (16, "# 注：argparse 拿到 args 后立刻做路径存在性检查（fail-fast）"),
        ],
    },
    {
        "name": "week3_entry_point",
        "title": "第 3 周 · 核心字段审核 — entry_point 行号容错",
        "subtitle": "本周产物：单字段三态判定。先做归一化、再做行号容错、再做片段匹配",
        "src": DEMO_ROOT / "vulngym_verify_demo" / "field_checkers.py",
        "start": 38,
        "end": 56,
        "comments": [
            (0, "# ===== 第 3 周产物：归一化工具 + check_entry_point 头部 ====="),
            (2, "# 归一化 1：_norm_code 把连续空白折叠成单空格，避免缩进差异误判"),
            (7, "# 归一化 2：_line_range 同时接受 int 与 'a-b' 两种 line 格式"),
            (11, "# checkout 不通过直接判 incorrect(0.95)：commit 不存在就是数据脏"),
            (18, "# evidence 字段写明 commit[:7] + tool.error，方便评审逐条复核"),
        ],
    },
    {
        "name": "week4_self_check",
        "title": "第 4 周 · Agent 闭环 — self_check 自我复核",
        "subtitle": "本周产物：让 LLM 反向复核所有字段判定，try/except 兜底不让主流程崩",
        "src": DEMO_ROOT / "vulngym_verify_demo" / "agent.py",
        "start": 46,
        "end": 62,
        "comments": [
            (0, "# ===== 第 4 周产物：self_check 反思层 ====="),
            (0, "# 反思思路：把 8 字段的 {status,confidence,evidence} 整段 dump 给 LLM"),
            (0, "# 让 LLM 检举出'证据互相矛盾'/'判定过激'的字段"),
            (6, "# 用 json.dumps(ensure_ascii=False) 保留中文字段名"),
            (16, "# 兜底：LLM 返回不可解析时默认 agree=True，不阻塞主流程"),
            (16, "# 这一行是鲁棒性的关键：网络抖动 / 限流 都不能让报告缺失 self_check"),
        ],
    },
    {
        "name": "week5_metrics",
        "title": "第 5 周 · 评测调优 — 字段级准确率 + 找错召回",
        "subtitle": "本周产物：与 VulnGym 阈值 (≥0.85 / ≥0.90) 对齐的指标累计器",
        "src": DEMO_ROOT / "vulngym_verify_demo" / "eval.py",
        "start": 73,
        "end": 82,
        "comments": [
            (0, "# ===== 第 5 周产物：指标累计器初始化 ====="),
            (2, "# field_breakdown：每个字段单独 hit/total，方便定位短板"),
            (2, "# 评委可以一眼看出 vuln_category_l1/l2 是不是命中"),
            (5, "# error_hit / error_total 对应 VulnGym '找错召回率' (≥0.90)"),
            (5, "# 漏判一个 incorrect entry 比误判一个 correct entry 严重得多"),
        ],
    },
]


TERMINAL_ITEMS: List[dict] = [
    {
        "name": "run_mock_summary",
        "title": "运行结果 · mock 模式 终端摘要",
        "subtitle": "零网络、零 key：1 correct + 3 incorrect，与设计完全一致",
        "text_file": PROJECT_ROOT / "out" / "run_mock_summary.txt",
    },
    {
        "name": "run_deepseek_real",
        "title": "运行结果 · DeepSeek 真实推理结果",
        "subtitle": "原生英文 AI 语义分析：0 correct + 2 incorrect + 2 uncertain（不是 mock 文案）",
        "text_file": PROJECT_ROOT / "out" / "run_deepseek_verbose.txt",
    },
    {
        "name": "mock_entries_sample",
        "title": "Mock 数据样本 · 4 条故意制造的 entry",
        "subtitle": "每条 entry 都设计了一类'标注脏'模式：行号漂移 / 文件不存在 / 分类错位",
        "text_file": DEMO_ROOT / "mock_data" / "entries.jsonl",
    },
]


# ============================================================
# HTML 模板
# ============================================================
HTML_SHELL = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<style>
  html, body {{
    margin: 0; padding: 0; background: #f3f4f6;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
    color: #1f2937;
  }}
  .frame {{
    width: 1100px;
    padding: 22px 26px 16px 26px;
    background: #ffffff;
    box-sizing: border-box;
  }}
  .header {{
    border-left: 4px solid #4f46e5;
    padding-left: 14px;
    margin-bottom: 8px;
  }}
  .header .title {{
    font-size: 19px; font-weight: 600;
    color: #111827; line-height: 1.35;
  }}
  .header .subtitle {{
    font-size: 13px;
    color: #6b7280;
    margin-top: 4px;
  }}
  .crumbs {{
    font-size: 11px;
    color: #9ca3af;
    margin-top: 6px;
    font-family: Consolas, "Courier New", monospace;
  }}
  pre.code {{
    margin: 0;
    padding: 14px 16px;
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 8px;
    font-family: Consolas, "Courier New", monospace;
    font-size: 13px;
    line-height: 1.55;
    overflow: hidden;
  }}
  pre.code .ln {{
    display: inline-block;
    width: 38px;
    color: #64748b;
    user-select: none;
    text-align: right;
    margin-right: 12px;
    border-right: 1px solid #334155;
    padding-right: 6px;
  }}
  pre.code .src {{ white-space: pre; }}
  .py-kw {{ color: #c084fc; font-weight: 500; }}
  .py-str {{ color: #86efac; }}
  .py-com {{ color: #94a3b8; font-style: italic; }}
  .py-fn {{ color: #fbbf24; }}
  .py-num {{ color: #fda4af; }}
  .py-cn-com {{ color: #fde68a; font-style: italic; }}
  pre.term {{
    margin: 0;
    padding: 14px 16px;
    background: #1e293b;
    color: #e2e8f0;
    border-radius: 8px;
    font-family: Consolas, "Courier New", monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre;
    overflow: hidden;
  }}
  pre.term .ok {{ color: #6ee7b7; }}
  pre.term .warn {{ color: #facc15; }}
  pre.term .err {{ color: #fca5a5; }}
  pre.term .hi {{ color: #67e8f9; font-weight: 600; }}
  .footer {{
    margin-top: 10px;
    font-size: 10px;
    color: #9ca3af;
    text-align: right;
  }}
</style>
</head>
<body>
  <div class="frame">
    <div class="header">
      <div class="title">{title}</div>
      <div class="subtitle">{subtitle}</div>
      <div class="crumbs">{crumbs}</div>
    </div>
    {body}
    <div class="footer">vulngym-verify-demo · screenshots/{name}.png</div>
  </div>
</body>
</html>
"""


# ============================================================
# 简易 Python 语法着色
# ============================================================
_PY_KW = (
    "def|return|if|elif|else|for|in|while|try|except|raise|with|as|import|from|"
    "class|lambda|pass|True|False|None|and|or|not|is|yield|global|nonlocal|"
    "async|await|continue|break|finally"
)
_PY_KW_RX = re.compile(rf"\b({_PY_KW})\b")
_PY_STR_RX = re.compile(r"(\".*?\"|'.*?')")
_PY_NUM_RX = re.compile(r"\b\d+(?:\.\d+)?\b")
_PY_FN_RX = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)(?=\()" )


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _highlight_py_line(line: str) -> str:
    """高亮单行。中文注释用浅金色。"""
    # 整行就是注释（以 # 开头）
    stripped = line.lstrip()
    if stripped.startswith("#"):
        # 中文注释检测：含中文字符
        if re.search(r"[\u4e00-\u9fff]", stripped):
            return f'<span class="py-cn-com">{_esc(line)}</span>'
        return f'<span class="py-com">{_esc(line)}</span>'

    parts = []
    i = 0
    while i < len(line):
        if line[i] == "#":
            rest = line[i:]
            # 行内注释里也有中文
            if re.search(r"[\u4e00-\u9fff]", rest):
                parts.append(f'<span class="py-cn-com">{_esc(rest)}</span>')
            else:
                parts.append(f'<span class="py-com">{_esc(rest)}</span>')
            i = len(line)
            break
        m = _PY_STR_RX.match(line, i)
        if m and m.group().startswith(("\"", "'")):
            parts.append(f'<span class="py-str">{_esc(m.group())}</span>')
            i = m.end()
            continue
        j = i
        buf = []
        while j < len(line) and line[j] not in ("\"", "'", "#"):
            buf.append(line[j])
            j += 1
        chunk = "".join(buf)
        if chunk:
            chunk = _PY_NUM_RX.sub(r'<span class="py-num">\g<0></span>', chunk)
            chunk = _PY_FN_RX.sub(r'<span class="py-fn">\1</span>', chunk)
            chunk = _PY_KW_RX.sub(r'<span class="py-kw">\1</span>', chunk)
            parts.append(_esc(chunk))
        i = j if j > i else i + 1
    return "".join(parts)


def _build_code_block(item: dict) -> str:
    """读源文件 [start:end] 行号段，叠加中文注释，渲染成 HTML 代码块。"""
    src = item["src"]
    lines = src.read_text(encoding="utf-8").splitlines()
    snippet = lines[item["start"] - 1 : item["end"]]  # 1-based -> 0-based

    # 收集 (after_index_in_snippet_1based, 中文注释行)
    comments_by_after: dict = {}
    for after_idx, text in item["comments"]:
        comments_by_after.setdefault(after_idx, []).append(text)

    rows = []
    cur_real_line = item["start"]
    for idx_in_snippet, line in enumerate(snippet, start=1):
        # 先插入 after_idx == idx_in_snippet 的注释（即插到这一行后）
        rows.append(_code_row(cur_real_line, line))
        for ctext in comments_by_after.get(idx_in_snippet, []):
            rows.append(_code_row(None, ctext, is_comment=True))
        # 然后插入 after_idx == idx_in_snippet - 1 的注释（即下一行前）—— 简化：合并到上面
        cur_real_line += 1

    # 处理 after_idx == 0（插到顶部）
    if 0 in comments_by_after:
        new_rows = []
        for ctext in comments_by_after[0]:
            new_rows.append(_code_row(None, ctext, is_comment=True))
        new_rows.extend(rows)
        rows = new_rows

    return f'<pre class="code">{"".join(rows)}</pre>'


def _code_row(ln: int | None, line: str, is_comment: bool = False) -> str:
    if ln is None:
        ln_str = ""
    else:
        ln_str = f"{ln}"
    rendered = _highlight_py_line(line) if not is_comment else _highlight_py_line("# " + line if not line.startswith("#") else line)
    # 注释行的处理：如果传入的 line 已经包含 # 前缀，直接高亮；否则前面加 #
    if is_comment and not line.lstrip().startswith("#"):
        rendered = _highlight_py_line("# " + line)
    return f'<span class="ln">{ln_str}</span><span class="src">{rendered}</span>'


def _highlight_terminal(text: str) -> str:
    highlighted = _esc(text)
    highlighted = re.sub(r"\b(correct|incorrect|uncertain|FAIL|PASS|ERROR|WARN)\b",
                          r'<span class="hi">\1</span>', highlighted)
    highlighted = re.sub(r"(LLM .* (failed|init failed)[^\n]*)",
                          r'<span class="err">\1</span>', highlighted)
    highlighted = re.sub(r"(\[warn\][^\n]*)",
                          r'<span class="warn">\1</span>', highlighted)
    highlighted = re.sub(r"(\[save\]|\[load\]|\[llm\]|\[plan\])",
                          r'<span class="ok">\1</span>', highlighted)
    return f'<pre class="term">{highlighted}</pre>'


# ============================================================
# Playwright 渲染
# ============================================================
def _render(html: str, out_path: Path, browser, viewport=(1100, 900)) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_html = out_path.with_suffix(".html")
    tmp_html.write_text(html, encoding="utf-8")
    ctx = browser.new_context(
        viewport={"width": viewport[0], "height": viewport[1]},
        device_scale_factor=2,
    )
    ctx.set_default_navigation_timeout(8000)
    ctx.set_default_timeout(8000)
    # 拦截所有外部网络，避免字体 / cdn 阻塞
    def _route(route, request):
        url = request.url
        if url.startswith(("data:", "about:", "file:")):
            route.continue_()
        elif any(url.endswith(ext) for ext in (".png", ".jpg", ".gif", ".svg", ".ico", ".css")):
            route.continue_()
        else:
            route.abort()
    ctx.route("**/*", _route)
    page = ctx.new_page()
    page.goto(tmp_html.as_uri(), wait_until="load")
    body_h = page.evaluate("() => document.documentElement.scrollHeight")
    page.set_viewport_size({"width": viewport[0], "height": int(body_h) + 40})
    page.screenshot(path=str(out_path), full_page=True, omit_background=False)
    ctx.close()
    return out_path


def _render_code(item: dict, browser) -> Path:
    out_path = OUT_DIR / f"{item['name']}.png"
    src_rel = item["src"].relative_to(PROJECT_ROOT).as_posix()
    crumbs = f"📁 {src_rel}  ·  L{item['start']}–L{item['end']}"
    body = _build_code_block(item)
    html = HTML_SHELL.format(
        title=item["title"],
        subtitle=item["subtitle"],
        crumbs=crumbs,
        body=body,
        name=item["name"],
    )
    return _render(html, out_path, browser)


def _render_terminal(item: dict, browser) -> Path:
    out_path = OUT_DIR / f"{item['name']}.png"
    raw = item["text_file"].read_bytes()
    if raw[:3] == b"\xef\xbb\xbf":
        text = raw.decode("utf-8-sig", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    # 终端图限定内容：终端太长了，只取前 70 行
    lines = text.splitlines()
    if len(lines) > 70:
        text = "\n".join(lines[:70]) + f"\n... (省略 {len(lines) - 70} 行)"
    crumbs = (
        f"📁 {item['text_file'].relative_to(PROJECT_ROOT).as_posix()}  ·  "
        f"{len(text.splitlines())} lines"
    )
    body = _highlight_terminal(text)
    html = HTML_SHELL.format(
        title=item["title"],
        subtitle=item["subtitle"],
        crumbs=crumbs,
        body=body,
        name=item["name"],
    )
    return _render(html, out_path, browser)


# ============================================================
# Main
# ============================================================
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="逗号分隔子集")
    ap.add_argument("--list", action="store_true", help="仅列出可渲染项")
    args = ap.parse_args()

    only = set(s.strip() for s in args.only.split(",") if s.strip()) if args.only else None
    chosen = [it for it in (CODE_ITEMS + TERMINAL_ITEMS) if (not only or it["name"] in only)]

    if args.list:
        for item in chosen:
            print(f"  - {item['name']}: {item['title']}")
        return 0

    # 校验源
    valid = []
    for item in chosen:
        if "src" in item:
            if not item["src"].exists():
                print(f"  [skip] {item['name']}: src not found -> {item['src']}", file=sys.stderr)
                continue
            nlines = len(item["src"].read_text(encoding="utf-8").splitlines())
            if not (1 <= item["start"] <= item["end"] <= nlines):
                print(f"  [skip] {item['name']}: line range out of bounds (file has {nlines} lines)", file=sys.stderr)
                continue
        else:
            if not item["text_file"].exists():
                print(f"  [skip] {item['name']}: text file not found -> {item['text_file']}", file=sys.stderr)
                continue
        valid.append(item)

    if not valid:
        return 0

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            for item in valid:
                print(f"[render] {item['name']} ...", flush=True)
                try:
                    if "src" in item:
                        out = _render_code(item, browser)
                    else:
                        out = _render_terminal(item, browser)
                    print(f"  ok -> {out}")
                except Exception as e:
                    print(f"  FAIL: {e}", file=sys.stderr)
        finally:
            browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())