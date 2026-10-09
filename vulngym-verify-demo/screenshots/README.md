# VulnGym-verify-demo 截图清单

`vulngym-verify-demo/screenshots/` 目录存放课题规划 + 申请书要引用的全部 PNG。

## 重新生成截图

```bash
python screenshots/render.py                  # 全部 8 张
python screenshots/render.py --only week1,week5
python screenshots/render.py --list           # 仅列出
```

依赖：`playwright` + `playwright install chromium`。

## 截图清单（按周对应）

| 截图 | 源文件 | 行号 | 用途 |
|---|---|---|---|
| `week1_schema.png` | `vulngym_verify_demo/eval.py` | L28–L37 | 课题规划第 1 周 + 申请书 Schema 节 |
| `week2_cli_main.png` | `vulngym_verify_demo/cli.py` | L72–L93 | 课题规划第 2 周 + 申请书 CLI 节 |
| `week3_entry_point.png` | `vulngym_verify_demo/field_checkers.py` | L38–L56 | 课题规划第 3 周 + 申请书 字段审核节 |
| `week4_self_check.png` | `vulngym_verify_demo/agent.py` | L46–L62 | 课题规划第 4 周 + 申请书 Agent 闭环节 |
| `week5_metrics.png` | `vulngym_verify_demo/eval.py` | L73–L82 | 课题规划第 5 周 + 申请书 评测节 |
| `run_mock_summary.png` | `out/run_mock_summary.txt` | — | 课题规划末 + 申请书 R1 |
| `run_deepseek_real.png` | `out/run_deepseek_verbose.txt` | — | 课题规划末 + 申请书 R6 |
| `mock_entries_sample.png` | `mock_data/entries.jsonl` | — | 课题规划末 + 申请书 R7 |

## 设计

- **每张代码截图 ≤ 15 行**，原代码切片 + 中文注释以 `#` 行形式叠加（注释只在渲染时插入，不修改源文件）
- **中文注释**用浅金色斜体（`py-cn-com` class）显示，与英文注释（灰色斜体）区分
- **行号**精确到原文件真实行号，方便评审按行号跳读源文件
- **面包屑**标注 `📁 <相对路径> · L<start>–L<end>`，截图左上角直接能看到出处

## 修改某张截图

编辑 `screenshots/render.py` 顶部的 `CODE_ITEMS` / `TERMINAL_ITEMS` 列表：

- 改 `start` / `end` 调整代码段范围（保持 10–15 行）
- 改 `comments` 列表调整中文注释。`after_line_index=N` 表示插到原代码第 N 行后；`N=0` 插到片段顶部
- 改 `title` / `subtitle` 调整章节标题与副标题