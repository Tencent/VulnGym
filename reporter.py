"""Output generation: fix_diff.csv, needs_human.csv, structural_report.csv, README.md."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .models import FixRecord, HumanRecord, MatchResult, StructuralRecord


class Reporter:
    """Generates output files from processing results."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # fix_diff.csv
    # ------------------------------------------------------------------
    def write_fix_diff(self, records: list[FixRecord]) -> Path:
        path = self.output_dir / "fix_diff.csv"
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["entry_id", "node_path", "field",
                             "old_value", "new_value", "strategy"])
            for r in records:
                writer.writerow([
                    r.entry_id, r.node_path, r.field,
                    r.old_value, r.new_value, r.strategy,
                ])
        return path

    # ------------------------------------------------------------------
    # needs_human.csv
    # ------------------------------------------------------------------
    def write_needs_human(self, records: list[HumanRecord]) -> Path:
        path = self.output_dir / "needs_human.csv"
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["entry_id", "node_path", "reason_code", "detail",
                             "original_file", "original_line", "original_code_preview"])
            for r in records:
                writer.writerow([
                    r.entry_id, r.node_path, r.reason_code, r.detail,
                    r.original_file, str(r.original_line), r.original_code_preview,
                ])
        return path

    # ------------------------------------------------------------------
    # structural_report.csv
    # ------------------------------------------------------------------
    def write_structural_report(self, records: list[StructuralRecord]) -> Path:
        path = self.output_dir / "structural_report.csv"
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["entry_id", "issue_type", "detail"])
            for r in records:
                writer.writerow([r.entry_id, r.issue_type, r.detail])
        return path

    # ------------------------------------------------------------------
    # entries.fixed.jsonl
    # ------------------------------------------------------------------
    def write_fixed_jsonl(self, entries: list[dict[str, Any]]) -> Path:
        path = self.output_dir / "entries.fixed.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        import json
        with path.open("w", encoding="utf-8", newline="\n") as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return path

    # ------------------------------------------------------------------
    # README.md
    # ------------------------------------------------------------------
    def write_readme(self,
                     total_entries: int,
                     verify0_count: int,
                     fix_records: list[FixRecord],
                     human_records: list[HumanRecord],
                     structural_records: list[StructuralRecord]) -> Path:
        path = self.output_dir / "README.md"
        lines = []

        lines.append("# VulnGym entries.jsonl 自动修复报告")
        lines.append("")
        lines.append("## 概览")
        lines.append("")
        lines.append(f"- 总条目数：{total_entries}")
        lines.append(f"- 处理的 verify=0 条目：{verify0_count}")
        lines.append(f"- 自动修复数：{len(fix_records)}")
        lines.append(f"- 需人工复核数：{len(human_records)}")
        lines.append(f"- 结构性警告数：{len(structural_records)}")
        lines.append("")

        # Fix breakdown by strategy
        if fix_records:
            lines.append("## 自动修复明细")
            lines.append("")
            lines.append("| entry_id | node_path | field | old_value | new_value | strategy |")
            lines.append("|---|---|---|---|---|---|")
            for r in fix_records:
                lines.append(f"| {r.entry_id} | {r.node_path} | {r.field} "
                             f"| `{r.old_value[:60]}` | `{r.new_value[:60]}` | {r.strategy} |")
            lines.append("")

            # Strategy counts
            from collections import Counter
            strat_counts = Counter(r.strategy for r in fix_records)
            lines.append("### 按策略分布")
            lines.append("")
            for strategy, count in strat_counts.most_common():
                lines.append(f"- **{strategy}**：{count}")
            lines.append("")

        # Human review needed
        if human_records:
            lines.append("## 需人工复核")
            lines.append("")
            lines.append("| entry_id | node_path | reason_code | detail | file | line | code_preview |")
            lines.append("|---|---|---|---|---|---|---|")
            for r in human_records:
                lines.append(f"| {r.entry_id} | {r.node_path} | {r.reason_code} "
                             f"| {r.detail} | {r.original_file} | {r.original_line} "
                             f"| `{r.original_code_preview[:60]}` |")
            lines.append("")

            from collections import Counter
            reason_counts = Counter(r.reason_code for r in human_records)
            lines.append("### 按原因分布")
            lines.append("")
            for reason, count in reason_counts.most_common():
                lines.append(f"- **{reason}**：{count}")
            lines.append("")

        # Structural warnings
        if structural_records:
            lines.append("## 结构性警告 (Trace 自引用)")
            lines.append("")
            lines.append("| entry_id | issue_type | detail |")
            lines.append("|---|---|---|")
            for r in structural_records:
                lines.append(f"| {r.entry_id} | {r.issue_type} | {r.detail} |")
            lines.append("")

        lines.append("## 交付物")
        lines.append("")
        lines.append("- `entries.fixed.jsonl` — 修复后的数据文件")
        lines.append("- `fix_diff.csv` — 每处修改的前后对比")
        lines.append("- `needs_human.csv` — 需人工复核的节点")
        lines.append("- `structural_report.csv` — Trace 结构性问题")
        lines.append("")

        with path.open("w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
