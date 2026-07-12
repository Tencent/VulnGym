import csv
from pathlib import Path
from typing import Dict


class TraceLogger:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self._init_csv()

    def _init_csv(self):
        with open(self.log_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "entry_id",
                "duplicates_removed",
                "out_of_order_detected",
            ])

    def log(self, entry_id: str, stats: Dict[str, int]):
        with open(self.log_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                entry_id,
                stats["duplicates_removed"],
                stats["out_of_order_detected"],
            ])