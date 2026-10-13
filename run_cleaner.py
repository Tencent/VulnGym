import json
from pathlib import Path
from cleaner import clean_trace
from logger import TraceLogger


def main():
    input_path = Path("data/entries.jsonl")
    output_path = Path("data/entries.trace_fixed.jsonl")
    logger = TraceLogger("trace_fix_log.csv")

    with open(input_path, "r", encoding="utf-8") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:

        for line in fin:
            entry = json.loads(line)

            result = clean_trace(
                trace=entry.get("trace", []),
                entry_point_line=entry["entry_point"]["line"],
                critical_op_line=entry["critical_operation"]["line"],
            )

            entry["trace"] = result["trace"]
            logger.log(entry["entry_id"], result["stats"])

            fout.write(json.dumps(entry, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()