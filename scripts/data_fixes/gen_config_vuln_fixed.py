#!/usr/bin/env python3
"""Idempotent generator for the config-type-vulnerability trace fix (issue #8).

Reads data/entries.jsonl read-only (the shared baseline is never modified —
see the revert commit in this PR for why) and writes:

  - data/entries.config_vuln.fixed.jsonl
        Full 408-row copy of entries.jsonl with only the `trace` field of
        entry-00241/00242/00243 rewritten. entry-00244 (and everything else)
        passes through byte-for-byte unchanged.

  - data/config_vuln_diff.csv
        Field-level before/after diff (entry_id, field, before, after) for
        all four target entries of GHSA-W7J5-J98M-W679, covering
        entry_point / critical_operation / trace / verify so a reviewer can
        see at a glance which fields changed (trace) and which were checked
        and left alone (entry_point, critical_operation, verify).

Rationale for the trace content itself — why entry-00241/242/243 collapse to
a 2-node (entry_point, critical_operation) trace while entry-00244 keeps its
original 7-node causal chain — is documented in config_vuln_annotation.md
(sections 2-3). This script only encodes the resulting data; it does not
re-derive the judgment.

Safe to re-run: output is fully determined by the FIXED_TRACE table below
and the current content of data/entries.jsonl. Running it twice produces
byte-identical output (see scripts/data_fixes/verify_config_vuln_fixes.py).
"""
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE = REPO_ROOT / "data" / "entries.jsonl"
OUT_FIXED = REPO_ROOT / "data" / "entries.config_vuln.fixed.jsonl"
OUT_DIFF_CSV = REPO_ROOT / "data" / "config_vuln_diff.csv"

TARGET_IDS = ["entry-00241", "entry-00242", "entry-00243", "entry-00244"]

# Only these three get a new trace. entry-00244 is listed in TARGET_IDS so it
# still shows up in the diff CSV as "reviewed, unchanged" — it is the
# active-bypass control sample and must NOT be edited.
FIXED_TRACE = {
    "entry-00241": [
        {
            "file": "scripts/e2e/Dockerfile",
            "line": 1,
            "code": "FROM node:22-bookworm",
            "desc": "FROM node:22-bookworm 确立基础镜像的默认执行身份为 root（uid=0）。这不是一条传播链的起点，而是本漏洞唯一的因果动作：该 Dockerfile 全文自此行至末尾未出现任何 USER 指令，风险状态在此一次性确立后即保持不变，不存在后续步骤对其进行修改或递进传递。",
        },
        {
            "file": "scripts/e2e/Dockerfile",
            "line": 23,
            "code": "CMD [\"bash\"]",
            "desc": "CMD [\"bash\"] 是容器启动时唯一被执行的进程声明，直接继承 FROM 层确立的 root 身份。中间的 corepack enable、WORKDIR、pnpm install/build/ui:build 等构建步骤均未插入 USER 指令，因此都不改变风险状态、不构成独立的传播节点，已从 trace 中省略。此节点仅标注该静态风险状态最终被兑现为运行时进程权限之处。",
        },
    ],
    "entry-00242": [
        {
            "file": "scripts/e2e/Dockerfile.qr-import",
            "line": 1,
            "code": "FROM node:22-bookworm",
            "desc": "FROM node:22-bookworm 确立基础镜像的默认执行身份为 root（uid=0）。这不是一条传播链的起点，而是本漏洞唯一的因果动作：该 Dockerfile 全文自此行至末尾未出现任何 USER 指令，风险状态在此一次性确立后即保持不变，不存在后续步骤对其进行修改或递进传递。",
        },
        {
            "file": "scripts/e2e/Dockerfile.qr-import",
            "line": 9,
            "code": "RUN pnpm install --frozen-lockfile",
            "desc": "RUN pnpm install --frozen-lockfile 是该 Dockerfile 中唯一具备安全意义的操作（触发依赖安装/构建脚本执行的风险面）。其执行身份并非由中间步骤决定——corepack enable、WORKDIR、COPY . . 均未插入 USER 指令，风险状态自 FROM 层确立后未发生任何变化，已从 trace 中省略这些冗余节点。此节点仅标注该静态风险状态最终生效之处。",
        },
    ],
    "entry-00243": [
        {
            "file": "scripts/docker/install-sh-e2e/Dockerfile",
            "line": 1,
            "code": "FROM node:22-bookworm-slim",
            "desc": "FROM node:22-bookworm-slim 确立基础镜像的默认执行身份为 root（uid 0）。这不是一条传播链的起点，而是本漏洞唯一的因果动作：该 Dockerfile 全文自此行至末尾未出现任何 USER 指令，风险状态在此一次性确立后即保持不变，不存在后续步骤对其进行修改或递进传递。",
        },
        {
            "file": "scripts/docker/install-sh-e2e/Dockerfile",
            "line": 14,
            "code": "ENTRYPOINT [\"/usr/local/bin/openclaw-install-e2e\"]",
            "desc": "ENTRYPOINT [\"/usr/local/bin/openclaw-install-e2e\"] 是容器启动时唯一被执行的进程声明，直接继承 FROM 层确立的 root 身份。中间的 apt-get install、COPY run.sh、chmod +x 等步骤均未插入 USER 指令，因此都不改变风险状态、不构成独立的传播节点，已从 trace 中省略。此节点仅标注该静态风险状态最终被兑现为运行时进程权限之处。",
        },
    ],
}


def load_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    entries = load_jsonl(BASELINE)
    by_id = {e["entry_id"]: e for e in entries}

    missing = set(TARGET_IDS) - set(by_id)
    if missing:
        raise SystemExit(f"ERROR: target entry_ids not found in {BASELINE}: {missing}")

    diff_rows = []
    fixed_out = []

    for e in entries:
        eid = e["entry_id"]
        if eid in FIXED_TRACE:
            before = json.loads(json.dumps(e))  # deep copy for diffing
            e = dict(e)
            e["trace"] = FIXED_TRACE[eid]
            fixed_out.append(e)
        elif eid in TARGET_IDS:
            # entry-00244: passes through unchanged, still diffed below.
            before = e
            fixed_out.append(e)
        else:
            fixed_out.append(e)
            continue

        after = by_id[eid] if eid not in FIXED_TRACE else e
        for field in ("entry_point", "critical_operation", "trace", "verify"):
            b = before[field]
            a = after[field] if field != "trace" or eid not in FIXED_TRACE else FIXED_TRACE[eid]
            b_s = json.dumps(b, ensure_ascii=False, sort_keys=True)
            a_s = json.dumps(a, ensure_ascii=False, sort_keys=True)
            diff_rows.append({
                "entry_id": eid,
                "field": field,
                "before": b_s,
                "after": a_s,
                "changed": "yes" if b_s != a_s else "no (reviewed, unchanged)",
            })

    OUT_FIXED.parent.mkdir(parents=True, exist_ok=True)
    with OUT_FIXED.open("w", encoding="utf-8", newline="\n") as f:
        for e in fixed_out:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")

    with OUT_DIFF_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["entry_id", "field", "before", "after", "changed"])
        writer.writeheader()
        writer.writerows(diff_rows)

    print(f"baseline rows read:  {len(entries)}")
    print(f"fixed rows written:  {len(fixed_out)}  -> {OUT_FIXED.relative_to(REPO_ROOT)}")
    print(f"diff rows written:   {len(diff_rows)}  -> {OUT_DIFF_CSV.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
