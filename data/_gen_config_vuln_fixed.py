"""
Apply config-vuln annotation fixes (GHSA-W7J5-J98M-W679, entry-00241..00244).

Per issue's explicit delivery requirement: this script does NOT modify
`data/entries.jsonl` in place. Instead it:

  1. Reads `data/entries.jsonl` (original pre-fix state) as the baseline.
  2. Rewrites only the 4 target rows according to the annotation principles
     described in `data/config_vuln_annotation.md`.
  3. Writes the result to `data/entries.config_vuln.fixed.jsonl` (a parallel
     408-row file where only the 4 targets are replaced).
  4. Emits `data/config_vuln_diff.csv` (field-level diff with exact before/after
     values plus full JSON payloads for structured fields).
  5. Validates every modified row against the SCHEMA.md invariants.

Per Q&A:
  - entry_point  = "config declaration that establishes unsafe default"
                   (i.e. the FROM line, line 1)
  - critical_operation = the structural defect range (whole Dockerfile for
                   missing-USER cases; the useradd+sudo+USER block for the
                   invalid-deescalation case in entry-00244).
  - trace        = a single "config-propagation step" covering the same range
                   as critical_operation, with code = full file content.
  - line         = "start-end" range string (SCHEMA.md permits this form).
  - code         = full file content verbatim, multi-line via \\n. The
                   trailing \\n is stripped so that `len(code.split("\\n"))`
                   matches `b - a + 1` for the range `"a-b"`.
  - verify       = 0 (note recorded in annotation.md that the row has been
                   corrected but not yet dual-reviewed).
  - vuln_category: reused existing l1/l2; no new meta field introduced.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL_IN = ROOT / "data" / "entries.jsonl"  # original pre-fix baseline (read-only)
JSONL_OUT = ROOT / "data" / "entries.config_vuln.fixed.jsonl"  # parallel write target
CSV_OUT = ROOT / "data" / "config_vuln_diff.csv"

TARGET_IDS = ("entry-00241", "entry-00242", "entry-00243", "entry-00244")

# ---------- source-of-truth file contents (verbatim from commit c56fb7f3) ----

# The .rstrip("\n") on each block ensures that
#   len(code.split("\n")) == int(range.split("-")[1]) - int(range.split("-")[0]) + 1
# i.e. line-count arithmetic is consistent with the range notation.
DOCKERFILE_E2E = (
    "FROM node:22-bookworm\n"
    "\n"
    "RUN corepack enable\n"
    "\n"
    "WORKDIR /app\n"
    "\n"
    "ENV NODE_OPTIONS=\"--disable-warning=ExperimentalWarning\"\n"
    "\n"
    "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json tsdown.config.ts vitest.config.ts vitest.e2e.config.ts openclaw.mjs ./\n"
    "COPY src ./src\n"
    "COPY test ./test\n"
    "COPY scripts ./scripts\n"
    "COPY docs ./docs\n"
    "COPY skills ./skills\n"
    "COPY patches ./patches\n"
    "COPY ui ./ui\n"
    "COPY extensions/memory-core ./extensions/memory-core\n"
    "\n"
    "RUN pnpm install --frozen-lockfile\n"
    "RUN pnpm build\n"
    "RUN pnpm ui:build\n"
    "\n"
    "CMD [\"bash\"]"
).rstrip("\n")

DOCKERFILE_QR_IMPORT = (
    "FROM node:22-bookworm\n"
    "\n"
    "RUN corepack enable\n"
    "\n"
    "WORKDIR /app\n"
    "\n"
    "COPY . .\n"
    "\n"
    "RUN pnpm install --frozen-lockfile"
).rstrip("\n")

DOCKERFILE_INSTALL_SH_E2E = (
    "FROM node:22-bookworm-slim\n"
    "\n"
    "RUN apt-get update \\\n"
    "  && apt-get install -y --no-install-recommends \\\n"
    "    bash \\\n"
    "    ca-certificates \\\n"
    "    curl \\\n"
    "    git \\\n"
    "  && rm -rf /var/lib/apt/lists/*\n"
    "\n"
    "COPY run.sh /usr/local/bin/openclaw-install-e2e\n"
    "RUN chmod +x /usr/local/bin/openclaw-install-e2e\n"
    "\n"
    "ENTRYPOINT [\"/usr/local/bin/openclaw-install-e2e\"]"
).rstrip("\n")

DOCKERFILE_INSTALL_SH_NONROOT = (
    "FROM ubuntu:24.04\n"
    "\n"
    "RUN set -eux; \\\n"
    "  for attempt in 1 2 3; do \\\n"
    "    if apt-get update -o Acquire::Retries=3; then break; fi; \\\n"
    "    echo \"apt-get update failed (attempt ${attempt})\" >&2; \\\n"
    "    if [ \"${attempt}\" -eq 3 ]; then exit 1; fi; \\\n"
    "    sleep 3; \\\n"
    "  done; \\\n"
    "  apt-get -o Acquire::Retries=3 install -y --no-install-recommends \\\n"
    "    bash \\\n"
    "    ca-certificates \\\n"
    "    curl \\\n"
    "    sudo \\\n"
    "  && rm -rf /var/lib/apt/lists/*\n"
    "\n"
    "RUN useradd -m -s /bin/bash app \\\n"
    "  && echo \"app ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/app\n"
    "\n"
    "USER app\n"
    "WORKDIR /home/app\n"
    "\n"
    "ENV NPM_CONFIG_FUND=false\n"
    "ENV NPM_CONFIG_AUDIT=false\n"
    "\n"
    "COPY run.sh /usr/local/bin/openclaw-install-nonroot\n"
    "RUN sudo chmod +x /usr/local/bin/openclaw-install-nonroot\n"
    "\n"
    "ENTRYPOINT [\"/usr/local/bin/openclaw-install-nonroot\"]"
).rstrip("\n")

# line count for each file (so the range can be expressed as "1-N")
# Note: .rstrip("\n") strips the trailing \n, so .count("\n") equals N-1.
N_E2E = DOCKERFILE_E2E.count("\n") + 1  # 23 lines -> 22 \n chars
N_QR = DOCKERFILE_QR_IMPORT.count("\n") + 1  # 9 lines -> 8 \n chars
N_SH_E2E = DOCKERFILE_INSTALL_SH_E2E.count("\n") + 1  # 14 lines -> 13 \n chars
N_SH_NONROOT = DOCKERFILE_INSTALL_SH_NONROOT.count("\n") + 1  # 29 lines -> 28 \n chars

assert N_E2E == 23, f"DOCKERFILE_E2E: {DOCKERFILE_E2E.count(chr(10))} \\n chars -> {N_E2E} lines"
assert N_QR == 9, f"DOCKERFILE_QR_IMPORT: {DOCKERFILE_QR_IMPORT.count(chr(10))} \\n chars -> {N_QR} lines"
assert N_SH_E2E == 14, f"DOCKERFILE_INSTALL_SH_E2E: {DOCKERFILE_INSTALL_SH_E2E.count(chr(10))} \\n chars -> {N_SH_E2E} lines"
assert N_SH_NONROOT == 29, f"DOCKERFILE_INSTALL_SH_NONROOT: {DOCKERFILE_INSTALL_SH_NONROOT.count(chr(10))} \\n chars -> {N_SH_NONROOT} lines"

# ---------- shared fields -----------------------------------------------

SHARED = {
    "commit": "c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1",
    "origin": "GitHub Advisory Database (reviewed)",
    "project": "openclaw",
    "repo_url": "https://github.com/openclaw/openclaw",
    "report_id": "GHSA-W7J5-J98M-W679",
    "source_link": "https://github.com/advisories/GHSA-w7j5-j98m-w679",
    "vuln_ids": ["GHSA-W7J5-J98M-W679"],
    "vuln_category_l1": "特权提升",
    "vuln_category_l2": "容器以不必要特权运行",
    "verify": 0,
}

EP_DESC = (
    "以 {base_image} 为构建起点的基础镜像声明。该镜像内建默认活跃用户为 root（uid=0），"
    "FROM 指令由此把 root 上下文引入镜像，是整条特权传播链的源头；"
    "在缺少 USER 指令覆盖默认身份的配置类漏洞中，FROM 即 entry_point。"
)

# ---------- per-entry payloads -----------------------------------------

ENTRIES: list[dict] = [
    {
        "entry_id": "entry-00241",
        "vuln_title": "OpenClaw has multiple E2E/test Dockerfiles that run all processes as root - Dockerfile",
        "file": "scripts/e2e/Dockerfile",
        "from_image": "node:22-bookworm",
        "co_range": f"1-{N_E2E}",
        "co_code": DOCKERFILE_E2E,
        "co_desc": (
            f"scripts/e2e/Dockerfile 第 1-{N_E2E} 行（整段配置）构成 CWE-250 过度特权漏洞的直接根因："
            "从基础镜像声明到默认 CMD 注册，全文件没有任何 USER 指令来中断 root 特权向运行时进程的传递。"
            "特权状态在该范围内由 FROM 引入、由各 RUN/COPY 步骤承载、最终由 CMD [\"bash\"] 在容器启动时兑现为 root bash 进程。"
            "缺失的 USER 指令是结构性问题，因此 critical_operation 必须覆盖整段配置而非某一单行 sink。"
        ),
        "trace_desc": (
            f"对 scripts/e2e/Dockerfile 第 1-{N_E2E} 行整段范围的单一配置传播步："
            "声明端（FROM node:22-bookworm）确立 root 默认用户，构建步骤（corepack enable / pnpm install / pnpm build 等）"
            "均以 root 身份执行但未改变权限状态，运行时端（CMD [\"bash\"]）以 root 进程完成兑现。"
            "三者构成完整的配置—构建—运行时特权传递链；其中关键的失败点是配置层面缺少 USER 指令。"
            "由于该路径不存在传统污点传播，trace 折叠为单节点，code 字段包含完整 Dockerfile 以便人工核查。"
        ),
    },
    {
        "entry_id": "entry-00242",
        "vuln_title": "OpenClaw has multiple E2E/test Dockerfiles that run all processes as root - Dockerfile.qr-import",
        "file": "scripts/e2e/Dockerfile.qr-import",
        "from_image": "node:22-bookworm",
        "co_range": f"1-{N_QR}",
        "co_code": DOCKERFILE_QR_IMPORT,
        "co_desc": (
            f"scripts/e2e/Dockerfile.qr-import 第 1-{N_QR} 行（整段配置）构成 CWE-250 过度特权漏洞的直接根因："
            "该 Dockerfile 长度虽短但仍无任何 USER 指令，从 FROM 到最后一个 RUN 全程以 root 身份执行。"
            "特权状态在该范围内从基础镜像（root 默认用户）经 corepack enable、依赖拷贝与 pnpm install 一路向下传递，"
            "缺位的 USER 指令使整个构建—执行流程继承 root 权限。"
        ),
        "trace_desc": (
            f"对 scripts/e2e/Dockerfile.qr-import 第 1-{N_QR} 行整段范围的单一配置传播步："
            "声明端确立 root 默认用户，构建端（corepack enable / COPY . . / pnpm install）以 root 身份执行但不改变权限状态，"
            "未声明运行时 CMD 但镜像默认行为仍以 root 运行。"
            "整个配置路径中缺少 USER 指令是关键失败点，因此 trace 折叠为单节点覆盖整段配置。"
        ),
    },
    {
        "entry_id": "entry-00243",
        "vuln_title": "OpenClaw has multiple E2E/test Dockerfiles that run all processes as root - Dockerfile",
        "file": "scripts/docker/install-sh-e2e/Dockerfile",
        "from_image": "node:22-bookworm-slim",
        "co_range": f"1-{N_SH_E2E}",
        "co_code": DOCKERFILE_INSTALL_SH_E2E,
        "co_desc": (
            f"scripts/docker/install-sh-e2e/Dockerfile 第 1-{N_SH_E2E} 行（整段配置）构成 CWE-250 过度特权漏洞的直接根因："
            "从基础镜像（root 默认用户）到 ENTRYPOINT 入口脚本，整段配置路径没有任何 USER 指令切换至非特权账户。"
            "系统包安装、二进制部署、权限激活均以 root 身份完成，最终 ENTRYPOINT "
            "\"/usr/local/bin/openclaw-install-e2e\" 以 root 进程运行。"
        ),
        "trace_desc": (
            f"对 scripts/docker/install-sh-e2e/Dockerfile 第 1-{N_SH_E2E} 行整段范围的单一配置传播步："
            "声明端（FROM）确立 root 默认用户，构建端（apt-get 安装系统包、COPY run.sh、chmod +x）以 root 身份执行但不改变权限状态，"
            "运行时端（ENTRYPOINT）以 root 进程兑现特权。"
            "整段配置路径中缺少 USER 指令是关键失败点；trace 因此折叠为单节点覆盖整段配置。"
        ),
    },
    {
        "entry_id": "entry-00244",
        "vuln_title": "OpenClaw has multiple E2E/test Dockerfiles that run all processes as root - Dockerfile",
        "file": "scripts/docker/install-sh-nonroot/Dockerfile",
        "from_image": "ubuntu:24.04",
        # Narrow range: lines 17-20 (useradd + sudoers echo + blank + USER app).
        "co_range": "17-20",
        # Note: the blank line (19) is part of the source file and is included.
        "co_code": (
            "RUN useradd -m -s /bin/bash app \\\n"
            "  && echo \"app ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/app\n"
            "\n"
            "USER app"
        ),
        "co_desc": (
            "scripts/docker/install-sh-nonroot/Dockerfile 第 17-20 行构成 CWE-250 过度特权漏洞的核心："
            "RUN useradd 创建 app 用户后，紧随其后的 sudoers 配置授予该用户免密全权提权通道（无密码 sudo），"
            "使 app 在技术上已与 root 等价；随后 USER app 在形式上完成了身份切换，"
            "但因 sudo 通道无成本，USER 指令带来的降权在安全语义上完全失效。"
            "本条与其他 3 条不同——它不是缺失 USER，而是 USER 被紧随的 sudo 授权所消解，"
            "因此 critical_operation 必须聚焦于这条 useradd + sudo 写入 + USER 的紧凑指令段，而非整段 Dockerfile。"
        ),
        "trace_desc": (
            "对 scripts/docker/install-sh-nonroot/Dockerfile 第 17-20 行的单一配置传播步："
            "useradd 创建 app 用户（root 权限下），sudoers 写入免密全权授权（消解权限分隔），"
            "USER app 在形式上完成降权但实质等价 root。"
            "三个相邻指令共同构成 '降权无效' 的核心结构缺陷；"
            "后续 RUN sudo chmod +x 与 ENTRYPOINT 步骤均依赖该 app 用户身份运行，因此该 4 行范围是漏洞链路唯一的关键节点。"
            "trace 折叠为单节点。"
        ),
    },
]


# ---------- helpers ----------------------------------------------------

def build_row(entry: dict) -> dict:
    row: dict = {**SHARED, **{
        "entry_id": entry["entry_id"],
        "vuln_title": entry["vuln_title"],
        "entry_point": {
            "file": entry["file"],
            "line": 1,
            "code": f"FROM {entry['from_image']}",
            "desc": EP_DESC.format(base_image=entry["from_image"]),
        },
        "critical_operation": {
            "file": entry["file"],
            "line": entry["co_range"],
            "code": entry["co_code"],
            "desc": entry["co_desc"],
        },
        "trace": [
            {
                "file": entry["file"],
                "line": entry["co_range"],
                "code": entry["co_code"],
                "desc": entry["trace_desc"],
            }
        ],
    }}
    return row


def validate(row: dict) -> None:
    """Validate against the SCHEMA.md invariants that apply to entries.jsonl."""
    for k in ("entry_id", "report_id", "source_link", "origin", "project",
              "repo_url", "commit", "vuln_title", "vuln_category_l1",
              "vuln_category_l2", "entry_point", "critical_operation",
              "trace", "verify"):
        assert k in row, f"missing {k} in {row.get('entry_id')}"
    assert row["verify"] in (0, 1)
    assert len(row["commit"]) == 40
    assert row["repo_url"].startswith("https://github.com/")
    assert row["source_link"].startswith("https://github.com/advisories/GHSA-")
    assert row["report_id"].lower() in row["source_link"].lower()
    assert row["vuln_ids"] == ["GHSA-W7J5-J98M-W679"]

    ep = row["entry_point"]
    co = row["critical_operation"]
    assert isinstance(row["trace"], list) and len(row["trace"]) >= 1

    for node in (ep, co, *row["trace"]):
        assert "file" in node and "line" in node and "code" in node
        line = node["line"]
        if isinstance(line, int):
            assert line >= 1
        else:
            a_str, b_str = line.split("-")
            a, b = int(a_str), int(b_str)
            assert 1 <= a <= b


# ---------- main -------------------------------------------------------

def load_entries() -> list[dict]:
    with JSONL_IN.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def apply_fix(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (new_entries, originals_for_diff)."""
    new_entries = []
    originals_by_id = {e["entry_id"]: e for e in entries}
    for row in entries:
        eid = row["entry_id"]
        if eid in TARGET_IDS:
            new_entries.append(build_row(next(p for p in ENTRIES if p["entry_id"] == eid)))
        else:
            new_entries.append(row)
    return new_entries, [originals_by_id[eid] for eid in TARGET_IDS]


def write_entries(entries: list[dict]) -> None:
    with JSONL_OUT.open("w", encoding="utf-8", newline="\n") as f:
        for row in entries:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def write_csv(originals: list[dict]) -> None:
    fieldnames = [
        "entry_id", "field", "field_path",
        "original_file", "original_line", "original_code", "original_desc",
        "fixed_file", "fixed_line", "fixed_code", "fixed_desc",
        "original_value_json", "fixed_value_json",
        "change_rationale",
    ]
    diffs: list[dict] = []

    def dump_json(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    for orig in originals:
        eid = orig["entry_id"]
        fixed = next(p for p in ENTRIES if p["entry_id"] == eid)
        fixed_entry_point = {
            "file": fixed["file"],
            "line": 1,
            "code": f"FROM {fixed['from_image']}",
            "desc": EP_DESC.format(base_image=fixed["from_image"]),
        }
        fixed_critical_operation = {
            "file": fixed["file"],
            "line": fixed["co_range"],
            "code": fixed["co_code"],
            "desc": fixed["co_desc"],
        }
        fixed_trace = [
            {
                "file": fixed["file"],
                "line": fixed["co_range"],
                "code": fixed["co_code"],
                "desc": fixed["trace_desc"],
            }
        ]
        # trace: collapsed to single config-range step
        diffs.append({
            "entry_id": eid,
            "field": "trace",
            "field_path": "trace",
            "original_file": "multiple (per-step RUN/FROM/ENTRYPOINT nodes)",
            "original_line": "see original row",
            "original_code": f"{len(orig['trace'])} taint-style trace nodes",
            "original_desc": "see original_value_json for the exact pre-fix trace array",
            "fixed_file": fixed["file"],
            "fixed_line": fixed["co_range"],
            "fixed_code": fixed["co_code"],
            "fixed_desc": fixed["trace_desc"],
            "original_value_json": dump_json(orig["trace"]),
            "fixed_value_json": dump_json(fixed_trace),
            "change_rationale": (
                "Collapsed verbose taint chain into a single config-propagation step: "
                "this vulnerability is a structural absence (missing USER / sudo-overridden USER), "
                "not a taint flow, so per-step tracing is misleading."
            ),
        })
        # critical_operation
        diffs.append({
            "entry_id": eid,
            "field": "critical_operation",
            "field_path": "critical_operation",
            "original_file": orig["critical_operation"]["file"],
            "original_line": str(orig["critical_operation"]["line"]),
            "original_code": orig["critical_operation"]["code"],
            "original_desc": orig["critical_operation"].get("desc", ""),
            "fixed_file": fixed["file"],
            "fixed_line": fixed["co_range"],
            "fixed_code": fixed["co_code"],
            "fixed_desc": fixed["co_desc"],
            "original_value_json": dump_json(orig["critical_operation"]),
            "fixed_value_json": dump_json(fixed_critical_operation),
            "change_rationale": (
                "Expanded from a single sink line (CMD/ENTRYPOINT) to the structural defect range: "
                "the root cause is the absence of USER / invalid deescalation, so the whole block must "
                "be marked. entry-00244 keeps a narrow 17-20 range since its defect is concentrated."
                if eid == "entry-00244"
                else
                "Expanded from a single sink line (CMD/ENTRYPOINT) to the structural defect range: "
                "the root cause is the absence of USER instruction, so the whole Dockerfile must "
                "be marked to convey the structural absence."
            ),
        })
        # entry_point
        diffs.append({
            "entry_id": eid,
            "field": "entry_point",
            "field_path": "entry_point",
            "original_file": orig["entry_point"]["file"],
            "original_line": str(orig["entry_point"]["line"]),
            "original_code": orig["entry_point"]["code"],
            "original_desc": orig["entry_point"].get("desc", ""),
            "fixed_file": fixed["file"],
            "fixed_line": "1",
            "fixed_code": f"FROM {fixed['from_image']}",
            "fixed_desc": EP_DESC.format(base_image=fixed["from_image"]),
            "original_value_json": dump_json(orig["entry_point"]),
            "fixed_value_json": dump_json(fixed_entry_point),
            "change_rationale": (
                "Retained FROM as entry_point; desc simplified to clearly state that this line "
                "establishes the unsafe default and that the missing USER is the structural defect."
            ),
        })
        # vuln_category: unchanged
        diffs.append({
            "entry_id": eid,
            "field": "vuln_category",
            "field_path": "vuln_category_l1/l2",
            "original_file": "(n/a)",
            "original_line": "(n/a)",
            "original_code": f"{orig['vuln_category_l1']} / {orig['vuln_category_l2']}",
            "original_desc": "(unchanged)",
            "fixed_file": "(n/a)",
            "fixed_line": "(n/a)",
            "fixed_code": f"{SHARED['vuln_category_l1']} / {SHARED['vuln_category_l2']}",
            "fixed_desc": "(unchanged)",
            "original_value_json": dump_json({
                "vuln_category_l1": orig["vuln_category_l1"],
                "vuln_category_l2": orig["vuln_category_l2"],
            }),
            "fixed_value_json": dump_json({
                "vuln_category_l1": SHARED["vuln_category_l1"],
                "vuln_category_l2": SHARED["vuln_category_l2"],
            }),
            "change_rationale": "l1/l2 already accurate; no new meta category introduced (per Q11).",
        })

    with CSV_OUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(diffs)


def main() -> None:
    entries = load_entries()
    fixed, originals = apply_fix(entries)
    for row in fixed:
        if row["entry_id"] in TARGET_IDS:
            validate(row)
    # Cross-check: still 408 rows (parallel file, not modifying entries.jsonl)
    assert len(fixed) == 408, f"row count drifted: {len(fixed)}"
    write_entries(fixed)
    write_csv(originals)
    print(f"Wrote {len(fixed)} rows (4 modified, 404 unmodified) to {JSONL_OUT.name}")
    print(f"  - baseline (read-only): {JSONL_IN.name} (unchanged)")
    print(f"Wrote diff CSV to {CSV_OUT}")


if __name__ == "__main__":
    main()
