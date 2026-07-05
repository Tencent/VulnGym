"""Generate config-vulnerability annotation artifacts for entry-00241..244.

The issue targets four OpenClaw Dockerfiles from commit
c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1.  This script keeps the original
dataset immutable, writes a four-row patch fragment, writes a full fixed
JSONL for reviewers that prefer a complete file, and emits a field-level CSV.
"""

from __future__ import annotations

import csv
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASELINE_JSONL = ROOT / "data" / "entries.jsonl"
PATCH_JSONL = ROOT / "data" / "entries.config_vuln_fixed.jsonl"
FULL_JSONL = ROOT / "data" / "entries.fixed.jsonl"
DIFF_CSV = ROOT / "reports" / "config_vuln_fix_diff.csv"

TARGET_IDS = ("entry-00241", "entry-00242", "entry-00243", "entry-00244")
UPSTREAM_COMMIT = "c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1"

SOURCE_FILES = {
    "scripts/e2e/Dockerfile": "\n".join(
        [
            "FROM node:22-bookworm",
            "",
            "RUN corepack enable",
            "",
            "WORKDIR /app",
            "",
            'ENV NODE_OPTIONS="--disable-warning=ExperimentalWarning"',
            "",
            "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json tsdown.config.ts vitest.config.ts vitest.e2e.config.ts openclaw.mjs ./",
            "COPY src ./src",
            "COPY test ./test",
            "COPY scripts ./scripts",
            "COPY docs ./docs",
            "COPY skills ./skills",
            "COPY patches ./patches",
            "COPY ui ./ui",
            "COPY extensions/memory-core ./extensions/memory-core",
            "",
            "RUN pnpm install --frozen-lockfile",
            "RUN pnpm build",
            "RUN pnpm ui:build",
            "",
            'CMD ["bash"]',
        ]
    ),
    "scripts/e2e/Dockerfile.qr-import": "\n".join(
        [
            "FROM node:22-bookworm",
            "",
            "RUN corepack enable",
            "",
            "WORKDIR /app",
            "",
            "COPY . .",
            "",
            "RUN pnpm install --frozen-lockfile",
        ]
    ),
    "scripts/docker/install-sh-e2e/Dockerfile": "\n".join(
        [
            "FROM node:22-bookworm-slim",
            "",
            "RUN apt-get update \\",
            "  && apt-get install -y --no-install-recommends \\",
            "    bash \\",
            "    ca-certificates \\",
            "    curl \\",
            "    git \\",
            "  && rm -rf /var/lib/apt/lists/*",
            "",
            "COPY run.sh /usr/local/bin/openclaw-install-e2e",
            "RUN chmod +x /usr/local/bin/openclaw-install-e2e",
            "",
            'ENTRYPOINT ["/usr/local/bin/openclaw-install-e2e"]',
        ]
    ),
    "scripts/docker/install-sh-nonroot/Dockerfile": "\n".join(
        [
            "FROM ubuntu:24.04",
            "",
            "RUN set -eux; \\",
            "  for attempt in 1 2 3; do \\",
            "    if apt-get update -o Acquire::Retries=3; then break; fi; \\",
            '    echo "apt-get update failed (attempt ${attempt})" >&2; \\',
            '    if [ "${attempt}" -eq 3 ]; then exit 1; fi; \\',
            "    sleep 3; \\",
            "  done; \\",
            "  apt-get -o Acquire::Retries=3 install -y --no-install-recommends \\",
            "    bash \\",
            "    ca-certificates \\",
            "    curl \\",
            "    sudo \\",
            "  && rm -rf /var/lib/apt/lists/*",
            "",
            "RUN useradd -m -s /bin/bash app \\",
            '  && echo "app ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/app',
            "",
            "USER app",
            "WORKDIR /home/app",
            "",
            "ENV NPM_CONFIG_FUND=false",
            "ENV NPM_CONFIG_AUDIT=false",
            "",
            "COPY run.sh /usr/local/bin/openclaw-install-nonroot",
            "RUN sudo chmod +x /usr/local/bin/openclaw-install-nonroot",
            "",
            'ENTRYPOINT ["/usr/local/bin/openclaw-install-nonroot"]',
        ]
    ),
}


def parse_line_span(line: int | str) -> tuple[int, int]:
    if isinstance(line, int):
        if line < 1:
            raise ValueError(f"line must be positive: {line!r}")
        return line, line
    start_text, end_text = line.split("-", 1)
    start, end = int(start_text), int(end_text)
    if start < 1 or end < start:
        raise ValueError(f"invalid range: {line!r}")
    return start, end


def source_slice(file_name: str, line: int | str) -> str:
    start, end = parse_line_span(line)
    lines = SOURCE_FILES[file_name].splitlines()
    if end > len(lines):
        raise ValueError(f"{file_name}:{line} exceeds {len(lines)} lines")
    return "\n".join(lines[start - 1 : end])


def make_node(file_name: str, line: int | str, desc: str) -> dict[str, Any]:
    return {
        "file": file_name,
        "line": line,
        "code": source_slice(file_name, line),
        "desc": desc,
    }


PATCH_SPECS = {
    "entry-00241": {
        "file": "scripts/e2e/Dockerfile",
        "entry_point": make_node(
            "scripts/e2e/Dockerfile",
            1,
            "The FROM instruction introduces the base image default root user into "
            "the Dockerfile state. Because no later USER instruction narrows that "
            "identity, root remains active through the build steps and the final "
            "CMD; for this missing-USER configuration bug, the first FROM line is "
            "the entry point.",
        ),
        "critical_operation": make_node(
            "scripts/e2e/Dockerfile",
            "1-23",
            "Lines 1-23 are the vulnerable configuration interval. The Dockerfile "
            "starts from a root-default Node image, copies and builds the app, and "
            "registers CMD [\"bash\"] without ever declaring USER. The bug is the "
            "structural absence of a non-root boundary, so marking only CMD would "
            "hide the root cause.",
        ),
        "trace": [
            make_node(
                "scripts/e2e/Dockerfile",
                "1-23",
                "Configuration state: the whole file keeps the default root user "
                "from FROM through dependency install, build, and CMD registration. "
                "No instruction changes the active user.",
            ),
            make_node(
                "scripts/e2e/Dockerfile",
                23,
                "Runtime materialization: CMD [\"bash\"] starts the default shell "
                "under the still-active root identity.",
            ),
        ],
    },
    "entry-00242": {
        "file": "scripts/e2e/Dockerfile.qr-import",
        "entry_point": make_node(
            "scripts/e2e/Dockerfile.qr-import",
            1,
            "The FROM instruction introduces the base image default root user into "
            "this short import Dockerfile. Since the file never declares USER, the "
            "root identity remains the active build identity from the first line.",
        ),
        "critical_operation": make_node(
            "scripts/e2e/Dockerfile.qr-import",
            "1-9",
            "Lines 1-9 are the complete vulnerable configuration interval. The "
            "image inherits root from node:22-bookworm, copies the project, and "
            "runs pnpm install with no USER boundary. The risk is not a single "
            "tainted value; it is the unbroken privileged configuration state.",
        ),
        "trace": [
            make_node(
                "scripts/e2e/Dockerfile.qr-import",
                "1-9",
                "Configuration state: FROM establishes root and every later "
                "instruction, including COPY and pnpm install, executes without "
                "a user downgrade.",
            ),
            make_node(
                "scripts/e2e/Dockerfile.qr-import",
                9,
                "Build-time materialization: pnpm install, including any package "
                "lifecycle scripts, runs with root privileges because USER is absent.",
            ),
        ],
    },
    "entry-00243": {
        "file": "scripts/docker/install-sh-e2e/Dockerfile",
        "entry_point": make_node(
            "scripts/docker/install-sh-e2e/Dockerfile",
            1,
            "The FROM instruction selects a root-default Node slim image. With no "
            "later USER instruction, that default identity becomes the active "
            "identity for package installation, script placement, chmod, and the "
            "container entrypoint.",
        ),
        "critical_operation": make_node(
            "scripts/docker/install-sh-e2e/Dockerfile",
            "1-14",
            "Lines 1-14 are the vulnerable configuration interval. The Dockerfile "
            "installs system packages, copies an installer into /usr/local/bin, "
            "marks it executable, and registers it as ENTRYPOINT while never "
            "switching away from root. The root cause is the missing USER boundary "
            "across the complete file.",
        ),
        "trace": [
            make_node(
                "scripts/docker/install-sh-e2e/Dockerfile",
                "1-14",
                "Configuration state: root is introduced by FROM and remains active "
                "while apt-get, COPY, chmod, and ENTRYPOINT are configured.",
            ),
            make_node(
                "scripts/docker/install-sh-e2e/Dockerfile",
                14,
                "Runtime materialization: the installer entrypoint launches under "
                "root because the Dockerfile never declares USER.",
            ),
        ],
    },
    "entry-00244": {
        "file": "scripts/docker/install-sh-nonroot/Dockerfile",
        "entry_point": make_node(
            "scripts/docker/install-sh-nonroot/Dockerfile",
            17,
            "This RUN starts the non-root boundary by creating app. In this variant "
            "the defect is not simply missing USER; the app boundary is immediately "
            "invalidated by the adjacent sudoers grant, so the user-creation block "
            "is the configuration entry point.",
        ),
        "critical_operation": make_node(
            "scripts/docker/install-sh-nonroot/Dockerfile",
            "17-20",
            "Lines 17-20 are the vulnerable configuration interval. The Dockerfile "
            "creates app, grants it NOPASSWD:ALL through sudoers, and then switches "
            "to USER app. That switch only looks like a downgrade: app can regain "
            "root without a password, so the non-root boundary is ineffective.",
        ),
        "trace": [
            make_node(
                "scripts/docker/install-sh-nonroot/Dockerfile",
                "17-20",
                "Configuration state: app is created, given passwordless full sudo, "
                "and then selected as USER. These adjacent instructions together "
                "erase the intended privilege boundary.",
            ),
            make_node(
                "scripts/docker/install-sh-nonroot/Dockerfile",
                27,
                "Privilege proof: after USER app, the build still uses sudo to chmod "
                "a system path, demonstrating that the app user can exercise root.",
            ),
            make_node(
                "scripts/docker/install-sh-nonroot/Dockerfile",
                29,
                "Runtime materialization: the nonroot-named entrypoint runs as app, "
                "but that app identity carries passwordless full-root escalation.",
            ),
        ],
    },
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def dump_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )


def build_patch_rows(baseline_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    baseline_by_id = {row["entry_id"]: row for row in baseline_rows}
    missing = sorted(set(TARGET_IDS) - set(baseline_by_id))
    if missing:
        raise KeyError(f"target rows missing from baseline: {missing}")

    patch_rows = []
    for entry_id in TARGET_IDS:
        row = deepcopy(baseline_by_id[entry_id])
        spec = PATCH_SPECS[entry_id]
        row["entry_point"] = deepcopy(spec["entry_point"])
        row["critical_operation"] = deepcopy(spec["critical_operation"])
        row["trace"] = deepcopy(spec["trace"])
        row["verify"] = 0
        patch_rows.append(row)
    return patch_rows


def apply_patch_rows(
    baseline_rows: list[dict[str, Any]], patch_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    patches = {row["entry_id"]: row for row in patch_rows}
    return [deepcopy(patches.get(row["entry_id"], row)) for row in baseline_rows]


def validate_node(node: dict[str, Any]) -> None:
    required = {"file", "line", "code"}
    if not required.issubset(node):
        raise AssertionError(f"node missing required fields: {node}")
    if node["file"] not in SOURCE_FILES:
        raise AssertionError(f"unexpected file: {node['file']}")
    if node["code"] != source_slice(node["file"], node["line"]):
        raise AssertionError(f"code mismatch at {node['file']}:{node['line']}")
    desc = node.get("desc", "")
    if len(desc) < 80:
        raise AssertionError(f"desc too short for {node['file']}:{node['line']}")
    if "??" in desc or "\ufffd" in desc:
        raise AssertionError(f"damaged desc detected at {node['file']}:{node['line']}")


def validate_patch_rows(patch_rows: list[dict[str, Any]]) -> None:
    ids = [row["entry_id"] for row in patch_rows]
    if ids != list(TARGET_IDS):
        raise AssertionError(f"patch rows out of order or incomplete: {ids}")
    for row in patch_rows:
        if row["commit"] != UPSTREAM_COMMIT:
            raise AssertionError(f"unexpected commit for {row['entry_id']}")
        if row["verify"] not in (0, 1):
            raise AssertionError(f"invalid verify value for {row['entry_id']}")
        validate_node(row["entry_point"])
        validate_node(row["critical_operation"])
        trace = row.get("trace")
        if not isinstance(trace, list) or not trace:
            raise AssertionError(f"empty trace for {row['entry_id']}")
        for node in trace:
            validate_node(node)


def compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_diff_csv(baseline_rows: list[dict[str, Any]], patch_rows: list[dict[str, Any]]) -> None:
    baseline_by_id = {row["entry_id"]: row for row in baseline_rows}
    fields = [
        "entry_id",
        "field_path",
        "old_file",
        "old_line",
        "old_code",
        "old_desc",
        "new_file",
        "new_line",
        "new_code",
        "new_desc",
        "old_value_json",
        "new_value_json",
        "reason",
    ]
    rows: list[dict[str, Any]] = []
    reasons = {
        "entry_point": (
            "Select the first instruction that introduces the vulnerable "
            "configuration state: FROM for missing-USER files, and useradd for "
            "the ineffective-nonroot sudoers variant."
        ),
        "critical_operation": (
            "Mark the minimal configuration interval that makes the unsafe "
            "privilege state unavoidable instead of a single taint sink line."
        ),
        "trace": (
            "Represent configuration-state propagation with compact state/effect "
            "nodes rather than a verbose per-command taint flow."
        ),
    }

    for patch_row in patch_rows:
        old = baseline_by_id[patch_row["entry_id"]]
        for field in ("entry_point", "critical_operation", "trace"):
            old_value = old[field]
            new_value = patch_row[field]
            if field == "trace":
                old_node = old_value[-1] if old_value else {}
                new_node = new_value[0] if new_value else {}
            else:
                old_node = old_value
                new_node = new_value
            rows.append(
                {
                    "entry_id": patch_row["entry_id"],
                    "field_path": field,
                    "old_file": old_node.get("file", "multiple"),
                    "old_line": old_node.get("line", "multiple"),
                    "old_code": old_node.get("code", compact(old_value)),
                    "old_desc": old_node.get("desc", ""),
                    "new_file": new_node.get("file", "multiple"),
                    "new_line": new_node.get("line", "multiple"),
                    "new_code": new_node.get("code", compact(new_value)),
                    "new_desc": new_node.get("desc", ""),
                    "old_value_json": compact(old_value),
                    "new_value_json": compact(new_value),
                    "reason": reasons[field],
                }
            )

    with DIFF_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    baseline_rows = load_jsonl(BASELINE_JSONL)
    patch_rows = build_patch_rows(baseline_rows)
    validate_patch_rows(patch_rows)
    fixed_rows = apply_patch_rows(baseline_rows, patch_rows)
    if len(fixed_rows) != len(baseline_rows):
        raise AssertionError("full fixed row count changed")

    dump_jsonl(PATCH_JSONL, patch_rows)
    dump_jsonl(FULL_JSONL, fixed_rows)
    write_diff_csv(baseline_rows, patch_rows)

    print(f"patch rows: {len(patch_rows)} -> {PATCH_JSONL}")
    print(f"full rows: {len(fixed_rows)} -> {FULL_JSONL}")
    print(f"diff rows: {len(patch_rows) * 3} -> {DIFF_CSV}")


if __name__ == "__main__":
    main()
