"""Apply and verify Issue #8 configuration-vulnerability annotations.

The target entries describe effective Dockerfile privilege state rather than a
traditional attacker-controlled taint flow.  Node code is materialized from the
pinned OpenClaw commit so every {file, line, code} triple is source-backed.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
DIFF_PATH = ROOT / "reports" / "issue-8-config-annotations.diff.csv"
TARGET_IDS = {
    "entry-00241",
    "entry-00242",
    "entry-00243",
    "entry-00244",
}
REPORT_ID = "GHSA-W7J5-J98M-W679"
SOURCE_REPO = "openclaw/openclaw"
VULNERABLE_COMMIT = "c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1"
FIX_COMMIT = "84281abd4bd1c717bb37a2de12694fe203827eee"


@dataclass(frozen=True)
class NodeSpec:
    file: str
    start: int
    end: int
    desc: str


def spec(file: str, start: int, end: int, desc: str) -> NodeSpec:
    return NodeSpec(file=file, start=start, end=end, desc=desc)


E2E = "scripts/e2e/Dockerfile"
QR_IMPORT = "scripts/e2e/Dockerfile.qr-import"
INSTALL_E2E = "scripts/docker/install-sh-e2e/Dockerfile"
INSTALL_NONROOT = "scripts/docker/install-sh-nonroot/Dockerfile"
MISSING_USER_FILES = {
    E2E,
    QR_IMPORT,
    INSTALL_E2E,
}


SPECS: dict[str, dict[str, Any]] = {
    "entry-00241": {
        "entry_point": spec(
            E2E,
            1,
            1,
            "FROM 开启该镜像的配置作用域，并从 node:22-bookworm 继承默认 root 身份。"
            "本 Dockerfile 后续没有 USER 指令，因此这里建立的权限状态会持续到构建命令和"
            "容器默认进程；它是配置继承入口，而不是传统污点输入。",
        ),
        "critical_operation": spec(
            E2E,
            23,
            23,
            "CMD 将 bash 注册为容器默认进程。由于此前始终没有 USER 身份切换，"
            "该进程启动时的有效 uid 为 0；缺失的加固指令无法被定位到源码行，"
            "因此选择这一实际运行时生效点作为关键操作。",
        ),
        "trace": [
            spec(
                E2E,
                1,
                1,
                "基础镜像提供默认 root 用户，建立本阶段继承的权限状态。",
            ),
            spec(
                E2E,
                19,
                21,
                "依赖安装和两次构建均在未发生 USER 转换的 root 上下文中执行，"
                "展示危险配置在构建阶段的实际效果。",
            ),
            spec(
                E2E,
                23,
                23,
                "CMD 继续消费同一 root 状态，容器运行时默认进程因而以 uid 0 启动。",
            ),
        ],
    },
    "entry-00242": {
        "entry_point": spec(
            QR_IMPORT,
            1,
            1,
            "FROM 开启 qr-import 镜像阶段并继承 node:22-bookworm 的默认 root 用户；"
            "文件中没有后续 USER 指令覆盖这一有效身份。",
        ),
        "critical_operation": spec(
            QR_IMPORT,
            9,
            9,
            "pnpm install 在继承的 root 身份下执行，依赖生命周期脚本因此获得不必要的"
            " uid 0 权限。这是该短生命周期测试镜像中危险配置明确生效的操作。",
        ),
        "trace": [
            spec(
                QR_IMPORT,
                1,
                1,
                "基础镜像的默认用户配置建立 root 权限状态。",
            ),
            spec(
                QR_IMPORT,
                9,
                9,
                "没有 USER 转换时，依赖安装直接在 root 权限状态下执行。",
            ),
        ],
    },
    "entry-00243": {
        "entry_point": spec(
            INSTALL_E2E,
            1,
            1,
            "FROM 开启安装脚本测试镜像的配置阶段，并从 node:22-bookworm-slim "
            "继承默认 root 身份；后续没有 USER 指令改变该状态。",
        ),
        "critical_operation": spec(
            INSTALL_E2E,
            14,
            14,
            "ENTRYPOINT 将测试安装器设为容器主进程。由于整个阶段没有发生用户切换，"
            "安装器启动时直接继承 uid 0，这是过度特权在运行时的实际生效点。",
        ),
        "trace": [
            spec(
                INSTALL_E2E,
                1,
                1,
                "基础镜像建立持续生效的 root 用户配置。",
            ),
            spec(
                INSTALL_E2E,
                11,
                12,
                "启动脚本被写入系统目录并设置为可执行文件，操作仍处于继承的 root 配置作用域。",
            ),
            spec(
                INSTALL_E2E,
                14,
                14,
                "ENTRYPOINT 消费该配置状态，使安装脚本作为 uid 0 的容器主进程启动。",
            ),
        ],
    },
    "entry-00244": {
        "entry_point": spec(
            INSTALL_NONROOT,
            17,
            18,
            "该 RUN 配置块创建 app 用户，并立即写入与其关联的 sudoers 规则。"
            "与前三条依赖缺失 USER 的样本不同，这里的危险状态由显式配置引入，"
            "因此入口直接锚定到用户与授权配置作用域。",
        ),
        "critical_operation": spec(
            INSTALL_NONROOT,
            18,
            18,
            "sudoers 规则授予 app 对任意用户和任意命令的 NOPASSWD sudo 权限。"
            "这条显式危险配置使后续 USER app 仅形成名义降权，受控进程可立即恢复完整 root。",
        ),
        "trace": [
            spec(
                INSTALL_NONROOT,
                17,
                18,
                "同一配置块创建 app，并通过 NOPASSWD:ALL 建立无口令的完整提权能力。",
            ),
            spec(
                INSTALL_NONROOT,
                20,
                20,
                "USER app 改变名义 uid，但没有撤销前一步赋予的全量 sudo 能力。",
            ),
            spec(
                INSTALL_NONROOT,
                27,
                27,
                "app 随后实际调用 sudo 修改系统目录中的文件，证明危险授权已经可用而非静态死配置。",
            ),
            spec(
                INSTALL_NONROOT,
                29,
                29,
                "ENTRYPOINT 以仍具完整 root 恢复能力的 app 身份启动测试安装器，"
                "危险配置状态延续到运行时。",
            ),
        ],
    },
}


def _source_text(
    path: str,
    source_repo: Path | None = None,
    commit: str = VULNERABLE_COMMIT,
) -> str:
    if source_repo is not None:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(source_repo),
                "show",
                f"{commit}:{path}",
            ],
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        return result.stdout

    request = Request(
        f"https://raw.githubusercontent.com/{SOURCE_REPO}/{commit}/{path}",
        headers={"User-Agent": "VulnGym-Issue-8-validator"},
    )
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def _materialize(node_spec: NodeSpec, sources: dict[str, str]) -> dict[str, Any]:
    source = sources[node_spec.file]
    lines = source.splitlines()
    if node_spec.start < 1 or node_spec.end < node_spec.start or node_spec.end > len(lines):
        raise RuntimeError(
            f"invalid range {node_spec.file}:{node_spec.start}-{node_spec.end}"
        )
    code = "\n".join(lines[node_spec.start - 1 : node_spec.end])
    line: int | str = (
        node_spec.start
        if node_spec.start == node_spec.end
        else f"{node_spec.start}-{node_spec.end}"
    )
    return {
        "code": code,
        "desc": node_spec.desc,
        "file": node_spec.file,
        "line": line,
    }


def build_updates(source_repo: Path | None = None) -> dict[str, dict[str, Any]]:
    paths = {
        node.file
        for entry_spec in SPECS.values()
        for node in [
            entry_spec["entry_point"],
            entry_spec["critical_operation"],
            *entry_spec["trace"],
        ]
    }
    sources = {path: _source_text(path, source_repo) for path in sorted(paths)}
    updates: dict[str, dict[str, Any]] = {}
    for entry_id, entry_spec in SPECS.items():
        updates[entry_id] = {
            "entry_point": _materialize(entry_spec["entry_point"], sources),
            "critical_operation": _materialize(
                entry_spec["critical_operation"], sources
            ),
            "trace": [_materialize(node, sources) for node in entry_spec["trace"]],
            "verify": 0,
        }
    return updates


def apply(source_repo: Path | None = None) -> None:
    updates = build_updates(source_repo)
    raw_lines = DATA_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
    output: list[str] = []
    seen: set[str] = set()
    diff_rows: list[dict[str, str]] = []

    for raw in raw_lines:
        if not raw.strip():
            output.append(raw)
            continue
        record = json.loads(raw)
        entry_id = record["entry_id"]
        if entry_id not in TARGET_IDS:
            output.append(raw)
            continue

        seen.add(entry_id)
        for field in ("entry_point", "critical_operation", "trace", "verify"):
            before = record[field]
            after = updates[entry_id][field]
            if before != after:
                diff_rows.append(
                    {
                        "entry_id": entry_id,
                        "field": field,
                        "before": json.dumps(
                            before, ensure_ascii=False, sort_keys=True
                        ),
                        "after": json.dumps(
                            after, ensure_ascii=False, sort_keys=True
                        ),
                        "reason": {
                            "entry_point": "配置继承或显式危险配置进入生效作用域的位置",
                            "critical_operation": "危险配置声明或过度特权实际生效的最窄源码位置",
                            "trace": "以配置声明、继承、权限转换和生效点替代伪造的污点传播",
                            "verify": "语义修改后保守等待维护者人工确认",
                        }[field],
                    }
                )
            record[field] = after
        output.append(json.dumps(record, ensure_ascii=False) + "\n")

    if seen != TARGET_IDS:
        missing = ", ".join(sorted(TARGET_IDS - seen))
        raise RuntimeError(f"missing target entries: {missing}")

    DATA_PATH.write_text("".join(output), encoding="utf-8", newline="\n")
    DIFF_PATH.parent.mkdir(parents=True, exist_ok=True)
    if diff_rows or not DIFF_PATH.exists():
        with DIFF_PATH.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["entry_id", "field", "before", "after", "reason"],
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(diff_rows)


def _line_bounds(value: int | str) -> tuple[int, int]:
    if isinstance(value, int):
        return value, value
    start, end = value.split("-", 1)
    return int(start), int(end)


def _user_directives(source: str) -> list[str]:
    return [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("USER ")
        and not line.lstrip().startswith("#")
    ]


def check_upstream(source_repo: Path | None = None) -> None:
    records: dict[str, dict[str, Any]] = {}
    with DATA_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record["entry_id"] in TARGET_IDS:
                records[record["entry_id"]] = record
    if set(records) != TARGET_IDS:
        raise RuntimeError("canonical data does not contain all Issue #8 targets")

    paths = {
        node["file"]
        for record in records.values()
        for node in [
            record["entry_point"],
            record["critical_operation"],
            *record["trace"],
        ]
    }
    sources = {path: _source_text(path, source_repo) for path in sorted(paths)}
    fixed_sources = {
        path: _source_text(path, source_repo, FIX_COMMIT)
        for path in sorted(MISSING_USER_FILES)
    }
    occurrences = 0
    unique_nodes: set[tuple[str, str, str]] = set()

    for entry_id, record in sorted(records.items()):
        if record["commit"] != VULNERABLE_COMMIT:
            raise RuntimeError(f"{entry_id} has an unexpected vulnerable commit")
        if record["report_id"] != REPORT_ID:
            raise RuntimeError(f"{entry_id} has an unexpected report id")
        for node in [
            record["entry_point"],
            record["critical_operation"],
            *record["trace"],
        ]:
            start, end = _line_bounds(node["line"])
            actual = "\n".join(sources[node["file"]].splitlines()[start - 1 : end])
            if actual != node["code"]:
                raise RuntimeError(
                    f"source mismatch at {node['file']}:{node['line']}"
                )
            occurrences += 1
            unique_nodes.add((node["file"], str(node["line"]), node["code"]))

    for path in sorted(MISSING_USER_FILES):
        vulnerable_users = _user_directives(sources[path])
        if vulnerable_users:
            raise RuntimeError(
                f"unexpected USER directive in vulnerable source {path}: "
                f"{vulnerable_users}"
            )
        fixed_users = _user_directives(fixed_sources[path])
        if "USER appuser" not in fixed_users:
            raise RuntimeError(
                f"{FIX_COMMIT} does not add USER appuser to {path}"
            )

    print(
        f"upstream validation passed: {occurrences} annotated occurrences, "
        f"{len(unique_nodes)} unique nodes, {len(sources)} Dockerfiles"
    )
    print(
        f"fix validation passed: {FIX_COMMIT} adds USER appuser to "
        f"{len(fixed_sources)} previously root-default Dockerfiles"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="validate canonical nodes against the pinned OpenClaw commit",
    )
    parser.add_argument(
        "--source-repo",
        type=Path,
        help="optional local OpenClaw git checkout used instead of raw GitHub",
    )
    args = parser.parse_args()
    if args.check_upstream:
        check_upstream(args.source_repo)
    else:
        apply(args.source_repo)


if __name__ == "__main__":
    main()
