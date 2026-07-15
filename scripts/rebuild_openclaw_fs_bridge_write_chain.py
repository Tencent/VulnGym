#!/usr/bin/env python3
"""Rebuild and verify the two OpenClaw staged-write chains from issue #7."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import urllib.request
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ENTRIES_PATH = ROOT / "data" / "entries.jsonl"
DIFF_PATH = ROOT / "issue-7-fs-bridge-write-fix-diff.csv"
TARGET_IDS = ("entry-00301", "entry-00302")
REPORT_ID = "GHSA-MJ4P-RC52-M843"
VULNERABLE_COMMIT = "3caab9260cb0a0064e6a37b2de3bedc8a547e599"
FIX_COMMIT = "11924a70264f235b2b1d47e3d32a5f0dae111bb1"
FIX_PARENT = "702f6f3305653922548ed2f5c78228ef3c3573e7"
PATCH_FIELDS = ("entry_point", "critical_operation", "trace", "verify")
BASELINE_DIGESTS = {
    "entry-00301": "a6e8642dbd3eaf68247946e9f7c441b4f7abd2dd54ffc074363a93085c4d94aa",
    "entry-00302": "cb51cc9ab6ea871e74ba3f710c621f5ba684241d2c50521a554cef73bc8fc0b5",
}


def node(file: str, line: int | str, code: str, desc: str) -> dict[str, Any]:
    return {"file": file, "line": line, "code": code, "desc": desc}


WRITE_TOOL_ENTRY = node(
    "src/agents/pi-tools.read.ts",
    "538-539",
    """    writeFile: async (absolutePath: string, content: string) => {
      await params.bridge.writeFile({ filePath: absolutePath, cwd: params.root, data: content });""",
    "沙箱 write/edit 工具在此接收模型可控的 absolutePath 与 content，并把二者原样交给 fs bridge。"
    "这是第一条真实可达写入路径，而不是原标注中的 readFile 闭合括号。",
)

APPLY_PATCH_ENTRY = node(
    "src/agents/apply-patch.ts",
    "98-100",
    """    execute: async (_toolCallId, args, signal) => {
      const params = args as { input?: string };
      const input = typeof params.input === "string" ? params.input : "";""",
    "apply_patch 工具在此接收模型提供的 patch input；路径与写入内容随后从 parsed hunks 中产生。"
    "这是第二条独立入口，能够到达同一个存在竞态的 fs bridge 写入实现。",
)

BRIDGE_BOUNDARY = node(
    "src/agents/sandbox/fs-bridge.ts",
    "105-112",
    """  async writeFile(params: {
    filePath: string;
    cwd?: string;
    data: Buffer | string;
    encoding?: BufferEncoding;
    mkdir?: boolean;
    signal?: AbortSignal;
  }): Promise<void> {""",
    "SandboxFsBridgeImpl.writeFile 汇聚攻击者控制的目标路径和数据，是两条上层入口进入容器写入流程的共同边界。",
)

INITIAL_CHECK = node(
    "src/agents/sandbox/fs-bridge.ts",
    "113-115",
    """    const target = this.resolveResolvedPath(params);
    this.ensureWriteAccess(target, "write files");
    await this.pathGuard.assertPathSafety(target, { action: "write files", requireWritable: true });""",
    "目标先经过挂载权限和路径安全检查；问题在于检查结果没有绑定父目录句柄，父路径可在后续使用前被替换。",
)

BUFFER_STAGE = node(
    "src/agents/sandbox/fs-bridge.ts",
    "116-118",
    """    const buffer = Buffer.isBuffer(params.data)
      ? params.data
      : Buffer.from(params.data, params.encoding ?? "utf8");""",
    "攻击者控制的 content 被规范为 Buffer，随后作为 stdin 送入临时文件写入脚本。",
)

TEMP_STAGE_CALL = node(
    "src/agents/sandbox/fs-bridge.ts",
    "119-124",
    """    const tempPath = await this.writeFileToTempPath({
      targetContainerPath: target.containerPath,
      mkdir: params.mkdir !== false,
      data: buffer,
      signal: params.signal,
    });""",
    "路径检查完成后才调用 writeFileToTempPath；此调用与前面的检查之间形成 check/use 分离，并进入未固定父目录的阶段写入。",
)

UNSAFE_STAGE = node(
    "src/agents/sandbox/fs-bridge.ts",
    "274-298",
    """    const script = params.mkdir
      ? [
          "set -eu",
          'target="$1"',
          'dir=$(dirname -- "$target")',
          'if [ "$dir" != "." ]; then mkdir -p -- "$dir"; fi',
          'base=$(basename -- "$target")',
          'tmp=$(mktemp "$dir/.openclaw-write-$base.XXXXXX")',
          'cat >"$tmp"',
          'printf "%s\\\\n" "$tmp"',
        ].join("\\n")
      : [
          "set -eu",
          'target="$1"',
          'dir=$(dirname -- "$target")',
          'base=$(basename -- "$target")',
          'tmp=$(mktemp "$dir/.openclaw-write-$base.XXXXXX")',
          'cat >"$tmp"',
          'printf "%s\\\\n" "$tmp"',
        ].join("\\n");
    const result = await this.runCommand(script, {
      args: [params.targetContainerPath],
      stdin: params.data,
      signal: params.signal,
    });""",
    "shell 脚本重新按可变路径计算 dirname，并在该目录执行 mktemp 与 cat。它没有使用已验证父目录的 fd，"
    "因此竞态替换父路径后，临时文件及攻击者字节会先在允许挂载之外物化。",
)

UNSAFE_WRITE = node(
    "src/agents/sandbox/fs-bridge.ts",
    "281-298",
    """          'tmp=$(mktemp "$dir/.openclaw-write-$base.XXXXXX")',
          'cat >"$tmp"',
          'printf "%s\\\\n" "$tmp"',
        ].join("\\n")
      : [
          "set -eu",
          'target="$1"',
          'dir=$(dirname -- "$target")',
          'base=$(basename -- "$target")',
          'tmp=$(mktemp "$dir/.openclaw-write-$base.XXXXXX")',
          'cat >"$tmp"',
          'printf "%s\\\\n" "$tmp"',
        ].join("\\n");
    const result = await this.runCommand(script, {
      args: [params.targetContainerPath],
      stdin: params.data,
      signal: params.signal,
    });""",
    "mktemp 与 cat 在未固定父路径中创建临时文件并准备攻击者字节，随后的 runCommand 真正执行该脚本。"
    "这是越界物化发生的完整操作范围；后续 rename 即使被重新检查并拒绝，也无法撤销这次写入。",
)

FINAL_COMMIT_CALL = node(
    "src/agents/sandbox/fs-bridge.ts",
    "126-130",
    """    try {
      await this.runCheckedCommand({
        ...buildWriteCommitPlan(target, tempPath),
        signal: params.signal,
      });""",
    "临时文件写完后才构建最终提交计划；该阶段的重新检查只能保护最终移动，无法撤销此前已经发生的越界临时写入。",
)

FINAL_COMMIT_PLAN = node(
    "src/agents/sandbox/fs-bridge-shell-command-plans.ts",
    "13-22",
    """export function buildWriteCommitPlan(
  target: SandboxResolvedFsPath,
  tempPath: string,
): SandboxFsCommandPlan {
  return {
    checks: [{ target, options: { action: "write files", requireWritable: true } }],
    recheckBeforeCommand: true,
    script: 'set -eu; mv -f -- "$1" "$2"',
    args: [tempPath, target.containerPath],
  };""",
    "最终 mv 前确实设置 recheckBeforeCommand，这说明旧防护只覆盖 commit 阶段；漏洞发生在更早的 temp-file materialization 阶段。",
)

APPLY_PATCH_CALL = node(
    "src/agents/apply-patch.ts",
    "110-115",
    """      const result = await applyPatch(input, {
        cwd,
        sandbox,
        workspaceOnly,
        signal,
      });""",
    "未经语义约束的 patch input 被送入 applyPatch，开始解析文件路径和新增/修改内容。",
)

PATCH_FILE_OPS = node(
    "src/agents/apply-patch.ts",
    "229-240",
    """function resolvePatchFileOps(options: ApplyPatchOptions): PatchFileOps {
  if (options.sandbox) {
    const { root, bridge } = options.sandbox;
    return {
      readFile: async (filePath) => {
        const buf = await bridge.readFile({ filePath, cwd: root });
        return buf.toString("utf8");
      },
      writeFile: (filePath, content) => bridge.writeFile({ filePath, cwd: root, data: content }),
      remove: (filePath) => bridge.remove({ filePath, cwd: root, force: false }),
      mkdirp: (dir) => bridge.mkdirp({ filePath: dir, cwd: root }),
    };""",
    "沙箱模式把 patch 的 filePath/content 映射到 bridge.writeFile，使 apply_patch 与普通 write/edit 工具汇聚到同一底层实现。",
)

PATCH_HUNK_WRITE = node(
    "src/agents/apply-patch.ts",
    "146-156",
    """  for (const hunk of parsed.hunks) {
    if (options.signal?.aborted) {
      const err = new Error("Aborted");
      err.name = "AbortError";
      throw err;
    }

    if (hunk.kind === "add") {
      const target = await resolvePatchPath(hunk.path, options);
      await ensureDir(target.resolved, fileOps);
      await fileOps.writeFile(target.resolved, hunk.contents);""",
    "add hunk 将模型控制的路径和内容交给 fileOps.writeFile；这是 patch 语义进入沙箱写入桥的实际传播节点。",
)


TARGET_PATCHES: dict[str, dict[str, Any]] = {
    "entry-00301": {
        "entry_point": WRITE_TOOL_ENTRY,
        "critical_operation": UNSAFE_WRITE,
        "trace": [
            WRITE_TOOL_ENTRY,
            BRIDGE_BOUNDARY,
            INITIAL_CHECK,
            BUFFER_STAGE,
            TEMP_STAGE_CALL,
            UNSAFE_STAGE,
            FINAL_COMMIT_CALL,
            FINAL_COMMIT_PLAN,
        ],
        "verify": 0,
    },
    "entry-00302": {
        "entry_point": APPLY_PATCH_ENTRY,
        "critical_operation": UNSAFE_WRITE,
        "trace": [
            APPLY_PATCH_ENTRY,
            APPLY_PATCH_CALL,
            PATCH_FILE_OPS,
            PATCH_HUNK_WRITE,
            BRIDGE_BOUNDARY,
            INITIAL_CHECK,
            TEMP_STAGE_CALL,
            UNSAFE_STAGE,
            FINAL_COMMIT_CALL,
            FINAL_COMMIT_PLAN,
        ],
        "verify": 0,
    },
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_jsonl(path: Path, entries: list[dict[str, Any]]) -> None:
    content = "".join(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n" for entry in entries)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def payload_digest(entry: dict[str, Any]) -> str:
    payload = {field: entry[field] for field in PATCH_FIELDS}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def patch_entries(entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    patched = deepcopy(entries)
    by_id = {entry["entry_id"]: entry for entry in patched}
    if set(TARGET_IDS) - set(by_id):
        raise ValueError("target entries are missing")

    rows: list[dict[str, str]] = []
    for entry_id in TARGET_IDS:
        entry = by_id[entry_id]
        expected = TARGET_PATCHES[entry_id]
        current_digest = payload_digest(entry)
        after_probe = deepcopy(entry)
        after_probe.update(deepcopy(expected))
        after_digest = payload_digest(after_probe)
        if current_digest not in {BASELINE_DIGESTS[entry_id], after_digest}:
            raise ValueError(f"{entry_id} is neither the known baseline nor the rebuilt payload")
        for field in PATCH_FIELDS:
            before = entry[field]
            after = deepcopy(expected[field])
            if before != after:
                rows.append(
                    {
                        "entry_id": entry_id,
                        "field": field,
                        "before": json.dumps(before, ensure_ascii=False, sort_keys=True),
                        "after": json.dumps(after, ensure_ascii=False, sort_keys=True),
                        "rationale": {
                            "entry_point": "replace non-input node with a reachable attacker-controlled ingress",
                            "critical_operation": "move from an unrelated check/declaration to pre-commit temp-file materialization",
                            "trace": "rebuild the full check -> raced staging write -> guarded final commit sequence",
                            "verify": "require maintainer confirmation after semantic reconstruction",
                        }[field],
                    }
                )
            entry[field] = after
    return patched, rows


def write_diff(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("entry_id", "field", "before", "after", "rationale"), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def parse_span(line: int | str) -> tuple[int, int]:
    if isinstance(line, int):
        return line, line
    start, end = line.split("-", 1)
    return int(start), int(end)


def source_nodes() -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for patch in TARGET_PATCHES.values():
        for item in (patch["entry_point"], patch["critical_operation"], *patch["trace"]):
            key = (item["file"], str(item["line"]), item["code"])
            unique[key] = item
    return list(unique.values())


def request(url: str) -> bytes:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "VulnGym-issue-7-verifier"}
    if url.startswith("https://api.github.com/") and (token := os.getenv("GITHUB_TOKEN")):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return response.read()


def check_upstream() -> list[str]:
    cache: dict[str, str] = {}
    checked = 0
    for item in source_nodes():
        file = item["file"]
        if file not in cache:
            url = f"https://raw.githubusercontent.com/openclaw/openclaw/{VULNERABLE_COMMIT}/{file}"
            cache[file] = request(url).decode("utf-8").replace("\r\n", "\n")
        start, end = parse_span(item["line"])
        actual = "\n".join(cache[file].splitlines()[start - 1 : end])
        if actual != item["code"]:
            raise ValueError(f"source mismatch: {file}:{item['line']}")
        checked += 1

    commit = json.loads(request(f"https://api.github.com/repos/openclaw/openclaw/commits/{FIX_COMMIT}"))
    parents = [parent["sha"] for parent in commit["parents"]]
    if parents != [FIX_PARENT]:
        raise ValueError(f"unexpected fix parent: {parents}")

    comparison = json.loads(
        request(f"https://api.github.com/repos/openclaw/openclaw/compare/{VULNERABLE_COMMIT}...{FIX_PARENT}")
    )
    if comparison["status"] != "ahead":
        raise ValueError("vulnerable snapshot is not an ancestor of the fix parent")

    fixed_bridge = request(
        f"https://raw.githubusercontent.com/openclaw/openclaw/{FIX_COMMIT}/src/agents/sandbox/fs-bridge.ts"
    ).decode("utf-8")
    fixed_helper = request(
        f"https://raw.githubusercontent.com/openclaw/openclaw/{FIX_COMMIT}/src/agents/sandbox/fs-bridge-write-helper.ts"
    ).decode("utf-8")
    if "writeFileToTempPath" in fixed_bridge or "buildPinnedWritePlan" not in fixed_bridge:
        raise ValueError("fix does not replace the vulnerable staging helper as expected")
    markers = (
        "os.open(candidate, WRITE_FLAGS, 0o600, dir_fd=parent_fd)",
        "os.replace(temp_name, basename, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)",
    )
    if not all(marker in fixed_helper for marker in markers):
        raise ValueError("pinned directory-fd fix markers are missing")
    return [
        f"upstream source nodes: {checked}/{checked} exact matches",
        f"fix commit parent: {FIX_COMMIT[:7]} -> {FIX_PARENT[:7]}",
        f"vulnerable snapshot precedes fix parent: yes ({comparison['ahead_by']} commits)",
        "fix pins temp creation and atomic replace to the verified parent fd: yes",
    ]


def check_diff_artifact(entries: list[dict[str, Any]]) -> None:
    with DIFF_PATH.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != len(TARGET_IDS) * len(PATCH_FIELDS):
        raise ValueError("diff artifact must contain four changed fields for each target")
    by_id = {entry["entry_id"]: entry for entry in entries}
    reconstructed = deepcopy(entries)
    reconstructed_by_id = {entry["entry_id"]: entry for entry in reconstructed}
    for row in rows:
        if row["entry_id"] not in TARGET_IDS or row["field"] not in PATCH_FIELDS:
            raise ValueError("unexpected diff row")
        if json.loads(row["after"]) != by_id[row["entry_id"]][row["field"]]:
            raise ValueError("diff after value does not match canonical data")
        reconstructed_by_id[row["entry_id"]][row["field"]] = json.loads(row["before"])
    for entry_id in TARGET_IDS:
        if payload_digest(reconstructed_by_id[entry_id]) != BASELINE_DIGESTS[entry_id]:
            raise ValueError(f"diff before values do not reconstruct {entry_id} baseline")
    replayed, replay_rows = patch_entries(reconstructed)
    if replayed != entries or replay_rows != rows:
        raise ValueError("diff artifact cannot reproduce the canonical entries")


def check_base_ref(entries: list[dict[str, Any]], base_ref: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{base_ref}:data/entries.jsonl"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    base = [json.loads(line) for line in result.stdout.splitlines() if line]
    current_by_id = {entry["entry_id"]: entry for entry in entries}
    base_by_id = {entry["entry_id"]: entry for entry in base}
    if current_by_id.keys() != base_by_id.keys():
        raise ValueError("entry ids changed relative to base")
    changed_ids: list[str] = []
    for entry_id, current in current_by_id.items():
        original = base_by_id[entry_id]
        if current != original:
            changed_ids.append(entry_id)
            changed_fields = {key for key in current if current[key] != original[key]}
            if entry_id not in TARGET_IDS or changed_fields != set(PATCH_FIELDS):
                raise ValueError(f"unexpected canonical change: {entry_id} {sorted(changed_fields)}")
    if tuple(changed_ids) != TARGET_IDS:
        raise ValueError(f"unexpected changed entries: {changed_ids}")
    return f"canonical diff against {base_ref}: 2 entries / 8 fields"


def check_canonical(base_ref: str | None, upstream: bool) -> None:
    entries = load_jsonl(ENTRIES_PATH)
    by_id = {entry["entry_id"]: entry for entry in entries}
    for entry_id, expected in TARGET_PATCHES.items():
        entry = by_id[entry_id]
        if entry["report_id"] != REPORT_ID or entry["commit"] != VULNERABLE_COMMIT:
            raise ValueError(f"unexpected report metadata for {entry_id}")
        for field in PATCH_FIELDS:
            if entry[field] != expected[field]:
                raise ValueError(f"canonical mismatch: {entry_id}.{field}")
    check_diff_artifact(entries)

    verified_entries = sum(entry["verify"] == 1 for entry in entries)
    verified_reports = len({entry["report_id"] for entry in entries if entry["verify"] == 1})
    print("canonical target entries: 2/2 valid")
    print(f"source-backed semantic nodes: {len(source_nodes())} unique")
    print(f"dataset audit state: {verified_entries}/408 entries, {verified_reports}/184 advisories")
    print("field-level diff replay: 8/8 rows valid")
    if base_ref:
        print(check_base_ref(entries, base_ref))
    if upstream:
        for line in check_upstream():
            print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply the two patches to the canonical JSONL")
    parser.add_argument("--check-upstream", action="store_true", help="verify pinned source and fix evidence online")
    parser.add_argument("--base-ref", help="git ref used to prove canonical change scope")
    args = parser.parse_args()

    if args.apply:
        entries = load_jsonl(ENTRIES_PATH)
        patched, rows = patch_entries(entries)
        if not rows:
            print("canonical patches already applied; files left unchanged")
            return
        write_jsonl(ENTRIES_PATH, patched)
        write_diff(DIFF_PATH, rows)
        print(f"applied {len(rows)} field changes across {len(TARGET_IDS)} entries")
        return

    check_canonical(args.base_ref, args.check_upstream)


if __name__ == "__main__":
    main()
