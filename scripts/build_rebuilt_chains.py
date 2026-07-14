#!/usr/bin/env python3
"""Build source-backed patches for the complex chains in issue #7."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NodeSpec:
    file: str
    start: int
    end: int
    desc: str


def n(file: str, start: int, end: int, desc: str) -> NodeSpec:
    return NodeSpec(file, start, end, desc)


SPECS: dict[str, dict[str, object]] = {
    "entry-00185": {
        "repo": "n8n-io__n8n", "url": "https://github.com/n8n-io/n8n",
        "entry_point": n("packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts", 69, 74, "The authenticated workflow author controls fileName, which is read here and paired with overwrite/append flags. This is the first security-relevant input to the disk-write chain."),
        "critical_operation": n("packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts", 118, 131, "writeContentToFile permits paths not covered by the restricted-path list and calls fsWriteFile. Writing attacker-controlled Git configuration or metadata here enables the later Git-operation command-execution stage."),
        "trace": [
            n("packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts", 69, 74, "Workflow parameters provide the destination path and write mode."),
            n("packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts", 95, 100, "The node resolves fileName and forwards content and flags to the filesystem helper."),
            n("packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts", 39, 48, "resolvePath canonicalizes an existing destination or lexically resolves a missing file, preserving a target under .git."),
            n("packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts", 50, 65, "isFilePathBlocked checks configured n8n and allow-list paths but has no Git-metadata restriction, so the malicious destination returns false."),
            n("packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts", 118, 131, "The unblocked path reaches fsWriteFile and plants the Git configuration used by the prerequisite follow-up Git operation."),
        ],
    },
    "entry-00197": {
        "repo": "openclaw__openclaw", "url": "https://github.com/openclaw/openclaw",
        "entry_point": n("src/media/server.ts", 35, 36, "Main trigger stage: an unauthenticated GET /media/:id request supplies the media identifier after the attacker has prepared or retargeted a media-path symlink in the prerequisite stage."),
        "critical_operation": n("src/media/server.ts", 57, 57, "The route reads bytes from the file handle selected after path validation. In the vulnerable multi-stage scenario, check/use drift around a retargeted media path can make this read disclose a host file outside sandboxRoot."),
        "trace": [
            n("src/media/server.ts", 35, 40, "The main trigger receives the attacker-chosen media id and applies only lexical identifier validation."),
            n("src/media/server.ts", 42, 45, "The route asks openFileWithinRoot to validate/open the prepared media path."),
            n("src/infra/fs-safe.ts", 119, 138, "The helper resolves the root and candidate and performs the lexical root-boundary check."),
            n("src/infra/fs-safe.ts", 140, 165, "The helper opens/verifies the candidate and performs a later canonical boundary check; the advisory identifies drift between validation and use across media call sites."),
            n("src/media/server.ts", 46, 57, "Size and TTL checks occur before the final handle read, widening the check/use sequence represented by this main trigger stage."),
        ],
    },
    "entry-00290": {
        "repo": "openclaw__openclaw", "url": "https://github.com/openclaw/openclaw",
        "entry_point": n("src/agents/apply-patch.ts", 94, 106, "An agent-controlled apply_patch invocation supplies patch text, including an add-file path that can traverse a pre-created dangling symlink alias."),
        "critical_operation": n("src/agents/apply-patch.ts", 149, 152, "For an add hunk, the resolved target is passed to fileOps.writeFile. If the dangling-symlink guard has accepted an outside alias, this sink creates or overwrites the file beyond the workspace boundary."),
        "trace": [
            n("src/agents/apply-patch.ts", 94, 106, "Patch text enters the apply_patch tool from the agent call."),
            n("src/agents/apply-patch.ts", 121, 125, "applyPatch parses attacker-controlled hunks and paths."),
            n("src/agents/apply-patch.ts", 149, 152, "An add hunk resolves its path and immediately uses the resulting target for directory creation and writing."),
            n("src/agents/sandbox-paths.ts", 60, 78, "assertSandboxPath performs lexical resolution and delegates alias checking to assertNoPathAliasEscape."),
            n("src/infra/boundary-path.ts", 150, 168, "When lstat encounters a missing path component, the resolver appends the missing suffix to the current canonical cursor and accepts it after a boundary assertion."),
            n("src/infra/boundary-path.ts", 487, 497, "For a dangling symlink, realpath fails and the fallback resolves the link target through its existing ancestor; this is the key fail-open alias-handling stage."),
            n("src/agents/apply-patch.ts", 149, 152, "fileOps.writeFile consumes the accepted alias target and realizes the out-of-workspace write."),
        ],
    },
    "entry-00320": {
        "repo": "langflow-ai__langflow", "url": "https://github.com/langflow-ai/langflow",
        "entry_point": n("src/backend/base/langflow/api/v2/files.py", 159, 166, "The v2 upload route reads the attacker-controlled multipart filename into new_filename and splits it without rejecting path separators or traversal components."),
        "critical_operation": n("src/backend/base/langflow/services/storage/local.py", 114, 121, "LocalStorageService joins the untrusted file_name to the user's folder and opens the resulting path for writing. OS path resolution interprets traversal segments here, producing an arbitrary file write."),
        "trace": [
            n("src/backend/base/langflow/api/v2/files.py", 159, 166, "Multipart file.filename enters naming logic and retains traversal components through rsplit."),
            n("src/backend/base/langflow/api/v2/files.py", 201, 220, "Uniqueness handling reconstructs unique_filename without sanitizing separators and passes it to save_file_routine."),
            n("src/backend/base/langflow/api/v2/files.py", 107, 125, "save_file_routine reads the upload and forwards file_name unchanged to storage_service.save_file."),
            n("src/backend/base/langflow/services/storage/local.py", 100, 121, "The local backend combines data_dir/flow_id with the untrusted filename and opens that path for append or overwrite."),
        ],
    },
    "entry-00391": {
        "repo": "PrefectHQ__fastmcp", "url": "https://github.com/PrefectHQ/fastmcp",
        "entry_point": n("src/fastmcp/utilities/openapi/director.py", 23, 28, "RequestDirector.build receives LLM-controlled flat_args together with the OpenAPI route and backend base URL. Path-parameter payloads enter request construction here."),
        "critical_operation": n("src/fastmcp/utilities/openapi/director.py", 208, 216, "_build_url substitutes path parameters with raw str values and passes the result to urljoin. Traversal or absolute-path syntax is interpreted during joining, allowing the request target to escape the intended backend path and enabling SSRF/path traversal."),
        "trace": [
            n("src/fastmcp/utilities/openapi/director.py", 23, 28, "LLM-provided flattened arguments enter request construction."),
            n("src/fastmcp/utilities/openapi/director.py", 44, 54, "build separates arguments by OpenAPI location and forwards path_params into _build_url."),
            n("src/fastmcp/utilities/openapi/director.py", 98, 115, "The parameter map copies attacker values into path_params without URL encoding."),
            n("src/fastmcp/utilities/openapi/director.py", 208, 213, "Raw string replacement injects each path parameter directly into the route template."),
            n("src/fastmcp/utilities/openapi/director.py", 215, 216, "urljoin normalizes the attacker-shaped URL path against the backend base URL, completing target escape."),
        ],
    },
}


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], text=True, encoding="utf-8", errors="replace", capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout


def ensure_repo(repo: Path, url: str) -> None:
    if not repo.exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(repo)], check=True)


def materialize(repo: Path, commit: str, spec: NodeSpec) -> dict:
    lines = git(repo, "show", f"{commit}:{spec.file}").splitlines()
    code = "\n".join(lines[spec.start - 1:spec.end])
    if not code or spec.end > len(lines):
        raise ValueError(f"invalid source range {spec.file}:{spec.start}-{spec.end}")
    line: int | str = spec.start if spec.start == spec.end else f"{spec.start}-{spec.end}"
    return {"file": spec.file, "line": line, "code": code, "desc": spec.desc}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/entries.jsonl"))
    parser.add_argument("--patch", type=Path, default=Path("data/entries.rebuilt_chains.jsonl"))
    parser.add_argument("--diff", type=Path, default=Path("reports/rebuild_fix_diff.csv"))
    parser.add_argument("--manual-review", type=Path, default=Path("reports/rebuild_manual_review.csv"))
    parser.add_argument("--cache-root", type=Path, default=Path(".cache/vulngym-location-fixer/repos"))
    args = parser.parse_args(argv)
    entries = {row["entry_id"]: row for row in map(json.loads, args.input.read_text(encoding="utf-8").splitlines())}
    patches, diffs = [], []
    for entry_id, spec in SPECS.items():
        original = entries[entry_id]
        repo = args.cache_root / spec["repo"]
        ensure_repo(repo, spec["url"])
        fixed = dict(original)
        for field in ("entry_point", "critical_operation"):
            fixed[field] = materialize(repo, original["commit"], spec[field])
            diffs.append({"entry_id": entry_id, "field": field, "old": json.dumps(original[field], ensure_ascii=False, sort_keys=True), "new": json.dumps(fixed[field], ensure_ascii=False, sort_keys=True), "reason": "rebuild source or sink semantics"})
        fixed["trace"] = [materialize(repo, original["commit"], node) for node in spec["trace"]]
        diffs.append({"entry_id": entry_id, "field": "trace", "old": json.dumps(original["trace"], ensure_ascii=False, sort_keys=True), "new": json.dumps(fixed["trace"], ensure_ascii=False, sort_keys=True), "reason": "rebuild essential multi-stage chain"})
        patches.append(fixed)
    args.patch.parent.mkdir(parents=True, exist_ok=True)
    args.patch.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in patches), encoding="utf-8")
    args.diff.parent.mkdir(parents=True, exist_ok=True)
    fields = ("entry_id", "field", "old", "new", "reason")
    with args.diff.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(diffs)
    with args.manual_review.open("w", encoding="utf-8-sig", newline="") as handle:
        csv.DictWriter(handle, fieldnames=("entry_id", "field", "blocker", "candidates")).writeheader()
    print(f"wrote {len(patches)} patches, {len(diffs)} diffs, 0 unresolved reviews")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
