#!/usr/bin/env python3
"""Build source-backed configuration vulnerability patches for issue #8."""

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
    "entry-00241": {
        "entry_point": n("scripts/e2e/Dockerfile", 1, 1, "FROM starts the image configuration from node:22-bookworm, whose inherited default user is root. With no later USER instruction, this identity remains effective for build steps and the container command."),
        "critical_operation": n("scripts/e2e/Dockerfile", 19, 23, "Dependency installation, application builds, and the final bash command all remain under the inherited root identity because no USER instruction intervenes. A compromise therefore starts with uid 0 and amplifies container-breakout impact."),
        "trace": [
            n("scripts/e2e/Dockerfile", 1, 1, "The base image establishes root as the inherited effective user for this configuration stage."),
            n("scripts/e2e/Dockerfile", 19, 23, "The final build and runtime instructions execute without any user transition, demonstrating where the unsafe configuration takes effect."),
        ],
    },
    "entry-00242": {
        "entry_point": n("scripts/e2e/Dockerfile.qr-import", 1, 1, "The node:22-bookworm stage begins with root as its default effective user, and this Dockerfile never overrides it."),
        "critical_operation": n("scripts/e2e/Dockerfile.qr-import", 7, 9, "The entire build context is copied and pnpm install runs as root. Dependency lifecycle scripts therefore receive unnecessary root privilege, and any image derived from this stage also inherits root absent a USER directive."),
        "trace": [
            n("scripts/e2e/Dockerfile.qr-import", 1, 1, "Base-image user inheritance establishes the privileged configuration state."),
            n("scripts/e2e/Dockerfile.qr-import", 5, 9, "The application context and dependency installation execute under the unchanged root identity."),
        ],
    },
    "entry-00243": {
        "entry_point": n("scripts/docker/install-sh-e2e/Dockerfile", 1, 1, "The node:22-bookworm-slim base image supplies root as the default user for this test image."),
        "critical_operation": n("scripts/docker/install-sh-e2e/Dockerfile", 11, 14, "The launcher is installed and selected as ENTRYPOINT without a preceding USER transition. Every invocation of the test entrypoint consequently begins as root."),
        "trace": [
            n("scripts/docker/install-sh-e2e/Dockerfile", 1, 1, "The image stage inherits root from its base."),
            n("scripts/docker/install-sh-e2e/Dockerfile", 3, 9, "Package installation runs in the inherited privileged build context."),
            n("scripts/docker/install-sh-e2e/Dockerfile", 11, 14, "The executable is installed and becomes the runtime entrypoint while root remains effective."),
        ],
    },
    "entry-00244": {
        "entry_point": n("scripts/docker/install-sh-nonroot/Dockerfile", 1, 1, "The Ubuntu image starts configuration as root; later instructions create an app account intended to lower runtime privilege."),
        "critical_operation": n("scripts/docker/install-sh-nonroot/Dockerfile", 17, 18, "The app user is granted passwordless sudo for ALL commands. Although USER app is selected later, this sudoers rule lets any compromised process recover unrestricted root immediately, defeating the intended privilege boundary."),
        "trace": [
            n("scripts/docker/install-sh-nonroot/Dockerfile", 3, 15, "The privileged build stage installs sudo, making later privilege recovery available in the image."),
            n("scripts/docker/install-sh-nonroot/Dockerfile", 17, 18, "The configuration creates app and grants it unrestricted passwordless sudo."),
            n("scripts/docker/install-sh-nonroot/Dockerfile", 20, 20, "USER app changes the nominal runtime uid but does not remove the NOPASSWD sudo capability."),
            n("scripts/docker/install-sh-nonroot/Dockerfile", 26, 29, "The image already exercises sudo as app and then launches the test entrypoint with the same root-recoverable account."),
        ],
    },
}


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], text=True, encoding="utf-8", errors="replace", capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout


def ensure_repo(repo: Path) -> None:
    if not repo.exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", "https://github.com/openclaw/openclaw", str(repo)], check=True)


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
    parser.add_argument("--patch", type=Path, default=Path("data/entries.config_vuln_fixed.jsonl"))
    parser.add_argument("--diff", type=Path, default=Path("reports/config_vuln_fix_diff.csv"))
    parser.add_argument("--repo-cache", type=Path, default=Path(".cache/vulngym-location-fixer/repos/openclaw__openclaw"))
    args = parser.parse_args(argv)
    ensure_repo(args.repo_cache)
    entries = {row["entry_id"]: row for row in map(json.loads, args.input.read_text(encoding="utf-8").splitlines())}
    patches, diffs = [], []
    for entry_id, spec in SPECS.items():
        original = entries[entry_id]
        fixed = dict(original)
        for field in ("entry_point", "critical_operation"):
            fixed[field] = materialize(args.repo_cache, original["commit"], spec[field])
            diffs.append({"entry_id": entry_id, "field": field, "old": json.dumps(original[field], ensure_ascii=False, sort_keys=True), "new": json.dumps(fixed[field], ensure_ascii=False, sort_keys=True), "reason": "configuration-effective privilege annotation"})
        fixed["trace"] = [materialize(args.repo_cache, original["commit"], node) for node in spec["trace"]]
        diffs.append({"entry_id": entry_id, "field": "trace", "old": json.dumps(original["trace"], ensure_ascii=False, sort_keys=True), "new": json.dumps(fixed["trace"], ensure_ascii=False, sort_keys=True), "reason": "configuration declaration-to-effect sequence"})
        patches.append(fixed)
    args.patch.parent.mkdir(parents=True, exist_ok=True)
    args.patch.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in patches), encoding="utf-8")
    args.diff.parent.mkdir(parents=True, exist_ok=True)
    with args.diff.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("entry_id", "field", "old", "new", "reason")); writer.writeheader(); writer.writerows(diffs)
    print(f"wrote {len(patches)} patches and {len(diffs)} diff rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
