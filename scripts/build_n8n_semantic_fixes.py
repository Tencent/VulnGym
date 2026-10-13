#!/usr/bin/env python3
"""Build source-backed semantic annotation patches for issue #6."""

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


EXPRESSION = "packages/workflow/src/expression.ts"
SANDBOX = "packages/workflow/src/expression-sandboxing.ts"
EVALUATOR = "packages/workflow/src/expression-evaluator-proxy.ts"
EXTEND = "packages/@n8n/expression-runtime/src/extensions/extend.ts"
RESET = "packages/@n8n/expression-runtime/src/runtime/reset.ts"


SPECS: dict[str, dict[str, object]] = {
    "entry-00099": {
        "entry_point": n(EXPRESSION, 368, 393, "resolveSimpleParameterValue receives the workflow-controlled parameterValue, confirms it is an expression, and strips the leading equals sign. This is where attacker-authored expression source enters evaluation."),
        "critical_operation": n(EVALUATOR, 19, 20, "evaluateExpression passes the transformed attacker expression and workflow data to Tournament's bound execute method. In the vulnerable revision, WithStatement and reserved-variable shadowing are not rejected, so execution here turns the sanitizer gap into arbitrary code execution."),
        "trace": [
            n(EXPRESSION, 368, 393, "A workflow expression enters through parameterValue and is normalized for evaluation."),
            n(EXPRESSION, 451, 453, "The expression is syntax-extended and handed to renderExpression without rejecting with statements or reserved internal identifiers."),
            n(EVALUATOR, 9, 13, "Tournament is configured with ThisSanitizer before execution and PrototypeSanitizer/DollarSignValidator afterwards; the vulnerable hook set lacks the later WithStatement and reserved-variable guards."),
            n(EVALUATOR, 19, 20, "The evaluator executes the transformed expression with attacker-controlled syntax against the workflow data context."),
        ],
    },
    "entry-00100": {
        "entry_point": n(EXPRESSION, 368, 393, "The workflow-controlled parameterValue is accepted as expression source and enters the sandbox transformation pipeline."),
        "critical_operation": n(SANDBOX, 288, 299, "Dynamic member access is rewritten to call the sanitizer through dataNode. Because the vulnerable revision does not reserve the internal data-node identifier, attacker syntax can shadow that binding and redirect this generated call, bypassing property validation."),
        "trace": [
            n(EXPRESSION, 368, 393, "User-authored node expression text enters expression resolution."),
            n(EXPRESSION, 434, 438, "The host data object receives a non-writable sanitizer, but this does not prevent attacker syntax from shadowing the generated internal data-node binding."),
            n(SANDBOX, 264, 299, "PrototypeSanitizer handles computed member access and rewrites dynamic properties through dataNode.__sanitize; the unreserved dataNode name is the bypass boundary."),
            n(EVALUATOR, 19, 20, "Tournament executes the rewritten expression after the internal binding has been attacker-shadowed."),
        ],
    },
    "entry-00103": {
        "entry_point": n("packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts", 372, 400, "The Respond to Webhook node reads workflow-controlled options and copies responseHeaders names and values into the outgoing header map. A Content-Type value with leading whitespace enters the response path here."),
        "critical_operation": n("packages/cli/src/webhooks/webhook-request-handler.ts", 153, 158, "The handler derives needsSandbox from isHtmlRenderedContentType and conditionally installs the CSP sandbox header. A whitespace-prefixed HTML Content-Type is misclassified, makes needsSandbox false, and skips the protection at this decision point."),
        "trace": [
            n("packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts", 372, 400, "Workflow configuration supplies the attacker-controlled response header value."),
            n("packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts", 558, 565, "The response object carries the configured headers into sendResponse."),
            n("packages/cli/src/webhooks/webhook-request-handler.ts", 127, 136, "sendStaticResponse applies status and headers before sending the attacker-controlled response body."),
            n("packages/cli/src/webhooks/webhook-request-handler.ts", 146, 158, "setResponseHeaders writes the supplied Content-Type, reads it back, and uses the vulnerable classifier to decide whether to add CSP."),
            n("packages/core/src/html-sandbox.ts", 19, 25, "isHtmlRenderedContentType lowercases but does not trim its input, so leading whitespace defeats both HTML prefix checks."),
        ],
    },
    "entry-00176": {
        "entry_point": n("packages/nodes-base/nodes/Code/Code.node.ts", 206, 209, "The Python Code node reads attacker-authored code from the workflow parameter, creates a PythonTaskRunnerSandbox, and starts execution."),
        "critical_operation": n("packages/@n8n/task-runner-python/src/task_executor.py", 202, 213, "After compilation and restricted-globals construction, exec runs the attacker-authored Python bytecode. The missing __objclass__ attribute block allows the payload to recover powerful runtime objects before this sink executes it."),
        "trace": [
            n("packages/nodes-base/nodes/Code/Code.node.ts", 206, 209, "Workflow-controlled Python source enters the task-runner sandbox."),
            n("packages/nodes-base/nodes/Code/PythonTaskRunnerSandbox.ts", 62, 65, "The sandbox submits the Python source as a runner job."),
            n("packages/@n8n/task-runner-python/src/task_runner.py", 321, 329, "The runner validates task_settings.code and then creates the child process that will execute the same code."),
            n("packages/@n8n/task-runner-python/src/task_analyzer.py", 63, 69, "Attribute validation consults BLOCKED_ATTRIBUTES, but the vulnerable list omits __objclass__."),
            n("packages/@n8n/task-runner-python/src/task_executor.py", 202, 213, "The validated payload is compiled and executed with filtered builtins; __objclass__ bypasses the analyzer before reaching exec."),
        ],
    },
    "entry-00511": {
        "entry_point": n(EXPRESSION, 451, 465, "resolveSimpleParameterValue receives the user expression in parameterValue and removes its expression marker, establishing the attacker-controlled VM input."),
        "critical_operation": n(EXTEND, 132, 134, "The native fallback function is invoked with attacker-controlled args via Function.apply. When functionName is constructor, the earlier unchecked lookup returns Function itself and this call executes the supplied JavaScript source."),
        "trace": [
            n(EXPRESSION, 451, 465, "Attacker-controlled workflow expression text enters evaluation."),
            n(EXPRESSION, 484, 503, "extend is exposed to expressions while the regex only rejects literal dot-constructor syntax, not a constructor string passed to extend."),
            n(RESET, 165, 168, "The VM re-exposes extend on __data, making the helper reachable inside the isolated expression runtime."),
            n(EXTEND, 105, 106, "extend forwards the attacker-controlled functionName to findExtendedFunction without a property-name denylist."),
            n(EXTEND, 76, 85, "The native fallback reads inputAny[functionName]; constructor on a function resolves to the Function constructor."),
            n(EXTEND, 132, 134, "Function.apply invokes the recovered native constructor with attacker-controlled arguments, completing code execution."),
        ],
    },
    "entry-00512": {
        "entry_point": n(EXPRESSION, 451, 465, "The user-controlled workflow expression enters resolveSimpleParameterValue and is passed toward the VM evaluator."),
        "critical_operation": n(RESET, 41, 46, "VM reset creates a plain __data object and assigns __sanitize as a writable property. An expression can overwrite this security hook before computed member access calls it, turning a validation primitive into an attacker-controlled function."),
        "trace": [
            n(EXPRESSION, 451, 465, "Attacker-authored expression source enters the VM expression pipeline."),
            n(EXPRESSION, 524, 536, "renderExpression dispatches the expression and workflow data to the configured VM evaluator."),
            n(RESET, 41, 46, "The VM data context exposes __sanitize through an ordinary writable assignment rather than an immutable accessor."),
            n(SANDBOX, 493, 502, "Computed member accesses generated by PrototypeSanitizer call __sanitize through the data object, so overwriting that slot bypasses the property check."),
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
    if not (1 <= spec.start <= spec.end <= len(lines)):
        raise ValueError(f"invalid source range {spec.file}:{spec.start}-{spec.end}")
    code = "\n".join(lines[spec.start - 1:spec.end])
    line: int | str = spec.start if spec.start == spec.end else f"{spec.start}-{spec.end}"
    return {"file": spec.file, "line": line, "code": code, "desc": spec.desc}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/entries.jsonl"))
    parser.add_argument("--patch", type=Path, default=Path("data/entries.n8n_semantic_fixed.jsonl"))
    parser.add_argument("--diff", type=Path, default=Path("reports/n8n_semantic_fix_diff.csv"))
    parser.add_argument("--repo-cache", type=Path, default=Path(".cache/n8n-semantic/n8n"))
    args = parser.parse_args(argv)
    ensure_repo(args.repo_cache, "https://github.com/n8n-io/n8n")
    entries = {row["entry_id"]: row for row in map(json.loads, args.input.read_text(encoding="utf-8").splitlines())}
    patches, diffs = [], []
    for entry_id, spec in SPECS.items():
        original = entries[entry_id]
        fixed = dict(original)
        for field in ("entry_point", "critical_operation"):
            fixed[field] = materialize(args.repo_cache, original["commit"], spec[field])
            diffs.append({"entry_id": entry_id, "field": field, "old": json.dumps(original[field], ensure_ascii=False, sort_keys=True), "new": json.dumps(fixed[field], ensure_ascii=False, sort_keys=True), "reason": "semantic source/sink correction"})
        fixed["trace"] = [materialize(args.repo_cache, original["commit"], node) for node in spec["trace"]]
        diffs.append({"entry_id": entry_id, "field": "trace", "old": json.dumps(original["trace"], ensure_ascii=False, sort_keys=True), "new": json.dumps(fixed["trace"], ensure_ascii=False, sort_keys=True), "reason": "retain only essential source-backed propagation and control-flow nodes"})
        patches.append(fixed)
    args.patch.parent.mkdir(parents=True, exist_ok=True)
    args.patch.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in patches), encoding="utf-8")
    args.diff.parent.mkdir(parents=True, exist_ok=True)
    with args.diff.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("entry_id", "field", "old", "new", "reason"))
        writer.writeheader(); writer.writerows(diffs)
    print(f"wrote {len(patches)} patches and {len(diffs)} diff rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
