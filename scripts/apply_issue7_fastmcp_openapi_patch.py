"""Apply and verify the Issue #7 FastMCP OpenAPI chain rebuild.

Only the two RequestDirector-backed entries are changed in canonical JSONL.
The sibling resource entries are documented in manual_review.csv because the
upstream security fix does not modify their implementation.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
DIFF_PATH = ROOT / "reports" / "issue-7-fastmcp-openapi.diff.csv"
TARGET_IDS = {"entry-00391", "entry-00394"}
VULNERABLE_COMMIT = "c861862aededc7294cea5634d77e6926444ca101"
FIX_COMMIT = "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71"
UPSTREAM_REPO = "PrefectHQ/fastmcp"
RAW_BASE = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}"


def node(file: str, line: int | str, code: str, desc: str) -> dict[str, Any]:
    return {"file": file, "line": line, "code": code, "desc": desc}


DIRECTOR_BUILD = node(
    "src/fastmcp/utilities/openapi/director.py",
    "23-28",
    "    def build(\n"
    "        self,\n"
    "        route: HTTPRoute,\n"
    "        flat_args: dict[str, Any],\n"
    "        base_url: str = \"http://localhost\",\n"
    "    ) -> httpx.Request:",
    "RequestDirector.build 接收 route、base_url 和扁平化参数 flat_args；"
    "path 参数从 MCP 工具调用在这里进入 FastMCP 的请求构造链，"
    "是外部可控值跨入后续参数映射与 URL 生成逻辑的真实入口。",
)

DIRECTOR_UNFLATTEN = node(
    "src/fastmcp/utilities/openapi/director.py",
    "44-47",
    "        # Step 1: Un-flatten arguments into path, query, body, etc. using parameter map\n"
    "        path_params, query_params, header_params, body = self._unflatten_arguments(\n"
    "            route, flat_args\n"
    "        )",
    "build 将 flat_args 交给 _unflatten_arguments，开始按 OpenAPI 参数位置拆分；"
    "此时路径参数仍保持调用方提供的原始字符串，尚未进行 URL 编码。",
)

DIRECTOR_PATH_MAP = node(
    "src/fastmcp/utilities/openapi/director.py",
    "114-115",
    "                if location == \"path\":\n"
    "                    path_params[openapi_name] = value",
    "_unflatten_arguments 将未编码的调用参数写入 path_params。"
    "这是从输入映射到 URL 模板替换的数据传播节点，而不是漏洞最终 sink。",
)

DIRECTOR_REPLACE = node(
    "src/fastmcp/utilities/openapi/director.py",
    "208-213",
    "        # Substitute path parameters\n"
    "        url_path = path_template\n"
    "        for param_name, param_value in path_params.items():\n"
    "            placeholder = f\"{{{param_name}}}\"\n"
    "            if placeholder in url_path:\n"
    "                url_path = url_path.replace(placeholder, str(param_value))",
    "漏洞根因在这里兑现：path 参数未经 quote 编码就以 str(param_value) "
    "直接替换进 URL 模板，攻击者提供的 ../、/、? 或 # 仍保留为 URL 语法。",
)

DIRECTOR_URLJOIN = node(
    "src/fastmcp/utilities/openapi/director.py",
    "215-216",
    "        # Combine with base URL\n"
    "        return urljoin(base_url.rstrip(\"/\") + \"/\", url_path.lstrip(\"/\"))",
    "urljoin 会把未编码路径中的 ../ 解释为目录折叠，令请求离开 OpenAPI "
    "路径前缀；它是直接替换造成 SSRF/路径穿越的紧邻兑现节点。",
)

DIRECTOR_REQUEST = node(
    "src/fastmcp/utilities/openapi/director.py",
    "71-73",
    "        return httpx.Request(\n"
    "            method=method,\n"
    "            url=url,",
    "构造出的越界 URL 被封装进 httpx.Request，随后交给调用方发送；"
    "该节点是影响向网络请求对象落地的末端传递点，不是根因本身。",
)

TOOL_RUN = node(
    "src/fastmcp/server/providers/openapi/components.py",
    179,
    "    async def run(self, arguments: dict[str, Any]) -> ToolResult:",
    "OpenAPITool.run 接收 MCP 工具调用提供的 arguments，是完整工具执行链中"
    "攻击者可控路径参数进入 HTTP 请求构造流程的外部入口。",
)

TOOL_BUILD = node(
    "src/fastmcp/server/providers/openapi/components.py",
    "183-185",
    "        try:\n"
    "            base_url = str(self._client.base_url) or \"http://localhost\"\n"
    "            request = self._director.build(self._route, arguments, base_url)",
    "run 将 arguments、路由和带认证上下文的客户端 base_url 交给 RequestDirector.build，"
    "把外部工具输入传入存在缺陷的 URL 构造器。",
)

TOOL_SEND = node(
    "src/fastmcp/server/providers/openapi/components.py",
    "203-210",
    "        # Send the request and process the response.\n"
    "        try:\n"
    "            logger.debug(\n"
    "                f\"run - sending request; headers: {_redact_headers(request.headers)}\"\n"
    "            )\n"
    "\n"
    "            response = await self._client.send(request)\n"
    "            response.raise_for_status()",
    "客户端最终发送包含越界 URL 的请求并沿用 provider 的认证上下文，"
    "SSRF/路径穿越影响在这里落地；日志只是相邻上下文，不被单独标为链路节点。",
)


UPDATES: dict[str, dict[str, Any]] = {
    "entry-00391": {
        "entry_point": DIRECTOR_BUILD,
        "critical_operation": DIRECTOR_REPLACE,
        "trace": [
            DIRECTOR_BUILD,
            DIRECTOR_UNFLATTEN,
            DIRECTOR_PATH_MAP,
            DIRECTOR_REPLACE,
            DIRECTOR_URLJOIN,
            DIRECTOR_REQUEST,
        ],
        "verify": 1,
    },
    "entry-00394": {
        "entry_point": TOOL_RUN,
        "critical_operation": DIRECTOR_REPLACE,
        "trace": [
            TOOL_RUN,
            TOOL_BUILD,
            DIRECTOR_BUILD,
            DIRECTOR_UNFLATTEN,
            DIRECTOR_PATH_MAP,
            DIRECTOR_REPLACE,
            DIRECTOR_URLJOIN,
            DIRECTOR_REQUEST,
            TOOL_SEND,
        ],
        "verify": 1,
    },
}


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "VulnGym-Issue-7-validator"})
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def _line_bounds(value: int | str) -> tuple[int, int]:
    if isinstance(value, int):
        return value, value
    if "-" not in value:
        line = int(value)
        return line, line
    start, end = value.split("-", 1)
    return int(start), int(end)


def _assert_exact_node(node_value: dict[str, Any], sources: dict[str, str]) -> None:
    path = node_value["file"]
    if path not in sources:
        sources[path] = _fetch_text(
            f"{RAW_BASE}/{VULNERABLE_COMMIT}/{path}"
        )
    start, end = _line_bounds(node_value["line"])
    actual = "\n".join(sources[path].splitlines()[start - 1 : end])
    if actual != node_value["code"]:
        raise RuntimeError(
            f"source mismatch for {path}:{node_value['line']}\n"
            f"expected: {node_value['code']!r}\n"
            f"actual:   {actual!r}"
        )


def check_upstream() -> None:
    """Validate every repaired node and the vulnerable-to-fix relationship."""
    entries: dict[str, dict[str, Any]] = {}
    with DATA_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record["entry_id"] in TARGET_IDS:
                entries[record["entry_id"]] = record

    if set(entries) != TARGET_IDS:
        missing = ", ".join(sorted(TARGET_IDS - set(entries)))
        raise RuntimeError(f"target entries missing from {DATA_PATH}: {missing}")

    sources: dict[str, str] = {}
    node_count = 0
    for entry_id in sorted(TARGET_IDS):
        record = entries[entry_id]
        if record["commit"] != VULNERABLE_COMMIT:
            raise RuntimeError(
                f"{entry_id} points to {record['commit']}, expected {VULNERABLE_COMMIT}"
            )
        if record["report_id"] != "GHSA-VV7Q-7JX5-F767":
            raise RuntimeError(f"{entry_id} has unexpected report_id")
        for node_value in [
            record["entry_point"],
            record["critical_operation"],
            *record["trace"],
        ]:
            _assert_exact_node(node_value, sources)
            node_count += 1

    commit_url = f"https://github.com/{UPSTREAM_REPO}/commit/{FIX_COMMIT}"
    commit_page = _fetch_text(commit_url)
    parent_link = f'/{UPSTREAM_REPO}/commit/{VULNERABLE_COMMIT}'
    if parent_link not in commit_page:
        raise RuntimeError("fix commit is not a direct child of the vulnerable commit")
    commit_diff = _fetch_text(f"{commit_url}.diff")
    director_path = "src/fastmcp/utilities/openapi/director.py"
    components_path = "src/fastmcp/server/providers/openapi/components.py"
    director_header = f"diff --git a/{director_path} b/{director_path}"
    if director_header not in commit_diff:
        raise RuntimeError("fix commit does not modify RequestDirector")
    if components_path in commit_diff:
        raise RuntimeError(
            "manual-review assumption changed: fix now includes components.py"
        )
    resource_candidate = (
        "                    for param_name, param_value in path_params.items():\n"
        "                        path = path.replace(f\"{{{param_name}}}\", str(param_value))"
    )
    actual_candidate = "\n".join(
        sources[components_path].splitlines()[306:308]
    )
    if actual_candidate != resource_candidate:
        raise RuntimeError("resource manual-review candidate no longer matches lines 307-308")

    vulnerable_director = sources[director_path]
    fixed_director = _fetch_text(f"{RAW_BASE}/{FIX_COMMIT}/{director_path}")
    vulnerable_replace = (
        "url_path = url_path.replace(placeholder, str(param_value))"
    )
    safe_replace = 'safe_value = quote(str(param_value), safe="").replace(".", "%2E")'
    if vulnerable_replace not in vulnerable_director:
        raise RuntimeError("vulnerable replacement is absent from pinned snapshot")
    if vulnerable_replace in fixed_director or safe_replace not in fixed_director:
        raise RuntimeError("fix commit does not replace the vulnerable operation as expected")

    print(
        f"upstream validation passed: {node_count} annotated node occurrences, "
        f"{len(sources)} source files, direct fix parent and patch semantics confirmed"
    )


def apply() -> None:
    raw_lines = DATA_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
    seen: set[str] = set()
    diff_rows: list[dict[str, str]] = []
    output: list[str] = []

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
        before = {
            "entry_point": record["entry_point"],
            "critical_operation": record["critical_operation"],
            "trace": record["trace"],
            "verify": record["verify"],
        }
        for field, value in UPDATES[entry_id].items():
            record[field] = value
        after = {
            "entry_point": record["entry_point"],
            "critical_operation": record["critical_operation"],
            "trace": record["trace"],
            "verify": record["verify"],
        }
        for field in before:
            if before[field] != after[field]:
                diff_rows.append(
                    {
                        "entry_id": entry_id,
                        "field": field,
                        "before": json.dumps(before[field], ensure_ascii=False, sort_keys=True),
                        "after": json.dumps(after[field], ensure_ascii=False, sort_keys=True),
                        "reason": {
                            "entry_point": "把入口锚定到外部 URI/flat_args 进入漏洞路径的位置",
                            "critical_operation": "把 critical 锚定到未编码参数直接替换进 URL 模板的实际缺陷点",
                            "trace": "删除函数声明/参数拆分等误导节点，保留输入、替换、规范化和请求传递阶段",
                            "verify": "脆弱提交逐节点匹配，且修复提交直接替换该缺陷操作",
                        }[field],
                    }
                )
        output.append(json.dumps(record, ensure_ascii=False) + "\n")

    if seen != TARGET_IDS:
        missing = ", ".join(sorted(TARGET_IDS - seen))
        raise RuntimeError(f"target entries missing from {DATA_PATH}: {missing}")

    DATA_PATH.write_text("".join(output), encoding="utf-8", newline="\n")
    DIFF_PATH.parent.mkdir(parents=True, exist_ok=True)
    if diff_rows or not DIFF_PATH.exists():
        with DIFF_PATH.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["entry_id", "field", "before", "after", "reason"],
            )
            writer.writeheader()
            writer.writerows(diff_rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="validate patched nodes and fix evidence against pinned upstream commits",
    )
    args = parser.parse_args()
    if args.check_upstream:
        check_upstream()
    else:
        apply()
