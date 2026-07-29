"""Apply and verify the Issue #7 multistage vulnerability-chain rebuild.

The five priority samples named by Issue #7 are rebuilt, and the directly
fix-backed FastMCP tool sibling is retained as an additional reconstruction.
Uncertain candidates remain explicitly unverified in manual_review.csv.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
DIFF_PATH = ROOT / "reports" / "issue-7-multistage-chains.diff.csv"
MANUAL_PATH = ROOT / "reports" / "issue-7-multistage-chains.manual_review.csv"
MANIFEST_PATH = ROOT / "reports" / "issue-7-multistage-chain-manifest.json"
TARGET_IDS = {
    "entry-00185",
    "entry-00197",
    "entry-00290",
    "entry-00320",
    "entry-00391",
    "entry-00394",
}
MANUAL_IDS = {"entry-00290", "entry-00392", "entry-00395"}
GITHUB_API = "https://api.github.com"

EVIDENCE: dict[str, dict[str, Any]] = {
    "entry-00185": {
        "repo": "n8n-io/n8n",
        "vulnerable": "538181cbe32a92616df5e00d7ffaf4d568557f4f",
        "fix": "e22acaab3dcb2004e5fe0bf9ef2db975bde61866",
        "report_id": "GHSA-X2MW-7J39-93XQ",
        "fix_paths": {
            "packages/@n8n/config/src/configs/security.config.ts",
            "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
        },
        "patch_markers": {
            "N8N_BLOCK_FILE_PATTERNS",
            "isFilePatternBlocked",
        },
        "advisory_requires_fix_reference": True,
    },
    "entry-00197": {
        "repo": "openclaw/openclaw",
        "vulnerable": "4320cde91d9574d65dd240f8b033463cc723d6a6",
        "fix": "c823a85302119044bc26763644c15fe35dd04f4a",
        "report_id": "GHSA-7XMQ-G46G-F8PV",
        "fix_paths": {
            "src/infra/fs-safe.ts",
            "src/infra/outbound/message-action-params.ts",
        },
        "patch_markers": {
            "createRootScopedReadFile",
            "readPathWithinRoot",
        },
        "advisory_requires_fix_reference": False,
    },
    "entry-00290": {
        "repo": "openclaw/openclaw",
        "vulnerable": "8b5ebff67ba16bb68e26a2a0a22ed9556800009d",
        "fix": "4fd29a35bb85a1898ebff518364c467058b50e14",
        "report_id": "GHSA-QCC4-P59M-P54M",
        "fix_paths": {
            "src/agents/apply-patch.test.ts",
            "src/infra/path-alias-guards.test.ts",
        },
        "patch_markers": {
            "broken final symlink",
            "Symlink escapes sandbox root",
        },
        "advisory_requires_fix_reference": True,
        "tests_only": True,
    },
    "entry-00320": {
        "repo": "langflow-ai/langflow",
        "vulnerable": "e8bbae8eeb8729abd650f07bfc55957cbdbc1636",
        "fix": "d50eda2a480ed55a92f794fdbb9e4da89f62e7c8",
        "report_id": "GHSA-G2J9-7RJ2-GM6C",
        "fix_paths": {
            "src/backend/base/langflow/api/v2/files.py",
            "src/backend/base/langflow/services/storage/local.py",
        },
        "patch_markers": {
            "dangerous_chars",
            "is_relative_to",
        },
        "advisory_requires_fix_reference": False,
    },
    "entry-00391": {
        "repo": "PrefectHQ/fastmcp",
        "vulnerable": "c861862aededc7294cea5634d77e6926444ca101",
        "fix": "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71",
        "report_id": "GHSA-VV7Q-7JX5-F767",
        "fix_paths": {"src/fastmcp/utilities/openapi/director.py"},
        "patch_markers": {
            'safe_value = quote(str(param_value), safe="").replace(".", "%2E")',
            "url_path.replace(placeholder, safe_value)",
        },
        "advisory_requires_fix_reference": True,
    },
    "entry-00394": {
        "repo": "PrefectHQ/fastmcp",
        "vulnerable": "c861862aededc7294cea5634d77e6926444ca101",
        "fix": "40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71",
        "report_id": "GHSA-VV7Q-7JX5-F767",
        "fix_paths": {"src/fastmcp/utilities/openapi/director.py"},
        "patch_markers": {
            'safe_value = quote(str(param_value), safe="").replace(".", "%2E")',
            "url_path.replace(placeholder, safe_value)",
        },
        "advisory_requires_fix_reference": True,
    },
}


def node(file: str, line: int | str, code: str, desc: str) -> dict[str, Any]:
    return {"file": file, "line": line, "code": code, "desc": desc}


N8N_INPUT = node(
    "packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts",
    70,
    "\t\t\tfileName = this.getNodeParameter('fileName', itemIndex) as string;",
    "ReadWriteFile 的 Write 操作从工作流参数读取攻击者可控的 fileName；"
    "这是目标路径进入写文件链路的真实输入点。",
)

N8N_FORWARD = node(
    "packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts",
    "96-100",
    "\t\t\tawait this.helpers.writeContentToFile(\n"
    "\t\t\t\tawait this.helpers.resolvePath(fileName),\n"
    "\t\t\t\tfileContent,\n"
    "\t\t\t\tflag,\n"
    "\t\t\t);",
    "节点将已解析的 fileName、攻击者控制的文件内容和写入标志交给 "
    "writeContentToFile，连接输入层与核心文件系统辅助函数。",
)

N8N_RESOLVE = node(
    "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
    41,
    "\t\treturn (await fsRealpath(path)) as ResolvedFilePath; // apply brand, since we know it's resolved now",
    "resolvePath 使用 fsRealpath 得到规范路径；该步骤只解析路径，并不会阻止 "
    ".git/config 目标。",
)

N8N_ALLOW = node(
    "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
    65,
    "\treturn false;",
    "isFilePathBlocked 在旧版本中落到 false，使 .git 目标未被现有策略拦截；"
    "直接修复随后在此判断之前加入默认 .git 正则阻断。",
)

N8N_WRITE = node(
    "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
    "128-132",
    "\t\treturn await fsWriteFile(resolvedFilePath, content, {\n"
    "\t\t\tencoding: 'binary',\n"
    "\t\t\tflag: (flag ?? 0) | constants.O_NOFOLLOW,\n"
    "\t\t});\n"
    "\t},",
    "fsWriteFile 把攻击者控制的内容写入已放行的 .git/config 路径，是本 entry "
    "可直接定位的落盘 sink；完整 RCE 还要求后续触发 Git 操作。",
)

OPENCLAW_TOCTOU_INPUT = node(
    "src/infra/outbound/message-action-params.ts",
    288,
    '    const raw = readStringParam(params.args, key, { trim: false });',
    "第一阶段从工具参数读取攻击者可控的媒体路径，路径在这里进入沙箱媒体处理。",
)

OPENCLAW_TOCTOU_VALIDATE = node(
    "src/infra/outbound/message-action-params.ts",
    296,
    "    const normalized = await resolveSandboxedMediaSource({ media: raw, sandboxRoot });",
    "路径在符号链接仍指向沙箱内部时完成解析与边界检查，形成 TOCTOU 的 check 阶段。",
)

OPENCLAW_TOCTOU_STORE = node(
    "src/infra/outbound/message-action-params.ts",
    298,
    "      params.args[key] = normalized;",
    "已验证的路径被保存供稍后使用；两阶段之间的文件系统状态可被改变，产生竞态窗口。",
)

OPENCLAW_TOCTOU_RELOAD = node(
    "src/infra/outbound/message-action-params.ts",
    338,
    '  const mediaHint = readStringParam(params.args, "media", { trim: false });',
    "第二阶段重新取得先前保存的媒体路径，开始附件 hydration 的实际读取流程。",
)

OPENCLAW_TOCTOU_HYDRATE = node(
    "src/infra/outbound/message-action-params.ts",
    "258-261",
    "    const media = await loadWebMedia(\n"
    "      mediaSource,\n"
    "      buildAttachmentMediaLoadOptions({ policy: params.mediaPolicy, maxBytes }),\n"
    "    );",
    "附件 hydration 将旧路径和沙箱加载选项传入 loadWebMedia；"
    "源码定义顺序与运行时调用顺序不同，因此该节点位于第二阶段。",
)

OPENCLAW_TOCTOU_OPTIONS = node(
    "src/infra/outbound/message-action-params.ts",
    "215-216",
    "      sandboxValidated: true,\n"
    "      readFile: (filePath: string) => fs.readFile(filePath),",
    "旧实现声明 sandboxValidated=true，同时提供不受 root 约束的 fs.readFile；"
    "直接修复将其替换为 root-scoped reader。",
)

OPENCLAW_TOCTOU_SKIP = node(
    "src/web/media.ts",
    "353-355",
    '  if (!(sandboxValidated || localRoots === "any")) {\n'
    "    await assertLocalMediaAllowed(mediaUrl, localRoots);\n"
    "  }",
    "sandboxValidated 使 use 阶段跳过新的本地根目录检查，错误地继续信任旧状态。",
)

OPENCLAW_TOCTOU_READ = node(
    "src/web/media.ts",
    360,
    "    data = await readFileOverride(mediaUrl);",
    "不受根目录约束的回调跟随已被重定向的符号链接并完成越界读取，是 TOCTOU 的 use-stage sink。",
)

PATCH_ENTRY = node(
    "src/agents/apply-patch.ts",
    94,
    "    execute: async (_toolCallId, args, signal) => {",
    "apply_patch 工具从调用方接收包含 hunk 路径的非可信补丁参数。",
)

PATCH_DISPATCH = node(
    "src/agents/apply-patch.ts",
    "106-111",
    "      const result = await applyPatch(input, {\n"
    "        cwd,\n"
    "        sandbox,\n"
    "        workspaceOnly,\n"
    "        signal,\n"
    "      });",
    "execute 将补丁输入和沙箱策略传入 applyPatch。",
)

PATCH_RESOLVE = node(
    "src/agents/apply-patch.ts",
    150,
    "      const target = await resolvePatchPath(hunk.path, options);",
    "新增文件 hunk 的目标路径经 resolvePatchPath 解析并进入边界校验。",
)

PATCH_ASSERT = node(
    "src/agents/sandbox-paths.ts",
    "72-77",
    "  await assertNoPathAliasEscape({\n"
    "    absolutePath: resolved.resolved,\n"
    "    rootPath: params.root,\n"
    '    boundaryLabel: "sandbox root",\n'
    "    policy,\n"
    "  });",
    "解析后的目标进入符号链接与硬链接别名边界检查。",
)

PATCH_GUARD = node(
    "src/infra/boundary-path.ts",
    "196-197",
    "    const linkCanonical = await resolveSymlinkHopPath(lexicalCursor);\n"
    "    if (!isPathInside(params.rootCanonicalPath, linkCanonical)) {",
    "争议 guard 会规范化符号链接 hop 并检查是否仍在根目录内；"
    "记录快照看起来 fail-closed，而官方修复提交只改测试。",
)

PATCH_WRITE = node(
    "src/agents/apply-patch.ts",
    152,
    "      await fileOps.writeFile(target.resolved, hunk.contents);",
    "候选影响 sink：只有在更早的边界 guard 确实可绕过时，该写入才会落到沙箱外；"
    "现有提交证据不足，因此保留 verify=0。",
)

LANGFLOW_INPUT = node(
    "src/backend/base/langflow/api/v2/files.py",
    162,
    "        new_filename = file.filename",
    "v2 上传接口把 multipart Content-Disposition 中的非可信 filename 直接复制到 "
    "new_filename；直接修复在这里加入拒绝路径分隔符、.. 和控制字符的校验。",
)

LANGFLOW_SPLIT = node(
    "src/backend/base/langflow/api/v2/files.py",
    "163-166",
    '        try:\n'
    '            root_filename, file_extension = new_filename.rsplit(".", 1)\n'
    "        except ValueError:\n"
    '            root_filename, file_extension = new_filename, ""',
    "文件名被拆为主名和扩展名，但目录穿越片段仍保留在 root_filename 中。",
)

LANGFLOW_DEDUP = node(
    "src/backend/base/langflow/api/v2/files.py",
    "205-214",
    "                for my_file in files:\n"
    '                    match = re.search(r"\\((\\d+)\\)(?=\\.\\w+$|$)", my_file.name)\n'
    "                    if match:\n"
    "                        counts.append(int(match.group(1)))\n"
    "\n"
    "                count = max(counts) if counts else 0\n"
    '                root_filename = f"{root_filename} ({count + 1})"\n'
    "\n"
    "            # Create the unique filename with extension for storage\n"
    '            unique_filename = f"{root_filename}.{file_extension}" if file_extension else root_filename',
    "去重逻辑重建 unique_filename，但没有规范化或拒绝仍在其中的路径穿越片段。",
)

LANGFLOW_SAVE = node(
    "src/backend/base/langflow/api/v2/files.py",
    "218-220",
    "            file_id, stored_file_name = await save_file_routine(\n"
    "                file, storage_service, current_user, file_name=unique_filename, append=append\n"
    "            )",
    "路由把保留穿越片段的 unique_filename 交给存储服务。",
)

LANGFLOW_JOIN = node(
    "src/backend/base/langflow/services/storage/local.py",
    116,
    "        file_path = folder_path / file_name",
    "LocalStorageService 直接拼接 folder_path 与非可信 file_name；"
    "旧版本没有 resolve 后的目录包含关系校验。",
)

LANGFLOW_WRITE = node(
    "src/backend/base/langflow/services/storage/local.py",
    120,
    "            async with async_open(str(file_path), mode) as f:",
    "async_open 打开拼接后的路径，文件系统解析穿越片段并产生任意文件写入；"
    "直接修复在此 sink 之前加入双层路径约束。",
)

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
    "entry-00185": {
        "entry_point": N8N_INPUT,
        "critical_operation": N8N_WRITE,
        "trace": [
            N8N_INPUT,
            N8N_FORWARD,
            N8N_RESOLVE,
            N8N_ALLOW,
            N8N_WRITE,
        ],
        "verify": 1,
    },
    "entry-00197": {
        "entry_point": OPENCLAW_TOCTOU_INPUT,
        "critical_operation": OPENCLAW_TOCTOU_READ,
        "trace": [
            OPENCLAW_TOCTOU_INPUT,
            OPENCLAW_TOCTOU_VALIDATE,
            OPENCLAW_TOCTOU_STORE,
            OPENCLAW_TOCTOU_RELOAD,
            OPENCLAW_TOCTOU_HYDRATE,
            OPENCLAW_TOCTOU_OPTIONS,
            OPENCLAW_TOCTOU_SKIP,
            OPENCLAW_TOCTOU_READ,
        ],
        "verify": 1,
    },
    "entry-00290": {
        "entry_point": PATCH_ENTRY,
        "critical_operation": PATCH_WRITE,
        "trace": [
            PATCH_ENTRY,
            PATCH_DISPATCH,
            PATCH_RESOLVE,
            PATCH_ASSERT,
            PATCH_GUARD,
            PATCH_WRITE,
        ],
        "verify": 0,
    },
    "entry-00320": {
        "entry_point": LANGFLOW_INPUT,
        "critical_operation": LANGFLOW_WRITE,
        "trace": [
            LANGFLOW_INPUT,
            LANGFLOW_SPLIT,
            LANGFLOW_DEDUP,
            LANGFLOW_SAVE,
            LANGFLOW_JOIN,
            LANGFLOW_WRITE,
        ],
        "verify": 1,
    },
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

MANUAL_REVIEW_ROWS = [
    {
        "entry_id": "entry-00290",
        "current_status": "candidate chain rebuilt; verify=0",
        "blocker": (
            "The advisory names fix 4fd29a35, but that direct child modifies "
            "only two test files. The recorded vulnerable snapshot already "
            "canonicalizes each symlink hop and appears fail-closed."
        ),
        "source_evidence": (
            "apply-patch.ts reaches fileOps.writeFile through resolvePatchPath; "
            "boundary-path.ts:196-197 checks the canonical hop against the root."
        ),
        "fix_evidence": (
            "Fix 4fd29a35 is a direct child of 8b5ebff but changes only "
            "src/agents/apply-patch.test.ts and "
            "src/infra/path-alias-guards.test.ts."
        ),
        "candidate_action": (
            "Retain the rebuilt candidate chain and verify=0 until the "
            "maintainer identifies the production-code snapshot that contains "
            "the documented dangling-symlink gap."
        ),
    },
    {
        "entry_id": "entry-00392",
        "current_status": "canonical record retained",
        "blocker": (
            "The resource URI is split before path substitution; no upstream "
            "regression test demonstrates that traversal syntax survives this "
            "parsing and the client's base-URL resolution."
        ),
        "source_evidence": (
            "components.py:286-320 contains OpenAPIResource.read, "
            "path-parameter extraction, unencoded path.replace, and "
            "AsyncClient.request."
        ),
        "fix_evidence": (
            "Fix 40bdfb6 changes only director.py and test_director.py; "
            "components.py is untouched."
        ),
        "candidate_action": (
            "Build a resource-path reproduction at c861862. If it escapes the "
            "configured API prefix, retain lines 307-308 as critical and add "
            "lines 318-320 as the impact node; otherwise decouple this entry "
            "from the advisory."
        ),
    },
    {
        "entry_id": "entry-00395",
        "current_status": "canonical record retained",
        "blocker": (
            "The current critical node at components.py:294 only splits the "
            "URI and is not itself dangerous, but moving it without an exploit "
            "reproduction would force an unproven resource-path chain."
        ),
        "source_evidence": (
            "components.py:294-308 shows URI splitting followed by an "
            "unencoded path.replace candidate at lines 307-308."
        ),
        "fix_evidence": (
            "Fix 40bdfb6 neither changes components.py nor adds "
            "OpenAPIResource tests."
        ),
        "candidate_action": (
            "Reproduce create_resource -> read -> request at c861862. If "
            "confirmed, move critical_operation to lines 307-308 and extend "
            "the trace through lines 318-320; otherwise leave the candidate "
            "in manual review."
        ),
    },
]

ADVISORY_MARKERS = {
    "GHSA-X2MW-7J39-93XQ": (
        "Read/Write Files from Disk",
        "git operations",
    ),
    "GHSA-7XMQ-G46G-F8PV": (
        "time-of-check/time-of-use",
        "symlink retarget",
    ),
    "GHSA-QCC4-P59M-P54M": (
        "dangling symlink",
        "fails closed",
    ),
    "GHSA-G2J9-7RJ2-GM6C": (
        "new_filename = file.filename",
        "file_path = folder_path / file_name",
    ),
    "GHSA-VV7Q-7JX5-F767": (
        "path parameters",
        "SSRF",
    ),
}


def _fetch_text(url: str) -> str:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VulnGym-Issue-7-validator",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(GITHUB_API):
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def _fetch_json(url: str) -> dict[str, Any]:
    return json.loads(_fetch_text(url))


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _line_bounds(value: int | str) -> tuple[int, int]:
    if isinstance(value, int):
        return value, value
    if "-" not in value:
        line = int(value)
        return line, line
    start, end = value.split("-", 1)
    return int(start), int(end)


def _assert_exact_node(
    entry_id: str,
    node_value: dict[str, Any],
    sources: dict[tuple[str, str, str], str],
) -> None:
    evidence = EVIDENCE[entry_id]
    path = node_value["file"]
    source_key = (evidence["repo"], evidence["vulnerable"], path)
    if source_key not in sources:
        sources[source_key] = _fetch_text(
            "https://raw.githubusercontent.com/"
            f"{evidence['repo']}/{evidence['vulnerable']}/{path}"
        )
    start, end = _line_bounds(node_value["line"])
    actual = "\n".join(
        sources[source_key].splitlines()[start - 1 : end]
    )
    if actual != node_value["code"]:
        raise RuntimeError(
            f"source mismatch for {entry_id} {path}:{node_value['line']}\n"
            f"expected: {node_value['code']!r}\n"
            f"actual:   {actual!r}"
        )


def _validate_fix_evidence(evidence: dict[str, Any]) -> None:
    repo = evidence["repo"]
    vulnerable = evidence["vulnerable"]
    fix = evidence["fix"]
    commit = _fetch_json(f"{GITHUB_API}/repos/{repo}/commits/{fix}")
    parents = [parent["sha"] for parent in commit["parents"]]
    if parents != [vulnerable]:
        raise RuntimeError(
            f"{repo}@{fix} parents {parents}, expected direct parent {vulnerable}"
        )

    files = commit.get("files", [])
    changed_paths = {file["filename"] for file in files}
    if not evidence["fix_paths"] <= changed_paths:
        raise RuntimeError(
            f"{repo}@{fix} lacks expected fix paths: "
            f"{sorted(evidence['fix_paths'] - changed_paths)}"
        )
    patch_text = "\n".join(file.get("patch") or "" for file in files)
    for marker in evidence["patch_markers"]:
        if marker.lower() not in patch_text.lower():
            raise RuntimeError(
                f"{repo}@{fix} lacks patch marker {marker!r}"
            )
    if evidence.get("tests_only") and any(
        not (
            path.endswith(".test.ts")
            or "/__tests__/" in path
            or path.startswith("tests/")
        )
        for path in changed_paths
    ):
        raise RuntimeError(
            f"{repo}@{fix} is no longer test-only; re-review entry-00290"
        )

    advisory = _fetch_json(
        f"{GITHUB_API}/advisories/{evidence['report_id']}"
    )
    if advisory["ghsa_id"].upper() != evidence["report_id"]:
        raise RuntimeError(
            f"{evidence['report_id']} advisory identity mismatch"
        )
    if not advisory["source_code_location"].endswith(repo):
        raise RuntimeError(
            f"{evidence['report_id']} source repository mismatch"
        )
    advisory_text = (
        advisory.get("summary", "")
        + "\n"
        + advisory.get("description", "")
    )
    for marker in ADVISORY_MARKERS[evidence["report_id"]]:
        if marker.lower() not in advisory_text.lower():
            raise RuntimeError(
                f"{evidence['report_id']} lacks advisory marker {marker!r}"
            )
    if evidence["advisory_requires_fix_reference"]:
        expected_reference = f"https://github.com/{repo}/commit/{fix}"
        if expected_reference not in advisory.get("references", []):
            raise RuntimeError(
                f"{evidence['report_id']} does not reference fix {fix}"
            )


def check_upstream() -> None:
    """Validate every repaired node, advisory, and direct fix relationship."""
    entries: dict[str, dict[str, Any]] = {}
    with DATA_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record["entry_id"] in TARGET_IDS:
                entries[record["entry_id"]] = record

    if set(entries) != TARGET_IDS:
        missing = ", ".join(sorted(TARGET_IDS - set(entries)))
        raise RuntimeError(f"target entries missing from {DATA_PATH}: {missing}")

    sources: dict[tuple[str, str, str], str] = {}
    node_count = 0
    for entry_id in sorted(TARGET_IDS):
        record = entries[entry_id]
        evidence = EVIDENCE[entry_id]
        if record["commit"] != evidence["vulnerable"]:
            raise RuntimeError(
                f"{entry_id} points to {record['commit']}, "
                f"expected {evidence['vulnerable']}"
            )
        if record["report_id"] != evidence["report_id"]:
            raise RuntimeError(f"{entry_id} has unexpected report_id")
        for node_value in [
            record["entry_point"],
            record["critical_operation"],
            *record["trace"],
        ]:
            _assert_exact_node(entry_id, node_value, sources)
            node_count += 1

    unique_evidence: dict[tuple[str, str], dict[str, Any]] = {}
    for evidence in EVIDENCE.values():
        unique_evidence[(evidence["repo"], evidence["fix"])] = evidence
    for evidence in unique_evidence.values():
        _validate_fix_evidence(evidence)

    fastmcp = EVIDENCE["entry-00391"]
    components_path = "src/fastmcp/server/providers/openapi/components.py"
    fastmcp_commit = _fetch_json(
        f"{GITHUB_API}/repos/{fastmcp['repo']}/commits/{fastmcp['fix']}"
    )
    if components_path in {
        file["filename"] for file in fastmcp_commit.get("files", [])
    }:
        raise RuntimeError(
            "manual-review assumption changed: fix now includes components.py"
        )
    components_key = (
        fastmcp["repo"],
        fastmcp["vulnerable"],
        components_path,
    )
    if components_key not in sources:
        sources[components_key] = _fetch_text(
            "https://raw.githubusercontent.com/"
            f"{fastmcp['repo']}/{fastmcp['vulnerable']}/{components_path}"
        )
    resource_candidate = (
        "                    for param_name, param_value in path_params.items():\n"
        "                        path = path.replace(f\"{{{param_name}}}\", str(param_value))"
    )
    actual_candidate = "\n".join(
        sources[components_key].splitlines()[306:308]
    )
    if actual_candidate != resource_candidate:
        raise RuntimeError(
            "resource manual-review candidate no longer matches lines 307-308"
        )

    print(
        f"upstream validation passed: {node_count} annotated node occurrences, "
        f"{len(sources)} pinned source files, "
        f"{len(unique_evidence)} advisories/direct fixes confirmed"
    )


def _change_reason(entry_id: str, field: str) -> str:
    if entry_id == "entry-00290":
        return {
            "entry_point": "保留工具调用输入边界",
            "critical_operation": "把 critical 移到候选文件写入影响点，但维持 verify=0",
            "trace": "按输入、路径解析、别名 guard 和候选写入重建，明确证据阻塞点",
            "verify": "官方修复只改测试，不能据此提升置信度",
        }[field]
    return {
        "entry_point": "把入口移到攻击者可控输入首次进入漏洞链的位置",
        "critical_operation": "把 critical 移到直接修复支持的根因或最终危险操作",
        "trace": "按运行时数据流重建多阶段链路并删除无关声明、日志或返回值",
        "verify": "每个节点逐字匹配固定脆弱提交，且直接子修复提交消除所选缺陷",
    }[field]


def apply() -> None:
    raw_lines = DATA_PATH.read_text(encoding="utf-8").splitlines(
        keepends=True
    )
    seen: set[str] = set()
    existing_rows: dict[tuple[str, str], dict[str, str]] = {}
    if DIFF_PATH.exists():
        with DIFF_PATH.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["entry_id"] in TARGET_IDS:
                    existing_rows[(row["entry_id"], row["field"])] = row
    diff_rows: dict[tuple[str, str], dict[str, str]] = dict(existing_rows)
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
            key = (entry_id, field)
            if before[field] == after[field] and key not in diff_rows:
                continue
            previous = diff_rows.get(key)
            diff_rows[key] = {
                "entry_id": entry_id,
                "field": field,
                "before": (
                    previous["before"]
                    if previous
                    else json.dumps(
                        before[field],
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                ),
                "after": json.dumps(
                    after[field],
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "reason": _change_reason(entry_id, field),
            }
        output.append(json.dumps(record, ensure_ascii=False) + "\n")

    if seen != TARGET_IDS:
        missing = ", ".join(sorted(TARGET_IDS - seen))
        raise RuntimeError(f"target entries missing from {DATA_PATH}: {missing}")

    DATA_PATH.write_text("".join(output), encoding="utf-8", newline="\n")
    DIFF_PATH.parent.mkdir(parents=True, exist_ok=True)
    field_order = {
        "entry_point": 0,
        "critical_operation": 1,
        "trace": 2,
        "verify": 3,
    }
    with DIFF_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["entry_id", "field", "before", "after", "reason"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            sorted(
                diff_rows.values(),
                key=lambda row: (
                    row["entry_id"],
                    field_order[row["field"]],
                ),
            )
        )
    with MANUAL_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "entry_id",
                "current_status",
                "blocker",
                "source_evidence",
                "fix_evidence",
                "candidate_action",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(MANUAL_REVIEW_ROWS)

    target_entries = {
        record["entry_id"]: record
        for record in (
            json.loads(line)
            for line in DATA_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
        if record["entry_id"] in TARGET_IDS
    }
    manifest = {
        "schema_version": 1,
        "dataset_sha256": _file_sha256(DATA_PATH),
        "diff_sha256": _file_sha256(DIFF_PATH),
        "manual_review_sha256": _file_sha256(MANUAL_PATH),
        "target_ids": sorted(TARGET_IDS),
        "manual_review_ids": sorted(MANUAL_IDS),
        "verified_target_ids": sorted(
            entry_id
            for entry_id, record in target_entries.items()
            if record["verify"] == 1
        ),
        "node_occurrences": sum(
            2 + len(record["trace"]) for record in target_entries.values()
        ),
        "diff_rows": len(diff_rows),
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


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
