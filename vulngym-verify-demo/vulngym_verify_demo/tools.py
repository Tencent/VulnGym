# -*- coding: utf-8 -*-
"""工具集：read_advisory / checkout / read_file_lines / grep_code / git_log。

所有工具都是纯本地（无网络），输入严格，输出严格 JSON。
被 Agent 调用，对应 VulnGym 题目要求的"至少 3 类工具"。

I2 升级：
  * 可选 manifest 参数：repo_url 通过 manifest 解析到唯一 project key，防 collision
  * 路径安全：用 Path.resolve().is_relative_to() 严格校验 cwd 与 file
  * 4 类失败（404 / 权限 / 坏 JSON / 坏 commit）全部 ToolResult(ok=false)，不抛异常
  * git_log 在 commit 不在 manifest 时返回 ok=false
  * 无网络：不 import requests/urllib/socket/http.client/aiohttp
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================
# 异常与 manifest 加载
# ============================================================


class UnknownProjectError(KeyError):
    """repo_url 不在 manifest 中，或 manifest 缺失/格式错。"""


def load_manifest(path: Path | str) -> Dict[str, Any]:
    """读取只读 snapshot manifest。

    manifest 仅描述 repo URL、project key、commit 和 fixture 文件；不得承载
    ``vulnerable``/``fixed`` 或版本范围等会替代公告、git 证据的结论。
    """
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"manifest not found: {fp}")
    with open(fp, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "items" not in data or not isinstance(data["items"], list):
        raise ValueError(f"manifest schema error: missing 'items' list in {fp}")
    required = {"repo_url", "project", "commit"}
    for it in data["items"]:
        if not required.issubset(it.keys()):
            raise ValueError(f"manifest item missing required fields: {it}")
        if {"role", "vulnerable", "fixed", "affected_versions", "fixed_in"} & set(it):
            raise ValueError("manifest must not contain vulnerability verdict or range fields")
        if not re.fullmatch(r"[0-9a-f]{40}", it["commit"]):
            raise ValueError(f"bad commit in manifest item: {it}")
    return data


def load_repo_catalog(path: Path | str) -> Dict[str, Any]:
    """Load an explicit mapping from canonical repo URLs to local git clones.

    The catalog is operational metadata, not vulnerability evidence. Its items
    contain exactly ``repo_url``, ``project`` and ``repo_path`` (plus optional
    descriptive fields); verdict/range keys are rejected to avoid leaking a
    precomputed answer into the verifier.
    """
    fp = Path(path)
    with fp.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("repo catalog schema error: missing 'items' list")
    seen_urls, seen_projects = set(), set()
    for item in items:
        if not isinstance(item, dict) or not {"repo_url", "project", "repo_path"}.issubset(item):
            raise ValueError("repo catalog item needs repo_url, project and repo_path")
        if {"role", "vulnerable", "fixed", "affected_versions", "fixed_in"} & set(item):
            raise ValueError("repo catalog must not contain vulnerability verdict or range fields")
        url = _canonical_repo_url(item["repo_url"])
        project = item["project"]
        if not url or not isinstance(project, str) or not project or url in seen_urls or project in seen_projects:
            raise ValueError("repo catalog repo_url and project must be unique")
        seen_urls.add(url)
        seen_projects.add(project)
    return data


def _canonical_repo_url(repo_url: str) -> str:
    """规范化 repo_url：
    - 去除尾部 '/' 和 '.git'
    - 保留 owner/name（不做大小写折叠——保持用户原值精确匹配）
    - 去掉 /tree/... 等附加 path（只取 owner/name）
    """
    u = (repo_url or "").strip().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    # 提取 owner/name
    parts = u.split("/")
    # 找到 github.com 后两段
    for i, seg in enumerate(parts):
        if seg in {"github.com", "gitlab.com", "bitbucket.org"} and i + 2 < len(parts):
            return "{}/{}/{}".format("/".join(parts[: i + 1]), parts[i + 1], parts[i + 2])
    # 兜底：取最后两段
    return "/".join(parts[-2:]) if len(parts) >= 2 else u


def normalize_project_from_repo(
    repo_url: str, manifest: Optional[Dict[str, Any]] = None,
) -> str:
    """repo_url -> project key。

    manifest 提供时严格按 repo_url 查 manifest 唯一映射（防 collision）。
    manifest=None 或空 items 时回退到 basename（兼容 I1 旧调用）。
    """
    if manifest and manifest.get("items"):
        key = _canonical_repo_url(repo_url)
        for entry in manifest["items"]:
            if _canonical_repo_url(entry["repo_url"]) == key:
                return entry["project"]
        raise UnknownProjectError(f"repo_url not in manifest: {repo_url!r}")
    # fallback（无 manifest 或空 manifest）
    return (
        repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        if repo_url else ""
    )


# ============================================================
# ToolResult 与 VulnGymTools
# ============================================================

#: 工具失败的**唯一权威**错误码枚举。
#:
#: ``schema.py`` 直接导入本常量，避免出现两份枚举漂移。任何 ``ok=False`` 的
#: ``ToolResult`` 都必须携带其中之一，否则报告层 ``validate_tool_call`` 会拒绝
#: 整条 ``tool_trace``，进而让整份 Agent 报告失效（P0-3 根因）。
TOOL_ERROR_CODES: frozenset = frozenset({
    "invalid_argument",        # 参数格式非法（commit / file / regex / report_id ...）
    "path_invalid",            # 路径逃逸、越界或不可解析
    "advisory_not_found",      # 公告文件不存在
    "advisory_invalid",        # 公告存在但不是合法 JSON / 结构损坏
    "repo_unavailable",        # 仓库未配置、目录不存在或 git 调用失败
    "commit_missing",          # 仓库可用但目标 commit 对象不存在
    "file_missing_at_commit",  # commit 可读但该路径的文件不存在
    "line_out_of_range",       # 请求起始行超出文件总行数
    "permission_denied",       # 文件系统拒绝访问
    "timeout",                 # git / IO 操作超时
    "tool_internal_error",     # 未预期异常（兜底，永远不应静默用于真实分支）
})

#: 关键词 → 错误码的**兜底**推断（仅用于第三方/stub 构造的 ToolResult 归一化）。
_ERROR_CODE_HINTS: tuple = (
    ("line range", "line_out_of_range"),
    ("out of range", "line_out_of_range"),
    ("not found at commit", "file_missing_at_commit"),
    ("file not found", "file_missing_at_commit"),
    ("commit not available", "commit_missing"),
    ("commit_missing", "commit_missing"),
    ("advisory not found", "advisory_not_found"),
    ("json decode", "advisory_invalid"),
    ("advisory", "advisory_invalid"),
    ("traversal", "path_invalid"),
    ("escape", "path_invalid"),
    ("outside", "path_invalid"),
    ("path invalid", "path_invalid"),
    ("bad ", "invalid_argument"),
    ("invalid", "invalid_argument"),
    ("unavailable", "repo_unavailable"),
    ("timeout", "timeout"),
    ("permission", "permission_denied"),
    ("denied", "permission_denied"),
)


def _infer_error_code(error: str) -> str:
    """从错误文本推断错误码，仅作为构造期不变量兜底。"""
    lowered = (error or "").lower()
    for needle, code in _ERROR_CODE_HINTS:
        if needle in lowered:
            return code
    return "tool_internal_error"


@dataclass
class ToolResult:
    """工具调用结果。

    强制不变量（构造期归一化，见 ``__post_init__``）：
      * ``ok=True``  → ``error`` 与 ``error_code`` 必须为空；
      * ``ok=False`` → ``error`` 非空 **且** ``error_code`` ∈ ``TOOL_ERROR_CODES``。
    """

    name: str
    ok: bool
    data: Any
    error: Optional[str] = None
    error_code: Optional[str] = None

    def __post_init__(self) -> None:
        if self.ok:
            self.error = None
            self.error_code = None
            return
        if not isinstance(self.error, str) or not self.error.strip():
            self.error = f"{self.name} failed without a diagnostic message"
        if self.error_code not in TOOL_ERROR_CODES:
            self.error_code = _infer_error_code(self.error)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "data": self.data,
            "error": self.error,
            "error_code": self.error_code,
        }


def ok_result(name: str, data: Any) -> ToolResult:
    """成功结果工厂（显式清空 error 字段）。"""
    return ToolResult(name, True, data, None, None)


def fail_result(name: str, error: str, error_code: str, data: Any = None) -> ToolResult:
    """失败结果工厂——**必须**提供合法 error_code。"""
    if error_code not in TOOL_ERROR_CODES:
        raise ValueError(f"unknown tool error code: {error_code!r}")
    return ToolResult(name, False, data, error, error_code)


# 合法 GHSA-id 格式：GHSA-xxxx-xxxx-xxxx（4 段字符）。简化用 [A-Z0-9-]+ 但禁止 . 和 ..
_GHSA_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]*$")
_HEX40 = re.compile(r"[0-9a-f]{40}")

#: 不透明仓库句柄：``repo:<owner>/<name>``。
#: 它由 :class:`RepositoryResolver` 签发，业务层不得自行拼装或 ``split('/')[-1]``。
REPO_HANDLE_RE = re.compile(r"^repo:([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)$")

#: 允许执行的**只读** Git 子命令白名单（唯一权威定义）。
READ_ONLY_GIT_SUBCOMMANDS: frozenset = frozenset({
    "cat-file", "show", "log", "tag", "rev-parse", "rev-list",
    "ls-tree", "for-each-ref", "branch", "describe", "shortlog",
})

#: 明确拒绝的写/网络子命令。
FORBIDDEN_GIT_SUBCOMMANDS: frozenset = frozenset({
    "checkout", "reset", "apply", "clone", "fetch", "pull", "push",
    "init", "config", "remote", "am", "rebase", "merge", "commit",
    "stash", "clean", "worktree", "submodule", "archive", "gc", "repack",
})


class VulnGymTools:
    """封装 demo 用到的全部工具。

    repo_cache_dir:  可选 snapshot 缓存根目录，格式为 <project>/<commit>/<file>
    advisory_dir:    本地公告缓存目录 (json per GHSA-id)
    manifest:        可选 snapshot manifest，启用 repo_url -> project 严格映射
    repo_catalog:    可选本地 git clone catalog；存在时是权威代码后端
    repo_resolver:   可选 :class:`RepositoryResolver`；存在时按规范化 repo_url
                     解析 bare Git 仓库，仓库身份唯一键是 URL 而不是 basename。
    """

    def __init__(
        self,
        repo_cache_dir: Path | str,
        advisory_dir: Path | str,
        manifest: Optional[Dict[str, Any]] = None,
        repo_catalog: Optional[Dict[str, Any]] = None,
        git_executable: str = "git",
        repo_resolver: Any = None,
    ) -> None:
        self.repo_cache_dir = Path(repo_cache_dir).resolve()
        self.advisory_dir = Path(advisory_dir).resolve()
        self.manifest = manifest
        self.repo_catalog = repo_catalog or {"items": []}
        self.git_executable = git_executable
        self.repo_resolver = repo_resolver
        #: 只读 Git 输出缓存（有界，见 ``_run_git``）。
        self._git_read_cache: Dict[Any, ToolResult] = {}
        self._git_read_cache_limit: int = 20000
        #: Git 子命令审计计数（用于"未执行写命令"的运行时证据）。
        self.git_subcommand_log: Dict[str, int] = {}

    # ---------- 仓库身份解析（P0-2） ----------
    def repo_handle(self, entry_or_url: Any) -> Optional[str]:
        """把 entry / repo_url 解析为不透明的仓库句柄 ``repo:<owner>/<name>``。

        返回 ``None`` 表示无法映射（此时调用方必须给出 ``repo_unavailable``，
        而不是用 basename 兜底造成同名仓库串仓）。业务层不得再调用
        ``split('/')[-1]`` 自行造键。
        """
        url = entry_or_url.get("repo_url") if isinstance(entry_or_url, dict) else entry_or_url
        if not isinstance(url, str) or not url.strip():
            return None
        if self.repo_resolver is not None:
            try:
                return self.repo_resolver.issue_handle(url)
            except Exception:
                return None
        # 无 resolver（旧 demo 路径）：manifest 严格映射，否则 basename 兼容。
        try:
            return normalize_project_from_repo(url, self.manifest)
        except UnknownProjectError:
            return None

    def _resolve_repo_path(self, project: str) -> tuple:
        """句柄/项目键 → ``(repo_path | None, error_code | None, error | None)``。"""
        if not project:
            return None, "repo_unavailable", "repository handle could not be resolved"
        if self.repo_resolver is not None and REPO_HANDLE_RE.match(project):
            try:
                return self.repo_resolver.resolve(project), None, None
            except Exception as exc:  # structured resolver failure
                code = getattr(exc, "code", None) or "repo_unavailable"
                return None, code, str(exc)
        return self._git_repo(project), None, None

    def _catalog_item(self, project: str) -> Optional[Dict[str, Any]]:
        for item in self.repo_catalog.get("items", []):
            if item.get("project") == project:
                return item
        return None

    def _git_repo(self, project: str) -> Optional[Path]:
        item = self._catalog_item(project)
        if item is None:
            return None
        try:
            path = Path(item["repo_path"]).resolve()
        except (OSError, TypeError, ValueError):
            return None
        return path if path.is_dir() else None

    def _run_git(self, repo: Path, args: List[str]) -> ToolResult:
        """Run a read-only git command without a shell or a working-tree mutation.

        纯读命令的结果按 ``(repo, args)`` 做有界缓存：同一条目内的 entry_point /
        critical_operation / trace 经常读取同一个 ``<commit>:<file>``，缓存把
        408 条全量运行从数千次子进程降到可接受量级。缓存只保存只读输出，不含
        任何判定结论。
        """
        cache_key = (str(repo), tuple(args))
        cached = self._git_read_cache.get(cache_key)
        if cached is not None:
            return cached
        subcommand = args[0] if args else ""
        if subcommand in FORBIDDEN_GIT_SUBCOMMANDS or subcommand not in READ_ONLY_GIT_SUBCOMMANDS:
            # 只读不变量：绝不 checkout / reset / fetch / 执行目标仓库脚本。
            return fail_result(
                "git",
                f"refused non read-only git subcommand: {subcommand or '<empty>'}",
                "tool_internal_error",
            )
        self.git_subcommand_log[subcommand] = self.git_subcommand_log.get(subcommand, 0) + 1
        try:
            completed = subprocess.run(
                [self.git_executable, "-C", str(repo), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return fail_result("git", "local git command timed out", "timeout")
        except OSError as exc:
            return fail_result(
                "git", f"local git invocation failed: {type(exc).__name__}",
                "tool_internal_error",
            )
        if completed.returncode:
            # stderr frequently includes an absolute clone path; do not expose it.
            detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "git returned non-zero"
            detail = detail.replace(str(repo), "<repo>")
            detail = re.sub(r"[A-Za-z]:[\\/][^\s\"']+", "<abspath>", detail)
            detail = re.sub(r"/(?:home|Users|var|tmp|opt|root)/[^\s\"']+", "<abspath>", detail)
            return fail_result("git", f"local git command failed: {detail[:180]}", "repo_unavailable")
        result = ok_result("git", completed.stdout)
        if len(self._git_read_cache) < self._git_read_cache_limit:
            self._git_read_cache[cache_key] = result
        return result

    @staticmethod
    def _virtual_cwd(project: str, commit: str) -> str:
        return f"git://{project}/{commit}"

    @staticmethod
    def _parse_virtual_cwd(cwd: str) -> Optional[tuple[str, str]]:
        """解析虚拟 cwd。

        支持两种形态，均以 40 位 commit 结尾：
          * ``git://<opaque-handle>/<sha>``（handle 形如 ``repo:owner/name``，含一个 ``/``）
          * ``git://<project>/<sha>``（旧 catalog project key）
        """
        text = cwd or ""
        match = re.fullmatch(
            r"git://(repo:[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)/([0-9a-f]{40})",
            text,
        )
        if match:
            return match.group(1), match.group(2)
        match = re.fullmatch(r"git://([^/]+)/([0-9a-f]{40})", text)
        return (match.group(1), match.group(2)) if match else None

    # ---------- 1. read_advisory ----------
    def read_advisory(self, report_id: str) -> ToolResult:
        # 格式校验：拒绝路径穿越字符
        if not isinstance(report_id, str) or not report_id or not _GHSA_ID_RE.fullmatch(report_id):
            return fail_result(
                "read_advisory", f"bad report_id format: {report_id!r}", "invalid_argument",
            )
        if "/" in report_id or "\\" in report_id or ".." in report_id:
            return fail_result(
                "read_advisory", f"path traversal in report_id: {report_id!r}", "invalid_argument",
            )
        fp = self.advisory_dir / f"{report_id}.json"
        # 防止逃逸到 advisory_dir 之外
        try:
            fp_resolved = fp.resolve()
        except OSError as exc:
            return fail_result(
                "read_advisory", f"advisory path invalid: {type(exc).__name__}", "path_invalid",
            )
        try:
            inside = fp_resolved.is_relative_to(self.advisory_dir)
        except (OSError, ValueError):
            inside = False
        if not inside:
            return fail_result(
                "read_advisory", "advisory path escapes the configured advisory directory",
                "path_invalid",
            )
        if not fp_resolved.exists():
            # 大小写不敏感回退：T1Data 的 report_id 为大写，缓存文件同名，这里只做
            # 一个不改变身份的兜底查找，不猜测、不合成路径。
            alt = self._advisory_case_insensitive_path(report_id)
            if alt is None:
                return fail_result(
                    "read_advisory", f"advisory not found: {report_id}", "advisory_not_found",
                )
            fp_resolved = alt
        try:
            with open(fp_resolved, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return fail_result(
                "read_advisory", f"advisory json decode failed: {type(e).__name__}",
                "advisory_invalid",
            )
        except PermissionError as e:
            return fail_result(
                "read_advisory", f"advisory permission denied: {type(e).__name__}",
                "permission_denied",
            )
        except OSError as e:
            return fail_result(
                "read_advisory", f"advisory read failed: {type(e).__name__}", "advisory_invalid",
            )
        if not isinstance(data, dict):
            return fail_result(
                "read_advisory", "advisory root is not a JSON object", "advisory_invalid",
            )
        return ok_result("read_advisory", data)

    def _advisory_case_insensitive_path(self, report_id: str) -> Optional[Path]:
        """在 advisory 目录中按大小写不敏感方式查找同名 JSON（只读、不猜造）。"""
        try:
            target = f"{report_id}.json".casefold()
            for candidate in self.advisory_dir.iterdir():
                if candidate.name.casefold() == target and candidate.is_file():
                    return candidate
        except OSError:
            return None
        return None

    # ---------- 2. checkout ----------
    def checkout(self, project: str, commit: str) -> ToolResult:
        if not _HEX40.fullmatch(commit or ""):
            return fail_result("checkout", f"bad commit format: {commit!r}", "invalid_argument")
        if not project:
            # repo_url 未能映射到唯一仓库：这是"证据不可用"，不是"参数非法"。
            # 仍然作为一次**真实的失败工具调用**返回，以便进入 tool_trace 审计。
            return fail_result(
                "checkout",
                "repository handle could not be resolved (repo_url is not mapped in this package)",
                "repo_unavailable",
            )
        if ".." in project:
            return fail_result("checkout", f"bad repo handle: {project!r}", "invalid_argument")
        is_handle = bool(REPO_HANDLE_RE.match(project))
        if not is_handle and ("/" in project or "\\" in project):
            return fail_result("checkout", f"bad project key: {project!r}", "invalid_argument")

        repo, resolve_code, resolve_error = self._resolve_repo_path(project)
        if resolve_code is not None:
            return fail_result("checkout", resolve_error or resolve_code, resolve_code)
        catalog_item = self._catalog_item(project) if not is_handle else None
        if (catalog_item is not None or is_handle) and repo is None:
            return fail_result(
                "checkout", "configured repository is unavailable", "repo_unavailable",
            )
        if repo is not None:
            result = self._run_git(repo, ["cat-file", "-e", f"{commit}^{{commit}}"])
            if not result.ok:
                return fail_result(
                    "checkout", "commit not available in local repository", "commit_missing",
                )
            return ok_result(
                "checkout",
                {"cwd": self._virtual_cwd(project, commit), "commit": commit, "backend": "git"},
            )
        # manifest 校验：(project, commit) 联合 key 必须存在
        if self.manifest and self.manifest.get("items"):
            declared = any(
                e["project"] == project and e["commit"] == commit
                for e in self.manifest["items"]
            )
            if not declared:
                return fail_result(
                    "checkout",
                    f"(project={project}, commit={commit[:7]}) not declared in manifest",
                    "repo_unavailable",
                )
        path = (self.repo_cache_dir / project / commit).resolve()
        # 严格校验路径在 repo_cache_dir 之内
        try:
            if not path.is_relative_to(self.repo_cache_dir):
                return fail_result(
                    "checkout", "checkout path escapes the snapshot cache root", "path_invalid",
                )
        except (OSError, ValueError):
            return fail_result("checkout", "checkout path is not resolvable", "path_invalid")
        if not path.exists() or not path.is_dir():
            # 注意语义区分（P0-3 + 保守判据）：
            #   * 真实 Git 后端已配置、且 commit 对象不在库中 → ``commit_missing``
            #     —— 这是"目标对象确实不存在"的强证据，可支撑 incorrect；
            #   * 目录型快照缓存缺少 <project>/<commit> → ``repo_unavailable``
            #     —— 这只说明"本地证据不可用"，不能证明上游不存在该 commit，
            #        因此必须落到 uncertain，而不是伪造反证。
            return fail_result(
                "checkout",
                "commit is not present in the local snapshot cache (evidence unavailable)",
                "repo_unavailable",
            )
        return ok_result(
            "checkout", {"cwd": str(path), "commit": commit, "backend": "snapshot"},
        )

    # ---------- 3. read_file_lines ----------
    def read_file_lines(self, cwd: str, file: str, start: int, end: int) -> ToolResult:
        if not isinstance(file, str) or not file or file.startswith("/") or "\\" in file \
                or ".." in file.split("/"):
            return fail_result("read_file_lines", f"bad file path: {file!r}", "invalid_argument")
        try:
            s, e = int(start), int(end)
        except (TypeError, ValueError):
            return fail_result("read_file_lines", "line range endpoints must be integers", "invalid_argument")
        if s < 1 or e < s:
            return fail_result("read_file_lines", "line range must satisfy 1 <= start <= end", "invalid_argument")

        virtual = self._parse_virtual_cwd(cwd)
        if virtual is not None:
            project, commit = virtual
            repo, resolve_code, resolve_error = self._resolve_repo_path(project)
            if resolve_code is not None:
                return fail_result("read_file_lines", resolve_error or resolve_code, resolve_code)
            if repo is None:
                return fail_result(
                    "read_file_lines", "local repository is unavailable", "repo_unavailable",
                )
            content = self._run_git(repo, ["show", f"{commit}:{file}"])
            if not content.ok:
                return fail_result(
                    "read_file_lines", "file not found at commit", "file_missing_at_commit",
                )
            lines = content.data.splitlines(keepends=True)
            if s > len(lines):
                return fail_result(
                    "read_file_lines",
                    f"line range starts beyond end of file: {s} > {len(lines)}",
                    "line_out_of_range",
                    {
                        "file": file,
                        "requested_start": s,
                        "requested_end": e,
                        "total_lines": len(lines),
                    },
                )
            end_clamped = min(len(lines), e)
            snippet = "".join(lines[s - 1 : end_clamped]) if s <= end_clamped else ""
            return ok_result(
                "read_file_lines",
                {"file": file, "start": s, "end": end_clamped, "snippet": snippet,
                 "total_lines": len(lines), "backend": "git", "commit": commit},
            )

        try:
            cwd_resolved = Path(cwd).resolve()
            file_path = (cwd_resolved / file).resolve()
        except (OSError, ValueError) as exc:
            return fail_result(
                "read_file_lines", f"path not resolvable: {type(exc).__name__}", "path_invalid",
            )
        # cwd 必须严格在 repo_cache_dir 之内
        try:
            if not cwd_resolved.is_relative_to(self.repo_cache_dir):
                return fail_result(
                    "read_file_lines", "cwd is outside the snapshot cache root", "path_invalid",
                )
        except (OSError, ValueError):
            return fail_result("read_file_lines", "cwd is not resolvable", "path_invalid")
        # file 必须仍在 cwd 之下
        try:
            if not file_path.is_relative_to(cwd_resolved):
                return fail_result(
                    "read_file_lines", "file path escapes the working directory", "path_invalid",
                )
        except (OSError, ValueError):
            return fail_result("read_file_lines", "file path is not resolvable", "path_invalid")
        if not file_path.exists():
            return fail_result(
                "read_file_lines", "file not found at commit", "file_missing_at_commit",
            )
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except PermissionError as exc:
            return fail_result(
                "read_file_lines", f"file permission denied: {type(exc).__name__}",
                "permission_denied",
            )
        except OSError as exc:
            return fail_result(
                "read_file_lines", f"file read failed: {type(exc).__name__}", "file_missing_at_commit",
            )
        clamped_end = min(len(lines), e)
        if s > clamped_end:
            return fail_result(
                "read_file_lines",
                f"line range starts beyond end of file: {s} > {len(lines)}",
                "line_out_of_range",
                {
                    "file": file,
                    "requested_start": s,
                    "requested_end": int(end),
                    "total_lines": len(lines),
                },
            )
        snippet = "".join(lines[s - 1 : clamped_end])
        return ok_result(
            "read_file_lines",
            {"file": file, "start": s, "end": clamped_end, "snippet": snippet, "total_lines": len(lines)},
        )

    # ---------- 4. grep_code ----------
    def grep_code(self, cwd: str, file: str, pattern: str) -> ToolResult:
        # 复用 read_file_lines 的安全检查
        rdl = self.read_file_lines(cwd, file, 1, 10**9)
        if not rdl.ok:
            # P0-3：必须**保留/映射底层错误码**，不能只复制错误文字（否则 error_code 丢失）。
            return ToolResult("grep_code", False, None, rdl.error, rdl.error_code)
        # 使用经过同一安全边界读取的完整内容；这同时支持 snapshot 与 git 虚拟 cwd。
        lines = rdl.data["snippet"].splitlines(keepends=True)
        try:
            rx = re.compile(pattern)
        except (re.error, TypeError) as exc:
            return fail_result(
                "grep_code", f"bad regex: {type(exc).__name__}", "invalid_argument",
            )
        hits = []
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                hits.append({"line": i, "text": line.rstrip("\n")})
        return ok_result("grep_code", {"file": file, "pattern": pattern, "hits": hits})

    # ---------- 5. git_log ----------
    def git_log(self, project: str, commit: str, limit: int = 5) -> ToolResult:
        if not _HEX40.fullmatch(commit or ""):
            return fail_result("git_log", f"bad commit format: {commit!r}", "invalid_argument")
        repo, resolve_code, resolve_error = self._resolve_repo_path(project)
        if resolve_code is not None:
            return fail_result("git_log", resolve_error or resolve_code, resolve_code)
        catalog_item = self._catalog_item(project) if not REPO_HANDLE_RE.match(project or "") else None
        if (catalog_item is not None or REPO_HANDLE_RE.match(project or "")) and repo is None:
            return fail_result("git_log", "configured repository is unavailable", "repo_unavailable")
        if repo is not None:
            cap = min(max(int(limit or 0), 1), 10)
            result = self._run_git(
                repo,
                ["log", "-n", str(cap), "--format=%H%x1f%ae%x1f%s", commit],
            )
            if not result.ok:
                return fail_result(
                    "git_log", "commit not available in local repository", "commit_missing",
                )
            entries = []
            for row in result.data.splitlines():
                sha, author, message = (row.split("\x1f", 2) + ["", "", ""])[:3]
                entries.append({"sha": sha, "author": author, "message": message})
            return ok_result("git_log", entries)
        # 必须 commit 在 manifest 或 (project, commit) 在缓存
        if self.manifest and self.manifest.get("items"):
            ok = any(
                e["project"] == project and e["commit"] == commit
                for e in self.manifest["items"]
            )
            if not ok:
                return fail_result(
                    "git_log",
                    f"(project={project}, commit={commit[:7]}) not declared",
                    "repo_unavailable",
                )
        entries = [
            {"sha": commit, "author": "alice@example.com",
             "message": f"introduce: {project} change at {commit[:7]}"},
            {"sha": "0" * 40, "author": "bob@example.com",
             "message": "previous: cleanups"},
            {"sha": "1" * 40, "author": "carol@example.com",
             "message": "earlier: refactor"},
            {"sha": "2" * 40, "author": "dave@example.com",
             "message": "earlier still: init"},
            {"sha": "3" * 40, "author": "eve@example.com",
             "message": "oldest: bootstrap"},
            {"sha": "4" * 40, "author": "frank@example.com",
             "message": "ancient: scaffold"},
        ]
        # limit 上限 10（防止内存滥用）
        cap = min(max(int(limit or 0), 1), 10)
        return ok_result("git_log", entries[:cap])

    def git_tags_at_commit(self, project: str, commit: str) -> ToolResult:
        """Return local version tags pointing exactly at ``commit``.

        Exact tags are deliberately used instead of heuristically inferring a
        version from surrounding history. A missing tag is evidence of an
        incomplete mapping and must lead to ``uncertain`` at the checker layer.
        """
        if not _HEX40.fullmatch(commit or ""):
            return fail_result(
                "git_tags_at_commit", f"bad commit format: {commit!r}", "invalid_argument",
            )
        repo, resolve_code, resolve_error = self._resolve_repo_path(project)
        if resolve_code is not None:
            return fail_result("git_tags_at_commit", resolve_error or resolve_code, resolve_code)
        if repo is None:
            return fail_result(
                "git_tags_at_commit", "local repository is unavailable", "repo_unavailable",
            )
        # ``git tag --points-at <sha>`` 对不存在的对象会以 0 退出并给出空输出，
        # 因此必须先用 cat-file 证明对象存在，否则"提交不存在"会被误报成"没有 tag"。
        exists = self._run_git(repo, ["cat-file", "-e", f"{commit}^{{commit}}"])
        if not exists.ok:
            return fail_result(
                "git_tags_at_commit", "commit not available in local repository", "commit_missing",
            )
        result = self._run_git(repo, ["tag", "--points-at", commit])
        if not result.ok:
            return fail_result(
                "git_tags_at_commit", "commit not available in local repository", "commit_missing",
            )
        return ok_result("git_tags_at_commit", [tag for tag in result.data.splitlines() if tag])

