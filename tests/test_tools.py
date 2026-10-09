# -*- coding: utf-8 -*-
"""I2 — VulnGymTools 测试套件。

覆盖 ISSUE_OUTLINE.md §5 I2 验收条款：
  * mock 仓库目录与 manifest 对齐
  * repo_url -> project 唯一映射（防 collision）
  * 4 类失败（404、坏 JSON、坏 commit、路径穿越）返回 ToolResult(ok=false)
  * 无网络运行
  * manifest/catalog 不携带漏洞角色或版本范围结论
  * 并发只读安全
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List

import pytest

# 保证可以 import vulngym_verify_demo
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo.tools import (  # noqa: E402
    ToolResult,
    UnknownProjectError,
    VulnGymTools,
    load_repo_catalog,
    normalize_project_from_repo,
    load_manifest,
)


# ============================================================
# Fixtures
# ============================================================

MOCK_REPO_ROOT = ROOT / "vulngym-verify-demo" / "mock_repo"
MANIFEST_PATH = MOCK_REPO_ROOT / "manifest.json"


@pytest.fixture(scope="module")
def manifest() -> Dict[str, Any]:
    """manifest.json 加载结果。"""
    assert MANIFEST_PATH.exists(), f"manifest not found: {MANIFEST_PATH}"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def tmp_workspace(tmp_path: Path, manifest: Dict[str, Any]):
    """构造独立的 repo_cache_dir + advisory_dir，复制 mock_repo 内容。"""
    repo_cache = tmp_path / "repo_cache"
    advisory_dir = tmp_path / "advisories"
    repo_cache.mkdir()
    advisory_dir.mkdir()

    # 把 manifest 中声明的 (project, commit, file) 全部镜像到 tmp
    for item in manifest["items"]:
        p = repo_cache / item["project"] / item["commit"] / item["file"]
        p.parent.mkdir(parents=True, exist_ok=True)
        header = "// mock file: {} @ {}\n".format(item["file"], item["commit"])
        p.write_text(header, encoding="utf-8")
        # 追加每个 target line（line 2 起步，保证 read_file_lines 命中）
        with p.open("a", encoding="utf-8") as fp:
            for i, target in enumerate(item["targets"], 1):
                fp.write("// padding line {}\n".format(i))
                fp.write(target["code"] + "\n")

    return repo_cache, advisory_dir


@pytest.fixture
def tools(tmp_workspace) -> VulnGymTools:
    repo_cache, advisory_dir = tmp_workspace
    return VulnGymTools(repo_cache_dir=repo_cache, advisory_dir=advisory_dir, manifest=None)


@pytest.fixture
def tools_with_manifest(tmp_workspace, manifest) -> VulnGymTools:
    """启用 manifest 严格校验的 tools 实例。"""
    repo_cache, advisory_dir = tmp_workspace
    return VulnGymTools(repo_cache_dir=repo_cache, advisory_dir=advisory_dir, manifest=manifest)


# ============================================================
# TestNormalizeProject
# ============================================================

class TestNormalizeProject:
    """repo_url -> project key 唯一映射。"""

    def test_standard_url(self, manifest):
        proj = normalize_project_from_repo(
            "https://github.com/example/blog-platform", manifest=manifest,
        )
        assert proj == "blog-platform"

    def test_url_with_git_suffix(self, manifest):
        proj = normalize_project_from_repo(
            "https://github.com/example/blog-platform.git", manifest=manifest,
        )
        assert proj == "blog-platform"

    def test_url_with_trailing_slash(self, manifest):
        proj = normalize_project_from_repo(
            "https://github.com/example/blog-platform/", manifest=manifest,
        )
        assert proj == "blog-platform"

    def test_url_with_extra_path_segments(self, manifest):
        proj = normalize_project_from_repo(
            "https://github.com/example/blog-platform/tree/main/src", manifest=manifest,
        )
        assert proj == "blog-platform"

    def test_unknown_repo_raises(self, manifest):
        with pytest.raises(UnknownProjectError):
            normalize_project_from_repo(
                "https://github.com/example/no-such-repo", manifest=manifest,
            )

    def test_collision_two_repos_same_basename(self, manifest):
        """两个 repo 的 owner 不同但 basename 相同（如 fork）—— 必须能区分。"""
        # 注入 collision case：构造 manifest 让 basename 重复但 url 不同
        collision_manifest = {
            "items": [
                {"repo_url": "https://github.com/owner-a/cool-lib", "project": "cool-lib-a"},
                {"repo_url": "https://github.com/owner-b/cool-lib", "project": "cool-lib-b"},
            ]
        }
        assert normalize_project_from_repo(
            "https://github.com/owner-a/cool-lib", manifest=collision_manifest,
        ) == "cool-lib-a"
        assert normalize_project_from_repo(
            "https://github.com/owner-b/cool-lib", manifest=collision_manifest,
        ) == "cool-lib-b"

    def test_fallback_without_manifest(self):
        """无 manifest 时回退到 basename 解析（兼容 I1 旧调用）。"""
        assert normalize_project_from_repo("https://github.com/x/y") == "y"
        assert normalize_project_from_repo("https://github.com/x/y.git") == "y"
        assert normalize_project_from_repo("https://github.com/x/y/") == "y"

    def test_empty_manifest_treated_as_fallback(self):
        """manifest 空列表 → 走 fallback。"""
        assert normalize_project_from_repo(
            "https://github.com/x/y", manifest={"items": []},
        ) == "y"


# ============================================================
# TestCheckout
# ============================================================

class TestCheckout:
    """checkout 行为契约。"""

    def test_hit_manifest_and_cache(self, tools, manifest):
        ok = [
            i for i in manifest["items"]
            if i["project"] == "blog-platform"
            and i["commit"] == "1" * 40
        ][0]
        r = tools.checkout(ok["project"], ok["commit"])
        assert r.ok
        assert r.data["commit"] == ok["commit"]
        assert Path(r.data["cwd"]).is_absolute()
        assert Path(r.data["cwd"]).is_dir()

    def test_bad_commit_format(self, tools):
        r = tools.checkout("blog-platform", "not-a-commit")
        assert not r.ok
        assert "bad commit format" in r.error

    def test_short_commit_rejected(self, tools):
        r = tools.checkout("blog-platform", "abc123")  # too short
        assert not r.ok

    def test_unknown_project(self, tools):
        r = tools.checkout("no-such-project", "1" * 40)
        assert not r.ok

    def test_unknown_commit_in_known_project(self, tools_with_manifest):
        # manifest 声明以外的 commit → 即使目录存在也应该拒绝
        r = tools_with_manifest.checkout("blog-platform", "f" * 40)
        assert not r.ok
        assert "manifest" in r.error.lower() or "not declared" in r.error.lower()

    def test_path_escape_rejected(self, tmp_path):
        # cwd = tmp_path/repo_cache/../../etc → checkout 应拒绝
        fake_repo_cache = tmp_path / "repo_cache"
        fake_repo_cache.mkdir()
        # 创建 ../etc
        etc_dir = tmp_path / "etc"
        etc_dir.mkdir()
        t = VulnGymTools(repo_cache_dir=fake_repo_cache, advisory_dir=tmp_path / "adv", manifest=None)
        # 通过 cwd 试图逃逸（cwd 来自外部）
        # checkout 本身不直接接 cwd，但 read_file_lines 会。 这里只能验证 bad path
        r = t.checkout("../../etc", "1" * 40)
        assert not r.ok


# ============================================================
# TestReadAdvisory
# ============================================================

class TestReadAdvisory:
    """read_advisory 失败安全契约。"""

    def test_normal_read(self, tmp_workspace, tmp_path):
        repo_cache, advisory_dir = tmp_workspace
        adv = advisory_dir / "GHSA-DEMO-0001-0XSS.json"
        adv.write_text('{"id": "GHSA-DEMO-0001-0XSS", "severity": "high"}', encoding="utf-8")
        t = VulnGymTools(repo_cache_dir=repo_cache, advisory_dir=advisory_dir, manifest=None)
        r = t.read_advisory("GHSA-DEMO-0001-0XSS")
        assert r.ok
        assert r.data["severity"] == "high"

    def test_404(self, tools):
        r = tools.read_advisory("GHSA-NOT-EXIST")
        assert not r.ok
        assert "not found" in r.error.lower()

    def test_corrupted_json(self, tmp_workspace):
        repo_cache, advisory_dir = tmp_workspace
        adv = advisory_dir / "GHSA-DEMO-BROKEN.json"
        adv.write_text("{not valid json,,,}", encoding="utf-8")
        t = VulnGymTools(repo_cache_dir=repo_cache, advisory_dir=advisory_dir, manifest=None)
        r = t.read_advisory("GHSA-DEMO-BROKEN")
        assert not r.ok
        assert "json" in r.error.lower() or "decode" in r.error.lower()

    def test_path_traversal_in_report_id(self, tools):
        # 即使 advisory 不存在，也必须先做正则校验
        for bad in ["../../etc/passwd", "..", "a/b", "a.b", "a b", "/abs"]:
            r = tools.read_advisory(bad)
            assert not r.ok, f"should reject report_id={bad!r}"

    def test_valid_ghsa_id_format(self, tools):
        """合法格式但不存在 → 必须返回 not found 而非路径穿越。"""
        r = tools.read_advisory("GHSA-AAAA-BBBB-CCCC")
        assert not r.ok
        assert "not found" in r.error.lower()


# ============================================================
# TestReadFileLines
# ============================================================

class TestReadFileLines:
    """read_file_lines 路径安全 + 行范围契约。"""

    def test_normal_range(self, tools, manifest):
        item = manifest["items"][0]  # blog-platform handlers/comment.js
        co = tools.checkout(item["project"], item["commit"])
        assert co.ok
        # 第一个 target 在 line 2 (header) + padding 后
        r = tools.read_file_lines(co.data["cwd"], item["file"], 1, 1)
        assert r.ok

    def test_range_clamp_to_file_end(self, tools, manifest):
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        assert co.ok
        r = tools.read_file_lines(co.data["cwd"], item["file"], 1, 99999)
        assert r.ok
        assert r.data["end"] <= r.data["total_lines"]

    def test_start_beyond_file_end_is_structured_contradiction(self, tools, manifest):
        """起始行越界是已确认的标注错误，不能返回可与任意文本匹配的空片段。"""
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        assert co.ok

        r = tools.read_file_lines(
            co.data["cwd"], item["file"], 99999, 99999,
        )

        assert not r.ok
        assert r.error_code == "line_out_of_range"
        assert r.data == {
            "file": item["file"],
            "requested_start": 99999,
            "requested_end": 99999,
            "total_lines": r.data["total_lines"],
        }
        assert r.data["total_lines"] > 0

    def test_file_not_found(self, tools, manifest):
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        assert co.ok
        r = tools.read_file_lines(co.data["cwd"], "src/nonexistent.js", 1, 10)
        assert not r.ok
        assert r.error_code == "file_missing_at_commit"

    def test_path_escape_via_file(self, tools, manifest):
        """file 含 .. 或绝对路径 → 拒绝"""
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        assert co.ok
        for bad in ["../../etc/passwd", "/etc/passwd", "src/../../escape"]:
            r = tools.read_file_lines(co.data["cwd"], bad, 1, 1)
            assert not r.ok, f"should reject file={bad!r}"

    def test_cwd_outside_repo_rejected(self, tools):
        """cwd 是 repo_cache 之外的目录 → 拒绝"""
        # 这里直接用 tmp_path（不在 repo_cache_dir 下）
        import tempfile
        outside = tempfile.gettempdir()
        r = tools.read_file_lines(outside, "anything", 1, 1)
        assert not r.ok


# ============================================================
# TestGrepCode
# ============================================================

class TestGrepCode:
    """grep_code 失败安全 + 命中契约。"""

    def test_hit(self, tools, manifest):
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        # mock 文件内容里有 insertTextHandler 或 RichText
        r = tools.grep_code(co.data["cwd"], item["file"], r".+")
        assert r.ok
        assert len(r.data["hits"]) >= 1

    def test_no_hit(self, tools, manifest):
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        r = tools.grep_code(co.data["cwd"], item["file"], r"NEVER_MATCHES_xyzzy_123")
        assert r.ok
        assert r.data["hits"] == []

    def test_file_not_found(self, tools, manifest):
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        r = tools.grep_code(co.data["cwd"], "src/missing.js", r".")
        assert not r.ok

    def test_bad_regex(self, tools, manifest):
        item = manifest["items"][0]
        co = tools.checkout(item["project"], item["commit"])
        r = tools.grep_code(co.data["cwd"], item["file"], r"[unclosed")
        assert not r.ok
        assert "regex" in r.error.lower() or "bad" in r.error.lower()


# ============================================================
# TestGitLog
# ============================================================

class TestGitLog:
    """git_log mock 行为。"""

    def test_default_limit(self, tools, manifest):
        item = manifest["items"][0]
        r = tools.git_log(item["project"], item["commit"])
        assert r.ok
        assert isinstance(r.data, list)
        assert len(r.data) <= 5  # default

    def test_custom_limit(self, tools, manifest):
        item = manifest["items"][0]
        r = tools.git_log(item["project"], item["commit"], limit=2)
        assert r.ok
        assert len(r.data) == 2

    def test_unknown_commit(self, tools_with_manifest):
        # 不在 manifest 中的 commit → 应返回 ok=false
        r = tools_with_manifest.git_log("blog-platform", "f" * 40)
        assert not r.ok


# ============================================================
# TestLocalGitCloneBackend
# ============================================================
class TestLocalGitCloneBackend:
    """本地 clone 是权威后端；工具只读对象数据库，不切换共享 HEAD。"""

    @staticmethod
    def _run(repo: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *args], check=True, capture_output=True,
            text=True, encoding="utf-8",
        ).stdout.strip()

    def test_reads_exact_commit_without_checkout(self, tmp_path: Path):
        repo = tmp_path / "repo"
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
        self._run(repo, "config", "user.email", "test@example.invalid")
        self._run(repo, "config", "user.name", "VulnGym test")
        source = repo / "src"
        source.mkdir()
        (source / "app.py").write_text("first = 1\nsecond = 2\n", encoding="utf-8")
        self._run(repo, "add", ".")
        self._run(repo, "commit", "-m", "fixture")
        commit = self._run(repo, "rev-parse", "HEAD")
        original_head = self._run(repo, "rev-parse", "HEAD")
        catalog = {"items": [{
            "repo_url": "https://github.com/example/local-fixture",
            "project": "local-fixture",
            "repo_path": str(repo),
        }]}
        tools = VulnGymTools(tmp_path / "snapshots", tmp_path / "advisories", repo_catalog=catalog)

        checkout = tools.checkout("local-fixture", commit)
        assert checkout.ok
        assert checkout.data["backend"] == "git"
        assert checkout.data["cwd"] == f"git://local-fixture/{commit}"
        read = tools.read_file_lines(checkout.data["cwd"], "src/app.py", 2, 2)
        assert read.ok and read.data["snippet"] == "second = 2\n"
        grep = tools.grep_code(checkout.data["cwd"], "src/app.py", r"second")
        assert grep.ok and grep.data["hits"][0]["line"] == 2
        history = tools.git_log("local-fixture", commit, limit=1)
        assert history.ok and history.data[0]["sha"] == commit
        assert self._run(repo, "rev-parse", "HEAD") == original_head

    def test_catalog_rejects_verdict_fields(self, tmp_path: Path):
        path = tmp_path / "catalog.json"
        path.write_text(json.dumps({"items": [{
            "repo_url": "https://github.com/example/repo", "project": "repo",
            "repo_path": str(tmp_path), "role": "vulnerable",
        }]}), encoding="utf-8")
        with pytest.raises(ValueError, match="verdict"):
            load_repo_catalog(path)

    def test_configured_clone_unavailable_has_stable_error_code(self, tmp_path: Path):
        missing_repo = tmp_path / "missing-local-clone"
        catalog = {"items": [{
            "repo_url": "https://github.com/example/missing",
            "project": "missing",
            "repo_path": str(missing_repo),
        }]}
        tools = VulnGymTools(
            tmp_path / "snapshots", tmp_path / "advisories", repo_catalog=catalog,
        )

        result = tools.checkout("missing", "a" * 40)

        assert not result.ok
        assert result.error_code == "repo_unavailable"

    def test_missing_commit_in_available_clone_has_stable_error_code(self, tmp_path: Path):
        repo = tmp_path / "repo"
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
        self._run(repo, "config", "user.email", "test@example.invalid")
        self._run(repo, "config", "user.name", "VulnGym test")
        (repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self._run(repo, "add", ".")
        self._run(repo, "commit", "-m", "fixture")
        catalog = {"items": [{
            "repo_url": "https://github.com/example/local-fixture",
            "project": "local-fixture",
            "repo_path": str(repo),
        }]}
        tools = VulnGymTools(
            tmp_path / "snapshots", tmp_path / "advisories", repo_catalog=catalog,
        )

        result = tools.checkout("local-fixture", "f" * 40)

        assert not result.ok
        assert result.error_code == "commit_missing"


# ============================================================
# TestManifestSchema
# ============================================================

class TestManifestSchema:
    """manifest.json 结构合规性。"""

    def test_valid_json(self, manifest):
        assert "items" in manifest
        assert isinstance(manifest["items"], list)
        assert len(manifest["items"]) >= 4

    def test_required_fields(self, manifest):
        required = {"repo_url", "project", "commit", "file", "targets"}
        for it in manifest["items"]:
            assert required.issubset(it.keys()), f"missing fields in {it}"

    def test_manifest_has_no_verdict_or_version_range_fields(self, manifest):
        for it in manifest["items"]:
            assert not ({"role", "vulnerable", "fixed", "affected_versions", "fixed_in"} & set(it))

    def test_commit_is_40_hex(self, manifest):
        for it in manifest["items"]:
            assert re.fullmatch(r"[0-9a-f]{40}", it["commit"]), f"bad commit: {it['commit']}"

    def test_repo_url_is_canonical(self, manifest):
        for it in manifest["items"]:
            u = it["repo_url"]
            assert u.startswith("https://github.com/"), f"bad url: {u}"
            assert not u.endswith(".git"), f"manifest should store canonical url: {u}"
            assert not u.endswith("/"), f"manifest should store canonical url: {u}"


# ============================================================
# TestNoNetworkLeak
# ============================================================

class TestNoNetworkLeak:
    """确保 tools.py 在 import/调用全过程中不使用网络。"""

    def test_no_network_imports(self):
        """检查 tools.py 源码不 import 网络库。"""
        import ast as _ast
        src = (ROOT / "vulngym-verify-demo" / "vulngym_verify_demo" / "tools.py").read_text(
            encoding="utf-8"
        )
        # AST 扫描 import 节点，避免 docstring/comment 误报
        tree = _ast.parse(src)
        forbidden = {"requests", "urllib", "socket", "http", "http.client", "aiohttp"}
        imported = set()
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for n in node.names:
                    imported.add(n.name.split(".")[0])
            elif isinstance(node, _ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        leak = imported & forbidden
        assert not leak, f"tools.py imports network modules: {leak}"

    def test_run_under_offline_simulation(self, tools, manifest, monkeypatch):
        """模拟 socket 完全失败 —— 所有工具调用仍正常返回。"""
        import socket as _socket

        def _fail(*_a, **_kw):
            raise RuntimeError("network disabled by test")

        monkeypatch.setattr(_socket, "socket", _fail)
        # 跑全部工具 —— 不应抛出 RuntimeError
        co = tools.checkout(manifest["items"][0]["project"], manifest["items"][0]["commit"])
        assert co.ok
        r = tools.read_file_lines(co.data["cwd"], manifest["items"][0]["file"], 1, 1)
        assert r.ok


# ============================================================
# TestConcurrentReadOnly
# ============================================================

class TestConcurrentReadOnly:
    """并发只读安全 —— 多线程同时操作不污染共享工作树。"""

    def test_concurrent_checkout_and_read(self, tools, manifest, tmp_path):
        # 记录初始文件列表（mock_repo 应无变化）
        initial_snapshot = {
            p.name
            for p in (tmp_path / "repo_cache").rglob("*")
            if p.is_file()
        }

        item = manifest["items"][0]

        def worker(_i: int):
            co = tools.checkout(item["project"], item["commit"])
            assert co.ok
            r = tools.read_file_lines(co.data["cwd"], item["file"], 1, 1)
            assert r.ok
            g = tools.grep_code(co.data["cwd"], item["file"], r".")
            assert g.ok

        with ThreadPoolExecutor(max_workers=10) as ex:
            for fut in [ex.submit(worker, i) for i in range(20)]:
                fut.result()  # 不抛即成功

        # 缓存目录应完全不变
        after_snapshot = {
            p.name
            for p in (tmp_path / "repo_cache").rglob("*")
            if p.is_file()
        }
        assert initial_snapshot == after_snapshot, "concurrent ops mutated cache"
