#!/usr/bin/env python3
"""
Git 仓库管理模块
负责克隆、缓存、切换 commit，并提供线程安全的仓库准备。
"""

import threading
from collections import defaultdict
from pathlib import Path
import git
from git.exc import GitCommandError
from .config import CACHE_DIR

# 仓库锁：同一 URL 串行操作，避免并发冲突
repo_locks = defaultdict(threading.Lock)

def prepare_repo(repo_url: str, commit: str) -> Path:
    """
    准备指定仓库并切换到目标 commit。
    如果本地缓存不存在则执行浅克隆，否则更新并切换。
    同一 repo_url 的操作通过锁串行化，避免竞态。

    Args:
        repo_url (str): Git 仓库 URL
        commit (str): 40 位 commit 哈希

    Returns:
        Path: 本地仓库路径（已切换到目标 commit）

    Raises:
        Exception: 克隆或切换失败时抛出
    """
    with repo_locks[repo_url]:
        # 生成缓存目录名
        name = repo_url.rstrip('/').split('/')[-2] + '_' + repo_url.rstrip('/').split('/')[-1]
        if name.endswith('.git'):
            name = name[:-4]
        cache_path = CACHE_DIR / name

        # 克隆或更新
        if not cache_path.exists():
            print(f"\n  Cloning {repo_url} ...")
            git.Repo.clone_from(repo_url, cache_path, depth=1)
        else:
            try:
                repo = git.Repo(cache_path)
                repo.git.fetch('--all', '--prune')
            except:
                pass

        # 切换 commit
        repo = git.Repo(cache_path)
        try:
            repo.git.checkout(commit, force=True)
        except GitCommandError:
            # 浅克隆可能缺少该 commit，扩展深度 fetch
            print(f"    Fetching commit {commit[:7]} (扩展浅克隆)...")
            repo.git.fetch('--depth=100', 'origin', commit)
            repo.git.checkout(commit, force=True)

        return cache_path
