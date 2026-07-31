"""Repository management: clone, cache, checkout, and search."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Known file extensions for repo file listing
CODE_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".pyi", ".pyx",
    ".go",
    ".java", ".kt", ".scala",
    ".svelte", ".vue",
    ".rs", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cc", ".cxx",
    ".swift", ".m", ".mm",
    ".sql", ".sh", ".bash", ".zsh",
    ".yaml", ".yml", ".toml", ".json", ".xml",
    ".dockerfile", ".Dockerfile",
}


class RepoManager:
    """Manages git repository clones and provides search capabilities.

    Uses bare clones + git-show for file access, avoiding full checkouts.
    """

    def __init__(self, cache_dir: Path, timeout: int = 120):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self._locks: dict[str, threading.Lock] = {}
        self._available: set[str] = set()  # repos successfully cloned

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_repo(self, repo_url: str) -> bool:
        """Clone or fetch a bare repo. Returns True on success."""
        repo_key = self._repo_key(repo_url)
        repo_path = self.cache_dir / repo_key

        if repo_key not in self._locks:
            self._locks[repo_key] = threading.Lock()

        with self._locks[repo_key]:
            if repo_path.exists():
                # Already cloned — fetch to update
                return self._fetch(repo_path)
            else:
                return self._clone_bare(repo_url, repo_path)

    def get_file_content(self, repo_url: str, commit: str, file_path: str) -> Optional[str]:
        """Read a file's content at a specific commit. Returns None if not found."""
        try:
            result = subprocess.run(
                ["git", "show", f"{commit}:{file_path}"],
                cwd=str(self._bare_path(repo_url)),
                capture_output=True, text=True,
                timeout=self.timeout,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("git show failed for %s @ %s: %s: %s",
                           repo_url, commit, file_path, e)
            return None

    def search_in_file(self, repo_url: str, commit: str, file_path: str,
                       needle: str) -> list[int]:
        """Search for needle text in a specific file. Returns list of 1-based line numbers."""
        content = self.get_file_content(repo_url, commit, file_path)
        if content is None:
            return []
        lines = content.split("\n")
        results = []
        for i, line in enumerate(lines, 1):
            if needle in line:
                results.append(i)
        return results

    def git_grep(self, repo_url: str, commit: str, pattern: str,
                 path_filter: str = ".") -> list[tuple[str, int]]:
        """Search the entire repo for a literal pattern using git grep.

        Returns list of (file_path, line_number).
        """
        bare_path = self._bare_path(repo_url)
        if not bare_path.exists():
            logger.warning("Repo not available for grep: %s", repo_url)
            return []

        try:
            # Use -F for fixed-string (literal) search, not regex
            result = subprocess.run(
                ["git", "grep", "-F", "-n", "-I", pattern, commit, "--", path_filter],
                cwd=str(bare_path),
                capture_output=True, text=True,
                timeout=self.timeout,
                encoding="utf-8", errors="replace",
            )
            if result.returncode not in (0, 1):
                # returncode 1 = no matches (normal), >1 = error
                if result.returncode > 1:
                    logger.warning("git grep error (rc=%d): %s",
                                   result.returncode, result.stderr[:200])
                return []

            matches = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                # Format: "commit:file_path:line_num:content"
                parts = line.split(":", 3)
                if len(parts) >= 3:
                    file_path_match = parts[1]
                    try:
                        line_num = int(parts[2])
                        matches.append((file_path_match, line_num))
                    except ValueError:
                        continue
            return matches
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning("git grep failed for %s: %s", repo_url, e)
            return []

    def repo_available(self, repo_url: str) -> bool:
        """Check if a repo has been successfully cloned."""
        return self._bare_path(repo_url).exists()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _repo_key(self, repo_url: str) -> str:
        """Convert repo URL to a safe filesystem name."""
        # https://github.com/org/repo → github.com/org/repo
        url = repo_url.strip()
        for prefix in ("https://", "http://", "git://"):
            if url.startswith(prefix):
                url = url[len(prefix):]
        if url.endswith(".git"):
            url = url[:-4]
        url = url.rstrip("/")
        # Replace dangerous chars
        return url.replace(":", "_").replace("\\", "/")

    def _bare_path(self, repo_url: str) -> Path:
        return self.cache_dir / self._repo_key(repo_url)

    def _clone_bare(self, repo_url: str, dest: Path) -> bool:
        """Clone a bare repo. Returns True on success."""
        logger.info("Cloning %s → %s ...", repo_url, dest)
        try:
            dest.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--bare", "--filter=blob:none",
                 "--single-branch", "--no-tags", repo_url, str(dest)],
                capture_output=True, text=True,
                timeout=self.timeout * 2,
                encoding="utf-8", errors="replace",
                check=True,
            )
            logger.info("Clone complete: %s", repo_url)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Clone failed for %s: %s", repo_url, e.stderr[:300])
            return False
        except subprocess.TimeoutExpired:
            logger.error("Clone timed out for %s", repo_url)
            return False

    def _fetch(self, repo_path: Path) -> bool:
        """Fetch updates for an existing bare repo."""
        try:
            subprocess.run(
                ["git", "fetch", "--prune"],
                cwd=str(repo_path),
                capture_output=True, text=True,
                timeout=self.timeout,
                encoding="utf-8", errors="replace",
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.warning("Fetch failed for %s: %s", repo_path, str(e)[:200])
            return True  # non-fatal: use existing data
