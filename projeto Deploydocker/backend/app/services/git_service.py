import os
import shutil
from urllib.parse import urlparse, urlunparse

# Auto-detect git executable if not in system PATH
if not shutil.which("git"):
    candidates = [
        "C:\\Program Files\\Git\\cmd\\git.exe",
        "C:\\Program Files (x86)\\Git\\cmd\\git.exe",
    ]
    gh_desktop = os.path.expanduser("~\\AppData\\Local\\GitHubDesktop")
    if os.path.exists(gh_desktop):
        for entry in sorted(os.listdir(gh_desktop), reverse=True):
            candidate = os.path.join(gh_desktop, entry, "resources", "app", "git", "cmd", "git.exe")
            if os.path.isfile(candidate):
                candidates.insert(0, candidate)

    for c in candidates:
        if os.path.isfile(c):
            os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = c
            git_dir = os.path.dirname(c)
            if git_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = git_dir + os.pathsep + os.environ.get("PATH", "")
            break

os.environ.setdefault("GIT_PYTHON_REFRESH", "quiet")

import asyncio
from typing import Any, Dict, Optional

import git


def _inject_git_token(repo_url: str, git_token: Optional[str]) -> str:
    """Injeta Personal Access Token (PAT) em URLs HTTP/HTTPS para clonar repositórios privados."""
    if not git_token or not git_token.strip():
        return repo_url
    token = git_token.strip()
    if not repo_url.startswith(("http://", "https://")):
        return repo_url
    parsed = urlparse(repo_url)
    host = parsed.hostname or ""
    port_part = f":{parsed.port}" if parsed.port else ""
    netloc = f"oauth2:{token}@{host}{port_part}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


class GitService:
    async def clone_repo(
        self,
        repo_url: str,
        dest_path: str,
        branch: str = "main",
        git_token: Optional[str] = None,
    ) -> str:
        def _clone():
            auth_url = _inject_git_token(repo_url, git_token)
            if not os.path.exists(dest_path):
                repo = git.Repo.clone_from(auth_url, dest_path, branch=branch)
            else:
                repo = git.Repo(dest_path)
                if repo.remotes:
                    if git_token:
                        repo.remotes.origin.set_url(auth_url)
                    elif repo_url:
                        repo.remotes.origin.set_url(repo_url)
                    repo.remotes.origin.fetch(prune=True)
                    repo.git.clean("-fd")
                    try:
                        repo.git.checkout("-B", branch, f"origin/{branch}")
                    except Exception:
                        repo.git.checkout(branch)
                    try:
                        repo.git.reset("--hard", f"origin/{branch}")
                    except Exception:
                        pass
            return repo.head.commit.hexsha

        return await asyncio.to_thread(_clone)

    async def pull_repo(
        self,
        repo_path: str,
        branch: str = "main",
        git_token: Optional[str] = None,
        repo_url: Optional[str] = None,
    ) -> str:
        def _pull():
            repo = git.Repo(repo_path)
            if repo.remotes:
                if git_token and repo_url:
                    repo.remotes.origin.set_url(_inject_git_token(repo_url, git_token))
                elif repo_url:
                    repo.remotes.origin.set_url(repo_url)
                repo.remotes.origin.fetch(prune=True)
                repo.git.clean("-fd")
                try:
                    repo.git.checkout("-B", branch, f"origin/{branch}")
                except Exception:
                    repo.git.checkout(branch)
                try:
                    repo.git.reset("--hard", f"origin/{branch}")
                except Exception:
                    pass
            return repo.head.commit.hexsha

        return await asyncio.to_thread(_pull)

    async def get_current_commit(self, repo_path: str) -> Dict[str, Any]:
        def _get():
            repo = git.Repo(repo_path)
            commit = repo.head.commit
            return {
                "sha": commit.hexsha,
                "message": commit.message,
                "author": commit.author.name,
                "timestamp": commit.committed_datetime.isoformat(),
            }

        return await asyncio.to_thread(_get)
