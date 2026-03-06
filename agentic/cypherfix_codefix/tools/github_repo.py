"""GitHubRepoManager: clone, branch, commit, push, create PR."""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPOS_BASE = Path(os.environ.get("CYPHERFIX_REPOS_BASE", "/tmp/cypherfix-repos"))


class GitHubRepoManager:
    def __init__(self, token: str, repo: str, default_branch: str = "main"):
        self.token = token
        self.repo = repo  # owner/repo
        self.default_branch = default_branch
        self.repo_path: Optional[Path] = None

    def clone(self, branch: str = None) -> Path:
        """Clone the repository."""
        REPOS_BASE.mkdir(parents=True, exist_ok=True)
        repo_dir = REPOS_BASE / self.repo.replace("/", "_")
        if repo_dir.exists():
            shutil.rmtree(repo_dir)

        clone_url = f"https://x-access-token:{self.token}@github.com/{self.repo}.git"
        cmd = ["git", "clone", "--depth", "50"]
        if branch:
            cmd.extend(["-b", branch])
        cmd.extend([clone_url, str(repo_dir)])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if result.returncode != 0:
            stderr = result.stderr or ""
            if self.token:
                stderr = stderr.replace(self.token, "***")
            raise RuntimeError(f"Clone failed: {stderr}")

        self.repo_path = repo_dir
        return repo_dir

    def create_branch(self, branch_name: str):
        """Create and switch to a new branch."""
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=self.repo_path, capture_output=True, text=True, check=True,
        )

    def commit(self, message: str):
        """Stage all changes and commit."""
        subprocess.run(
            ["git", "add", "-A"],
            cwd=self.repo_path, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=self.repo_path, capture_output=True, text=True, check=True,
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "CypherFix",
                "GIT_AUTHOR_EMAIL": "cypherfix@redamon.io",
                "GIT_COMMITTER_NAME": "CypherFix",
                "GIT_COMMITTER_EMAIL": "cypherfix@redamon.io",
            },
        )

    def push(self, branch_name: str):
        """Push branch to remote (force-push to handle re-runs on same branch)."""
        result = subprocess.run(
            ["git", "push", "--force", "origin", branch_name],
            cwd=self.repo_path, capture_output=True, text=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if result.returncode != 0:
            # Sanitize token from error output
            stderr = result.stderr or ""
            if self.token:
                stderr = stderr.replace(self.token, "***")
            logger.error(f"Git push failed (exit {result.returncode}): {stderr}")
            raise RuntimeError(f"Git push failed: {stderr}")

    def create_pr(self, title: str, body: str, branch: str, base: str = None) -> dict:
        """Create a pull request via GitHub API, or update the existing one."""
        from github import Github, GithubException
        g = Github(self.token)
        repo = g.get_repo(self.repo)
        try:
            pr = repo.create_pull(
                title=title, body=body,
                head=branch, base=base or self.default_branch,
            )
        except GithubException as e:
            # PR already exists for this branch — find and update it
            if e.status == 422:
                existing = repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch}")
                pr = None
                for p in existing:
                    pr = p
                    break
                if pr is None:
                    raise RuntimeError(f"PR already exists but could not be found for branch {branch}")
                pr.edit(title=title, body=body)
                logger.info(f"Updated existing PR #{pr.number} for branch {branch}")
            else:
                raise
        return {
            "pr_url": pr.html_url,
            "pr_number": pr.number,
            "branch": branch,
            "title": title,
            "files_changed": pr.changed_files,
            "additions": pr.additions,
            "deletions": pr.deletions,
        }

    def cleanup(self):
        """Remove the cloned repository."""
        if self.repo_path and self.repo_path.exists():
            shutil.rmtree(self.repo_path, ignore_errors=True)
