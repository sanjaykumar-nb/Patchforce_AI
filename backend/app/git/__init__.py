"""
PatchForge AI - Git & GitHub Integration Package
================================================
Automates branch management, conventional commit formatting,
and Pull Request generation with verification scorecards.
"""

from app.git.formatter import generate_pr_markdown_description
from app.git.github_client import GitHubClient, github_client

__all__ = [
    "generate_pr_markdown_description",
    "GitHubClient",
    "github_client",
]
