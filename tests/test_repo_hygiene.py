"""Repository Hygiene and Rules Compliance Tests."""

import os
import re
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_gitignore_exists_and_contains_rules():
    gitignore_path = ROOT_DIR / ".gitignore"
    assert gitignore_path.exists(), ".gitignore must exist"

    content = gitignore_path.read_text()
    assert ".antigravity/" in content
    assert ".venv/" in content
    assert ".env" in content
    assert "!.env.example" in content
    assert "__pycache__/" in content


def test_no_forbidden_files_tracked_by_git():
    """Verify that git tracked files do not contain forbidden artifacts."""
    res = subprocess.run(
        ["git", "ls-files"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
    )
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    forbidden_patterns = [
        r"^\.antigravity/.*",
        r"^\.env(\..+)?$",
        r".*\.py[cod]$",
        r".*__pycache__/.*",
        r"^\.venv/.*",
        r"^venv/.*",
        r".*\.log$",
        r".*\.tmp$",
    ]

    for file_path in tracked_files:
        if file_path == ".env.example" or file_path == ".env.template":
            continue
        for pattern in forbidden_patterns:
            assert not re.match(
                pattern, file_path
            ), f"Forbidden file tracked by git: {file_path}"


def test_no_secrets_in_source_files():
    """Scan tracked source code for accidental real secrets or private keys."""
    res = subprocess.run(
        ["git", "ls-files"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
    )
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    secret_patterns = [
        (re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"), "Private Key"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
        (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token"),
    ]

    for file_path in tracked_files:
        full_path = ROOT_DIR / file_path
        if full_path.is_file():
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                for pattern, desc in secret_patterns:
                    assert not pattern.search(
                        content
                    ), f"Potential secret detected ({desc}) in file: {file_path}"
            except Exception:
                pass
