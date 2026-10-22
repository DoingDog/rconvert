import os
import subprocess
import sys
from pathlib import Path

from generate import fetch_https


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True,
                            env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if check:
        result.check_returncode()
    return result


def _superseded(root: Path, tested_sha: str) -> bool:
    remote = _git(root, "ls-remote", "--exit-code", "origin", "refs/heads/main")
    tip, ref = remote.stdout.strip().split("\t")
    if ref != "refs/heads/main":
        raise ValueError("Expected origin refs/heads/main")
    if tip != tested_sha:
        print(f"superseded: tested {tested_sha}; origin main is {tip}; skipping publication")
        return True
    return False


def update(root: Path, tested_sha: str) -> str:
    root = root.resolve()
    if _git(root, "rev-parse", "HEAD").stdout.strip() != tested_sha:
        raise ValueError("HEAD does not match the tested event SHA")
    if _superseded(root, tested_sha):
        return "superseded"
