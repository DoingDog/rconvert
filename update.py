import os
import re
import subprocess
import sys
from pathlib import Path

from formats import FILES
from generate import fetch_https, generate, publish
from sources import load_config
from update_readme_counts import update as update_counts


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


def _push_race(push: subprocess.CompletedProcess, tested_sha: str) -> bool:
    statuses = [line.split("\t") for line in push.stdout.splitlines() if "\t" in line]
    if len(statuses) != 1 or len(statuses[0]) != 3 or statuses[0][:2] != ["!", "HEAD:refs/heads/main"]:
        return False
    summary = statuses[0][2]
    if summary in ("[rejected] (fetch first)", "[rejected] (non-fast-forward)",
                   "[remote rejected] (non-fast-forward)"):
        return True
    if summary not in ("[remote rejected] (failed to update ref)",
                       "[remote rejected] (incorrect old value provided)"):
        return False
    mismatch = re.search(
        r"^remote: error: cannot lock ref 'refs/heads/main': is at ([0-9a-f]{40}) but expected "
        + re.escape(tested_sha) + r"[ \t]*$", push.stderr, re.MULTILINE)
    return mismatch is not None and mismatch[1] != tested_sha


def update(root: Path, tested_sha: str) -> str:
    root = root.resolve()
    if _git(root, "rev-parse", "HEAD").stdout.strip() != tested_sha:
        raise ValueError("HEAD does not match the tested event SHA")
    if _superseded(root, tested_sha):
        return "superseded"
    if _git(root, "diff", "--cached", "--name-only").stdout:
        raise ValueError("Refusing to publish with existing staged changes")
    publish(generate(root, fetch_https), root=root)
    update_counts(root)
    if _superseded(root, tested_sha):
        return "superseded"
    paths = [str(Path(group["name"]) / name) for group in load_config(root) for name in FILES]
    _git(root, "add", "--", *paths, "README.md")
    diff = _git(root, "diff", "--cached", "--quiet", check=False)
    if diff.returncode == 0:
        print("unchanged: no generated changes to publish")
        return "unchanged"
    if diff.returncode != 1:
        diff.check_returncode()
    _git(root, "-c", "user.name=github-actions[bot]",
         "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
         "commit", "-m", "Update generated rules")
    push = _git(root, "push", "--porcelain", "origin", "HEAD:refs/heads/main", check=False)
    if push.returncode:
        if _push_race(push, tested_sha) and _superseded(root, tested_sha):
            return "superseded"
        push.check_returncode()
    return "published"


if __name__ == "__main__":
    update(Path(__file__).resolve().parent, os.environ["GITHUB_SHA"])
