import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import update as ci
from generate import generate, publish
from update_readme_counts import update as update_counts


OLD = b"DOMAIN,initial.example\nIP-CIDR,192.0.2.0/24\n"
NEW = OLD + b"DOMAIN,new.example\nIP-CIDR,198.51.100.0/24\n"
START = datetime(2026, 10, 22, 0, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 22, 0, 1, tzinfo=timezone.utc)


class CiPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rconvert-ci-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.origin = self.directory / "origin.git"
        seed = self.directory / "seed"
        seed.mkdir()
        self.git(seed, "init", "-q", "-b", "main")
        self.git(seed, "config", "user.name", "Fixture Writer")
        self.git(seed, "config", "user.email", "fixture@example.org")
        groups = [{"name": f"fixture-{index}", "purpose": purpose,
                   "no_resolve": "strip" if purpose == "direct" else "add",
                   "sources": ["https://fixture.invalid/rules"], "whitelist": []}
                  for index, purpose in enumerate(
                      ("proxy", "block", "block", "proxy", "proxy", "proxy", "direct"))]
        (seed / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
        (seed / "README.md").write_text(
            "prefix\n<!-- RULE_COUNTS_START -->\nstale\n<!-- RULE_COUNTS_END -->\nsuffix\n",
            encoding="utf-8")
        (seed / "static").mkdir()
        (seed / "static/input.list").write_bytes(OLD)
        (seed / "source.py").write_text("original = True\n", encoding="utf-8")
        (seed / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
        with patch("formats.datetime") as clock, redirect_stderr(io.StringIO()):
            clock.now.return_value = START
            publish(generate(seed, lambda url: OLD), root=seed)
        update_counts(seed)
        self.git(seed, "add", ".")
        self.git(seed, "commit", "-qm", "Seed fixture")
        self.base = self.git(seed, "rev-parse", "HEAD").stdout.strip()
        self.git(self.directory, "init", "-q", "--bare", str(self.origin))
        self.git(self.origin, "symbolic-ref", "HEAD", "refs/heads/main")
        self.git(seed, "remote", "add", "origin", str(self.origin))
        self.git(seed, "push", "-q", "origin", "HEAD:refs/heads/main")
        self.runner = self.clone("runner", detached=True)
        self.writer = self.clone("writer")
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def git(self, root, *args, check=True):
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True,
                                env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        if check and result.returncode:
            self.fail(f"git {args}: {result.stdout}\n{result.stderr}")
        return result

    def clone(self, name, *, detached=False):
        root = self.directory / name
        self.git(self.directory, "clone", "-q", "--depth", "1", self.origin.as_uri(), str(root))
        self.git(root, "config", "user.name", "Fixture Writer")
        self.git(root, "config", "user.email", "fixture@example.org")
        if detached:
            self.git(root, "checkout", "-q", "--detach", self.base)
        return root

    def advance(self):
        (self.writer / "source.py").write_text("advanced = True\n", encoding="utf-8")
        self.git(self.writer, "add", "source.py")
        self.git(self.writer, "commit", "-qm", "Advance source")
        self.git(self.writer, "push", "-q", "origin", "HEAD:refs/heads/main")
        return self.git(self.writer, "rev-parse", "HEAD").stdout.strip()

    def tip(self):
        return self.git(self.origin, "rev-parse", "refs/heads/main").stdout.strip()

    def run_update(self, *, root=None, sha=None, data=NEW, moment=LATER, fetch=None):
        with patch("formats.datetime") as clock, patch("update.fetch_https", side_effect=fetch or (lambda url: data)):
            clock.now.return_value = moment
            with redirect_stdout(self.stdout), redirect_stderr(self.stderr):
                return ci.update(root or self.runner, sha or self.base)

    def test_head_must_equal_the_tested_event_sha(self):
        with self.assertRaisesRegex(ValueError, "HEAD.*tested"):
            self.run_update(sha="0" * 40)
        self.assertEqual(self.tip(), self.base)
        self.assertEqual(self.git(self.runner, "status", "--porcelain").stdout, "")

    def test_missing_main_fails_before_generation(self):
        self.git(self.origin, "update-ref", "-d", "refs/heads/main")
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.run_update()
        self.assertEqual(raised.exception.returncode, 2)
        self.assertEqual(self.git(self.runner, "status", "--porcelain").stdout, "")
        self.assertNotIn("superseded", self.stdout.getvalue())

    def test_unreadable_origin_fails_before_generation(self):
        self.git(self.runner, "remote", "set-url", "origin", str(self.directory / "missing.git"))
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.run_update()
        self.assertEqual(raised.exception.returncode, 128)
        self.assertIn("does not appear to be a git repository", self.stderr.getvalue())
        self.assertEqual(self.git(self.runner, "status", "--porcelain").stdout, "")

    def test_superseded_run_skips_generation_and_preserves_checkout(self):
        advanced = self.advance()
        before = (self.runner / "fixture-1/fin-adb.txt").read_bytes()
        (self.runner / "rulesets.json").write_text("invalid source config", encoding="utf-8")
        result = self.run_update(fetch=lambda url: self.fail("superseded run fetched a source"))
        self.assertEqual(result, "superseded")
        self.assertIn("superseded", self.stdout.getvalue())
        self.assertEqual(self.tip(), advanced)
        self.assertEqual(self.git(self.runner, "rev-parse", "HEAD").stdout.strip(), self.base)
        self.assertEqual((self.runner / "fixture-1/fin-adb.txt").read_bytes(), before)
        self.assertEqual(self.git(self.runner, "diff", "--cached", "--name-only").stdout, "")
