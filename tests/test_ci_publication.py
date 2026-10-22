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
            clock.now.side_effect = lambda zone: START.astimezone(zone)
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
            self.git(root, "fetch", "-q", "--depth", "1", "origin", self.base)
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
            clock.now.side_effect = lambda zone: moment.astimezone(zone)
            with redirect_stdout(self.stdout), redirect_stderr(self.stderr):
                return ci.update(root or self.runner, sha or self.base)

    def test_publishes_real_generated_files_and_readme_with_bot_identity(self):
        self.assertEqual(self.run_update(), "published")
        published = self.tip()
        self.assertNotEqual(published, self.base)
        self.assertEqual(self.git(self.runner, "rev-parse", "HEAD^").stdout.strip(), self.base)
        self.assertEqual(self.git(self.runner, "show", "-s", "--format=%an%n%ae%n%s").stdout,
                         "github-actions[bot]\n"
                         "41898282+github-actions[bot]@users.noreply.github.com\n"
                         "Update generated rules\n")
        paths = set(self.git(self.runner, "show", "--format=", "--name-only", "HEAD").stdout.splitlines())
        expected = {f"fixture-{index}/{name}" for index in range(7) for name in
                    ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")}
        self.assertEqual(paths, expected | {"README.md"})
        self.assertIn("DOMAIN,new.example\n", self.git(
            self.origin, "show", "main:fixture-1/fin.txt").stdout)
        self.assertIn("! Version: 202610220801\n", self.git(
            self.origin, "show", "main:fixture-1/fin-adb.txt").stdout)
        readme = self.git(self.origin, "show", "main:README.md").stdout
        self.assertIn("| `fin.txt` | 4 | 4 | 4 | 4 | 4 | 4 | 4 |", readme)
        self.assertTrue(readme.startswith("prefix\n<!-- RULE_COUNTS_START -->\n"))
        self.assertTrue(readme.endswith("<!-- RULE_COUNTS_END -->\nsuffix\n"))
        self.assertEqual(self.git(self.runner, "status", "--porcelain").stdout, "")

    def test_same_sha_runs_are_strictly_serial_and_second_run_does_not_generate(self):
        self.assertEqual(self.run_update(), "published")
        published = self.tip()
        second = self.clone("second", detached=True)
        self.assertEqual(self.run_update(root=second, fetch=lambda url: self.fail("stale fetch")),
                         "superseded")
        self.assertEqual(self.tip(), published)
        self.assertEqual(self.git(second, "rev-parse", "HEAD").stdout.strip(), self.base)
        self.assertIn(b"! Version: 202610220800\n", (second / "fixture-1/fin-adb.txt").read_bytes())
        self.assertEqual(self.git(second, "status", "--porcelain").stdout, "")

    def test_publication_preserves_unrelated_tracked_and_untracked_changes(self):
        unrelated = {"source.py": b"edited = True\n", "static/input.list": OLD + b"# edited\n",
                     "static/new.list": b"DOMAIN,local.example\n", "unexpected.py": b"extra = True\n",
                     "fixture-0/unconfigured.txt": b"manual output\n"}
        for name, data in unrelated.items():
            (self.runner / name).write_bytes(data)
        self.assertEqual(self.run_update(), "published")
        committed = set(self.git(self.runner, "show", "--format=", "--name-only").stdout.splitlines())
        self.assertTrue(committed.isdisjoint(unrelated))
        for name, data in unrelated.items():
            self.assertEqual((self.runner / name).read_bytes(), data)
        self.assertEqual(self.git(self.runner, "diff", "--cached", "--name-only").stdout, "")
        self.assertIn(" M source.py", self.git(self.runner, "status", "--porcelain").stdout)
        self.assertEqual(self.git(self.origin, "show", "main:source.py").stdout, "original = True\n")
        self.assertEqual(self.git(self.origin, "show", "main:static/input.list").stdout.encode(), OLD)

    def test_existing_staged_changes_are_preserved_and_not_published(self):
        (self.runner / "source.py").write_text("staged = True\n", encoding="utf-8")
        self.git(self.runner, "add", "source.py")
        before = self.git(self.runner, "diff", "--cached", "--binary").stdout
        with self.assertRaisesRegex(ValueError, "staged"):
            self.run_update()
        self.assertEqual(self.git(self.runner, "diff", "--cached", "--binary").stdout, before)
        self.assertEqual(self.git(self.runner, "diff", "--name-only").stdout, "")
        self.assertEqual(self.tip(), self.base)

    def test_unchanged_generation_creates_no_commit(self):
        self.assertEqual(self.run_update(data=OLD, moment=START), "unchanged")
        self.assertEqual(self.tip(), self.base)
        self.assertEqual(self.git(self.runner, "rev-parse", "HEAD").stdout.strip(), self.base)
        self.assertEqual(self.git(self.runner, "status", "--porcelain").stdout, "")

    def test_source_advance_during_generation_skips_staging_and_commit(self):
        def fetch(url):
            self.advance()
            return NEW

        self.assertEqual(self.run_update(fetch=fetch), "superseded")
        self.assertNotEqual(self.tip(), self.base)
        self.assertEqual(self.git(self.runner, "rev-parse", "HEAD").stdout.strip(), self.base)
        self.assertEqual(self.git(self.runner, "diff", "--cached", "--name-only").stdout, "")
        self.assertIn(b"DOMAIN,new.example\n", (self.runner / "fixture-1/fin.txt").read_bytes())
        self.assertEqual(self.git(self.origin, "show", "main:source.py").stdout, "advanced = True\n")
        self.assertNotIn("new.example", self.git(self.origin, "show", "main:fixture-1/fin.txt").stdout)

    def test_second_remote_read_failure_stops_before_staging(self):
        def fetch(url):
            self.git(self.runner, "remote", "set-url", "origin", str(self.directory / "missing.git"))
            return NEW

        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.run_update(fetch=fetch)
        self.assertEqual(raised.exception.returncode, 128)
        self.assertIn("ls-remote", raised.exception.cmd)
        self.assertEqual(self.tip(), self.base)
        self.assertEqual(self.git(self.runner, "rev-parse", "HEAD").stdout.strip(), self.base)
        self.assertEqual(self.git(self.runner, "diff", "--cached", "--name-only").stdout, "")
        self.assertNotIn("superseded", self.stdout.getvalue())

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
