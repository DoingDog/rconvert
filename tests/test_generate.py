import contextlib
import io
import json
from http.client import IncompleteRead
import os
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib import error, request

from generate import fetch_https, generate, publish


ROOT = Path(__file__).resolve().parents[1]
GROUPS = ("a1", "a2", "a3", "cdn", "big-data", "dirt")
NAMES = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")


def configure_groups(root, sources=None, whitelist=None):
    sources = sources or {}
    whitelist = whitelist or {}
    (root / "rulesets.json").write_text(json.dumps([
        {"name": group, "purpose": "block" if group in {"a1", "a2", "a3"} else
         "direct" if group == "dirt" else "proxy",
         "no_resolve": "strip" if group == "dirt" else "add",
         "sources": sources.get(group, [f"{group}/rules.txt"]),
         "whitelist": whitelist.get(group, [])}
        for group in ("a2", "cdn", "a3", "a1", "big-data", "dirt")
    ]), encoding="utf-8")
    for group in GROUPS:
        (root / group).mkdir(exist_ok=True)


class GenerateTests(unittest.TestCase):
    def test_http_source_is_rejected_before_network(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            fetch_https("http://example.org/list.txt")

    def test_https_download_returns_rule_bytes(self):
        url = "https://example.org/list.txt"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), b"DOMAIN,ads.example.org\n")

    def test_https_redirect_to_http_is_rejected(self):
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: "http://example.org/list.txt"
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                fetch_https("https://example.org/list.txt")

    def test_insecure_redirect_is_blocked_before_request(self):
        url = "https://example.org/list.txt"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url
        visited_http = []

        class RedirectingOpener:
            def __init__(self, handler):
                self.handler = handler

            def open(self, source, timeout):
                self.handler.redirect_request(
                    request.Request(source), None, 302, "Found", {}, "http://example.org/list.txt"
                )
                visited_http.append(True)
                return response

        with patch("urllib.request.build_opener", side_effect=lambda handler: RedirectingOpener(handler)):
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    fetch_https(url)
        self.assertFalse(visited_http)

    def test_download_larger_than_limit_is_rejected(self):
        response = BytesIO(b"12345")
        response.geturl = lambda: "https://example.org/list.txt"
        with patch("generate.MAX_BYTES", 4, create=True), patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "size"):
                fetch_https("https://example.org/list.txt")

    def test_partial_http_response_is_rejected_before_parsing(self):
        url = "https://example.org/partial.txt"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url
        response.status = 206
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "206"):
                fetch_https(url)

    def test_html_response_is_rejected_even_when_it_contains_rule_text(self):
        url = "https://example.org/list.txt"
        response = BytesIO(b"<html>DOMAIN,ads.example.org</html>")
        response.geturl = lambda: url
        response.headers = {"Content-Type": "text/html"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "HTML"):
                fetch_https(url)

    def test_empty_download_is_rejected(self):
        url = "https://example.org/empty.txt"
        response = BytesIO(b"")
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "empty"):
                fetch_https(url)

    def test_html_body_is_rejected_when_server_mislabels_it(self):
        url = "https://example.org/list.txt"
        response = BytesIO(b"<!DOCTYPE html><html>DOMAIN,ads.example.org</html>")
        response.geturl = lambda: url
        response.headers = {"Content-Type": "text/plain"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "HTML"):
                fetch_https(url)

    def test_download_uses_accepted_user_agent_for_sukka_source(self):
        url = "https://ruleset.skk.moe/List/non_ip/my_reject.conf"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url

        class AgentSensitiveOpener:
            addheaders = []

            def open(self, source, timeout):
                if not any(name.lower() == "user-agent" and "Mozilla" in value
                           for name, value in self.addheaders):
                    raise error.HTTPError(url, 403, "Forbidden", {}, None)
                return response

        with patch("urllib.request.build_opener", return_value=AgentSensitiveOpener()):
            self.assertEqual(fetch_https(url), b"DOMAIN,ads.example.org\n")

    def test_http_failure_identifies_source_url(self):
        url = "https://example.org/broken.txt"
        failure = error.HTTPError(url, 404, "Not Found", {}, None)
        with patch("urllib.request.OpenerDirector.open", side_effect=failure):
            with self.assertRaisesRegex(Exception, url):
                fetch_https(url)

    def test_timeout_identifies_source_url(self):
        url = "https://example.org/slow.txt"
        with patch("urllib.request.OpenerDirector.open", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(Exception, url):
                fetch_https(url)

    def test_timeout_while_reading_identifies_source_url(self):
        url = "https://example.org/slow.txt"

        class SlowResponse(BytesIO):
            def read(self, size=-1):
                raise TimeoutError("timed out")

        response = SlowResponse()
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(Exception, url):
                fetch_https(url)

    def test_short_response_with_content_length_is_rejected(self):
        url = "https://example.org/truncated.txt"
        data = b"DOMAIN,ads.example.org\n"
        response = BytesIO(data)
        response.geturl = lambda: url
        response.headers = {"Content-Length": str(len(data) + 50)}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, url):
                fetch_https(url)

    def test_incomplete_download_identifies_source_url(self):
        url = "https://example.org/truncated.txt"

        class TruncatedResponse(BytesIO):
            def read(self, size=-1):
                raise IncompleteRead(b"DOMAIN,partial.example.org", 50)

        response = TruncatedResponse()
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(RuntimeError, url):
                fetch_https(url)

    def test_publish_writes_a_complete_utf8_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "a3" / "fin.txt"
            output.parent.mkdir()
            publish({output: "DOMAIN,例子.example\n"})
            self.assertEqual(output.read_bytes(), "DOMAIN,例子.example\n".encode("utf-8"))

    def test_second_replacement_failure_restores_all_old_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            first, second = root / "a2" / "fin.txt", root / "a3" / "fin.txt"
            for path in (first, second):
                path.parent.mkdir()
                path.write_bytes(b"old data\n")
            original_replace = os.replace
            calls = 0

            def fail_second(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("replacement failed")
                return original_replace(source, target)

            with patch("os.replace", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "replacement failed"):
                    publish({first: "new first\n", second: "new second\n"})
            self.assertEqual(first.read_bytes(), b"old data\n")
            self.assertEqual(second.read_bytes(), b"old data\n")

    def test_publish_rejects_paths_outside_worktree(self):
        outside = ROOT.parent / "outside-fin.txt"
        with patch("os.replace", side_effect=RuntimeError("would write outside")):
            with self.assertRaisesRegex(ValueError, "worktree"):
                publish({outside: "DOMAIN,ads.example.org\n"})
        self.assertFalse(outside.exists())

    def test_publish_rejects_static_paths_before_replacement(self):
        target = ROOT / "static/main/Direct.list"
        original = target.read_bytes()
        with patch("os.replace", side_effect=AssertionError("static write attempted")):
            with self.assertRaisesRegex(ValueError, "static"):
                publish({target: "DOMAIN,evil.example\n"})
        self.assertEqual(target.read_bytes(), original)

    def test_generate_rejects_root_outside_worktree_before_reading(self):
        with self.assertRaisesRegex(ValueError, "worktree"):
            generate(ROOT.parent, lambda _: self.fail("network must not be used"))

    def test_json_config_builds_a_new_group_without_hardcoded_names(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "custom", "purpose": "block", "no_resolve": "keep",
                "sources": ["input.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "input.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / "custom" / name for name in NAMES})
            self.assertIn("DOMAIN,ads.example.org\n", outputs[root / "custom" / "fin.txt"])

    def test_no_resolve_policy_add_strip_and_keep_is_configured_per_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "tagged.list").write_text("IP-CIDR,192.0.2.0/24,no-resolve\n", encoding="utf-8")
            (root / "untagged.list").write_text("IP-CIDR,198.51.100.0/24\n", encoding="utf-8")
            groups = [
                {"name": name, "purpose": "direct", "no_resolve": policy,
                 "sources": [source], "whitelist": []}
                for name, policy, source in (
                    ("dirt", "strip", "tagged.list"),
                    ("preserved", "keep", "tagged.list"),
                    ("untagged", "keep", "untagged.list"),
                    ("forced", "add", "untagged.list"),
                )
            ]
            (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            for name in ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin.yaml"):
                self.assertNotIn("no-resolve", outputs[root / "dirt" / name], name)
                self.assertIn("no-resolve", outputs[root / "preserved" / name], name)
                self.assertNotIn("no-resolve", outputs[root / "untagged" / name], name)
                self.assertIn("no-resolve", outputs[root / "forced" / name], name)

    def test_json_whitelist_removes_only_covered_rules_and_adds_dns_exceptions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["block.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "block.list").write_text(
                "DOMAIN-SUFFIX,a.com\nDOMAIN,remove.example.com\n"
                "DOMAIN-KEYWORD,ad.track\n@@||safe.org^\n", encoding="utf-8",
            )
            (root / "allow.list").write_text(
                "DOMAIN,safe.a.com,DIRECT\nDOMAIN-SUFFIX,remove.example.com,DIRECT\n"
                "USER-AGENT,*bot*,DIRECT\n", encoding="utf-8",
            )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            surge = outputs[root / "a3" / "fin.txt"]
            dns = outputs[root / "a3" / "fin-adb.txt"]
            self.assertIn("DOMAIN-SUFFIX,a.com\n", surge)
            self.assertIn("DOMAIN-KEYWORD,ad.track\n", surge)
            self.assertNotIn("remove.example.com", surge)
            self.assertIn("||a.com^\n", dns)
            self.assertIn("/^.*ad\\.track.*$/\n", dns)
            self.assertIn("@@|safe.a.com|\n", dns)
            self.assertIn("@@||safe.org^\n", dns)
            self.assertNotIn("\nremove.example.com\n", dns)
            self.assertNotIn("USER-AGENT", dns)

    def test_cli_builds_fixture_with_local_sources_only(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "generate.py"), "--root", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                {root / group / name for group in GROUPS for name in NAMES},
                {path for group in GROUPS for path in (root / group).glob("fin*")},
            )

    def test_adblock_keeps_wide_block_with_narrow_allow_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\n@@||safe.example.com^\n"
                    if group == "a2" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a2" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a2" / "fin-adb.txt"])
            self.assertIn("@@||safe.example.com^", outputs[root / "a2" / "fin-adb.txt"])

    def test_whitelist_keeps_broad_route_and_adds_dns_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a2": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN-SUFFIX,safe.example.com,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\nDOMAIN,ads.example.com\n"
                    if group == "a2" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a2" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a2" / "fin-adb.txt"])
            self.assertIn("@@||safe.example.com^", outputs[root / "a2" / "fin-adb.txt"])

    def test_exact_whitelist_keeps_broad_block_with_anchored_dns_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a2": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN,safe.example.com,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\n" if group == "a2"
                    else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a2" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a2" / "fin-adb.txt"])
            self.assertIn("@@|safe.example.com|", outputs[root / "a2" / "fin-adb.txt"])

    def test_empty_required_source_aborts_with_its_path(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "# no rules\n" if group == "a3" else "DOMAIN,ads.example.org\n",
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(ValueError, "a3.*rules.txt"):
                generate(root, lambda _: self.fail("local input must not fetch"))

    def test_invalid_utf8_identifies_remote_source_and_does_not_publish(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            target = root / "a2" / "fin.txt"
            configure_groups(root, sources={"a3": ["https://example.org/broken.txt"]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            target.write_bytes(b"previous version\n")
            with self.assertRaisesRegex(UnicodeError, "https://example.org/broken.txt"):
                publish(generate(root, lambda _: b"\xff\xfe"))
            self.assertEqual(target.read_bytes(), b"previous version\n")

    def test_last_source_failure_keeps_all_previous_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"dirt": ["https://example.org/final.txt"]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            with self.assertRaisesRegex(RuntimeError, "final.txt"):
                publish(generate(root, lambda _: (_ for _ in ()).throw(RuntimeError("final.txt unavailable"))))
            self.assertTrue(all(
                (root / group / name).read_bytes() == b"previous version\n"
                for group in GROUPS for name in NAMES
            ))

    def test_unsupported_source_rule_reports_url_and_line(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"a3": ["https://example.org/mixed.txt"]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                generate(root, lambda _: b"DOMAIN,ads.example.org\nUNKNOWN-TYPE,foo\n")
            self.assertIn("https://example.org/mixed.txt", stderr.getvalue())
            self.assertIn("line 2", stderr.getvalue())
            self.assertIn("UNKNOWN-TYPE", stderr.getvalue())

    def test_incompatible_target_type_reports_count(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "PROCESS-NAME,Game.exe,REJECT\n" if group == "a3"
                    else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("a3 fin-qx.txt:PROCESS-NAME: 1", stderr.getvalue())

    def test_dependent_groups_use_current_in_memory_cdn_and_a2_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"a1": ["a2/fin.txt"], "big-data": ["cdn/fin.txt"]})
            for group in GROUPS:
                if group not in {"a1", "big-data"}:
                    (root / group / "rules.txt").write_text(
                        f"DOMAIN,from-{group}.example.org\n", encoding="utf-8",
                    )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,from-a2.example.org", outputs[root / "a1" / "fin.txt"])
            self.assertIn("DOMAIN,from-cdn.example.org", outputs[root / "big-data" / "fin.txt"])
            self.assertFalse((root / "a2" / "fin.txt").exists())
            self.assertFalse((root / "cdn" / "fin.txt").exists())

    def test_changed_dependencies_change_the_same_round_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"a1": ["a2/fin.txt"], "big-data": ["cdn/fin.txt"]})
            for group in GROUPS:
                if group not in {"a1", "big-data"}:
                    (root / group / "rules.txt").write_text(
                        f"DOMAIN,original-{group}.example.org\n", encoding="utf-8",
                    )
            first = generate(root, lambda _: self.fail("local input must not fetch"))
            for group in ("a2", "cdn"):
                (root / group / "rules.txt").write_text(
                    f"DOMAIN,replaced-{group}.example.org\n", encoding="utf-8",
                )
            second = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,replaced-a2.example.org", second[root / "a1" / "fin.txt"])
            self.assertIn("DOMAIN,replaced-cdn.example.org", second[root / "big-data" / "fin.txt"])
            self.assertNotEqual(first[root / "a1" / "fin.txt"], second[root / "a1" / "fin.txt"])
            self.assertNotEqual(first[root / "big-data" / "fin.txt"], second[root / "big-data" / "fin.txt"])

    def test_same_remote_url_is_fetched_once_for_rules_and_whitelist(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            shared = "https://example.org/shared.txt"
            configure_groups(root, sources={"a2": [shared], "a3": [shared]},
                             whitelist={"a3": [shared]})
            for group in GROUPS:
                if group not in {"a2", "a3"}:
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            calls = []

            def fetch(url):
                calls.append(url)
                return b"DOMAIN,shared.example.org\n"

            generate(root, fetch)
            self.assertEqual(calls, [shared])

    def test_automatic_no_resolve_allows_cidr_coalescing_across_source_options(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25,no-resolve\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            rules = outputs[root / "a3" / "fin.txt"].splitlines()[1:]
            self.assertEqual(rules, ["IP-CIDR,192.0.2.0/24,no-resolve"])

    def test_repeat_build_has_identical_utf8_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\nIP-CIDR,203.0.113.0/24\n", encoding="utf-8",
                )
            with contextlib.redirect_stderr(io.StringIO()):
                first = generate(root, lambda _: self.fail("local input must not fetch"))
                second = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(
                {path: text.encode("utf-8") for path, text in first.items()},
                {path: text.encode("utf-8") for path, text in second.items()},
            )

    def test_offline_build_produces_six_files_per_group_without_writing_them(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={group: [f"https://example.org/{group}.txt"] for group in GROUPS})
            contents = {
                f"https://example.org/{group}.txt": b"DOMAIN,ads.example.org\n"
                for group in GROUPS
            }
            outputs = generate(root, contents.__getitem__)
            self.assertEqual(set(outputs), {root / group / name for group in GROUPS for name in NAMES})
            self.assertFalse(any(path.exists() for path in outputs))
