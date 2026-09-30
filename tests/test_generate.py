import contextlib
import gzip
import io
import json
from datetime import datetime, timezone
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
GROUPS = ("cdn", "a3", "big-data", "dirt")
NAMES = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")


def configure_groups(root, sources=None, whitelist=None):
    sources = sources or {}
    whitelist = whitelist or {}
    (root / "rulesets.json").write_text(json.dumps([
        {"name": group, "purpose": "block" if group == "a3" else
         "direct" if group == "dirt" else "proxy",
         "no_resolve": "strip" if group == "dirt" else "add",
         "sources": sources.get(group, [f"{group}/rules.txt"]),
         "whitelist": whitelist.get(group, [])}
        for group in GROUPS
    ]), encoding="utf-8")
    for group in GROUPS:
        (root / group).mkdir(exist_ok=True)


class SurgeEscapedFieldDependencyGenerateTests(unittest.TestCase):
    def test_encoded_fields_survive_generation_publish_and_disk_reimport(self):
        from rules import parse

        values = ("Game\\", "Game\\\\", "Game\\\\\\", "'Game\\\\", '"Game\'Inc"', "'Game\"Inc'", '"Game\\', "'Game\\")
        expressions = []
        for leaf in ("PROCESS-NAME", "PROCESS-PATH"):
            for value in values:
                payload = "/Applications/" + value if leaf == "PROCESS-PATH" else value
                expressions.extend((operator, f"(({leaf},{payload}),(IP-CIDR,192.0.2.0/24,no-resolve),"
                                    "(SRC-IP-CIDR,198.51.100.0/24))") for operator in ("AND", "OR"))
                expressions.append(("NOT", f"((NOT,(({leaf},{payload}))))"))
        native_lines = [f"{kind},{value}" for kind, value in expressions]
        document = "payload:\n" + "".join("  - " + json.dumps(line) + "\n" for line in native_lines)
        document += "  - DOMAIN-KEYWORD,keep\n"
        original, messages = parse(document, purpose="proxy")
        self.assertEqual(messages, [])
        self.assertEqual(len(original), len(expressions) + 1)
        for mode in ("keep", "add", "strip"):
            expected = {line.replace(",no-resolve", "") if mode == "strip" else line for line in native_lines}
            expected.add("DOMAIN-KEYWORD,keep")
            for dependency in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                with self.subTest(mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": "source", "purpose": "proxy", "no_resolve": mode,
                                "sources": ["native.yaml"], "whitelist": []},
                               {"name": "dependent", "purpose": "proxy", "no_resolve": mode,
                                "sources": [f"source/{dependency}"], "whitelist": []}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "native.yaml").write_text(document, encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / group / name
                                                   for group in ("source", "dependent") for name in NAMES})
                    publish(outputs)
                    for group in ("source", "dependent"):
                        yaml = (root / group / "fin.yaml").read_text(encoding="utf-8")
                        self.assertEqual({json.loads(line[4:]) for line in yaml.splitlines()[2:]}, expected)
                        parsed, warnings = parse(yaml, purpose="proxy")
                        self.assertEqual(warnings, [])
                        self.assertTrue(all(rule.native_fields for rule in parsed if rule.kind in {"AND", "OR", "NOT"}))
                        for name in ("fin.txt", "fin-surge.txt"):
                            text = (root / group / name).read_text(encoding="utf-8")
                            self.assertEqual(text.splitlines()[0], f"# {group} rules: {len(expected)}")
                            self.assertFalse(any(f"{group} {name}:{kind}:" in stderr.getvalue()
                                                 for kind in ("AND", "OR", "NOT")))
                        for name in NAMES:
                            self.assertEqual((root / group / name).read_bytes(), outputs[root / group / name].encode("utf-8"))
                    self.assertNotIn(": line ", stderr.getvalue())
                    (root / "rulesets.json").write_text(json.dumps([
                        {"name": "disk", "purpose": "proxy", "no_resolve": mode,
                         "sources": [f"source/{dependency}"], "whitelist": []},
                    ]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk_outputs = generate(root, lambda url: self.fail(url))
                    publish(disk_outputs)
                    self.assertEqual(set(disk_outputs), {root / "disk" / name for name in NAMES})
                    self.assertEqual({json.loads(line[4:]) for line in
                                      (root / "disk" / "fin.yaml").read_text(encoding="utf-8").splitlines()[2:]}, expected)
                    self.assertNotIn(": line ", disk_stderr.getvalue())


class LiteralQuoteDependencyGenerateTests(unittest.TestCase):
    def test_native_literal_quotes_survive_surge_and_yaml_dependencies_for_all_modes(self):
        from rules import Rule, parse

        expressions = (
            ('AND', '((PROCESS-NAME,"Game"),(DOMAIN,x.example.com))'),
            ('OR', "((PROCESS-NAME,'Game'),(IP-CIDR,198.51.100.0/24,no-resolve),"
                   "(SRC-IP-CIDR,192.0.2.0/24))"),
            ('NOT', r'((PROCESS-NAME,"Game\Inc"))'),
            ('AND', '((OR,((PROCESS-NAME,"Game"),(DOMAIN,other.example.com))),'
                    '(NOT,((IP-CIDR,203.0.113.0/24))))'),
        )
        for mode, suffix, added in (("keep", ",no-resolve", ""),
                                    ("add", ",no-resolve", ",no-resolve"), ("strip", "", "")):
            expected = (
                expressions[0],
                ('OR', "((PROCESS-NAME,'Game'),(IP-CIDR,198.51.100.0/24" + suffix + "),"
                       "(SRC-IP-CIDR,192.0.2.0/24))"),
                expressions[2],
                ('AND', '((OR,((PROCESS-NAME,"Game"),(DOMAIN,other.example.com))),'
                        '(NOT,((IP-CIDR,203.0.113.0/24' + added + '))))'),
            )
            for dependency in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                with self.subTest(mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    (root / "rulesets.json").write_text(json.dumps([
                        {"name": "source", "purpose": "proxy", "no_resolve": mode,
                         "sources": ["native.yaml"], "whitelist": []},
                        {"name": "dependent", "purpose": "proxy", "no_resolve": mode,
                         "sources": [f"source/{dependency}"], "whitelist": []},
                    ]), encoding="utf-8")
                    native = "payload:\n  - 'AND,((PROCESS-NAME,\"Game\"),(DOMAIN,x.example.com))'\n"
                    native += "".join(
                        "  - " + json.dumps(f"{kind},{value}") + "\n" for kind, value in expressions[1:]
                    ) + '  - "DOMAIN-KEYWORD,keep"\n'
                    (root / "native.yaml").write_text(native, encoding="utf-8")
                    self.assertEqual(parse(native, purpose="proxy"), (
                        [Rule(kind, value, literal_process=True, native_fields=True) for kind, value in expressions]
                        + [Rule("DOMAIN-KEYWORD", "keep")], [],
                    ))
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / group / name
                                                   for group in ("source", "dependent") for name in NAMES})
                    publish(outputs)
                    self.assertTrue(all(path.is_file() and path.read_text(encoding="utf-8") == text
                                        for path, text in outputs.items()))
                    for group, values in (("dependent", expected), ("source", expected)):
                        yaml = (root / group / "fin.yaml").read_text(encoding="utf-8")
                        self.assertEqual({json.loads(line[4:]) for line in yaml.splitlines()[2:]},
                                         {f"{kind},{value}" for kind, value in values}
                                         | {"DOMAIN-KEYWORD,keep"})
                        parsed, messages = parse(yaml, purpose="proxy")
                        self.assertEqual(messages, [])
                        self.assertEqual(set(parsed), {
                            Rule(kind, value, literal_process=True, native_fields=True) for kind, value in values
                        } | {Rule("DOMAIN-KEYWORD", "keep")})
                        for name in ("fin.txt", "fin-surge.txt"):
                            surge = (root / group / name).read_text(encoding="utf-8")
                            self.assertIn('AND,((PROCESS-NAME,\'"Game"\'),(DOMAIN,x.example.com))\n', surge)
                            self.assertNotIn(f"{group} {name}:AND:", stderr.getvalue())
                            self.assertNotIn(f"{group} {name}:OR:", stderr.getvalue())
                            self.assertNotIn(f"{group} {name}:NOT:", stderr.getvalue())
                        for kind, count in (("AND", 2), ("OR", 1), ("NOT", 1)):
                            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                                self.assertIn(f"{group} {name}:{kind}: {count}\n", stderr.getvalue())
                    self.assertNotIn(": line ", stderr.getvalue())
                    self.assertNotIn("no routable rules", stderr.getvalue())
                    (root / "rulesets.json").write_text(json.dumps([
                        {"name": "disk", "purpose": "proxy", "no_resolve": mode,
                         "sources": [f"source/{dependency}"], "whitelist": []},
                    ]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk_outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk_outputs), {root / "disk" / name for name in NAMES})
                    publish(disk_outputs)
                    self.assertTrue(all(path.is_file() and path.read_text(encoding="utf-8") == text
                                        for path, text in disk_outputs.items()))
                    self.assertEqual((root / "disk" / "fin.yaml").read_text(encoding="utf-8").splitlines()[2:],
                                     (root / "dependent" / "fin.yaml").read_text(encoding="utf-8").splitlines()[2:])
                    self.assertNotIn(": line ", disk_stderr.getvalue())
                    self.assertNotIn("no routable rules", disk_stderr.getvalue())

    def test_unrepresentable_native_quotes_skip_surge_logic_without_losing_yaml_dependency(self):
        from rules import Rule, parse

        invalid = []
        # 用原生字面 * 验证整个逻辑规则的目标 skip，不把可转义的引号判为不可表达。
        for value in ('"Game\'Inc*"', '"Game*\\'):
            invalid.extend((kind, f"((PROCESS-NAME,{value}),(DOMAIN,x.example.com))")
                           for kind in ("AND", "OR"))
            invalid.append(("NOT", f"((PROCESS-NAME,{value}))"))
        invalid.append(("AND", '((OR,((PROCESS-NAME,"Game*\\),(DOMAIN,x.example.com))),'
                               '(DOMAIN,other.example.com))'))
        safe = "OR,((DOMAIN,a.example.com),(DOMAIN,b.example.com))"
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                configs = [{"name": "source", "purpose": "proxy", "no_resolve": mode,
                            "sources": ["native.yaml"], "whitelist": []}] + [
                    {"name": group, "purpose": "proxy", "no_resolve": mode,
                     "sources": [f"source/{name}"], "whitelist": []}
                    for group, name in (("txt", "fin.txt"), ("surge", "fin-surge.txt"), ("yaml", "fin.yaml"))
                ]
                (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                document = "payload:\n" + "".join(
                    "  - " + json.dumps(f"{kind},{value}") + "\n" for kind, value in invalid
                ) + "  - " + json.dumps(safe) + '\n  - "DOMAIN-KEYWORD,keep"\n'
                (root / "native.yaml").write_text(document, encoding="utf-8")
                original = [Rule(kind, value, literal_process=True, native_fields=True)
                            for kind, value in invalid]
                self.assertEqual(parse(document, purpose="proxy"), (
                    original + [Rule("OR", safe[3:], native_fields=True), Rule("DOMAIN-KEYWORD", "keep")], [],
                ))
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(set(outputs), {root / group / name
                                               for group in ("source", "txt", "surge", "yaml") for name in NAMES})
                publish(outputs)
                self.assertTrue(all(path.is_file() and path.read_text(encoding="utf-8") == text
                                    for path, text in outputs.items()))
                for group in ("source", "txt", "surge", "yaml"):
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual((root / group / name).read_text(encoding="utf-8"),
                                         f"# {group} rules: 2\nDOMAIN-KEYWORD,keep\n{safe}\n")
                        for kind, count in (("AND", 3), ("OR", 2), ("NOT", 2)):
                            diagnostic = f"{group} {name}:{kind}:"
                            if group in ("source", "yaml"):
                                self.assertIn(f"{diagnostic} {count}\n", stderr.getvalue())
                            else:
                                self.assertNotIn(diagnostic, stderr.getvalue())
                    yaml = (root / group / "fin.yaml").read_text(encoding="utf-8")
                    expected = {safe, "DOMAIN-KEYWORD,keep"}
                    if group in ("source", "yaml"):
                        expected |= {f"{kind},{value}" for kind, value in invalid}
                    self.assertEqual({json.loads(line[4:]) for line in yaml.splitlines()[2:]}, expected)
                    parsed, messages = parse(yaml, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(set(parsed), {
                        Rule("OR", safe[3:], native_fields=True), Rule("DOMAIN-KEYWORD", "keep"),
                    } | (set(original) if group in ("source", "yaml") else set()))
                self.assertNotIn(": line ", stderr.getvalue())
                self.assertNotIn("no routable rules", stderr.getvalue())


class NativeFieldFix8GenerateTests(unittest.TestCase):
    def test_generated_yaml_dependency_keeps_native_logic_provenance_for_all_modes(self):
        from rules import parse

        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "source", "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["native.yaml"], "whitelist": []},
                    {"name": "dependent", "purpose": "proxy", "no_resolve": mode,
                     "sources": ["source/fin.yaml"], "whitelist": []},
                ]), encoding="utf-8")
                expression = '((DOMAIN-REGEX,"*ads"),(PROCESS-NAME-REGEX,^Game,Inc$))'
                (root / "native.yaml").write_text("rules:\n  - 'AND," + expression + "'\n", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                for group in ("source", "dependent"):
                    text = outputs[root / group / "fin.yaml"]
                    self.assertEqual([json.loads(line[4:]) for line in text.splitlines()[2:]], ["AND," + expression])
                    parsed, messages = parse(text, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertTrue(parsed[0].native_fields)
                    self.assertEqual({path.name for path in outputs if path.parent.name == group}, set(NAMES))
                self.assertNotIn("invalid", stderr.getvalue())


class SourceFieldContinuationGenerateTests(unittest.TestCase):
    def test_quoted_url_regex_markers_survive_surge_generated_dependency(self):
        from rules import Rule, parse

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "source", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "dependent", "purpose": "proxy", "no_resolve": "strip",
                 "sources": ["source/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            values = ["^foo #bar$", "^foo ;bar$", "^foo //bar$"]
            (root / "source.list").write_text("".join(f"URL-REGEX,'{value}',PROXY\n" for value in values), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda url: self.fail(url))
            for group in ("source", "dependent"):
                self.assertEqual({path.name for path in outputs if path.parent.name == group}, set(NAMES))
                parsed, messages = parse(outputs[root / group / "fin.txt"], purpose="proxy")
                self.assertEqual(set(parsed), {Rule("URL-REGEX", value) for value in values})
                self.assertEqual(messages, [])


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

    def test_html_response_is_passed_to_parser(self):
        url = "https://example.org/list.txt"
        body = b"<html>DOMAIN,ads.example.org</html>"
        response = BytesIO(body)
        response.geturl = lambda: url
        response.headers = {"Content-Type": "text/html"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), body)

    def test_empty_download_is_rejected(self):
        url = "https://example.org/empty.txt"
        response = BytesIO(b"")
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "empty"):
                fetch_https(url)

    def test_html_body_with_wrong_media_type_is_passed_to_parser(self):
        url = "https://example.org/list.txt"
        body = b"<!DOCTYPE html><html>DOMAIN,ads.example.org</html>"
        response = BytesIO(body)
        response.geturl = lambda: url
        response.headers = {"Content-Type": "text/plain"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), body)

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

    def test_gzip_download_is_decompressed_for_rules(self):
        url = "https://example.org/list.txt"
        data = b"DOMAIN,ads.example.org\n"
        compressed = gzip.compress(data)
        response = BytesIO(compressed)
        response.geturl = lambda: url
        response.headers = {"Content-Encoding": "gzip", "Content-Length": str(len(compressed))}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), data)

    def test_gzip_checks_compressed_and_decompressed_size_limits(self):
        url = "https://example.org/huge.txt"
        compressed = gzip.compress(b"DOMAIN," + b"a" * 1000)
        for maximum, label in ((len(compressed) - 1, "size"), (len(compressed), "Decompressed")):
            with self.subTest(label=label):
                response = BytesIO(compressed)
                response.geturl = lambda: url
                response.headers = {"Content-Encoding": "gzip", "Content-Length": str(len(compressed))}
                with patch("generate.MAX_BYTES", maximum), patch("urllib.request.OpenerDirector.open", return_value=response):
                    with self.assertRaisesRegex(ValueError, label):
                        fetch_https(url)

    def test_truncated_gzip_download_aborts_instead_of_skipping(self):
        url = "https://example.org/broken.txt"
        response = BytesIO(gzip.compress(b"DOMAIN,ads.example.org\n")[:-5])
        response.geturl = lambda: url
        response.headers = {"Content-Encoding": "gzip"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(RuntimeError, url):
                fetch_https(url)

    def test_publish_writes_a_complete_utf8_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "a3" / "fin.txt"
            output.parent.mkdir()
            publish({output: "DOMAIN,例子.example\n"})
            self.assertEqual(output.read_bytes(), "DOMAIN,例子.example\n".encode("utf-8"))

    def test_publish_creates_a_new_group_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "new-group" / "fin.txt"
            publish({output: "DOMAIN,new.example.org\n"})
            self.assertEqual(output.read_text(encoding="utf-8"), "DOMAIN,new.example.org\n")

    def test_second_replacement_failure_restores_all_old_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            first, second = root / "cdn" / "fin.txt", root / "a3" / "fin.txt"
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

    def test_publish_failure_removes_new_group_and_keeps_prior_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            new = root / "new-group" / "fin.txt"
            old = root / "cdn" / "fin.txt"
            old.parent.mkdir()
            old.write_bytes(b"previous version\n")
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
                    publish({new: "new content\n", old: "new old\n"})
            self.assertFalse(new.parent.exists())
            self.assertEqual(old.read_bytes(), b"previous version\n")

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
                "name": "custom", "title": "Custom Ads", "purpose": "block", "no_resolve": "keep",
                "sources": ["input.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "input.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / "custom" / name for name in NAMES})
            self.assertIn("DOMAIN,ads.example.org\n", outputs[root / "custom" / "fin.txt"])
            self.assertIn("! Title: Custom Ads\n", outputs[root / "custom" / "fin-adb.txt"])

    def test_generate_keeps_literal_and_glob_process_sources_separate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "proxy", "purpose": "proxy", "no_resolve": "strip",
                "sources": ["literal.yaml", "surge.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "literal.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Foo*Bar"\n'
                '  - "AND,((PROCESS-NAME,Foo*Bar),(DOMAIN,a.example.com))"\n',
                encoding="utf-8",
            )
            (root / "surge.list").write_text(
                "PROCESS-NAME,Foo*Bar,PROXY\n"
                "HOST-SUFFIX,googleapis.com,PROXY,force-cellular\n", encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                out = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(out[root / "proxy" / "fin.yaml"],
                             '# proxy rules: 4\npayload:\n'
                             '  - "AND,((PROCESS-NAME,Foo*Bar),(DOMAIN,a.example.com))"\n'
                             '  - "DOMAIN-SUFFIX,googleapis.com"\n'
                             '  - "PROCESS-NAME,Foo*Bar"\n'
                             '  - "PROCESS-NAME-WILDCARD,Foo*Bar"\n')
            self.assertEqual(out[root / "proxy" / "fin.txt"],
                             '# proxy rules: 2\nDOMAIN-SUFFIX,googleapis.com\nPROCESS-NAME,Foo*Bar\n')
            self.assertEqual(out[root / "proxy" / "fin-qx.txt"],
                             '# proxy rules: 1\nHOST-SUFFIX,googleapis.com,LIST\n')
            self.assertIn("proxy fin.txt:AND: 1", stderr.getvalue())
            self.assertIn("proxy fin.txt:PROCESS-NAME: 1", stderr.getvalue())
            self.assertIn("proxy fin-qx.txt:DOMAIN-SUFFIX:interface-option: 1", stderr.getvalue())

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

    def test_local_source_ip_direction_and_ip_suffix_are_target_specific(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "proxy", "purpose": "proxy", "no_resolve": "add",
                "sources": ["source.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "source.list").write_text(
                "DOMAIN,baseline.example.org,PROXY\n"
                "IP-CIDR,192.0.2.0/24,PROXY,src\n"
                "IP-SUFFIX,8.8.8.8/24,PROXY,no-resolve\n", encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            for name in ("fin.txt", "fin-surge.txt"):
                self.assertIn("SRC-IP,192.0.2.0/24\n", outputs[root / "proxy" / name])
                self.assertNotIn("IP-CIDR,192.0.2.0/24", outputs[root / "proxy" / name])
                self.assertNotIn("8.8.8.8/24", outputs[root / "proxy" / name])
            self.assertIn('  - "SRC-IP-CIDR,192.0.2.0/24"\n', outputs[root / "proxy" / "fin.yaml"])
            self.assertIn('  - "IP-SUFFIX,8.8.8.8/24,no-resolve"\n', outputs[root / "proxy" / "fin.yaml"])
            self.assertNotIn("192.0.2.0/24", outputs[root / "proxy" / "fin-qx.txt"])
            self.assertNotIn("8.8.8.8/24", outputs[root / "proxy" / "fin-qx.txt"])
            self.assertIn("proxy fin-qx.txt:SRC-IP-CIDR: 1", stderr.getvalue())
            self.assertIn("proxy fin-surge.txt:IP-SUFFIX: 1", stderr.getvalue())

    def test_local_sources_preserve_matchers_across_six_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "add",
                 "sources": ["block.list", "literal.yaml"], "whitelist": ["allow.list"]},
                {"name": "dirt", "purpose": "direct", "no_resolve": "strip",
                 "sources": ["direct.list"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "block.list").write_text(
                "DOMAIN-SUFFIX,ads.example.org,REJECT\n"
                "DOMAIN,safe.ads.example.org,REJECT\n"
                "DOMAIN-WILDCARD,api-[0-9].example.org,REJECT\n"
                "IP-CIDR,192.0.2.0/24,REJECT,src\n"
                "AND,((IP-CIDR,198.51.100.0/24),(DOMAIN,track.example.net)),REJECT\n",
                encoding="utf-8",
            )
            (root / "literal.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Foo*Bar"\n', encoding="utf-8",
            )
            (root / "allow.list").write_text(
                "DOMAIN,safe.ads.example.org,DIRECT\n", encoding="utf-8",
            )
            (root / "direct.list").write_text(
                "OR,((IP-CIDR,203.0.113.0/24,no-resolve),(DOMAIN,direct.example.net)),DIRECT\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stderr(io.StringIO()) as warnings:
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "dirt") for name in NAMES})
            publish(outputs)
            self.assertTrue(all(path.is_file() for path in outputs))

            block = {
                "fin.txt": "# a3 rules: 4\n"
                           "AND,((IP-CIDR,198.51.100.0/24,no-resolve),(DOMAIN,track.example.net))\n"
                           "DOMAIN-SUFFIX,ads.example.org\n"
                           "DOMAIN-WILDCARD,api-[0-9].example.org\n"
                           "SRC-IP,192.0.2.0/24\n",
                "fin-qx.txt": "# a3 rules: 1\nHOST-SUFFIX,ads.example.org,LIST\n",
                "fin.yaml": '# a3 rules: 5\npayload:\n'
                            '  - "AND,((IP-CIDR,198.51.100.0/24,no-resolve),(DOMAIN,track.example.net))"\n'
                            '  - "DOMAIN-REGEX,^api\\\\-[0-9]\\\\.example\\\\.org$"\n'
                            '  - "DOMAIN-SUFFIX,ads.example.org"\n'
                            '  - "PROCESS-NAME,Foo*Bar"\n'
                            '  - "SRC-IP-CIDR,192.0.2.0/24"\n',
                "fin-surge.txt": "# a3 rules: 3\n"
                                 "AND,((IP-CIDR,198.51.100.0/24,no-resolve),(DOMAIN,track.example.net))\n"
                                 "DOMAIN-WILDCARD,api-[0-9].example.org\n"
                                 "SRC-IP,192.0.2.0/24\n",
                "fin-surge-ds.txt": "# a3 rules: 1\n.ads.example.org\n",
            }
            for name, expected in block.items():
                with self.subTest(group="a3", name=name):
                    self.assertEqual((root / "a3" / name).read_text(encoding="utf-8"), expected)
            self.assertEqual((root / "a3" / "fin-adb.txt").read_text(encoding="utf-8").splitlines()[6:], [
                "! Total count: 3", "@@|safe.ads.example.org|", "||ads.example.org^",
                r"/^api\-[0-9]\.example\.org$/",
            ])
            self.assertIn("a3 fin-qx.txt:SRC-IP-CIDR: 1", warnings.getvalue())
            self.assertIn("a3 fin-qx.txt:DOMAIN-WILDCARD: 1", warnings.getvalue())
            self.assertIn("a3 fin-surge.txt:PROCESS-NAME: 1", warnings.getvalue())

            direct = "OR,((IP-CIDR,203.0.113.0/24),(DOMAIN,direct.example.net))"
            self.assertEqual((root / "dirt" / "fin.txt").read_text(encoding="utf-8"),
                             f"# dirt rules: 1\n{direct}\n")
            self.assertEqual((root / "dirt" / "fin-surge.txt").read_text(encoding="utf-8"),
                             f"# dirt rules: 1\n{direct}\n")
            self.assertEqual((root / "dirt" / "fin.yaml").read_text(encoding="utf-8"),
                             f'# dirt rules: 1\npayload:\n  - "{direct}"\n')
            for name in ("fin-qx.txt", "fin-surge-ds.txt"):
                self.assertEqual((root / "dirt" / name).read_text(encoding="utf-8"),
                                 "# dirt rules: 0\n")
            self.assertEqual((root / "dirt" / "fin-adb.txt").read_text(encoding="utf-8").splitlines()[6:], [
                "! Total count: 0", "! No AdBlock rules for non-advertising group.",
            ])
            self.assertTrue(all("no-resolve" not in outputs[root / "dirt" / name] for name in NAMES))

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

    def test_dirt_whitelist_removes_requested_routes_and_keeps_unrelated_domain(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            whitelist = root / "static/main/NoDirect.list"
            whitelist.parent.mkdir(parents=True)
            whitelist.write_bytes((ROOT / "static/main/NoDirect.list").read_bytes())
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "dirt", "purpose": "direct", "no_resolve": "strip",
                "sources": ["direct.list"], "whitelist": ["static/main/NoDirect.list"],
            }]), encoding="utf-8")
            (root / "direct.list").write_text(
                "DOMAIN-KEYWORD,microsoft\nDOMAIN-WILDCARD,windows-*.net\n"
                "DOMAIN-SUFFIX,ms\nDOMAIN-SUFFIX,sm.ms\nDOMAIN-SUFFIX,loli.net\n"
                "DOMAIN,office.ms\nDOMAIN,cdn.loli.net\nDOMAIN,keep.example.org\n",
                encoding="utf-8",
            )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(outputs[root / "dirt" / "fin.txt"].splitlines()[1:],
                             ["DOMAIN,keep.example.org"])
            for name in ("fin-qx.txt", "fin.yaml", "fin-surge.txt", "fin-surge-ds.txt"):
                with self.subTest(name=name):
                    self.assertNotIn("microsoft", outputs[root / "dirt" / name])
                    self.assertNotIn("windows-*.net", outputs[root / "dirt" / name])
                    self.assertNotIn("loli.net", outputs[root / "dirt" / name])
                    self.assertNotIn("sm.ms", outputs[root / "dirt" / name])

    def test_html_whitelist_aborts_instead_of_silently_disabling_exclusions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["rules.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "rules.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("<html><body>login</body></html>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"allow\.list.*HTML"):
                generate(root, lambda _: self.fail("local input must not fetch"))

    def test_non_html_invalid_whitelist_aborts_but_unsupported_types_are_ignored(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["rules.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "rules.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("Login required\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"allow\.list.*invalid rule"):
                generate(root, lambda _: self.fail("local input must not fetch"))
            (root / "allow.list").write_text("USER-AGENT,*bot*,DIRECT\n", encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,ads.example.org\n", outputs[root / "a3" / "fin.txt"])

    def test_missing_or_invalid_utf8_local_whitelist_aborts_entire_round(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            with self.assertRaises(FileNotFoundError):
                publish(generate(root, lambda _: self.fail("local input must not fetch")))
            (root / "allow.list").write_bytes(b"DOMAIN,good.example.org\n\xff\n")
            with self.assertRaisesRegex(UnicodeError, "allow.list"):
                publish(generate(root, lambda _: self.fail("local input must not fetch")))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_configured_empty_whitelist_aborts_instead_of_disabling_exclusions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["rules.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "rules.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            for content in ("", "# only comments\n"):
                with self.subTest(content=content):
                    (root / "allow.list").write_text(content, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, r"allow\.list.*no rules"):
                        generate(root, lambda _: self.fail("local input must not fetch"))

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

    def test_cli_publishes_allow_only_group_and_updates_healthy_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "@@||safe.example.org^\n" if group == "a3" else "DOMAIN,current.example.org\n",
                    encoding="utf-8",
                )
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            result = subprocess.run(
                [sys.executable, str(ROOT / "generate.py"), "--root", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(all((root / "a3" / name).read_bytes() != b"previous version\n" for name in NAMES))
            self.assertEqual((root / "a3" / "fin-adb.txt").read_text(encoding="utf-8").splitlines()[6:],
                             ["! Total count: 1", "@@||safe.example.org^"])
            self.assertIn("DOMAIN,current.example.org", (root / "cdn" / "fin.txt").read_text(encoding="utf-8"))

    def test_adblock_keeps_wide_block_with_narrow_allow_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\n@@||safe.example.com^\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a3" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn("@@||safe.example.com^", outputs[root / "a3" / "fin-adb.txt"])

    def test_whitelist_keeps_broad_route_and_adds_dns_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN-SUFFIX,safe.example.com,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\nDOMAIN,ads.example.com\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a3" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn("@@||safe.example.com^", outputs[root / "a3" / "fin-adb.txt"])

    def test_exact_whitelist_keeps_broad_block_with_anchored_dns_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN,safe.example.com,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\n" if group == "a3"
                    else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a3" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn("@@|safe.example.com|", outputs[root / "a3" / "fin-adb.txt"])

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

    def test_wholly_bad_utf8_remote_source_freezes_its_group_without_stopping_others(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/broken.txt"
            configure_groups(root, sources={"a3": [url]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"\xff\xfe")
            self.assertIn(url, stderr.getvalue())
            self.assertIn("UTF-8", stderr.getvalue())
            self.assertNotIn(root / "a3" / "fin.txt", outputs)
            publish(outputs)
            self.assertTrue(all((root / "a3" / name).read_bytes() == b"previous version\n" for name in NAMES))
            self.assertIn("DOMAIN,current.example.org", (root / "cdn" / "fin.txt").read_text(encoding="utf-8"))

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

    def test_non404_http_errors_and_timeout_stop_all_publication(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/final.txt"
            configure_groups(root, sources={"dirt": [url]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            for failure in (
                error.HTTPError(url, 410, "Gone", {}, None),
                error.HTTPError(url, 429, "Too Many Requests", {}, None),
                error.HTTPError(url, 503, "Service Unavailable", {}, None),
                TimeoutError("timed out"),
                IncompleteRead(b"DOMAIN,partial.example.org", 50),
            ):
                with self.subTest(failure=str(failure)):
                    with patch("urllib.request.OpenerDirector.open", side_effect=failure):
                        with self.assertRaisesRegex(RuntimeError, url):
                            publish(generate(root, fetch_https))
                    self.assertTrue(all(
                        (root / group / name).read_bytes() == b"previous version\n"
                        for group in GROUPS for name in NAMES
                    ))

    def test_short_http_200_response_stops_all_publication(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/final.txt"
            configure_groups(root, sources={"dirt": [url]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            response = BytesIO(b"DOMAIN,partial.example.org\n")
            response.geturl = lambda: url
            response.headers = {"Content-Length": "999"}
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with self.assertRaisesRegex(ValueError, "Incomplete source"):
                    publish(generate(root, fetch_https))
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

    def test_generated_process_name_hash_is_preserved_before_replacing_six_old_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.yaml"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Game #1"\n', encoding="utf-8",
            )
            previous = {}
            for name in NAMES:
                path = root / "cdn" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = b"previous version\n"
                path.write_bytes(previous[path])
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(outputs[root / "a3" / "fin.txt"],
                             "# a3 rules: 1\nPROCESS-NAME,Game #1\n")
            self.assertEqual(outputs[root / "cdn" / "fin.txt"],
                             "# cdn rules: 1\nPROCESS-NAME,Game #1\n")
            self.assertIn('"PROCESS-NAME,Game #1"', outputs[root / "cdn" / "fin.yaml"])
            self.assertNotIn("a3/fin.txt: line 2", stderr.getvalue())
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            publish(outputs)
            self.assertEqual((root / "cdn" / "fin.txt").read_text(encoding="utf-8"),
                             outputs[root / "cdn" / "fin.txt"])

    def test_generated_process_comment_markers_survive_six_output_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.yaml"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Game ;1"\n'
                '  - "PROCESS-NAME,Game //1"\n', encoding="utf-8",
            )
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "cdn") for name in NAMES})
            for group in ("a3", "cdn"):
                self.assertEqual(outputs[root / group / "fin.txt"],
                                 f"# {group} rules: 2\nPROCESS-NAME,Game ;1\nPROCESS-NAME,Game //1\n")
                self.assertIn('"PROCESS-NAME,Game //1"', outputs[root / group / "fin.yaml"])
                self.assertIn('"PROCESS-NAME,Game ;1"', outputs[root / group / "fin.yaml"])
            self.assertNotIn("a3/fin.txt: line", stderr.getvalue())
            publish(outputs)
            self.assertTrue(all(path.read_text(encoding="utf-8") == text
                                for path, text in outputs.items()))

    def test_process_regex_policy_token_is_not_truncated_in_six_output_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "direct", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "cdn", "purpose": "direct", "no_resolve": "keep",
                 "sources": ["a3/fin.yaml"], "whitelist": []},
            ]), encoding="utf-8")
            values = [f"^Game,DIRECT {marker}1$" for marker in (";", "#", "//")]
            values.append("^Game,'s$")
            (root / "source.list").write_text(
                "".join(f'PROCESS-NAME-REGEX,"{value}",DIRECT # note\n' for value in values),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "cdn") for name in NAMES})
            for group in ("a3", "cdn"):
                text = outputs[root / group / "fin.yaml"]
                self.assertEqual(sorted(json.loads(line.removeprefix("  - "))
                                        for line in text.splitlines()[2:]),
                                 sorted(f"PROCESS-NAME-REGEX,{value}" for value in values))
            self.assertNotIn("source.list: line", stderr.getvalue())
            self.assertNotIn("a3/fin.yaml: line", stderr.getvalue())

    def test_domain_regex_comment_group_and_tail_survive_yaml_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "cdn", "purpose": "block", "no_resolve": "keep",
                 "sources": ["a3/fin.yaml"], "whitelist": []},
            ]), encoding="utf-8")
            scoped = r"^(?x:(?#note)a)\.example\.com$"
            (root / "source.list").write_text(
                "DOMAIN-REGEX,^foo$,REJECT # note,REJECT\n"
                f"DOMAIN-REGEX,{scoped},REJECT\n"
                "AND,((DOMAIN-REGEX,^ads$,no-resolve),(DOMAIN,x.example.com)),REJECT\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            expected = {"DOMAIN-REGEX,^foo$", f"DOMAIN-REGEX,{scoped}"}
            for group in ("a3", "cdn"):
                yaml = outputs[root / group / "fin.yaml"]
                self.assertEqual({json.loads(line.removeprefix("  - "))
                                  for line in yaml.splitlines()[2:]}, expected)
            self.assertIn("source.list: line 3: invalid logical expression", stderr.getvalue())
            self.assertNotIn("source.list: line 1:", stderr.getvalue())
            self.assertNotIn("source.list: line 2:", stderr.getvalue())
            self.assertNotIn("a3/fin.yaml: line", stderr.getvalue())

    def test_unquoted_yaml_process_markers_survive_six_output_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.yaml"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.yaml").write_text(
                "# upstream\npayload:\n  - PROCESS-NAME,Game ;1\n"
                "  - PROCESS-NAME,Game //1\n# end\n", encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "cdn") for name in NAMES})
            for group in ("a3", "cdn"):
                self.assertEqual(outputs[root / group / "fin.txt"],
                                 f"# {group} rules: 2\nPROCESS-NAME,Game ;1\nPROCESS-NAME,Game //1\n")
                self.assertIn('  - "PROCESS-NAME,Game ;1"\n', outputs[root / group / "fin.yaml"])
                self.assertIn('  - "PROCESS-NAME,Game //1"\n', outputs[root / group / "fin.yaml"])
                self.assertEqual(outputs[root / group / "fin-surge.txt"],
                                 outputs[root / group / "fin.txt"])
                for name in ("fin-qx.txt", "fin-surge-ds.txt"):
                    self.assertEqual(outputs[root / group / name], f"# {group} rules: 0\n")
                self.assertIn("! Total count: 0", outputs[root / group / "fin-adb.txt"])
            self.assertNotIn("source.yaml: line", stderr.getvalue())
            self.assertNotIn("a3/fin.txt: line", stderr.getvalue())

    def test_dependent_group_uses_current_in_memory_cdn_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"big-data": ["cdn/fin.txt"]})
            for group in GROUPS:
                if group != "big-data":
                    (root / group / "rules.txt").write_text(
                        f"DOMAIN,from-{group}.example.org\n", encoding="utf-8",
                    )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,from-cdn.example.org", outputs[root / "big-data" / "fin.txt"])
            self.assertFalse((root / "cdn" / "fin.txt").exists())

    def test_header_only_generated_dependency_replaces_stale_derived_routes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": ["allow.list"]},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
            previous = {}
            for group in ("a3", "cdn"):
                for name in NAMES:
                    path = root / group / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = "DOMAIN,stale.example.org\n"
                    path.write_text(previous[path], encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), set(previous))
            self.assertEqual(outputs[root / "a3" / "fin.txt"], "# a3 rules: 0\n")
            self.assertEqual(outputs[root / "cdn" / "fin.txt"], "# cdn rules: 0\n")
            publish(outputs)
            for path in previous:
                self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                self.assertNotIn("stale.example.org", outputs[path])

    def test_header_only_yaml_and_adblock_dependencies_remain_empty(self):
        for filename in ("fin.yaml", "fin-adb.txt"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": ["allow.list"]},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": [f"a3/{filename}"], "whitelist": []},
                ]), encoding="utf-8")
                (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
                (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda _: self.fail("local input must not fetch"))
                self.assertEqual(outputs[root / "cdn" / "fin.txt"], "# cdn rules: 0\n")
                self.assertEqual({root / "cdn" / name for name in NAMES},
                                 {path for path in outputs if path.parent.name == "cdn"})

    def test_header_only_generated_whitelist_allows_downstream_publication(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": ["allow.list"]},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["cdn.list"], "whitelist": ["a3/fin.txt"]},
            ]), encoding="utf-8")
            (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
            (root / "cdn.list").write_text("DOMAIN,keep.example.org\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "cdn" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = b"DOMAIN,stale.example.org\n"
                path.write_bytes(previous[path])
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(outputs[root / "a3" / "fin.txt"], "# a3 rules: 0\n")
            self.assertEqual(outputs[root / "cdn" / "fin.txt"],
                             "# cdn rules: 1\nDOMAIN,keep.example.org\n")
            publish(outputs)
            self.assertTrue(all(path.read_bytes() != previous[path] for path in previous))

    def test_nonempty_unadaptable_generated_whitelist_aborts_before_publish(self):
        for source_rule, line in (
            ("PROCESS-NAME,Game.exe,REJECT\n", 3),
            ("DOMAIN,exclude.example.org,REJECT\nPROCESS-NAME,Game.exe,REJECT\n", 4),
        ):
            with self.subTest(line=line), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": []},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["cdn.list"], "whitelist": ["a3/fin.yaml"]},
                ]), encoding="utf-8")
                (root / "source.list").write_text(source_rule, encoding="utf-8")
                (root / "cdn.list").write_text("DOMAIN,exclude.example.org\n", encoding="utf-8")
                previous = {}
                for name in NAMES:
                    path = root / "cdn" / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = b"previous version\n"
                    path.write_bytes(previous[path])
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, rf"a3.*fin\.yaml.*line {line}"):
                        publish(generate(root, lambda _: self.fail("local input must not fetch")))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    @unittest.skipUnless(os.name == "nt", "WindowsPath case-insensitive dependency")
    def test_case_variant_header_only_generated_dependencies_stay_empty(self):
        for filename in ("FIN.YAML", "FIN-ADB.TXT"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": ["allow.list"]},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": [f"a3/{filename}"], "whitelist": []},
                ]), encoding="utf-8")
                (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
                (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda _: self.fail("local input must not fetch"))
                self.assertEqual(outputs[root / "cdn" / "fin.txt"], "# cdn rules: 0\n")
                self.assertFalse((root / "a3" / filename).exists())

    def test_mixed_generated_adblock_rules_abort_without_publishing_partial_result(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "a4", "purpose": "block", "no_resolve": "keep",
                 "sources": ["a3/fin-adb.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.list").write_text(
                "DOMAIN-SUFFIX,plain.example.org\n"
                r"DOMAIN-REGEX,^ads[0-9]+\.example\.org$" "\n", encoding="utf-8",
            )
            previous = {}
            for group in ("a3", "a4"):
                for name in NAMES:
                    path = root / group / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = f"previous {group} {name}\n".encode()
                    path.write_bytes(previous[path])
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, r"a3.*fin-adb\.txt.*line 9"):
                    publish(generate(root, lambda _: self.fail("local input must not fetch")))
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_unadaptable_generated_adblock_rules_cannot_clear_old_downstream_files(self):
        for source_rule in ("DOMAIN-SUFFIX,ads.example.org\n",
                            r"DOMAIN-REGEX,^ads[0-9]+\.example\.org$" + "\n"):
            with self.subTest(source_rule=source_rule), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": []},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["a3/fin-adb.txt"], "whitelist": []},
                ]), encoding="utf-8")
                (root / "source.list").write_text(source_rule, encoding="utf-8")
                previous = {}
                for name in NAMES:
                    path = root / "cdn" / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = b"previous version\n"
                    path.write_bytes(previous[path])
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, r"a3.*fin-adb\.txt"):
                        publish(generate(root, lambda _: self.fail("local input must not fetch")))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_missing_remote_source_with_empty_generated_dependency_freezes_downstream(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": ["allow.list"]},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt", missing], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "cdn" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = "DOMAIN,stale.example.org\n"
                path.write_text(previous[path], encoding="utf-8")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(set(outputs), {root / "a3" / name for name in NAMES})
            publish(outputs)
            self.assertEqual({path: path.read_text(encoding="utf-8") for path in previous}, previous)

    def test_forward_generated_dependency_rejects_stale_disk_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "cdn").mkdir()
            (root / "cdn" / "fin.txt").write_text("DOMAIN,stale.example.org\n", encoding="utf-8")
            (root / "new.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "big-data", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["cdn/fin.txt"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["new.list"], "whitelist": []},
            ]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not yet generated"):
                generate(root, lambda _: self.fail("local input must not fetch"))

    def test_changed_dependency_changes_the_same_round_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"big-data": ["cdn/fin.txt"]})
            for group in GROUPS:
                if group != "big-data":
                    (root / group / "rules.txt").write_text(
                        f"DOMAIN,original-{group}.example.org\n", encoding="utf-8",
                    )
            first = generate(root, lambda _: self.fail("local input must not fetch"))
            (root / "cdn" / "rules.txt").write_text(
                "DOMAIN,replaced-cdn.example.org\n", encoding="utf-8",
            )
            second = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,replaced-cdn.example.org", second[root / "big-data" / "fin.txt"])
            self.assertNotEqual(first[root / "big-data" / "fin.txt"], second[root / "big-data" / "fin.txt"])

    def test_same_remote_url_is_fetched_once_for_rules_and_whitelist(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            shared = "https://example.org/shared.txt"
            configure_groups(root, sources={"cdn": [shared], "a3": [shared, "a3/rules.txt"]},
                             whitelist={"a3": [shared]})
            for group in GROUPS:
                if group != "cdn":
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            calls = []

            def fetch(url):
                calls.append(url)
                return b"DOMAIN,shared.example.org\n"

            generate(root, fetch)
            self.assertEqual(calls, [shared])

    def test_missing_remote_source_and_whitelist_share_cached_404_and_keep_good_rules(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            good = "https://example.org/good.txt"
            configure_groups(root, sources={"a3": [missing, good]}, whitelist={"a3": [missing]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            calls = []

            def fetch(url):
                calls.append(url)
                if url == missing:
                    raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)
                return b"DOMAIN,good.example.org\n"

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, fetch)
            self.assertEqual(calls, [missing, good])
            self.assertIn("404", stderr.getvalue())
            self.assertIn(missing, stderr.getvalue())
            self.assertIn("DOMAIN,good.example.org", outputs[root / "a3" / "fin.txt"])

    def test_fetch_https_wrapped_real_http_404_freezes_existing_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/missing.txt"
            configure_groups(root, sources={"a3": [url]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            failure = error.HTTPError(url, 404, "Not Found", {}, None)
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", side_effect=failure):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            self.assertIn(f"{url}: HTTP 404", stderr.getvalue())
            self.assertNotIn(root / "a3" / "fin.txt", outputs)
            self.assertIn(root / "cdn" / "fin.txt", outputs)

    def test_all_404_freezes_group_six_files_while_healthy_groups_publish(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"a3": [missing]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "a3" / name
                previous[path] = f"previous {name}\n".encode()
                path.write_bytes(previous[path])

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertFalse(any(path.parent.name == "a3" for path in outputs))
            self.assertEqual(len(outputs), 18)
            publish(outputs)
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertIn("DOMAIN,current.example.org", (root / "cdn" / "fin.txt").read_text(encoding="utf-8"))

    def test_frozen_cdn_also_freezes_big_data_without_reading_stale_cdn_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing-cdn.txt"
            configure_groups(root, sources={"cdn": [missing],
                                            "big-data": ["cdn/fin.txt", "https://example.org/extra.txt"]})
            for group in ("a3", "dirt"):
                (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            previous = {}
            for group in ("cdn", "big-data"):
                for name in NAMES:
                    path = root / group / name
                    previous[path] = f"DOMAIN,stale-{group}.example.org\n".encode()
                    path.write_bytes(previous[path])
            calls = []

            def fetch(url):
                calls.append(url)
                if url == missing:
                    raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)
                return b"DOMAIN,extra.example.org\n"

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(calls, [missing])
            self.assertEqual(set(outputs), {root / group / name for group in ("a3", "dirt") for name in NAMES})
            publish(outputs)
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_freeze_propagates_through_multiple_generated_dependency_levels(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing-cdn.txt"
            configure_groups(root, sources={"cdn": [missing], "big-data": ["cdn/fin.txt"]})
            configs = json.loads((root / "rulesets.json").read_text(encoding="utf-8"))
            configs.append({"name": "archive", "purpose": "proxy", "no_resolve": "keep",
                            "sources": ["big-data/fin.txt"], "whitelist": []})
            (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
            for group in ("a3", "dirt"):
                (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for group in ("cdn", "big-data", "archive"):
                (root / group).mkdir(exist_ok=True)
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(set(outputs), {root / group / name for group in ("a3", "dirt") for name in NAMES})
            self.assertTrue(all(
                (root / group / name).read_bytes() == b"previous version\n"
                for group in ("cdn", "big-data", "archive") for name in NAMES
            ))

    def test_missing_local_whitelist_still_aborts_when_source_is_404(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"a3": [missing]}, whitelist={"a3": ["allow.list"]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(FileNotFoundError):
                    publish(generate(root, fetch))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_frozen_dependency_does_not_hide_missing_local_whitelist(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"cdn": [missing], "big-data": ["cdn/fin.txt"]},
                             whitelist={"big-data": ["allow.list"]})
            for group in ("a3", "dirt"):
                (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for group in ("cdn", "big-data"):
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(FileNotFoundError):
                    publish(generate(root, fetch))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_missing_old_file_in_frozen_group_aborts_entire_round(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"dirt": [missing]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    if group != "dirt" or name != "fin.yaml":
                        (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with self.assertRaisesRegex(ValueError, r"dirt.*fin.yaml"):
                publish(generate(root, fetch))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_html_labeled_mixed_source_keeps_rules_around_markup(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/mixed.txt"
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": [url], "whitelist": [],
            }]), encoding="utf-8")
            (root / "a3").mkdir()
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            response = BytesIO(b"DOMAIN,one.example\n<html>noise</html>\nDOMAIN,two.example\n")
            response.geturl = lambda: url
            response.headers = {"Content-Type": "text/html"}
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            text = outputs[root / "a3" / "fin.txt"]
            self.assertIn("DOMAIN,one.example\n", text)
            self.assertIn("DOMAIN,two.example\n", text)
            self.assertIn(f"{url}: line 2: HTML", stderr.getvalue())

    def test_http_200_html_remote_source_is_skipped_with_warning(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/login.txt"
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": [url, "good.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "good.list").write_text("DOMAIN,good.example\n", encoding="utf-8")
            response = BytesIO(b"<html><body>DOMAIN,evil.example</body></html>")
            response.geturl = lambda: url
            response.headers = {"Content-Type": "text/html"}
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            self.assertIn("DOMAIN,good.example\n", outputs[root / "a3" / "fin.txt"])
            self.assertNotIn("evil.example", outputs[root / "a3" / "fin.txt"])
            self.assertIn(f"{url}: line 1: HTML", stderr.getvalue())

    def test_remote_whitelist_html_200_is_skipped_with_warning(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"<html><body>login</body></html>")
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("HTML", stderr.getvalue())

    def test_bad_utf8_remote_line_keeps_other_complete_rules_and_line_number(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/mixed.txt"
            configure_groups(root, sources={"a3": [url]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"DOMAIN,first.example.org\nDOMAIN,\xffbad.example.org\nDOMAIN,last.example.org\n")
            text = outputs[root / "a3" / "fin.txt"]
            self.assertIn("DOMAIN,first.example.org", text)
            self.assertIn("DOMAIN,last.example.org", text)
            self.assertNotIn("bad.example.org", text)
            self.assertIn(f"{url}: line 2", stderr.getvalue())
            self.assertIn("UTF-8", stderr.getvalue())

    def test_whitelist_covering_every_block_replaces_stale_dns_and_six_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["block.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "block.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("DOMAIN,ads.example.org,DIRECT\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "a3" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = "||ads.example.org^\n" if name == "fin-adb.txt" else "previous version\n"
                path.write_text(previous[path], encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), set(previous))
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@|ads.example.org|"])
            publish(outputs)
            for path in previous:
                self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                self.assertNotEqual(outputs[path], previous[path])

    def test_whitelist_covering_ip_source_replaces_old_six_files_without_dns_exception(self):
        for group, purpose, action in (("a3", "block", "REJECT"),
                                       ("cdn", "proxy", "PROXY"),
                                       ("dirt", "direct", "DIRECT")):
            with self.subTest(group=group), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([{
                    "name": group, "purpose": purpose, "no_resolve": "keep",
                    "sources": ["source.list"], "whitelist": ["allow.list"],
                }]), encoding="utf-8")
                (root / "source.list").write_text(
                    f"IP-CIDR,203.0.113.0/24,{action}\n", encoding="utf-8",
                )
                (root / "allow.list").write_text(
                    "IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8",
                )
                previous = {}
                for name in NAMES:
                    path = root / group / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = "IP-CIDR,203.0.113.0/24\n"
                    path.write_text(previous[path], encoding="utf-8")
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
                self.assertEqual(set(outputs), set(previous))
                self.assertEqual(outputs[root / group / "fin.txt"], f"# {group} rules: 0\n")
                self.assertEqual(outputs[root / group / "fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 0"] if purpose == "block" else
                                 ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                publish(outputs)
                for path in previous:
                    self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                    self.assertNotEqual(outputs[path], previous[path])

    def test_allow_only_source_replaces_stale_dns_and_six_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["allow.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "allow.list").write_text("@@||safe.example.org^\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "a3" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = "||safe.example.org^\n" if name == "fin-adb.txt" else "previous version\n"
                path.write_text(previous[path], encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), set(previous))
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@||safe.example.org^"])
            publish(outputs)
            for path in previous:
                self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                self.assertNotEqual(outputs[path], previous[path])

    def test_unavailable_or_unadaptable_source_with_unrelated_whitelist_stays_frozen(self):
        for source in ("missing", "unadaptable"):
            with self.subTest(source=source), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                url = "https://example.org/missing.txt"
                (root / "rulesets.json").write_text(json.dumps([{
                    "name": "a3", "purpose": "block", "no_resolve": "keep",
                    "sources": [url], "whitelist": ["allow.list"],
                }]), encoding="utf-8")
                (root / "allow.list").write_text("DOMAIN,unrelated.example.org,DIRECT\n", encoding="utf-8")
                previous = {}
                for name in NAMES:
                    path = root / "a3" / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = "previous version\n"
                    path.write_text(previous[path], encoding="utf-8")

                def fetch(_):
                    if source == "missing":
                        raise RuntimeError("source unavailable") from error.HTTPError(url, 404, "Not Found", {}, None)
                    return b"UNKNOWN-TYPE,ads.example.org\n"

                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, fetch)
                self.assertEqual(outputs, {})
                publish(outputs)
                self.assertEqual({path: path.read_text(encoding="utf-8") for path in previous}, previous)

    def test_only_dns_allow_without_routable_rules_publishes_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "@@||safe.example.org^\n" if group == "a3" else "DOMAIN,current.example.org\n",
                    encoding="utf-8",
                )
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual({root / "a3" / name for name in NAMES}, {path for path in outputs if path.parent.name == "a3"})
            self.assertEqual(len(outputs), 24)
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@||safe.example.org^"])

    def test_wholly_bad_utf8_remote_whitelist_is_skipped(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"\xff\xfe")
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("skipped", stderr.getvalue())

    def test_whitelist_removing_all_routes_publishes_dns_exceptions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN,ads.example.org,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name for group in GROUPS for name in NAMES})
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@|ads.example.org|"])

    def test_remote_whitelist_unsupported_only_warns_and_skips(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"USER-AGENT,*bot*,DIRECT\n")
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("skipped", stderr.getvalue())

    def test_http_200_html_remote_whitelist_is_skipped_by_generate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            response = BytesIO(b"<html>login</html>")
            response.geturl = lambda: url
            response.headers = {"Content-Type": "text/html"}
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("HTML", stderr.getvalue())

    def test_remote_whitelist_keeps_recognized_lines_around_bad_utf8_and_unsupported(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN,remove.example.org\nDOMAIN,keep.example.org\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"DOMAIN,\xffbad.example.org\nUSER-AGENT,*bot*,DIRECT\nDOMAIN,remove.example.org,DIRECT\n")
            self.assertNotIn("DOMAIN,remove.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn("DOMAIN,keep.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn("@@|remove.example.org|", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn(f"{url}: line 1", stderr.getvalue())

    def test_a3_and_a4_freeze_independently_when_configured(self):
        for frozen in ("a3", "a4"):
            with self.subTest(frozen=frozen), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                missing = f"https://example.org/{frozen}.txt"
                groups = [
                    {"name": name, "purpose": "block", "no_resolve": "keep",
                     "sources": [missing if name == frozen else f"{name}.list"], "whitelist": []}
                    for name in ("a3", "a4")
                ]
                (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
                healthy = "a4" if frozen == "a3" else "a3"
                (root / f"{healthy}.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    path = root / frozen / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(b"previous version\n")

                def fetch(url):
                    raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, fetch)
                self.assertEqual(set(outputs), {root / healthy / name for name in NAMES})
                publish(outputs)
                self.assertTrue(all((root / frozen / name).read_bytes() == b"previous version\n" for name in NAMES))
                self.assertIn("DOMAIN,current.example.org", (root / healthy / "fin.txt").read_text(encoding="utf-8"))

    def test_remote_html_or_unsupported_only_200_source_skips_but_keeps_good_source(self):
        for body in (b"<html><body>login</body></html>", b"UNKNOWN-TYPE,ads.example.org\n"):
            with self.subTest(body=body), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                bad = "https://example.org/bad.txt"
                good = "https://example.org/good.txt"
                configure_groups(root, sources={"a3": [bad, good]})
                for group in GROUPS:
                    if group != "a3":
                        (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, lambda url: body if url == bad else b"DOMAIN,good.example.org\n")
                self.assertIn("DOMAIN,good.example.org", outputs[root / "a3" / "fin.txt"])
                self.assertIn(bad, stderr.getvalue())
                self.assertIn("skipped", stderr.getvalue())

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
            with contextlib.redirect_stderr(io.StringIO()), patch("formats.datetime") as clock:
                clock.now.side_effect = lambda tz: datetime(2026, 9, 29, tzinfo=timezone.utc).astimezone(tz)
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
            self.assertEqual(len(outputs), 24)
            self.assertEqual(set(outputs), {root / group / name for group in GROUPS for name in NAMES})
            self.assertFalse(any(path.exists() for path in outputs))
