import contextlib
import gzip
import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from http import HTTPStatus
from http.client import HTTPResponse, IncompleteRead
from pathlib import Path
from unittest.mock import patch
from urllib import error, request

from generate import fetch_https, generate, publish
from tests.test_formats import expected_domain


URL = "https://example.org/list.txt"
RULE_BYTES = b"DOMAIN,ads.example.org\n"


def _wire(body, *, status=200, headers=()):
    headers = list(headers)
    if not any(name.lower() in ("content-length", "transfer-encoding")
               for name, _ in headers):
        headers.append(("Content-Length", str(len(body))))
    head = f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
    head += "".join(f"{name}:{value}\r\n" for name, value in headers)
    return head.encode("latin-1") + b"\r\n" + body


class _UnreadBody(io.BytesIO):
    # 端点在 header 之后拒绝任何读取，不产生无限网络流或等待。
    def __init__(self, wire, body_start):
        super().__init__(wire)
        self.body_start = body_start
        self.body_read_attempts = 0

    def _check_body(self):
        if self.tell() >= self.body_start:
            self.body_read_attempts += 1
            raise AssertionError("redirect body read attempted")

    def read(self, size=-1):
        self._check_body()
        return super().read(size)

    def readline(self, size=-1):
        self._check_body()
        return super().readline(size)

    def readinto(self, buffer):
        self._check_body()
        return super().readinto(buffer)


def _redirect(location, *, status=302, body=b"unused redirect body", chunked=False):
    headers = [("Location", location)]
    if chunked:
        headers.append(("Transfer-Encoding", "chunked"))
    wire = _wire(body, status=status, headers=headers)
    return lambda: _UnreadBody(wire, len(wire) - len(body))


class _WireSocket:
    def __init__(self, wire):
        self.stream = wire() if callable(wire) else io.BytesIO(wire)

    def makefile(self, mode):
        return self.stream


class _WireEndpoint:
    # 仅替换 TLS/外部端点，HTTPResponse、handler 链和 gzip 均使用标准库。
    def __init__(self, routes):
        self.routes = routes
        self.visited = []
        self.responses = []
        self.sockets = []

    def open(self, req):
        self.visited.append(req.full_url)
        sock = _WireSocket(self.routes[req.full_url])
        response = HTTPResponse(sock)
        response.begin()
        response.url = req.full_url
        response.msg = response.reason
        self.responses.append(response)
        self.sockets.append(sock)
        return response

    def __enter__(self):
        self.network = patch.object(request.HTTPSHandler, "https_open", self.open)
        self.network.start()
        return self

    def __exit__(self, *exc):
        self.network.stop()
        for response in self.responses:
            response.close()


class GzipTransportTests(unittest.TestCase):
    def test_wire_gzip_alias_and_ascii_ows_return_original_rule_bytes(self):
        compressed = gzip.compress(RULE_BYTES)
        for encoding in ("gzip", "GzIp", "gzip ", "\tgzip\t", " \tGzIp\t ",
                         "x-gzip", "X-GzIp", " \tX-GzIp\t "):
            with self.subTest(encoding=encoding):
                wire = _wire(compressed, headers=(("Content-Encoding", encoding),))
                with _WireEndpoint({URL: wire}):
                    self.assertEqual(fetch_https(URL), RULE_BYTES)

    def test_other_encoding_tokens_are_not_decoded(self):
        compressed = gzip.compress(RULE_BYTES)
        for encoding in ("\xa0gzip\xa0", "\vgzip\v", "gzip, x-gzip", "br", "identity"):
            with self.subTest(encoding=encoding):
                wire = _wire(compressed, headers=(("Content-Encoding", encoding),))
                with _WireEndpoint({URL: wire}):
                    self.assertEqual(fetch_https(URL), compressed)

    def test_wire_compressed_and_decompressed_size_limits(self):
        compressed = gzip.compress(RULE_BYTES)
        for encoding in ("gzip", " \tGzIp\t ", " \tX-GzIp\t "):
            cases = (
                (compressed, len(compressed) - 1, "Source exceeds size limit"),
                (gzip.compress(b"a" * 129), 128, "Decompressed source exceeds size limit"),
                (gzip.compress(b"a" * 128), 128, None),
            )
            for body, maximum, message in cases:
                with self.subTest(encoding=encoding, maximum=maximum, message=message):
                    wire = _wire(body, headers=(("Content-Encoding", encoding),))
                    with _WireEndpoint({URL: wire}), patch("generate.MAX_BYTES", maximum):
                        if message:
                            with self.assertRaisesRegex(ValueError, message) as caught:
                                fetch_https(URL)
                            self.assertIn(URL, str(caught.exception))
                        else:
                            self.assertEqual(fetch_https(URL), b"a" * 128)

    def test_wire_uncompressed_size_limit_includes_exact_boundary(self):
        for size in (128, 129):
            with self.subTest(size=size):
                with _WireEndpoint({URL: _wire(b"a" * size)}), patch("generate.MAX_BYTES", 128):
                    if size == 128:
                        self.assertEqual(fetch_https(URL), b"a" * 128)
                    else:
                        with self.assertRaisesRegex(ValueError, "Source exceeds size limit") as caught:
                            fetch_https(URL)
                        self.assertIn(URL, str(caught.exception))

    def test_wire_short_content_length_is_rejected_before_gzip(self):
        for encoding in (None, " \tX-GzIp\t "):
            with self.subTest(encoding=encoding):
                body = RULE_BYTES if encoding is None else gzip.compress(RULE_BYTES)
                headers = [("Content-Length", str(len(body) + 10))]
                if encoding is not None:
                    headers.append(("Content-Encoding", encoding))
                with _WireEndpoint({URL: _wire(body, headers=headers)}):
                    with self.assertRaisesRegex(ValueError, "Incomplete source") as caught:
                        fetch_https(URL)
                self.assertIn(URL, str(caught.exception))

    def test_wire_invalid_crc_and_truncated_gzip_preserve_url_and_cause(self):
        compressed = gzip.compress(RULE_BYTES)
        bad_crc = bytearray(compressed)
        bad_crc[-8] ^= 1
        for encoding in ("gzip", " \tGzIp\t ", " \tX-GzIp\t "):
            for body, cause in ((bytes(bad_crc), gzip.BadGzipFile),
                                (compressed[:-5], EOFError),
                                (b"not-gzip", gzip.BadGzipFile)):
                with self.subTest(encoding=encoding, cause=cause):
                    wire = _wire(body, headers=(("Content-Encoding", encoding),))
                    with _WireEndpoint({URL: wire}):
                        with self.assertRaisesRegex(RuntimeError, "Incomplete or invalid gzip") as caught:
                            fetch_https(URL)
                    self.assertIn(URL, str(caught.exception))
                    self.assertIsInstance(caught.exception.__cause__, cause)

    def test_wire_empty_plain_or_decoded_body_is_unusable(self):
        for encoding in (None, " \tGzIp\t ", " \tX-GzIp\t "):
            with self.subTest(encoding=encoding):
                body = b"" if encoding is None else gzip.compress(b"")
                headers = () if encoding is None else (("Content-Encoding", encoding),)
                with _WireEndpoint({URL: _wire(body, headers=headers)}):
                    with self.assertRaisesRegex(ValueError, "Source is empty") as caught:
                        fetch_https(URL)
                self.assertIn(URL, str(caught.exception))

    def test_wire_status_and_incomplete_chunk_preserve_url_and_cause(self):
        for status, exception, cause in ((206, ValueError, None),
                                         (503, RuntimeError, error.HTTPError)):
            with self.subTest(status=status):
                with _WireEndpoint({URL: _wire(RULE_BYTES, status=status)}):
                    with self.assertRaises(exception) as caught:
                        fetch_https(URL)
                self.assertIn(URL, str(caught.exception))
                self.assertIn(str(status), str(caught.exception))
                if cause is None:
                    self.assertIsNone(caught.exception.__cause__)
                else:
                    self.assertIsInstance(caught.exception.__cause__, cause)
        wire = _wire(b"10\r\nshort", headers=(("Transfer-Encoding", "chunked"),))
        with _WireEndpoint({URL: wire}):
            with self.assertRaises(RuntimeError) as caught:
                fetch_https(URL)
        self.assertIn(URL, str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, IncompleteRead)

    def test_network_errors_keep_original_cause_and_source_url(self):
        for failure in (error.URLError("TLS endpoint failed"), TimeoutError("timed out")):
            with self.subTest(failure=failure):
                with patch.object(request.HTTPSHandler, "https_open", side_effect=failure):
                    with self.assertRaises(RuntimeError) as caught:
                        fetch_https(URL)
                self.assertIn(URL, str(caught.exception))
                self.assertIs(caught.exception.__cause__, failure)

    def test_wire_gzip_source_and_remote_whitelist_generate_six_files(self):
        white_url = "https://example.org/white.txt"
        source = RULE_BYTES + b"DOMAIN,keep.example.org\n"
        for purpose in ("block", "direct", "proxy"):
            for source_encoding, white_encoding in ((" \tGzIp\t ", " \tX-GzIp\t "),
                                                     (" \tX-GzIp\t ", " \tGzIp\t ")):
                with self.subTest(purpose=purpose, source_encoding=source_encoding):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory).resolve()
                        (root / "rulesets.json").write_text(json.dumps([{
                            "name": "sample", "purpose": purpose, "no_resolve": "keep",
                            "sources": [URL], "whitelist": [white_url],
                        }]), encoding="utf-8")
                        plain_routes = {URL: _wire(source), white_url: _wire(RULE_BYTES)}
                        gzip_routes = {
                            URL: _wire(gzip.compress(source), headers=(("Content-Encoding", source_encoding),)),
                            white_url: _wire(gzip.compress(RULE_BYTES), headers=(("Content-Encoding", white_encoding),)),
                        }
                        with patch("formats.datetime") as clock, contextlib.redirect_stderr(io.StringIO()) as messages:
                            clock.now.return_value = datetime(2026, 10, 11, tzinfo=timezone.utc)
                            with _WireEndpoint(plain_routes):
                                expected = generate(root, fetch_https)
                            with _WireEndpoint(gzip_routes):
                                outputs = generate(root, fetch_https)
                        self.assertEqual(outputs, expected)
                        self.assertEqual({path.name for path in outputs}, {
                            "fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt",
                            "fin-surge.txt", "fin-surge-ds.txt",
                        })
                        self.assertEqual(outputs[root / "sample" / "fin.txt"].splitlines()[1:],
                                         ["DOMAIN,keep.example.org"])
                        self.assertEqual(messages.getvalue(), "" if purpose == "block" else
                                         "sample fin-adb.txt:DOMAIN: 1\n" * 2)


class RedirectTransportTests(unittest.TestCase):
    def test_wire_real_max_plus_one_redirect_bodies_are_closed_without_reading(self):
        final_url = "https://example.org/final.txt"
        rules = b"DOMAIN,ok.example.org\n"
        body = b"x" * (64 * 1024 * 1024 + 1)
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                framed = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n" if chunked else body
                routes = {URL: _redirect("/final.txt", body=framed, chunked=chunked),
                          final_url: _wire(rules)}
                with _WireEndpoint(routes) as endpoint:
                    self.assertEqual(fetch_https(URL), rules)
                    self.assertEqual(endpoint.visited, [URL, final_url])
                    self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)
                    self.assertTrue(endpoint.sockets[0].stream.closed)
                    self.assertTrue(endpoint.responses[0].closed)
                    self.assertTrue(endpoint.responses[0].isclosed())
                    self.assertEqual(endpoint.responses[0].read(), b"")
                    self.assertTrue(endpoint.responses[1].isclosed())

    def test_all_redirect_statuses_keep_relative_encoded_and_cross_host_locations(self):
        locations = (
            ("/final.txt", "https://example.org/final.txt"),
            ("../final%20rules.txt", "https://example.org/final%20rules.txt"),
            ("/r\xe9gles list.txt", "https://example.org/r%E9gles%20list.txt"),
            ("https://other.example.org/rules%2Flist.txt?x=1&y=2",
             "https://other.example.org/rules%2Flist.txt?x=1&y=2"),
            ("//other.example.org/final.txt", "https://other.example.org/final.txt"),
        )
        for status in (301, 302, 303, 307, 308):
            for location, final_url in locations:
                with self.subTest(status=status, location=location):
                    routes = {URL: _redirect(location, status=status),
                              final_url: _wire(gzip.compress(RULE_BYTES),
                                               headers=(("Content-Encoding", " \tX-GzIp\t "),))}
                    with _WireEndpoint(routes) as endpoint:
                        self.assertEqual(fetch_https(URL), RULE_BYTES)
                        self.assertEqual(endpoint.visited, [URL, final_url])
                        self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)
                        self.assertTrue(endpoint.responses[0].closed)
                        self.assertTrue(endpoint.sockets[0].stream.closed)

    def test_redirect_chain_uses_stdlib_uri_fallback_and_location_precedence(self):
        middle = "https://example.org/middle.txt"
        final_url = "https://example.org/final.txt"
        first = _wire(b"unused", status=301, headers=(("URI", "/middle.txt"),))
        second = _wire(b"unused", status=308,
                       headers=(("Location", "/final.txt"), ("URI", "/wrong.txt")))
        routes = {URL: lambda: _UnreadBody(first, len(first) - len(b"unused")),
                  middle: lambda: _UnreadBody(second, len(second) - len(b"unused")),
                  final_url: _wire(RULE_BYTES)}
        with _WireEndpoint(routes) as endpoint:
            self.assertEqual(fetch_https(URL), RULE_BYTES)
            self.assertEqual(endpoint.visited, [URL, middle, final_url])
            for response, sock in zip(endpoint.responses[:-1], endpoint.sockets[:-1]):
                self.assertTrue(response.closed)
                self.assertTrue(sock.stream.closed)
                self.assertEqual(sock.stream.body_read_attempts, 0)

    def test_https_downgrade_is_rejected_before_following_or_reading_body(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                routes = {URL: _redirect("http://other.example.org/list.txt", status=status)}
                with _WireEndpoint(routes) as endpoint:
                    with self.assertRaisesRegex(ValueError, "HTTPS redirect required") as caught:
                        fetch_https(URL)
                    self.assertIn("http://other.example.org/list.txt", str(caught.exception))
                    self.assertEqual(endpoint.visited, [URL])
                    self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)
                    self.assertFalse(endpoint.responses[0].closed)

    def test_standard_repeated_and_total_redirect_loop_limits_are_preserved(self):
        for repeated in (True, False):
            with self.subTest(repeated=repeated):
                if repeated:
                    routes = {URL: _redirect(URL)}
                    expected_visits = [URL] * 5
                else:
                    urls = [URL] + [f"https://example.org/step{number}" for number in range(1, 12)]
                    routes = {old: _redirect(new) for old, new in zip(urls, urls[1:])}
                    expected_visits = urls[:11]
                with _WireEndpoint(routes) as endpoint:
                    with self.assertRaisesRegex(RuntimeError, "Failed to fetch") as caught:
                        fetch_https(URL)
                    self.assertIn(URL, str(caught.exception))
                    self.assertIsInstance(caught.exception.__cause__, error.HTTPError)
                    self.assertEqual(caught.exception.__cause__.code, 302)
                    self.assertIn("infinite loop", str(caught.exception.__cause__))
                    self.assertEqual(endpoint.visited, expected_visits)
                    for response, sock in zip(endpoint.responses, endpoint.sockets):
                        self.assertTrue(response.closed)
                        self.assertTrue(sock.stream.closed)
                        self.assertEqual(sock.stream.body_read_attempts, 0)

    def test_unterminated_chunked_redirect_does_not_read_under_hard_timeout(self):
        script = r'''
import json
import sys
sys.path.insert(0, sys.argv[1])
from generate import fetch_https
from tests.test_functional_audit_transport import URL, RULE_BYTES, _WireEndpoint, _redirect, _wire
final_url = "https://example.org/final.txt"
routes = {URL: _redirect("/final.txt", body=b"1\r\nx\r\n", chunked=True), final_url: _wire(RULE_BYTES)}
with _WireEndpoint(routes) as endpoint:
    assert fetch_https(URL) == RULE_BYTES
    assert endpoint.visited == [URL, final_url]
    assert endpoint.responses[0].closed
    assert endpoint.sockets[0].stream.closed
    assert endpoint.sockets[0].stream.body_read_attempts == 0
print(json.dumps({"body_read_attempts": 0, "closed": True}))
'''
        completed = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                                    str(Path(__file__).resolve().parents[1])],
                                   capture_output=True, text=True, timeout=8, check=True)
        self.assertEqual(json.loads(completed.stdout), {"body_read_attempts": 0, "closed": True})

    def test_final_response_after_redirect_keeps_status_size_gzip_and_truncation_checks(self):
        final_url = "https://example.org/final.txt"
        compressed = gzip.compress(RULE_BYTES)
        bad_crc = bytearray(compressed)
        bad_crc[-8] ^= 1
        cases = (
            (_wire(b"a" * 129), ValueError, "Source exceeds size limit", None),
            (_wire(gzip.compress(b"a" * 129), headers=(("Content-Encoding", " \tX-GzIp\t "),)),
             ValueError, "Decompressed source exceeds size limit", None),
            (_wire(RULE_BYTES, status=206), ValueError, "Unexpected HTTP status 206", None),
            (_wire(RULE_BYTES, status=503), RuntimeError, "Failed to fetch", error.HTTPError),
            (_wire(RULE_BYTES, headers=(("Content-Length", "99"),)), ValueError, "Incomplete source", None),
            (_wire(compressed, headers=(("Content-Length", "99"), ("Content-Encoding", "x-gzip"))),
             ValueError, "Incomplete source", None),
            (_wire(b"10\r\nshort", headers=(("Transfer-Encoding", "chunked"),)),
             RuntimeError, "Failed to fetch", IncompleteRead),
            (_wire(bytes(bad_crc), headers=(("Content-Encoding", "x-gzip"),)),
             RuntimeError, "Incomplete or invalid gzip", gzip.BadGzipFile),
            (_wire(compressed[:-5], headers=(("Content-Encoding", "gzip"),)),
             RuntimeError, "Incomplete or invalid gzip", EOFError),
            (_wire(b"not-gzip", headers=(("Content-Encoding", "gzip"),)),
             RuntimeError, "Incomplete or invalid gzip", gzip.BadGzipFile),
            (_wire(b""), ValueError, "Source is empty", None),
            (_wire(gzip.compress(b""), headers=(("Content-Encoding", "x-gzip"),)),
             ValueError, "Source is empty", None),
        )
        for final, exception, message, cause in cases:
            with self.subTest(message=message, cause=cause):
                routes = {URL: _redirect("/final.txt"), final_url: final}
                with _WireEndpoint(routes) as endpoint, patch("generate.MAX_BYTES", 128):
                    with self.assertRaisesRegex(exception, message) as caught:
                        fetch_https(URL)
                    self.assertIn(URL, str(caught.exception))
                    if cause is None:
                        self.assertIsNone(caught.exception.__cause__)
                    else:
                        self.assertIsInstance(caught.exception.__cause__, cause)
                    self.assertEqual(endpoint.visited, [URL, final_url])
                    self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)
                    self.assertTrue(endpoint.responses[0].closed)
                    if cause is error.HTTPError:
                        self.assertEqual(caught.exception.__cause__.url, final_url)
                        self.assertIs(caught.exception.__cause__.fp, endpoint.responses[1])
                    else:
                        self.assertTrue(endpoint.responses[1].closed)

    def test_final_exact_boundaries_and_chunked_gzip_still_return_rule_bytes(self):
        final_url = "https://example.org/final.txt"
        for encoding in (None, "gzip", " \tGzIp\t ", " \tX-GzIp\t "):
            for original in ((RULE_BYTES, b"a" * 128) if encoding else (b"a" * 128,)):
                for chunked in (False, True):
                    with self.subTest(encoding=encoding, chunked=chunked, size=len(original)):
                        body = gzip.compress(original) if encoding else original
                        maximum = max(len(body), len(original))
                        headers = [("Content-Encoding", encoding)] if encoding else []
                        if chunked:
                            headers.append(("Transfer-Encoding", "chunked"))
                            body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
                        routes = {URL: _redirect("/final.txt"), final_url: _wire(body, headers=headers)}
                        with _WireEndpoint(routes) as endpoint, patch("generate.MAX_BYTES", maximum):
                            self.assertEqual(fetch_https(URL), original)
                            self.assertTrue(endpoint.responses[0].closed)
                            self.assertTrue(endpoint.responses[1].closed)
                            self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)

    def test_redirected_source_and_whitelist_generate_and_publish_six_complete_files(self):
        white_url = "https://example.org/white.txt"
        source_url = "https://source.example.org/final.txt"
        white_final = "https://white.example.org/final.txt"
        source = RULE_BYTES + b"DOMAIN,keep.example.org\n"
        for purpose in ("block", "direct", "proxy"):
            for source_encoding, white_encoding in ((" \tGzIp\t ", " \tX-GzIp\t "),
                                                     (" \tX-GzIp\t ", " \tGzIp\t ")):
                with self.subTest(purpose=purpose, source_encoding=source_encoding):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory).resolve()
                        (root / "rulesets.json").write_text(json.dumps([{
                            "name": "sample", "purpose": purpose, "no_resolve": "keep",
                            "sources": [URL], "whitelist": [white_url],
                        }]), encoding="utf-8")
                        static = root / "static" / "owned.list"
                        static.parent.mkdir()
                        static.write_bytes(b"DOMAIN,local.example.org\r\n")
                        static_before = static.read_bytes()
                        routes = {URL: _redirect(source_url, status=307),
                                  white_url: _redirect(white_final, status=308, chunked=True,
                                                       body=b"1\r\nx\r\n0\r\n\r\n"),
                                  source_url: _wire(gzip.compress(source),
                                                    headers=(("Content-Encoding", source_encoding),)),
                                  white_final: _wire(gzip.compress(RULE_BYTES),
                                                     headers=(("Content-Encoding", white_encoding),))}
                        with patch("formats.datetime") as clock, contextlib.redirect_stderr(io.StringIO()) as messages:
                            clock.now.return_value = datetime(2026, 10, 11, tzinfo=timezone.utc)
                            with _WireEndpoint(routes) as endpoint:
                                outputs = generate(root, fetch_https)
                                self.assertEqual(endpoint.visited, [URL, source_url, white_url, white_final])
                                for index in (0, 2):
                                    self.assertTrue(endpoint.responses[index].closed)
                                    self.assertEqual(endpoint.sockets[index].stream.body_read_attempts, 0)
                            publish(outputs, root=root)
                        dns_body = "@@|ads.example.org|\n0.0.0.0 keep.example.org\n" if purpose == "block" else \
                                   "! No AdBlock rules for non-advertising group.\n"
                        expected = {
                            "fin.txt": "# sample rules: 1\nDOMAIN,keep.example.org\n",
                            "fin-qx.txt": "# sample rules: 1\nHOST,keep.example.org,LIST\n",
                            "fin.yaml": '# sample rules: 1\npayload:\n  - ' + json.dumps(expected_domain("DOMAIN", "keep.example.org")) + '\n',
                            "fin-surge.txt": "# sample rules: 0\n",
                            "fin-surge-ds.txt": "# sample rules: 1\nkeep.example.org\n",
                            "fin-adb.txt": "[Adblock Plus 2.0]\n! Title: sample\n"
                                           "! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n"
                                           "! License: Inherits upstream licenses\n! Version: 202610110000\n"
                                           f"! Total count: {2 if purpose == 'block' else 0}\n" + dns_body,
                        }
                        self.assertEqual({path.name: text for path, text in outputs.items()}, expected)
                        self.assertEqual({name: (root / "sample" / name).read_bytes() for name in expected},
                                         {name: text.encode("utf-8") for name, text in expected.items()})
                        self.assertEqual(messages.getvalue(), "" if purpose == "block" else
                                         "sample fin-adb.txt:DOMAIN: 1\n")
                        self.assertEqual(static.read_bytes(), static_before)

    def test_redirected_404_is_cached_and_freezes_dependencies_without_changing_static(self):
        missing_final = "https://example.org/missing-final.txt"
        good_url = "https://example.org/good.txt"
        names = {"fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "frozen", "purpose": "block", "no_resolve": "keep",
                 "sources": [URL], "whitelist": []},
                {"name": "healthy", "purpose": "block", "no_resolve": "keep",
                 "sources": [URL, good_url], "whitelist": [URL, "static/local.list"]},
                {"name": "dependent", "purpose": "block", "no_resolve": "keep",
                 "sources": ["frozen/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            static = root / "static" / "local.list"
            static.parent.mkdir()
            static.write_bytes(b"DOMAIN,local.example.org,DIRECT\r\n")
            static_before = static.read_bytes()
            previous = {}
            for group in ("frozen", "dependent"):
                (root / group).mkdir()
                for name in names:
                    path = root / group / name
                    previous[path] = f"old complete {group} {name}\r\n".encode()
                    path.write_bytes(previous[path])
            routes = {URL: _redirect("/missing-final.txt"), missing_final: _wire(b"missing", status=404),
                      good_url: _wire(b"DOMAIN,local.example.org\nDOMAIN,keep.example.org\n")}
            with _WireEndpoint(routes) as endpoint, contextlib.redirect_stderr(io.StringIO()) as messages:
                outputs = generate(root, fetch_https)
                self.assertEqual(endpoint.visited, [URL, missing_final, good_url])
                self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)
                self.assertTrue(endpoint.responses[0].closed)
                publish(outputs, root=root)
            self.assertEqual(set(outputs), {root / "healthy" / name for name in names})
            self.assertEqual(outputs[root / "healthy" / "fin.txt"].splitlines()[1:],
                             ["DOMAIN,keep.example.org"])
            self.assertEqual(messages.getvalue(), f"{URL}: HTTP 404; skipped\n")
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertEqual(static.read_bytes(), static_before)
            with self.assertRaisesRegex(ValueError, "Output path targets static"):
                publish({static: "DOMAIN,changed.example.org\n"}, root=root)
            self.assertEqual(static.read_bytes(), static_before)
            static.write_text("UNKNOWN-TYPE,invalid\n", encoding="utf-8")
            with _WireEndpoint(routes) as endpoint:
                with self.assertRaisesRegex(ValueError, "Invalid whitelist"):
                    generate(root, fetch_https)
                self.assertEqual(endpoint.visited, [])
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
