import contextlib
import gzip
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from http import HTTPStatus
from http.client import HTTPResponse, IncompleteRead
from pathlib import Path
from unittest.mock import patch
from urllib import error, request

from generate import fetch_https, generate


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


class _WireSocket:
    def __init__(self, wire):
        self.stream = io.BytesIO(wire)

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
