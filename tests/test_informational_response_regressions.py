import contextlib
import gzip
import io
import json
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from http.client import IncompleteRead, RemoteDisconnected
from pathlib import Path
from unittest.mock import patch
from urllib import error

from formats import FILES
from generate import fetch_https, generate, publish
from tests.test_chunked_ows_regressions import _chunked
from tests.test_functional_audit_transport import RULE_BYTES, URL, _WireEndpoint, _wire


EARLY_HINTS = b"HTTP/1.1 103 Early Hints\r\nLink: </hint>; rel=preload\r\n\r\n"
PROCESSING = b"HTTP/1.1 102 Processing\r\n\r\n"
CONTINUE = b"HTTP/1.1 100 Continue\r\n\r\n"


class InformationalResponseTests(unittest.TestCase):
    def test_early_hints_reads_final_response_on_same_connection(self):
        wire = EARLY_HINTS + _wire(RULE_BYTES)
        with _WireEndpoint({URL: wire}) as endpoint:
            self.assertEqual(fetch_https(URL), b"DOMAIN,ads.example.org\n")
            self.assertEqual(endpoint.visited, [URL])
            self.assertTrue(endpoint.responses[0].closed)

    def test_multiple_hints_processing_and_continue_keep_final_headers(self):
        misleading = (b"HTTP/1.1 103 Early Hints\r\nContent-Length: 99999\r\n"
                      b"Content-Encoding: gzip\r\nLocation: http://unused.example/hint\r\n\r\n")
        for interim in (b"", CONTINUE, PROCESSING, EARLY_HINTS * 3,
                        CONTINUE + EARLY_HINTS + CONTINUE + PROCESSING + EARLY_HINTS + CONTINUE,
                        misleading):
            with self.subTest(interim=interim):
                with _WireEndpoint({URL: interim + _wire(RULE_BYTES)}) as endpoint:
                    self.assertEqual(fetch_https(URL), b"DOMAIN,ads.example.org\n")
                    self.assertEqual(endpoint.visited, [URL])
                    response = endpoint.responses[0]
                    self.assertEqual((response.status, response.code, response.msg), (200, 200, "OK"))
                    self.assertEqual(response.headers.get("Content-Length"), "23")
                    self.assertIsNone(response.headers.get("Content-Encoding"))
                    self.assertIsNone(response.headers.get("Location"))
                    self.assertTrue(response.closed)

    def test_hints_before_and_after_https_redirect_keep_final_location(self):
        final_url = "https://example.org/final.txt"
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                redirect = _wire(b"unused", status=status, headers=(("Location", "/final.txt"),))
                routes = {URL: EARLY_HINTS + redirect,
                          final_url: PROCESSING + EARLY_HINTS + _wire(RULE_BYTES)}
                with _WireEndpoint(routes) as endpoint:
                    self.assertEqual(fetch_https(URL), b"DOMAIN,ads.example.org\n")
                    self.assertEqual(endpoint.visited, [URL, final_url])
                    self.assertTrue(all(response.closed for response in endpoint.responses))
        with _WireEndpoint({URL: EARLY_HINTS + _wire(
                b"unused", status=302, headers=(("Location", "http://example.org/final.txt"),))}) as endpoint:
            with self.assertRaisesRegex(ValueError, "HTTPS redirect required"):
                fetch_https(URL)
            self.assertEqual(endpoint.visited, [URL])

    def test_final_plain_gzip_and_chunked_bytes_keep_existing_decoding(self):
        for chunked in (False, True):
            for encoding in (None, "gzip", " \tX-GzIp\t "):
                with self.subTest(chunked=chunked, encoding=encoding):
                    body = gzip.compress(RULE_BYTES, mtime=0) if encoding else RULE_BYTES
                    headers = (("Content-Encoding", encoding),) if encoding else ()
                    final = (_chunked(body, " \tChUnKeD\t ", headers=headers) if chunked
                             else _wire(body, headers=headers))
                    with _WireEndpoint({URL: EARLY_HINTS + PROCESSING + final}) as endpoint:
                        self.assertEqual(fetch_https(URL), b"DOMAIN,ads.example.org\n")
                        self.assertEqual(endpoint.visited, [URL])
                        self.assertTrue(endpoint.responses[0].closed)

    def test_final_status_and_switching_protocols_keep_errors_and_reason(self):
        for status in (101, 206, 404, 429, 500, 503):
            with self.subTest(status=status):
                final = _wire(RULE_BYTES, status=status)
                with _WireEndpoint({URL: EARLY_HINTS + final}) as endpoint:
                    with self.assertRaises(ValueError if status == 206 else RuntimeError) as caught:
                        fetch_https(URL)
                    self.assertIn(URL, str(caught.exception))
                    self.assertIn(str(status), str(caught.exception))
                    self.assertEqual(endpoint.visited, [URL])
                    if status == 206:
                        self.assertIsNone(caught.exception.__cause__)
                        self.assertTrue(endpoint.responses[0].closed)
                    else:
                        cause = caught.exception.__cause__
                        self.assertIsInstance(cause, error.HTTPError)
                        self.assertEqual(cause.code, status)
                        self.assertEqual(cause.msg, endpoint.responses[0].reason)
                        cause.close()
                        self.assertTrue(endpoint.responses[0].closed)

    def test_final_size_content_length_chunk_gzip_and_empty_checks_remain(self):
        compressed = gzip.compress(RULE_BYTES, mtime=0)
        bad_crc = bytearray(compressed)
        bad_crc[-8] ^= 1
        cases = (
            (_wire(b"a" * 129), 128, ValueError, "Source exceeds size limit", None),
            (_wire(compressed, headers=(("Content-Encoding", "gzip"),)), len(compressed) - 1,
             ValueError, "Source exceeds size limit", None),
            (_wire(gzip.compress(b"a" * 129, mtime=0), headers=(("Content-Encoding", "gzip"),)),
             128, ValueError, "Decompressed source exceeds size limit", None),
            (_wire(RULE_BYTES, headers=(("Content-Length", "50"),)), 128,
             ValueError, "Incomplete source", None),
            (_wire(b"17\r\nshort", headers=(("Transfer-Encoding", "chunked"),)), 128,
             RuntimeError, "Failed to fetch", IncompleteRead),
            (_wire(b"17\r\n" + RULE_BYTES + b"\r\n", headers=(("Transfer-Encoding", "chunked"),)),
             128, RuntimeError, "Failed to fetch", IncompleteRead),
            (_wire(bytes(bad_crc), headers=(("Content-Encoding", "gzip"),)), 128,
             RuntimeError, "Incomplete or invalid gzip", gzip.BadGzipFile),
            (_chunked(compressed[:-5], headers=(("Content-Encoding", "gzip"),)), 128,
             RuntimeError, "Incomplete or invalid gzip", EOFError),
            (_wire(b""), 128, ValueError, "Source is empty", None),
            (_chunked(gzip.compress(b"", mtime=0), headers=(("Content-Encoding", "gzip"),)), 128,
             ValueError, "Source is empty", None),
        )
        for final, maximum, exception, message, cause in cases:
            with self.subTest(message=message, cause=cause):
                with _WireEndpoint({URL: EARLY_HINTS + final}) as endpoint, patch("generate.MAX_BYTES", maximum):
                    with self.assertRaisesRegex(exception, message) as caught:
                        fetch_https(URL)
                    self.assertIn(URL, str(caught.exception))
                    if cause:
                        self.assertIsInstance(caught.exception.__cause__, cause)
                    else:
                        self.assertIsNone(caught.exception.__cause__)
                    self.assertEqual(endpoint.visited, [URL])
                    self.assertTrue(endpoint.responses[0].closed)
        for final in (_wire(b"a" * 128), _chunked(b"a" * 128),
                      _chunked(gzip.compress(b"a" * 128, mtime=0), headers=(("Content-Encoding", "gzip"),))):
            with self.subTest(final=final):
                with _WireEndpoint({URL: EARLY_HINTS + final}), patch("generate.MAX_BYTES", 128):
                    self.assertEqual(fetch_https(URL), b"a" * 128)

    def test_missing_final_response_is_propagated_and_closed(self):
        for interim in (EARLY_HINTS, EARLY_HINTS + PROCESSING + CONTINUE):
            with self.subTest(interim=interim):
                with _WireEndpoint({URL: interim}) as endpoint:
                    with self.assertRaises(RemoteDisconnected):
                        fetch_https(URL)
                    self.assertEqual(endpoint.visited, [URL])
                    self.assertTrue(endpoint.responses[0].closed)
                    self.assertTrue(endpoint.sockets[0].stream.closed)

    def test_error_while_reading_final_headers_closes_without_retry(self):
        failure = TimeoutError("final response timed out")

        class InterruptedWire(io.BytesIO):
            def readline(self, size=-1):
                if self.tell() >= len(EARLY_HINTS):
                    raise failure
                return super().readline(size)

        with _WireEndpoint({URL: lambda: InterruptedWire(EARLY_HINTS)}) as endpoint:
            with self.assertRaisesRegex(RuntimeError, "Failed to fetch") as caught:
                fetch_https(URL)
            self.assertIn(URL, str(caught.exception))
            self.assertIs(caught.exception.__cause__, failure)
            self.assertEqual(endpoint.visited, [URL])
            self.assertTrue(endpoint.responses[0].closed)
            self.assertTrue(endpoint.sockets[0].stream.closed)


class InformationalGenerateTests(unittest.TestCase):
    def test_source_white_encodings_redirects_and_nine_options_match_without_interim(self):
        white_url = "https://example.org/white.txt"
        source = (b"\xef\xbb\xbfDOMAIN,ads.example.org\r\nDOMAIN,keep.example.org\r\n"
                  b"IP-CIDR,192.0.2.0/24\r\nIP-CIDR,198.51.100.0/24,no-resolve\r\n"
                  b"SRC-IP,203.0.113.0/24\r\nIP-SUFFIX,192.0.7.1/24\r\n")
        white = b"DOMAIN,ads.example.org\r\n"
        for purpose in ("block", "direct", "proxy"):
            for mode in ("add", "strip", "keep"):
                for role in ("source", "white"):
                    for encoding in ("plain", "gzip", "chunked", "chunked-gzip"):
                        for redirect in (False, True):
                            with self.subTest(purpose=purpose, mode=mode, role=role,
                                              encoding=encoding, redirect=redirect), tempfile.TemporaryDirectory() as directory:
                                root = Path(directory).resolve()
                                local = root / "static" / "input.txt"
                                local.parent.mkdir()
                                local.write_bytes(b"DOMAIN,local.example.org\r\n")
                                config = root / "rulesets.json"
                                config.write_text(json.dumps([{
                                    "name": "sample", "purpose": purpose, "no_resolve": mode,
                                    "sources": [URL, URL, "static/input.txt"],
                                    "whitelist": [white_url, white_url],
                                }]), encoding="utf-8")
                                inputs = {path: path.read_bytes() for path in (local, config)}
                                results = []
                                for interim in (b"", EARLY_HINTS + PROCESSING + CONTINUE):
                                    routes, visited = {}, []
                                    selected = URL if role == "source" else white_url
                                    for url, body in ((URL, source), (white_url, white)):
                                        if url != selected:
                                            routes[url] = _wire(body)
                                            visited.append(url)
                                            continue
                                        compressed = "gzip" in encoding
                                        data = gzip.compress(body, mtime=0) if compressed else body
                                        headers = (("Content-Encoding", " \tX-GzIp\t "),) if compressed else ()
                                        final = (_chunked(data, " \tChUnKeD\t ", headers=headers)
                                                 if "chunked" in encoding else _wire(data, headers=headers))
                                        if redirect:
                                            target = url + "?final"
                                            routes[url] = interim + _wire(b"unused", status=302,
                                                                          headers=(("Location", target),))
                                            routes[target] = interim + final
                                            visited.extend((url, target))
                                        else:
                                            routes[url] = interim + final
                                            visited.append(url)
                                    with patch("formats.datetime") as clock, _WireEndpoint(routes) as endpoint, \
                                            contextlib.redirect_stderr(io.StringIO()) as messages:
                                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                                        outputs = generate(root, fetch_https)
                                        publish(outputs, root=root)
                                        self.assertEqual(endpoint.visited, visited)
                                        self.assertTrue(all(response.closed for response in endpoint.responses))
                                    actual = {path.name: path.read_bytes() for path in outputs}
                                    self.assertEqual(set(actual), set(FILES))
                                    self.assertEqual(actual, {path.name: text.encode("utf-8")
                                                              for path, text in outputs.items()})
                                    flag = ",no-resolve" if mode == "add" else ""
                                    existing_flag = "" if mode == "strip" else ",no-resolve"
                                    self.assertEqual(outputs[root / "sample" / "fin.txt"].splitlines()[1:], [
                                        "DOMAIN,keep.example.org", "DOMAIN,local.example.org",
                                        "IP-CIDR,192.0.2.0/24" + flag,
                                        "IP-CIDR,198.51.100.0/24" + existing_flag,
                                        "SRC-IP,203.0.113.0/24",
                                    ])
                                    self.assertIn("sample fin.txt:IP-SUFFIX: 1\n", messages.getvalue())
                                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                                    results.append((actual, messages.getvalue()))
                                self.assertEqual(results[1], results[0])

    def test_published_bytes_keep_same_round_and_disk_only_dependencies(self):
        for purpose in ("block", "direct", "proxy"):
            for mode in ("add", "strip", "keep"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    local = root / "static" / "input.txt"
                    local.parent.mkdir()
                    local.write_bytes(b"DOMAIN,ads.example.org\r\nDOMAIN,keep.example.org\r\n")
                    parent = dict(name="parent", purpose=purpose, no_resolve=mode,
                                  sources=[URL], whitelist=[])
                    config = root / "rulesets.json"
                    config.write_text(json.dumps([parent]), encoding="utf-8")
                    expected = {}
                    with patch("formats.datetime") as clock, warnings.catch_warnings():
                        warnings.simplefilter("always")
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        for interim in (b"", EARLY_HINTS):
                            routes = {URL: interim + _chunked(gzip.compress(
                                RULE_BYTES + b"IP-CIDR,192.0.2.0/24,no-resolve\n", mtime=0),
                                headers=(("Content-Encoding", "gzip"),))}
                            for name in FILES:
                                if name == "fin-adb.txt" and purpose != "block":
                                    continue
                                for role in ("source", "white"):
                                    child = dict(name="child", purpose=purpose, no_resolve=mode,
                                                 sources=["parent/" + name] if role == "source" else ["static/input.txt"],
                                                 whitelist=[] if role == "source" else ["parent/" + name])
                                    for disk_only in (False, True):
                                        with self.subTest(name=name, role=role, disk_only=disk_only):
                                            config.write_text(json.dumps([child] if disk_only else [parent, child]),
                                                              encoding="utf-8")
                                            with _WireEndpoint(routes) as endpoint, \
                                                    contextlib.redirect_stderr(io.StringIO()) as messages:
                                                outputs = generate(root, fetch_https)
                                                publish(outputs, root=root)
                                                self.assertEqual(endpoint.visited, [] if disk_only else [URL])
                                            actual = {path.name: path.read_bytes() for path in outputs
                                                      if path.parent.name == "child"}
                                            self.assertEqual(set(actual), set(FILES))
                                            if role == "white":
                                                self.assertIn("DOMAIN,keep.example.org",
                                                              outputs[root / "child" / "fin.txt"])
                                            elif name == "fin-surge.txt":
                                                self.assertIn("IP-CIDR,192.0.2.0/24",
                                                              outputs[root / "child" / "fin.txt"])
                                            else:
                                                self.assertIn("ads.example.org", "".join(outputs.values()))
                                            result = actual, messages.getvalue()
                                            key = name, role, disk_only
                                            if not interim:
                                                expected[key] = result
                                            else:
                                                self.assertEqual(result, expected[key])
                    self.assertEqual(local.read_bytes(), b"DOMAIN,ads.example.org\r\nDOMAIN,keep.example.org\r\n")

    def test_shared_source_and_white_url_uses_one_get_and_keeps_uncovered_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            local = root / "static" / "input.txt"
            local.parent.mkdir()
            local.write_bytes(b"DOMAIN,keep.example.org\r\n")
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "sample", "purpose": "block", "no_resolve": "keep",
                "sources": [URL, URL, "static/input.txt"], "whitelist": [URL, URL],
            }]), encoding="utf-8")
            with _WireEndpoint({URL: EARLY_HINTS + _wire(RULE_BYTES)}) as endpoint:
                outputs = generate(root, fetch_https)
                publish(outputs, root=root)
                self.assertEqual(endpoint.visited, [URL])
                self.assertTrue(endpoint.responses[0].closed)
            self.assertEqual(outputs[root / "sample" / "fin.txt"].splitlines()[1:],
                             ["DOMAIN,keep.example.org"])

    def test_final_404_is_cached_and_freezes_old_dependents(self):
        good = "https://example.org/good.txt"
        target = "https://example.org/missing-final.txt"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            local = root / "static" / "input.txt"
            local.parent.mkdir()
            local.write_bytes(b"DOMAIN,local.example.org\r\n")
            configs = [
                dict(name="frozen", sources=[URL, URL], whitelist=[]),
                dict(name="healthy", sources=[URL, good], whitelist=[URL]),
                dict(name="dependent", sources=["frozen/fin.txt"], whitelist=[]),
            ]
            for group in configs:
                group.update(purpose="block", no_resolve="keep")
            config = root / "rulesets.json"
            config.write_text(json.dumps(configs), encoding="utf-8")
            previous = {}
            for group in ("frozen", "dependent"):
                (root / group).mkdir()
                for name in FILES:
                    path = root / group / name
                    path.write_bytes(f"old {group} {name}\r\n".encode())
                    previous[path] = path.read_bytes()
            inputs = {path: path.read_bytes() for path in (local, config)}
            routes = {URL: EARLY_HINTS + _wire(b"unused", status=302, headers=(("Location", target),)),
                      target: EARLY_HINTS + _wire(b"missing", status=404),
                      good: EARLY_HINTS + _wire(b"DOMAIN,keep.example.org\n")}
            with _WireEndpoint(routes) as endpoint, contextlib.redirect_stderr(io.StringIO()) as messages:
                outputs = generate(root, fetch_https)
                publish(outputs, root=root)
                self.assertEqual(endpoint.visited, [URL, target, good])
            self.assertEqual(set(outputs), {root / "healthy" / name for name in FILES})
            self.assertEqual(outputs[root / "healthy" / "fin.txt"].splitlines()[1:],
                             ["DOMAIN,keep.example.org"])
            self.assertEqual(messages.getvalue(), f"{URL}: HTTP 404; skipped\n")
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_final_failures_do_not_publish_any_group_or_change_inputs(self):
        compressed = gzip.compress(RULE_BYTES, mtime=0)
        bad_crc = bytearray(compressed)
        bad_crc[-8] ^= 1
        finals = [(_wire(b"error", status=status), ValueError if status == 206 else RuntimeError)
                  for status in (101, 206, 429, 500, 503)]
        finals += [(_wire(RULE_BYTES, headers=(("Content-Length", "50"),)), ValueError),
                   (_wire(b"17\r\nshort", headers=(("Transfer-Encoding", "chunked"),)), RuntimeError),
                   (_wire(bytes(bad_crc), headers=(("Content-Encoding", "gzip"),)), RuntimeError),
                   (_wire(compressed[:-5], headers=(("Content-Encoding", "gzip"),)), RuntimeError),
                   (b"", RemoteDisconnected)]
        for role in ("source", "white"):
            for final, exception in finals:
                with self.subTest(role=role, final=final), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    local = root / "static" / "input.txt"
                    local.parent.mkdir()
                    local.write_bytes(b"DOMAIN,local.example.org\r\n")
                    configs = [dict(name="healthy", sources=["static/input.txt"], whitelist=[]),
                               dict(name="failed", sources=[URL] if role == "source" else ["static/input.txt"],
                                    whitelist=[] if role == "source" else [URL])]
                    for group in configs:
                        group.update(purpose="block", no_resolve="keep")
                    config = root / "rulesets.json"
                    config.write_text(json.dumps(configs), encoding="utf-8")
                    previous = {path: path.read_bytes() for path in (local, config)}
                    for group in ("healthy", "failed"):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            path.write_bytes(f"old {group} {name}\r\n".encode())
                            previous[path] = path.read_bytes()
                    with _WireEndpoint({URL: EARLY_HINTS + final}) as endpoint, \
                            contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(exception):
                            publish(generate(root, fetch_https), root=root)
                        self.assertEqual(endpoint.visited, [URL])
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
