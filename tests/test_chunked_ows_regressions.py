import contextlib
import gzip
import io
import json
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import patch
from urllib import error

from formats import FILES
from generate import fetch_https, generate, publish
from tests.test_functional_audit_transport import RULE_BYTES, URL, _WireEndpoint, _redirect, _wire


TRANSFERS = ("chunked", "ChUnKeD", "chunked ", "chunked\t", " \tChUnKeD\t ")


def _chunked(body, transfer="chunked", *, headers=(), status=200):
    framed = b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n"
                      for part in (body[:9], body[9:]) if part) + b"0\r\n\r\n"
    return _wire(framed, status=status,
                 headers=(("Transfer-Encoding", transfer), *headers))


class ChunkedOwsTests(unittest.TestCase):
    def test_complete_plain_and_gzip_chunks_return_original_bytes(self):
        for transfer in TRANSFERS:
            for encoding in (None, "gzip", " \tX-GzIp\t "):
                with self.subTest(transfer=transfer, encoding=encoding):
                    body = gzip.compress(RULE_BYTES, mtime=0) if encoding else RULE_BYTES
                    headers = (("Content-Encoding", encoding),) if encoding else ()
                    with _WireEndpoint({URL: _chunked(body, transfer, headers=headers)}) as endpoint:
                        self.assertEqual(fetch_https(URL), RULE_BYTES)
                        self.assertTrue(endpoint.responses[0].closed)

    def test_missing_zero_or_short_chunk_rejects_incomplete_source(self):
        for transfer in TRANSFERS:
            for body in (b"17\r\n" + RULE_BYTES + b"\r\n", b"17\r\nDOMAIN,ads"):
                with self.subTest(transfer=transfer, body=body):
                    wire = _wire(body, headers=(("Transfer-Encoding", transfer),))
                    with _WireEndpoint({URL: wire}) as endpoint:
                        with self.assertRaisesRegex(RuntimeError, "Failed to fetch") as caught:
                            fetch_https(URL)
                        self.assertIn(URL, str(caught.exception))
                        self.assertIsInstance(caught.exception.__cause__, IncompleteRead)
                        self.assertTrue(endpoint.responses[0].closed)

    def test_truncated_source_or_white_keeps_all_old_outputs_and_static(self):
        for transfer in TRANSFERS:
            for role in ("source", "white"):
                with self.subTest(transfer=transfer, role=role), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    static = root / "static" / "input.txt"
                    static.parent.mkdir()
                    static.write_bytes(RULE_BYTES + b"DOMAIN,keep.example.org\r\n")
                    static_before = static.read_bytes()
                    groups = [
                        dict(name="healthy", sources=["static/input.txt"], whitelist=[]),
                        dict(name="parent", sources=[URL] if role == "source" else ["static/input.txt"],
                             whitelist=[] if role == "source" else [URL]),
                        dict(name="child", sources=["parent/fin.txt"], whitelist=[]),
                    ]
                    for group in groups:
                        group.update(purpose="block", no_resolve="keep")
                    (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
                    previous = {}
                    for group in groups:
                        (root / group["name"]).mkdir()
                        for name in FILES:
                            path = root / group["name"] / name
                            previous[path] = f"old {group['name']} {name}\r\n".encode()
                            path.write_bytes(previous[path])
                    wire = _wire(b"17\r\n" + RULE_BYTES + b"\r\n",
                                 headers=(("Transfer-Encoding", transfer),))
                    with _WireEndpoint({URL: wire}), contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(RuntimeError) as caught:
                            publish(generate(root, fetch_https), root=root)
                    self.assertIsInstance(caught.exception.__cause__, IncompleteRead)
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    self.assertEqual(static.read_bytes(), static_before)

    def test_content_size_limits_exclude_framing_and_keep_exact_boundaries(self):
        compressed = gzip.compress(RULE_BYTES, mtime=0)
        for transfer in TRANSFERS:
            for encoding in (None, "gzip", "x-gzip"):
                cases = ((b"a" * 128, 128, None),
                         (b"a" * 129, 128, "Source exceeds size limit")) if encoding is None else (
                    (compressed, len(compressed), None),
                    (compressed, len(compressed) - 1, "Source exceeds size limit"),
                    (gzip.compress(b"a" * 128, mtime=0), 128, None),
                    (gzip.compress(b"a" * 129, mtime=0), 128, "Decompressed source exceeds size limit"),
                )
                headers = (("Content-Encoding", encoding),) if encoding else ()
                for body, maximum, message in cases:
                    with self.subTest(transfer=transfer, encoding=encoding, maximum=maximum, message=message):
                        with _WireEndpoint({URL: _chunked(body, transfer, headers=headers)}) as endpoint, \
                                patch("generate.MAX_BYTES", maximum):
                            if message:
                                with self.assertRaisesRegex(ValueError, message) as caught:
                                    fetch_https(URL)
                                self.assertIn(URL, str(caught.exception))
                            else:
                                self.assertEqual(fetch_https(URL), RULE_BYTES if body == compressed else b"a" * 128)
                            self.assertTrue(endpoint.responses[0].closed)

    def test_chunked_gzip_keeps_crc_truncation_and_empty_checks(self):
        compressed = gzip.compress(RULE_BYTES, mtime=0)
        bad_crc = bytearray(compressed)
        bad_crc[-8] ^= 1
        for transfer in TRANSFERS:
            for encoding in ("gzip", "x-gzip"):
                for body, cause, message in ((bytes(bad_crc), gzip.BadGzipFile, "CRC check failed"),
                                             (compressed[:-5], EOFError, "Incomplete or invalid gzip"),
                                             (b"not-gzip", gzip.BadGzipFile, "Not a gzipped file"),
                                             (gzip.compress(b"", mtime=0), None, "Source is empty")):
                    with self.subTest(transfer=transfer, encoding=encoding, message=message):
                        wire = _chunked(body, transfer, headers=(("Content-Encoding", encoding),))
                        with _WireEndpoint({URL: wire}) as endpoint:
                            with self.assertRaisesRegex(RuntimeError if cause else ValueError, message) as caught:
                                fetch_https(URL)
                            self.assertIn(URL, str(caught.exception))
                            if cause:
                                self.assertIsInstance(caught.exception.__cause__, cause)
                            self.assertTrue(endpoint.responses[0].closed)

    def test_other_transfer_tokens_do_not_gain_chunk_decoding(self):
        body = b"17\r\n" + RULE_BYTES + b"\r\n0\r\n\r\n"
        for transfer in ("\xa0chunked\xa0", "\vchunked\v", "gzip, chunked",
                         "chunked, gzip", "chunked;foo=bar", "identity"):
            with self.subTest(transfer=transfer):
                with _WireEndpoint({URL: _wire(body, headers=(("Transfer-Encoding", transfer),))}):
                    self.assertEqual(fetch_https(URL), body)

    def test_redirect_final_chunks_keep_status_failures_and_no_retry(self):
        final_url = "https://example.org/final.txt"
        for transfer in TRANSFERS:
            cases = (
                (_chunked(RULE_BYTES, transfer), None, None),
                (_chunked(gzip.compress(RULE_BYTES, mtime=0), transfer,
                          headers=(("Content-Encoding", "x-gzip"),)), None, None),
                (_wire(b"17\r\nshort", headers=(("Transfer-Encoding", transfer),)), RuntimeError, IncompleteRead),
                (_chunked(RULE_BYTES, transfer, status=206), ValueError, None),
                (_chunked(RULE_BYTES, transfer, status=503), RuntimeError, error.HTTPError),
            )
            for wire, exception, cause in cases:
                with self.subTest(transfer=transfer, exception=exception, cause=cause):
                    with _WireEndpoint({URL: _redirect("/final.txt"), final_url: wire}) as endpoint:
                        if exception:
                            with self.assertRaises(exception) as caught:
                                fetch_https(URL)
                            self.assertIn(URL, str(caught.exception))
                            if cause:
                                self.assertIsInstance(caught.exception.__cause__, cause)
                            else:
                                self.assertIsNone(caught.exception.__cause__)
                        else:
                            self.assertEqual(fetch_https(URL), RULE_BYTES)
                        self.assertEqual(endpoint.visited, [URL, final_url])
                        self.assertTrue(endpoint.responses[0].closed)
                        self.assertEqual(endpoint.sockets[0].stream.body_read_attempts, 0)
                        if cause is not error.HTTPError:
                            self.assertTrue(endpoint.responses[1].closed)


class ChunkedGenerateTests(unittest.TestCase):
    def test_source_and_remote_white_match_canonical_for_nine_options(self):
        white_url = "https://example.org/white.txt"
        source = (RULE_BYTES + b"DOMAIN,keep.example.org\n"
                  b"@@||allowed.example.org^\n||allowed.example.org^\n"
                  b"HOST,from-qx.example.org,LIST\n"
                  b"IP-CIDR,192.0.2.0/24\nIP-CIDR,198.51.100.0/24,no-resolve\n"
                  b"SRC-IP,203.0.113.0/24\nIP-SUFFIX,192.0.7.1/24\n"
                  b"AND,((IP-CIDR,192.0.5.0/24),(SRC-IP,198.18.0.0/16))\n")
        for purpose in ("block", "direct", "proxy"):
            for no_resolve in ("add", "strip", "keep"):
                with self.subTest(purpose=purpose, no_resolve=no_resolve), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    native = root / "static" / "native.yaml"
                    native.parent.mkdir()
                    native.write_bytes(b'payload:\r\n  - "DOMAIN,native.example.org"\r\n')
                    static_before = native.read_bytes()
                    groups = [dict(name="parent", sources=[URL, URL, "static/native.yaml"], whitelist=[white_url]),
                              dict(name="child", sources=["parent/fin.txt"], whitelist=[white_url])]
                    for group in groups:
                        group.update(purpose=purpose, no_resolve=no_resolve)
                    (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
                    with patch("formats.datetime") as clock:
                        clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                        for encoding in (None, "gzip", "x-gzip"):
                            expected = None
                            for transfer in TRANSFERS:
                                with self.subTest(encoding=encoding, transfer=transfer):
                                    headers = (("Content-Encoding", encoding),) if encoding else ()
                                    routes = {url: _chunked(gzip.compress(body, mtime=0) if encoding else body,
                                                           transfer, headers=headers)
                                              for url, body in ((URL, source), (white_url, RULE_BYTES))}
                                    with _WireEndpoint(routes) as endpoint, \
                                            contextlib.redirect_stderr(io.StringIO()) as messages:
                                        outputs = generate(root, fetch_https)
                                        publish(outputs, root=root)
                                        self.assertEqual(endpoint.visited, [URL, white_url])
                                        self.assertTrue(all(response.closed for response in endpoint.responses))
                                    result = (outputs, messages.getvalue())
                                    if expected is None:
                                        expected = result
                                    self.assertEqual(result, expected)
                                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                                     {path: text.encode() for path, text in outputs.items()})
                                    self.assertEqual(set(outputs), {root / group / name
                                                     for group in ("parent", "child") for name in FILES})
                                    body = outputs[root / "parent" / "fin.txt"].splitlines()[1:]
                                    self.assertIn("DOMAIN,keep.example.org", body)
                                    self.assertNotIn("DOMAIN,ads.example.org", body)
                                    self.assertNotIn("DOMAIN,native.example.org", body)
                                    self.assertIn("SRC-IP,203.0.113.0/24", body)
                                    flag = ",no-resolve" if no_resolve == "add" else ""
                                    self.assertIn("IP-CIDR,192.0.2.0/24" + flag, body)
                                    flag = "" if no_resolve == "strip" else ",no-resolve"
                                    self.assertIn("IP-CIDR,198.51.100.0/24" + flag, body)
                                    self.assertIn("DOMAIN,native.example.org", outputs[root / "parent" / "fin.yaml"])
                                    self.assertIn("parent fin.txt:IP-SUFFIX: 1", messages.getvalue())
                                    if purpose == "block":
                                        self.assertIn("@@||allowed.example.org^", outputs[root / "parent" / "fin-adb.txt"])
                                    self.assertEqual(native.read_bytes(), static_before)

    def test_all_six_generated_bytes_keep_same_round_and_disk_dependency_behavior(self):
        white_url = "https://example.org/white.txt"
        source = RULE_BYTES + b"IP-CIDR,192.0.2.0/24,no-resolve\n"
        for purpose in ("block", "direct", "proxy"):
            for no_resolve in ("add", "strip", "keep"):
                with self.subTest(purpose=purpose, no_resolve=no_resolve), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    local = root / "static" / "input.txt"
                    local.parent.mkdir()
                    local.write_bytes(source + b"DOMAIN,keep.example.org\r\n")
                    static_before = local.read_bytes()
                    parent = dict(name="parent", purpose=purpose, no_resolve=no_resolve,
                                  sources=[URL], whitelist=[white_url])
                    expected = {}
                    with patch("formats.datetime") as clock, warnings.catch_warnings():
                        warnings.simplefilter("always")
                        clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                        for transfer in ("chunked", "chunked ", "\tChUnKeD\t"):
                            routes = {URL: _chunked(source, transfer),
                                      white_url: _chunked(b"DOMAIN-SUFFIX,unrelated.example.org\n", transfer)}
                            (root / "rulesets.json").write_text(json.dumps([parent]), encoding="utf-8")
                            with _WireEndpoint(routes), contextlib.redirect_stderr(io.StringIO()):
                                publish(generate(root, fetch_https), root=root)
                            for filename in FILES:
                                for role in ("source", "white"):
                                    child = dict(name="child", purpose=purpose, no_resolve=no_resolve,
                                                 sources=["parent/" + filename] if role == "source" else ["static/input.txt"],
                                                 whitelist=[] if role == "source" else ["parent/" + filename])
                                    for stage in ("same-round", "disk"):
                                        with self.subTest(transfer=transfer, filename=filename, role=role, stage=stage):
                                            groups = [parent, child] if stage == "same-round" else [child]
                                            (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
                                            with _WireEndpoint(routes) as endpoint, \
                                                    contextlib.redirect_stderr(io.StringIO()) as messages:
                                                if filename == "fin-adb.txt" and purpose != "block" and stage == "disk":
                                                    with self.assertRaisesRegex(ValueError, "No adaptable rules|Invalid whitelist") as caught:
                                                        generate(root, fetch_https)
                                                    result = str(caught.exception)
                                                else:
                                                    outputs = generate(root, fetch_https)
                                                    publish(outputs, root=root)
                                                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                                                     {path: text.encode() for path, text in outputs.items()})
                                                    result = outputs
                                                self.assertEqual(endpoint.visited,
                                                                 [URL, white_url] if stage == "same-round" else [])
                                            result = (result, messages.getvalue())
                                            key = (filename, role, stage)
                                            if transfer == "chunked":
                                                expected[key] = result
                                            else:
                                                self.assertEqual(result, expected[key])
                                            self.assertEqual(local.read_bytes(), static_before)

    def test_404_freeze_and_invalid_remote_white_keep_existing_distinctions(self):
        missing_url = "https://example.org/missing.txt"
        white_url = "https://example.org/white.txt"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            local = root / "static" / "input.txt"
            local.parent.mkdir()
            local.write_bytes(b"DOMAIN,local.example.org\r\n")
            static_before = local.read_bytes()
            groups = [dict(name="frozen", sources=[missing_url], whitelist=[]),
                      dict(name="healthy", sources=[missing_url, URL, "static/input.txt"],
                           whitelist=[missing_url, white_url]),
                      dict(name="child", sources=["frozen/fin.txt"], whitelist=[])]
            for group in groups:
                group.update(purpose="block", no_resolve="keep")
            (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
            previous = {}
            for group in ("frozen", "child"):
                (root / group).mkdir()
                for name in FILES:
                    path = root / group / name
                    previous[path] = f"old {group} {name}\r\n".encode()
                    path.write_bytes(previous[path])
            with patch("formats.datetime") as clock:
                clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                for invalid in (b"<html>DOMAIN,ads.example.org</html>", b"\xff", b"", b"UNKNOWN-TYPE,invalid\n"):
                    expected = None
                    for transfer in TRANSFERS:
                        with self.subTest(transfer=transfer, invalid=invalid):
                            routes = {missing_url: _chunked(b"missing", transfer, status=404),
                                      URL: _chunked(RULE_BYTES, transfer),
                                      white_url: _chunked(invalid, transfer)}
                            with _WireEndpoint(routes) as endpoint, \
                                    contextlib.redirect_stderr(io.StringIO()) as messages:
                                outputs = generate(root, fetch_https)
                                publish(outputs, root=root)
                                self.assertEqual(endpoint.visited, [missing_url, URL, white_url])
                            result = (outputs, messages.getvalue())
                            if expected is None:
                                expected = result
                            self.assertEqual(result, expected)
                            self.assertIn(f"{missing_url}: HTTP 404; skipped", messages.getvalue())
                            self.assertIn(white_url, messages.getvalue())
                            self.assertEqual(set(outputs), {root / "healthy" / name for name in FILES})
                            self.assertEqual(outputs[root / "healthy" / "fin.txt"].splitlines()[1:],
                                             ["DOMAIN,ads.example.org", "DOMAIN,local.example.org"])
                            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                            self.assertEqual(local.read_bytes(), static_before)
