import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib import error

from formats import FILES
from generate import generate, publish
from sources import load_config, resolve_source
from tests.test_formats import expected_domain


class StaticMigrationTests(unittest.TestCase):
    def test_moved_local_white_excludes_fixture_when_remote_lan_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "static").mkdir()
            old = root / "tg-sentinel.txt"
            white = root / "static/tg-sentinel.txt"
            content = b"\xef\xbb\xbf# local white\r\nDOMAIN,excluded.example.org\r\n"
            old.write_bytes(content)
            (root / "static/input.list").write_bytes(
                b"DOMAIN,excluded.example.org\nDOMAIN,keep.example.org\n"
            )
            group = {"name": "tg", "purpose": "proxy", "no_resolve": "add",
                     "sources": ["static/input.list"], "whitelist": [
                         "static/tg-sentinel.txt",
                         "https://example.org/non_ip/lan.txt", "https://example.org/ip/lan.txt",
                     ]}
            (root / "rulesets.json").write_text(json.dumps([group]), encoding="utf-8")
            self.assertEqual(load_config(root), [group])
            self.assertEqual(resolve_source(root, group["whitelist"][0]), white)
            with self.assertRaises(FileNotFoundError):
                generate(root, lambda url: self.fail(url))
            old.rename(white)
            self.assertFalse(old.exists())
            self.assertEqual(white.read_bytes(), content)
            before = {path: path.read_bytes() for path in (white, root / "static/input.list")}

            def unavailable(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(
                    url, 404, "Not Found", {}, None
                )

            diagnostics = io.StringIO()
            with contextlib.redirect_stderr(diagnostics):
                outputs = generate(root, unavailable)
            self.assertEqual(set(outputs), {root / "tg" / name for name in FILES})
            expected = {
                "fin.txt": "# tg rules: 1\nDOMAIN,keep.example.org\n",
                "fin-qx.txt": "# tg rules: 1\nHOST,keep.example.org,LIST\n",
                "fin.yaml": '# tg rules: 1\npayload:\n  - ' + json.dumps(expected_domain("DOMAIN", "keep.example.org")) + '\n',
                "fin-surge.txt": "# tg rules: 0\n",
                "fin-surge-ds.txt": "# tg rules: 1\nkeep.example.org\n",
            }
            for name, text in expected.items():
                self.assertEqual(outputs[root / "tg" / name], text)
            self.assertEqual(outputs[root / "tg/fin-adb.txt"].splitlines()[6:], [
                "! Total count: 0", "! No AdBlock rules for non-advertising group.",
            ])
            for url in group["whitelist"][1:]:
                self.assertIn(f"{url}: HTTP 404; skipped", diagnostics.getvalue())
            publish(outputs, root=root)
            self.assertEqual({path: path.read_bytes() for path in outputs},
                             {path: text.encode("utf-8") for path, text in outputs.items()})
            self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_invalid_missing_or_empty_moved_white_preserves_old_products(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "static").mkdir()
            white = root / "static/tg-sentinel.txt"
            (root / "static/input.list").write_bytes(b"DOMAIN,keep.example.org\n")
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "tg", "purpose": "proxy", "no_resolve": "add",
                "sources": ["static/input.list"], "whitelist": ["static/tg-sentinel.txt"],
            }]), encoding="utf-8")
            (root / "tg").mkdir()
            previous = {root / "tg" / name: b"previous version\r\n\x00" for name in FILES}
            for path, data in previous.items():
                path.write_bytes(data)
            cases = ((None, FileNotFoundError), (b"", ValueError),
                     (b"# comments only\n", ValueError), (b"Login required\n", ValueError),
                     (b"DOMAIN,keep.example.org\n\xff\n", UnicodeError))
            for content, exception in cases:
                with self.subTest(content=content):
                    if content is not None:
                        white.write_bytes(content)
                    with self.assertRaises(exception):
                        publish(generate(root, lambda url: self.fail(url)), root=root)
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    if content is not None:
                        self.assertEqual(white.read_bytes(), content)

    def test_publish_cannot_replace_moved_white(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            white = root / "static/tg-sentinel.txt"
            white.parent.mkdir()
            content = b"DOMAIN,excluded.example.org\r\n"
            white.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "Output path targets static"):
                publish({white: "DOMAIN,other.example.org\n"}, root=root)
            self.assertEqual(white.read_bytes(), content)
            self.assertFalse((root / ".tmp").exists())
