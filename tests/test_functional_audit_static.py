import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from formats import FILES
from generate import generate, publish
from sources import load_config, resolve_source


DOMAINS = ("alpha.example.org", "beta.example.org", "gamma.example.org", "keep.example.org")
SOURCE = "".join(f"DOMAIN,{domain}\n" for domain in DOMAINS).encode("utf-8")
STATIC_EDITS = (
    ("replace", b"DOMAIN,gamma.example.org\n", {"gamma.example.org"}),
    ("add", b"DOMAIN,alpha.example.org\nDOMAIN,beta.example.org\nDOMAIN,gamma.example.org\n",
     {"alpha.example.org", "beta.example.org", "gamma.example.org"}),
    ("delete", b"DOMAIN,beta.example.org\n", {"beta.example.org"}),
    ("reorder", b"DOMAIN,beta.example.org\nDOMAIN,alpha.example.org\n",
     {"alpha.example.org", "beta.example.org"}),
    ("comment", b"# local whitelist\nDOMAIN,alpha.example.org\n\nDOMAIN,beta.example.org\n",
     {"alpha.example.org", "beta.example.org"}),
    ("bom", b"\xef\xbb\xbfDOMAIN,alpha.example.org\nDOMAIN,beta.example.org\n",
     {"alpha.example.org", "beta.example.org"}),
    ("crlf", b"DOMAIN,alpha.example.org\r\nDOMAIN,beta.example.org\r\n",
     {"alpha.example.org", "beta.example.org"}),
)
STATIC_WHITES = ("static/main/Direct.list", "static/main/NoReject.list", "static/main/NoDirect.list")


class StaticMaintenanceTests(unittest.TestCase):
    def test_legal_static_edits_control_outputs_without_changing_inputs(self):
        for path, is_white in [(path, True) for path in STATIC_WHITES] + [("static/input.list", False)]:
            for edit, content, domains in STATIC_EDITS:
                with self.subTest(path=path, edit=edit), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "static/input.list"
                    white = root / (path if is_white else "static/new-white.list")
                    white.parent.mkdir(parents=True, exist_ok=True)
                    source.write_bytes(SOURCE if is_white else content)
                    white.write_bytes(content if is_white else b"DOMAIN,unused.example.org\n")
                    (root / "rulesets.json").write_text(json.dumps([{
                        "name": "sample", "purpose": "block", "no_resolve": "keep",
                        "sources": ["static/input.list"], "whitelist": [str(white.relative_to(root))],
                    }]), encoding="utf-8")
                    before = {source: source.read_bytes(), white: white.read_bytes()}
                    with contextlib.redirect_stderr(io.StringIO()):
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / "sample" / name for name in FILES})
                    expected = set(DOMAINS) - domains if is_white else domains
                    self.assertEqual(outputs[root / "sample/fin.txt"].splitlines()[1:],
                                     [f"DOMAIN,{domain}" for domain in sorted(expected,
                                                                           key=lambda value: (len(value), value))])
                    if is_white:
                        for domain in domains:
                            self.assertIn(f"@@|{domain}|\n", outputs[root / "sample/fin-adb.txt"])
                            for name in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-surge.txt", "fin-surge-ds.txt"):
                                self.assertNotIn(domain, outputs[root / "sample" / name])
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in before}, before)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode("utf-8") for path, text in outputs.items()})

    def test_new_local_static_source_and_whitelist_are_read_from_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "static").mkdir()
            source = root / "static/new-source.list"
            white = root / "static/new-white.list"
            source.write_bytes(b"\xef\xbb\xbf# new source\r\nDOMAIN,keep.example.org\r\nDOMAIN,alpha.example.org\r\n")
            white.write_bytes(b"# new whitelist\r\nDOMAIN,alpha.example.org\r\n")
            group = {"name": "sample", "purpose": "proxy", "no_resolve": "add",
                     "sources": ["static/new-source.list"], "whitelist": ["static/new-white.list"]}
            (root / "rulesets.json").write_text(json.dumps([group]), encoding="utf-8")
            self.assertEqual(load_config(root), [group])
            self.assertEqual(resolve_source(root, group["sources"][0]), source)
            before = {source: source.read_bytes(), white: white.read_bytes()}
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda url: self.fail(url))
            self.assertEqual(outputs[root / "sample/fin.txt"],
                             "# sample rules: 1\nDOMAIN,keep.example.org\n")
            publish(outputs, root=root)
            self.assertEqual({path: path.read_bytes() for path in before}, before)
