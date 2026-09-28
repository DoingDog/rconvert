import json
import tempfile
import unittest
from pathlib import Path

from formats import FILES
from update_readme_counts import update


ROOT = Path(__file__).resolve().parents[1]
START = "<!-- RULE_COUNTS_START -->"
END = "<!-- RULE_COUNTS_END -->"


class ReadmeCountsTests(unittest.TestCase):
    def test_updates_actual_rule_lines_and_preserves_surrounding_readme(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "sample", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/one"], "whitelist": []}
            ]), encoding="utf-8")
            (root / "sample").mkdir()
            bodies = {
                "fin.txt": "DOMAIN,a.example\nIP-CIDR,1.2.3.4/32,no-resolve\n",
                "fin-qx.txt": "HOST,a.example,LIST\n",
                "fin.yaml": "payload:\n  - \"DOMAIN,a.example\"\n",
                "fin-adb.txt": "@@|safe.example|\n||ads.example^\n",
                "fin-surge.txt": "IP-CIDR,1.2.3.4/32,no-resolve\n",
                "fin-surge-ds.txt": ".example.com\n",
            }
            for filename in FILES:
                (root / "sample" / filename).write_bytes(
                    (f"{'!' if filename == 'fin-adb.txt' else '#'} sample rules: 999\n"
                     + bodies[filename]).encode("utf-8"))
            readme = root / "README.md"
            readme.write_bytes(f"prefix\r\n{START}\r\nstale\r\n{END}\r\nsuffix\r\n".encode("utf-8"))
            update(root)
            self.assertEqual(readme.read_bytes().count(b"\n"), readme.read_bytes().count(b"\r\n"))
            result = readme.read_text(encoding="utf-8")
            self.assertTrue(result.startswith(f"prefix\n{START}\n"))
            self.assertTrue(result.endswith(f"{END}\nsuffix\n"))
            self.assertIn("| `fin.txt` | 2 |", result)
            self.assertIn("| `fin.yaml` | 1 |", result)
            self.assertIn("| `fin-adb.txt` | 2 |", result)
            previous = readme.read_bytes()
            update(root)
            self.assertEqual(readme.read_bytes(), previous)

    def test_missing_output_does_not_change_readme(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "sample", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/one"], "whitelist": []}
            ]), encoding="utf-8")
            readme = root / "README.md"
            readme.write_bytes(f"{START}\nold\n{END}\n".encode("utf-8"))
            with self.assertRaises(FileNotFoundError):
                update(root)
            self.assertEqual(readme.read_text(encoding="utf-8"), f"{START}\nold\n{END}\n")
