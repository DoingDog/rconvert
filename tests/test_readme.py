import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReadmeTests(unittest.TestCase):
    def test_github_readme_uses_markdown_extension(self):
        self.assertTrue((ROOT / "README.md").is_file())
        self.assertFalse((ROOT / "README.text").exists())

    def test_landing_page_redirects_to_markdown_readme(self):
        landing = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('content="0;url=./README.md"', landing)
        self.assertIn('href="./README.md"', landing)
        self.assertNotIn("README.text", landing)

    def test_readme_lists_four_groups_and_24_outputs(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        rows = (
            line for line in readme.splitlines()
            if line.startswith("| `") and "https://raw.githubusercontent.com/DoingDog/rconvert/main/" in line
        )
        self.assertEqual([line.split("`")[1] for line in rows], ["cdn", "a3", "big-data", "dirt"])
        self.assertIn("共 24 个", readme)
        for filename in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt"):
            with self.subTest(filename=filename):
                self.assertIn(f"| `{filename}` |", readme)

    def test_readme_links_only_current_groups_and_static_files(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for group in ("cdn", "a3", "big-data", "dirt"):
            with self.subTest(group=group):
                self.assertIn(f"https://raw.githubusercontent.com/DoingDog/rconvert/main/{group}/fin.txt", readme)
                self.assertIn(f"https://r.awsl.app/{group}/fin.txt", readme)
        for path in ("static/main/Adb-unblock.list", "static/serv/sharing.list"):
            with self.subTest(path=path):
                self.assertIn(f"https://r.awsl.app/{path}", readme)
        self.assertNotIn("a1/", readme)
        self.assertNotIn("a2/", readme)
        self.assertIn("cdn/fin.txt", readme)
        self.assertIn("static/main/Direct.list", readme)
        self.assertIn("static/main/NoReject.list", readme)
        self.assertIn("static/main/NoDirect.list", readme)
