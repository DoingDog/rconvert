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

    def test_cloudflare_links_cover_rule_groups_and_original_static_files(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        paths = (
            "a1/fin.txt", "a2/fin.txt", "a3/fin.txt", "cdn/fin.txt",
            "big-data/fin.txt", "dirt/fin.txt", "a1/fin-adb.txt",
            "static/main/Adb-unblock.list", "static/serv/sharing.list",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertIn(f"https://r.awsl.app/{path}", readme)
