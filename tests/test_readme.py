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

    def test_readme_has_all_download_links_in_alternating_rows(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        groups = ("cdn", "a3", "a4", "big-data", "tg", "proxy", "dirt")
        filenames = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")
        table = readme.split("## 下载链接", 1)[1].split("| 文件 | 用法 |", 1)[0]
        rows = [line for line in table.splitlines() if line.startswith("| `fin")]
        self.assertIn("| 格式 | " + " | ".join(f"`{name}`" for name in groups) + " |", table)
        self.assertEqual(len(rows), 2 * len(filenames))
        self.assertIn("共 42 个", readme)
        for index, filename in enumerate(filenames):
            for offset, (label, host) in enumerate((
                ("非加速", "https://raw.githubusercontent.com/DoingDog/rconvert/main"),
                ("加速", "https://r.awsl.app"),
            )):
                with self.subTest(filename=filename, label=label):
                    cells = [cell.strip() for cell in rows[2 * index + offset].strip("|").split("|")]
                    self.assertEqual(cells, [f"`{filename}` {label}"] + [
                        f"[{filename}]({host}/{name}/{filename})" for name in groups
                    ])

    def test_rule_count_table_has_stable_anchor_and_matches_rule_lines(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("# rconvert\n\n<a name=\"rule-counts\"></a>\n\n## 规则数量", readme)
        self.assertIn("[规则数量](#rule-counts)", readme)
        self.assertIn(".venv/bin/python update_readme_counts.py", readme)
        table = readme.split("<!-- RULE_COUNTS_START -->", 1)[1].split("<!-- RULE_COUNTS_END -->", 1)[0]
        groups = ("cdn", "a3", "a4", "big-data", "tg", "proxy", "dirt")
        self.assertIn("| 格式 | " + " | ".join(f"`{name}`" for name in groups) + " |", table)
        for filename in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt"):
            with self.subTest(filename=filename):
                counts = []
                for name in groups:
                    path = ROOT / name / filename
                    if not path.is_file():
                        continue
                    lines = path.read_text(encoding="utf-8").splitlines()
                    headers = ("payload:", "[Adblock Plus 2.0]") if filename == "fin-adb.txt" else ("payload:",)
                    count = sum(line.strip() not in ("", *headers) and not line.lstrip().startswith(("#", "!"))
                                for line in lines)
                    header_count = (lines[6].split("Total count: ", 1)[1]
                                    if filename == "fin-adb.txt" and lines[:1] == ["[Adblock Plus 2.0]"]
                                    else lines[0].split("rules: ", 1)[1])
                    self.assertEqual(int(header_count), count)
                    counts.append(count)
                row = next(line for line in table.splitlines() if line.startswith(f"| `{filename}` |"))
                self.assertEqual([int(cell.strip()) for cell in row.strip("|").split("|")[1:]], counts)

    def test_readme_explains_lan_whitelists_and_failures(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("https://ruleset.skk.moe/Clash/non_ip/lan.txt", readme)
        self.assertIn("https://ruleset.skk.moe/Clash/ip/lan.txt", readme)
        self.assertIn("tg-sentinel.txt", readme)
        self.assertIn("404", readme)
        self.assertIn("429", readme)
        self.assertIn("冻结", readme)

    def test_readme_explains_final_sort_order(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("字符数", readme)
        self.assertIn("字典序", readme)
        self.assertIn("IPv4", readme)
        self.assertIn("IPv6", readme)
        self.assertIn("`@@`", readme)

    def test_readme_links_only_current_groups_and_static_files(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for group in ("cdn", "a3", "a4", "big-data", "tg", "proxy", "dirt"):
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
