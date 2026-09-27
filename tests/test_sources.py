import tempfile
import unittest
from pathlib import Path

from sources import load_sources


ROOT = Path(__file__).resolve().parents[1]


class SourcesTests(unittest.TestCase):
    def test_loads_https_and_windows_relative_paths_ignoring_comments(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            config = root / "sample" / "attach" / "rule-list.ini"
            config.parent.mkdir(parents=True)
            config.write_text(
                "# ignored\n\n  https://example.org/rules.txt  \n"
                "..\\..\\static\\rules.txt\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_sources(root, "sample"),
                ["https://example.org/rules.txt", root / "static" / "rules.txt"],
            )

    def test_utf8_bom_does_not_change_first_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            config = root / "sample" / "attach" / "rule-list.ini"
            config.parent.mkdir(parents=True)
            config.write_text(chr(0xfeff) + "https://example.org/rules.txt\n", encoding="utf-8")
            self.assertEqual(load_sources(root, "sample"), ["https://example.org/rules.txt"])

    def test_rejects_non_https_and_malformed_urls(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            config = root / "sample" / "attach" / "rule-list.ini"
            config.parent.mkdir(parents=True)
            for url in ("http://example.org/rules", "ftp://example.org/rules", "https://", "https://example.org:abc/rules"):
                with self.subTest(url=url):
                    config.write_text(url, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_sources(root, "sample")

    def test_rejects_local_paths_outside_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            config = root / "sample" / "attach" / "rule-list.ini"
            config.parent.mkdir(parents=True)
            for path in (r"..\..\..\secret.txt", "../../../secret.txt", str(root.parent / "secret.txt")):
                with self.subTest(path=path):
                    config.write_text(path, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_sources(root, "sample")

    def test_rejects_group_paths_outside_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, tempfile.TemporaryDirectory(dir=ROOT) as other:
            root = Path(directory)
            config = Path(other) / "attach" / "rule-list.ini"
            config.parent.mkdir()
            config.write_text("https://example.org/rules.txt", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_sources(root, "../" + Path(other).name)

    def test_six_groups_load_and_a3_has_only_approved_sources(self):
        groups = ("a1", "a2", "a3", "big-data", "cdn", "dirt")
        for group in groups:
            with self.subTest(group=group):
                sources = load_sources(ROOT, group)
                self.assertTrue(sources)
                for source in sources:
                    if isinstance(source, str):
                        self.assertEqual(source.split(":", 1)[0].lower(), "https")
                    else:
                        self.assertTrue(source.is_relative_to(ROOT))
        self.assertEqual(
            load_sources(ROOT, "a3"),
            [
                "https://raw.githubusercontent.com/Cats-Team/AdRules/main/qx.conf",
                "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",
                "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list",
            ],
        )

    def test_a1_replaces_confirmed_404_sources(self):
        sources = load_sources(ROOT, "a1")
        self.assertIn("https://raw.githubusercontent.com/neodevpro/neodevhost/master/ownblocklist", sources)
        for dead in (
            "https://raw.githubusercontent.com/neodevpro/neodevhost/master/customblocklist",
            "https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/filter/fenliu.list",
            "https://raw.githubusercontent.com/ZenmoFeiShi/rule/main/Pinduoduo.list",
        ):
            with self.subTest(dead=dead):
                self.assertNotIn(dead, sources)

    def test_a1_drops_disabled_sources_and_case_duplicate(self):
        sources = load_sources(ROOT, "a1")
        for dead in (
            "https://whatshub.top/rule/AntiAD.list",
            "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser",
            "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        ):
            with self.subTest(dead=dead):
                self.assertNotIn(dead, sources)
        self.assertNotIn(
            "https://raw.githubusercontent.com/Moli-X/Resources/main/Filter/ADblack.list", sources
        )
        self.assertIn(
            "https://raw.githubusercontent.com/Moli-X/Resources/main/Filter/ADBlack.list", sources
        )

    def test_big_data_drops_404_gmedia_but_keeps_global_media(self):
        sources = load_sources(ROOT, "big-data")
        self.assertNotIn(
            "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/GMedia.list",
            sources,
        )
        self.assertIn(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/GlobalMedia/GlobalMedia.list",
            sources,
        )

    def test_dirt_drops_404_and_disabled_sources(self):
        sources = load_sources(ROOT, "dirt")
        for dead in (
            "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/CMedia.list",
            "https://whatshub.top/rule/China.list",
            "https://whatshub.top/rule/ChinaMedia.list",
        ):
            with self.subTest(dead=dead):
                self.assertNotIn(dead, sources)

    def test_dirt_adds_targeted_ipv4_ipv6_and_apple_without_redundant_lists(self):
        sources = load_sources(ROOT, "dirt")
        for url in (
            "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
            "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt",
            "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/apple.txt",
            "https://ruleset.skk.moe/List/ip/domestic.conf",
            "https://ruleset.skk.moe/List/non_ip/direct.conf",
            "https://ruleset.skk.moe/List/non_ip/domestic.conf",
        ):
            with self.subTest(url=url):
                self.assertEqual(sources.count(url), 1)
        self.assertNotIn("https://ruleset.skk.moe/List/domainset/domestic_cdn.conf", sources)
        self.assertFalse(any(isinstance(source, str) and "china-list" in source for source in sources))
