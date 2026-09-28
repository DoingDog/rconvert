import json
import tempfile
import unittest
from pathlib import Path

from sources import load_config, load_sources, resolve_source


ROOT = Path(__file__).resolve().parents[1]


class SourcesTests(unittest.TestCase):
    def test_loads_ordered_json_groups_and_resolves_sources_from_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            groups = [
                {"name": "a2", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/list", "static/main/Direct.list"], "whitelist": []},
                {"name": "dirt", "purpose": "direct", "no_resolve": "strip",
                 "sources": ["static/serv/domestic.list"], "whitelist": []},
            ]
            (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
            self.assertEqual(load_config(root), groups)
            self.assertEqual(resolve_source(root, "static/main/Direct.list"), root / "static/main/Direct.list")
            self.assertEqual(resolve_source(root, "static\\main\\Direct.list"), root / "static/main/Direct.list")
            self.assertEqual(resolve_source(root, "static/main/white list.txt"), root / "static/main/white list.txt")
            self.assertEqual(resolve_source(root, "https://example.org/list"), "https://example.org/list")

    def test_rejects_invalid_json_group_structure(self):
        valid = {"name": "a2", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/list"], "whitelist": []}
        invalid = (
            {}, [], [valid, valid], [{**valid, "sources": []}], [{**valid, "name": "../elsewhere"}],
            [{**valid, "name": "a2/../a1"}], [{**valid, "purpose": "unknown"}],
            [{**valid, "no_resolve": "true"}], [{**valid, "sources": "https://example.org/list"}],
            [{**valid, "sources": [42]}], [{**valid, "whitelist": [None]}],
            [{key: value for key, value in valid.items() if key != "whitelist"}],
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            for data in invalid:
                with self.subTest(data=data):
                    (root / "rulesets.json").write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_config(root)

    def test_no_resolve_policy_is_add_strip_or_keep_not_boolean(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            group = {"name": "sample", "purpose": "direct", "no_resolve": "keep",
                     "sources": ["https://example.org/rules"], "whitelist": []}
            for policy in ("add", "strip", "keep"):
                with self.subTest(policy=policy):
                    (root / "rulesets.json").write_text(json.dumps([{**group, "no_resolve": policy}]), encoding="utf-8")
                    self.assertEqual(load_config(root)[0]["no_resolve"], policy)
            (root / "rulesets.json").write_text(json.dumps([{**group, "no_resolve": False}]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no_resolve|options"):
                load_config(root)

    def test_rejects_invalid_sources_in_either_config_list(self):
        valid = {"name": "a3", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/list"], "whitelist": []}
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            for key in ("sources", "whitelist"):
                for entry in ("http://example.org/list", "https://", "https://example.org:bad/list",
                              "../outside.txt", r"..\outside.txt", str(ROOT / "static/main/Direct.list")):
                    with self.subTest(key=key, entry=entry):
                        (root / "rulesets.json").write_text(json.dumps([{**valid, key: [entry]}]), encoding="utf-8")
                        with self.assertRaises(ValueError):
                            load_config(root)

    def test_resolve_source_rejects_url_and_path_tricks(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            for entry in ("http://example.org/list", "ftp://example.org/list", "https://",
                          "https://example.org:bad/list", "https://example.org\\@other.example/list",
                          "https://exa mple.org/list", "\x00https://example.org/list",
                          "https://example.org/li\x00st", "", "../outside.txt", r"..\outside.txt",
                          str(ROOT / "static/main/Direct.list")):
                with self.subTest(entry=entry):
                    with self.assertRaises(ValueError):
                        resolve_source(root, entry)

    def test_migrates_six_groups_in_dependency_order_without_disabled_sources(self):
        groups = load_config(ROOT)
        self.assertEqual([group["name"] for group in groups], ["a2", "cdn", "a3", "a1", "big-data", "dirt"])
        self.assertEqual([len(group["sources"]) for group in groups], [16, 4, 4, 40, 17, 18])
        self.assertEqual([group["purpose"] for group in groups],
                         ["block", "proxy", "block", "block", "proxy", "direct"])
        self.assertEqual([group["no_resolve"] for group in groups], ["add", "add", "add", "add", "add", "strip"])
        config = {group["name"]: group for group in groups}
        self.assertEqual(config["a1"]["sources"][0], "a2/fin.txt")
        self.assertEqual(config["big-data"]["sources"][:4],
                         ["cdn/fin.txt", "static/serv/cdn.list", "static/serv/emby.list",
                          "static/serv/sharing.list"])
        self.assertEqual(config["a3"]["whitelist"],
                         ["static/main/Direct.list", "static/main/NoReject.list"])
        for name, group in config.items():
            with self.subTest(group=name):
                self.assertEqual(group["whitelist"],
                                 ["static/main/Direct.list", "static/main/NoReject.list"] if name == "a3" else [])
                for source in group["sources"] + group["whitelist"]:
                    resolved = resolve_source(ROOT, source)
                    if isinstance(resolved, Path) and source not in ("a2/fin.txt", "cdn/fin.txt"):
                        self.assertTrue(resolved.is_file(), source)
                for filename in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt",
                                 "fin-surge.txt", "fin-surge-ds.txt"):
                    self.assertTrue((ROOT / name / filename).is_file(), f"{name}/{filename}")

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
                "https://raw.githubusercontent.com/fmz200/wool_scripts/refs/heads/main/QuantumultX/filter/filter.list",
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

    def test_dirt_adds_novel_sukka_ipv4_without_redundant_ipv6(self):
        sources = load_sources(ROOT, "dirt")
        self.assertEqual(sources.count("https://ruleset.skk.moe/Clash/ip/china_ip.txt"), 1)
        self.assertNotIn("https://ruleset.skk.moe/Clash/ip/china_ip_ipv6.txt", sources)

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
