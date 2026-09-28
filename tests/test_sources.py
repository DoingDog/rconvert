import json
import tempfile
import unittest
from pathlib import Path

from sources import load_config, resolve_source


ROOT = Path(__file__).resolve().parents[1]


class SourcesTests(unittest.TestCase):
    def test_legacy_ini_loader_is_removed(self):
        import sources

        self.assertFalse(hasattr(sources, "load_sources"))

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
                          "https://example.org/li\x00st", "https://example.org/li\u0080st",
                          "", "../outside.txt", r"..\outside.txt",
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

    def test_utf8_bom_does_not_change_first_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            groups = [{"name": "sample", "purpose": "block", "no_resolve": "add",
                       "sources": ["https://example.org/rules.txt"], "whitelist": []}]
            (root / "rulesets.json").write_text(chr(0xfeff) + json.dumps(groups), encoding="utf-8")
            self.assertEqual(load_config(root)[0]["sources"], ["https://example.org/rules.txt"])

    def test_a3_has_only_approved_sources(self):
        config = {group["name"]: group for group in load_config(ROOT)}
        self.assertEqual(
            config["a3"]["sources"],
            [
                "https://raw.githubusercontent.com/Cats-Team/AdRules/main/qx.conf",
                "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",
                "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list",
                "https://raw.githubusercontent.com/fmz200/wool_scripts/refs/heads/main/QuantumultX/filter/filter.list",
            ],
        )

    def test_a1_replaces_confirmed_404_sources(self):
        sources = {group["name"]: group for group in load_config(ROOT)}["a1"]["sources"]
        self.assertIn("https://raw.githubusercontent.com/neodevpro/neodevhost/master/ownblocklist", sources)
        for dead in (
            "https://raw.githubusercontent.com/neodevpro/neodevhost/master/customblocklist",
            "https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/filter/fenliu.list",
            "https://raw.githubusercontent.com/ZenmoFeiShi/rule/main/Pinduoduo.list",
        ):
            with self.subTest(dead=dead):
                self.assertNotIn(dead, sources)

    def test_a1_drops_disabled_sources_and_case_duplicate(self):
        sources = {group["name"]: group for group in load_config(ROOT)}["a1"]["sources"]
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
        sources = {group["name"]: group for group in load_config(ROOT)}["big-data"]["sources"]
        self.assertNotIn(
            "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/GMedia.list",
            sources,
        )
        self.assertIn(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/GlobalMedia/GlobalMedia.list",
            sources,
        )

    def test_dirt_adds_novel_sukka_ipv4_without_redundant_ipv6(self):
        sources = {group["name"]: group for group in load_config(ROOT)}["dirt"]["sources"]
        self.assertEqual(sources.count("https://ruleset.skk.moe/Clash/ip/china_ip.txt"), 1)
        self.assertNotIn("https://ruleset.skk.moe/Clash/ip/china_ip_ipv6.txt", sources)

    def test_dirt_drops_404_and_disabled_sources(self):
        sources = {group["name"]: group for group in load_config(ROOT)}["dirt"]["sources"]
        for dead in (
            "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/CMedia.list",
            "https://whatshub.top/rule/China.list",
            "https://whatshub.top/rule/ChinaMedia.list",
        ):
            with self.subTest(dead=dead):
                self.assertNotIn(dead, sources)

    def test_dirt_adds_targeted_ipv4_ipv6_and_apple_without_redundant_lists(self):
        sources = {group["name"]: group for group in load_config(ROOT)}["dirt"]["sources"]
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
        self.assertFalse(any("china-list" in source for source in sources))
