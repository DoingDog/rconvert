import json
import tempfile
import unittest
from pathlib import Path

from rules import parse_whitelist
from sources import load_config, resolve_source


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SOURCES = {
    "cdn": [
        "https://ruleset.skk.moe/List/domainset/cdn.conf",
        "https://ruleset.skk.moe/List/non_ip/cdn.conf",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Jsdelivr/Jsdelivr.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Limelight/Limelight.list",
    ],
    "a3": [
        "https://raw.githubusercontent.com/Cats-Team/AdRules/main/qx.conf",
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list",
        "https://raw.githubusercontent.com/fmz200/wool_scripts/refs/heads/main/QuantumultX/filter/filter.list",
        "https://ruleset.skk.moe/List/domainset/reject.conf",
        "https://ruleset.skk.moe/List/non_ip/reject.conf",
    ],
    "big-data": [
        "cdn/fin.txt", "static/serv/cdn.list", "static/serv/emby.list", "static/serv/sharing.list",
        "https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/Emby.list",
        "https://ruleset.skk.moe/List/domainset/download.conf",
        "https://ruleset.skk.moe/List/ip/download.conf",
        "https://ruleset.skk.moe/List/ip/stream.conf",
        "https://ruleset.skk.moe/List/non_ip/stream.conf",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Apkpure/Apkpure.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Dropbox/Dropbox.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Dubox/Dubox.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/GlobalMedia/GlobalMedia.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/GoogleDrive/GoogleDrive.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/MEGA/MEGA.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/OneDrive/OneDrive.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/SourceForge/SourceForge.list",
        "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/domainset/game-download.conf",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/YouTube.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/Netflix.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/Disney.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/Spotify.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/TikTok.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/GlobalMedia.list",
    ],
    "tg": [
        "https://ruleset.skk.moe/List/non_ip/telegram.conf",
        "https://ruleset.skk.moe/List/ip/telegram.conf",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/Telegram.list",
    ],
    "proxy": [
        "https://ruleset.skk.moe/List/non_ip/my_proxy.conf",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ProxyLite/ProxyLite.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/Proxy.list",
    ],
    "dirt": [
        "static/serv/domestic.list",
        "https://static-file-global.353355.xyz/rules/cn-additional-list-clash-classical.yaml",
        "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/Mainland.list",
        "https://ruleset.skk.moe/List/ip/domestic.conf",
        "https://ruleset.skk.moe/Clash/ip/china_ip.txt",
        "https://ruleset.skk.moe/List/non_ip/direct.conf",
        "https://ruleset.skk.moe/List/non_ip/domestic.conf",
        "https://ruleset.skk.moe/List/non_ip/my_direct.conf",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/China/China.list",
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AccelerateDirectSites.list",
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list",
        "https://github.com/jqyisbest/RuCu6/raw/refs/heads/main/Rules/China.list",
        "https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/QuantumultX/rules/Mainland.list",
        "https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/QuantumultX/rules/CMedia.list",
        "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
        "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/apple.txt",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/China.list",
        "https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/ChinaCIDR.list",
    ],
}
REQUIRED_SOURCES["a4"] = REQUIRED_SOURCES["a3"][:4]
LAN_WHITELISTS = ["https://ruleset.skk.moe/Clash/non_ip/lan.txt",
                  "https://ruleset.skk.moe/Clash/ip/lan.txt"]
REQUIRED_WHITELISTS = {
    "cdn": LAN_WHITELISTS,
    "a3": ["static/main/Direct.list", "static/main/NoReject.list"] + LAN_WHITELISTS,
    "a4": ["static/main/Direct.list", "static/main/NoReject.list"] + LAN_WHITELISTS,
    "big-data": LAN_WHITELISTS,
    "tg": ["static/tg-sentinel.txt"] + LAN_WHITELISTS,
    "proxy": LAN_WHITELISTS,
    "dirt": ["static/main/NoDirect.list"] + LAN_WHITELISTS,
}


class SourcesTests(unittest.TestCase):
    def test_legacy_ini_loader_is_removed(self):
        import sources

        self.assertFalse(hasattr(sources, "load_sources"))

    def test_loads_ordered_json_groups_and_resolves_sources_from_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            groups = [
                {"name": "sample", "purpose": "block", "no_resolve": "add",
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

    def test_load_config_validates_optional_title(self):
        group = {"name": "sample", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/list"], "whitelist": []}
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            titled = {**group, "title": "Sample Rules"}
            (root / "rulesets.json").write_text(json.dumps([titled]), encoding="utf-8")
            self.assertEqual(load_config(root), [titled])
            for title in (None, 42, "", " ", " leading", "trailing ",
                          "safe\n! injected", "safe\r! injected", "safe" + chr(0x2028) + "! injected",
                          "safe\x00name", "safe\x7fname", "safe\u0085name"):
                with self.subTest(title=title):
                    (root / "rulesets.json").write_text(json.dumps([{**group, "title": title}]), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "title"):
                        load_config(root)

    def test_rejects_invalid_json_group_structure(self):
        valid = {"name": "sample", "purpose": "block", "no_resolve": "add",
                 "sources": ["https://example.org/list"], "whitelist": []}
        invalid = (
            {}, [], [valid, valid], [{**valid, "sources": []}], [{**valid, "name": "../elsewhere"}],
            [{**valid, "name": "sample/../other"}], [{**valid, "purpose": "unknown"}],
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

    def test_retains_seven_groups_in_dependency_order_without_stale_sources(self):
        groups = load_config(ROOT)
        self.assertEqual([group["name"] for group in groups],
                         ["cdn", "a3", "a4", "big-data", "tg", "proxy", "dirt"])
        self.assertEqual([group["purpose"] for group in groups],
                         ["proxy", "block", "block", "proxy", "proxy", "proxy", "direct"])
        self.assertEqual([group["no_resolve"] for group in groups],
                         ["add", "add", "add", "add", "add", "add", "strip"])
        config = {group["name"]: group for group in groups}
        self.assertEqual(config["big-data"]["sources"][0], "cdn/fin.txt")
        self.assertNotIn("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/CN.list",
                         config["dirt"]["sources"])
        for name, group in config.items():
            with self.subTest(group=name):
                self.assertEqual([source for source in group["sources"] if source in REQUIRED_SOURCES[name]],
                                 REQUIRED_SOURCES[name])
                self.assertEqual([source for source in group["whitelist"] if source in REQUIRED_WHITELISTS[name]],
                                 REQUIRED_WHITELISTS[name])
                for source in group["sources"] + group["whitelist"]:
                    resolved = resolve_source(ROOT, source)
                    if isinstance(resolved, Path) and source != "cdn/fin.txt":
                        self.assertTrue(resolved.is_file(), source)
        for name in ("a1", "a2"):
            self.assertFalse((ROOT / name).exists(), name)

    def test_all_seven_groups_have_six_generated_artifacts(self):
        for name in ("cdn", "a3", "a4", "big-data", "tg", "proxy", "dirt"):
            for filename in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt",
                             "fin-surge.txt", "fin-surge-ds.txt"):
                with self.subTest(group=name, filename=filename):
                    self.assertTrue((ROOT / name / filename).is_file(), f"{name}/{filename}")

    def test_configured_local_static_whitelists_are_valid(self):
        entries = {entry for group in load_config(ROOT) for entry in group["whitelist"]
                   if entry.startswith("static/")}
        for entry in entries:
            with self.subTest(entry=entry):
                path = resolve_source(ROOT, entry)
                self.assertTrue(path.is_file())
                parse_whitelist(path.read_text(encoding="utf-8-sig"))

    def test_utf8_bom_does_not_change_first_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            groups = [{"name": "sample", "purpose": "block", "no_resolve": "add",
                       "sources": ["https://example.org/rules.txt"], "whitelist": []}]
            (root / "rulesets.json").write_text(chr(0xfeff) + json.dumps(groups), encoding="utf-8")
            self.assertEqual(load_config(root)[0]["sources"], ["https://example.org/rules.txt"])

    def test_every_group_retains_two_lan_whitelists_without_routing_them(self):
        for group in load_config(ROOT):
            with self.subTest(group=group["name"]):
                self.assertEqual([source for source in group["whitelist"] if source in LAN_WHITELISTS],
                                 LAN_WHITELISTS)
                self.assertTrue(set(LAN_WHITELISTS).isdisjoint(group["sources"]))

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

    def test_tg_sentinel_uses_static_path(self):
        self.assertFalse((ROOT / "tg-sentinel.txt").exists())
        path = resolve_source(ROOT, "static/tg-sentinel.txt")
        self.assertTrue(path.is_file())
        parse_whitelist(path.read_text(encoding="utf-8-sig"))

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
        self.assertFalse(any("china-list" in source for source in sources if source.startswith("https://")))
