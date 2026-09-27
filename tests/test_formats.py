import json
import unittest

from rules import Rule
from formats import render


class FormatTests(unittest.TestCase):
    def test_wildcard_survives_compatible_targets(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-*.example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.txt"])
        self.assertIn("HOST-WILDCARD,api-*.example.com,LIST", out["fin-qx.txt"])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.yaml"])
        self.assertNotIn("api-*.example.com", out["fin-surge-ds.txt"])

    def test_surge_character_class_wildcard_is_not_reinterpreted_by_qx_or_mihomo(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-[0-9].example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin.txt"])
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertEqual(skipped["fin-qx.txt:DOMAIN-WILDCARD"], 1)
        self.assertEqual(skipped["fin.yaml:DOMAIN-WILDCARD"], 1)

    def test_six_files_are_ordered_and_count_actual_lines(self):
        high = Rule("DOMAIN-WILDCARD", "z-*.example.com")
        low = Rule("DOMAIN-WILDCARD", "a-*.example.com")
        out, _ = render("a3", iter([high, low]))
        self.assertEqual(set(out), {
            "fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt",
            "fin-surge.txt", "fin-surge-ds.txt",
        })
        self.assertEqual(out, render("a3", iter([low, high]))[0])
        self.assertEqual(out["fin.txt"],
                         "# a3 rules: 2\nDOMAIN-WILDCARD,a-*.example.com\nDOMAIN-WILDCARD,z-*.example.com\n")
        self.assertTrue(all(body.endswith("\n") and "\r" not in body for body in out.values()))

    def test_newlines_in_rule_values_cannot_insert_extra_rules(self):
        out, skipped = render("a3", [Rule("DOMAIN-SUFFIX", "safe.example.com\r\nEVIL,host")])
        self.assertTrue(all("EVIL" not in body and "\r" not in body for body in out.values()))
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)

    def test_exact_domain_does_not_expand_into_adblock_subdomains(self):
        out, skipped = render("a3", [Rule("DOMAIN", "exact.example.com")])
        self.assertIn("DOMAIN,exact.example.com\n", out["fin.txt"])
        self.assertIn("HOST,exact.example.com,LIST\n", out["fin-qx.txt"])
        self.assertIn('  - "DOMAIN,exact.example.com"\n', out["fin.yaml"])
        self.assertIn("\nexact.example.com\n", out["fin-surge-ds.txt"])
        self.assertNotIn("exact.example.com", out["fin-surge.txt"])
        self.assertNotIn("exact.example.com", out["fin-adb.txt"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN"], 1)

    def test_suffix_is_shared_by_domain_set_and_adblock(self):
        out, skipped = render("a2", [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertIn("DOMAIN-SUFFIX,ads.example.com\n", out["fin.txt"])
        self.assertIn("HOST-SUFFIX,ads.example.com,LIST\n", out["fin-qx.txt"])
        self.assertIn('  - "DOMAIN-SUFFIX,ads.example.com"\n', out["fin.yaml"])
        self.assertEqual(out["fin-surge-ds.txt"], "# a2 rules: 1\n.ads.example.com\n")
        self.assertEqual(out["fin-surge.txt"], "# a2 rules: 0\n")
        self.assertEqual(out["fin-adb.txt"], "! a2 rules: 1\n||ads.example.com^\n")
        self.assertNotIn("fin-adb.txt:DOMAIN-SUFFIX", skipped)

    def test_source_cidr_keeps_direction_for_ipv4_and_ipv6(self):
        out, skipped = render("a3", [
            Rule("SRC-IP-CIDR", "2001:db8::/32"),
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
        ])
        self.assertIn("SRC-IP,192.0.2.0/24\n", out["fin.txt"])
        self.assertIn("SRC-IP,2001:db8::/32\n", out["fin-surge.txt"])
        self.assertIn('  - "SRC-IP-CIDR,2001:db8::/32"\n', out["fin.yaml"])
        self.assertNotIn("IP-CIDR6,2001:db8::/32", out["fin.yaml"])
        self.assertEqual(skipped["fin-qx.txt:SRC-IP-CIDR"], 2)
        self.assertEqual(skipped["fin-adb.txt:SRC-IP-CIDR"], 2)
        self.assertEqual(skipped["fin-surge-ds.txt:SRC-IP-CIDR"], 2)
        self.assertNotIn("2001:db8", out["fin-qx.txt"])

    def test_destination_cidr_uses_native_ipv6_names(self):
        out, skipped = render("a3", [
            Rule("IP-CIDR", "192.0.2.0/24"),
            Rule("IP-CIDR6", "2001:db8::/32"),
        ])
        self.assertIn("IP-CIDR,192.0.2.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR,192.0.2.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn("IP6-CIDR,2001:db8::/32,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('  - "IP-CIDR6,2001:db8::/32,no-resolve"\n', out["fin.yaml"])
        self.assertEqual(skipped["fin-adb.txt:IP-CIDR"], 1)

    def test_ipv6_address_in_generic_cidr_uses_ipv6_target_types(self):
        out, _ = render("a3", [Rule("IP-CIDR", "2001:db8::/32")])
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve\n", out["fin.txt"])
        self.assertIn("IP6-CIDR,2001:db8::/32,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('  - "IP-CIDR,2001:db8::/32,no-resolve"\n', out["fin.yaml"])

    def test_surge_port_names_keep_source_and_destination_distinct(self):
        out, skipped = render("a3", [Rule("SRC-PORT", "5353"), Rule("DST-PORT", "443")])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("SRC-PORT,5353\n", out[name])
            self.assertIn("DEST-PORT,443\n", out[name])
        self.assertIn('  - "SRC-PORT,5353"\n', out["fin.yaml"])
        self.assertIn('  - "DST-PORT,443"\n', out["fin.yaml"])
        self.assertEqual(skipped["fin-qx.txt:DST-PORT"], 1)
        self.assertEqual(skipped["fin-qx.txt:SRC-PORT"], 1)

    def test_surge_destination_port_maps_to_mihomo_dst_port(self):
        out, _ = render("a3", [Rule("DEST-PORT", "443")])
        self.assertIn('  - "DST-PORT,443"\n', out["fin.yaml"])

    def test_single_source_ip_maps_to_mihomo_source_cidr(self):
        out, _ = render("a3", [
            Rule("SRC-IP", "192.0.2.1"), Rule("SRC-IP", "2001:db8::1"),
        ])
        self.assertIn('"SRC-IP-CIDR,192.0.2.1/32"', out["fin.yaml"])
        self.assertIn('"SRC-IP-CIDR,2001:db8::1/128"', out["fin.yaml"])
        self.assertNotIn("no-resolve", out["fin.yaml"])

    def test_equivalent_port_aliases_render_once_per_target(self):
        out, _ = render("a3", [Rule("DST-PORT", "443"), Rule("DEST-PORT", "443")])
        self.assertEqual(out["fin.txt"].count("DEST-PORT,443\n"), 1)
        self.assertEqual(out["fin-surge.txt"].count("DEST-PORT,443\n"), 1)
        self.assertEqual(out["fin.yaml"].count('"DST-PORT,443"\n'), 1)

    def test_mihomo_udp_network_maps_to_surge_protocol(self):
        out, _ = render("a3", [Rule("NETWORK", "udp")])
        self.assertIn("PROTOCOL,UDP\n", out["fin.txt"])
        self.assertIn("PROTOCOL,UDP\n", out["fin-surge.txt"])
        self.assertIn('"NETWORK,udp"', out["fin.yaml"])

    def test_surge_udp_protocol_maps_to_mihomo_network(self):
        out, _ = render("a3", [Rule("PROTOCOL", "UDP")])
        self.assertIn('"NETWORK,udp"', out["fin.yaml"])
        self.assertIn("PROTOCOL,UDP\n", out["fin.txt"])

    def test_process_name_wildcard_maps_to_surge_process_name(self):
        out, _ = render("a3", [Rule("PROCESS-NAME-WILDCARD", "*telegram*")])
        self.assertIn("PROCESS-NAME,*telegram*\n", out["fin.txt"])
        self.assertIn("PROCESS-NAME,*telegram*\n", out["fin-surge.txt"])
        self.assertIn('"PROCESS-NAME-WILDCARD,*telegram*"', out["fin.yaml"])

    def test_posix_process_path_maps_to_surge_process_name(self):
        path = "/Applications/Foo.app/Contents/MacOS/Foo"
        out, _ = render("a3", [Rule("PROCESS-PATH", path)])
        self.assertIn(f"PROCESS-NAME,{path}\n", out["fin.txt"])
        self.assertIn(f'"PROCESS-PATH,{path}"', out["fin.yaml"])

    def test_process_and_user_agent_only_go_to_confirmed_clients(self):
        out, skipped = render("a3", [Rule("PROCESS-NAME", "FooApp"), Rule("USER-AGENT", "*bot*")])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("PROCESS-NAME,FooApp\n", out[name])
            self.assertIn("USER-AGENT,*bot*\n", out[name])
        self.assertIn('  - "PROCESS-NAME,FooApp"\n', out["fin.yaml"])
        self.assertNotIn("USER-AGENT", out["fin.yaml"])
        self.assertIn("USER-AGENT,*bot*,LIST\n", out["fin-qx.txt"])
        self.assertNotIn("PROCESS-NAME", out["fin-qx.txt"])
        self.assertEqual(skipped["fin-qx.txt:PROCESS-NAME"], 1)
        self.assertEqual(skipped["fin.yaml:USER-AGENT"], 1)

    def test_ip_asn_geoip_and_keyword_are_not_discarded(self):
        out, skipped = render("a3", [
            Rule("IP-ASN", "13335"), Rule("GEOIP", "CN"),
            Rule("DOMAIN-KEYWORD", "ads"),
        ])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("IP-ASN,13335,no-resolve\n", out[name])
            self.assertIn("GEOIP,CN,no-resolve\n", out[name])
            self.assertIn("DOMAIN-KEYWORD,ads\n", out[name])
        for entry in ("IP-ASN,13335,LIST,no-resolve", "GEOIP,CN,LIST,no-resolve", "HOST-KEYWORD,ads,LIST"):
            self.assertIn(entry + "\n", out["fin-qx.txt"])
        for entry in ("IP-ASN,13335,no-resolve", "GEOIP,CN,no-resolve", "DOMAIN-KEYWORD,ads"):
            self.assertIn('  - "' + entry + '"\n', out["fin.yaml"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-KEYWORD"], 1)

    def test_mihomo_only_types_are_json_quoted_yaml_scalars(self):
        rules = [
            Rule("DOMAIN-REGEX", '^ad-"promo"\\.example\\.com$'),
            Rule("PROCESS-PATH", "C:\\Program Files\\Foo\\bar.exe"),
            Rule("NETWORK", "udp"), Rule("IN-TYPE", "SOCKS/HTTP"),
        ]
        out, skipped = render("a3", rules)
        self.assertEqual(out["fin.yaml"].splitlines()[0:2], ["# a3 rules: 4", "payload:"])
        self.assertEqual(
            {json.loads(line.removeprefix("  - ")) for line in out["fin.yaml"].splitlines()[2:]},
            {
                'DOMAIN-REGEX,^ad-"promo"\\.example\\.com$',
                "PROCESS-PATH,C:\\Program Files\\Foo\\bar.exe",
                "NETWORK,udp", "IN-TYPE,SOCKS/HTTP",
            },
        )
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin-qx.txt:DOMAIN-REGEX"], 1)
        self.assertEqual(skipped["fin.txt:PROCESS-PATH"], 1)

    def test_all_mihomo_values_use_json_quoted_yaml_strings(self):
        value = 'Foo"bar\\baz'
        out, _ = render("a3", [Rule("PROCESS-NAME", value)])
        self.assertIn('\\"', out["fin.yaml"].splitlines()[2])
        self.assertEqual(json.loads(out["fin.yaml"].splitlines()[2][4:]),
                         'PROCESS-NAME,Foo"bar\\baz')
        self.assertEqual(out["fin.yaml"].splitlines()[0], "# a3 rules: 1")

    def test_mihomo_classical_preserves_documented_types_not_provider_directives(self):
        entries = [
            ("GEOSITE", "youtube"), ("IP-SUFFIX", "8.8.8.8/24"),
            ("SRC-GEOIP", "CN"), ("SRC-IP-ASN", "9808"),
            ("SRC-IP-SUFFIX", "192.0.2.1/8"), ("IN-PORT", "7890"),
            ("IN-USER", "alice"), ("IN-NAME", "socks"),
            ("REMATCH-NAME", "rematch1"), ("PROCESS-PATH-WILDCARD", "/usr/*/wget"),
            ("PROCESS-PATH-REGEX", ".*bin/wget"),
            ("PROCESS-NAME-WILDCARD", "*telegram*"),
            ("PROCESS-NAME-REGEX", "curl$"), ("UID", "1001"), ("DSCP", "4"),
        ]
        out, skipped = render("a3", [Rule(kind, value) for kind, value in entries] + [
            Rule("RULE-SET", "another-provider"), Rule("SUB-RULE", "(NETWORK,tcp)"),
            Rule("MATCH", ""),
        ])
        self.assertEqual(out["fin.yaml"].splitlines()[0], "# a3 rules: 15")
        self.assertEqual(
            {json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
            {f"{kind},{value}" for kind, value in entries},
        )
        for kind in ("RULE-SET", "SUB-RULE", "MATCH"):
            self.assertEqual(skipped[f"fin.yaml:{kind}"], 1)
        self.assertNotIn("IN-TYPE", out["fin-qx.txt"])

    def test_parsed_single_child_not_is_rendered_with_valid_parentheses(self):
        from rules import parse

        parsed, messages = parse("NOT,(DOMAIN,cdn.example.com),PROXY", purpose="proxy")
        self.assertEqual(messages, [])
        out, _ = render("cdn", parsed)
        self.assertIn("NOT,((DOMAIN,cdn.example.com))\n", out["fin.txt"])
        self.assertIn('"NOT,((DOMAIN,cdn.example.com))"', out["fin.yaml"])

    def test_logical_rules_keep_parentheses_only_with_compatible_children(self):
        values = {
            "AND": "((DOMAIN,ads.example.com),(NETWORK,UDP))",
            "OR": "((DOMAIN,ads.example.com),(DOMAIN-SUFFIX,other.example.com))",
            "NOT": "((DOMAIN,safe.example.com))",
        }
        out, skipped = render("a3", [Rule(kind, value) for kind, value in values.items()] + [
            Rule("AND", "((RULE-SET,another-provider),(DOMAIN,ad.example.com))"),
        ])
        for kind, value in values.items():
            self.assertIn(f'  - "{kind},{value}"\n', out["fin.yaml"])
            self.assertEqual(skipped[f"fin-qx.txt:{kind}"], 1 if kind != "AND" else 2)
        self.assertIn("OR," + values["OR"] + "\n", out["fin.txt"])
        self.assertIn("NOT," + values["NOT"] + "\n", out["fin-surge.txt"])
        self.assertNotIn("NETWORK,UDP", out["fin.txt"])
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.txt:AND"], 2)
        self.assertNotIn("RULE-SET", out["fin.yaml"])

    def test_surge_translates_nested_source_cidr_and_destination_port(self):
        value = "((SRC-IP-CIDR,2001:db8::/32),(DST-PORT,443))"
        out, skipped = render("a3", [Rule("AND", value)])
        expected = "AND,((SRC-IP,2001:db8::/32),(DEST-PORT,443))\n"
        self.assertIn(expected, out["fin.txt"])
        self.assertIn(expected, out["fin-surge.txt"])
        self.assertIn('  - "AND,' + value + '"\n', out["fin.yaml"])
        self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_surge_ipv6_cidr_inside_logic_uses_ipv6_matcher(self):
        value = "((IP-CIDR,2001:db8::/32),(DOMAIN,ads.example.com))"
        out, _ = render("a3", [Rule("OR", value)])
        self.assertIn("OR,((IP-CIDR6,2001:db8::/32),(DOMAIN,ads.example.com))\n", out["fin.txt"])
        self.assertIn('  - "OR,' + value + '"\n', out["fin.yaml"])

    def test_logical_regex_character_class_parenthesis_is_not_structural(self):
        expression = r"((DOMAIN-REGEX,^[a)b]\.example$),(DOMAIN,ads.example))"
        out, _ = render("a3", [Rule("AND", expression)])
        self.assertIn(
            f"AND,{expression}",
            [json.loads(line.removeprefix("  - ")) for line in out["fin.yaml"].splitlines()[2:]],
        )

    def test_invalid_logical_children_and_parentheses_are_skipped(self):
        out, skipped = render("a3", [
            Rule("AND", "((DOMAIN,valid.example.com),(UNKNOWN,v))"),
            Rule("NOT", "(UNKNOWN,invalid.example.com)"),
        ])
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.yaml:NOT"], 1)

    def test_logical_arity_is_valid_for_not_and_and(self):
        out, skipped = render("a3", [
            Rule("AND", "((DOMAIN,ad.example.com))"),
            Rule("NOT", "((DOMAIN,first.example.com),(DOMAIN,second.example.com))"),
        ])
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.yaml:NOT"], 1)

    def test_logical_children_require_separating_comma(self):
        out, skipped = render("a3", [Rule("AND", "((DOMAIN,one.example.com)(DOMAIN,two.example.com))")])
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertEqual(skipped["fin.txt:AND"], 1)

    def test_mihomo_does_not_accept_surge_only_wildcard_class_inside_logic(self):
        value = "((DOMAIN-WILDCARD,api-[0-9].example.com),(DOMAIN,ads.example.com))"
        out, skipped = render("a3", [Rule("AND", value)])
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertIn("AND," + value + "\n", out["fin.txt"])
        self.assertEqual(skipped["fin.yaml:AND"], 1)

    def test_surge_ruleset_retains_other_documented_types(self):
        entries = [
            ("SRC-IP", "192.0.2.1"), ("URL-REGEX", "^https://ads\\.example/"),
            ("DEVICE-NAME", "Kids-iPad"), ("MAC-ADDRESS", "A4:83:E7:11:22:33"),
            ("PROTOCOL", "UDP"), ("HOSTNAME-TYPE", "IP"),
            ("SUBNET", "TYPE:CELLULAR"), ("CELLULAR-RADIO", "NR"),
            ("CELLULAR-CARRIER", "Carrier"),
        ]
        out, skipped = render("a3", [Rule(kind, value) for kind, value in entries])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertEqual(out[name].splitlines()[0], "# a3 rules: 9")
            self.assertEqual(set(out[name].splitlines()[1:]),
                             {f"{kind},{value}" for kind, value in entries})
        self.assertEqual(skipped["fin.yaml:URL-REGEX"], 1)
        self.assertEqual(skipped["fin-qx.txt:DEVICE-NAME"], 1)

    def test_surge_quotes_regex_with_comma_in_value(self):
        value = r"^https://ads\.example\.com/promo.{1,2}$"
        out, skipped = render("a3", [Rule("URL-REGEX", value)])
        self.assertIn("URL-REGEX,'" + value + "'\n", out["fin.txt"])
        self.assertIn("URL-REGEX,'" + value + "'\n", out["fin-surge.txt"])
        self.assertEqual(skipped["fin.yaml:URL-REGEX"], 1)

    def test_qx_does_not_split_user_agent_value_containing_comma(self):
        value = "Mozilla/5.0 (Macintosh, Intel Mac OS X)"
        out, skipped = render("a3", [Rule("USER-AGENT", value)])
        self.assertIn("USER-AGENT,'" + value + "'\n", out["fin.txt"])
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin-qx.txt:USER-AGENT"], 1)

    def test_simple_allow_rule_is_only_emitted_as_adblock_exception(self):
        out, skipped = render("a3", [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN", "exact.example.com", allow=True),
        ])
        self.assertEqual(out["fin-adb.txt"], "! a3 rules: 1\n@@||safe.example.com^\n")
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin-adb.txt:DOMAIN"], 1)
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)

    def test_unknown_and_wildcard_omissions_are_counted_per_file(self):
        out, skipped = render("a3", [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"), Rule("UNKNOWN-TYPE", "opaque"),
        ])
        self.assertEqual(skipped.get("fin-adb.txt:DOMAIN-WILDCARD"), 1)
        self.assertEqual(skipped.get("fin-surge-ds.txt:DOMAIN-WILDCARD"), 1)
        self.assertTrue(all(skipped.get(f"{name}:UNKNOWN-TYPE") == 1 for name in out))
        self.assertNotIn("fin-surge.txt:DOMAIN-WILDCARD", skipped)
        self.assertEqual(out["fin.txt"].splitlines()[0], "# a3 rules: 1")

    def test_non_advertising_groups_emit_only_adblock_explanation(self):
        for group in ("cdn", "big-data", "dirt"):
            with self.subTest(group=group):
                out, skipped = render(group, [Rule("DOMAIN-SUFFIX", "legitimate.example.com")])
                self.assertEqual(out["fin-adb.txt"],
                                 f"! {group} rules: 0\n! No AdBlock rules for non-advertising group.\n")
                self.assertIn("DOMAIN-SUFFIX,legitimate.example.com\n", out["fin.txt"])
                self.assertEqual(skipped["fin-adb.txt:DOMAIN-SUFFIX"], 1)

    def test_non_dirt_destination_cidr_adds_no_resolve_on_supported_targets(self):
        rule = Rule("IP-CIDR", "203.0.113.0/24")
        out, _ = render("a3", [rule])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin-surge.txt"])
        self.assertIn("IP-CIDR,203.0.113.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('"IP-CIDR,203.0.113.0/24,no-resolve"', out["fin.yaml"])
        domestic, _ = render("dirt", [rule])
        self.assertIn("IP-CIDR,203.0.113.0/24\n", domestic["fin.txt"])
        self.assertNotIn("no-resolve", domestic["fin.txt"])

    def test_no_resolve_is_preserved_without_silently_dropping_other_options(self):
        out, skipped = render("a3", [
            Rule("IP-CIDR", "203.0.113.0/24", ("no-resolve",)),
            Rule("DOMAIN-SUFFIX", "unsafe.example.com", ("unverified-flag",)),
        ])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn('  - "IP-CIDR,203.0.113.0/24,no-resolve"\n', out["fin.yaml"])
        self.assertIn("IP-CIDR,203.0.113.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertEqual(skipped.get("fin-qx.txt:IP-CIDR", 0), 0)
        self.assertTrue(all("unsafe.example.com" not in body for body in out.values()))
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)
