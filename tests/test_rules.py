import time
import unittest
import warnings

import rules
from rules import Rule, normalize, parse


class RuleTests(unittest.TestCase):
    def test_domain_canonicalization_preserves_process_case(self):
        self.assertEqual(Rule("domain", "Ads.Example.COM."), Rule("DOMAIN", "ads.example.com"))
        self.assertNotEqual(Rule("PROCESS-NAME", "FooApp"), Rule("PROCESS-NAME", "fooapp"))
        self.assertEqual(len({Rule("DOMAIN", "EXAMPLE.COM"), Rule("domain", "example.com")}), 1)

    def test_options_are_canonical_for_grouping(self):
        self.assertEqual(
            Rule("IP-CIDR", "192.0.2.0/24", ("NO-RESOLVE", "extra")),
            Rule("IP-CIDR", "192.0.2.0/24", ("extra", "no-resolve")),
        )


class ParseTests(unittest.TestCase):
    def test_mixed_inputs_and_wildcard_survive(self):
        rules, warnings = parse(
            "HOST-SUFFIX,EXAMPLE.COM,REJECT\n"
            "DOMAIN-WILDCARD,api-*.example.com\n"
            "0.0.0.0 ads.test\n"
            "body{",
            purpose="block",
        )
        self.assertIn(Rule("DOMAIN-SUFFIX", "example.com"), rules)
        self.assertIn(Rule("DOMAIN-WILDCARD", "api-*.example.com"), rules)
        self.assertIn(Rule("DOMAIN", "ads.test"), rules)
        self.assertEqual(len(rules), 3)
        self.assertTrue(any("4" in warning for warning in warnings))

    def test_hosts_aliases_and_ipv6_loopback_keep_all_domains(self):
        rules, warnings = parse(
            "0.0.0.0 ads.example.com track.example.com\n::1 ipv6.example.com\n"
            "1.2.3.4 legitimate.example.com",
            purpose="block",
        )
        self.assertEqual(rules, [
            Rule("DOMAIN", "ads.example.com"), Rule("DOMAIN", "track.example.com"),
            Rule("DOMAIN", "ipv6.example.com"),
        ])
        self.assertEqual(len(warnings), 1)

    def test_abp_block_and_allow_preserve_domain_scope(self):
        rules, warnings = parse("||ads.example.com^\n@@||safe.example.com^", purpose="block")
        self.assertEqual(rules, [
            Rule("DOMAIN-SUFFIX", "ads.example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])
        self.assertEqual(warnings, [])

    def test_abp_block_rule_is_not_a_no_action_direct_rule(self):
        rules, warnings = parse("||ads.example.com^\n@@||safe.example.com^", purpose="direct")
        self.assertEqual(rules, [Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True)])
        self.assertTrue(any("line 1" in message for message in warnings))

    def test_conditional_abp_is_skipped_with_reason(self):
        rules, warnings = parse(
            "@@||safe.example.com^$domain=example.org\n||ads.example.com^$third-party\n||bad.example.com^",
            purpose="block",
        )
        self.assertEqual(rules, [Rule("DOMAIN-SUFFIX", "bad.example.com")])
        self.assertEqual(len(warnings), 2)
        self.assertTrue(all("conditional" in message for message in warnings))

    def test_surge_domain_set_exact_and_suffix(self):
        rules, warnings = parse("ads.example.com\n.example.org", purpose="block")
        self.assertEqual(rules, [
            Rule("DOMAIN", "ads.example.com"),
            Rule("DOMAIN-SUFFIX", "example.org"),
        ])
        self.assertEqual(warnings, [])

    def test_quoted_yaml_payload_only(self):
        rules, warnings = parse(
            "payload:\n  - 'DOMAIN,ads.example.com'\n  - 'DOMAIN-SUFFIX,AD.EXAMPLE.COM,REJECT'",
            purpose="block",
        )
        self.assertEqual(rules, [
            Rule("DOMAIN", "ads.example.com"),
            Rule("DOMAIN-SUFFIX", "ad.example.com"),
        ])
        self.assertEqual(warnings, [])

    def test_renderer_double_quoted_yaml_payload_round_trips(self):
        from formats import render

        document = render("a3", [Rule("DOMAIN-SUFFIX", "ads.example.com")],
                          purpose="block", no_resolve="add")[0]["fin.yaml"]
        rules, messages = parse(document, purpose="block")
        self.assertEqual(rules, [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertEqual(messages, [])

    def test_unquoted_mihomo_yaml_payload_retains_rules(self):
        rules, warnings = parse(
            "# Total Lines: 2\npayload:\n  - DOMAIN-SUFFIX,000607.com.cn\n"
            "  - IP-CIDR,203.0.113.0/24\n", purpose="direct",
        )
        self.assertEqual(rules, [
            Rule("DOMAIN-SUFFIX", "000607.com.cn"), Rule("IP-CIDR", "203.0.113.0/24"),
        ])
        self.assertEqual(warnings, [])

    def test_yaml_payload_stops_at_next_top_level_key(self):
        rules, warnings = parse(
            "payload:\n  - 'DOMAIN,good.example.com'\nmetadata:\n"
            "  - 'DOMAIN,bad.example.com'\nDOMAIN,other.example.com",
            purpose="block",
        )
        self.assertEqual(rules, [
            Rule("DOMAIN", "good.example.com"), Rule("DOMAIN", "other.example.com")
        ])
        self.assertTrue(any("line 4" in message for message in warnings))

    def test_qx_policies_do_not_change_other_purposes(self):
        source = ("HOST,ads.example.com,REJECT\nDOMAIN,direct.example.com,DIRECT\n"
                  "DOMAIN,proxy.example.com,PROXY\nDOMAIN,unassigned.example.com,LIST")
        for purpose, expected in (
            ("block", "ads.example.com"),
            ("direct", "direct.example.com"),
            ("proxy", "proxy.example.com"),
        ):
            with self.subTest(purpose=purpose):
                rules, warnings = parse(source, purpose=purpose)
                self.assertEqual(rules, [
                    Rule("DOMAIN", expected), Rule("DOMAIN", "unassigned.example.com")
                ])
                self.assertEqual(len(warnings), 2)

    def test_adblock_named_policy_is_only_accepted_in_block_group(self):
        source = "HOST-SUFFIX,ads.example.com,ADBLOCK"
        self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_advertisinglite_named_policy_is_only_accepted_in_block_group(self):
        source = "HOST-SUFFIX,ads.example.com,AdvertisingLite"
        self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_hijacking_named_policy_is_only_accepted_in_block_group(self):
        source = "HOST-SUFFIX,hijack.example.com,Hijacking"
        self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "hijack.example.com")])
        self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_curated_privacy_and_zhihu_ads_policies_are_block_only(self):
        for policy in ("Privacy", "ZhihuAds"):
            with self.subTest(policy=policy):
                source = f"HOST-SUFFIX,ads.example.com,{policy}"
                self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com")])
                self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_named_routing_policies_are_accepted_without_reclassifying_reject(self):
        self.assertEqual(
            parse("HOST-SUFFIX,cdn.example.com,JSDELIVR", purpose="proxy")[0],
            [Rule("DOMAIN-SUFFIX", "cdn.example.com")],
        )
        self.assertEqual(
            parse("HOST-SUFFIX,cn.example.com,China", purpose="direct")[0],
            [Rule("DOMAIN-SUFFIX", "cn.example.com")],
        )
        self.assertEqual(parse("HOST-SUFFIX,cdn.example.com,REJECT", purpose="proxy")[0], [])
        self.assertEqual(parse("HOST-SUFFIX,cn.example.com,DIRECT", purpose="block")[0], [])

    def test_curated_a1_filter_policies_remain_block_only(self):
        for policy in ("AdGuardSDNSFilter", "AdvertisingMiTV", "BlockHttpDNS", "EasyPrivacy"):
            with self.subTest(policy=policy):
                source = f"HOST-SUFFIX,ads.example.com,{policy}"
                self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com")])
                self.assertEqual(parse(source, purpose="proxy")[0], [])

    def test_ruleset_wide_option_is_not_mistaken_for_a_routing_policy(self):
        rules, messages = parse(
            "DOMAIN-SUFFIX,ads.example.com,extended-matching\n"
            "DOMAIN,keep.example.com,PROXY", purpose="proxy",
        )
        self.assertEqual(rules, [Rule("DOMAIN", "keep.example.com")])
        self.assertTrue(any("extended-matching" in message for message in messages))

    def test_unknown_reject_like_action_cannot_be_treated_as_a_routing_policy(self):
        for purpose in ("direct", "proxy"):
            with self.subTest(purpose=purpose):
                source = "DOMAIN,wrong.example.com,REJECT-FAKE\nDOMAIN,right.example.com,China"
                rules, messages = parse(source, purpose=purpose)
                self.assertEqual(rules, [Rule("DOMAIN", "right.example.com")])
                self.assertTrue(any("REJECT-FAKE" in message for message in messages))

    def test_unknown_action_cannot_be_treated_as_block(self):
        rules, warnings = parse(
            "DOMAIN,wrong.example.com,REJECTION\nDOMAIN,also-wrong.example.com,REJECT-FAKE\n"
            "DOMAIN,valid.example.com,REJECT-IMG",
            purpose="block",
        )
        self.assertEqual(rules, [Rule("DOMAIN", "valid.example.com")])
        self.assertEqual(len(warnings), 2)

    def test_qx_host_keyword_retains_keyword_type(self):
        rules, warnings = parse("HOST-KEYWORD,TrackAds,REJECT", purpose="block")
        self.assertEqual(rules, [Rule("DOMAIN-KEYWORD", "trackads")])
        self.assertEqual(warnings, [])

    def test_explicit_single_label_hosts_and_tld_suffixes_are_kept(self):
        rules, messages = parse(
            "DOMAIN-SUFFIX,cn,DIRECT\nDOMAIN-SUFFIX,xn--fiqs8s,DIRECT\n"
            "DOMAIN,unifi,DIRECT\nunifi", purpose="direct",
        )
        self.assertEqual(rules, [
            Rule("DOMAIN-SUFFIX", "cn"), Rule("DOMAIN-SUFFIX", "xn--fiqs8s"),
            Rule("DOMAIN", "unifi"),
        ])
        self.assertTrue(any("line 4" in message for message in messages))

    def test_bare_ipv4_and_ipv6_network_lists_remain_ip_rules(self):
        rules, warnings = parse("203.0.113.0/24\n2001:db8::/32\n", purpose="direct")
        self.assertEqual(rules, [
            Rule("IP-CIDR", "203.0.113.0/24"), Rule("IP-CIDR6", "2001:db8::/32"),
        ])
        self.assertEqual(warnings, [])

    def test_ipv4_ipv6_source_and_destination_cidr_keep_direction_and_options(self):
        rules, warnings = parse(
            "SRC-IP-CIDR,2001:db8::1/32,DIRECT,no-resolve\n"
            "IP-CIDR,192.0.2.15/24,DIRECT,no-resolve\n"
            "IP6-CIDR,2001:db8:1::/48,PROXY",
            purpose="direct",
        )
        self.assertEqual(rules, [
            Rule("SRC-IP-CIDR", "2001:db8::/32", ("no-resolve",)),
            Rule("IP-CIDR", "192.0.2.0/24", ("no-resolve",)),
        ])
        self.assertEqual(len(warnings), 1)
        proxy, _ = parse("IP6-CIDR,2001:db8:1::/48,PROXY", purpose="proxy")
        self.assertEqual(proxy, [Rule("IP-CIDR6", "2001:db8:1::/48")])

    def test_port_rules_keep_source_destination_and_range(self):
        rules, warnings = parse(
            "SRC-PORT,8080,PROXY\nDEST-PORT,443,PROXY\nDST-PORT,1024-2048,PROXY\nDST-PORT,65536,PROXY",
            purpose="proxy",
        )
        self.assertEqual(rules, [
            Rule("SRC-PORT", "8080"),
            Rule("DEST-PORT", "443"),
            Rule("DST-PORT", "1024-2048"),
        ])
        self.assertEqual(len(warnings), 1)

    def test_in_port_is_kept_for_compatible_targets(self):
        rules, warnings = parse("IN-PORT,443,PROXY", purpose="proxy")
        self.assertEqual(rules, [Rule("IN-PORT", "443")])
        self.assertEqual(warnings, [])

    def test_rendered_surge_regex_with_literal_comma_round_trips(self):
        from formats import render

        original = Rule("URL-REGEX", r"^https://ads\.example/promo,a$")
        text = render("a3", [original], purpose="block", no_resolve="add")[0]["fin.txt"]
        parsed, messages = parse(text, purpose="block")
        self.assertEqual(parsed, [original])
        self.assertEqual(messages, [])

    def test_surge_url_regex_survives_parsing(self):
        rules, warnings = parse(r"URL-REGEX,^https://ads\.example/,REJECT", purpose="block")
        self.assertEqual(rules, [Rule("URL-REGEX", r"^https://ads\.example/")])
        self.assertEqual(warnings, [])

    def test_process_wildcard_types_survive_parsing(self):
        rules, warnings = parse(
            "PROCESS-NAME-WILDCARD,*telegram*,PROXY\n"
            "PROCESS-PATH-WILDCARD,/Applications/*,PROXY", purpose="proxy",
        )
        self.assertEqual(rules, [
            Rule("PROCESS-NAME-WILDCARD", "*telegram*"),
            Rule("PROCESS-PATH-WILDCARD", "/Applications/*"),
        ])
        self.assertEqual(warnings, [])

    def test_process_values_retain_case_and_path(self):
        rules, warnings = parse(
            "PROCESS-NAME,MyBrowser.exe,DIRECT\nPROCESS-PATH,C:\\Apps\\Browser.exe,DIRECT",
            purpose="direct",
        )
        self.assertEqual(rules, [
            Rule("PROCESS-NAME", "MyBrowser.exe"),
            Rule("PROCESS-PATH", "C:\\Apps\\Browser.exe"),
        ])
        self.assertEqual(warnings, [])

    def test_surge_protocol_is_retained_for_compatible_outputs(self):
        rules, warnings = parse("PROTOCOL,UDP,PROXY", purpose="proxy")
        self.assertEqual(rules, [Rule("PROTOCOL", "UDP")])
        self.assertEqual(warnings, [])

    def test_non_domain_types_are_retained_without_domain_coercion(self):
        source = ("IP-ASN,64512,PROXY\nGEOIP,CN,PROXY\nUSER-AGENT,Chrome/*,PROXY\n"
                  "SRC-IP,2001:db8::1,PROXY\nNETWORK,TCP,PROXY\nIN-TYPE,HTTP,PROXY\n"
                  "DOMAIN-KEYWORD,AdServe,PROXY\nDOMAIN-REGEX,^ads\\.example\\.com$,PROXY")
        rules, warnings = parse(source, purpose="proxy")
        self.assertEqual(rules, [
            Rule("IP-ASN", "64512"), Rule("GEOIP", "CN"),
            Rule("USER-AGENT", "Chrome/*"), Rule("SRC-IP", "2001:db8::1"),
            Rule("NETWORK", "TCP"), Rule("IN-TYPE", "HTTP"),
            Rule("DOMAIN-KEYWORD", "adserve"),
            Rule("DOMAIN-REGEX", r"^ads\.example\.com$"),
        ])
        self.assertEqual(warnings, [])

    def test_domain_regex_quantifier_comma_stays_in_value(self):
        rules, warnings = parse(
            r"DOMAIN-REGEX,^ad{2,3}\.example\.com$,REJECT", purpose="block"
        )
        self.assertEqual(rules, [Rule("DOMAIN-REGEX", r"^ad{2,3}\.example\.com$")])
        self.assertEqual(warnings, [])

    def test_invalid_domain_regex_is_skipped_before_normalization(self):
        rules, messages = parse(
            "DOMAIN-REGEX,*ads,REJECT\nDOMAIN,valid.example.com,REJECT", purpose="block",
        )
        self.assertEqual(rules, [Rule("DOMAIN", "valid.example.com")])
        self.assertTrue(any("line 1" in message and "invalid" in message for message in messages))
        self.assertEqual(normalize(rules), rules)

    def test_logical_regex_character_class_parenthesis_survives_parse(self):
        expression = r"((DOMAIN-REGEX,^[a)b]\.example$),(DOMAIN,ads.example))"
        rules, warnings = parse(f"AND,{expression},REJECT", purpose="block")
        self.assertEqual(rules, [Rule("AND", expression)])
        self.assertEqual(warnings, [])

    def test_logical_child_rejects_invalid_regex(self):
        rules, messages = parse(
            "AND,((DOMAIN-REGEX,*ads),(DOMAIN,ads.example.com)),REJECT", purpose="block",
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("invalid logical" in message for message in messages))

    def test_logical_child_rejects_invalid_port(self):
        rules, warnings = parse(
            "AND,((SRC-PORT,99999),(DOMAIN,ads.example.com)),REJECT", purpose="block"
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("invalid logical" in warning for warning in warnings))

    def test_logical_child_rejects_invalid_asn(self):
        rules, warnings = parse(
            "AND,((IP-ASN,NaN),(DOMAIN,ads.example.com)),REJECT", purpose="block"
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("invalid logical" in warning for warning in warnings))

    def test_logical_rules_keep_nested_expression_and_policy(self):
        rules, warnings = parse(
            "AND,((DOMAIN,ads.example.com),(PROCESS-NAME,Game.exe)),PROXY\n"
            "OR,((NETWORK,TCP),(NETWORK,UDP)),PROXY\n"
            "NOT,(DOMAIN,cdn.example.com),PROXY",
            purpose="proxy",
        )
        self.assertEqual(rules, [
            Rule("AND", "((DOMAIN,ads.example.com),(PROCESS-NAME,Game.exe))"),
            Rule("OR", "((NETWORK,TCP),(NETWORK,UDP))"),
            Rule("NOT", "(DOMAIN,cdn.example.com)"),
        ])
        self.assertEqual(warnings, [])

    def test_not_accepts_a_single_child_wrapped_for_classical_rules(self):
        expression = "((DOMAIN,cdn.example.com))"
        rules, messages = parse(f"NOT,{expression},PROXY", purpose="proxy")
        self.assertEqual(rules, [Rule("NOT", expression)])
        self.assertEqual(messages, [])

    def test_logical_rule_rejects_unknown_nested_type(self):
        rules, warnings = parse(
            "AND,((UNKNOWN,foo),(DOMAIN,ads.example.com)),PROXY\n"
            "AND,(DOMAIN,ads.example.com),PROXY\n"
            "NOT,(DOMAIN,cdn.example.com),PROXY",
            purpose="proxy",
        )
        self.assertEqual(rules, [Rule("NOT", "(DOMAIN,cdn.example.com)")])
        self.assertEqual(len(warnings), 2)

    def test_logical_rule_rejects_invalid_nested_domain(self):
        rules, warnings = parse(
            "AND,((DOMAIN,bad..example.com),(DOMAIN,good.example.com)),PROXY",
            purpose="proxy",
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("line 1" in message for message in warnings))

    def test_generic_html_tag_rejects_source_but_comment_markup_does_not(self):
        html, messages = parse(
            "<main>\nDOMAIN,ads.example.com,REJECT\n</main>", purpose="block",
        )
        self.assertEqual(html, [])
        self.assertTrue(any("HTML" in message for message in messages))
        commented, messages = parse(
            "# <div>documentation</div>\nDOMAIN,ads.example.com,REJECT", purpose="block",
        )
        self.assertEqual(commented, [Rule("DOMAIN", "ads.example.com")])
        self.assertEqual(messages, [])

    def test_self_closing_html_tag_cannot_hide_a_valid_rule(self):
        rules, messages = parse("<img/>\nDOMAIN,ads.example.com,REJECT", purpose="block")
        self.assertEqual(rules, [])
        self.assertTrue(any("HTML" in message for message in messages))

    def test_html_document_cannot_hide_a_valid_rule(self):
        rules, warnings = parse(
            "<!doctype html>\n<html><body>\nDOMAIN,ads.example.com,REJECT\n</body></html>",
            purpose="block",
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("HTML" in message and "1" in message for message in warnings))

    def test_script_html_wrapper_is_rejected_as_a_whole(self):
        rules, warnings = parse(
            "<script>\nDOMAIN,ads.example.com,REJECT\n</script>", purpose="block"
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("HTML" in message for message in warnings))

    def test_dns_names_accept_one_final_dot_but_not_ip_literals(self):
        rules, warnings = parse(
            "DOMAIN,Ads.Example.COM.,REJECT\n8.8.8.8\nDOMAIN,192.0.2.1,REJECT",
            purpose="block",
        )
        self.assertEqual(rules, [Rule("DOMAIN", "ads.example.com")])
        self.assertEqual(len(warnings), 2)

    def test_surge_brackets_survive_only_as_wildcard_and_domains_are_validated(self):
        rules, warnings = parse(
            "DOMAIN-WILDCARD,cdn[0-9].example.com,REJECT\n"
            "DOMAIN,*.example.com,REJECT\nDOMAIN,ads..example.com,REJECT\n"
            "DOMAIN-WILDCARD,cdn[0-9.example.com,REJECT\nMYSTERY,ads.example.com,REJECT",
            purpose="block",
        )
        self.assertEqual(rules, [Rule("DOMAIN-WILDCARD", "cdn[0-9].example.com")])
        self.assertEqual(len(warnings), 4)
        self.assertIn("MYSTERY", warnings[-1])

    def test_qx_no_resolve_before_or_after_action(self):
        rules, warnings = parse(
            "[filter_local]\nIP-CIDR,192.0.2.0/25,no-resolve,REJECT\n"
            "IP-CIDR,198.51.100.0/24,REJECT,NO-RESOLVE",
            purpose="block",
        )
        self.assertEqual(rules, [
            Rule("IP-CIDR", "192.0.2.0/25", ("no-resolve",)),
            Rule("IP-CIDR", "198.51.100.0/24", ("no-resolve",)),
        ])
        self.assertEqual(warnings, [])


class WhitelistTests(unittest.TestCase):
    def test_qx_policy_is_ignored_when_parsing_whitelist(self):
        self.assertEqual(rules.parse_whitelist("host-suffix,a.com,DIRECT"), [
            Rule("DOMAIN-SUFFIX", "a.com")
        ])

    def test_surge_reject_policy_is_ignored_when_parsing_whitelist(self):
        self.assertEqual(rules.parse_whitelist("DOMAIN-KEYWORD,ads,REJECT"), [
            Rule("DOMAIN-KEYWORD", "ads")
        ])

    def test_whitelist_skips_useragent_process_and_reports_invalid_domain(self):
        source = ("USER-AGENT,*bot*,DIRECT\nPROCESS-NAME,App,REJECT\n"
                  "DOMAIN-SUFFIX,ads.example.com,DIRECT\nDOMAIN,bad..com,REJECT")
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            parsed = rules.parse_whitelist(source)
        self.assertEqual(parsed, [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertTrue(any("line 4" in str(item.message) and "invalid domain" in str(item.message)
                            for item in reported))

    def test_keyword_whitelist_preserves_trailing_dot_match_scope(self):
        trailing = rules.parse_whitelist("DOMAIN-KEYWORD,ads.")
        self.assertEqual(trailing, [Rule("DOMAIN-KEYWORD", "ads.")])
        exact = [Rule("DOMAIN", "adsense.com")]
        self.assertEqual(rules.exclude_covered(exact, trailing), exact)
        dot = rules.parse_whitelist("DOMAIN-KEYWORD,.")
        self.assertEqual(dot, [Rule("DOMAIN-KEYWORD", ".")])
        keyword = [Rule("DOMAIN-KEYWORD", "track")]
        self.assertEqual(rules.exclude_covered(keyword, dot), keyword)

    def test_keyword_whitelist_covers_rules_with_required_substring(self):
        source = [
            Rule("DOMAIN", "tracker.example.com"),
            Rule("DOMAIN-SUFFIX", "tracker.example.com"),
            Rule("DOMAIN-KEYWORD", "tracker"),
            Rule("DOMAIN-KEYWORD", "tra"),
            Rule("DOMAIN", "example.net"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-KEYWORD", "track")]
        ), source[3:])

    def test_wildcard_whitelist_covers_matching_exact_domain_only(self):
        source = [
            Rule("DOMAIN", "api-1.example.com"),
            Rule("DOMAIN", "api.example.com"),
            Rule("DOMAIN-SUFFIX", "api-1.example.com"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-WILDCARD", "api-*.example.com")]
        ), source[1:])

    def test_identical_surge_bracket_wildcard_is_covered(self):
        source = [
            Rule("DOMAIN-WILDCARD", "cdn[0-9].example.com"),
            Rule("DOMAIN-WILDCARD", "cdn*.example.com"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-WILDCARD", "cdn[0-9].example.com")]
        ), source[1:])

    def test_literal_wildcard_rule_is_treated_as_exact_domain(self):
        self.assertEqual(rules.exclude_covered(
            [Rule("DOMAIN-WILDCARD", "api.example.com")],
            [Rule("DOMAIN-SUFFIX", "example.com")],
        ), [])

    def test_keyword_covers_wildcard_only_via_fixed_text(self):
        source = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "cdn[0-9].example.com"),
            Rule("DOMAIN-WILDCARD", "cdn*.other.com"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-KEYWORD", "example")]
        ), source[2:])
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-KEYWORD", "0-9")]
        ), source)

    def test_suffix_covers_wildcards_only_with_fixed_label_boundary(self):
        source = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "cdn[0-9].example.com"),
            Rule("DOMAIN-WILDCARD", "api-*.notexample.com"),
            Rule("DOMAIN-WILDCARD", "*example.com"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-SUFFIX", "example.com")]
        ), source[2:])

    def test_exact_whitelist_does_not_remove_wider_suffix(self):
        source = [Rule("DOMAIN-SUFFIX", "a.com")]
        self.assertEqual(rules.exclude_covered(source, [Rule("DOMAIN", "a.com")]), source)

    def test_parent_suffix_whitelist_removes_narrow_suffix(self):
        self.assertEqual(rules.exclude_covered(
            [Rule("DOMAIN-SUFFIX", "a.com")], [Rule("DOMAIN-SUFFIX", "com")]
        ), [])

    def test_suffix_whitelist_removes_child_domain_ignoring_options(self):
        self.assertEqual(rules.exclude_covered(
            [Rule("DOMAIN", "sub.a.com", ("no-resolve",))],
            [Rule("DOMAIN-SUFFIX", "a.com")],
        ), [])

    def test_exact_whitelist_removes_only_same_domain(self):
        source = [Rule("DOMAIN", "ads.a.com"), Rule("DOMAIN", "notads.a.com")]
        self.assertEqual(rules.exclude_covered(source, [Rule("DOMAIN", "ADS.A.COM")]), source[1:])

    def test_parent_destination_ipv4_cidr_covers_child_ignoring_options(self):
        self.assertEqual(rules.exclude_covered(
            [Rule("IP-CIDR", "192.0.2.0/25", ("no-resolve",))],
            [Rule("IP-CIDR", "192.0.2.0/24")],
        ), [])

    def test_ipv6_coverage_does_not_cross_family_or_direction(self):
        source = [
            Rule("IP-CIDR6", "2001:db8:1::/48"),
            Rule("IP-CIDR6", "2001:db8::/31"),
            Rule("SRC-IP-CIDR", "2001:db8:1::/48"),
            Rule("IP-CIDR", "192.0.2.0/25"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("IP-CIDR6", "2001:db8::/32")]
        ), source[1:])

    def test_source_cidr_parent_only_covers_same_family_children(self):
        source = [
            Rule("SRC-IP-CIDR", "192.0.2.0/25"),
            Rule("SRC-IP-CIDR", "192.0.2.0/23"),
            Rule("SRC-IP-CIDR", "2001:db8::/48"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("SRC-IP-CIDR", "192.0.2.0/24")]
        ), source[1:])

    def test_source_address_is_covered_by_source_network_only(self):
        source = [Rule("SRC-IP", "192.0.2.15"), Rule("IP-CIDR", "192.0.2.0/32")]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("SRC-IP-CIDR", "192.0.2.0/24")]
        ), source[1:])

    def test_source_address_whitelist_covers_only_host_network(self):
        source = [Rule("SRC-IP-CIDR", "2001:db8::1/128"), Rule("SRC-IP-CIDR", "2001:db8::/64")]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("SRC-IP", "2001:db8::1")]
        ), source[1:])

    def test_asn_and_geoip_only_match_same_type_and_value(self):
        source = [
            Rule("IP-ASN", "64512"), Rule("IP-ASN", "64513"),
            Rule("GEOIP", "CN"), Rule("GEOIP", "US"),
            Rule("IP-CIDR", "192.0.2.0/24"),
        ]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("IP-ASN", "64512"), Rule("GEOIP", "cn")]
        ), [source[1], *source[3:]])

    def test_source_exception_is_kept_for_dns_output(self):
        source = [Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True)]
        self.assertEqual(rules.exclude_covered(
            source, [Rule("DOMAIN-SUFFIX", "example.com")]
        ), source)

    def test_unrelated_large_whitelist_does_not_scan_every_suffix(self):
        count = 6000
        source = [Rule("DOMAIN-SUFFIX", f"s{i}.example.com") for i in range(count)]
        whitelist = [Rule("DOMAIN-SUFFIX", f"x{i}.other.com") for i in range(count)]
        start = time.perf_counter()
        self.assertEqual(rules.exclude_covered(source, whitelist), source)
        self.assertLess(time.perf_counter() - start, 3.0)


class NormalizeTests(unittest.TestCase):
    def test_normalize_accepts_only_rules(self):
        with self.assertRaises(TypeError):
            normalize([], [])

    def test_suffix_covers_only_complete_domain_labels(self):
        original = [
            Rule("DOMAIN", "api.example.com"), Rule("DOMAIN", "notexample.com"),
            Rule("DOMAIN-SUFFIX", "api.example.com"), Rule("DOMAIN", "example.com"),
            Rule("DOMAIN-SUFFIX", "example.com"), Rule("DOMAIN", "notexample.com"),
        ]
        expected = [Rule("DOMAIN", "notexample.com"), Rule("DOMAIN-SUFFIX", "example.com")]
        self.assertEqual(normalize(original), expected)
        self.assertEqual(normalize(reversed(original)), expected)

    def test_narrow_allow_coexists_with_broad_block(self):
        original = [
            Rule("DOMAIN-SUFFIX", "example.com"),
            Rule("DOMAIN", "safe.example.com", allow=True),
        ]
        self.assertEqual(normalize(original), [
            Rule("DOMAIN", "safe.example.com", allow=True),
            Rule("DOMAIN-SUFFIX", "example.com"),
        ])

    def test_upstream_allow_keeps_wide_block_and_suffix_deduplication(self):
        parsed, parse_warnings = parse(
            "||example.com^\n@@||safe.example.com^\nDOMAIN,ads.example.com,REJECT",
            purpose="block",
        )
        self.assertEqual(parse_warnings, [])
        self.assertEqual(normalize(parsed), [
            Rule("DOMAIN-SUFFIX", "example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])

    def test_wildcards_are_only_dropped_when_suffix_proves_coverage(self):
        rules = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "*.example.com"),
            Rule("DOMAIN-WILDCARD", "*example.com"),
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-SUFFIX", "example.com"),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN-SUFFIX", "example.com"), Rule("DOMAIN-WILDCARD", "*example.com")
        ])
        self.assertEqual(normalize([Rule("DOMAIN-WILDCARD", "*.example.com")]), [
            Rule("DOMAIN-WILDCARD", "*.example.com")
        ])

    def test_exact_allow_does_not_delete_wider_wildcard(self):
        rules = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN", "api-safe.example.com", allow=True),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN", "api-safe.example.com", allow=True),
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
        ])

    def test_large_suffix_list_normalizes_without_quadratic_scan(self):
        count = 8000
        rules = [Rule("DOMAIN-SUFFIX", f"s{i}.example.com") for i in range(count)]
        rules += [Rule("DOMAIN", f"sub.s{i}.example.com") for i in range(count)]
        start = time.perf_counter()
        output = normalize(rules)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(output), count)
        self.assertLess(elapsed, 3.0)

    def test_keywords_do_not_compare_against_every_domain(self):
        count = 8000
        rules = [Rule("DOMAIN-KEYWORD", f"k{i:05d}") for i in range(count)]
        rules += [Rule("DOMAIN", f"d{i}.example.com") for i in range(count)]
        start = time.perf_counter()
        output = normalize(rules)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(output), 2 * count)
        self.assertLess(elapsed, 3.0)

    def test_allow_suffix_does_not_remove_blocking_exact_domains(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN", "safe.example.com"),
            Rule("DOMAIN", "child.safe.example.com"),
            Rule("DOMAIN", "ads.example.com"),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN", "ads.example.com"),
            Rule("DOMAIN", "child.safe.example.com"),
            Rule("DOMAIN", "safe.example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])

    def test_allow_suffix_does_not_remove_blocking_suffixes(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN-SUFFIX", "ads.safe.example.com"),
            Rule("DOMAIN-SUFFIX", "other.example.com"),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN-SUFFIX", "ads.safe.example.com"),
            Rule("DOMAIN-SUFFIX", "other.example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])

    def test_keyword_containment_requires_same_options_and_allow(self):
        rules = [
            Rule("DOMAIN-KEYWORD", "ads"), Rule("DOMAIN-KEYWORD", "ad"),
            Rule("DOMAIN-KEYWORD", "track"), Rule("DOMAIN-KEYWORD", "adserver"),
            Rule("DOMAIN-KEYWORD", "ads", ("special",)),
            Rule("DOMAIN-KEYWORD", "ads", allow=True),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN-KEYWORD", "ad"), Rule("DOMAIN-KEYWORD", "ads", allow=True),
            Rule("DOMAIN-KEYWORD", "ads", ("special",)), Rule("DOMAIN-KEYWORD", "track"),
        ])

    def test_cidr_collapse_keeps_family_direction_options_and_allow_separate(self):
        rules = [
            Rule("IP-CIDR", "192.0.2.0/25"), Rule("IP-CIDR", "192.0.2.128/25"),
            Rule("IP-CIDR", "192.0.2.0/25", ("no-resolve",)),
            Rule("SRC-IP-CIDR", "192.0.2.0/25"),
            Rule("SRC-IP-CIDR", "192.0.2.128/25"),
            Rule("SRC-IP-CIDR", "2001:db8::/33"),
            Rule("SRC-IP-CIDR", "2001:db8:8000::/33"),
            Rule("IP-CIDR6", "2001:db8::/32"),
            Rule("IP-CIDR", "192.0.2.0/25", allow=True),
        ]
        self.assertEqual(normalize(reversed(rules)), [
            Rule("IP-CIDR", "192.0.2.0/24"),
            Rule("IP-CIDR", "192.0.2.0/25", allow=True),
            Rule("IP-CIDR", "192.0.2.0/25", ("no-resolve",)),
            Rule("IP-CIDR6", "2001:db8::/32"),
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
            Rule("SRC-IP-CIDR", "2001:db8::/32"),
        ])

    def test_unrelated_allow_does_not_remove_domain_regex(self):
        rule = Rule("DOMAIN-REGEX", r"^tracker\.example\.com$")
        self.assertEqual(normalize([rule, Rule("DOMAIN", "safe.example.org", allow=True)]), [
            Rule("DOMAIN", "safe.example.org", allow=True), rule,
        ])

    def test_keyword_overlapping_exact_allow_is_preserved(self):
        rules = [
            Rule("DOMAIN-KEYWORD", "example"), Rule("DOMAIN-KEYWORD", "unrelated"),
            Rule("DOMAIN", "safe.example.com", allow=True),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN", "safe.example.com", allow=True),
            Rule("DOMAIN-KEYWORD", "example"), Rule("DOMAIN-KEYWORD", "unrelated"),
        ])

    def test_wildcard_overlapping_allow_suffix_is_preserved(self):
        rules = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "api-*.other.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "api-*.other.com"),
        ])
