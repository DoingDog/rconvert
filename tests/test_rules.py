import time
import unittest
import warnings

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


class NormalizeTests(unittest.TestCase):
    def test_suffix_covers_only_complete_domain_labels(self):
        original = [
            Rule("DOMAIN", "api.example.com"), Rule("DOMAIN", "notexample.com"),
            Rule("DOMAIN-SUFFIX", "api.example.com"), Rule("DOMAIN", "example.com"),
            Rule("DOMAIN-SUFFIX", "example.com"), Rule("DOMAIN", "notexample.com"),
        ]
        expected = [Rule("DOMAIN", "notexample.com"), Rule("DOMAIN-SUFFIX", "example.com")]
        self.assertEqual(normalize(original), expected)
        self.assertEqual(normalize(reversed(original)), expected)

    def test_explicit_domain_exclusion_is_exact(self):
        rules = [Rule("DOMAIN", "safe.example.com"), Rule("DOMAIN", "sub.safe.example.com")]
        self.assertEqual(normalize(rules, ["DOMAIN,safe.example.com"]), [
            Rule("DOMAIN", "sub.safe.example.com")
        ])

    def test_bare_and_comma_prefixed_exclusions_remove_domain_trees(self):
        rules = [
            Rule("DOMAIN", "example.com"), Rule("DOMAIN", "cdn.foo.example.com"),
            Rule("DOMAIN-SUFFIX", "foo.example.com"), Rule("DOMAIN", "notexample.com"),
        ]
        for exclusion in ("EXAMPLE.COM", ",example.com", ",EXAMPLE.COM."):
            with self.subTest(exclusion=exclusion):
                self.assertEqual(normalize(rules, [exclusion]), [Rule("DOMAIN", "notexample.com")])

    def test_exact_exclusion_drops_conflicting_suffix_but_keeps_unrelated_narrow_rules(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "example.com"), Rule("DOMAIN", "safe.example.com"),
            Rule("DOMAIN", "ads.example.com"), Rule("DOMAIN-SUFFIX", "another.com"),
        ]
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            result = normalize(rules, ["DOMAIN,safe.example.com"])
        self.assertEqual(result, [
            Rule("DOMAIN", "ads.example.com"), Rule("DOMAIN-SUFFIX", "another.com")
        ])
        self.assertTrue(any("DOMAIN-SUFFIX,example.com" in str(warning.message) for warning in reported))

    def test_upstream_allow_removes_wide_block_without_losing_unrelated_narrow_rule(self):
        parsed, parse_warnings = parse(
            "||example.com^\n@@||safe.example.com^\nDOMAIN,ads.example.com,REJECT",
            purpose="block",
        )
        self.assertEqual(parse_warnings, [])
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            output = normalize(parsed)
        self.assertEqual(output, [
            Rule("DOMAIN", "ads.example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])
        self.assertTrue(any("DOMAIN-SUFFIX,example.com" in str(warning.message) for warning in reported))

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

    def test_wildcard_conflicting_with_exact_allow_is_discarded(self):
        rules = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "other-*.example.com"),
            Rule("DOMAIN", "api-other.example.com"),
        ]
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            output = normalize(rules, ["DOMAIN,api-safe.example.com"])
        self.assertEqual(output, [
            Rule("DOMAIN", "api-other.example.com"),
            Rule("DOMAIN-WILDCARD", "other-*.example.com"),
        ])
        self.assertTrue(any("DOMAIN-WILDCARD,api-*.example.com" in str(item.message) for item in reported))

    def test_surge_bracket_wildcard_is_not_treated_as_glob_on_exclusions(self):
        rules = [
            Rule("DOMAIN-WILDCARD", "cdn[0-9].example.com"),
            Rule("DOMAIN-WILDCARD", "api-*.other.com"),
        ]
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            output = normalize(rules, ["DOMAIN,cdnB.example.com"])
        self.assertEqual(output, [Rule("DOMAIN-WILDCARD", "api-*.other.com")])
        self.assertTrue(any("cdn[0-9].example.com" in str(item.message) for item in reported))

    def test_large_suffix_list_normalizes_without_quadratic_scan(self):
        count = 8000
        rules = [Rule("DOMAIN-SUFFIX", f"s{i}.example.com") for i in range(count)]
        rules += [Rule("DOMAIN", f"sub.s{i}.example.com") for i in range(count)]
        start = time.perf_counter()
        output = normalize(rules)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(output), count)
        self.assertLess(elapsed, 3.0)

    def test_unrelated_whitelist_does_not_make_suffix_scan_quadratic(self):
        count = 8000
        rules = [Rule("DOMAIN-SUFFIX", f"s{i}.example.com") for i in range(count)]
        exclusions = [f"DOMAIN,unrelated{i}.other.com" for i in range(count)]
        start = time.perf_counter()
        output = normalize(rules, exclusions)
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

    def test_unrelated_tree_exclusions_do_not_scan_every_domain(self):
        count = 8000
        rules = [Rule("DOMAIN", f"sub.s{i}.example.com") for i in range(count)]
        exclusions = [f"unused{i}.other.com" for i in range(count)]
        start = time.perf_counter()
        output = normalize(rules, exclusions)
        elapsed = time.perf_counter() - start
        self.assertEqual(len(output), count)
        self.assertLess(elapsed, 3.0)

    def test_allow_suffix_suppresses_blocking_exact_domains_within_it(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN", "safe.example.com"),
            Rule("DOMAIN", "child.safe.example.com"),
            Rule("DOMAIN", "ads.example.com"),
        ]
        self.assertEqual(normalize(rules), [
            Rule("DOMAIN", "ads.example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])

    def test_allow_suffix_also_removes_narrower_blocking_suffix(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN-SUFFIX", "ads.safe.example.com"),
            Rule("DOMAIN-SUFFIX", "other.example.com"),
        ]
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            output = normalize(rules)
        self.assertEqual(output, [
            Rule("DOMAIN-SUFFIX", "other.example.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ])
        self.assertTrue(any("ads.safe.example.com" in str(item.message) for item in reported))

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

    def test_nondomain_exclusion_precedes_keyword_dedup(self):
        rules = [
            Rule("DOMAIN-KEYWORD", "ads"), Rule("DOMAIN-KEYWORD", "ads2"),
            Rule("PROCESS-NAME", "AdsApp"), Rule("DOMAIN", "ads.example.com"),
        ]
        self.assertEqual(normalize(rules, ["ads", "PROCESS-NAME,AdsApp"]), [
            Rule("DOMAIN", "ads.example.com"), Rule("DOMAIN-KEYWORD", "ads2"),
        ])

    def test_keyword_overlapping_exact_exception_is_reported_and_removed(self):
        rules = [Rule("DOMAIN-KEYWORD", "example"), Rule("DOMAIN-KEYWORD", "unrelated")]
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            output = normalize(rules, ["DOMAIN,safe.example.com"])
        self.assertEqual(output, [Rule("DOMAIN-KEYWORD", "unrelated")])
        self.assertTrue(any("DOMAIN-KEYWORD,example" in str(item.message) for item in reported))

    def test_wildcard_overlap_with_excluded_subtree_is_conservatively_removed(self):
        rules = [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"),
            Rule("DOMAIN-WILDCARD", "api-*.other.com"),
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
        ]
        with warnings.catch_warnings(record=True) as reported:
            warnings.simplefilter("always")
            output = normalize(rules)
        self.assertEqual(output, [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN-WILDCARD", "api-*.other.com"),
        ])
        self.assertTrue(any("DOMAIN-WILDCARD,api-*.example.com" in str(item.message) for item in reported))
