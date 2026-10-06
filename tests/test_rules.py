import subprocess
import sys
import time
import unittest
import warnings
from pathlib import Path

import rules
from rules import Rule, normalize, parse


def _quote_matcher(value):
    quote = next(mark for mark in ('"', "'") if mark not in value)
    return f"{quote}{value}{quote}"


class ConstructorValidationTests(unittest.TestCase):
    def check_matcher(self, kind, value, *, valid=True, native=True, expected_kind=None,
                      expected_value=None):
        import json

        expected_kind = expected_kind or kind
        expected_value = value if expected_value is None else expected_value
        for purpose in ("block", "direct", "proxy"):
            for operator in (None, "AND", "OR", "NOT"):
                expression = (f"(({kind},{value}))" if operator == "NOT" else
                              f"(({kind},{value}),(NETWORK,tcp))")
                expected_expression = (f"(({expected_kind},{expected_value}))" if operator == "NOT" else
                                       f"(({expected_kind},{expected_value}),(NETWORK,tcp))")
                matcher = f"{operator},{expression}" if operator else f"{kind},{value}"
                expected = Rule(operator, expected_expression, literal_process=kind == "PROCESS-NAME" and native,
                                native_fields=native) if operator else Rule(
                                    expected_kind, expected_value, literal_process=kind == "PROCESS-NAME" and native)
                sources = [matcher]
                if native:
                    sources = [f"{header}:\n  - {scalar}" for header in ("payload", "rules")
                               for scalar in (matcher, "'" + matcher + "'", json.dumps(matcher, ensure_ascii=False))]
                for source in sources:
                    line = 2 if native else 1
                    with self.subTest(source=source, purpose=purpose):
                        neighbor = "\nDOMAIN,neighbor.example.com"
                        parsed, messages = parse(source + neighbor, purpose=purpose)
                        self.assertEqual(parsed, ([expected] if valid else []) + [Rule("DOMAIN", "neighbor.example.com")])
                        reason = (f"invalid logical expression {expression}" if operator else
                                  f"invalid value {value}" if kind in {"IN-NAME", "REMATCH-NAME"} else
                                  f"invalid port {value}" if kind in {"DST-PORT", "SRC-PORT", "IN-PORT"} else
                                  f"invalid CIDR {value}" if kind == "IP-CIDR6" else f"invalid {kind} {value}")
                        self.assertEqual(messages, [] if valid else [f"line {line}: {reason}"])

    def test_r06_in_user_segment_whitespace_and_literal_values(self):
        for value in ("alice / bob", "alice bob/Alice Smith", "A\tB", "<Alice>"):
            self.check_matcher("IN-USER", value)
        for value in ("alice//bob", "alice/ /bob", "/alice", "alice/"):
            self.check_matcher("IN-USER", value, valid=False)
        import json

        for value, valid in (("\t", False), ("\u0085", False), (" ", False), ("\x1c", True), ("​", True)):
            source = "payload:\n  - " + json.dumps("IN-USER," + value)
            self.assertEqual(parse(source, purpose="proxy"),
                             ([Rule("IN-USER", value)], []) if valid else ([], [f"line 2: invalid IN-USER {value}"]))

    def test_r07_surge_asn_prefix_and_unknown_keep_source_context(self):
        for value, expected in (("AS13335", "13335"), ("AS4294967295", "4294967295"),
                                ("UNKNOWN", "UNKNOWN"), ("unknown", "unknown")):
            self.check_matcher("IP-ASN", value, native=False, expected_value=expected)
        for value in ("ASabc", "NaN", "-1", "AS4294967296", "4294967296"):
            self.check_matcher("IP-ASN", value, native=False, valid=False)
        for value in ("AS13335", "UNKNOWN"):
            self.check_matcher("IP-ASN", value, valid=False)

    def test_r08_geoip_lan_and_surge_unknown_keep_direction(self):
        for kind in ("GEOIP", "SRC-GEOIP"):
            for value in ("LAN", "lan", "LaN", "CN", "cn"):
                self.check_matcher(kind, value)
        self.check_matcher("GEOIP", "UNKNOWN", native=False)
        self.check_matcher("SRC-GEOIP", "UNKNOWN", native=False, valid=False)
        self.check_matcher("GEOIP", "UNKNOWN", valid=False)
        self.assertEqual(parse("GEOIP,LAN,src", purpose="proxy"),
                         ([], ["line 1: ambiguous src policy or option"]))
        self.assertEqual(parse("payload:\n  - GEOIP,LAN,src,no-resolve", purpose="proxy"),
                         ([Rule("SRC-GEOIP", "LAN")], ["line 2: unsupported no-resolve for SRC-GEOIP"]))
        self.assertEqual(parse("payload:\n  - SRC-GEOIP,LAN,no-resolve", purpose="proxy"),
                         ([Rule("SRC-GEOIP", "LAN")], []))

    def test_r14_zero_lower_bound_ports_cover_all_callers(self):
        for kind in ("DST-PORT", "SRC-PORT", "IN-PORT"):
            for value in ("0-65535", "0-80", "0000-80"):
                self.check_matcher(kind, value)
            for value in ("65536", "0-65536", "80-0"):
                self.check_matcher(kind, value, valid=False)
            for source in (f"{kind},0-80/443,PROXY", f"{kind},0-80,443,PROXY"):
                self.assertEqual(parse(source, purpose="proxy"),
                                 ([Rule("OR", f"(({kind},0-80),({kind},443))")], []))
            self.assertEqual(parse(f"payload:\n  - {kind},0-80/443", purpose="proxy"),
                             ([Rule("OR", f"(({kind},0-80),({kind},443))", native_fields=True)], []))

    def test_r15_uid_dscp_ranges_and_real_unsigned_conversion(self):
        for kind in ("UID", "DSCP"):
            for value in ("0-63", "0/1/2", "1-4/8", "8-1", "0//1", "/0/"):
                self.check_matcher(kind, value)
            self.check_matcher(kind, "/".join(["0"] * 28))
            for value in ("-1", "bad", "1-2-3", "18446744073709551616", "/".join(["0"] * 29)):
                self.check_matcher(kind, value, valid=False)
        for value in ("256", "256-319", "18446744073709551360"):
            self.check_matcher("DSCP", value)
        for value in ("64", "1-64/8", "18446744073709551615"):
            self.check_matcher("DSCP", value, valid=False)
        self.check_matcher("UID", "4294967296-4294967298")
        self.check_matcher("UID", "18446744073709551615")

    def test_r15_empty_uid_and_comma_range_constructor_boundaries(self):
        for value in ("", "*", "/", "//"):
            self.check_matcher("UID", value, valid=False)
            self.check_matcher("DSCP", value, valid=bool(value))
        for value in ("", " ", "  "):
            with self.subTest(value=value):
                self.assertFalse(rules._valid_simple("DSCP", value))
        for value in ("\t", "\u0085", " "):
            self.assertTrue(rules._valid_simple("DSCP", value))
        for kind in ("UID", "DSCP"):
            self.check_matcher(kind, "/ /", native=False)
            with self.subTest(kind=kind):
                self.assertTrue(rules._valid_simple(kind, "0,1,8-1"))
                self.assertTrue(rules._valid_simple(kind, ",".join(["0"] * 28)))
                self.assertFalse(rules._valid_simple(kind, ",".join(["0"] * 29)))
                self.assertEqual(parse(f"{kind},'0,1',PROXY", purpose="proxy"),
                                 ([Rule(kind, "0,1")], []))
                self.assertEqual(parse(f"payload:\n  - {kind},0,1", purpose="proxy"),
                                 ([Rule(kind, "0")], []))
        for value in ("+1", "[ ]", "1-", "1\t-2", "18446744073709551616"):
            self.check_matcher("DSCP", value, valid=False)

    def test_r16_in_type_full_enum_alias_whitespace_and_invalid_values(self):
        names = ("HTTP", "HTTPS", "SOCKS4", "SOCKS5", "SHADOWSOCKS", "SNELL", "VMESS", "VLESS",
                 "REDIR", "TPROXY", "TROJAN", "TUNNEL", "TUN", "TUIC", "HYSTERIA2", "ANYTLS",
                 "MIERU", "SUDOKU", "TRUSTTUNNEL", "SHADOWQUIC", "INNER", "SOCKS")
        for name in names:
            self.check_matcher("IN-TYPE", name)
        self.check_matcher("IN-TYPE", "HTTP / SOCKS")
        self.check_matcher("IN-TYPE", "http/ socks")
        for value in ("BOGUS", "HTTP-TEST", "MIXED", "HTTP_TEST", "HTTP/MIXED", "HTTP//SOCKS", "HTTP/ /SOCKS"):
            self.check_matcher("IN-TYPE", value, valid=False)

    def test_r17_name_lists_reject_empty_segments_and_keep_literal_tail(self):
        for kind in ("IN-NAME", "REMATCH-NAME"):
            for value in ("A/B", "A/ B"):
                self.check_matcher(kind, value)
            for value in ("/", "A/", "/A", "A//B", "A/ /B", "Foo(/"):
                self.check_matcher(kind, value, valid=False)
            self.assertEqual(parse(f"payload:\n  - {kind},Foo(", purpose="proxy"),
                             ([Rule(kind, "Foo(")], []))
            expression = f"(({kind},Foo(,ignored)))"
            self.assertEqual(parse(f"payload:\n  - NOT,{expression}", purpose="proxy"),
                             ([Rule("NOT", expression, native_fields=True)], []))

    def test_r18_ip_suffix_rejects_dotted_masks_and_preserves_host_bits(self):
        for kind in ("IP-SUFFIX", "SRC-IP-SUFFIX"):
            for value in ("192.0.2.7/24", "192.0.2.7/0", "192.0.2.7/32", "2001:db8::7/64"):
                self.check_matcher(kind, value)
            for value in ("192.0.2.7/255.255.255.0", "192.0.2.7/0.0.0.255", "192.0.2.7/33",
                          "192.0.2.7", "bad/24", "fe80::1%eth0/64"):
                self.check_matcher(kind, value, valid=False)

    def test_r19_native_literal_html_fields_and_document_guards(self):
        for kind in ("IN-USER", "IN-NAME", "REMATCH-NAME", "PROCESS-NAME", "PROCESS-PATH",
                     "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"):
            value = "/tmp/<Foo>" if "PATH" in kind else "<Foo>"
            self.check_matcher(kind, value)
        for text in ("<!doctype html>\nDOMAIN,hidden.example", "﻿<!doctype html>\nDOMAIN,hidden.example",
                     "<html>\nDOMAIN,hidden.example\n</html>", "<main>\nDOMAIN,hidden.example\n</main>"):
            self.assertEqual(parse(text, purpose="proxy"), ([], ["line 1: HTML document"]))
        self.assertEqual(parse("DOMAIN,a.example\n<div>\nDOMAIN,hidden.example\n</div>\nDOMAIN,b.example", purpose="proxy"),
                         ([Rule("DOMAIN", "a.example"), Rule("DOMAIN", "b.example")],
                          ["line 2: HTML markup", "line 4: HTML markup"]))

    def test_r20_native_ipv4_cidr6_alias_and_ordinary_family_boundary(self):
        self.check_matcher("IP-CIDR6", "127.0.0.1/8", expected_kind="IP-CIDR", expected_value="127.0.0.0/8")
        self.check_matcher("IP-CIDR6", "127.0.0.1/8", native=False, valid=False)
        self.check_matcher("IP-CIDR6", "127.0.0.1/33", valid=False)
        self.assertEqual(parse("payload:\n  - IP-CIDR6,127.0.0.1/8,src", purpose="proxy"),
                         ([Rule("SRC-IP-CIDR", "127.0.0.0/8")], []))
        self.assertEqual(parse("IP-CIDR6,127.0.0.1/8,PROXY,src", purpose="proxy"),
                         ([], ["line 1: invalid CIDR 127.0.0.1/8"]))

    def test_r21_geosite_confirmed_database_name(self):
        self.check_matcher("GEOSITE", "geolocation-!cn")
        self.check_matcher("GEOSITE", "geolocation-!cn", native=False)
        self.check_matcher("GEOSITE", "bad name", valid=False)

    def test_r23_native_asn_zero_keeps_literal_identity(self):
        for kind in ("IP-ASN", "SRC-IP-ASN"):
            for value in ("0", "00", "1", "4294967295"):
                self.check_matcher(kind, value)
            for value in ("-1", "NaN", "4294967296"):
                self.check_matcher(kind, value, valid=False)
        self.assertEqual(parse("payload:\n  - IP-ASN,0,src", purpose="proxy"),
                         ([Rule("SRC-IP-ASN", "0")], []))
        self.assertEqual(normalize([Rule("IP-ASN", "0"), Rule("IP-ASN", "00")]),
                         [Rule("IP-ASN", "0"), Rule("IP-ASN", "00")])

    def test_constructor_600_and_1000_layers_keep_values_options_and_public_fields(self):
        code = '''
import json
import sys
from dataclasses import fields
from formats import render
from rules import Rule, parse, normalize, parse_whitelist
limit = sys.getrecursionlimit()
assert [field.name for field in fields(Rule)] == ['kind', 'value', 'options', 'allow', 'literal_process', 'native_fields', 'domain_source']
def nest(value):
    for _ in range(DEPTH):
        value = '(NOT,(' + value + '))'
    return value
for leaf, canonical, literal in (
    ('(IN-USER,alice bob / <Alice>)', '(IN-USER,alice bob / <Alice>)', False),
    ('(IN-NAME,Foo(,ignored))', '(IN-NAME,Foo(,ignored))', False),
    ('(REMATCH-NAME,Foo(,ignored))', '(REMATCH-NAME,Foo(,ignored))', False),
    ('(PROCESS-NAME,<Foo>)', '(PROCESS-NAME,<Foo>)', True),
    ('(IN-TYPE,HTTP / SOCKS)', '(IN-TYPE,HTTP / SOCKS)', False),
    ('(DSCP,256-319/0//1)', '(DSCP,256-319/0//1)', False),
    ('(UID,4294967296-4294967298)', '(UID,4294967296-4294967298)', False),
    ('(DST-PORT,0-65535)', '(DST-PORT,0-65535)', False),
    ('(GEOSITE,geolocation-!cn)', '(GEOSITE,geolocation-!cn)', False),
    ('(GEOIP,LAN,no-resolve)', '(GEOIP,LAN,no-resolve)', False),
    ('(IP-ASN,00,no-resolve)', '(IP-ASN,00,no-resolve)', False),
    ('(IP-SUFFIX,192.0.2.7/24,no-resolve)', '(IP-SUFFIX,192.0.2.7/24,no-resolve)', False),
    ('(IP-CIDR6,127.0.0.1/8,no-resolve)', '(IP-CIDR,127.0.0.0/8,no-resolve)', False),
    ('(IP-CIDR6,127.0.0.1/8,src,no-resolve)', '(SRC-IP-CIDR,127.0.0.0/8)', False),
):
    matcher, expected = nest(leaf)[1:-1], nest(canonical)[1:-1]
    kind, value = expected.split(',', 1)
    for purpose in ('block', 'direct', 'proxy'):
        source = 'payload:\\n  - ' + json.dumps(matcher) + '\\n  - DOMAIN,keep.example.com'
        parsed, warnings = parse(source, purpose=purpose)
        assert parsed == [Rule(kind, value, literal_process=literal, native_fields=True), Rule('DOMAIN', 'keep.example.com')], leaf
        assert warnings == (['line 2: unsupported no-resolve for SRC-IP-CIDR'] if ',src,' in leaf else []), warnings
        assert normalize(parsed * 2) == normalize(parsed), leaf
        assert parse_whitelist(source) == [Rule('DOMAIN', 'keep.example.com')], leaf
        for mode in ('keep', 'add', 'strip'):
            emitted = canonical
            if mode == 'add' and emitted.startswith(('(GEOIP,', '(IP-ASN,', '(IP-CIDR,', '(IP-SUFFIX,')):
                emitted = emitted.replace(',no-resolve', '')[:-1] + ',no-resolve)'
            if mode == 'strip':
                emitted = emitted.replace(',no-resolve', '')
            expected_mihomo = '# deep rules: 2\\npayload:\\n  - "DOMAIN,keep.example.com"\\n  - ' + json.dumps(nest(emitted)[1:-1]) + '\\n'
            rendered, skips = render('deep', parsed, purpose=purpose, no_resolve=mode)
            assert rendered['fin.yaml'] == expected_mihomo, (leaf, mode)
            assert parse(rendered['fin.yaml'], purpose=purpose)[0] == [Rule('DOMAIN', 'keep.example.com'), Rule(kind, nest(emitted)[5:-1], literal_process=literal, native_fields=True)], (leaf, mode)
for leaf in ('(IN-NAME,A//B)', '(REMATCH-NAME,/A)', '(IP-SUFFIX,192.0.2.7/255.255.255.0)', '(IN-TYPE,MIXED)'):
    matcher = nest(leaf)[1:-1]
    parsed, warnings = parse('payload:\\n  - ' + json.dumps(matcher) + '\\n  - DOMAIN,keep.example.com', purpose='proxy')
    assert parsed == [Rule('DOMAIN', 'keep.example.com')], leaf
    assert warnings == ['line 2: invalid logical expression ' + matcher.split(',', 1)[1]], warnings
assert sys.getrecursionlimit() == limit
'''
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                result = subprocess.run([sys.executable, "-B", "-c", f"DEPTH = {depth}\n" + code],
                                        cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                        text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr[-3000:])


class DomainProvenanceRuleTests(unittest.TestCase):
    def test_regex_whitelist_keeps_valid_matchers_without_guessing_coverage(self):
        regexes = ("ad", r"^api\-.*\.example\.com\.?$", r"^api\-[0-9]\.example\.com\.?$",
                   r"^(?=ads)ads\.example\.com$")
        expected = [Rule("DOMAIN-REGEX", value) for value in regexes]
        for source in ("\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in regexes),
                       "payload:\n" + "\n".join("  - DOMAIN-REGEX," + value for value in regexes)):
            with self.subTest(source=source):
                self.assertEqual(rules.parse_whitelist(source), expected)
                blocked = [Rule("DOMAIN", "ads.example.com"), Rule("DOMAIN", "api-7.example.com")]
                self.assertEqual(rules.exclude_covered(blocked, expected), blocked)
        with self.assertRaisesRegex(ValueError, "invalid DOMAIN-REGEX"):
            rules.parse_whitelist("payload:\n  - DOMAIN-REGEX,*ads")

    def test_surge_native_and_unknown_qx_matchers_remain_distinct(self):
        for kind, value, qx in (("DOMAIN-KEYWORD", "ads", "HOST-KEYWORD"),
                                ("DOMAIN-WILDCARD", "api-*.example.com", "HOST-WILDCARD"),
                                ("DOMAIN-WILDCARD", "api-[0-9].example.com", "HOST-WILDCARD")):
            with self.subTest(kind=kind, value=value):
                surge, messages = parse(f"{kind},{value},REJECT", purpose="block")
                native, native_messages = parse(f"payload:\n  - {kind},{value}", purpose="block")
                unknown, qx_messages = parse(f"{qx},{value},REJECT", purpose="block")
                self.assertEqual(messages + native_messages + qx_messages, [])
                self.assertNotEqual(surge, native)
                self.assertNotEqual(unknown, surge)
                self.assertNotEqual(unknown, native)
                self.assertEqual(len(normalize(surge + native + unknown + surge)), 3)
                self.assertFalse(any(rule.native_fields or rule.literal_process
                                     for rule in surge + native + unknown))

    def test_whitelist_coverage_keeps_case_direction_and_unknown_qx(self):
        surge, _ = parse("DOMAIN-KEYWORD,ads,REJECT", purpose="block")
        native, _ = parse("payload:\n  - DOMAIN-KEYWORD,ads", purpose="block")
        qx, _ = parse("HOST-KEYWORD,ads,REJECT", purpose="block")
        native_allow = rules.parse_whitelist("payload:\n  - DOMAIN-KEYWORD,ad")
        surge_allow = rules.parse_whitelist("DOMAIN-KEYWORD,ad,DIRECT")
        qx_allow = rules.parse_whitelist("HOST-KEYWORD,ad,DIRECT")
        self.assertEqual(rules.exclude_covered(surge, native_allow), surge)
        self.assertEqual(rules.exclude_covered(native, native_allow), [])
        self.assertEqual(rules.exclude_covered(surge, surge_allow), [])
        self.assertEqual(rules.exclude_covered(qx, surge_allow + native_allow), qx)
        self.assertEqual(rules.exclude_covered(surge + native, qx_allow), surge + native)
        self.assertEqual(rules.exclude_covered(qx, qx_allow), [])
        self.assertEqual(len(normalize(surge + native_allow)), 2)
        for source in ("payload:\n  - DOMAIN-WILDCARD,api-[0-9].example.com",
                       "HOST-WILDCARD,api-[0-9].example.com,REJECT"):
            matcher, _ = parse(source, purpose="block")
            self.assertEqual(rules.exclude_covered(surge + matcher,
                             rules.parse_whitelist("DOMAIN-WILDCARD,api-[0-9].example.com")),
                             surge + matcher)

    def test_unknown_qx_exact_and_suffix_do_not_prove_cross_source_coverage(self):
        for kind, qx in (("DOMAIN", "HOST"), ("DOMAIN-SUFFIX", "HOST-SUFFIX")):
            with self.subTest(kind=kind):
                known, _ = parse(f"{kind},example.com,REJECT", purpose="block")
                unknown, _ = parse(f"{qx},example.com,REJECT", purpose="block")
                self.assertNotEqual(known, unknown)
                self.assertEqual(len(normalize(known + unknown)), 2)
                self.assertEqual(rules.exclude_covered(known, rules.parse_whitelist(
                    f"{qx},example.com,DIRECT")), known)

    def test_en1_is_known_without_accepting_unknown_interfaces(self):
        self.assertEqual(parse("HOST-SUFFIX,example.com,PROXY,via-interface=en1", purpose="proxy")[1], [])
        parsed, _ = parse("HOST-SUFFIX,example.com,PROXY,via-interface=en1", purpose="proxy")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].options, ("via-interface=en1",))
        for option in ("via-interface=en0", "via-interface=unknown", "unknown-option"):
            with self.subTest(option=option):
                self.assertEqual(parse(f"HOST-SUFFIX,example.com,PROXY,{option}", purpose="proxy"),
                                 ([], ["line 1: unexpected fields"]))


class DomainSetSuffixParserTests(unittest.TestCase):
    def test_single_label_domain_set_suffix_uses_suffix_validation(self):
        for purpose in ("direct", "block", "proxy"):
            with self.subTest(purpose=purpose):
                self.assertEqual(parse(".com", purpose=purpose),
                                 ([Rule("DOMAIN-SUFFIX", "com")], []))

    def test_other_legal_suffix_labels_reuse_existing_domain_boundaries(self):
        for purpose in ("direct", "block", "proxy"):
            for label in ("net", "local", "x", "1", "A-B", "XN--P1AI", "a" * 63, "COM."):
                with self.subTest(purpose=purpose, label=label):
                    self.assertEqual(parse("." + label, purpose=purpose),
                                     ([Rule("DOMAIN-SUFFIX", label.removesuffix(".").lower())], []))

    def test_exact_and_multilabel_domain_set_entries_keep_their_types(self):
        for purpose in ("direct", "block", "proxy"):
            with self.subTest(purpose=purpose):
                self.assertEqual(parse("example.com\n.example.com\nExample.ORG.", purpose=purpose),
                                 ([Rule("DOMAIN", "example.com"), Rule("DOMAIN-SUFFIX", "example.com"),
                                   Rule("DOMAIN", "example.org")], []))
                self.assertEqual(parse("DOMAIN,com\nDOMAIN-SUFFIX,com", purpose=purpose),
                                 ([Rule("DOMAIN", "com"), Rule("DOMAIN-SUFFIX", "com")], []))

    def test_invalid_bare_entries_warn_at_their_line_and_keep_legal_neighbors(self):
        entries = ("com", "local", "x", "-com", "com-", "a_b", ".", "..com", ".a..com",
                   ".-com", ".com-", ".a_b", ".*", ".a/b", ".192.0.2.1", ".2001:db8::1",
                   "." + "a" * 64, "." + ".".join(["a" * 63] * 4), "garbage{")
        for purpose in ("direct", "block", "proxy"):
            for entry in entries + (".com,REJECT",):
                with self.subTest(purpose=purpose, entry=entry):
                    message = {".com,REJECT": "unknown type .COM", "-com": "invalid YAML payload"}.get(
                        entry, "invalid rule")
                    self.assertEqual(parse(f"# domains\nexample.com\n{entry}\n.example.org", purpose=purpose),
                                     ([Rule("DOMAIN", "example.com"), Rule("DOMAIN-SUFFIX", "example.org")],
                                      ["line 3: " + message]))

    def test_suffix_whitelist_covers_only_its_domain_direction(self):
        allowed = rules.parse_whitelist(".com")
        self.assertEqual(allowed, [Rule("DOMAIN-SUFFIX", "com")])
        broad = Rule("DOMAIN-SUFFIX", "com")
        keep = [Rule("DOMAIN", "notcom"), Rule("DOMAIN", "example.org"),
                Rule("DOMAIN-SUFFIX", "company"), Rule("DOMAIN-KEYWORD", "com")]
        covered = [broad, Rule("DOMAIN", "ads.example.com"), Rule("DOMAIN-SUFFIX", "child.com"),
                   Rule("DOMAIN-WILDCARD", "*.child.com")]
        self.assertEqual(rules.exclude_covered(covered + keep, allowed), keep)
        self.assertEqual(rules.exclude_covered([broad], [Rule("DOMAIN", "ads.example.com")]), [broad])


class SurgeEscapedFieldParserTests(unittest.TestCase):
    def test_double_quote_escapes_decode_only_at_mixed_field_boundaries(self):
        import json
        from formats import render
        from tests.test_formats import expected_process

        cases = ((r'"Game\\"', "Game\\"),
                 (r'''"\"Game'Inc\""''', '"Game\'Inc"'),
                 (r'''"'Game\\\\"''', "'Game\\\\"),
                 (r'"^Game\\\\,Inc$"', r'^Game\\,Inc$'),
                 (r'"^Game\w,Inc$"', r'^Game\w,Inc$'))
        for field, matcher in cases:
            kind = "PROCESS-NAME-REGEX" if matcher.startswith("^") else "PROCESS-NAME"
            for marker in ("#", ";", "//"):
                with self.subTest(field=field, marker=marker):
                    self.assertEqual(parse(f"{kind},{field},PROXY {marker} comment,'unclosed", purpose="proxy"),
                                     ([Rule(kind, matcher)], []))
                    for operator in ("AND", "OR", "NOT"):
                        expression = (f"(({kind},{field}))" if operator == "NOT" else
                                      f"(({kind},{field}),(DOMAIN,x.example.com))")
                        parsed, messages = parse(f"{operator},{expression},PROXY", purpose="proxy")
                        self.assertEqual(messages, [])
                        out, _ = render("group", parsed, purpose="proxy", no_resolve="keep")
                        expected = expression.replace(f"{kind},{field}",
                                                      expected_process(matcher) if kind == "PROCESS-NAME" else f"{kind},{matcher}")
                        self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                         [f"{operator},{expected}"])
            if kind == "PROCESS-NAME":
                native = "payload:\n  - " + json.dumps(f"{kind},{field}")
                self.assertEqual(parse(native, purpose="proxy"), ([Rule(kind, field, literal_process=True)], []))

    def test_encoded_invalid_regex_still_rejects_the_complete_matcher(self):
        keep = Rule("DOMAIN", "keep.example.com")
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "URL-REGEX"):
            field = r'"^Game\\"'
            with self.subTest(kind=kind):
                parsed, messages = parse(f"{kind},{field},PROXY\nDOMAIN,keep.example.com,PROXY", purpose="proxy")
                self.assertEqual(parsed, [keep])
                self.assertEqual(messages, [f"line 1: invalid {kind} ^Game\\"])
                expression = f"(({kind},{field}),(DOMAIN,x.example.com))"
                parsed, messages = parse(f"AND,{expression},PROXY\nDOMAIN,keep.example.com,PROXY", purpose="proxy")
                self.assertEqual(parsed, [keep])
                self.assertEqual(messages, [f"line 1: invalid logical expression {expression}"])


class SourceBoundaryFix8Tests(unittest.TestCase):
    keep = Rule("DOMAIN", "keep.example.com")

    def test_bare_source_ambiguity_and_two_explicit_intents(self):
        values = ("^a{b$,My Proxy # note}c$|^foo$",
                  "^a{b$,My Proxy # [}c$|^foo$",
                  "^foo$,My Proxy [ # note }$", "^foo$,My } (Proxy$",
                  "^foo$,China", "^foo,bar$")
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(parse("DOMAIN-REGEX," + value + "\nDOMAIN,keep.example.com,China",
                                       purpose="proxy"),
                                 ([self.keep], ["line 1: ambiguous unquoted regex comma or policy"]))
        full = "^a{b$,My Proxy # note}c$|^foo$"
        self.assertEqual(parse(f"DOMAIN-REGEX,'{full}'\nDOMAIN,keep.example.com,China", purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", full), self.keep], []))
        self.assertEqual(parse("DOMAIN-REGEX,'^a{b$',My Proxy # note}c$|^foo$", purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", "^a{b$")], []))

    def test_quoted_policy_punctuation_and_comment_body_are_literal(self):
        for policy in ("My Proxy [", "My } (Proxy$", r"My } Proxy\z", "My Proxy ("):
            for marker in ("#", ";", "//"):
                for body in ("note", "}c$|^foo$", r"[$\z,(,PROXY", "note,REJECT"):
                    with self.subTest(policy=policy, marker=marker, body=body):
                        self.assertEqual(parse(f"DOMAIN-REGEX,'^foo$',{policy} {marker} {body}", purpose="proxy"),
                                         ([Rule("DOMAIN-REGEX", "^foo$")], []))
        self.assertEqual(parse("DOMAIN-REGEX,^foo,PROXY # note,REJECT ($ [", purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", "^foo")], []))

    def test_complete_invalid_and_class_comment_matchers_in_explicit_scopes(self):
        invalid = "^a{b$,My Proxy # [}c$|^foo$"
        for source in (f"DOMAIN-REGEX,'{invalid}'", f"payload:\n  - 'DOMAIN-REGEX,{invalid}'",
                       f"AND,((DOMAIN-REGEX,{invalid}),(DOMAIN,x.example.com)),PROXY"):
            with self.subTest(source=source):
                parsed, messages = parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy")
                self.assertEqual(parsed, [self.keep])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith("line "))
        for value in ("^a{b$,[ # note ]c}x$|^foo$", "^a{b$,(?# # note)c}x$|^foo$"):
            self.assertEqual(parse(f"DOMAIN-REGEX,'{value}'", purpose="proxy"),
                             ([Rule("DOMAIN-REGEX", value)], []))
            expression = f"((DOMAIN-REGEX,{value}),(DOMAIN,x.example.com))"
            self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                             ([Rule("AND", expression)], []))

    def test_provider_headers_and_native_field_consumption(self):
        for header in ("payload:", "payload :", "payload\t:", '"payload":', "'payload':",
                       "rules:", "rules :", "rules\t:", '"rules":', "'rules':", '"pay\\u006coad":'):
            with self.subTest(header=header):
                source = header + '\n  -  \'PROCESS-NAME,"Game,Inc",PROXY\'\n' + \
                         '  - "PROCESS-NAME,Game\\\\,Inc"\n' + \
                         "  - DOMAIN-REGEX,^Game , REJECT$\n  - PROCESS-NAME-REGEX,^Game,no-resolve\n" + \
                         "  - IP-CIDR,192.0.2.0/24,src,no-resolve,arbitrary\n" + \
                         "  - IP-CIDR,198.51.100.0/24,SRC,no-resolve\n"
                self.assertEqual(parse(source, purpose="proxy"), ([
                    Rule("PROCESS-NAME", '"Game', literal_process=True),
                    Rule("PROCESS-NAME", "Game\\", literal_process=True),
                    Rule("DOMAIN-REGEX", "^Game,REJECT$"),
                    Rule("PROCESS-NAME-REGEX", "^Game,no-resolve"),
                    Rule("SRC-IP-CIDR", "192.0.2.0/24"),
                    Rule("IP-CIDR", "198.51.100.0/24", ("no-resolve",)),
                ], ["line 6: unsupported no-resolve for SRC-IP-CIDR"]))

    def test_provider_inner_quotes_and_logic_provenance(self):
        source = "payload:\n  - 'PROCESS-NAME,''Game'',PROXY'\n" + \
                 '  - "PROCESS-NAME,\\"Other\\",PROXY"\n' + \
                 "  - 'DOMAIN-REGEX,\"^ads$\"'\n" + \
                 "  - 'AND,((DOMAIN-REGEX,\"*ads\"),(DOMAIN,x.example.com))'"
        expression = '((DOMAIN-REGEX,"*ads"),(DOMAIN,x.example.com))'
        self.assertEqual(parse(source, purpose="proxy"), ([
            Rule("PROCESS-NAME", "'Game'", literal_process=True),
            Rule("PROCESS-NAME", '"Other"', literal_process=True),
            Rule("DOMAIN-REGEX", '"^ads$"'), Rule("AND", expression, native_fields=True),
        ], []))
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy")[0], [])
        text = '((DOMAIN-REGEX,"^ads$"),(DOMAIN,x.example.com))'
        native = parse("payload:\n  - 'AND," + text + "'", purpose="proxy")[0][0]
        mixed = parse("AND," + text + ",PROXY", purpose="proxy")[0][0]
        self.assertEqual(native.value, mixed.value)
        self.assertNotEqual(native, mixed)
        self.assertEqual(len(normalize([native, mixed])), 2)

    def test_yaml_fixed_scalar_escape_set_and_decoded_controls(self):
        escapes = {r"\0": "\0", r"\a": "\a", r"\b": "\b", r"\t": "\t", "\\\t": "\t",
                   r"\n": "\n", r"\v": "\v", r"\f": "\f", r"\r": "\r", r"\e": "\x1b",
                   "\\ ": " ", r'\"': '"', r"\'": "'", r"\\": "\\", r"\N": "\x85",
                   r"\_": "\xa0", r"\L": " ", r"\P": " ", r"\x73": "s",
                   chr(92) + "u0073": "s", r"\U00000073": "s", r"\U0001F600": "\U0001f600"}
        for escaped, decoded in escapes.items():
            with self.subTest(escaped=escaped):
                self.assertEqual(parse(f'payload:\n  - "PROCESS-NAME,A{escaped}B"', purpose="proxy"),
                                 ([Rule("PROCESS-NAME", "A" + decoded + "B", literal_process=True)], []))
        self.assertEqual(parse('payload:\n  - "DOMAIN-REGEX,^ads\\t"', purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", "^ads\t")], []))
        for escape in (r"\/", r"\c", r"\q", r"\1", r"\x", r"\x7", r"\xGG", r"\u073",
                       r"\uZZZZ", r"\U0000073", r"\uD800", r"\uDC00", chr(92) + "uD800" + chr(92) + "uDC00",
                       r"\U0000D800", r"\U00110000"):
            with self.subTest(escape=escape):
                self.assertEqual(parse(f'payload:\n  - "PROCESS-NAME,A{escape},B"\n  - DOMAIN,keep.example.com',
                                       purpose="proxy"), ([self.keep], ["line 2: invalid YAML payload"]))

    def test_yaml_ascii_whitespace_plain_comments_and_unsupported_subset(self):
        for value in ("Game\xa0#Inc", "Game#Inc", "Game ;Inc", "Game //Inc"):
            self.assertEqual(parse(f"payload:\n  - PROCESS-NAME,{value}", purpose="proxy"),
                             ([Rule("PROCESS-NAME", value, literal_process=True)], []))
        for ending in (' #note', '\t#note', '#note'):
            self.assertEqual(parse('payload:\n  - "PROCESS-NAME,Game"' + ending, purpose="proxy"),
                             ([Rule("PROCESS-NAME", "Game", literal_process=True)], []))
        for item in ('-\tDOMAIN,x.example.com', '- \t DOMAIN,x.example.com', '-\xa0DOMAIN,x.example.com',
                     '\t- DOMAIN,x.example.com', '- "PROCESS-NAME,Game"\xa0#note',
                     '- "PROCESS-NAME,Game" extra', '- PROCESS-NAME,Game: Inc',
                     '- &rule DOMAIN,x.example.com', '- *rule', '- !!str DOMAIN,x.example.com',
                     '- [DOMAIN,x.example.com]', '- |', '- >', '- "PROCESS-NAME,Game',
                     "- 'PROCESS-NAME,Game"):
            with self.subTest(item=item):
                self.assertEqual(parse("payload:\n  " + item + "\n  - DOMAIN,keep.example.com", purpose="proxy"),
                                 ([self.keep], ["line 2: invalid YAML payload"]))
        self.assertEqual(parse("payload:\n  - 'PROCESS-NAME,Game: Inc'", purpose="proxy"),
                         ([Rule("PROCESS-NAME", "Game: Inc", literal_process=True)], []))

    def test_bom_document_html_and_regex_literal_doctype(self):
        self.assertEqual(parse("﻿<!doctype html>\nDOMAIN,keep.example.com,PROXY", purpose="proxy"),
                         ([], ["line 1: HTML document"]))
        self.assertEqual(parse("﻿PROCESS-NAME-REGEX,^<!doctype$,PROXY\nDOMAIN,keep.example.com,China",
                               purpose="proxy"), ([Rule("PROCESS-NAME-REGEX", "^<!doctype$"), self.keep], []))


class SourceScannerContinuationTests(unittest.TestCase):
    def test_extended_comment_cannot_create_source_policy(self):
        for suffix in (",PROXY", ",REJECT", ",LIST", ",China", ",PROXY # [ ($"):
            source = "DOMAIN-REGEX,^(?x)a # ignored" + suffix
            self.assertEqual(parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy"),
                             ([Rule("DOMAIN", "keep.example.com")],
                              ["line 1: ambiguous unquoted regex comment"]))
        value = "^(?x)a # ignored,PROXY"
        self.assertEqual(parse(f"DOMAIN-REGEX,'{value}',PROXY", purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", value)], []))
        expression = f"((DOMAIN-REGEX,{value}),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                         ([Rule("AND", expression)], []))

    def test_extended_hash_without_source_comment_separator_preserves_complete_matcher(self):
        for value in ("^(?x)a#ignored", "^(?x)a#ignored,PROXY", "^(?x)a#ignored,REJECT [ ($"):
            with self.subTest(value=value):
                self.assertEqual(parse("DOMAIN-REGEX," + value, purpose="proxy"),
                                 ([Rule("DOMAIN-REGEX", value)], []))

    def test_known_action_stops_before_fake_policy_and_regex_syntax_in_comment(self):
        for action, purpose in (("PROXY", "proxy"), ("LIST", "proxy"), ("DIRECT", "direct"), ("REJECT", "block")):
            for marker in ("#", ";", "//"):
                for body in ("note,REJECT", "note,PROXY ($ [", r"note $ \z,LIST", "note }c$|^foo$"):
                    self.assertEqual(parse(f"DOMAIN-REGEX,^a{{b$,{action} {marker} {body}", purpose=purpose),
                                     ([Rule("DOMAIN-REGEX", "^a{b$")], []))

    def test_both_quote_characters_are_preserved_in_native_and_mixed_scopes(self):
        value = "^[\"']Game$"
        expression = f"((DOMAIN-REGEX,{value}),(NETWORK,tcp))"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},PROXY", purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", value)], []))
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                         ([Rule("AND", expression)], []))
        document = "payload:\n  - 'AND," + expression.replace("'", "''") + "'"
        self.assertEqual(parse(document, purpose="proxy"),
                         ([Rule("AND", expression, native_fields=True)], []))


class ScalarContinuationTests(unittest.TestCase):
    keep = Rule("DOMAIN", "keep.example.com")

    def test_fixed_width_hex_and_scalar_boundaries_preserve_every_character(self):
        for escape, decoded in ((r"\x00", "\0"), (r"\xFF", "\xff"), (r"\x73z", "sz"),
                                (r"\u0000", "\0"), (r"\uD7FF", "\ud7ff"), (r"\uE000", "\ue000"),
                                (r"\uFFFF", "\uffff"), (r"\U00000000", "\0"),
                                (r"\U0010FFFF", "\U0010ffff")):
            with self.subTest(escape=escape):
                self.assertEqual(parse(f'payload:\n  - "PROCESS-NAME,A{escape}B"', purpose="proxy"),
                                 ([Rule("PROCESS-NAME", "A" + decoded + "B", literal_process=True)], []))
        for scalar, value in (("'PROCESS-NAME,Game\\'", "Game\\"),
                              ("'PROCESS-NAME,Game\\n'", r"Game\n"),
                              ("'PROCESS-NAME,Game''Inc'", "Game'Inc"),
                              ('"PROCESS-NAME,A\tB"', "A\tB"),
                              ("PROCESS-NAME,Game\\u0073", r"Game\u0073")):
            with self.subTest(scalar=scalar):
                self.assertEqual(parse("rules:\n  - " + scalar, purpose="proxy"),
                                 ([Rule("PROCESS-NAME", value, literal_process=True)], []))

    def test_decoded_controls_survive_regex_and_logic_normalization(self):
        for escape, control in ((r"\t", "\t"), (r"\r", "\r"), (r"\n", "\n"), (r"\0", "\0"),
                                (r"\N", "\x85"), (r"\L", "\u2028"), (r"\P", "\u2029")):
            for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
                with self.subTest(escape=escape, kind=kind):
                    value = "^A" + control + "B$"
                    source = f'payload:\n  - "{kind},^A{escape}B$"'
                    self.assertEqual(parse(source, purpose="proxy"), ([Rule(kind, value)], []))
                    expression = f"(({kind},{value}),(PROCESS-NAME,A{control}B))"
                    source = f'payload:\n  - "AND,(({kind},^A{escape}B$),(PROCESS-NAME,A{escape}B))"'
                    expected = Rule("AND", expression, literal_process=True, native_fields=True)
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual((parsed, messages), ([expected], []))
                    self.assertEqual(normalize(parsed), [expected])

    def test_malformed_scalar_branches_warn_and_keep_following_native_neighbor(self):
        invalid = (r'"PROCESS-NAME,A\x1"', r'"PROCESS-NAME,A\xＦF"', r'"PROCESS-NAME,A\uFFF"',
                   r'"PROCESS-NAME,A\uDFFF"', r'"PROCESS-NAME,A\U0000DC00"',
                   r'"PROCESS-NAME,A\UFFFFFFFF"', r'"PROCESS-NAME,A\U00110000"',
                   r'"PROCESS-NAME,A\uD800\uDC00"', r'"PROCESS-NAME,A\/B"',
                   r'"PROCESS-NAME,A\"', '"PROCESS-NAME,A\\', '"PROCESS-NAME,A',
                   "'PROCESS-NAME,A", "'PROCESS-NAME,A' extra", "'PROCESS-NAME,A'\xa0#note",
                   "'PROCESS-NAME,A\\'Inc'", "PROCESS-NAME,A: B", "PROCESS-NAME,A:\tB",
                   "&rule DOMAIN,x.example.com", "*rule", "!!str DOMAIN,x.example.com",
                   "[DOMAIN,x.example.com]", "{rule: DOMAIN,x.example.com}", "|", ">")
        for scalar in invalid:
            with self.subTest(scalar=scalar):
                self.assertEqual(parse("rules:\n  - " + scalar + "\n  - DOMAIN,keep.example.com", purpose="proxy"),
                                 ([self.keep], ["line 2: invalid YAML payload"]))

    def test_headers_dash_styles_and_content_whitespace_have_separate_boundaries(self):
        for header in ("payload:", "payload :", "payload\t:", '"payload" : #note',
                       "'rules'\t:", '"ru\\u006ces":', '"pay\\x6coad":'):
            for dash in ("- ", "-  ", "  -   "):
                with self.subTest(header=header, dash=dash):
                    self.assertEqual(parse(header + "\n" + dash + "DOMAIN,keep.example.com", purpose="proxy"),
                                     ([self.keep], []))
        for header in ("payload\xa0:", "\xa0payload:", '"payload\\_":', "' payload':", '"payload" extra:',
                       "payload: []", "rules: &rules", '"pay\\qload":'):
            with self.subTest(header=header):
                parsed, messages = parse(header + "\n  - DOMAIN,x.example.com\nDOMAIN,keep.example.com,China", purpose="proxy")
                self.assertEqual(parsed, [self.keep])
                self.assertTrue(messages)
                self.assertTrue(all(message.startswith("line ") for message in messages))
        for value in ("Game\xa0#Inc", "Game#Inc", "Game ;Inc", "Game //Inc", "Game:\xa0Inc"):
            self.assertEqual(parse("payload:\n  - PROCESS-NAME," + value, purpose="proxy"),
                             ([Rule("PROCESS-NAME", value, literal_process=True)], []))
        for separator in (" ", "\t"):
            self.assertEqual(parse("payload:\n  - PROCESS-NAME,Game" + separator + "# note", purpose="proxy"),
                             ([Rule("PROCESS-NAME", "Game", literal_process=True)], []))
        for control in ("\r", "\v", "\f", "\x85", "\u2028", "\u2029", "\0"):
            self.assertEqual(parse("payload:\n  - PROCESS-NAME,A" + control + "B\n  - DOMAIN,keep.example.com", purpose="proxy"),
                             ([self.keep], ["line 2: unsupported physical line separator"]))

    def test_provider_header_requires_separation_before_comment(self):
        for header in ("payload:#note", "rules:#note", '"payload":#note', "'rules':#note"):
            with self.subTest(header=header):
                source = header + "\n  - DOMAIN,probe.example\npayload:\n  - DOMAIN,keep.example.com"
                self.assertEqual(parse(source, purpose="proxy"),
                                 ([self.keep], ["line 1: invalid YAML payload", "line 2: invalid YAML payload"]))
        for header in ("payload: #note", "rules:\t#note", '"payload": #note', "'rules':\t#note"):
            self.assertEqual(parse(header + "\n  - DOMAIN,keep.example.com", purpose="proxy"), ([self.keep], []))

    def test_native_params_and_same_name_regex_suffixes_remain_source_specific(self):
        for header in ("payload:", "rules:"):
            for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
                for suffix in ("PROXY", "LIST", "DIRECT", "REJECT", "no-resolve"):
                    with self.subTest(header=header, kind=kind, suffix=suffix):
                        self.assertEqual(parse(header + f"\n  - {kind},^Game,{suffix}", purpose="proxy"),
                                         ([Rule(kind, f"^Game,{suffix}")], []))
            expression = '((PROCESS-NAME,"Game),(PROCESS-PATH,Game\\),(IP-CIDR,198.51.100.0/24,no-resolve))'
            source = header + '\n  - \'AND,((PROCESS-NAME,"Game,Inc"),(PROCESS-PATH,Game\\,Inc),(IP-CIDR,198.51.100.0/24,SRC,no-resolve,arbitrary))\''
            self.assertEqual(parse(source, purpose="proxy"),
                             ([Rule("AND", expression, literal_process=True, native_fields=True)], []))
        self.assertEqual(parse("rules:\n  - DOMAIN,keep.example.com,PROXY\n  - IP-CIDR,198.51.100.0/24,no-resolve", purpose="proxy"),
                         ([self.keep, Rule("IP-CIDR", "198.51.100.0/24", ("no-resolve",))], []))
        self.assertEqual(rules.parse_whitelist("rules:\n  - DOMAIN,keep.example.com,PROXY"), [self.keep])

    def test_bare_custom_policy_and_marker_matrix_keeps_legal_neighbor(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "URL-REGEX"):
            for value in ("^foo$", "^a{b$", r"^foo\z", "^(?x)a{b$"):
                for policy in ("China", "My Proxy [", "My } (Proxy$", r"My } Proxy\z"):
                    for marker in ("#", ";", "//"):
                        with self.subTest(kind=kind, value=value, policy=policy, marker=marker):
                            source = f"{kind},{value},{policy} {marker} note }} [ ($,PROXY"
                            self.assertEqual(parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy"),
                                             ([self.keep], ["line 1: ambiguous unquoted regex comma or policy"]))
                            explicit = f"{kind},{_quote_matcher(value)},{policy} {marker} note }} [ ($,PROXY"
                            expected = ([self.keep], [f"line 1: invalid URL-REGEX {value}"]) if (
                                kind == "URL-REGEX" and value in (r"^foo\z", "^(?x)a{b$")
                            ) else ([Rule(kind, value), self.keep], [])
                            self.assertEqual(parse(explicit + "\nDOMAIN,keep.example.com,China", purpose="proxy"), expected)


class SourceAdapterParserFix1Tests(unittest.TestCase):
    keep = Rule("DOMAIN", "keep.example.com")

    def test_mixed_quoted_regex_leaves_keep_complete_matcher_scope(self):
        for operator in ("AND", "OR", "NOT"):
            for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "URL-REGEX"):
                extended = "(?x)^a # comment (" if kind == "URL-REGEX" else "^(?x)a # comment ("
                for value in ("^[a(]$", "^[)]$", extended, "^(?# (()a$", "^(a,b)$"):
                    for quote in ("'", '"', ""):
                        with self.subTest(operator=operator, kind=kind, value=value, quote=quote):
                            child = f"({kind},{quote}{value}{quote})"
                            expression = f"({child})" if operator == "NOT" else f"({child},(DOMAIN,x.example.com))"
                            expected = Rule(operator, expression)
                            parsed, messages = parse(f"{operator},{expression},PROXY\nDOMAIN,keep.example.com,PROXY",
                                                     purpose="proxy")
                            self.assertEqual((parsed, messages), ([expected, self.keep], []))
                            self.assertIn(expected, normalize(parsed))

    def test_quoted_invalid_regex_leaves_validate_the_complete_matcher(self):
        for operator in ("AND", "OR", "NOT"):
            for quote in ("'", '"'):
                for value in ("^[a(]$[", "^[)]$[", "^(?# (()a$[", "*ads"):
                    with self.subTest(operator=operator, quote=quote, value=value):
                        child = f"(DOMAIN-REGEX,{quote}{value}{quote})"
                        expression = f"({child})" if operator == "NOT" else f"({child},(DOMAIN,x.example.com))"
                        source = f"{operator},{expression},PROXY\nDOMAIN,keep.example.com,PROXY"
                        self.assertEqual(parse(source, purpose="proxy"),
                                         ([self.keep], [f"line 1: invalid logical expression {expression}"]))

    def test_ordinary_tail_comments_are_isolated_before_field_scanning(self):
        for kind, value in (("DOMAIN", "foo.example"), ("PROCESS-NAME", "Game #1"),
                            ("IP-CIDR", "192.0.2.0/24"), ("HOST", "foo.example")):
            expected = Rule("DOMAIN" if kind == "HOST" else kind, value,
                            domain_source="qx" if kind == "HOST" else "surge")
            for action, purpose in (("PROXY", "proxy"), ("LIST", "proxy"), ("DIRECT", "direct"),
                                    ("REJECT", "block"), ("My Proxy [", "proxy")):
                for marker in ("#", ";", "//"):
                    for body in ("note,'oops", 'note,"oops', "note,(,[,REJECT", r"note,PROXY $ \z } [ ("):
                        with self.subTest(kind=kind, action=action, marker=marker, body=body):
                            line = f"{kind},{value},{action} {marker} {body}"
                            source = line + f"\nDOMAIN,keep.example.com,{action}"
                            self.assertEqual(parse(source, purpose=purpose), ([expected, self.keep], []))
                            self.assertEqual(rules._without_comment(line), f"{kind},{value},{action}")

    def test_ordinary_policy_free_comments_and_quoted_literal_markers_keep_their_scopes(self):
        for marker in ("#", ";", "//"):
            for body in ("note,'oops", 'note,"oops', "note,[,(,PROXY"):
                for line, expected in ((f"DOMAIN,foo.example {marker} {body}", Rule("DOMAIN", "foo.example")),
                                       (f"IP-CIDR,192.0.2.0/24 {marker} {body}", Rule("IP-CIDR", "192.0.2.0/24"))):
                    with self.subTest(line=line):
                        self.assertEqual(parse(line + "\nDOMAIN,keep.example.com,PROXY", purpose="proxy"),
                                         ([expected, self.keep], []))
            for quote in ("'", '"'):
                value = f"^Game {marker}1$"
                source = f"DOMAIN-REGEX,{quote}{value}{quote},PROXY {marker} note,'oops"
                self.assertEqual(parse(source + "\nDOMAIN,keep.example.com,PROXY", purpose="proxy"),
                                 ([Rule("DOMAIN-REGEX", value), self.keep], []))
        self.assertEqual(parse("DOMAIN-REGEX,^Game #1$,My Proxy\nDOMAIN,keep.example.com,PROXY", purpose="proxy"),
                         ([self.keep], ["line 1: ambiguous unquoted regex comment"]))

    def test_native_fixed_source_constructors_ignore_params_at_top_level_and_in_logic(self):
        for header in ("payload:", "rules:"):
            for kind, value in (("SRC-IP-CIDR", "127.0.0.0/8"), ("SRC-IP-SUFFIX", "127.0.0.1/8"),
                                ("SRC-IP-ASN", "64512"), ("SRC-GEOIP", "cn")):
                for params in ("", ",src", ",SRC", ",no-resolve", ",arbitrary", ",src,no-resolve,arbitrary"):
                    with self.subTest(header=header, kind=kind, params=params):
                        self.assertEqual(parse(f"{header}\n  - {kind},{value}{params}\n  - DOMAIN,keep.example.com",
                                               purpose="proxy"), ([Rule(kind, value), self.keep], []))
                    for operator in ("AND", "OR", "NOT"):
                        with self.subTest(header=header, kind=kind, params=params, operator=operator):
                            leaf = f"({kind},{value}{params})"
                            clean = f"({kind},{value})"
                            expression = f"({leaf})" if operator == "NOT" else f"({leaf},(NETWORK,tcp))"
                            normalized = f"({clean})" if operator == "NOT" else f"({clean},(NETWORK,tcp))"
                            source = f"{header}\n  - '{operator},{expression}'\n  - DOMAIN,keep.example.com"
                            expected = Rule(operator, normalized, native_fields=True)
                            parsed, messages = parse(source, purpose="proxy")
                            self.assertEqual((parsed, messages), ([expected, self.keep], []))
                            self.assertIn(expected, normalize(parsed))

    def test_native_destination_params_keep_case_sensitive_direction(self):
        for kind, source_kind, value in (("IP-CIDR", "SRC-IP-CIDR", "127.0.0.0/8"),
                                         ("IP-CIDR6", "SRC-IP-CIDR", "2001:db8::/32"),
                                         ("IP-SUFFIX", "SRC-IP-SUFFIX", "127.0.0.1/8"),
                                         ("IP-ASN", "SRC-IP-ASN", "64512"), ("GEOIP", "SRC-GEOIP", "cn")):
            for params, sourced, no_resolve in (("", False, False), (",src", True, False),
                                                (",SRC", False, False), (",no-resolve", False, True),
                                                (",arbitrary", False, False), (",src,no-resolve", True, False)):
                expected_kind = source_kind if sourced else kind
                options = ("no-resolve",) if no_resolve else ()
                warning = [f"line 2: unsupported no-resolve for {source_kind}"] if params == ",src,no-resolve" else []
                with self.subTest(kind=kind, params=params):
                    self.assertEqual(parse(f"payload:\n  - {kind},{value}{params}\n  - DOMAIN,keep.example.com",
                                           purpose="proxy"), ([Rule(expected_kind, value, options), self.keep], warning))
                for operator in ("AND", "OR", "NOT"):
                    with self.subTest(kind=kind, params=params, operator=operator):
                        leaf = f"({kind},{value}{params})"
                        clean = f"({expected_kind},{value}{',no-resolve' if no_resolve else ''})"
                        expression = f"({leaf})" if operator == "NOT" else f"({leaf},(NETWORK,tcp))"
                        normalized = f"({clean})" if operator == "NOT" else f"({clean},(NETWORK,tcp))"
                        expected = Rule(operator, normalized, native_fields=True)
                        self.assertEqual(parse(f"payload:\n  - '{operator},{expression}'\n  - DOMAIN,keep.example.com",
                                               purpose="proxy"), ([expected, self.keep], warning))

    def test_native_fixed_source_params_do_not_relax_mixed_or_payload_validation(self):
        for params in ("src", "arbitrary"):
            expression = f"((SRC-IP-CIDR,127.0.0.0/8,{params}),(NETWORK,tcp))"
            self.assertEqual(parse(f"AND,{expression},PROXY\nDOMAIN,keep.example.com,PROXY", purpose="proxy"),
                             ([self.keep], [f"line 1: invalid logical expression {expression}"]))
        expression = "((SRC-IP-CIDR,127.0.0.0/8,no-resolve),(NETWORK,tcp))"
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                         ([Rule("AND", "((SRC-IP-CIDR,127.0.0.0/8),(NETWORK,tcp))")],
                          ["line 1: unsupported no-resolve for SRC-IP-CIDR"]))
        expression = "((SRC-IP-CIDR,not-an-ip,src),(NETWORK,tcp))"
        self.assertEqual(parse(f"payload:\n  - 'AND,{expression}'\n  - DOMAIN,keep.example.com", purpose="proxy"),
                         ([self.keep], [f"line 2: invalid logical expression {expression}"]))

    def test_yaml_raw_character_ranges_reject_invalid_quoted_plain_and_header_sources(self):
        points = [point for point in range(0x20) if point not in (9, 10)] + list(range(0x7F, 0xA0))
        points += [0xD800, 0xDFFF, 0xFFFE, 0xFFFF, 0x2028, 0x2029]
        physical = {0, 11, 12, 13, 0x85, 0x2028, 0x2029}
        for point in points:
            control = chr(point)
            message = "unsupported physical line separator" if point in physical else "invalid YAML payload"
            for scalar in (f'"PROCESS-NAME,A{control}B"', f"'PROCESS-NAME,A{control}B'",
                           f"PROCESS-NAME,A{control}B", f'"PROCESS-NAME,Game" # noteA{control}B'):
                with self.subTest(point=hex(point), scalar=scalar):
                    self.assertEqual(parse(f"payload:\n  - {scalar}\n  - DOMAIN,keep.example.com", purpose="proxy"),
                                     ([self.keep], [f"line 2: {message}"]))
            for header in ("payload:", '"payload":', "'rules':"):
                with self.subTest(point=hex(point), header=header):
                    source = f"{header} # A{control}B\npayload:\n  - DOMAIN,keep.example.com"
                    self.assertEqual(parse(source, purpose="proxy"), ([self.keep], [f"line 1: {message}"]))

    def test_yaml_raw_printable_unicode_boundaries_and_tab_remain_literal(self):
        for point in (9, 0x20, 0x7E, 0xA0, 0xD7FF, 0xE000, 0xFDD0, 0xFFFD, 0x10000, 0x1F600, 0x10FFFF):
            value = "A" + chr(point) + "B"
            for scalar in (f'"PROCESS-NAME,{value}"', f"'PROCESS-NAME,{value}'", f"PROCESS-NAME,{value}"):
                with self.subTest(point=hex(point), scalar=scalar):
                    self.assertEqual(parse(f"payload:\n  - {scalar}\n  - DOMAIN,keep.example.com", purpose="proxy"),
                                     ([Rule("PROCESS-NAME", value, literal_process=True), self.keep], []))
            for header in ("payload:", '"payload":', "'rules':"):
                with self.subTest(point=hex(point), header=header):
                    self.assertEqual(parse(f"{header} # {value}\n  - DOMAIN,keep.example.com", purpose="proxy"),
                                     ([self.keep], []))
        self.assertEqual(parse('payload:\n  - "PROCESS-NAME,A\nB"\nDOMAIN,keep.example.com,PROXY', purpose="proxy"),
                         ([self.keep], ["line 2: invalid YAML payload", "line 3: invalid rule"]))
        self.assertEqual(parse("PROCESS-NAME,A\aB,PROXY", purpose="proxy"), ([Rule("PROCESS-NAME", "A\aB")], []))

    def test_yaml_escapes_can_decode_characters_disallowed_in_raw_source(self):
        escapes = [(rf"\x{point:02x}", chr(point)) for point in (*range(0x20), *range(0x7F, 0xA0))]
        escapes += [(r"\a", "\a"), (r"\e", "\x1b"), (r"\x01", "\x01"), (r"\x1f", "\x1f"),
                    (chr(92) + "uFFFE", chr(0xFFFE)), (chr(92) + "uFFFF", chr(0xFFFF))]
        for escape, control in escapes:
            with self.subTest(escape=escape):
                expected = Rule("PROCESS-NAME", "A" + control + "B", literal_process=True)
                self.assertEqual(parse(f'payload:\n  - "PROCESS-NAME,A{escape}B"\n  - DOMAIN,keep.example.com',
                                       purpose="proxy"), ([expected, self.keep], []))
        for escape, control in ((r"\a", "\a"), (r"\e", "\x1b"), (r"\x01", "\x01"), (r"\x1f", "\x1f")):
            with self.subTest(escape=escape):
                expression = f"((DOMAIN-REGEX,^A{control}B$),(PROCESS-NAME,A{control}B))"
                source = f'payload:\n  - "AND,((DOMAIN-REGEX,^A{escape}B$),(PROCESS-NAME,A{escape}B))"'
                expected = Rule("AND", expression, literal_process=True, native_fields=True)
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual((parsed, messages), ([expected], []))
                self.assertEqual(normalize(parsed), [expected])

    def test_native_regex_leaf_quotes_keep_their_literal_meaning(self):
        for operator in ("AND", "OR", "NOT"):
            for value in ('"*ads"', '"^[()]$"', "'^[()]$'"):
                with self.subTest(operator=operator, value=value):
                    child = f"(DOMAIN-REGEX,{value})"
                    expression = f"({child})" if operator == "NOT" else f"({child},(DOMAIN,x.example.com))"
                    scalar = f"{operator},{expression}".replace("'", "''")
                    source = f"payload:\n  - '{scalar}'\n  - DOMAIN,keep.example.com"
                    expected = Rule(operator, expression, native_fields=True)
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual((parsed, messages), ([expected, self.keep], []))
                    self.assertIn(expected, normalize(parsed))


class NativeLogicalRendererStructureTests(unittest.TestCase):
    def test_in_user_structural_tail_survives_parse_normalize_and_reparse(self):
        import json

        for depth in (1, 600, 1000):
            matcher = ('(NOT,(' * depth + '(IN-USER,Foo(,ignored))' + '))' * depth)[1:-1]
            source = 'payload:\n  - ' + json.dumps(matcher) + '\n  - DOMAIN,keep.example.com\n'
            expected = [Rule('NOT', matcher[4:], native_fields=True), Rule('DOMAIN', 'keep.example.com')]
            with self.subTest(depth=depth):
                parsed, messages = parse(source, purpose='proxy')
                self.assertEqual(messages, [])
                self.assertEqual(parsed, expected)
                self.assertEqual(set(normalize(parsed)), set(expected))
                self.assertEqual(parse(source, purpose='proxy'), (expected, []))

    def test_normalization_preserves_original_ignored_process_fields(self):
        import json

        for kind in ("PROCESS-NAME", "PROCESS-PATH", "IN-NAME"):
            for params in (",ignored", "(,ignored)"):
                expression = f"(({kind},Foo{params}))"
                with self.subTest(kind=kind, params=params):
                    parsed, messages = parse("payload:\n  - " + json.dumps("NOT," + expression), purpose="proxy")
                    expected = Rule("NOT", expression if '(' in params else f"(({kind},Foo))",
                                    literal_process=kind == "PROCESS-NAME", native_fields=True)
                    self.assertEqual((parsed, messages), ([expected], []))
                    self.assertEqual(normalize(parsed), [expected])
                    self.assertEqual(parse("payload:\n  - " + json.dumps("NOT," + parsed[0].value), purpose="proxy"),
                                     ([expected], []))


class DeepLogicalParserTests(unittest.TestCase):
    def test_deep_domain_types_share_traversal_and_ignore_matcher_text(self):
        leaves = (('(DOMAIN-KEYWORD,Ads)', True),
                  ('(DOMAIN-WILDCARD,api-[0-9].example.com)', True),
                  ('(DOMAIN-WILDCARD,api-*.example.com)', True),
                  ('(DOMAIN-REGEX,[(]DOMAIN-WILDCARD,Fake[)])', False),
                  ('(PROCESS-NAME-REGEX,DOMAIN-KEYWORD)', False))
        for depth in (600, 1000):
            for native in (False, True):
                for leaf, has_domain in leaves:
                    with self.subTest(depth=depth, native=native, leaf=leaf):
                        self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r}, mixed=True)
kind, value = condition[1:-1].split(',', 1)
expected = Rule(kind, value, native_fields={native},
                domain_source={'mihomo' if native and has_domain else 'surge'!r})
source = ('payload:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com') if {native} else condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT'
parsed, messages = parse(source, purpose='block')
assert (parsed, messages) == ([expected, keep], []), (len(parsed), messages)
assert normalize(parsed * 2) == normalize([expected, keep])
assert parse_whitelist(source) == [keep]
assert not expected.literal_process
''')

    def test_native_ignored_tail_parentheses_preserve_process_provenance(self):
        for depth in (1, 600, 1000):
            for kind in ('PROCESS-NAME', 'PROCESS-PATH', 'IN-NAME'):
                with self.subTest(depth=depth, kind=kind):
                    self.assert_subprocess(f'''
condition = nest({depth}, '({kind},Foo(,ignored))')
clean = condition
expected = Rule('NOT', clean[5:-1], literal_process={kind == 'PROCESS-NAME'}, native_fields=True)
source = 'payload:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com'
assert parse(source, purpose='block') == ([expected, keep], [])
assert normalize(parse(source, purpose='block')[0] * 2) == normalize([expected, keep])
assert parse_whitelist(source) == [keep]
''')

    def test_native_ignored_tail_does_not_abort_local_generation(self):
        self.assert_subprocess('''
import contextlib
import io
import tempfile
from pathlib import Path
from generate import generate
staging = Path.cwd() / '.tmp'
staging.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=staging) as directory:
    root = Path(directory)
    (root / 'rulesets.json').write_text(json.dumps([{
        'name': 'group', 'purpose': 'block', 'no_resolve': 'keep',
        'sources': ['native.yaml'], 'whitelist': []
    }]), encoding='utf-8')
    (root / 'native.yaml').write_text('payload:\\n  - "NOT,((PROCESS-NAME,Foo(,ignored)))"\\n  - DOMAIN,keep.example.com', encoding='utf-8')
    def unexpected_fetch(url):
        raise AssertionError(url)
    with contextlib.redirect_stderr(io.StringIO()) as messages:
        outputs = generate(root, unexpected_fetch)
    assert '  - "DOMAIN,keep.example.com"\\n' in outputs[root / 'group/fin.yaml']
    assert ': line ' not in messages.getvalue(), messages.getvalue()
''')

    def assert_subprocess(self, code):
        setup = '''
import json
import sys
from rules import Rule, parse, normalize, parse_whitelist, _has_process_name, _normalize_condition
limit = sys.getrecursionlimit()
keep = Rule('DOMAIN', 'keep.example.com')
def nest(depth, leaf, mixed=False, bare=False):
    for index in range(depth):
        kind = ('NOT', 'AND', 'OR')[index % 3] if mixed else 'NOT'
        if kind == 'NOT':
            leaf = '(NOT,' + (leaf if bare else '(' + leaf + ')') + ')'
        else:
            leaf = '(' + kind + ',(' + leaf + ',(NETWORK,tcp)))'
    return leaf
'''
        try:
            result = subprocess.run([sys.executable, '-B', '-c', setup + code +
                                     '\nassert sys.getrecursionlimit() == limit\n'],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail('深层逻辑解析子进程超过四秒')
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])

    def test_deep_long_regex_keeps_complete_matcher_within_timeout(self):
        for depth in (600, 1000):
            for native in (False, True):
                with self.subTest(depth=depth, native=native):
                    self.assert_subprocess(f'''
matcher = '^(' + '|'.join(f'host{{index}}.example.com' for index in range(1024)) + ')$'
condition = nest({depth}, '(PROCESS-NAME-REGEX,' + matcher + ')', mixed=True)
kind, value = condition[1:-1].split(',', 1)
expected = Rule(kind, value, native_fields={native})
source = ('rules:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com') if {native} else condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT'
parsed, messages = parse(source, purpose='block')
assert (parsed, messages) == ([expected, keep], []), (len(parsed), messages)
assert matcher in parsed[0].value and len(matcher) == 20397
assert not parsed[0].literal_process
assert normalize(parsed + parsed) == normalize([expected, keep])
''')

    def test_deep_not_keeps_wrapper_matcher_and_following_rule(self):
        for depth in (600, 1000):
            for bare in (False, True):
                with self.subTest(depth=depth, bare=bare):
                    self.assert_subprocess(f'''
condition = nest({depth}, '(DOMAIN,example.com)', bare={bare})
expected = Rule('NOT', condition[5:-1])
parsed, messages = parse(condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT', purpose='block')
assert (parsed, messages) == ([expected, keep], []), (len(parsed), messages)
assert normalize(parsed + parsed) == normalize([expected, keep])
assert _normalize_condition(condition) == condition
assert parse_whitelist(condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT') == [keep]
''')

    def test_deep_ip_options_keep_destination_source_and_warning_order(self):
        leaf = ('(AND,((IP-CIDR,203.0.113.7/24,no-resolve,no-resolve),'
                '(IP-CIDR,198.51.100.7/24),(IP-CIDR6,2001:db8::1/32,src,no-resolve),'
                '(SRC-IP-CIDR,192.0.2.7/24,no-resolve)))')
        clean = ('(AND,((IP-CIDR,203.0.113.0/24,no-resolve),'
                 '(IP-CIDR,198.51.100.0/24),(SRC-IP-CIDR,2001:db8::/32),'
                 '(SRC-IP-CIDR,192.0.2.0/24)))')
        for depth in (600, 1000):
            for native in (False, True):
                with self.subTest(depth=depth, native=native):
                    self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r})
expected = Rule('NOT', nest({depth}, {clean!r})[5:-1], native_fields={native})
source = ('payload:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com') if {native} else condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT'
parsed, messages = parse(source, purpose='block')
number = 2 if {native} else 1
assert parsed == [expected, keep], len(parsed)
assert messages == [f'line {{number}}: unsupported no-resolve for SRC-IP-CIDR'] * (1 if {native} else 2), messages
assert expected.options == () and expected.value.count('no-resolve') == 1
assert normalize(parsed + parsed) == normalize([expected, keep])
''')

    def test_deep_invalid_leaves_and_wrappers_warn_and_keep_neighbor(self):
        leaves = ('(IP-CIDR,203.0.113.0/33)', '(IP-CIDR6,203.0.113.0/24,src)',
                  '(NOT,((DOMAIN,example.com),(DOMAIN,other.example.com)))',
                  '(NOT,(((DOMAIN,example.com))))', '(AND,((DOMAIN,example.com)))',
                  '(UNKNOWN,example.com)', '(DOMAIN,bad..example.com)',
                  '(DOMAIN-REGEX,*ads)')
        for depth in (600, 1000):
            for leaf in leaves:
                with self.subTest(depth=depth, leaf=leaf):
                    self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r})
for native in (False, True):
    source = ('payload:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com') if native else condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT'
    parsed, messages = parse(source, purpose='block')
    if native and {leaf!r} == '(IP-CIDR6,203.0.113.0/24,src)':
        expected = nest({depth}, '(SRC-IP-CIDR,203.0.113.0/24)')
        assert parsed == [Rule('NOT', expected[5:-1], native_fields=True), keep]
        assert messages == []
    else:
        assert parsed == [keep], len(parsed)
        number = 2 if native else 1
        assert len(messages) == 1 and messages[0].startswith(f'line {{number}}:'), messages
''')
            for extra in (-1, 1):
                with self.subTest(depth=depth, extra=extra):
                    self.assert_subprocess(f'''
condition = nest({depth}, '(DOMAIN,example.com)')
line = condition[1:-1] + ')' if {extra} == 1 else condition[1:-2]
for native in (False, True):
    source = ('rules:\\n  - ' + json.dumps(line) + '\\n  - DOMAIN,keep.example.com') if native else line + ',REJECT\\nDOMAIN,keep.example.com,REJECT'
    parsed, messages = parse(source, purpose='block')
    assert parsed == [keep], len(parsed)
    number = 2 if native else 1
    assert len(messages) == 1 and messages[0].startswith(f'line {{number}}:'), messages
''')

    def test_deep_native_ignored_params_keep_mixed_validation(self):
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                self.assert_subprocess(f'''
condition = nest({depth}, '(DOMAIN,example.com,no-resolve)')
expected = Rule('NOT', nest({depth}, '(DOMAIN,example.com)')[5:-1], native_fields=True)
assert parse('payload:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com', purpose='block') == ([expected, keep], [])
parsed, messages = parse(condition[1:-1] + ',REJECT\\nDOMAIN,keep.example.com,REJECT', purpose='block')
assert parsed == [keep] and len(messages) == 1 and messages[0].startswith('line 1:'), messages
''')

    def test_deep_mixed_operators_preserve_quoted_regex_and_child_order(self):
        leaves = ('(DOMAIN-REGEX,"^(a,b)[)]$")',
                  r'''(PROCESS-NAME-REGEX,"^Game\\\\,Inc$")''',
                  '(URL-REGEX,"(?x)^a # comment (")',
                  r'(PROCESS-PATH-REGEX,^(?<name>a)\k<name>\z)',
                  '(AND,((PROCESS-NAME,"Game,Inc"),(IP-CIDR,203.0.113.1/24,no-resolve,no-resolve)))')
        for depth in (600, 1000):
            for leaf in leaves:
                with self.subTest(depth=depth, leaf=leaf):
                    self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r}, mixed=True)
clean = {leaf!r}.replace('203.0.113.1/24,no-resolve,no-resolve', '203.0.113.0/24,no-resolve')
expected_condition = nest({depth}, clean, mixed=True)
kind, value = expected_condition[1:-1].split(',', 1)
expected = Rule(kind, value)
parsed, messages = parse(condition[1:-1] + ',REJECT # note,unclosed[\\nDOMAIN,keep.example.com,REJECT', purpose='block')
assert (parsed, messages) == ([expected, keep], []), (len(parsed), messages)
assert normalize(parsed + parsed) == normalize([expected, keep])
''')

    def test_deep_native_process_flags_use_types_and_survive_normalize(self):
        leaves = (('(PROCESS-NAME,Foo*Bar)', True),
                  ('(PROCESS-NAME-REGEX,PROCESS-NAME)', False),
                  ('(DOMAIN-REGEX,[(]PROCESS-NAME,Fake[)])', False),
                  ('(AND,((PROCESS-PATH,PROCESS-NAME),(PROCESS-NAME,Foo*Bar)))', True))
        for depth in (600, 1000):
            for leaf, literal in leaves:
                with self.subTest(depth=depth, leaf=leaf):
                    self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r}, mixed=True)
kind, value = condition[1:-1].split(',', 1)
expected = Rule(kind, value, literal_process={literal}, native_fields=True)
parsed, messages = parse('rules:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com', purpose='block')
assert (parsed, messages) == ([expected, keep], []), (len(parsed), messages)
assert _has_process_name(kind, value, True) == {literal}
assert normalize(parsed + parsed) == normalize([expected, keep])
''')

    def test_deep_native_balanced_regex_class_parentheses_keep_field_scopes(self):
        for depth in (600, 1000):
            for leaf in ('(DOMAIN-REGEX,"^[)]$[a(]{1,2}")', '(DOMAIN-REGEX,^[)]$[a(]{1,2})'):
                with self.subTest(depth=depth, leaf=leaf):
                    self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r})
expected = Rule('NOT', condition[5:-1], native_fields=True)
parsed, messages = parse('payload:\\n  - ' + json.dumps(condition[1:-1]) + '\\n  - DOMAIN,keep.example.com', purpose='block')
assert (parsed, messages) == ([expected, keep], []), (len(parsed), messages)
assert normalize(parsed + parsed) == normalize([expected, keep])
''')

    def test_deep_native_and_mixed_quotes_keep_distinct_provenance(self):
        for depth in (600, 1000):
            for leaf in ('(DOMAIN-REGEX,"^ads$")', '(PROCESS-NAME,"Foo*Bar")'):
                with self.subTest(depth=depth, leaf=leaf):
                    self.assert_subprocess(f'''
condition = nest({depth}, {leaf!r})
kind, value = condition[1:-1].split(',', 1)
native, native_messages = parse('payload:\\n  - ' + json.dumps(condition[1:-1]), purpose='block')
mixed, mixed_messages = parse(condition[1:-1] + ',REJECT', purpose='block')
assert native_messages == mixed_messages == []
assert native == [Rule(kind, value, literal_process={'PROCESS-NAME' in leaf and 'REGEX' not in leaf}, native_fields=True)]
assert mixed == [Rule(kind, value)]
assert len(normalize(native + mixed + native + mixed)) == 2
''')


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
        self.assertIn(Rule("DOMAIN-SUFFIX", "example.com", domain_source="qx"), rules)
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

    def test_process_name_hash_survives_yaml_and_generated_surge_reparse(self):
        from formats import render

        parsed, messages = parse('payload:\n  - "PROCESS-NAME,Game #1"\n', purpose="proxy")
        self.assertEqual(parsed, [Rule("PROCESS-NAME", "Game #1", literal_process=True)])
        self.assertEqual(messages, [])
        native, skipped = render("a3", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(native["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.txt:PROCESS-NAME"], 1)
        parsed = [Rule("PROCESS-NAME", "Game #1")]
        text = render("a3", parsed, purpose="proxy", no_resolve="keep")[0]["fin.txt"]
        self.assertEqual(text, "# a3 rules: 1\nPROCESS-NAME,'Game #1'\n")
        reparsed, messages = parse(text, purpose="proxy")
        self.assertEqual(reparsed, [Rule("PROCESS-NAME", "Game #1")])
        self.assertEqual(messages, [])

    def test_logical_process_name_hash_survives_reparse(self):
        expression = "((PROCESS-NAME,Game #1),(DOMAIN,x.example.com))"
        parsed, messages = parse(f"AND,{expression},PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("AND", expression)])
        self.assertEqual(messages, [])

    def test_process_values_keep_comment_markers_inside_matchers(self):
        source = (
            "PROCESS-PATH,/Applications/Game #1.app,PROXY\n"
            "PROCESS-NAME-WILDCARD,*Game #1*,PROXY\n"
            "PROCESS-PATH-WILDCARD,/Applications/* Game //1*,PROXY\n"
            "PROCESS-NAME-REGEX,'^Game ;1$',PROXY\n"
            r"PROCESS-PATH-REGEX,'^/Applications/Game #1\.app$',PROXY" "\n"
            "PROCESS-NAME,Game ;1,PROXY\n"
            "PROCESS-NAME,Game //1,PROXY"
        )
        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(parsed, [
            Rule("PROCESS-PATH", "/Applications/Game #1.app"),
            Rule("PROCESS-NAME-WILDCARD", "*Game #1*"),
            Rule("PROCESS-PATH-WILDCARD", "/Applications/* Game //1*"),
            Rule("PROCESS-NAME-REGEX", "^Game ;1$"),
            Rule("PROCESS-PATH-REGEX", r"^/Applications/Game #1\.app$"),
            Rule("PROCESS-NAME", "Game ;1"), Rule("PROCESS-NAME", "Game //1"),
        ])
        self.assertEqual(messages, [])

    def test_process_regex_comma_and_markers_distinguish_matcher_from_comment(self):
        direct, messages = parse(
            "PROCESS-NAME-REGEX,'^Game,DIRECT ;1$',DIRECT\n"
            "PROCESS-NAME-REGEX,'^Game,DIRECT ;1$'\n"
            "PROCESS-NAME,Game ;1\nPROCESS-NAME,Game //1", purpose="direct",
        )
        self.assertEqual(direct, [
            Rule("PROCESS-NAME-REGEX", "^Game,DIRECT ;1$"),
            Rule("PROCESS-NAME-REGEX", "^Game,DIRECT ;1$"),
            Rule("PROCESS-NAME", "Game ;1"), Rule("PROCESS-NAME", "Game //1"),
        ])
        self.assertEqual(messages, [])
        source = (
            "PROCESS-NAME-REGEX,'^Game,Inc$' # note\n"
            "PROCESS-NAME-REGEX,'^Game,Inc #1$',PROXY # note\n"
            r"PROCESS-NAME-REGEX,'^Game,Inc\z' # note" "\n"
            "PROCESS-NAME,Game # literal\n"
            "PROCESS-NAME,Game,PROXY # note\n"
            "DOMAIN,x.example.com,PROXY # note"
        )
        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(parsed, [
            Rule("PROCESS-NAME-REGEX", "^Game,Inc$"),
            Rule("PROCESS-NAME-REGEX", "^Game,Inc #1$"),
            Rule("PROCESS-NAME-REGEX", r"^Game,Inc\z"),
            Rule("PROCESS-NAME", "Game # literal"),
            Rule("PROCESS-NAME", "Game"), Rule("DOMAIN", "x.example.com"),
        ])
        self.assertEqual(messages, [])

    def test_domain_regex_tail_comment_cannot_supply_a_second_policy(self):
        self.assertEqual(parse("DOMAIN-REGEX,^foo$,REJECT # note,REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", "^foo$")], []))

    def test_process_regex_policy_token_and_semicolon_remain_in_matcher_with_tail_comment(self):
        value = "^Game,DIRECT ;1$"
        self.assertEqual(parse(f"PROCESS-NAME-REGEX,{_quote_matcher(value)},DIRECT # note", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", value)], []))

    def test_process_regex_policy_token_and_hash_remain_in_matcher_with_tail_comment(self):
        value = "^Game,DIRECT #1$"
        self.assertEqual(parse(f"PROCESS-NAME-REGEX,{_quote_matcher(value)},DIRECT # note", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", value)], []))

    def test_process_regex_policy_token_and_slashes_remain_in_matcher_with_tail_comment(self):
        value = "^Game,DIRECT //1$"
        self.assertEqual(parse(f"PROCESS-NAME-REGEX,{_quote_matcher(value)},DIRECT # note", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", value)], []))

    def test_process_regex_literal_comma_and_comment_marker_remain_in_matcher(self):
        parsed, messages = parse(
            "PROCESS-NAME-REGEX,'^Game,Inc #1$',PROXY\n"
            r"PROCESS-PATH-REGEX,'^/Applications/Game,Inc //1\.app$',PROXY" "\n"
            "PROCESS-NAME-REGEX,^Game,Inc$,PROXY # note",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("PROCESS-NAME-REGEX", "^Game,Inc #1$"),
            Rule("PROCESS-PATH-REGEX", r"^/Applications/Game,Inc //1\.app$"),
            Rule("PROCESS-NAME-REGEX", "^Game,Inc$"),
        ])
        self.assertEqual(messages, [])

    def test_process_markers_inside_logic_and_tail_comments_keep_their_positions(self):
        expression = "((PROCESS-PATH,/Applications/Game #1.app),(PROCESS-NAME-WILDCARD,*Game //1*))"
        parsed, messages = parse(
            f"AND,{expression},PROXY # note\n"
            "PROCESS-PATH,/Applications/Game #1.app,PROXY ; note\n"
            'payload:\n  - "PROCESS-NAME,Game ;1" # note\n'
            "// whole-line comment",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("AND", expression), Rule("PROCESS-PATH", "/Applications/Game #1.app"),
            Rule("PROCESS-NAME", "Game ;1", literal_process=True),
        ])
        self.assertEqual(messages, [])

    def test_trailing_comment_does_not_change_rule_or_escaped_regex(self):
        parsed, messages = parse(
            r"DOMAIN,ads.example.com,REJECT # note" "\n"
            r"URL-REGEX,^https://ads\.example/a\#b$,REJECT # note",
            purpose="block",
        )
        self.assertEqual(parsed, [
            Rule("DOMAIN", "ads.example.com"),
            Rule("URL-REGEX", r"^https://ads\.example/a\#b$"),
        ])
        self.assertEqual(messages, [])

    def test_surge_trailing_comments_do_not_consume_quoted_values(self):
        parsed, messages = parse(
            "DOMAIN,one.example.com,REJECT // note\n"
            "DOMAIN,two.example.com,REJECT ; note\n"
            "URL-REGEX,'^https://ads\\.example/a // b$',REJECT // note",
            purpose="block",
        )
        self.assertEqual(parsed, [
            Rule("DOMAIN", "one.example.com"), Rule("DOMAIN", "two.example.com"),
            Rule("URL-REGEX", r"^https://ads\.example/a // b$"),
        ])
        self.assertEqual(messages, [])

    def test_process_regex_literal_comma_apostrophe_keeps_tail_comment(self):
        self.assertEqual(parse("PROCESS-NAME-REGEX,^Game,'s$,DIRECT # note", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", "^Game,'s$")], []))
        self.assertEqual(parse("PROCESS-NAME-REGEX,'^Game,Inc$',DIRECT # note", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", "^Game,Inc$")], []))

    def test_process_regex_apostrophe_does_not_quote_trailing_comment(self):
        value = "^Bob's$"
        self.assertEqual(parse(f"PROCESS-NAME-REGEX,{value},DIRECT # note", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", value)], []))

    def test_yaml_plain_scalar_apostrophe_does_not_quote_trailing_comment(self):
        self.assertEqual(parse("payload:\n  - PROCESS-NAME,Game's # note", purpose="proxy"),
                         ([Rule("PROCESS-NAME", "Game's", literal_process=True)], []))

    def test_quoted_hash_value_and_following_comment_stay_distinct(self):
        self.assertEqual(parse('payload:\n  - "PROCESS-NAME,Game #1" # note', purpose="proxy"),
                         ([Rule("PROCESS-NAME", "Game #1", literal_process=True)], []))

    def test_yaml_payload_comment_and_single_quote_escape(self):
        parsed, messages = parse(
            "payload: # exported\n"
            "  - 'URL-REGEX,^https://ads\\.example/it''s$,REJECT' # note\n"
            '  - "DOMAIN,ads.example.com,REJECT" # note',
            purpose="block",
        )
        self.assertEqual(parsed, [
            Rule("URL-REGEX", r"^https://ads\.example/it's$"),
            Rule("DOMAIN", "ads.example.com"),
        ])
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

    def test_unquoted_yaml_process_markers_are_literal_with_real_comments(self):
        source = (
            "# preceding comment\npayload: # exported\n"
            "  # payload comment\n"
            "  - PROCESS-NAME,Game ;1\n"
            "  - PROCESS-NAME,Game //1\n"
            "  - PROCESS-NAME,Game,PROXY # note\n"
            "  - DOMAIN,x.example.com,PROXY # note\n"
            "# trailing comment"
        )
        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(parsed, [
            Rule("PROCESS-NAME", "Game ;1", literal_process=True),
            Rule("PROCESS-NAME", "Game //1", literal_process=True),
            Rule("PROCESS-NAME", "Game", literal_process=True),
            Rule("DOMAIN", "x.example.com"),
        ])
        self.assertEqual(messages, [])

    def test_yaml_plain_scalar_keeps_semicolon_and_slashes_in_regex(self):
        values = ["^foo ;bar$", "^foo //bar$"]
        parsed, messages = parse(
            "payload:\n" + "\n".join(f"  - DOMAIN-REGEX,{value}" for value in values),
            purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_yaml_plain_scalar_hash_after_space_is_comment_even_inside_regex_class(self):
        parsed, messages = parse(
            "payload:\n  - DOMAIN-REGEX,^[a #]$\n"
            "  - 'DOMAIN-REGEX,^[a #]$'\n"
            '  - "DOMAIN-REGEX,^[a #]$"', purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", "^[a #]$")] * 2)
        self.assertEqual(messages, ["line 2: invalid DOMAIN-REGEX ^[a"])

    def test_yaml_single_quote_backslash_is_literal_before_comment(self):
        self.assertEqual(parse("payload:\n  - 'PROCESS-NAME,Game\\' # note", purpose="proxy"),
                         ([Rule("PROCESS-NAME", "Game\\", literal_process=True)], []))

    def test_yaml_double_quote_decodes_hex_escape_and_retains_json_escapes(self):
        parsed, messages = parse(
            'payload:\n  - "PROCESS-NAME,Game\\x73"\n'
            '  - "PROCESS-NAME,Game\\\\x73"\n'
            '  - "PROCESS-NAME,Game\\u0073"', purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("PROCESS-NAME", "Games", literal_process=True),
                                  Rule("PROCESS-NAME", r"Game\x73", literal_process=True),
                                  Rule("PROCESS-NAME", "Games", literal_process=True)])
        self.assertEqual(messages, [])

    def test_yaml_double_quote_rejects_invalid_and_incomplete_hex_escapes(self):
        parsed, messages = parse(
            'payload:\n  - "PROCESS-NAME,Game\\xG1"\n'
            '  - "PROCESS-NAME,Game\\x7"\n'
            '  - "PROCESS-NAME,Game\\x"\n'
            '  - "PROCESS-NAME,Games"', purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("PROCESS-NAME", "Games", literal_process=True)])
        self.assertEqual(messages, [f"line {number}: invalid YAML payload" for number in (2, 3, 4)])

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
                    Rule("DOMAIN", expected, domain_source="qx" if purpose == "block" else "surge"), Rule("DOMAIN", "unassigned.example.com")
                ])
                self.assertEqual(len(warnings), 2)

    def test_adblock_named_policy_is_only_accepted_in_block_group(self):
        source = "HOST-SUFFIX,ads.example.com,ADBLOCK"
        self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com", domain_source="qx")])
        self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_advertisinglite_named_policy_is_only_accepted_in_block_group(self):
        source = "HOST-SUFFIX,ads.example.com,AdvertisingLite"
        self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com", domain_source="qx")])
        self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_hijacking_named_policy_is_only_accepted_in_block_group(self):
        source = "HOST-SUFFIX,hijack.example.com,Hijacking"
        self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "hijack.example.com", domain_source="qx")])
        self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_curated_privacy_and_zhihu_ads_policies_are_block_only(self):
        for policy in ("Privacy", "ZhihuAds"):
            with self.subTest(policy=policy):
                source = f"HOST-SUFFIX,ads.example.com,{policy}"
                self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com", domain_source="qx")])
                self.assertEqual(parse(source, purpose="direct")[0], [])

    def test_named_routing_policies_are_accepted_without_reclassifying_reject(self):
        self.assertEqual(
            parse("HOST-SUFFIX,cdn.example.com,JSDELIVR", purpose="proxy")[0],
            [Rule("DOMAIN-SUFFIX", "cdn.example.com", domain_source="qx")],
        )
        self.assertEqual(
            parse("HOST-SUFFIX,cn.example.com,China", purpose="direct")[0],
            [Rule("DOMAIN-SUFFIX", "cn.example.com", domain_source="qx")],
        )
        self.assertEqual(parse("HOST-SUFFIX,cdn.example.com,REJECT", purpose="proxy")[0], [])
        self.assertEqual(parse("HOST-SUFFIX,cn.example.com,DIRECT", purpose="block")[0], [])

    def test_named_filter_policies_remain_block_only(self):
        for policy in ("AdGuardSDNSFilter", "AdvertisingMiTV", "BlockHttpDNS", "EasyPrivacy"):
            with self.subTest(policy=policy):
                source = f"HOST-SUFFIX,ads.example.com,{policy}"
                self.assertEqual(parse(source, purpose="block")[0], [Rule("DOMAIN-SUFFIX", "ads.example.com", domain_source="qx")])
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
        self.assertEqual(rules, [Rule("DOMAIN-KEYWORD", "trackads", domain_source="qx")])
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

    def test_mihomo_ipv6_ip_cidr_alias_preserves_family_and_options(self):
        parsed, messages = parse(
            "IP-CIDR,2001:db8::1/32,PROXY,no-resolve\nIP-CIDR6,192.0.2.0/24,PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("IP-CIDR", "2001:db8::/32", ("no-resolve",))])
        self.assertEqual(len(messages), 1)

    def test_ipv4_ipv6_source_and_destination_cidr_keep_direction_and_valid_options(self):
        rules, warnings = parse(
            "SRC-IP-CIDR,2001:db8::1/32,DIRECT,no-resolve\n"
            "IP-CIDR,192.0.2.15/24,DIRECT,no-resolve\n"
            "IP6-CIDR,2001:db8:1::/48,PROXY",
            purpose="direct",
        )
        self.assertEqual(rules, [
            Rule("SRC-IP-CIDR", "2001:db8::/32"),
            Rule("IP-CIDR", "192.0.2.0/24", ("no-resolve",)),
        ])
        self.assertEqual(warnings[0], "line 1: unsupported no-resolve for SRC-IP-CIDR")
        self.assertEqual(len(warnings), 2)
        proxy, _ = parse("IP6-CIDR,2001:db8:1::/48,PROXY", purpose="proxy")
        self.assertEqual(proxy, [Rule("IP-CIDR6", "2001:db8:1::/48")])

    def test_uppercase_src_policy_keeps_destination_address_in_six_outputs(self):
        from formats import render

        parsed, messages = parse("IP-CIDR,192.0.2.0/24,SRC", purpose="proxy")
        self.assertEqual((parsed, messages), ([Rule("IP-CIDR", "192.0.2.0/24")], []))
        output, skipped = render("group", parsed, purpose="proxy", no_resolve="strip")
        for name in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-surge.txt"):
            self.assertIn("IP-CIDR,192.0.2.0/24", output[name])
            self.assertNotIn("SRC-IP", output[name])
        self.assertEqual(skipped["fin-adb.txt:IP-CIDR"], 1)
        self.assertEqual(skipped["fin-surge-ds.txt:IP-CIDR"], 1)

    def test_uppercase_src_after_policy_is_not_a_source_option(self):
        parsed, messages = parse("IP-CIDR,192.0.2.0/24,PROXY,SRC", purpose="proxy")
        self.assertEqual(parsed, [Rule("IP-CIDR", "192.0.2.0/24")])
        self.assertEqual(messages, ["line 1: unsupported src option SRC"])

    def test_bare_lowercase_src_policy_or_option_is_ambiguous(self):
        self.assertEqual(parse("IP-CIDR,192.0.2.0/24,src", purpose="proxy"),
                         ([], ["line 1: ambiguous src policy or option"]))

    def test_logical_uppercase_src_does_not_reverse_ip_direction(self):
        expression = "((IP-CIDR,192.0.2.0/24,SRC),(DOMAIN,x.example.com))"
        normalized = "((IP-CIDR,192.0.2.0/24),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                         ([Rule("AND", normalized)], []))

    def test_mihomo_src_option_preserves_source_ip_matchers(self):
        parsed, messages = parse(
            "IP-CIDR,192.0.2.15/24,China,src\n"
            "IP-CIDR,192.0.2.0/24,PROXY,src\n"
            "IP-CIDR6,2001:db8::1/32,PROXY,src\n"
            "IP-SUFFIX,8.8.8.8/24,PROXY,src\n"
            "GEOIP,CN,PROXY,src\nIP-ASN,64512,PROXY,src",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
            Rule("SRC-IP-CIDR", "2001:db8::/32"),
            Rule("SRC-IP-SUFFIX", "8.8.8.8/24"),
            Rule("SRC-GEOIP", "CN"), Rule("SRC-IP-ASN", "64512"),
        ])
        self.assertEqual(messages, [])

    def test_source_ip_with_irrelevant_no_resolve_is_kept(self):
        parsed, messages = parse(
            "IP-SUFFIX,8.8.8.8/24,PROXY,src,no-resolve\n"
            "GEOIP,CN,PROXY,src,no-resolve",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("SRC-IP-SUFFIX", "8.8.8.8/24"), Rule("SRC-GEOIP", "CN")])
        self.assertEqual(messages, [
            "line 1: unsupported no-resolve for SRC-IP-SUFFIX",
            "line 2: unsupported no-resolve for SRC-GEOIP",
        ])

    def test_ip_cidr6_src_does_not_accept_ipv4(self):
        parsed, messages = parse("IP-CIDR6,192.0.2.0/24,PROXY,src", purpose="proxy")
        self.assertEqual(parsed, [])
        self.assertEqual(messages, ["line 1: invalid CIDR 192.0.2.0/24"])

    def test_mihomo_ip_suffix_keeps_no_resolve(self):
        parsed, messages = parse("IP-SUFFIX,8.8.8.8/24,PROXY,no-resolve", purpose="proxy")
        self.assertEqual(parsed, [Rule("IP-SUFFIX", "8.8.8.8/24", ("no-resolve",))])
        self.assertEqual(messages, [])

    def test_source_ip_no_resolve_is_discarded_without_losing_source_match(self):
        from formats import render

        parsed, messages = parse(
            "SRC-IP-CIDR,192.0.2.15/24,PROXY,no-resolve\n"
            "SRC-IP,2001:db8::1,PROXY,no-resolve\n"
            "IP-CIDR,198.51.100.0/24,PROXY,no-resolve", purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("SRC-IP-CIDR", "192.0.2.0/24"), Rule("SRC-IP", "2001:db8::1"),
            Rule("IP-CIDR", "198.51.100.0/24", ("no-resolve",)),
        ])
        self.assertEqual(messages, [
            "line 1: unsupported no-resolve for SRC-IP-CIDR",
            "line 2: unsupported no-resolve for SRC-IP",
        ])
        output, _ = render("group", parsed, purpose="proxy", no_resolve="keep")
        self.assertIn("SRC-IP,192.0.2.0/24\n", output["fin.txt"])
        self.assertIn("SRC-IP,2001:db8::1\n", output["fin-surge.txt"])
        self.assertIn('  - "SRC-IP-CIDR,192.0.2.0/24"\n', output["fin.yaml"])
        self.assertIn('  - "SRC-IP-CIDR,2001:db8::1/128"\n', output["fin.yaml"])
        self.assertNotIn("IP-CIDR,192.0.2.0/24", output["fin.txt"])
        self.assertIn("IP-CIDR,198.51.100.0/24,no-resolve\n", output["fin.txt"])

    def test_surge_src_ip_network_uses_source_cidr_for_other_targets(self):
        parsed, messages = parse(
            "SRC-IP,192.0.2.15/24,DIRECT\nSRC-IP,2001:db8::1/32,DIRECT\n"
            "SRC-IP,192.0.2.15,DIRECT\nSRC-IP,invalid/24,DIRECT",
            purpose="direct",
        )
        self.assertEqual(parsed, [
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
            Rule("SRC-IP-CIDR", "2001:db8::/32"), Rule("SRC-IP", "192.0.2.15"),
        ])
        self.assertEqual(len(messages), 1)
        from formats import render

        output, _ = render("group", parsed, purpose="direct", no_resolve="strip")
        self.assertIn("SRC-IP,192.0.2.0/24\n", output["fin.txt"])
        self.assertIn('"SRC-IP-CIDR,192.0.2.0/24"', output["fin.yaml"])

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

    def test_port_comparison_is_retained_as_equivalent_closed_range(self):
        parsed, messages = parse(
            "SRC-PORT,>=50000,PROXY\nDEST-PORT,<1024,PROXY\n"
            "IN-PORT,>65535,PROXY\nDST-PORT,<=0,PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("SRC-PORT", "50000-65535"), Rule("DEST-PORT", "1-1023"),
        ])
        self.assertEqual(len(messages), 2)

    def test_multi_port_segments_are_renderable_by_both_rule_engines(self):
        parsed, messages = parse(
            "DEST-PORT,80/443-445,PROXY\nDST-PORT,53,853,PROXY\n"
            "IN-PORT,80/70000,PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("OR", "((DST-PORT,80),(DST-PORT,443-445))"),
            Rule("OR", "((DST-PORT,53),(DST-PORT,853))"),
        ])
        self.assertEqual(len(messages), 1)
        from formats import render

        output, _ = render("group", parsed, purpose="proxy", no_resolve="strip")
        self.assertIn("OR,((DEST-PORT,80),(DEST-PORT,443-445))\n", output["fin.txt"])
        self.assertIn('"OR,((DST-PORT,80),(DST-PORT,443-445))"', output["fin.yaml"])

    def test_long_numeric_fields_are_skipped_without_aborting_other_rules(self):
        huge = '9' * 4400
        parsed, messages = parse(
            f"IP-ASN,{huge},PROXY\nSRC-PORT,{huge},PROXY\n"
            "DOMAIN,valid.example.com,PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("DOMAIN", "valid.example.com")])
        self.assertEqual(len(messages), 2)
        self.assertTrue(any("IP-ASN" in message for message in messages))
        self.assertTrue(any("port" in message for message in messages))

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

    def test_yaml_process_name_is_literal_but_surge_process_name_is_glob(self):
        literal, yaml_warnings = parse('payload:\n  - "PROCESS-NAME,Foo*Bar"\n', purpose="proxy")
        glob, surge_warnings = parse("PROCESS-NAME,Foo*Bar,PROXY", purpose="proxy")
        self.assertEqual(yaml_warnings, [])
        self.assertEqual(surge_warnings, [])
        self.assertEqual(literal, [Rule("PROCESS-NAME", "Foo*Bar", literal_process=True)])
        self.assertEqual(glob, [Rule("PROCESS-NAME", "Foo*Bar")])
        self.assertNotEqual(literal, glob)

    def test_yaml_logical_process_child_is_literal(self):
        rules, warnings = parse(
            'payload:\n  - "AND,((PROCESS-NAME,Foo*Bar),(DOMAIN,a.example.com))"\n',
            purpose="proxy",
        )
        self.assertEqual(warnings, [])
        self.assertEqual(rules, [Rule(
            "AND", "((PROCESS-NAME,Foo*Bar),(DOMAIN,a.example.com))", literal_process=True, native_fields=True,
        )])

    def test_process_source_intent_survives_normalize(self):
        literal, _ = parse('payload:\n  - "PROCESS-NAME,Foo*Bar"\n', purpose="proxy")
        glob, _ = parse("PROCESS-NAME,Foo*Bar,PROXY", purpose="proxy")
        self.assertEqual(normalize(literal + glob), [
            Rule("PROCESS-NAME", "Foo*Bar"),
            Rule("PROCESS-NAME", "Foo*Bar", literal_process=True),
        ])
        self.assertEqual(normalize(glob + literal), normalize(literal + glob))

    def test_qx_interface_options_do_not_replace_the_policy(self):
        for option in ("force-cellular", "multi-interface", "via-interface=pdp_ip0"):
            with self.subTest(option=option):
                rules, warnings = parse(
                    f"HOST-SUFFIX,googleapis.com,PROXY,{option}", purpose="proxy",
                )
                self.assertEqual(warnings, [])
                self.assertEqual(rules, [Rule("DOMAIN-SUFFIX", "googleapis.com", (option,), domain_source="qx")])

    def test_qx_multi_interface_balance_keeps_matcher_and_option(self):
        parsed, messages = parse(
            "HOST-SUFFIX,googleapis.com,PROXY,multi-interface-balance", purpose="proxy",
        )
        self.assertEqual(parsed, [Rule(
            "DOMAIN-SUFFIX", "googleapis.com", ("multi-interface-balance",), domain_source="qx"
        )])
        self.assertEqual(messages, [])

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

    def test_mihomo_additional_geo_and_ip_types_validate_values(self):
        source = (
            "GEOSITE,youtube,PROXY\nSRC-GEOIP,CN,PROXY\nSRC-IP-ASN,9808,PROXY\n"
            "IP-SUFFIX,8.8.8.8/24,PROXY\nSRC-IP-SUFFIX,192.0.2.1/8,PROXY\n"
            "SRC-GEOIP,UNKNOWN,PROXY\nSRC-IP-ASN,-1,PROXY\n"
            "IP-SUFFIX,invalid/24,PROXY\nSRC-IP-SUFFIX,192.0.2.1/129,PROXY"
        )
        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(parsed, [
            Rule("GEOSITE", "youtube"), Rule("SRC-GEOIP", "CN"),
            Rule("SRC-IP-ASN", "9808"), Rule("IP-SUFFIX", "8.8.8.8/24"),
            Rule("SRC-IP-SUFFIX", "192.0.2.1/8"),
        ])
        self.assertEqual(len(messages), 4)

    def test_mihomo_literal_closing_bracket_is_not_a_field_delimiter(self):
        parsed, messages = parse(
            'payload:\n  - "PROCESS-NAME,Foo]Bar"\n'
            '  - "PROCESS-NAME-REGEX,^foo[]]bar$"\n', purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("PROCESS-NAME", "Foo]Bar", literal_process=True),
            Rule("PROCESS-NAME-REGEX", "^foo[]]bar$"),
        ])
        self.assertEqual(messages, [])

    def test_mihomo_process_and_inbound_types_validate_values(self):
        parsed, messages = parse(
            "IN-USER,alice/bob,PROXY\nIN-NAME,home-socks,PROXY\n"
            "REMATCH-NAME,rematch1,PROXY\nPROCESS-PATH-REGEX,.*bin/wget,PROXY\n"
            "PROCESS-NAME-REGEX,curl$,PROXY\nUID,1001,PROXY\nDSCP,63,PROXY\n"
            "IN-USER,alice//bob,PROXY\nPROCESS-NAME-REGEX,(*,PROXY\n"
            "UID,-1,PROXY\nDSCP,64,PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("IN-USER", "alice/bob"), Rule("IN-NAME", "home-socks"),
            Rule("REMATCH-NAME", "rematch1"), Rule("PROCESS-PATH-REGEX", ".*bin/wget"),
            Rule("PROCESS-NAME-REGEX", "curl$"), Rule("UID", "1001"), Rule("DSCP", "63"),
        ])
        self.assertEqual(len(messages), 4)

    def test_surge_protocol_accepts_documented_values_only(self):
        parsed, messages = parse(
            "PROTOCOL,HTTPS,DIRECT\nPROTOCOL,MTProto,DIRECT\n"
            "PROTOCOL,INVALID,DIRECT",
            purpose="direct",
        )
        self.assertEqual(parsed, [Rule("PROTOCOL", "HTTPS"), Rule("PROTOCOL", "MTProto")])
        self.assertEqual(len(messages), 1)

    def test_surge_device_network_types_validate_values(self):
        parsed, messages = parse(
            "DEVICE-NAME,Kids-*,DIRECT\nMAC-ADDRESS,A4:83:E7:11:22:33,DIRECT\n"
            "HOSTNAME-TYPE,IPv6,DIRECT\nSUBNET,TYPE:CELLULAR,DIRECT\n"
            "CELLULAR-RADIO,NR,DIRECT\nCELLULAR-CARRIER,310260,DIRECT\n"
            "DEVICE-NAME,,DIRECT\nMAC-ADDRESS,invalid,DIRECT\n"
            "HOSTNAME-TYPE,unknown,DIRECT\nSUBNET,TYPE:INVALID,DIRECT\n"
            "CELLULAR-RADIO,6G,DIRECT\nCELLULAR-CARRIER,Carrier,DIRECT",
            purpose="direct",
        )
        self.assertEqual(parsed, [
            Rule("DEVICE-NAME", "Kids-*"), Rule("MAC-ADDRESS", "A4:83:E7:11:22:33"),
            Rule("HOSTNAME-TYPE", "IPv6"), Rule("SUBNET", "TYPE:CELLULAR"),
            Rule("CELLULAR-RADIO", "NR"), Rule("CELLULAR-CARRIER", "310260"),
        ])
        self.assertEqual(len(messages), 6)

    def test_mihomo_in_type_accepts_documented_combined_inbound(self):
        parsed, messages = parse("IN-TYPE,SOCKS/HTTP,PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("IN-TYPE", "SOCKS/HTTP")])
        self.assertEqual(messages, [])

    def test_domain_regex_quantifier_comma_stays_in_value(self):
        rules, warnings = parse(
            r"DOMAIN-REGEX,^ad{2,3}\.example\.com$,REJECT", purpose="block"
        )
        self.assertEqual(rules, [Rule("DOMAIN-REGEX", r"^ad{2,3}\.example\.com$")])
        self.assertEqual(warnings, [])

    def test_unquoted_process_regex_literal_brace_after_apostrophe_round_trips_yaml(self):
        from formats import render

        value = "^Game,'foo{bar'$"
        parsed, messages = parse(f"PROCESS-NAME-REGEX,{value},DIRECT", purpose="direct")
        self.assertEqual(parsed, [Rule("PROCESS-NAME-REGEX", value)])
        self.assertEqual(messages, [])
        yaml = render("a3", parsed, purpose="direct", no_resolve="keep")[0]["fin.yaml"]
        self.assertIn('  - "PROCESS-NAME-REGEX,^Game,\'foo{bar\'$"\n', yaml)
        self.assertEqual(parse(yaml, purpose="direct"), ([Rule("PROCESS-NAME-REGEX", value)], []))

    def test_unquoted_regex_literal_brace_preceding_numeric_quantifier(self):
        value = "^Game,'foo{bar{1,2}'$"
        self.assertEqual(parse(f"PROCESS-NAME-REGEX,{value},DIRECT", purpose="direct"),
                         ([Rule("PROCESS-NAME-REGEX", value)], []))

    def test_regexp2_literal_brace_pair_holds_its_comma(self):
        value = r"^a{b,c}\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{_quote_matcher(value)},China", purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", value)], []))
        self.assertEqual(parse(r"DOMAIN-REGEX,^a{1,2}\.example\.com$,REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", r"^a{1,2}\.example\.com$")], []))

    def test_regexp2_escaped_nested_and_hidden_braces_keep_commas_in_matcher(self):
        values = [r"^a\{b,c\}$", "^a{b{c,d}e,f}$", "^a{b[}]c,d}$",
                  "^a{b,(?#})c,d}$"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(parse(f"DOMAIN-REGEX,{_quote_matcher(value)},China", purpose="proxy"),
                                 ([Rule("DOMAIN-REGEX", value)], []))
                expression = f"((DOMAIN-REGEX,{value}),(DOMAIN,x.example.com))"
                self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                                 ([Rule("AND", expression)], []))

    def test_regexp2_character_class_first_closing_bracket_protects_comma(self):
        value = "^[]a,b]Game$"
        self.assertEqual(parse(f"PROCESS-NAME-REGEX,{_quote_matcher(value)},China", purpose="proxy"),
                         ([Rule("PROCESS-NAME-REGEX", value)], []))
        expression = f"((PROCESS-NAME-REGEX,{value}),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                         ([Rule("AND", expression)], []))

    def test_literal_process_delimiters_are_not_regex_groups(self):
        for value in ("Game{", "Game(", "Game[", "Game}", "Game)"):
            with self.subTest(value=value):
                self.assertEqual(parse(f"PROCESS-NAME,{value},PROXY", purpose="proxy"),
                                 ([Rule("PROCESS-NAME", value)], []))
        for value in ("Game{", "Game[", "Game}"):
            expression = f"((PROCESS-NAME,{value}),(DOMAIN,x.example.com))"
            self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                             ([Rule("AND", expression)], []))

    def test_unclosed_process_parenthesis_in_logic_is_not_silently_closed(self):
        source = "AND,((PROCESS-NAME,Game(),(DOMAIN,x.example.com)),PROXY"
        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(parsed, [])
        self.assertEqual(len(messages), 1)
        self.assertTrue(messages[0].startswith("line 1:"), messages)

    def test_extended_regex_line_comment_does_not_swallow_logical_siblings(self):
        child = "(DOMAIN-REGEX,^(?x)a # [)"
        for operator in ("AND", "OR"):
            expression = f"({child},(DOMAIN,x.example.com))"
            with self.subTest(operator=operator):
                self.assertEqual(parse(f"{operator},{expression},PROXY", purpose="proxy"),
                                 ([Rule(operator, expression)], []))
        nested = f"((OR,({child},(DOMAIN,x.example.com))),(IP-CIDR,192.0.2.0/24,no-resolve))"
        self.assertEqual(parse(f"AND,{nested},PROXY", purpose="proxy"),
                         ([Rule("AND", nested)], []))

    def test_scoped_extended_flag_and_comment_group_preserve_real_boundaries(self):
        values = ["^(?x:a[ # ])b$", "^(?x:a)(?-x:b#c)$",
                  "^(?x)a (?#note[) b$"]
        for value in values:
            expression = f"((DOMAIN-REGEX,{value}),(IP-CIDR,192.0.2.0/24,no-resolve))"
            with self.subTest(value=value):
                self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                                 ([Rule("AND", expression)], []))

    def test_unbounded_unquoted_regex_comma_remains_ambiguous(self):
        self.assertEqual(parse("DOMAIN-REGEX,^foo,China", purpose="proxy"),
                         ([], ["line 1: ambiguous unquoted regex comma or policy"]))

    def test_unpaired_regex_braces_do_not_stall_field_scanner(self):
        code = ("from rules import parse\n"
                "value = '^' + '{' * 20000 + '$'\n"
                "parsed, warnings = parse('DOMAIN-REGEX,' + value + ',REJECT', purpose='block')\n"
                "assert len(parsed) == 1 and parsed[0].value == value and warnings == []")
        try:
            result = subprocess.run(
                [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                capture_output=True, text=True, timeout=2,
            )
        except subprocess.TimeoutExpired:
            self.fail("重复的未配对字面花括号使字段扫描超时")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_regexp2_literal_brace_in_logical_child_is_not_a_group(self):
        expression = "((PROCESS-NAME-REGEX,^Game{bar$),(DOMAIN,a.example.com))"
        self.assertEqual(parse(f"AND,{expression},DIRECT", purpose="direct"),
                         ([Rule("AND", expression)], []))

    def test_logical_regex_braces_do_not_swallow_ip_no_resolve(self):
        expression = (r"((DOMAIN-REGEX,^a{b,c}\.example\.com$),"
                      "(IP-CIDR,192.0.2.0/24,no-resolve))")
        self.assertEqual(parse(f"AND,{expression},PROXY", purpose="proxy"),
                         ([Rule("AND", expression)], []))

    def test_regexp2_conditional_control_and_balance_groups_survive_python_probe(self):
        cases = [
            ("DOMAIN-REGEX", r"^(?(?=a)a|b)ds[.]example[.]com$", "block", "REJECT"),
            ("PROCESS-NAME-REGEX", r"^\e[a]$", "direct", "DIRECT"),
            ("DOMAIN-REGEX", r"^\cA?ds", "block", "REJECT"),
            ("DOMAIN-REGEX", r"^(a)\k<1>$", "block", "REJECT"),
            ("DOMAIN-REGEX", r"^(?<grp>a)(?<-grp>b)$", "block", "REJECT"),
        ]
        for kind, value, purpose, action in cases:
            with self.subTest(value=value):
                self.assertEqual(parse(f"{kind},{value},{action}", purpose=purpose),
                                 ([Rule(kind, value)], []))

    def test_regexp2_nearby_invalid_conditional_escapes_and_groups_stay_rejected(self):
        cases = [
            ("DOMAIN-REGEX", r"^(?(?=a)a|bds[.]example[.]com$", "block", "REJECT"),
            ("DOMAIN-REGEX", r"^(?(?=a)a|b|c)$", "block", "REJECT"),
            ("PROCESS-NAME-REGEX", r"^\q[a]$", "direct", "DIRECT"),
            ("DOMAIN-REGEX", r"^\c!?ds", "block", "REJECT"),
            ("DOMAIN-REGEX", r"^(a)\k<2>$", "block", "REJECT"),
            ("DOMAIN-REGEX", r"^(?<-grp>a)$", "block", "REJECT"),
        ]
        for kind, value, purpose, action in cases:
            source = f"{kind},{value},{action}\nDOMAIN,x.example.com,{action}"
            with self.subTest(value=value):
                parsed, messages = parse(source, purpose=purpose)
                self.assertEqual(parsed, [Rule("DOMAIN", "x.example.com")])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith("line 1:"), messages)

    def test_oversized_numeric_backreference_warns_without_crashing(self):
        code = ("from rules import Rule, parse\n"
                "value = r'^(a)\\k<' + '9' * 5000 + '>$'\n"
                "source = f'DOMAIN-REGEX,{value},REJECT\\nDOMAIN,x.example.com,REJECT'\n"
                "parsed, messages = parse(source, purpose='block')\n"
                "assert parsed == [Rule('DOMAIN', 'x.example.com')] and "
                "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)")
        try:
            result = subprocess.run(
                [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                capture_output=True, text=True, timeout=4,
            )
        except subprocess.TimeoutExpired:
            self.fail("过长数值引用让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1200:])

    def test_mihomo_regexp2_named_group_end_anchor_and_backref_survive(self):
        values = [r"^(?<name>ads)\.example\.com$", r"^ads\.example\.com\z",
                  r"^(?<name>ads)\k<name>\.example\.com$", r"^(ads)\1\.example\.com$"]
        parsed, messages = parse("\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values),
                                 purpose="block")
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_process_regex_uses_the_same_validation(self):
        value = r"^(?<name>ads)\k<name>\z"
        parsed, messages = parse(f"PROCESS-NAME-REGEX,{value},PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("PROCESS-NAME-REGEX", value)])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_unicode_hex_anchor_and_variable_lookbehind_survive(self):
        values = [r"^\p{L}+\.example\.com$", r"^\x{61}ds\.example\.com$",
                  r"^\Gads\.example\.com$", r"^a+(?<=a+)ds\.example\.com$"]
        parsed, messages = parse("\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values),
                                 purpose="block")
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_unclosed_regexp2_hex_escape_terminates_and_reports_line(self):
        source = (r"PROCESS-NAME-REGEX,\x{41,PROXY" "\n"
                  "DOMAIN,x.example.com,PROXY")
        expected = ([Rule("DOMAIN", "x.example.com")],
                    [r"line 1: invalid PROCESS-NAME-REGEX \x{41"])
        code = ("from rules import Rule, parse\n"
                f"assert parse({source!r}, purpose='proxy') == {expected!r}")
        try:
            result = subprocess.run(
                [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                capture_output=True, text=True, timeout=2,
            )
        except subprocess.TimeoutExpired:
            self.fail("未闭合 hex 转义使解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deep_regexp2_balanced_groups_keep_following_rule(self):
        code = ("from rules import Rule, parse\n"
                "value = '^' + '(' * 495 + 'a' + ')' * 495 + '$'\n"
                "source = f'DOMAIN-REGEX,{value},REJECT\\nDOMAIN,x.example.com,REJECT'\n"
                "assert parse(source, purpose='block') == "
                "([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'x.example.com')], [])")
        try:
            result = subprocess.run(
                [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                capture_output=True, text=True, timeout=4,
            )
        except subprocess.TimeoutExpired:
            self.fail("深层正则让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1200:])

    def test_deep_regexp2_extra_or_missing_closer_is_rejected_without_crash(self):
        for extra in (1, -1):
            code = ("from rules import Rule, parse\n"
                    f"value = '^' + '(' * 495 + 'a' + ')' * (495 + {extra}) + '$'\n"
                    "source = f'DOMAIN-REGEX,{value},REJECT\\nDOMAIN,x.example.com,REJECT'\n"
                    "parsed, messages = parse(source, purpose='block')\n"
                    "assert parsed == [Rule('DOMAIN', 'x.example.com')] and "
                    "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)")
            with self.subTest(extra=extra):
                try:
                    result = subprocess.run(
                        [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                        capture_output=True, text=True, timeout=4,
                    )
                except subprocess.TimeoutExpired:
                    self.fail("非法深层正则让解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1200:])

    def test_regexp2_huge_quantifier_is_rejected_without_losing_next_rule(self):
        value = r"^a{999999999999999999999999}\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT\nDOMAIN,valid.example.com,REJECT",
                               purpose="block"),
                         ([Rule("DOMAIN", "valid.example.com")],
                          [f"line 1: invalid DOMAIN-REGEX {value}"]))

    def test_mihomo_hex_escape_rejects_reversed_character_range(self):
        value = r"^[a-\x{21}]\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block"),
                         ([], [f"line 1: invalid DOMAIN-REGEX {value}"]))

    def test_mihomo_hex_escape_accepts_ascending_character_range(self):
        value = r"^[\x{21}-A]\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", value)], []))

    def test_mihomo_process_regex_treats_python_group_text_in_class_as_literal(self):
        value = r"^[(?P]$"
        parsed, messages = parse(f"PROCESS-NAME-REGEX,{value},PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("PROCESS-NAME-REGEX", value)])
        self.assertEqual(messages, [])

    def test_python_only_unicode_name_and_regexp2_unsupported_quote_escape_are_rejected(self):
        parsed, messages = parse(
            r"DOMAIN-REGEX,^\N{LATIN SMALL LETTER A}ds\.example\.com$,REJECT" "\n"
            r"DOMAIN-REGEX,^\Qads.example.com\E$,REJECT", purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(len(messages), 2)
        self.assertTrue(all("invalid DOMAIN-REGEX" in message for message in messages))

    def test_malformed_regexp2_group_and_python_only_named_group_are_rejected(self):
        parsed, messages = parse(
            "DOMAIN-REGEX,^(?<name>*ads),REJECT\n"
            "DOMAIN-REGEX,^(?P<name>ads),REJECT\n"
            "DOMAIN-REGEX,^(?<name>ads)(?P=name),REJECT\n"
            "DOMAIN-REGEX,*ads,REJECT", purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(len(messages), 4)
        self.assertTrue(all(f"line {number}:" in message for number, message in enumerate(messages, 1)))

    def test_process_regex_doctype_text_does_not_reject_entire_source(self):
        self.assertEqual(parse(
            "PROCESS-NAME-REGEX,^<!doctype$,PROXY\nDOMAIN,x.example.com,PROXY",
            purpose="proxy",
        ), ([Rule("PROCESS-NAME-REGEX", "^<!doctype$"),
             Rule("DOMAIN", "x.example.com")], []))

    def test_html_login_document_is_not_mistaken_for_regexp2(self):
        parsed, messages = parse("<html><body>login</body></html>", purpose="block")
        self.assertEqual(parsed, [])
        self.assertTrue(any("HTML document" in message for message in messages))

    def test_mihomo_regexp2_properties_and_named_forms_survive(self):
        values = [
            r"^\p{N}+\.example\.com$", r"^\p{Nd}+\.example\.com$",
            r"^\p{Han}+\.example\.com$", r"^(?'n'ads)\.example\.com$",
            r"^(?<n>ad)(?<n>s)\.example\.com$", r"^(?n:ads)\.example\.com$",
        ]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_unicode_property_names_and_group_syntax(self):
        values = [
            r"^\p{Lu}+\.example\.com$", r"^\p{Ll}+\.example\.com$",
            r"^\p{Greek}+\.example\.com$", r"^\p{Hiragana}+\.example\.com$",
            r"^\p{Other_Alphabetic}+\.example\.com$",
            r"^(?i)ads\.example\.com$", r"^(?'n'ads)\k'n'\.example\.com$",
        ]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_rejects_invalid_properties_and_possessive_quantifiers(self):
        values = [r"^\p{Nonexistent}+\.example\.com$", r"^(?P<name>ads)$",
                  r"^a++\.example\.com$", r"^a*+\.example\.com$",
                  r"^a?+\.example\.com$", r"^a{2,3}+\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line {number}: invalid DOMAIN-REGEX {value}"
                                    for number, value in enumerate(values, 1)])
        parsed, messages = parse("DOMAIN-REGEX,^ads" + chr(92), purpose="block")
        self.assertEqual(parsed, [])
        self.assertEqual(messages, ["line 1: invalid DOMAIN-REGEX ^ads" + chr(92)])
        valid = [r"^a\+\.example\.com$", r"^[a+]\.example\.com$",
                 r"^a[+]+\.example\.com$", r"^a+?\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in valid), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in valid])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_rejects_literal_to_class_character_ranges(self):
        values = [r"^[a-\p{Lu}]\.example\.com$", r"^[a-\P{Lu}]\.example\.com$",
                  r"^[\x{61}-\p{Lu}]\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line {number}: invalid DOMAIN-REGEX {value}"
                                    for number, value in enumerate(values, 1)])

    def test_mihomo_regexp2_hyphen_position_and_class_range_endpoints(self):
        invalid = [r"^[--\d]\.example\.com$", r"^[\p{Lu}--\p{Ll}]\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in invalid), purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line {number}: invalid DOMAIN-REGEX {value}"
                                    for number, value in enumerate(invalid, 1)])
        values = [r"^[-\d]\.example\.com$", r"^[\--\p{Lu}]\.example\.com$",
                  r"^[-\p{Lu}]\.example\.com$", r"^[a\-\p{Lu}]\.example\.com$",
                  r"^[\p{Lu}-\p{Ll}]\.example\.com$", r"^[\p{Lu}--a]\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_mihomo_escaped_hyphen_does_not_consume_pending_range(self):
        invalid = [r"^[--\-\p{Lu}]\.example\.com$", r"^[\---\d]\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in invalid), purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line {number}: invalid DOMAIN-REGEX {value}"
                                    for number, value in enumerate(invalid, 1)])

    def test_mihomo_escaped_hyphen_after_range_start_is_not_range_endpoint(self):
        valid = [r"^[\p{Lu}a-\-]\.example\.com$", r"^[\da-\-]\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in valid), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in valid])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_keeps_class_to_class_and_literal_hyphens(self):
        values = [r"^[\p{Lu}-a]\.example\.com$", r"^[-\p{Lu}]\.example\.com$",
                  r"^[a\-\p{Lu}]\.example\.com$", r"^[\p{Lu}-\p{Ll}]\.example\.com$",
                  r"^[\d-\p{Lu}]\.example\.com$", r"^[\p{Lu}-\d]\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_rejects_quantified_inline_flags(self):
        values = [r"^(?i)+a\.example\.com$", r"^(?m)+a\.example\.com$",
                  r"^(?s)+a\.example\.com$", r"^a(?i){2}\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line {number}: invalid DOMAIN-REGEX {value}"
                                    for number, value in enumerate(values, 1)])

    def test_mihomo_regexp2_keeps_inline_and_scoped_flags_with_repeatable_atoms(self):
        values = [r"^(?i)a+\.example\.com$", r"^(?i:a)+\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in values])
        self.assertEqual(messages, [])

    def test_mihomo_regexp2_extended_mode_and_disabled_inline_flags(self):
        invalid = r"^(?x) +a\.example\.com$"
        parsed, messages = parse(f"DOMAIN-REGEX,{invalid},REJECT", purpose="block")
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line 1: invalid DOMAIN-REGEX {invalid}"])
        valid = [r"^(?x) a+\.example\.com$", r"^(?i)A(?-i)b\.example\.com$"]
        parsed, messages = parse(
            "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in valid), purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value) for value in valid])
        self.assertEqual(messages, [])
        path = r"(?-i:\A/Applications/Widget[.]app/)"
        parsed, messages = parse(f"PROCESS-PATH-REGEX,{path},PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("PROCESS-PATH-REGEX", path)])
        self.assertEqual(messages, [])
        expression = f"((PROCESS-PATH-REGEX,{path}),(DOMAIN,x.example.com))"
        parsed, messages = parse(f"AND,{expression},PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("AND", expression)])
        self.assertEqual(messages, [])
        from formats import render

        output, _ = render("a3", [Rule("DOMAIN-REGEX", valid[1])], purpose="block", no_resolve="keep")
        reparsed, messages = parse(output["fin.yaml"], purpose="block")
        self.assertEqual(reparsed, [Rule("DOMAIN-REGEX", valid[1])])
        self.assertEqual(messages, [])
        self.assertNotIn("DOMAIN-REGEX", output["fin-adb.txt"])

    def test_scoped_extended_regex_complete_comment_group_survives(self):
        value = r"^(?x:(?#note)a)\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", value)], []))
        self.assertFalse(rules._valid_regex("DOMAIN-REGEX", r"^(?x:(?#note"))

    def test_regexp2_comment_closes_at_escaped_parenthesis(self):
        for flag in ("x", "-x"):
            invalid = rf"^(?{flag}:(?#note\)oops)a)\.example\.com$"
            valid = rf"^(?{flag}:(?#note)a)\.example\.com$"
            self.assertEqual(parse(f"DOMAIN-REGEX,{invalid},REJECT", purpose="block"),
                             ([], [f"line 1: invalid DOMAIN-REGEX {invalid}"]))
            self.assertEqual(parse(f"DOMAIN-REGEX,{valid},REJECT", purpose="block"),
                             ([Rule("DOMAIN-REGEX", valid)], []))
        class_value = r"^[(?#note\)oops]+\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{class_value},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", class_value)], []))
        self.assertEqual(parse("DOMAIN-REGEX,^(?x:(?#note,REJECT", purpose="block"),
                         ([], ["line 1: unbalanced delimiters"]))
        line_comment = r"^(?x)a+ # ignored +"
        self.assertEqual(parse(f"DOMAIN-REGEX,{_quote_matcher(line_comment)},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", line_comment)], []))

    def test_regexp2_comment_group_ignores_open_bracket(self):
        value = r"^(?x:(?#note[)a)\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", value)], []))

    def test_regexp2_comment_group_closes_at_first_parenthesis_even_after_backslash(self):
        value = r"^(?x:(?#note\)oops)\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", value)], []))

    def test_extended_regex_disabling_x_keeps_literal_hash_and_policy(self):
        value = r"^(?x)foo(?-x) #bar\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{_quote_matcher(value)},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", value)], []))

    def test_extended_regex_scoped_disabled_x_keeps_space_as_quantifier_target(self):
        value = r"^(?x)(?-x: +a)\.example\.com$"
        self.assertEqual(parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block"),
                         ([Rule("DOMAIN-REGEX", value)], []))

    def test_extended_regex_unscoped_hash_comment_and_bare_quantifier(self):
        self.assertTrue(rules._valid_regex("DOMAIN-REGEX", r"^(?x) a+ # ignored +"))
        self.assertFalse(rules._valid_regex("DOMAIN-REGEX", r"^(?x) +a\.example\.com$"))
        self.assertEqual(parse(r"DOMAIN-REGEX,^(?x) a+\.example\.com$,REJECT # note",
                               purpose="block"),
                         ([Rule("DOMAIN-REGEX", r"^(?x) a+\.example\.com$")], []))

    def test_invalid_regexp2_in_logical_child_is_rejected(self):
        expression = r"((DOMAIN-REGEX,^[a-\p{Lu}]\.example\.com$),(DOMAIN,x.example.com))"
        parsed, messages = parse(f"AND,{expression},REJECT", purpose="block")
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [f"line 1: invalid logical expression {expression}"])

    def test_mihomo_regexp2_rejects_python_only_ascii_mode(self):
        parsed, messages = parse(r"DOMAIN-REGEX,^(?a:ads)\.example\.com$,REJECT", purpose="block")
        self.assertEqual(parsed, [])
        self.assertEqual(messages, [r"line 1: invalid DOMAIN-REGEX ^(?a:ads)\.example\.com$"])

    def test_unquoted_regex_comma_with_clear_policy_keeps_complete_matcher(self):
        for source, expected in (
            ("DOMAIN-REGEX,^foo,bar$,PROXY", Rule("DOMAIN-REGEX", "^foo,bar$")),
            ("DOMAIN-REGEX,^foo,bar,PROXY", Rule("DOMAIN-REGEX", "^foo,bar")),
            ("PROCESS-NAME-REGEX,^foo,bar$,PROXY", Rule("PROCESS-NAME-REGEX", "^foo,bar$")),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(parsed, [expected])
                self.assertEqual(messages, [])

    def test_unquoted_policy_free_regex_comma_keeps_complete_matcher(self):
        parsed, messages = parse("DOMAIN-REGEX,^foo,bar$", purpose="proxy")
        self.assertEqual((parsed, messages), ([], ["line 1: ambiguous unquoted regex comma or policy"]))
        self.assertEqual(parse('DOMAIN-REGEX,"^foo,bar$"', purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", "^foo,bar$")], []))

    def test_unquoted_regex_custom_policy_ambiguity_warns_instead_of_widening(self):
        for source in ("DOMAIN-REGEX,^foo,China", "DOMAIN-REGEX,^foo,bar$,China",
                       "PROCESS-NAME-REGEX,^Game,China", "PROCESS-NAME-REGEX,^Game,Inc$,China"):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(parsed, [])
                self.assertEqual(len(messages), 1)
                self.assertIn("ambiguous", messages[0])

    def test_end_anchored_regex_before_custom_policy_is_unambiguous(self):
        for source, matcher in (
            ("DOMAIN-REGEX,^foo$,China", "^foo$"),
            (r"DOMAIN-REGEX,^foo\z,China", r"^foo\z"),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual((parsed, messages), ([], ["line 1: ambiguous unquoted regex comma or policy"]))
                self.assertEqual(parse(f"DOMAIN-REGEX,{_quote_matcher(matcher)},China", purpose="proxy"),
                                 ([Rule("DOMAIN-REGEX", matcher)], []))

    def test_mihomo_regex_with_explicit_proxy_policy_keeps_matcher(self):
        for source, expected in (
            ("DOMAIN-REGEX,^foo,PROXY", Rule("DOMAIN-REGEX", "^foo")),
            ("PROCESS-PATH-REGEX,.*bin/wget,PROXY", Rule("PROCESS-PATH-REGEX", ".*bin/wget")),
            ("PROCESS-NAME-REGEX,^foo,PROXY", Rule("PROCESS-NAME-REGEX", "^foo")),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(parsed, [expected])
                self.assertEqual(messages, [])

    def test_interface_token_on_non_qx_regex_does_not_truncate_matcher(self):
        for source in (
            "DOMAIN-REGEX,^foo,multi-interface",
            "PROCESS-NAME-REGEX,^foo,multi-interface",
            "URL-REGEX,^https://foo,multi-interface",
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(parsed, [])
                self.assertEqual(len(messages), 1)
                self.assertIn("ambiguous", messages[0])

    def test_end_anchored_non_qx_regex_interface_token_warns_instead_of_truncating(self):
        for source in (
            r"DOMAIN-REGEX,^a\.example\.com$|^b\.example\.com$,multi-interface",
            "URL-REGEX,^https://foo$,multi-interface",
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(parsed, [])
                self.assertEqual(messages, ["line 1: ambiguous unquoted regex comma or policy"])

    def test_quoted_regex_comma_keeps_complete_matcher(self):
        parsed, messages = parse('DOMAIN-REGEX,"^foo,bar$",PROXY', purpose="proxy")
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", "^foo,bar$")])
        self.assertEqual(messages, [])

    def test_literal_angle_tag_in_regex_is_not_html_but_real_html_is_rejected(self):
        regex, messages = parse("PROCESS-NAME-REGEX,^foo<bar>$,PROXY", purpose="proxy")
        self.assertEqual(regex, [Rule("PROCESS-NAME-REGEX", "^foo<bar>$")])
        self.assertEqual(messages, [])
        document, messages = parse(
            "\\k<html>\nDOMAIN,inside.example.com,REJECT\n</html>", purpose="block",
        )
        self.assertEqual(document, [])
        self.assertEqual(messages, ["line 1: HTML document"])

    def test_literal_html_tag_in_process_regex_is_not_a_document(self):
        parsed, messages = parse("PROCESS-NAME-REGEX,^foo<html>$,PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("PROCESS-NAME-REGEX", "^foo<html>$")])
        self.assertEqual(messages, [])

    def test_invalid_domain_regex_is_skipped_before_normalization(self):
        rules, messages = parse(
            "DOMAIN-REGEX,*ads,REJECT\nDOMAIN,valid.example.com,REJECT", purpose="block",
        )
        self.assertEqual(rules, [Rule("DOMAIN", "valid.example.com")])
        self.assertTrue(any("line 1" in message and "invalid" in message for message in messages))
        self.assertEqual(normalize(rules), rules)

    def test_logical_regex_child_rejects_no_resolve_after_end_anchor(self):
        expression = "((DOMAIN-REGEX,^ads$,no-resolve),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{expression},REJECT", purpose="block"),
                         ([], [f"line 1: invalid logical expression {expression}"]))

    def test_logical_process_regex_literal_comma_is_preserved(self):
        expression = "((PROCESS-NAME-REGEX,^Game,Inc$),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{expression},DIRECT", purpose="direct"),
                         ([Rule("AND", expression)], []))

    def test_logical_process_regex_literal_comma_with_invalid_class_is_rejected(self):
        expression = "((PROCESS-NAME-REGEX,^[Game,Inc$),(DOMAIN,x.example.com))"
        parsed, messages = parse(f"AND,{expression},DIRECT", purpose="direct")
        self.assertEqual(parsed, [])
        self.assertTrue(messages and any("invalid" in message or "unbalanced" in message
                                         for message in messages))

    def test_logical_regex_character_class_parenthesis_survives_parse(self):
        expression = r"((DOMAIN-REGEX,^[a)b]\.example$),(DOMAIN,ads.example))"
        rules, warnings = parse(f"AND,{expression},REJECT", purpose="block")
        self.assertEqual(rules, [Rule("AND", expression)])
        self.assertEqual(warnings, [])

    def test_logical_process_markers_survive_quantifier_comma_and_comments(self):
        expressions = [
            "((PROCESS-NAME-REGEX,^Game{1,2} #1$),(DOMAIN,x.example.com))",
            "((PROCESS-NAME,Game ;1),(DOMAIN,x.example.com))",
            "((PROCESS-NAME,Game //1),(DOMAIN,x.example.com))",
            "((PROCESS-NAME-REGEX,^Game{1,2} //1$),(DOMAIN,x.example.com))",
        ]
        parsed, messages = parse(
            "\n".join(f"AND,{expression},PROXY # note" for expression in expressions),
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("AND", expression) for expression in expressions])
        self.assertEqual(messages, [])
        yaml, messages = parse(
            'payload:\n  - "AND,((PROCESS-NAME,Game ;1),(DOMAIN,x.example.com))"\n'
            '  - "AND,((PROCESS-NAME,Game //1),(DOMAIN,x.example.com))"\n'
            '  - "AND,((PROCESS-NAME-REGEX,^Game{1,2} #1$),(DOMAIN,x.example.com))"',
            purpose="proxy",
        )
        self.assertEqual(yaml, [Rule("AND", value, literal_process=True, native_fields=True) for value in expressions[1:3]]
                         + [Rule("AND", expressions[0], native_fields=True)])
        self.assertEqual(messages, [])

    def test_logical_port_comparison_keeps_both_children(self):
        parsed, messages = parse(
            "AND,((SRC-PORT,>=50000),(DOMAIN,a.example.com)),PROXY", purpose="proxy"
        )
        self.assertEqual(parsed, [Rule("AND", "((SRC-PORT,50000-65535),(DOMAIN,a.example.com))")])
        self.assertEqual(messages, [])

    def test_logical_multi_port_becomes_nested_or(self):
        parsed, messages = parse(
            "OR,((DST-PORT,80/443),(DOMAIN,a.example.com)),PROXY", purpose="proxy"
        )
        self.assertEqual(parsed, [Rule("OR", "((OR,((DST-PORT,80),(DST-PORT,443))),(DOMAIN,a.example.com))")])
        self.assertEqual(messages, [])

    def test_logical_nested_whitespace_and_quoted_process_comma(self):
        parsed, messages = parse(
            'AND,((OR,((DOMAIN ,a.example.com), (DOMAIN,b.example.com))), '
            '(PROCESS-NAME,"Foo,Bar")),PROXY', purpose="proxy"
        )
        self.assertEqual(parsed, [Rule(
            "AND", '((OR,((DOMAIN,a.example.com),(DOMAIN,b.example.com))),(PROCESS-NAME,"Foo,Bar"))'
        )])
        self.assertEqual(messages, [])

    def test_logical_quoted_regex_validates_unquoted_value_and_preserves_quantifier_comma(self):
        source = (r'AND,((DOMAIN-REGEX,"*ads"),(DOMAIN,x.example.com)),REJECT' '\n'
                  r'AND,((DOMAIN-REGEX,"^a{2,3}\.example\.com$"),(DOMAIN,x.example.com)),REJECT')
        parsed, messages = parse(source, purpose="block")
        self.assertEqual(parsed, [Rule(
            "AND", r'((DOMAIN-REGEX,"^a{2,3}\.example\.com$"),(DOMAIN,x.example.com))'
        )])
        self.assertEqual(messages, ['line 1: invalid logical expression ((DOMAIN-REGEX,"*ads"),(DOMAIN,x.example.com))'])

    def test_logical_lowercase_child_types_are_canonicalized(self):
        parsed, messages = parse(
            "AND,((domain,x.example.com),(ip-cidr,203.0.113.7/24,no-resolve)),PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule(
            "AND", "((DOMAIN,x.example.com),(IP-CIDR,203.0.113.0/24,no-resolve))"
        )])
        self.assertEqual(messages, [])

    def test_logical_explicit_src_cidr_ignores_no_resolve_and_keeps_direction(self):
        parsed, messages = parse(
            "AND,((SRC-IP-CIDR,192.0.2.15/24,no-resolve),(IP-CIDR,203.0.113.7/24,no-resolve)),PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule(
            "AND", "((SRC-IP-CIDR,192.0.2.0/24),(IP-CIDR,203.0.113.0/24,no-resolve))"
        )])
        self.assertEqual(messages, ["line 1: unsupported no-resolve for SRC-IP-CIDR"])

    def test_logical_src_option_keeps_source_ip_direction(self):
        parsed, messages = parse(
            "AND,((IP-CIDR,192.0.2.15/24,src),(DOMAIN,x.example.com)),PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule(
            "AND", "((SRC-IP-CIDR,192.0.2.0/24),(DOMAIN,x.example.com))"
        )])
        self.assertEqual(messages, [])

    def test_logical_src_option_supports_each_mihomo_ip_matcher(self):
        for source, expected in (
            ("IP-CIDR6,2001:db8::1/32", "SRC-IP-CIDR,2001:db8::/32"),
            ("IP-SUFFIX,8.8.8.8/24", "SRC-IP-SUFFIX,8.8.8.8/24"),
            ("GEOIP,CN", "SRC-GEOIP,CN"),
            ("IP-ASN,64512", "SRC-IP-ASN,64512"),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(
                    f"AND,(({source},src),(DOMAIN,x.example.com)),PROXY", purpose="proxy",
                )
                self.assertEqual(parsed, [Rule(
                    "AND", f"(({expected}),(DOMAIN,x.example.com))"
                )])
                self.assertEqual(messages, [])

    def test_logical_src_with_irrelevant_no_resolve_keeps_source_matcher(self):
        parsed, messages = parse(
            "AND,((IP-CIDR,192.0.2.15/24,src,no-resolve),(DOMAIN,a.example.com)),PROXY\n"
            "NOT,(IP-SUFFIX,8.8.8.8/24,no-resolve,src),PROXY", purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("AND", "((SRC-IP-CIDR,192.0.2.0/24),(DOMAIN,a.example.com))"),
            Rule("NOT", "(SRC-IP-SUFFIX,8.8.8.8/24)"),
        ])
        self.assertEqual(messages, [
            "line 1: unsupported no-resolve for SRC-IP-CIDR",
            "line 2: unsupported no-resolve for SRC-IP-SUFFIX",
        ])

    def test_logical_destination_ip_options_are_deduplicated(self):
        parsed, messages = parse(
            "AND,((IP-CIDR,192.0.2.1/24,no-resolve,no-resolve),"
            "(IP-SUFFIX,8.8.8.8/24,no-resolve,no-resolve)),PROXY", purpose="proxy"
        )
        self.assertEqual(parsed, [Rule(
            "AND", "((IP-CIDR,192.0.2.0/24,no-resolve),(IP-SUFFIX,8.8.8.8/24,no-resolve))"
        )])
        self.assertEqual(messages, [])

    def test_logical_unsupported_child_keeps_the_other_child(self):
        expression = "((URL-REGEX,^https://example.com/ads$),(DOMAIN,a.example.com))"
        parsed, messages = parse(f"AND,{expression},PROXY", purpose="proxy")
        self.assertEqual(parsed, [Rule("AND", expression)])
        self.assertEqual(messages, [])

    def test_logical_invalid_port_and_html_still_warn(self):
        parsed, messages = parse(
            "AND,((SRC-PORT,65536),(DOMAIN,a.example.com)),PROXY\n"
            "<html>error</html>", purpose="proxy"
        )
        self.assertEqual(parsed, [])
        self.assertTrue(any("invalid logical" in message for message in messages))
        self.assertTrue(any("HTML" in message for message in messages))

    def test_logical_child_rejects_invalid_regex(self):
        rules, messages = parse(
            "AND,((DOMAIN-REGEX,*ads),(DOMAIN,ads.example.com)),REJECT", purpose="block",
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("invalid logical" in message for message in messages))

    def test_logical_children_allow_no_resolve_only_on_destination_ip_matchers(self):
        expression = "((IP-CIDR,192.0.2.0/24,no-resolve),(DOMAIN,ads.example.com))"
        parsed, messages = parse(
            f"AND,{expression},REJECT\n"
            "AND,((DOMAIN,ads.example.com,no-resolve),(SRC-PORT,443)),REJECT\n"
            "AND,((IP-CIDR,not-an-ip,no-resolve),(SRC-PORT,443)),REJECT",
            purpose="block",
        )
        self.assertEqual(parsed, [Rule("AND", expression)])
        self.assertEqual(len(messages), 2)
        from formats import render

        output, _ = render("group", parsed, purpose="block", no_resolve="strip")
        self.assertIn("AND,((IP-CIDR,192.0.2.0/24),(DOMAIN,ads.example.com))\n", output["fin.txt"])
        self.assertIn('"AND,((IP-CIDR,192.0.2.0/24),(DOMAIN,ads.example.com))"', output["fin.yaml"])

    def test_logical_child_normalizes_port_forms(self):
        parsed, messages = parse(
            "AND,((SRC-PORT,>=50000),(NETWORK,UDP)),PROXY\n"
            "OR,((DST-PORT,80/443),(DOMAIN,example.com)),PROXY\n"
            "AND,((SRC-PORT,50000-65535),(NETWORK,UDP)),PROXY",
            purpose="proxy",
        )
        self.assertEqual(parsed, [
            Rule("AND", "((SRC-PORT,50000-65535),(NETWORK,UDP))"),
            Rule("OR", "((OR,((DST-PORT,80),(DST-PORT,443))),(DOMAIN,example.com))"),
            Rule("AND", "((SRC-PORT,50000-65535),(NETWORK,UDP))"),
        ])
        self.assertEqual(messages, [])

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

    def test_multiline_html_fragment_keeps_rules_on_both_sides(self):
        parsed, messages = parse(
            "DOMAIN,a.example\n<div>\n</div>\nDOMAIN,b.example\n", purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("DOMAIN", "a.example"), Rule("DOMAIN", "b.example")])
        self.assertEqual(messages, ["line 2: HTML markup", "line 3: HTML markup"])

    def test_nested_html_fragment_does_not_leak_rules_and_keeps_warning_lines(self):
        parsed, messages = parse(
            "DOMAIN,first.example\n<div>\nDOMAIN,hidden.example\n<div>\n"
            "DOMAIN,also-hidden.example\n</div>\nDOMAIN,still-hidden.example\n"
            "</div>\nnot a rule\nDOMAIN,last.example", purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("DOMAIN", "first.example"), Rule("DOMAIN", "last.example")])
        self.assertEqual(messages, [
            "line 2: HTML markup", "line 4: HTML markup", "line 6: HTML markup",
            "line 8: HTML markup", "line 9: invalid rule",
        ])

    def test_isolated_html_tag_is_skipped_without_discarding_valid_rules(self):
        parsed, messages = parse(
            "DOMAIN,first.example.com,REJECT\n<img/>\nDOMAIN,ads.example.com,REJECT",
            purpose="block",
        )
        self.assertEqual(parsed, [
            Rule("DOMAIN", "first.example.com"), Rule("DOMAIN", "ads.example.com")
        ])
        self.assertTrue(any("line 2" in message and "HTML" in message for message in messages))

    def test_single_line_html_error_does_not_discard_surrounding_rules(self):
        parsed, messages = parse(
            "DOMAIN,keep.example\n<html>error</html>\nDOMAIN,other.example\n",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("DOMAIN", "keep.example"), Rule("DOMAIN", "other.example")])
        self.assertTrue(any("line 2" in message and "HTML" in message for message in messages))

    def test_unpaired_html_opener_does_not_discard_valid_rules(self):
        parsed, messages = parse(
            "<html>upstream error\nDOMAIN,keep.example\nDOMAIN,other.example",
            purpose="proxy",
        )
        self.assertEqual(parsed, [Rule("DOMAIN", "keep.example"), Rule("DOMAIN", "other.example")])
        self.assertTrue(any("line 1" in message and "HTML" in message for message in messages))

    def test_complete_single_line_html_document_still_rejects_source(self):
        parsed, messages = parse(
            "<html><body>error</body></html>\nDOMAIN,ads.example.com",
            purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertTrue(any("HTML document" in message for message in messages))

    def test_multiline_html_wrapper_without_doctype_rejects_source(self):
        parsed, messages = parse(
            "<html>\nDOMAIN,ads.example.com\n</html>", purpose="block"
        )
        self.assertEqual(parsed, [])
        self.assertTrue(any("HTML document" in message for message in messages))

    def test_html_document_cannot_hide_a_valid_rule(self):
        rules, warnings = parse(
            "<!doctype html>\n<html><body>\nDOMAIN,ads.example.com,REJECT\n</body></html>",
            purpose="block",
        )
        self.assertEqual(rules, [])
        self.assertTrue(any("HTML" in message and "1" in message for message in warnings))

    def test_script_html_attribute_containing_regex_type_does_not_import_rules(self):
        parsed, messages = parse(
            '<script data-rule="DOMAIN-REGEX,foo">\n'
            'DOMAIN,inside.example.com,REJECT\n</script>', purpose="block",
        )
        self.assertEqual(parsed, [])
        self.assertEqual(messages, ["line 1: HTML document"])

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

    def test_domain_no_resolve_option_is_rejected_before_rendering(self):
        parsed, messages = parse(
            "DOMAIN,ads.example.com,REJECT,no-resolve\n"
            "DOMAIN-SUFFIX,tracking.example.com,no-resolve\n"
            "DOMAIN,valid.example.com,REJECT",
            purpose="block",
        )
        self.assertEqual(parsed, [Rule("DOMAIN", "valid.example.com")])
        self.assertEqual(len(messages), 2)
        self.assertTrue(all("no-resolve" in message for message in messages))

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


class FollowupParseTests(unittest.TestCase):
    def assert_regex_preserved(self, value, kind="DOMAIN-REGEX", policy="China", logical_only=False,
                               following_rule=False):
        for logical in ((True,) if logical_only else (False, True)):
            expression = f"(({kind},{value}),(DOMAIN,x.example.com))"
            source = f"AND,{expression},{policy}" if logical else f"{kind},{_quote_matcher(value)},{policy}"
            expected = [Rule("AND", expression) if logical else Rule(kind, value)]
            if following_rule:
                source += "\nDOMAIN,keep.example.com,China"
                expected.append(Rule("DOMAIN", "keep.example.com"))
            with self.subTest(value=value, logical=logical):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual((parsed, messages), (expected, []))
                self.assertEqual(set(normalize(parsed)), set(expected))

    def assert_regex_rejected(self, value, kind="PROCESS-NAME-REGEX"):
        for logical in (False, True):
            expression = f"(({kind},{value}),(DOMAIN,x.example.com))"
            source = (f"AND,{expression},China" if logical else f"{kind},{_quote_matcher(value)},China")
            with self.subTest(value=value, logical=logical):
                parsed, messages = parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy")
                self.assertEqual(parsed, [Rule("DOMAIN", "keep.example.com")])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith("line 1:"), messages)

    def test_unanchored_known_policy_comments_keep_original_matcher(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for policy in ("PROXY", "LIST"):
                for marker in ("#", ";", "//"):
                    for body in ("note", "note $", r"note \z", "note [,China ( # ; //"):
                        source = f"{kind},^foo,{policy} {marker} {body}\nDOMAIN,keep.example.com,China"
                        with self.subTest(source=source):
                            parsed, messages = parse(source, purpose="proxy")
                            self.assertEqual((parsed, messages),
                                             ([Rule(kind, "^foo"), Rule("DOMAIN", "keep.example.com")], []))
                            self.assertEqual(set(normalize(parsed)), set(parsed))
            for marker in ("#", ";", "//"):
                self.assert_regex_preserved(f"^Game,DIRECT {marker}1$", kind=kind, policy="PROXY", following_rule=True)
                parsed, messages = parse(f"{kind},^foo,China {marker} note\n"
                                         "DOMAIN,keep.example.com,China", purpose="proxy")
                self.assertEqual((parsed, messages), ([Rule("DOMAIN", "keep.example.com")],
                                                     ["line 1: ambiguous unquoted regex comma or policy"]))

    def test_literal_brace_local_anchors_keep_complete_field_and_rendered_logic(self):
        from formats import render

        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in ("^a{b$,c}$", r"^a\{b$,c\}$", r"^a{b\z,c}$",
                          "^a{b${c,d},e}$", "^a{b$[}],c}$", "^a{b$,(?#})c,d}$", "^a{1,2}$"):
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
                expression = f"(({kind},{value}),(DOMAIN,x.example.com))"
                parsed, messages = parse(f"AND,{expression},China\nDOMAIN,keep.example.com,China", purpose="proxy")
                output, skipped = render("group", normalize(parsed), purpose="proxy", no_resolve="keep")
                self.assertNotIn("fin.yaml:AND", skipped)
                self.assertEqual(set(parse(output["fin.yaml"], purpose="proxy")[0]), {Rule("AND", expression, native_fields=True), Rule("DOMAIN", "keep.example.com")})
                self.assertEqual(messages, [])
            for marker in ("#", ";", "//"):
                value = f"^a{{b$,My Proxy {marker} note}}$|^foo$"
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
                self.assert_regex_preserved(value, kind=kind, policy="PROXY", following_rule=True)

    def test_unpaired_literal_braces_keep_confirmed_policy_and_source_comments(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in ("^a{b$", r"^a\{b$", "^a{b{1,2}$"):
                for marker in ("#", ";", "//"):
                    for policy in ("PROXY", "China"):
                        source = f"{kind},{_quote_matcher(value)},{policy} {marker} note [,China ($\nDOMAIN,keep.example.com,China"
                        with self.subTest(source=source):
                            self.assertEqual(parse(source, purpose="proxy"),
                                             ([Rule(kind, value), Rule("DOMAIN", "keep.example.com")], []))

    def test_invalid_complete_brace_matcher_is_never_shortened_before_validation(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for marker in ("#", ";", "//"):
                self.assert_regex_rejected(f"^a{{b$,My Proxy {marker} [}}$", kind=kind)

    def test_reserved_interface_policy_comments_keep_ambiguity(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for policy in sorted(rules._QX_INTERFACE_OPTIONS):
                for marker in ("#", ";", "//"):
                    for body in ("note", "note $", r"note \z", "note [,China ("):
                        source = f"{kind},^foo$,{policy} {marker} {body}\nDOMAIN,keep.example.com,China"
                        with self.subTest(source=source):
                            self.assertEqual(parse(source, purpose="proxy"),
                                             ([Rule("DOMAIN", "keep.example.com")],
                                              ["line 1: ambiguous unquoted regex comma or policy"]))
                self.assert_regex_preserved("^foo$", kind=kind, policy=policy + "-custom", following_rule=True)
                self.assert_regex_preserved("^foo$", kind=kind, policy="custom-" + policy, following_rule=True)
                self.assert_regex_preserved(f"^foo$,{policy}", kind=kind, logical_only=True, following_rule=True)

    def test_source_comment_brace_cannot_close_an_unpaired_matcher(self):
        source = "DOMAIN-REGEX,^a{b$,PROXY # note }\nDOMAIN,keep.example.com,China"
        self.assertEqual(parse(source, purpose="proxy"),
                         ([Rule("DOMAIN-REGEX", "^a{b$"), Rule("DOMAIN", "keep.example.com")], []))

    def test_source_regex_ranges_preserve_matcher_before_policy_and_comment(self):
        import json
        from formats import render

        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for value in ("^a{b$", r"^a\{b$", "^a{b{1,2}$", "^(?x)a{b$"):
                for quote in ("'", '"'):
                    for policy in ("PROXY", "LIST", "China", "中文 (My) Proxy", "My } Proxy"):
                        for marker in ("#", ";", "//"):
                            for body in ("note }", "note } [", r"note } \z,tail$ ( [ # ; //", "note },tail$"):
                                source = f"{kind},{quote}{value}{quote},{policy} {marker} {body}"
                                with self.subTest(source=source):
                                    parsed, messages = parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy")
                                    expected = [Rule(kind, value), Rule("DOMAIN", "keep.example.com")]
                                    self.assertEqual((parsed, messages), (expected, []))
                                    self.assertEqual(set(normalize(parsed)), set(expected))
                                    output, skipped = render("group", normalize(parsed), purpose="proxy", no_resolve="keep")
                                    payload = [json.loads(line[4:]) for line in output["fin.yaml"].splitlines()
                                               if line.startswith('  - "')]
                                    self.assertEqual(set(payload), {f"{kind},{value}", "DOMAIN,keep.example.com"})
                                    self.assertNotIn(f"fin.yaml:{kind}", skipped)

    def test_policy_literal_brace_does_not_close_unpaired_regex(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for value in ("^a{b$", r"^a\{b$", "^a{b{1,2}$"):
                for quote in ("'", '"'):
                    for policy in ("My } Proxy", "中文 } (My) Proxy", "My } Proxy (", "My } Proxy ["):
                        with self.subTest(kind=kind, value=value, quote=quote, policy=policy):
                            expected = [Rule(kind, value), Rule("DOMAIN", "keep.example.com")]
                            parsed, messages = parse(f"{kind},{quote}{value}{quote},{policy}\n"
                                                     "DOMAIN,keep.example.com,China", purpose="proxy")
                            self.assertEqual((parsed, messages), (expected, []))
                            self.assertEqual(set(normalize(parsed)), set(expected))

    def test_complete_paired_regex_ranges_keep_local_anchors_and_markers(self):
        import json
        from formats import render

        values = ["^a{b$,c}$", r"^a\{b$,c\}$", r"^a{b\z,c}$", "^a{b${c,d},e}$",
                  "^a{b$[}],c}$", "^a{b$,(?#})c,d}$", "^a{1,2}$"]
        values += [f"^a{{b$,My Proxy {marker} note}}$|^foo$" for marker in ("#", ";", "//")]
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for value in values:
                for quote in ("", "'", '"'):
                    expression = f"(({kind},{quote}{value}{quote}),(DOMAIN,x.example.com))"
                    for source, expected in ((f"{kind},{_quote_matcher(value)},China", Rule(kind, value)),
                                             (f"AND,{expression},China", Rule("AND", expression))):
                        with self.subTest(source=source):
                            parsed, messages = parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy")
                            self.assertEqual((parsed, messages), ([expected, Rule("DOMAIN", "keep.example.com")], []))
                            self.assertEqual(set(normalize(parsed)), set(parsed))
                            output, skipped = render("group", normalize(parsed), purpose="proxy", no_resolve="keep")
                            payload = [json.loads(line[4:]) for line in output["fin.yaml"].splitlines()
                                       if line.startswith('  - "')]
                            rendered = f"AND,(({kind},{value}),(DOMAIN,x.example.com))" if expected.kind == "AND" else f"{kind},{value}"
                            self.assertEqual(set(payload), {rendered, "DOMAIN,keep.example.com"})
                            self.assertNotIn(f"fin.yaml:{expected.kind}", skipped)

    def test_complete_invalid_paired_regex_is_rejected_at_public_entry(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for marker in ("#", ";", "//"):
                value = f"^a{{b$,My Proxy {marker} [}}$"
                for quote in ("", "'", '"'):
                    expression = f"(({kind},{quote}{value}{quote}),(DOMAIN,x.example.com))"
                    for source in (f"{kind},{_quote_matcher(value)},China", f"AND,{expression},China"):
                        with self.subTest(source=source):
                            parsed, messages = parse(source + "\nDOMAIN,keep.example.com,China", purpose="proxy")
                            self.assertEqual(parsed, [Rule("DOMAIN", "keep.example.com")])
                            warning = f"line 1: invalid {kind} {value}" if not source.startswith("AND,") else (f"line 1: invalid logical expression {expression}" if quote else "line 1: unbalanced delimiters")
                            self.assertEqual(messages, [warning])

    def test_reserved_regex_policy_comments_cannot_change_ambiguity(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for policy in sorted(rules._QX_INTERFACE_OPTIONS):
                for marker in ("#", ";", "//"):
                    source = f"{kind},^a{{b$,{policy} {marker} note }} [ ( $ \\z,tail$\nDOMAIN,keep.example.com,China"
                    with self.subTest(source=source):
                        self.assertEqual(parse(source, purpose="proxy"),
                                         ([Rule("DOMAIN", "keep.example.com")],
                                          ["line 1: ambiguous unquoted regex comma or policy"]))
                self.assert_regex_preserved("^a{b$", kind=kind, policy=policy + "-custom", following_rule=True)

    def test_policy_free_logical_regex_does_not_enter_source_policy_state(self):
        import json
        from formats import render

        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for value in ("^a{b$,My } Proxy", "^a{b$,My } Proxy[ab]$", "^a{b$,PROXY # note }", "^a{b$,LIST ; note }$"):
                expression = f"(({kind},{value}),(DOMAIN,x.example.com))"
                with self.subTest(kind=kind, value=value):
                    parsed, messages = parse(f"AND,{expression},China # note }} [\nDOMAIN,keep.example.com,China", purpose="proxy")
                    self.assertEqual((parsed, messages),
                                     ([Rule("AND", expression), Rule("DOMAIN", "keep.example.com")], []))
                    self.assertEqual(set(normalize(parsed)), set(parsed))
                    output, skipped = render("group", normalize(parsed), purpose="proxy", no_resolve="keep")
                    payload = [json.loads(line[4:]) for line in output["fin.yaml"].splitlines() if line.startswith('  - "')]
                    self.assertEqual(set(payload), {f"AND,{expression}", "DOMAIN,keep.example.com"})
                    self.assertNotIn("fin.yaml:AND", skipped)

    def test_confirmed_source_policy_regex_punctuation_is_literal(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for value in ("^foo$", "^a{b$"):
                for policy in ("My } Pro*xy (", "My } Pro+xy [", r"My } Pro\xy (", "My } Pro|xy [", "My } Pro$xy ("):
                    for marker in ("#", ";", "//"):
                        source = f"{kind},{_quote_matcher(value)},{policy} {marker} note }} [\nDOMAIN,keep.example.com,China"
                        with self.subTest(source=source):
                            self.assertEqual(parse(source, purpose="proxy"),
                                             ([Rule(kind, value), Rule("DOMAIN", "keep.example.com")], []))

    def test_policy_free_source_regex_keeps_anchored_tail_comment(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for marker in ("#", ";", "//"):
                source = f"{kind},'^a{{b$' {marker} note ( [\nDOMAIN,keep.example.com,China"
                self.assertEqual(parse(source, purpose="proxy"),
                                 ([Rule(kind, "^a{b$"), Rule("DOMAIN", "keep.example.com")], []))

    def test_source_range_deep_capture_neighbors_have_hard_timeout(self):
        for depth in (495, 510, 1000):
            code = ("from rules import Rule, parse, normalize\n"
                    f"depth = {depth}\n"
                    "values = [('^' + '(' * depth + 'a' + ')' * depth + '$', True),\n"
                    "          ('^' + '(' * depth + ')' * depth + '*$', True),\n"
                    "          ('^' + '(' * depth + ')' * depth + r'*\\1$', True),\n"
                    "          ('^' + '(' * depth + ')' * depth + '**$', False),\n"
                    "          ('^' + '(' * depth + ')' * (depth - 1) + '$', False),\n"
                    "          ('^' + '(' * depth + ')' * depth + r'\\k<' + str(depth + 1) + '>$', False)]\n"
                    "for value, valid in values:\n"
                    "    for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX'):\n"
                    "        for quote in ('', chr(39), chr(34)):\n"
                    "            expression = f'(({kind},{quote}{value}{quote}),(DOMAIN,x.example.com))'\n"
                    "            for source, rule in ((f'{kind},{chr(34)}{value}{chr(34)},China', Rule(kind,value)),\n"
                    "                                 (f'AND,{expression},China', Rule('AND',expression))):\n"
                    "                parsed, messages = parse(source + ' # note } [\\nDOMAIN,keep.example.com,China', purpose='proxy')\n"
                    "                expected = ([rule] if valid else []) + [Rule('DOMAIN','keep.example.com')]\n"
                    "                assert parsed == expected and (messages == [] if valid else\n"
                    "                    len(messages) == 1 and messages[0].startswith('line 1:')), (depth, kind, valid, len(value))\n"
                    "                assert set(normalize(parsed)) == set(expected)\n")
            with self.subTest(depth=depth):
                try:
                    result = subprocess.run([sys.executable, "-B", "-c", code],
                                            cwd=Path(__file__).resolve().parents[1],
                                            capture_output=True, text=True, timeout=4)
                except subprocess.TimeoutExpired:
                    self.fail("字段范围与深层普通捕获回归使解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_legacy_nonword_name_text_falls_back_to_literal(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^\<a²>$", r"^\'a²'$"):
                self.assert_regex_preserved(value, kind=kind, following_rule=True)

    def test_legacy_undefined_unicode_word_names_are_rejected(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^\<é>$", r"^\'é'$"):
                self.assert_regex_rejected(value, kind=kind)

    def test_go_word_names_share_declaration_reference_condition_and_balance_scanning(self):
        for character in ("é", "É", "ǅ", "ʰ", "字", "́", "١", "‿", "‌", "‍", "\U00011f02", "\U0001171e"):
            for name in (character, "a" + character):
                for opening, closing, reference in (("(?<", ">", r"\k<"), ("(?'", "'", r"\k'")):
                    capture = opening + name + closing + "a)"
                    values = ("^" + capture + reference + name + closing + "$",
                              "^" + capture + reference[0] + reference[2:] + name + closing + "$",
                              "^" + capture + "(?(" + name + ")b|c)$",
                              "^" + capture + opening + "-" + name + closing + "b)$",
                              "^" + capture + opening + "out-" + name + closing + "b)" + reference + "out" + closing + "$")
                    for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
                        for value in values:
                            self.assert_regex_preserved(value, kind=kind, following_rule=True)
                        self.assert_regex_rejected("^" + reference + name + closing + "$", kind=kind)

    def test_nonword_categories_follow_each_syntax_completion_rule(self):
        for character in ("²", "Ⅷ", "ा", "😀", "\U0002ebf0", "Ᲊ"):
            for name in (character, "a" + character):
                for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
                    for value in ("^\\<" + name + ">$", "^\\'" + name + "'$", "^(?(" + name + ")b|c)$"):
                        self.assert_regex_preserved(value, kind=kind, following_rule=True)
                    for value in ("^\\k<" + name + ">$", "^\\k'" + name + "'$",
                                  "^(?<" + name + ">a)$", "^(?'" + name + "'a)$",
                                  "^(?<a>a)(?<out-" + name + ">b)$"):
                        self.assert_regex_rejected(value, kind=kind)

    def test_ascii_decimal_slots_are_distinct_from_unicode_decimal_names(self):
        valid = (r"^(?<١>a)\k<١>$", r"^(?<١>a)\k<1>$", r"^(?<٣>a)\k<٣>$",
                 r"^(?<٠>a)\k<٠>$", r"^(?<١a>a)\k<١a>$", r"^(?<١1>a)\k<١1>$",
                 r"^(?<a١>a)\k<a١>$", r"^(?<١>a)(?(١)b|c)$", r"^(?<١>a)(?<-١>b)$",
                 r"^\<1١>$", r"^\'1a'$", r"^(?<1>a)\k<01>$",
                 r"^(?<1>a)(?(01)b|c)$", r"^(?<1>a)(?<-01>b)$")
        invalid = (r"^(?<٣>a)\k<3>$", r"^(?<1>a)\k<١>$", r"^(?<1١>a)$",
                   r"^(?<1a>a)$", r"^\k<1١>$", r"^\k'1a'$", r"^(?<٣>a)(?(3)b|c)$",
                   r"^(?<٣>a)(?<-3>b)$", r"^(?<0>a)$")
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in valid:
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in invalid:
                self.assert_regex_rejected(value, kind=kind)

    def test_legacy_incomplete_tokens_and_class_escapes_keep_literal_fallback(self):
        valid = (r"^\<é$", r"^\'é$", r"^\<1$", r"^\'1$", r"^\<>$", r"^\''$",
                 r"^\<-$", r"^\'-$", r"^\<a'$", r"^\'a>$", r"^[\<é>]$", r"^[\'é']$",
                 r"^(?<a>a)\<a²>$", r"^(?<a>a)\'a²'$")
        invalid = (r"^\k<é$", r"^\k'é$", r"^\k<1$", r"^\k'1$", r"^\k<>$", r"^\k''$",
                   r"^\k<-$", r"^\k'-$", r"^[\k<é>]$", r"^\<2147483648$", r"^\'2147483648$")
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in valid:
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in invalid:
                self.assert_regex_rejected(value, kind=kind)

    def test_unicode_names_preserve_case_duplicates_forward_and_expression_conditions(self):
        valid = (r"^(?<é>a)(?<é>b)\k<é>$", r"^\<é>(?<é>a)$", r"^(?(é)b|c)(?<é>a)$",
                 r"^(?<é>a)(?(É)b|c)$", r"^(?<a>a)(?(a²)b|c)$", r"^(?<é>a)(?<b-é>b)\k<b>$",
                 r"^(?<é>a)(?<-é>b)$", r"^(?<-é>a)(?<é>b)$", r"^(?i:(?<é>a))\k<é>$")
        invalid = (r"^(?<é>a)\k<É>$", r"^(?<é>a)(?<-É>b)$", r"^(?<é>a)(?<b-a²>b)$",
                   r"^(?<a>a)(?(a²)b|c)\k<2>$", r"^(?(é)b|c)\k<1>$", r"^(?(é)b|c|d)$")
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in valid:
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in invalid:
                self.assert_regex_rejected(value, kind=kind)

    def test_expression_condition_fallback_keeps_forbidden_comment_and_capture_heads_rejected(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^(?(?#note)a|b)$", r"^(?(?<é>a)b|c)$", "^(?(?'é'a)b|c)$"):
                self.assert_regex_rejected(value, kind=kind)

    def test_unknown_unicode_word_character_escapes_use_fixed_client_categories(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for character in ("é", "́", "١", "‿", "‌", "‍", "\U00011f02"):
                for value in ("^\\" + character + "$", "^[\\" + character + "]$"):
                    self.assert_regex_rejected(value, kind=kind)
            for character in ("²", "Ⅷ", "ा", "\U0002ebf0", "Ᲊ"):
                for value in ("^\\" + character + "$", "^[\\" + character + "]$"):
                    self.assert_regex_preserved(value, kind=kind, following_rule=True)

    def test_fixed_go_wordchar_ranges_have_exact_boundaries_and_size(self):
        boundaries = rules._REGEXP2_WORD_BOUNDARIES
        self.assertEqual(len(boundaries), 869 * 2)
        self.assertTrue(all(left < right for left, right in zip(boundaries, boundaries[1:])))
        self.assertEqual(sum(end - start for start, end in zip(boundaries[::2], boundaries[1::2])), 138781)
        for start, end in zip(boundaries[::2], boundaries[1::2]):
            for point, expected in ((start - 1, False), (start, True), (end - 1, True), (end, False)):
                self.assertEqual(rules._regexp2_word_char(chr(point)), expected, hex(point))
        for point in (0x11f02, 0x1171e, 0x200c, 0x200d, 0x323af):
            self.assertTrue(rules._regexp2_word_char(chr(point)))
        for point in (0xb2, 0x2167, 0x93e, 0x2ebf0, 0x2ee5d, 0x1c89, 0x10ffff):
            self.assertFalse(rules._regexp2_word_char(chr(point)))

    def test_long_unicode_names_and_all_numeric_reference_forms_have_hard_timeout(self):
        code = r'''
from rules import Rule, parse, normalize
for opening, closing in ((r'\k<', '>'), ("\\k'", "'"), (r'\<', '>'), ("\\'", "'")):
    name = 'a' + chr(0x301) * 5000
    value = '^(?<' + name + '>a)' + opening + name + closing + '$'
    values = [(value, True)]
    for digits, valid in (('0' * 5000 + '1', True), ('1' * 5000, False)):
        values.append(('^(?<1>a)' + opening + digits + closing + '$', valid))
        if not valid:
            values.append(('^(?<1>a)' + opening + digits + '$', False))
    for value, valid in values:
        for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):
            expression = f'(({kind},{value}),(DOMAIN,x.example.com))'
            for source, rule in ((f'{kind},{chr(34)}{value}{chr(34)},China', Rule(kind,value)),
                                 (f'AND,{expression},China', Rule('AND',expression))):
                parsed, messages = parse(source + '\nDOMAIN,keep.example.com,China', purpose='proxy')
                expected = ([rule] if valid else []) + [Rule('DOMAIN','keep.example.com')]
                assert parsed == expected and (messages == [] if valid else
                       len(messages) == 1 and messages[0].startswith('line 1:')), (kind, len(value), valid)
                assert set(normalize(parsed)) == set(expected)
'''
        try:
            result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("超长名称或数值引用使解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def assert_same_name_source(self, kind, value, source_kind):
        from formats import FILES, render

        expected = Rule(source_kind, value)
        for tail in ("src,src", "src,src,no-resolve", "src,no-resolve,src",
                     "PROXY,src", "SRC,src"):
            with self.subTest(tail=tail):
                parsed, messages = parse(f"{kind},{value},{tail}", purpose="proxy")
                self.assertEqual(parsed, [expected])
                self.assertEqual(normalize(parsed), [expected])
                self.assertEqual(messages, [f"line 1: unsupported no-resolve for {source_kind}"]
                                 if "no-resolve" in tail else [])
                for mode in ("add", "strip", "keep"):
                    output, skipped = render("group", normalize(parsed), purpose="proxy", no_resolve=mode)
                    emitted = {"fin.yaml"}
                    if source_kind == "SRC-IP-CIDR":
                        emitted.update(("fin.txt", "fin-surge.txt"))
                    self.assertEqual(skipped, {f"{name}:{source_kind}": 1 for name in FILES if name not in emitted})
                    for name in FILES:
                        self.assertNotIn("no-resolve", output[name])
                        self.assertIn(f"{'Total count' if name == 'fin-adb.txt' else 'rules'}: {int(name in emitted)}",
                                      output[name])
                    self.assertIn(f'  - "{source_kind},{value}"\n', output["fin.yaml"])
                    if source_kind == "SRC-IP-CIDR":
                        self.assertIn(f"SRC-IP,{value}\n", output["fin.txt"])
                        self.assertIn(f"SRC-IP,{value}\n", output["fin-surge.txt"])

    def test_same_name_src_cidr_policy_and_option(self):
        self.assert_same_name_source("IP-CIDR", "192.0.2.0/24", "SRC-IP-CIDR")

    def test_same_name_src_cidr6_policy_and_option(self):
        self.assert_same_name_source("IP-CIDR6", "2001:db8::/32", "SRC-IP-CIDR")

    def test_same_name_src_geoip_policy_and_option(self):
        self.assert_same_name_source("GEOIP", "CN", "SRC-GEOIP")

    def test_same_name_src_asn_policy_and_option(self):
        self.assert_same_name_source("IP-ASN", "64512", "SRC-IP-ASN")

    def test_same_name_src_suffix_policy_and_option(self):
        self.assert_same_name_source("IP-SUFFIX", "8.8.8.8/24", "SRC-IP-SUFFIX")

    def test_src_policy_without_explicit_source_option_keeps_ambiguity_and_options(self):
        for tail in ("src", "src,no-resolve"):
            self.assertEqual(parse(f"IP-CIDR,192.0.2.0/24,{tail}", purpose="proxy"),
                             ([], ["line 1: ambiguous src policy or option"]))
        for option in ("force-cellular", "multi-interface", "multi-interface-balance"):
            self.assertEqual(parse(f"IP-CIDR,192.0.2.0/24,src,{option}", purpose="proxy"),
                             ([Rule("IP-CIDR", "192.0.2.0/24", (option,))], []))
        self.assertEqual(parse("IP-CIDR,192.0.2.0/24,src,PROXY", purpose="proxy"),
                         ([], ["line 1: unexpected fields"]))

    def test_explicit_source_option_keeps_policy_compatibility(self):
        for policy, purpose in (("REJECT", "proxy"), ("DIRECT", "proxy"), ("China", "block")):
            with self.subTest(policy=policy, purpose=purpose):
                self.assertEqual(parse(f"IP-CIDR,192.0.2.0/24,{policy},src", purpose=purpose),
                                 ([], [f"line 1: incompatible action {policy.upper()}"]))

    def test_same_name_source_keeps_no_resolve_only_on_destination_leaf(self):
        from formats import FILES, render

        source, messages = parse("IP-CIDR,192.0.2.0/24,src,src", purpose="proxy")
        self.assertEqual((source, messages), ([Rule("SRC-IP-CIDR", "192.0.2.0/24")], []))
        expression = "((SRC-IP-CIDR,192.0.2.0/24),(IP-CIDR,198.51.100.0/24,no-resolve))"
        parsed, messages = parse(f"AND,{expression},src", purpose="proxy")
        self.assertEqual((parsed, messages), ([Rule("AND", expression)], []))
        for mode in ("add", "strip", "keep"):
            output, skipped = render("group", normalize(parsed), purpose="proxy", no_resolve=mode)
            self.assertEqual(skipped, {f"{name}:AND": 1 for name in FILES
                                       if name not in {"fin.txt", "fin.yaml", "fin-surge.txt"}})
            for name in ("fin.txt", "fin.yaml", "fin-surge.txt"):
                self.assertNotIn("SRC-IP,192.0.2.0/24,no-resolve", output[name])
                self.assertNotIn("SRC-IP-CIDR,192.0.2.0/24,no-resolve", output[name])
                target = "IP-CIDR,198.51.100.0/24" + (",no-resolve" if mode != "strip" else "")
                self.assertIn(target + ")", output[name])
                self.assertEqual(output[name].count("no-resolve"), int(mode != "strip"))

    def test_initial_class_escape_consumes_first_item(self):
        self.assert_regex_preserved(r"^[\d]+$")

    def test_initial_negated_class_escape_consumes_first_item(self):
        self.assert_regex_preserved(r"^[^\d]+$")

    def test_initial_escaped_closing_bracket_consumes_first_item(self):
        self.assert_regex_preserved(r"^[\]]$")

    def test_second_class_caret_is_literal(self):
        self.assert_regex_preserved("^[^^]$")

    def test_first_literal_closing_bracket_does_not_end_class_before_backreference(self):
        self.assert_regex_rejected(r"^[]\k<1>]$")

    def test_first_literal_closing_bracket_with_comma_does_not_end_class_before_backreference(self):
        self.assert_regex_rejected(r"^[]\k<1>,x]$")

    def test_first_literal_closing_bracket_does_not_hide_invalid_property_range(self):
        self.assert_regex_rejected(r"^[]a-\p{L}]$")

    def test_class_comment_and_subtraction_boundaries_keep_valid_neighbors(self):
        for value in (r"^[]a,b]$", r"^[^]a,b]$", r"^[\^]$",
                      r"^[a-z-[aeiou]]{1,2}$", r"^(?#note[)a$"):
            self.assert_regex_preserved(value)
        for value in (r"^[\d$", r"^[^\d$", r"^[\]$", r"^[^^$",
                      r"^[a-z-[aeiou]$", r"^(?#note[a$"):
            self.assert_regex_rejected(value)

    def test_nested_class_subtraction_keeps_boundary_and_rejects_trailing_item(self):
        self.assert_regex_preserved(r"^[a-z-[d-f-[e]]]$")
        self.assert_regex_preserved(r"^[-[a]]$")
        self.assert_regex_rejected(r"^[a-z-[aeiou]b]$")

    def test_first_literal_closing_bracket_keeps_hash_in_class(self):
        self.assert_regex_preserved(r"^[] #]$")

    def test_custom_policy_keeps_extended_regex_comment_in_logic(self):
        self.assert_regex_preserved(r"^(?x)a # [", logical_only=True)
        self.assert_regex_preserved(r"^(?x)a # [", policy="PROXY")
        self.assertEqual(parse(r"DOMAIN-REGEX,^(?x)a # [,China", purpose="proxy"),
                         ([], ["line 1: ambiguous unquoted regex comment"]))

    def test_custom_policy_keeps_literal_hash_after_disabling_extended_mode(self):
        self.assert_regex_preserved(r"^(?x)a(?-x) # [b]$")

    def test_custom_logical_policy_true_tail_comment_has_separate_boundary(self):
        expression = "((DOMAIN-REGEX,^(?x)a # [),(DOMAIN,x.example.com))"
        for comment in (" # note", " ; note (", " // note ["):
            with self.subTest(comment=comment):
                self.assertEqual(parse(f"AND,{expression},China{comment}", purpose="proxy"),
                                 ([Rule("AND", expression)], []))
        ordinary = "((DOMAIN-REGEX,^a$),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{ordinary},China # real comment", purpose="proxy"),
                         ([Rule("AND", ordinary)], []))
        self.assert_regex_rejected(r"^(?x)a(?-x) # [")

    def test_invalid_literal_hash_after_disabling_extended_mode_is_not_trimmed(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^(?x)a(?-x) # [", r"^foo$ # ["):
                self.assert_regex_rejected(value, kind=kind)

    def test_class_hash_and_unbalanced_true_tail_comment_have_separate_boundaries(self):
        value = r"^[] #]$"
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for logical in (False, True):
                expression = f"(({kind},{value}),(DOMAIN,x.example.com))"
                source = f"AND,{expression},China" if logical else f"{kind},{_quote_matcher(value)},China"
                expected = Rule("AND", expression) if logical else Rule(kind, value)
                for comment in (" # note (", " ; note [", " // note ("):
                    with self.subTest(kind=kind, logical=logical, comment=comment):
                        parsed, messages = parse(source + comment + "\nDOMAIN,keep.example.com,China",
                                                 purpose="proxy")
                        self.assertEqual((parsed, messages),
                                         ([expected, Rule("DOMAIN", "keep.example.com")], []))

    def test_closed_class_literal_hash_and_extended_comment_neighbors_are_preserved(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^[a #]$", r"^(?x)a(?-x) # [b]$", r"^(?x:(?# [)a)$",
                          r"^foo$ # [b]$", r"^(?x)a(?-x)$ # [b]$"):
                self.assert_regex_preserved(value, kind=kind)
        expression = "((PROCESS-NAME-REGEX,^(?x)a # [),(DOMAIN,x.example.com))"
        self.assertEqual(parse(f"AND,{expression},China # note (", purpose="proxy"),
                         ([Rule("AND", expression)], []))

    def test_regex_policy_tail_comment_does_not_use_comment_body_as_matcher(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in ("^foo$", r"^foo\z", r"^[] #]$"):
                for logical in (False, True):
                    expression = f"(({kind},{value}),(DOMAIN,x.example.com))"
                    source = f"AND,{expression},China" if logical else f"{kind},{_quote_matcher(value)},China"
                    expected = Rule("AND", expression) if logical else Rule(kind, value)
                    for marker in ("#", ";", "//"):
                        for body in ("note $", r"note \z", "note ($", "note [,China $"):
                            with self.subTest(kind=kind, value=value, logical=logical,
                                              marker=marker, body=body):
                                self.assertEqual(parse(source + f" {marker} {body}\n"
                                                       "DOMAIN,keep.example.com,China", purpose="proxy"),
                                                 ([expected, Rule("DOMAIN", "keep.example.com")], []))

    def test_quoted_regex_policy_field_accepts_spaces_and_unicode_before_comment(self):
        value = r"^[] #]$"
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for policy in ("My Proxy", "香港"):
                for quote in ("'", '"'):
                    expression = f"(({kind},{quote}{value}{quote}),(DOMAIN,x.example.com))"
                    for source, expected in ((f"{kind},{quote}{value}{quote},{policy}", Rule(kind, value)),
                                             (f"AND,{expression},{policy}", Rule("AND", expression))):
                        for marker in ("#", ";", "//"):
                            with self.subTest(source=source, marker=marker):
                                self.assertEqual(parse(source + f" {marker} note (\n"
                                                       "DOMAIN,keep.example.com,China", purpose="proxy"),
                                                 ([expected, Rule("DOMAIN", "keep.example.com")], []))

    def test_confirmed_regex_and_logical_policy_fields_are_literal(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for quoted in (False, True):
                matcher = "'^foo$'" if quoted else '"^foo$"'
                expression = f"(({kind},{matcher}),(DOMAIN,x.example.com))"
                for policy in ("My Proxy (", "香港 [", "My Proxy (香港)"):
                    for source, expected in ((f"{kind},{matcher},{policy}", Rule(kind, "^foo$")),
                                             (f"AND,{expression},{policy}", Rule("AND", expression))):
                        for comment in ("", " # note ($", " ; note ,China", r" // note \z"):
                            with self.subTest(source=source, comment=comment):
                                self.assertEqual(parse(source + comment + "\nDOMAIN,keep.example.com,China",
                                                       purpose="proxy"),
                                                 ([expected, Rule("DOMAIN", "keep.example.com")], []))

    def test_disabled_extended_hash_before_custom_policy_keeps_complete_invalid_matcher(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for policy in ("My Proxy", "香港"):
                for value in (r"^(?x)a(?-x)$ # [", r"^foo$ # ["):
                    for quote in ("", "'", '"'):
                        expression = f"(({kind},{quote}{value}{quote}),(DOMAIN,x.example.com))"
                        for source in (f"{kind},{quote}{value}{quote},{policy}",
                                       f"AND,{expression},{policy}"):
                            with self.subTest(source=source):
                                parsed, messages = parse(source + "\nDOMAIN,keep.example.com,China",
                                                         purpose="proxy")
                                self.assertEqual(parsed, [Rule("DOMAIN", "keep.example.com")])
                                self.assertEqual(len(messages), 1)
                                self.assertTrue(messages[0].startswith("line 1:"), messages)
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^(?x)a(?-x)$ # [b]$", r"^[] #]$"):
                self.assert_regex_preserved(value, kind=kind)
            self.assert_regex_preserved(r"^(?x)a # [", kind=kind, policy="PROXY")

    def test_unicode_control_escape_expansion_warns_without_crashing(self):
        self.assert_regex_rejected(r"^\cß[a]$", kind="DOMAIN-REGEX")

    def test_unicode_control_escape_fold_is_rejected(self):
        self.assert_regex_rejected(r"^\cſ[a]$", kind="DOMAIN-REGEX")

    def test_ascii_control_escape_boundaries_are_preserved(self):
        for value in (r"^\cA[a]$", r"^\ca[a]$", r"^\cZ[a]$", r"^\cz[a]$",
                      r"^\c@[a]$", r"^\c[[a]$", r"^\c][a]$", r"^\c\[a]$",
                      r"^\c^[a]$", r"^\c_[a]$"):
            self.assert_regex_preserved(value)
        for value in (r"^\cÉ[a]$", r"^\c![a]$", r"^\c`[a]$"):
            self.assert_regex_rejected(value)

    def test_conditional_negative_lookahead_is_preserved(self):
        self.assert_regex_preserved(r"^(?(?!a)b|a)ds[.]example[.]com$")
        self.assert_regex_rejected(r"^(?(?!a)b|a|c)$")

    def test_conditional_positive_lookbehind_is_preserved(self):
        self.assert_regex_preserved(r"^a(?(?<=a)b|c)ds[.]example[.]com$")
        self.assert_regex_rejected(r"^a(?(?<=a)b|c|d)$")

    def test_conditional_negative_lookbehind_is_preserved(self):
        self.assert_regex_preserved(r"^a(?(?<!b)b|c)ds[.]example[.]com$")
        self.assert_regex_rejected(r"^a(?(?<!b)b|c|d)$")

    def test_named_balancing_output_capture_is_preserved(self):
        self.assert_regex_preserved(r"^(?<grp>a)(?<out-grp>b)ds[.]example[.]com$")
        self.assert_regex_preserved(r"^(?'grp'a)(?'out-grp'b)ds[.]example[.]com$")
        self.assert_regex_preserved(r"^a(?<-grp>b)(?<grp>c)$")
        self.assert_regex_preserved(r"^(?<grp-grp>a)$")
        self.assert_regex_rejected(r"^(?<grp>a)(?<out-missing>b)$")
        self.assert_regex_rejected(r"^(?<out-grp>b)$")

    def test_numeric_backreference_with_leading_zeroes_is_preserved(self):
        self.assert_regex_preserved(r"^(a)\k<001>ds[.]example[.]com$")
        self.assert_regex_rejected(r"^(a)\k<002>$")

    def test_numeric_backreference_above_two_digits_is_preserved(self):
        self.assert_regex_preserved("^" + "(a)" * 100 + r"\k<100>$")
        self.assert_regex_rejected("^" + "(a)" * 100 + r"\k<101>$")

    def test_capture_reference_boundaries_include_zero_and_explicit_capture_mode(self):
        self.assert_regex_preserved(r"^a\k<0>$")
        self.assert_regex_preserved(r"^(\k<1>)$")
        self.assert_regex_preserved(r"^(?n:(?<grp>a))\k<1>$")
        self.assert_regex_rejected(r"^(?n:(a))\k<1>$")
        self.assert_regex_rejected(r"^(?(?!a)b|a)\k<1>$")

    def test_long_zero_padded_defined_reference_has_hard_timeout(self):
        code = ("from rules import Rule, parse\n"
                "value = r'^(a)\\k<' + '0' * 5000 + '1>$'\n"
                "assert parse(f'DOMAIN-REGEX,{value},REJECT', purpose='block') == "
                "([Rule('DOMAIN-REGEX', value)], [])")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("带大量前导零的合法引用让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_backreference_keeps_captures_under_hard_timeout(self):
        for reference in (r"\k<1>", r"\1"):
            code = ("from rules import Rule, parse, normalize\n"
                    f"value = '^' + '(' * 495 + 'a' + ')' * 495 + {reference!r} + 'ds[.]example[.]com$'\n"
                    "source = f'DOMAIN-REGEX,{value},REJECT\\nDOMAIN,x.example.com,REJECT'\n"
                    "parsed, messages = parse(source, purpose='block')\n"
                    "assert parsed == [Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'x.example.com')] "
                    "and messages == [], (parsed, messages)\n"
                    "assert set(normalize(parsed)) == set(parsed)")
            with self.subTest(reference=reference):
                try:
                    result = subprocess.run([sys.executable, "-c", code],
                                            cwd=Path(__file__).resolve().parents[1],
                                            capture_output=True, text=True, timeout=4)
                except subprocess.TimeoutExpired:
                    self.fail("深层引用让解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_bare_numeric_reference_overflow_warns(self):
        self.assert_regex_rejected(r"^\2147483648$")
        self.assert_regex_rejected(r"^\2147483648$", kind="DOMAIN-REGEX")

    def test_bare_numeric_octal_and_reference_boundaries_are_preserved(self):
        for value in (r"^\10$", r"^\18$", r"^\118$", r"^\400$", r"^\777$",
                      r"^\2147483647$", r"^\011$", r"^[\10]$", r"^(a)\1$",
                      "^" + "(a)" * 10 + r"\k<010>$"):
            self.assert_regex_preserved(value, kind="PROCESS-NAME-REGEX")
        for value in (r"^\1$", r"^\8$", r"^\80$", r"^(a)\k<10>$"):
            self.assert_regex_rejected(value)

    def test_long_bare_numeric_reference_overflow_has_hard_timeout(self):
        code = ("from rules import Rule, parse\n"
                "for value in (r'^\\2147483648$', '^' + chr(92) + '1' * 5000 + '$'):\n"
                "    for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):\n"
                "        for source in (f'{kind},{value},REJECT', "
                "f'AND,(({kind},{value}),(DOMAIN,x.example.com)),REJECT'):\n"
                "            parsed, messages = parse(source + '\\nDOMAIN,keep.example.com,REJECT', purpose='block')\n"
                "            assert parsed == [Rule('DOMAIN', 'keep.example.com')] and "
                "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)\n"
                "value = '^' + chr(92) + '0' + '1' * 5000 + '$'\n"
                "assert parse(f'PROCESS-NAME-REGEX,{value},REJECT', purpose='block') == "
                "([Rule('PROCESS-NAME-REGEX', value)], [])")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("超长裸数字转义让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_two_digit_numeric_reference_has_hard_timeout(self):
        for depth in (495, 510, 1000):
            code = ("from rules import Rule, parse, normalize\n"
                    f"value = '^' + '(' * {depth} + 'a' + ')' * {depth} + r'\\10$'\n"
                    "for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):\n"
                    "    expression = f'(({kind},{value}),(DOMAIN,x.example.com))'\n"
                    "    for source, expected in ((f'{kind},{value},REJECT', Rule(kind,value)), "
                    "(f'AND,{expression},REJECT', Rule('AND',expression))):\n"
                    "        parsed, messages = parse(source + '\\nDOMAIN,keep.example.com,REJECT', purpose='block')\n"
                    "        assert parsed == [expected, Rule('DOMAIN', 'keep.example.com')] and messages == [], (parsed, messages)\n"
                    "        assert set(normalize(parsed)) == set(parsed)")
            with self.subTest(depth=depth):
                try:
                    result = subprocess.run([sys.executable, "-c", code],
                                            cwd=Path(__file__).resolve().parents[1],
                                            capture_output=True, text=True, timeout=4)
                except subprocess.TimeoutExpired:
                    self.fail("深层两位数字引用让解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_explicit_numeric_capture_declarations_are_preserved(self):
        for value in (r"^(?<1>a)\k<1>$", r"^(?<100>a)\k<100>$",
                      r"^(?'100'a)\k<0100>$", r"^(?<100>a)\100$",
                      r"^(?<2147483647>a)\k<2147483647>$"):
            with self.subTest(value=value, policy="REJECT"):
                self.assertEqual(parse(f"PROCESS-NAME-REGEX,{value},REJECT", purpose="block"),
                                 ([Rule("PROCESS-NAME-REGEX", value)], []))
            self.assert_regex_preserved(value, kind="PROCESS-NAME-REGEX")
            self.assert_regex_preserved(value, kind="DOMAIN-REGEX")

    def test_numeric_capture_slots_and_named_assignment_are_preserved(self):
        for value in (r"^(?<1>a)(b)\1$", r"^(?<1>a)(?<grp>b)\k<2>$",
                      r"^(?<100>a)(?<grp>b)\k<1>$", r"^(?<1>a)(?<out-001>b)\k<2>$",
                      r"^(?<100>a)(?<100>b)\k<0100>$", r"^(a)(?<01>b)\k<001>$",
                      r"^(?<1>a)(?<out-002>b)$"):
            self.assert_regex_preserved(value, kind="PROCESS-NAME-REGEX")
        for value in (r"^(?<100>a)\k<2>$", r"^(?<1>a)(b)\k<2>$",
                      r"^(?<0>a)$", r"^(?<010>a)\k<10>$", r"^(?<1>a)(?<out-003>b)$",
                      r"^(?<2147483648>a)$", r"^(?<1>a)\k<2147483648>$"):
            self.assert_regex_rejected(value)

    def test_long_numeric_declarations_and_references_have_hard_timeout(self):
        code = ("from rules import Rule, parse\n"
                "invalid = (r'^(?<' + '1' * 5000 + r'>a)$', "
                "r'^(?<100>a)\\k<' + '1' * 5000 + '>$')\n"
                "for value in invalid:\n"
                "    parsed, messages = parse(f'PROCESS-NAME-REGEX,{value},REJECT\\nDOMAIN,keep.example.com,REJECT', purpose='block')\n"
                "    assert parsed == [Rule('DOMAIN', 'keep.example.com')] and "
                "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)\n"
                "value = r'^(?<100>a)\\k<' + '0' * 5000 + '100>$'\n"
                "assert parse(f'PROCESS-NAME-REGEX,{value},REJECT', purpose='block') == "
                "([Rule('PROCESS-NAME-REGEX', value)], [])")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("超长数值声明或引用让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_long_numeric_conditions_have_hard_timeout(self):
        code = ("from rules import Rule, parse, normalize\n"
                "for capture in (r'(?<1>a)', '(a)'):\n"
                "    for digits, valid in (('0' * 5000 + '1', True), ('1' * 5000, False)):\n"
                "        value = '^' + capture + '(?(' + digits + ')b|c)$'\n"
                "        for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):\n"
                "            expression = f'(({kind},{value}),(DOMAIN,x.example.com))'\n"
                "            for source, rule in ((f'{kind},{chr(34)}{value}{chr(34)},China', Rule(kind,value)), "
                "(f'AND,{expression},China', Rule('AND',expression))):\n"
                "                parsed, messages = parse(source + '\\nDOMAIN,keep.example.com,China', purpose='proxy')\n"
                "                expected = ([rule] if valid else []) + [Rule('DOMAIN','keep.example.com')]\n"
                "                assert parsed == expected and (messages == [] if valid else "
                "len(messages) == 1 and messages[0].startswith('line 1:')), (capture, valid, kind, len(value))\n"
                "                assert set(normalize(parsed)) == set(expected)")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("超长数值条件使解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_numeric_conditions_validate_original_sparse_and_forward_slots(self):
        valid = (r"^(?<100>a)(?(100)b|c)$", r"^(?<100>a)(?(0100)b|c)$",
                 r"^(?(100)b|c)(?<100>a)$", r"^(?<grp>a)(?(1)b|c)$",
                 r"^(?<2147483647>a)(?(2147483647)b|c)$", r"^(a)(?(0)b|c)$")
        invalid = (r"^(?<100>a)(?(1)b|c)$", r"^(?<100>a)(?(01)b|c)$",
                   r"^(?<100>a)(?(101)b|c)$", r"^(?<1>a)(?(2147483648)b|c)$",
                   r"^(?<100>a)(?(100)b|c|d)$", r"^(?<100>a)(?(100x)b|c)$")
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in valid:
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in invalid:
                self.assert_regex_rejected(value, kind=kind)

    def test_conditional_headers_do_not_allocate_capture_slots(self):
        valid = (r"^(?<1>a)(b)(?(1)c|d)\k<1>$", r"^(a)(?(1)b|c)\k<1>$",
                 r"^(a)(?(1)(b)|c)\k<2>$", r"^(?(?=(a))a|b)\k<1>$",
                 r"^(?<1>a)(?:b)(?=c)(?i:d)(?(1)e|f)\k<1>$",
                 r"^(?<grp>a)(?<grp>b)(?(grp)c|d)\k<1>$")
        invalid = (r"^(?<1>a)(b)(?(1)c|d)\k<2>$", r"^(a)(?(1)b|c)\k<2>$",
                   r"^(?<1>a)(?:b)(?=c)(?i:d)(?(1)e|f)\k<2>$",
                   r"^(?<grp>a)(?<grp>b)(?(grp)c|d)\k<2>$")
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in valid:
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in invalid:
                self.assert_regex_rejected(value, kind=kind)

    def test_named_conditional_forward_references_and_expression_conditions(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^(?(grp)a|b)(?<grp>c)$", r"^(?<grp>a)(?(grp)b|c)$",
                          r"^(?(missing)a|b)$"):
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in (r"^(?(missing)a|b)\k<missing>$", r"^(?(missing)a|b)\k<1>$"):
                self.assert_regex_rejected(value, kind=kind)

    def test_legacy_capture_references_share_slot_and_numeric_validation(self):
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX"):
            for value in (r"^(?<100>a)\<0100>$", r"^(?<100>a)\'0100'$",
                          r"^(?<grp>a)\<grp>$", r"^(?<grp>a)\'grp'$",
                          r"^\<100>(?<100>a)$", r"^\<0>$",
                          r"^(?<2147483647>a)\<2147483647>$",
                          r"^[\<100>]$", r"^[\'100']$", r"^[\<2147483648>]$",
                          r"^\<100$"):
                self.assert_regex_preserved(value, kind=kind, following_rule=True)
            for value in (r"^(?<100>a)\<101>$", r"^(?<100>a)\<0101>$",
                          r"^(?<100>a)\'101'$", r"^(?<100>a)\<2147483648>$",
                          r"^\<100>$", r"^\<missing>$", r"^(a)\'missing'$",
                          r"^\<2147483648$", r"^[\k<1>]$"):
                self.assert_regex_rejected(value, kind=kind)

    def test_long_legacy_capture_references_have_hard_timeout(self):
        code = ("from rules import Rule, parse\n"
                "for opening, closing in ((r'\\<', '>'), (chr(92) + chr(39), chr(39))):\n"
                "    for digits, valid in (('0' * 5000 + '100', True), ('1' * 5000, False)):\n"
                "        value = r'^(?<100>a)' + opening + digits + closing + '$'\n"
                "        for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):\n"
                "            expression = f'(({kind},{value}),(DOMAIN,x.example.com))'\n"
                "            for source, rule in ((f'{kind},{chr(34)}{value}{chr(34)},China', Rule(kind,value)), "
                "(f'AND,{expression},China', Rule('AND',expression))):\n"
                "                parsed, messages = parse(source + '\\nDOMAIN,keep.example.com,China', purpose='proxy')\n"
                "                expected = ([rule] if valid else []) + [Rule('DOMAIN','keep.example.com')]\n"
                "                assert parsed == expected and (messages == [] if valid else "
                "len(messages) == 1 and messages[0].startswith('line 1:')), (valid, kind, len(value))\n"
                "    value = '^[' + opening + '1' * 5000 + closing + ']$'\n"
                "    assert parse(f'DOMAIN-REGEX,{chr(34)}{value}{chr(34)},China', purpose='proxy') == "
                "([Rule('DOMAIN-REGEX',value)], [])")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("超长旧式数值引用使解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_group_atoms_and_initial_class_states_have_hard_timeout(self):
        for middle, quantifier in (("", "*"), (r"[\]]", ""), ("[^^]", "")):
            code = ("from rules import Rule, parse\n"
                    f"value = '^' + '(' * 495 + {middle!r} + ')' * 495 + {quantifier!r} + r'\\k<1>$'\n"
                    "assert parse(f'DOMAIN-REGEX,{value},REJECT', purpose='block') == "
                    "([Rule('DOMAIN-REGEX', value)], []), value\n"
                    "invalid = '^' + '(' * 495 + 'a**' + ')' * 495 + r'\\k<1>$'\n"
                    "parsed, messages = parse(f'DOMAIN-REGEX,{invalid},REJECT\\nDOMAIN,x.example.com,REJECT', purpose='block')\n"
                    "assert parsed == [Rule('DOMAIN', 'x.example.com')] and "
                    "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)")
            with self.subTest(middle=middle, quantifier=quantifier):
                try:
                    result = subprocess.run([sys.executable, "-c", code],
                                            cwd=Path(__file__).resolve().parents[1],
                                            capture_output=True, text=True, timeout=4)
                except subprocess.TimeoutExpired:
                    self.fail("深层空组量词或字符类让解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_empty_group_quantifier_and_reference_have_hard_timeout(self):
        for depth in (510, 1000):
            code = ("from rules import Rule, parse, normalize\n"
                    f"value = '^' + '(' * {depth} + ')' * {depth} + r'*\\k<1>$'\n"
                    "for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):\n"
                    "    expression = f'(({kind},{value}),(DOMAIN,x.example.com))'\n"
                    "    for source, expected in ((f'{kind},{value},REJECT', Rule(kind,value)), "
                    "(f'AND,{expression},REJECT', Rule('AND',expression))):\n"
                    "        parsed, messages = parse(source + '\\nDOMAIN,keep.example.com,REJECT', purpose='block')\n"
                    "        assert parsed == [expected, Rule('DOMAIN', 'keep.example.com')] and messages == [], (parsed, messages)\n"
                    "        assert set(normalize(parsed)) == set(parsed)")
            with self.subTest(depth=depth):
                try:
                    result = subprocess.run([sys.executable, "-c", code],
                                            cwd=Path(__file__).resolve().parents[1],
                                            capture_output=True, text=True, timeout=4)
                except subprocess.TimeoutExpired:
                    self.fail("深层空组量词与引用让解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_empty_atoms_quantifiers_and_numeric_references_have_hard_timeout(self):
        code = ("from rules import Rule, parse\n"
                "for depth in (510, 1000):\n"
                "    for quantifier, reference in (('', ''), ('', r'\\k<1>'), ('*', ''), "
                "('+', r'\\1'), ('?', r'\\10'), ('{0,2}', r'\\k<010>'), ('*?', r'\\k<1>')):\n"
                "        value = '^' + '(' * depth + ')' * depth + quantifier + reference + '$'\n"
                "        parsed, messages = parse(f'PROCESS-NAME-REGEX,{value},REJECT\\nDOMAIN,keep.example.com,REJECT', purpose='block')\n"
                "        assert parsed == [Rule('PROCESS-NAME-REGEX', value), Rule('DOMAIN', 'keep.example.com')] "
                "and messages == [], (depth, quantifier, reference, parsed, messages)")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("深层空原子与量词对照让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_invalid_empty_atom_neighbors_warn_under_hard_timeout(self):
        code = ("from rules import Rule, parse\n"
                "depth = 510\n"
                "values = ('^' + '(' * depth + ')' * depth + r'**\\k<1>$', "
                "'^' + '(' * depth + ')' * depth + r'{3,2}\\k<1>$', "
                "'^' + '(' * depth + '*' + ')' * depth + '$', "
                "'^' + '(' * depth + ')' * (depth-1) + r'*\\k<1>$', "
                "'^' + '(' * depth + ')' * (depth+1) + r'*\\k<1>$', "
                "'^' + '(' * depth + ')' * depth + r'*\\k<511>$')\n"
                "for value in values:\n"
                "    for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX'):\n"
                "        expression = f'(({kind},{value}),(DOMAIN,x.example.com))'\n"
                "        for source in (f'{kind},{value},REJECT', f'AND,{expression},REJECT'):\n"
                "            parsed, messages = parse(source + '\\nDOMAIN,keep.example.com,REJECT', purpose='block')\n"
                "            assert parsed == [Rule('DOMAIN', 'keep.example.com')] and "
                "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)")
        try:
            result = subprocess.run([sys.executable, "-c", code],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("非法深层空原子让解析子进程超时")
        self.assertEqual(result.returncode, 0, result.stderr[-1600:])

    def test_deep_invalid_backreferences_and_structure_warn_under_hard_timeout(self):
        for closers, reference in ((495, r"\k<496>"), (496, r"\k<1>"), (494, r"\k<1>")):
            code = ("from rules import Rule, parse\n"
                    f"value = '^' + '(' * 495 + 'a' + ')' * {closers} + {reference!r} + '$'\n"
                    "source = f'DOMAIN-REGEX,{value},REJECT\\nDOMAIN,x.example.com,REJECT'\n"
                    "parsed, messages = parse(source, purpose='block')\n"
                    "assert parsed == [Rule('DOMAIN', 'x.example.com')] and "
                    "len(messages) == 1 and messages[0].startswith('line 1:'), (parsed, messages)")
            with self.subTest(closers=closers, reference=reference):
                try:
                    result = subprocess.run([sys.executable, "-c", code],
                                            cwd=Path(__file__).resolve().parents[1],
                                            capture_output=True, text=True, timeout=4)
                except subprocess.TimeoutExpired:
                    self.fail("非法深层引用让解析子进程超时")
                self.assertEqual(result.returncode, 0, result.stderr[-1600:])


class WhitelistTests(unittest.TestCase):
    def test_qx_policy_is_ignored_when_parsing_whitelist(self):
        self.assertEqual(rules.parse_whitelist("host-suffix,a.com,DIRECT"), [
            Rule("DOMAIN-SUFFIX", "a.com", domain_source="qx")
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

    def test_whitelist_ipv6_alias_and_surge_source_network_keep_directions(self):
        whitelist = rules.parse_whitelist(
            "IP-CIDR,2001:db8::/32\nSRC-IP,192.0.2.1/24"
        )
        self.assertEqual(whitelist, [
            Rule("IP-CIDR", "2001:db8::/32"), Rule("SRC-IP-CIDR", "192.0.2.0/24"),
        ])
        original = [
            Rule("IP-CIDR6", "2001:db8:1::/48"),
            Rule("SRC-IP-CIDR", "192.0.2.128/25"), Rule("IP-CIDR", "192.0.2.0/24"),
        ]
        self.assertEqual(rules.exclude_covered(original, whitelist), original[2:])

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

    def test_source_asn_geoip_and_ip_suffix_whitelist_only_cover_equal_source_values(self):
        whitelist = rules.parse_whitelist(
            "IP-ASN,64500,PROXY,src\nGEOIP,CN,PROXY,src\n"
            "IP-SUFFIX,203.0.113.1/24,PROXY,src\n"
        )
        self.assertEqual(whitelist, [
            Rule("SRC-IP-ASN", "64500"), Rule("SRC-GEOIP", "CN"),
            Rule("SRC-IP-SUFFIX", "203.0.113.1/24"),
        ])
        blocked, messages = parse(
            "IP-ASN,64500,REJECT,src\nGEOIP,CN,REJECT,src\n"
            "IP-SUFFIX,203.0.113.1/24,REJECT,src\n"
            "IP-ASN,64500,REJECT\nGEOIP,CN,REJECT\nIP-SUFFIX,203.0.113.1/24,REJECT\n"
            "IP-ASN,64501,REJECT,src\nGEOIP,US,REJECT,src\n"
            "IP-SUFFIX,203.0.113.2/24,REJECT,src\n",
            purpose="block",
        )
        self.assertEqual(messages, [])
        self.assertEqual(rules.exclude_covered(blocked, whitelist), blocked[3:])
        self.assertEqual(rules.exclude_covered(
            [Rule("IP-SUFFIX", "203.0.113.1/24")],
            rules.parse_whitelist("IP-SUFFIX,203.0.113.1/24"),
        ), [])

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

    def test_normalize_deduplicates_ipv6_ip_cidr_alias(self):
        parsed, messages = parse(
            "IP-CIDR,2001:db8::/33,PROXY\nIP-CIDR,2001:db8:8000::/33,PROXY\n"
            "IP-CIDR6,2001:db8::/32,PROXY",
            purpose="proxy",
        )
        self.assertEqual(messages, [])
        self.assertEqual(normalize(parsed), [Rule("IP-CIDR6", "2001:db8::/32")])

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
