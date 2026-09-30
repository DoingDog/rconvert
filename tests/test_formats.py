import json
import re
import unittest
from datetime import datetime, timezone
from functools import partial
from unittest.mock import patch

from rules import Rule
from formats import render as render_configured


render = partial(render_configured, purpose="block", no_resolve="add")


class SurgeEscapedFieldFormatTests(unittest.TestCase):
    def test_shared_fields_encode_literal_quotes_and_backslashes_exactly(self):
        from rules import parse

        cases = (
            ("Game\\", '"Game\\\\"'),
            ("'Game\\\\", '"\'Game\\\\\\\\"'),
            ('"Game\'Inc"', '"\\"Game\'Inc\\""'),
            ("'Game\"Inc'", '"\'Game\\"Inc\'"'),
            ('"Game\\', '"\\"Game\\\\"'),
            ("'Game\\", '"\'Game\\\\"'),
            ("Game\\\\\\", '"Game\\\\\\\\\\\\"'),
        )
        for kind in ("PROCESS-NAME", "DEVICE-NAME", "USER-AGENT", "URL-REGEX"):
            for value, field in cases:
                if kind == "URL-REGEX" and (len(value) - len(value.rstrip("\\"))) % 2:
                    continue
                with self.subTest(kind=kind, value=value):
                    source = Rule(kind, value)
                    out, skipped = render_configured("group", [source], purpose="proxy", no_resolve="keep")
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], f"# group rules: 1\n{kind},{field}\n")
                        self.assertEqual(parse(out[name], purpose="proxy"), ([source], []))
                        self.assertNotIn(f"{name}:{kind}", skipped)

    def test_native_and_mixed_logic_encode_fields_without_losing_ip_options(self):
        from rules import parse

        values = ("Game\\", "Game\\\\", "Game\\\\\\", "'Game\\\\", '"Game\'Inc"', "'Game\"Inc'", '"Game\\', "'Game\\")
        for leaf in ("PROCESS-NAME", "PROCESS-PATH"):
            for value in values:
                payload = "/Applications/" + value if leaf == "PROCESS-PATH" else value
                field = '"' + payload.replace("\\", "\\\\").replace('"', '\\"') + '"'
                for operator in ("AND", "OR", "NOT"):
                    expression = (f"(({leaf},{payload}))" if operator == "NOT" else
                                  f"(({leaf},{payload}),(IP-CIDR,192.0.2.0/24,no-resolve),"
                                  "(SRC-IP-CIDR,198.51.100.0/24))")
                    native, messages = parse("payload:\n  - " + json.dumps(f"{operator},{expression}"), purpose="proxy")
                    self.assertEqual(messages, [])
                    mixed = f"{operator}," + expression.replace(f"{leaf},{payload}", f"{leaf},{field}") + ",PROXY"
                    for source in (native, parse(mixed, purpose="proxy")[0]):
                        for mode in ("keep", "add", "strip"):
                            with self.subTest(leaf=leaf, value=value, operator=operator, mode=mode, native=source == native):
                                self.assertEqual(len(source), 1)
                                out, skipped = render_configured("group", source, purpose="proxy", no_resolve=mode)
                                expected = expression.replace(",no-resolve", "") if mode == "strip" else expression
                                yaml = [json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]]
                                self.assertEqual(yaml, [f"{operator},{expected}"])
                                for name in ("fin.txt", "fin-surge.txt"):
                                    self.assertIn(f"(PROCESS-NAME,", out[name])
                                    self.assertNotIn(f"{name}:{operator}", skipped)
                                    reparsed, warnings = parse(out[name], purpose="proxy")
                                    self.assertEqual(warnings, [])
                                    rerendered, _ = render_configured("next", reparsed, purpose="proxy", no_resolve=mode)
                                    self.assertEqual([json.loads(line[4:]) for line in rerendered["fin.yaml"].splitlines()[2:]],
                                                     [f"{operator},{expected}"])


class LiteralQuoteFieldFormatTests(unittest.TestCase):
    def test_literal_quote_fields_preserve_matchers_in_surge_outputs(self):
        from rules import parse

        cases = (
            ('"Game"', '\'"Game"\''),
            ("'Game'", '"\'Game\'"'),
            ('"Game', '\'"Game\''),
            ("'Game", '"\'Game"'),
            (r'"Game\wInc"', '\'"Game\\wInc"\''),
            (r"'Game\wInc'", '"\'Game\\\\wInc\'"'),
            (r'"Game\"Inc"', r"""'"Game\"Inc"'"""),
            (r"'Game\'Inc'", r'''"'Game\\'Inc'"'''),
            ('Game"Inc', 'Game"Inc'),
            ("Game'Inc", "Game'Inc"),
            ('Game\'"Inc', 'Game\'"Inc'),
            ('"Game,Inc"', '\'"Game,Inc"\''),
        )
        for kind in ("PROCESS-NAME", "DEVICE-NAME", "USER-AGENT", "URL-REGEX"):
            for value, field in cases:
                with self.subTest(kind=kind, value=value):
                    source = Rule(kind, value)
                    out, skipped = render_configured("group", [source], purpose="proxy", no_resolve="keep")
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], f"# group rules: 1\n{kind},{field}\n")
                        self.assertEqual(parse(out[name], purpose="proxy"), ([source], []))
                        self.assertNotIn(f"{name}:{kind}", skipped)
                    if kind == "PROCESS-NAME" and "," not in value:
                        self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                         [f"{kind},{value}"])

    def test_mixed_logic_quote_roles_and_regexp2_matchers_remain_exact(self):
        from rules import parse

        cases = (
            ('AND,((PROCESS-NAME,"Game"),(DOMAIN,x.example.com)),PROXY',
             'AND,((PROCESS-NAME,Game),(DOMAIN,x.example.com))',
             'AND,((PROCESS-NAME,Game),(DOMAIN,x.example.com))'),
            ('AND,((PROCESS-NAME,\'"Game"\'),(DOMAIN,x.example.com)),PROXY',
             'AND,((PROCESS-NAME,\'"Game"\'),(DOMAIN,x.example.com))',
             'AND,((PROCESS-NAME,"Game"),(DOMAIN,x.example.com))'),
            ('OR,((PROCESS-NAME,"\'Game\'"),(DOMAIN,x.example.com)),PROXY',
             'OR,((PROCESS-NAME,"\'Game\'"),(DOMAIN,x.example.com))',
             "OR,((PROCESS-NAME,'Game'),(DOMAIN,x.example.com))"),
            ('NOT,((URL-REGEX,\'"Game\\w,Inc"\')),PROXY',
             'NOT,((URL-REGEX,\'"Game\\w,Inc"\'))', None),
        )
        for source, surge, yaml in cases:
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(messages, [])
                self.assertEqual(len(parsed), 1)
                self.assertFalse(parsed[0].native_fields)
                out, skipped = render_configured("group", parsed, purpose="proxy", no_resolve="keep")
                for name in ("fin.txt", "fin-surge.txt"):
                    self.assertEqual(out[name], f"# group rules: 1\n{surge}\n")
                    reparsed, warnings = parse(out[name], purpose="proxy")
                    self.assertEqual(warnings, [])
                    rendered, _ = render_configured("next", reparsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual(rendered[name], f"# next rules: 1\n{surge}\n")
                    self.assertNotIn(f"{name}:{parsed[0].kind}", skipped)
                self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                 [yaml] if yaml is not None else [])
                self.assertEqual(skipped.get(f"fin.yaml:{parsed[0].kind}", 0), int(yaml is None))
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for native in (False, True):
                value = '"Game\\w,Inc"'
                field = value if native else '\'' + value + '\''
                expression = f"(({kind},{field}),(DOMAIN,x.example.com))"
                source = ("payload:\n  - " + json.dumps("AND," + expression)
                          if native else "AND," + expression + ",PROXY")
                with self.subTest(kind=kind, native=native):
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual(messages, [])
                    out, skipped = render_configured("group", parsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                     [f'AND,(({kind},"Game\\w,Inc"),(DOMAIN,x.example.com))'])
                    self.assertNotIn("fin.yaml:AND", skipped)

    def test_unrepresentable_quote_fields_skip_whole_surge_rule_and_keep_native_rule(self):
        from rules import parse

        # 字面 * 仍无法保留到 Surge；引号和反斜杠自身的可表达值由上面的回归测试覆盖。
        values = ('"Game\'Inc*"', "'Game\"Inc*'", '"Game*\\', "'Game*\\")
        for value in values:
            cases = [("PROCESS-NAME", value)] + [
                (kind, f"((PROCESS-NAME,{value}),(DOMAIN,x.example.com))")
                for kind in ("AND", "OR")
            ] + [("NOT", f"((PROCESS-NAME,{value}))"),
                 ("AND", f"((OR,((PROCESS-NAME,{value}),(DOMAIN,x.example.com))),"
                         "(DOMAIN,other.example.com))")]
            for kind, matcher in cases:
                with self.subTest(value=value, kind=kind, matcher=matcher):
                    document = "payload:\n  - " + json.dumps(f"{kind},{matcher}")
                    parsed, messages = parse(document, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(parsed, [Rule(kind, matcher, literal_process=True,
                                                  native_fields=kind != "PROCESS-NAME")])
                    out, skipped = render_configured("group", parsed + [Rule("DOMAIN-KEYWORD", "keep")],
                                                     purpose="proxy", no_resolve="keep")
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], "# group rules: 1\nDOMAIN-KEYWORD,keep\n")
                        self.assertEqual(skipped[f"{name}:{kind}"], 1)
                    self.assertEqual({json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
                                     {f"{kind},{matcher}", "DOMAIN-KEYWORD,keep"})
                    self.assertNotIn(f"fin.yaml:{kind}", skipped)
        for value in ('"Game\\\\', '"Game\\\\\\\\'):
            with self.subTest(even_backslashes=value):
                out, skipped = render_configured("group", [Rule("PROCESS-NAME", value)],
                                                 purpose="proxy", no_resolve="keep")
                for name in ("fin.txt", "fin-surge.txt"):
                    self.assertEqual(parse(out[name], purpose="proxy"), ([Rule("PROCESS-NAME", value)], []))
                    self.assertNotIn(f"{name}:PROCESS-NAME", skipped)


class NativeFieldFix8FormatTests(unittest.TestCase):
    def test_native_logic_inner_quotes_and_comma_have_exact_decoded_payload(self):
        from rules import normalize, parse

        expression = '((DOMAIN-REGEX,"*ads"),(PROCESS-NAME-REGEX,^Game,Inc$))'
        parsed, messages = parse("payload:\n  - 'AND," + expression + "'", purpose="proxy")
        self.assertEqual(messages, [])
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode):
                out, skipped = render_configured("group", normalize(parsed), purpose="proxy", no_resolve=mode)
                self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                 ["AND," + expression])
                self.assertNotIn("fin.yaml:AND", skipped)
                self.assertEqual(out["fin-qx.txt"], "# group rules: 0\n")
                self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_same_logic_text_with_different_source_quotes_is_not_merged(self):
        from rules import normalize, parse

        expression = '((DOMAIN-REGEX,"^ads$"),(DOMAIN,x.example.com))'
        native = parse("payload:\n  - 'AND," + expression + "'", purpose="proxy")[0]
        mixed = parse("AND," + expression + ",PROXY", purpose="proxy")[0]
        out, _ = render_configured("group", normalize(native + mixed), purpose="proxy", no_resolve="strip")
        self.assertEqual({json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
                         {"AND," + expression, "AND,((DOMAIN-REGEX,^ads$),(DOMAIN,x.example.com))"})


class SourceFieldContinuationFormatTests(unittest.TestCase):
    def test_source_regex_markers_round_trip_in_surge_outputs(self):
        from rules import parse

        for value in ("^foo #bar$", "^foo ;bar$", "^foo //bar$", "(?x)^foo # ignored,PROXY"):
            with self.subTest(value=value):
                expected = Rule("URL-REGEX", value)
                out, skipped = render_configured("group", [expected], purpose="proxy", no_resolve="keep")
                for name in ("fin.txt", "fin-surge.txt"):
                    self.assertEqual(parse(out[name], purpose="proxy"), ([expected], []))
                    self.assertNotIn(f"{name}:URL-REGEX", skipped)

    def test_rule_rebuilds_keep_native_fields(self):
        from rules import normalize, parse_whitelist

        source = Rule("IP-CIDR", "192.0.2.0/25", ("force-cellular", "no-resolve"), native_fields=True)
        for mode in ("add", "strip", "keep"):
            with self.subTest(mode=mode), patch("formats.Rule", wraps=Rule) as clone:
                render_configured("group", [source], purpose="proxy", no_resolve=mode)
                self.assertTrue(clone.called)
                for call in clone.call_args_list:
                    self.assertTrue(call.args[5])
        collapsed = normalize([Rule("IP-CIDR", "192.0.2.0/25", native_fields=True),
                               Rule("IP-CIDR", "192.0.2.128/25", native_fields=True)])
        self.assertEqual(collapsed, [Rule("IP-CIDR", "192.0.2.0/24", native_fields=True)])
        with patch("rules.parse", return_value=(collapsed, [])):
            self.assertEqual(parse_whitelist("ignored"), [Rule("IP-CIDR", "192.0.2.0/24", native_fields=True)])


class FormatTests(unittest.TestCase):
    def test_wildcard_survives_compatible_targets(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-*.example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.txt"])
        self.assertIn("HOST-WILDCARD,api-*.example.com,LIST", out["fin-qx.txt"])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.yaml"])
        self.assertNotIn("api-*.example.com", out["fin-surge-ds.txt"])

    def test_wildcard_does_not_remove_exact_domain_from_surge_domain_set(self):
        out, _ = render("a3", [
            Rule("DOMAIN-WILDCARD", "api-*.example.org"), Rule("DOMAIN", "api-v2.example.org"),
        ])
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 1\napi-v2.example.org\n")
        self.assertIn("HOST-WILDCARD,api-*.example.org,LIST\n", out["fin-qx.txt"])
        self.assertIn("HOST,api-v2.example.org,LIST\n", out["fin-qx.txt"])
        self.assertIn('  - "DOMAIN-WILDCARD,api-*.example.org"\n', out["fin.yaml"])
        self.assertIn('  - "DOMAIN,api-v2.example.org"\n', out["fin.yaml"])

    def test_surge_character_class_wildcard_is_converted_for_mihomo_but_not_qx(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-[0-9].example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin.txt"])
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [r"DOMAIN-REGEX,^api\-[0-9]\.example\.com$"])
        self.assertEqual(skipped["fin-qx.txt:DOMAIN-WILDCARD"], 1)
        self.assertNotIn("fin.yaml:DOMAIN-WILDCARD", skipped)
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 1", r"/^api\-[0-9]\.example\.com$/"])

    def test_character_class_wildcard_preserves_digit_only_scope_for_mihomo_and_dns(self):
        source = Rule("DOMAIN-WILDCARD", "api-[0-9].example.com")
        for allow in (False, True):
            with self.subTest(allow=allow):
                out, skipped = render("a3", [Rule(source.kind, source.value, allow=allow)])
                if not allow:
                    self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin.txt"])
                    self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin-surge.txt"])
                    self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                     [r"DOMAIN-REGEX,^api\-[0-9]\.example\.com$"])
                    self.assertNotIn("fin.yaml:DOMAIN-WILDCARD", skipped)
                expected_dns = ("@@" if allow else "") + r"/^api\-[0-9]\.example\.com$/"
                self.assertIn(expected_dns, out["fin-adb.txt"].splitlines()[7:])
                dns_rule = out["fin-adb.txt"].splitlines()[7]
                expression = re.compile(dns_rule.removeprefix("@@")[1:-1])
                self.assertIsNotNone(expression.fullmatch("api-7.example.com"))
                for domain in ("api-a.example.com", "api-7.exampleXcom", "api-7.example.com.evil"):
                    self.assertIsNone(expression.fullmatch(domain))
                self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

    def test_portable_domain_regex_emits_dns_block_and_allow_only(self):
        value = r"^api[0-9]\.example\.com$"
        out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                     Rule("DOMAIN-REGEX", value, allow=True)])
        self.assertEqual(out["fin-adb.txt"].splitlines()[7:],
                         [f"@@/{value}/", f"/{value}/"])
        self.assertEqual(json.loads(out["fin.yaml"].splitlines()[2][4:]),
                         f"DOMAIN-REGEX,{value}")
        self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)
        expression = re.compile(value)
        self.assertIsNotNone(expression.fullmatch("api7.example.com"))
        self.assertIsNone(expression.fullmatch("apia.example.com"))

    def test_go_portable_domain_regex_emits_literal_dns_block_and_allow(self):
        cases = (
            (r"^ads\.example\.com\z", r"/^ads\.example\.com\z/", r"@@/^ads\.example\.com\z/"),
            (r"^api\d\.example\.com$", r"/^api\p{Nd}\.example\.com$/", r"@@/^api\p{Nd}\.example\.com$/"),
            (r"^(?:ads|track)\.example\.com$", r"/^(?:ads|track)\.example\.com$/", r"@@/^(?:ads|track)\.example\.com$/"),
            (r"^(?<name>ads)\.example\.com$", r"/^(?<name>ads)\.example\.com$/", r"@@/^(?<name>ads)\.example\.com$/"),
        )
        for value, block, allow in cases:
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 2", allow, block])
                self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)

    def test_adguard_portable_capture_flags_and_property_emit_block_and_allow(self):
        cases = (
            (r"^(?<n>ad)(?<n>s)\.example\.com$",
             r"/^(?<n>ad)(?<n>s)\.example\.com$/",
             r"@@/^(?<n>ad)(?<n>s)\.example\.com$/"),
            (r"^(?i:ads)\.example\.com$",
             r"/^(?i:ads)\.example\.com$/",
             r"@@/^(?i:ads)\.example\.com$/"),
            (r"^\p{L}+\.example\.com$",
             r"/^\p{L}+\.example\.com$/",
             r"@@/^\p{L}+\.example\.com$/"),
        )
        for value, block, allow in cases:
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 2", allow, block])
                self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)

    def test_regexp2_zero_padded_repetition_keeps_its_count_in_dns(self):
        cases = (
            (r"^a{01}\.example\.com$", r"/^a{1}\.example\.com$/",
             r"@@/^a{1}\.example\.com$/"),
            (r"^a{00,01}\.example\.com$", r"/^a{0,1}\.example\.com$/",
             r"@@/^a{0,1}\.example\.com$/"),
            (r"^a{0001,}\.example\.com$", r"/^a{1,}\.example\.com$/",
             r"@@/^a{1,}\.example\.com$/"),
        )
        for value, block, allow in cases:
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 2", allow, block])
                self.assertIn(f"DOMAIN-REGEX,{value}",
                              [json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])
                self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)

    def test_go_invalid_property_range_stays_out_of_dns(self):
        value = r"^[a-\p{L}]+\.example\.com$"
        out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                     Rule("DOMAIN-REGEX", value, allow=True)])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 2)
        self.assertIn(f"DOMAIN-REGEX,{value}",
                      [json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])

    def test_go_valid_property_class_followed_by_literal_hyphen_emits_dns(self):
        value = r"^[\p{L}-a]+\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def _assert_domain_regex_dns(self, value, dns_value):
        from rules import parse

        parsed, messages = parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block")
        self.assertEqual(messages, [])
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value)])
        out, skipped = render("a3", parsed + [Rule("DOMAIN-REGEX", value, allow=True)])
        expected_dns = (["! Total count: 0"] if dns_value is None else
                        ["! Total count: 2", f"@@/{dns_value}/", f"/{dns_value}/"])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], expected_dns)
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - ' +
                         json.dumps(f"DOMAIN-REGEX,{value}", ensure_ascii=False) + "\n")
        expected_skipped = {"fin.yaml:DOMAIN-REGEX": 1}
        for name in ("fin.txt", "fin-qx.txt", "fin-surge.txt", "fin-surge-ds.txt"):
            self.assertEqual(out[name], "# a3 rules: 0\n")
            expected_skipped[f"{name}:DOMAIN-REGEX"] = 2
        if dns_value is None:
            expected_skipped["fin-adb.txt:DOMAIN-REGEX"] = 2
        self.assertEqual(skipped, expected_skipped)
        for allow in (False, True):
            single, single_skipped = render("a3", [Rule("DOMAIN-REGEX", value, allow=allow)])
            expected_single = (["! Total count: 0"] if dns_value is None else
                               ["! Total count: 1", ("@@" if allow else "") + f"/{dns_value}/"])
            self.assertEqual(single["fin-adb.txt"].splitlines()[6:], expected_single)
            self.assertEqual(single_skipped.get("fin-adb.txt:DOMAIN-REGEX", 0),
                             1 if dns_value is None else 0)

    def test_posix_looking_classes_stay_out_of_dns(self):
        for value in (r"^[[:alpha:]-a]+\.example\.com$", r"^[[:alpha:]]+\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_posix_class_literal_braces_are_preserved_in_yaml_and_skipped_in_dns(self):
        self._assert_domain_regex_dns(r"^[[:alpha:]{01}]+\.example\.com$", None)

    def test_regexp2_class_subtraction_stays_out_of_dns(self):
        self._assert_domain_regex_dns(r"^[a-z-[aeiou]]+\.example\.com$", None)

    def test_unicode_decimal_digit_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^\d+\.example\.com$", r"^\p{Nd}+\.example\.com$")

    def test_unicode_decimal_digit_class_combination_stays_out_of_dns(self):
        self._assert_domain_regex_dns(r"^[a\d]+\.example\.com$", None)

    def test_literal_backslash_digit_is_not_translated_for_dns(self):
        value = r"^\\d\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_character_class_literal_braces_are_not_rewritten_as_quantifiers(self):
        value = r"^[a{01}]+\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_absolute_anchors_are_preserved_for_dns(self):
        value = r"\Aads\.example\.com\z"
        self._assert_domain_regex_dns(value, value)

    def test_braced_hex_atom_is_preserved_for_dns(self):
        value = r"^\x{61}ds\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unproved_nonascii_hex_casefold_stays_out_of_dns(self):
        self._assert_domain_regex_dns(r"^\x{130}\.example\.com$", None)

    def test_nested_counted_repetition_respects_go_combined_limit(self):
        self._assert_domain_regex_dns(r"^(?:\w{500}){3}\.example\.com$", None)
        self._assert_domain_regex_dns(r"^(?:\w{500}){2}\.example\.com$",
                                      r"^(?:[\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]{500}){2}\.example\.com$")
        value = r"^(?:a{500}){0,1}\.example\.com$"
        self._assert_domain_regex_dns(value, value)
        value = r"^(?:(?:a{500}){0}){3}\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_zero_minimum_unbounded_repeat_preserves_inner_go_budget(self):
        for atom in (r"\d{500}", "a{500}", "a{0500}"):
            for repeat in ("{0,}", "{00,}"):
                value = rf"^(?:(?:{atom}|b){repeat}){{3}}\.example\.com$"
                with self.subTest(value=value):
                    self._assert_domain_regex_dns(value, None)
        for value in (r"^(?:(?:a{500}){0,}|b){3}\.example\.com$",
                      r"^((a{500}|b){00,}){03}\.example\.com$",
                      r"^(?:(?:(?:a{250}|b){0,}){2}){3}\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_zero_minimum_repeat_keeps_valid_go_boundaries(self):
        for repeat, normalized in (("{0,}", "{0,}"), ("{00,}", "{0,}"),
                                   ("*", "*"), ("+", "+"), ("?", "?"),
                                   ("{1,}", "{1,}"), ("{0001,}", "{1,}"),
                                   ("{0,1}", "{0,1}"), ("{00,01}", "{0,1}")):
            value = rf"^(?:(?:a{{500}}|b){repeat}){{2}}\.example\.com$"
            dns_value = rf"^(?:(?:a{{500}}|b){normalized}){{2}}\.example\.com$"
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, dns_value)
        for repeat, normalized in (("{0}", "{0}"), ("{0,0}", "{0,0}"),
                                   ("{00}", "{0}"), ("{00,00}", "{0,0}")):
            value = rf"^(?:(?:a{{500}}){repeat}|b){{3}}\.example\.com$"
            dns_value = rf"^(?:(?:a{{500}}){normalized}|b){{3}}\.example\.com$"
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, dns_value)
        value = r"^(?:(?:\d{0500}|b){00,}){02}\.example\.com$"
        self._assert_domain_regex_dns(value, r"^(?:(?:\p{Nd}{500}|b){0,}){2}\.example\.com$")
        value = r"^(?:(?:a{250}|b){0,2}){2}\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unicode_nd_property_is_preserved_for_dns(self):
        value = r"^\p{Nd}\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unicode_nondigit_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^ad\Dtrack\.example\.com$",
                                      r"^ad\P{Nd}track\.example\.com$")

    def test_unicode_word_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^\w+\.example\.com$",
                                      r"^[\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]+\.example\.com$")

    def test_unicode_nonword_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^ad\Wtrack\.example\.com$",
                                      r"^ad[^\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]track\.example\.com$")

    def test_unicode_space_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^ads\s?\.example\.com$",
                                      r"^ads[\x09-\x0D\x{85}\p{Z}]?\.example\.com$")

    def test_unicode_nonspace_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^\S+\.example\.com$",
                                      r"^[^\x09-\x0D\x{85}\p{Z}]+\.example\.com$")

    def test_unproved_unicode_class_combinations_stay_out_of_dns(self):
        for atom in (r"\d", r"\D", r"\w", r"\W", r"\s", r"\S", r"\p{Nd}"):
            for value in (rf"^[a{atom}]+\.example\.com$", rf"^[]{atom}]+\.example\.com$",
                          rf"^[^]{atom}]+\.example\.com$"):
                with self.subTest(value=value):
                    self._assert_domain_regex_dns(value, None)

    def test_unicode_boundary_and_ignorecase_lowercase_property_stay_out_of_dns(self):
        for value in (r"^\bads\.example\.com$", r"^\p{Ll}\.example\.com$",
                      r"^(?i:\p{Ll})\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_literal_backslashes_before_unicode_atoms_are_preserved(self):
        for atom in ("d", "D", "w", "W", "s", "S", "b", "p{Nd}", "x{61}", "A", "z"):
            value = rf"^\\{atom}\.example\.com$"
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, value)
        self._assert_domain_regex_dns(r"^\\\d\.example\.com$", r"^\\\p{Nd}\.example\.com$")
        value = r"^[a\\d]+\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unsupported_regex_constructs_keep_yaml_and_dns_skip_counts(self):
        for value in (r"^ads/track\.example\.com$", r"^ads\/track\.example\.com$",
                      r"^ads{01001}\.example\.com$", r"^(ads)\1\.example\.com$",
                      r"^(?<name>ads)\k<name>\.example\.com$", r"^ads(?=track)\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_go_invalid_repetition_is_not_emitted_or_counted_in_dns(self):
        value = r"^ads{0,1001}\.example\.com$"
        out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                     Rule("DOMAIN-REGEX", value, allow=True)])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 2)
        self.assertIn(f"DOMAIN-REGEX,{value}",
                      [json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])

    def test_regexp2_only_domain_regex_stays_out_of_dns(self):
        for value in (r"^(ads)\1\.example\.com$", r"^ads(?=track)\.example\.com$",
                      r"^(?<name>ads)\k<name>\.example\.com$"):
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
                self.assertIn(f"DOMAIN-REGEX,{value}",
                              [json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])
                self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 2)

    def test_client_accepted_regexp2_rules_keep_go_portable_property_in_dns(self):
        from rules import parse

        values = [r"^\p{L}+\.example\.com$", r"^\x{61}ds\.example\.com$",
                  r"^\Gads\.example\.com$", r"^a+(?<=a+)ds\.example\.com$"]
        source = "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values)
        parsed, messages = parse(source + "\nPROCESS-NAME-REGEX,^[(?P]$,REJECT", purpose="block")
        self.assertEqual(messages, [])
        out, skipped = render("a3", parsed)
        self.assertEqual({json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
                         {f"DOMAIN-REGEX,{value}" for value in values} |
                         {"PROCESS-NAME-REGEX,^[(?P]$"})
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 2", r"/^\p{L}+\.example\.com$/",
                          r"/^\x{61}ds\.example\.com$/"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], len(values) - 2)
        self.assertEqual(skipped["fin-adb.txt:PROCESS-NAME-REGEX"], 1)

    def test_six_files_are_ordered_and_count_actual_lines(self):
        high = Rule("DOMAIN-WILDCARD", "z-*.example.com")
        low = Rule("DOMAIN-WILDCARD", "a-*.example.com")
        with patch("formats.datetime") as clock:
            clock.now.side_effect = lambda tz: datetime(2026, 9, 29, tzinfo=timezone.utc).astimezone(tz)
            out, _ = render("a3", iter([high, low]))
            reordered, _ = render("a3", iter([low, high]))
        self.assertEqual(set(out), {
            "fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt",
            "fin-surge.txt", "fin-surge-ds.txt",
        })
        self.assertEqual(out, reordered)
        self.assertEqual(out["fin.txt"],
                         "# a3 rules: 2\nDOMAIN-WILDCARD,a-*.example.com\nDOMAIN-WILDCARD,z-*.example.com\n")
        self.assertTrue(all(body.endswith("\n") and "\r" not in body for body in out.values()))

    def test_render_sorts_each_output_type_by_final_line_length_then_text(self):
        out, _ = render("a3", [
            Rule("NETWORK", "udp"), Rule("DOMAIN-SUFFIX", "q.org"),
            Rule("DOMAIN", "long.example.org"), Rule("DOMAIN", "z.org"),
            Rule("DOMAIN-KEYWORD", "ad"), Rule("DOMAIN-SUFFIX", "b.org"),
            Rule("DOMAIN", "a.org"),
        ])
        adb = out.pop("fin-adb.txt")
        self.assertEqual(adb.splitlines()[6:], ["! Total count: 6", "a.org", "z.org", "||b.org^", "||q.org^", "/^.*ad.*$/", "long.example.org"])
        self.assertEqual(out, {
            "fin.txt": "# a3 rules: 7\nDOMAIN,a.org\nDOMAIN,z.org\nDOMAIN,long.example.org\nDOMAIN-KEYWORD,ad\nDOMAIN-SUFFIX,b.org\nDOMAIN-SUFFIX,q.org\nPROTOCOL,UDP\n",
            "fin-qx.txt": "# a3 rules: 6\nHOST,a.org,LIST\nHOST,z.org,LIST\nHOST,long.example.org,LIST\nHOST-KEYWORD,ad,LIST\nHOST-SUFFIX,b.org,LIST\nHOST-SUFFIX,q.org,LIST\n",
            "fin.yaml": '# a3 rules: 7\npayload:\n  - "DOMAIN,a.org"\n  - "DOMAIN,z.org"\n  - "DOMAIN,long.example.org"\n  - "DOMAIN-KEYWORD,ad"\n  - "DOMAIN-SUFFIX,b.org"\n  - "DOMAIN-SUFFIX,q.org"\n  - "NETWORK,udp"\n',
            "fin-surge.txt": "# a3 rules: 2\nDOMAIN-KEYWORD,ad\nPROTOCOL,UDP\n",
            "fin-surge-ds.txt": "# a3 rules: 5\na.org\nz.org\n.b.org\n.q.org\nlong.example.org\n",
        })

    def test_ip_types_follow_other_types_and_split_same_type_by_address_family(self):
        out, _ = render("a3", [
            Rule("SRC-IP-CIDR", "2001:db8::/32"), Rule("IP-CIDR", "2001:db8::/32"),
            Rule("IP-ASN", "64500"), Rule("GEOIP", "CN"),
            Rule("SRC-IP-CIDR", "192.0.2.0/24"), Rule("IP-CIDR", "192.0.2.0/24"),
            Rule("NETWORK", "udp"), Rule("DOMAIN", "a.org"),
        ])
        self.assertEqual(out["fin.txt"].splitlines()[1:], [
            "DOMAIN,a.org", "PROTOCOL,UDP", "GEOIP,CN,no-resolve", "IP-ASN,64500,no-resolve",
            "IP-CIDR,192.0.2.0/24,no-resolve", "SRC-IP,192.0.2.0/24",
            "IP-CIDR6,2001:db8::/32,no-resolve", "SRC-IP,2001:db8::/32",
        ])
        self.assertEqual(out["fin-qx.txt"].splitlines()[1:], [
            "HOST,a.org,LIST", "GEOIP,CN,LIST,no-resolve", "IP-ASN,64500,LIST,no-resolve",
            "IP-CIDR,192.0.2.0/24,LIST,no-resolve", "IP6-CIDR,2001:db8::/32,LIST,no-resolve",
        ])
        self.assertEqual(out["fin.yaml"].splitlines()[2:], [
            '  - "DOMAIN,a.org"', '  - "NETWORK,udp"', '  - "GEOIP,CN,no-resolve"',
            '  - "IP-ASN,64500,no-resolve"', '  - "IP-CIDR,192.0.2.0/24,no-resolve"',
            '  - "SRC-IP-CIDR,192.0.2.0/24"', '  - "IP-CIDR,2001:db8::/32,no-resolve"',
            '  - "SRC-IP-CIDR,2001:db8::/32"',
        ])
        self.assertEqual(out["fin-surge.txt"].splitlines()[1:], [
            "PROTOCOL,UDP", "GEOIP,CN,no-resolve", "IP-ASN,64500,no-resolve",
            "IP-CIDR,192.0.2.0/24,no-resolve", "SRC-IP,192.0.2.0/24",
            "IP-CIDR6,2001:db8::/32,no-resolve", "SRC-IP,2001:db8::/32",
        ])

    def test_adblock_exceptions_precede_shorter_blocks_and_duplicates_are_removed(self):
        with patch("formats.datetime") as clock:
            clock.now.side_effect = lambda tz: datetime(2026, 9, 28, 16, 45, tzinfo=timezone.utc).astimezone(tz)
            out, _ = render("a3", [
                Rule("DOMAIN", "a.org"), Rule("DOMAIN", "b.org"),
                Rule("DOMAIN-SUFFIX", "example.org"), Rule("DOMAIN", "b.org", allow=True),
            ], whitelist=[
                Rule("DOMAIN", "z.org"), Rule("DOMAIN", "a.org"),
                Rule("DOMAIN", "a.org"), Rule("DOMAIN-SUFFIX", "example.org"),
            ])
        self.assertEqual(out["fin-adb.txt"],
                         "[Adblock Plus 2.0]\n! Title: a3\n! Homepage: https://github.com/DoingDog/rconvert\n"
                         "! Expires: 1 day\n! License: Inherits upstream licenses\n"
                         "! Version: 202609290045\n! Total count: 7\n"
                         "@@|a.org|\n@@|b.org|\n@@|z.org|\n@@||example.org^\na.org\nb.org\n||example.org^\n")

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
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 1", "exact.example.com"])
        self.assertNotIn("fin-adb.txt:DOMAIN", skipped)

    def test_suffix_is_shared_by_domain_set_and_adblock(self):
        out, skipped = render("a3", [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertIn("DOMAIN-SUFFIX,ads.example.com\n", out["fin.txt"])
        self.assertIn("HOST-SUFFIX,ads.example.com,LIST\n", out["fin-qx.txt"])
        self.assertIn('  - "DOMAIN-SUFFIX,ads.example.com"\n', out["fin.yaml"])
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 1\n.ads.example.com\n")
        self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 1", "||ads.example.com^"])
        self.assertNotIn("fin-adb.txt:DOMAIN-SUFFIX", skipped)

    def test_keyword_with_dot_is_literal_in_dns_regex(self):
        out, skipped = render("a3", [Rule("DOMAIN-KEYWORD", "ad.track")])
        self.assertGreater(len(out["fin-adb.txt"].splitlines()), 7)
        line = out["fin-adb.txt"].splitlines()[7]
        self.assertTrue(line.startswith("/^") and line.endswith("$/"))
        expression = re.compile(line[1:-1])
        self.assertIsNotNone(expression.fullmatch("cdn.ad.track.example.org"))
        self.assertIsNone(expression.fullmatch("cdn.adXtrack.example.org"))
        self.assertNotIn("fin-adb.txt:DOMAIN-KEYWORD", skipped)

    def test_safe_wildcard_is_anchored_in_dns_regex(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-*.example.org")])
        self.assertGreater(len(out["fin-adb.txt"].splitlines()), 7)
        line = out["fin-adb.txt"].splitlines()[7]
        self.assertTrue(line.startswith("/^") and line.endswith("$/"))
        expression = re.compile(line[1:-1])
        self.assertIsNotNone(expression.fullmatch("api-v2.example.org"))
        for domain in ("other-api-v2.example.org", "api-v2.example.org.evil", "api-v2.exampleXorg"):
            with self.subTest(domain=domain):
                self.assertIsNone(expression.fullmatch(domain))
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

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

    def test_source_ip_family_keeps_direction_per_target(self):
        out, skipped = render("a3", [
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
            Rule("SRC-IP-SUFFIX", "8.8.8.8/24"),
            Rule("SRC-GEOIP", "CN"), Rule("SRC-IP-ASN", "64512"),
        ])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("SRC-IP,192.0.2.0/24\n", out[name])
            self.assertNotIn("IP-CIDR,192.0.2.0/24", out[name])
        self.assertIn('  - "SRC-IP-CIDR,192.0.2.0/24"\n', out["fin.yaml"])
        for entry in ("SRC-IP-SUFFIX,8.8.8.8/24", "SRC-GEOIP,CN", "SRC-IP-ASN,64512"):
            self.assertIn(f'  - "{entry}"\n', out["fin.yaml"])
            self.assertNotIn(entry, out["fin.txt"])
            self.assertNotIn(entry, out["fin-surge.txt"])
            self.assertNotIn(entry, out["fin-qx.txt"])
        self.assertNotIn("192.0.2.0/24", out["fin-qx.txt"])
        self.assertEqual(skipped["fin-qx.txt:SRC-IP-CIDR"], 1)
        self.assertEqual(skipped["fin-qx.txt:SRC-IP-SUFFIX"], 1)

    def test_ip_suffix_no_resolve_is_mihomo_only(self):
        out, skipped = render("a3", [
            Rule("IP-SUFFIX", "8.8.8.8/24", ("no-resolve", "NO-RESOLVE")),
        ])
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "IP-SUFFIX,8.8.8.8/24,no-resolve"\n')
        for name in ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-surge-ds.txt"):
            self.assertNotIn("8.8.8.8/24", out[name])
            self.assertEqual(skipped[f"{name}:IP-SUFFIX"], 1)

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

    def test_process_name_regex_quantifier_comma_survives_mihomo_top_level_and_logic(self):
        from rules import parse

        for source, expected in (
            ("PROCESS-NAME-REGEX,^Foo{1,2}Bar$,PROXY",
             "PROCESS-NAME-REGEX,^Foo{1,2}Bar$"),
            ("AND,((PROCESS-NAME-REGEX,^Foo{1,2}Bar$),(DOMAIN,a.example.com)),PROXY",
             "AND,((PROCESS-NAME-REGEX,^Foo{1,2}Bar$),(DOMAIN,a.example.com))"),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(messages, [])
                self.assertEqual(len(parsed), 1)
                out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
                self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
                self.assertEqual(skipped, {
                    f"{name}:{parsed[0].kind}": 1 for name in
                    ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                })

    def test_surge_absolute_process_names_keep_exact_and_glob_path_scope_in_mihomo(self):
        from rules import parse

        for path, mihomo_kind in (("/usr/bin/ssh", "PROCESS-PATH"),
                                  ("/usr/*/ssh", "PROCESS-PATH-WILDCARD")):
            for source, surge_rule, mihomo_rule in (
                (f"PROCESS-NAME,{path},PROXY", f"PROCESS-NAME,{path}",
                 f"{mihomo_kind},{path}"),
                (f"AND,((PROCESS-NAME,{path}),(DOMAIN,a.example.com)),PROXY",
                 f"AND,((PROCESS-NAME,{path}),(DOMAIN,a.example.com))",
                 f"AND,(({mihomo_kind},{path}),(DOMAIN,a.example.com))"),
            ):
                with self.subTest(source=source):
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(len(parsed), 1)
                    out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual(out["fin.txt"], f"# cdn rules: 1\n{surge_rule}\n")
                    self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
                    self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - ' + json.dumps(mihomo_rule) + '\n')
                    self.assertEqual(skipped, {
                        f"{name}:{parsed[0].kind}": 1 for name in
                        ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                    })

    def test_mihomo_literal_process_name_absolute_path_remains_name(self):
        from rules import parse

        for source, expected in (
            ('payload:\n  - "PROCESS-NAME,/usr/bin/ssh"', "PROCESS-NAME,/usr/bin/ssh"),
            ('payload:\n  - "AND,((PROCESS-NAME,/usr/bin/ssh),(DOMAIN,a.example.com))"',
             "AND,((PROCESS-NAME,/usr/bin/ssh),(DOMAIN,a.example.com))"),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(messages, [])
                out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
                self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
                self.assertEqual(skipped, {
                    f"{name}:{parsed[0].kind}": 1 for name in
                    ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                })

    def test_mihomo_literal_process_path_metacharacters_do_not_become_surge_globs(self):
        from rules import parse

        for path in ("/Applications/Foo*Bar", "/Applications/Foo?Bar"):
            for source, expected in (
                (f'payload:\n  - "PROCESS-PATH,{path}"', f"PROCESS-PATH,{path}"),
                (f'payload:\n  - "AND,((PROCESS-PATH,{path}),(DOMAIN,a.example.com))"',
                 f"AND,((PROCESS-PATH,{path}),(DOMAIN,a.example.com))"),
            ):
                with self.subTest(source=source):
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual(messages, [])
                    out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                    self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
                    self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
                    self.assertEqual(skipped, {
                        f"{name}:{parsed[0].kind}": 1 for name in
                        ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                    })

    def test_surge_process_name_glob_keeps_wildcard_semantics_in_mihomo(self):
        out, skipped = render("dirt", [
            Rule("PROCESS-NAME", "qbittorrent*"), Rule("PROCESS-NAME", "FooApp"),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"].splitlines()[1:], [
            "PROCESS-NAME,FooApp", "PROCESS-NAME,qbittorrent*",
        ])
        self.assertEqual(out["fin-surge.txt"].splitlines()[1:], [
            "PROCESS-NAME,FooApp", "PROCESS-NAME,qbittorrent*",
        ])
        self.assertEqual(out["fin.yaml"].splitlines()[2:], [
            '  - "PROCESS-NAME,FooApp"', '  - "PROCESS-NAME-WILDCARD,qbittorrent*"',
        ])
        self.assertEqual(out["fin-qx.txt"], "# dirt rules: 0\n")
        self.assertEqual(skipped["fin-qx.txt:PROCESS-NAME"], 2)

    def test_mihomo_literal_process_wildcard_is_not_widened_for_surge(self):
        out, skipped = render_configured(
            "cdn", [Rule("PROCESS-NAME", "Foo*Bar", literal_process=True)],
            purpose="proxy", no_resolve="strip",
        )
        self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - "PROCESS-NAME,Foo*Bar"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped["fin.txt:PROCESS-NAME"], 1)
        self.assertEqual(skipped["fin-surge.txt:PROCESS-NAME"], 1)

    def test_mixed_process_source_intents_render_both_mihomo_matchers(self):
        from rules import normalize, parse

        literal, _ = parse('payload:\n  - "PROCESS-NAME,Foo*Bar"\n', purpose="proxy")
        glob, _ = parse("PROCESS-NAME,Foo*Bar,PROXY", purpose="proxy")
        for ordered in (literal + glob, glob + literal):
            with self.subTest(first_is_literal=ordered[0].literal_process):
                out, skipped = render_configured(
                    "cdn", normalize(ordered), purpose="proxy", no_resolve="keep",
                )
                self.assertEqual(out["fin.yaml"], '# cdn rules: 2\npayload:\n'
                                 '  - "PROCESS-NAME,Foo*Bar"\n'
                                 '  - "PROCESS-NAME-WILDCARD,Foo*Bar"\n')
                self.assertEqual(out["fin.txt"], "# cdn rules: 1\nPROCESS-NAME,Foo*Bar\n")
                self.assertEqual(skipped["fin.txt:PROCESS-NAME"], 1)

    def test_mihomo_literal_process_child_is_not_widened_in_surge_logic(self):
        from rules import parse

        parsed, warnings = parse(
            'payload:\n  - "AND,((OR,((PROCESS-NAME,Foo?Bar),(DOMAIN,a.example.com))),(DOMAIN,b.example.com))"\n',
            purpose="proxy",
        )
        self.assertEqual(warnings, [])
        out, skipped = render_configured("cdn", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n'
                         '  - "AND,((OR,((PROCESS-NAME,Foo?Bar),(DOMAIN,a.example.com))),(DOMAIN,b.example.com))"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin-surge.txt:AND"], 1)

    def test_qx_interface_options_emit_remote_matcher_and_report_omission(self):
        from rules import parse

        for option in ("force-cellular", "multi-interface", "via-interface=pdp_ip0"):
            with self.subTest(option=option):
                parsed, warnings = parse(
                    f"HOST-SUFFIX,googleapis.com,PROXY,{option}", purpose="proxy",
                )
                self.assertEqual(warnings, [])
                out, skipped = render_configured(
                    "cdn", parsed, purpose="proxy", no_resolve="keep",
                )
                self.assertEqual(out["fin-qx.txt"],
                                 "# cdn rules: 1\nHOST-SUFFIX,googleapis.com,LIST\n")
                self.assertEqual(out["fin.txt"],
                                 "# cdn rules: 1\nDOMAIN-SUFFIX,googleapis.com\n")
                self.assertEqual(out["fin.yaml"],
                                 '# cdn rules: 1\npayload:\n  - "DOMAIN-SUFFIX,googleapis.com"\n')
                self.assertNotIn(option, "".join(out.values()))
                self.assertEqual(skipped["fin-qx.txt:DOMAIN-SUFFIX:interface-option"], 1)

    def test_mihomo_name_wildcard_with_absolute_path_stays_out_of_surge(self):
        from rules import parse

        parsed, warnings = parse('payload:\n  - "PROCESS-NAME-WILDCARD,/usr/*/ssh"', purpose="proxy")
        self.assertEqual(warnings, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - "PROCESS-NAME-WILDCARD,/usr/*/ssh"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped, {
            "fin.txt:PROCESS-NAME-WILDCARD": 1, "fin-surge.txt:PROCESS-NAME-WILDCARD": 1,
            "fin-qx.txt:PROCESS-NAME-WILDCARD": 1, "fin-adb.txt:PROCESS-NAME-WILDCARD": 1,
            "fin-surge-ds.txt:PROCESS-NAME-WILDCARD": 1,
        })

    def test_mihomo_name_wildcard_with_absolute_path_stays_out_of_surge_logic(self):
        from rules import parse

        parsed, warnings = parse(
            'payload:\n  - "AND,((PROCESS-NAME-WILDCARD,/usr/*/ssh),(DOMAIN,a.example.com))"',
            purpose="proxy",
        )
        self.assertEqual(warnings, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n'
                         '  - "AND,((PROCESS-NAME-WILDCARD,/usr/*/ssh),(DOMAIN,a.example.com))"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped, {
            "fin.txt:AND": 1, "fin-surge.txt:AND": 1, "fin-qx.txt:AND": 1,
            "fin-adb.txt:AND": 1, "fin-surge-ds.txt:AND": 1,
        })

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

    def test_posix_process_path_wildcard_maps_to_surge_process_name(self):
        out, skipped = render("a3", [Rule("PROCESS-PATH-WILDCARD", "/Applications/Foo*/bin")])
        expected = "# a3 rules: 1\nPROCESS-NAME,/Applications/Foo*/bin\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "PROCESS-PATH-WILDCARD,/Applications/Foo*/bin"\n')
        self.assertNotIn("fin.txt:PROCESS-PATH-WILDCARD", skipped)

    def test_mihomo_skips_process_names_with_unrepresentable_commas(self):
        out, skipped = render("dirt", [
            Rule("PROCESS-NAME", "Foo,Bar"), Rule("PROCESS-PATH", "/Applications/Foo,Bar"),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"].splitlines()[1:], [
            "PROCESS-NAME,'Foo,Bar'", "PROCESS-NAME,'/Applications/Foo,Bar'",
        ])
        self.assertEqual(out["fin-surge.txt"].splitlines()[1:], [
            "PROCESS-NAME,'Foo,Bar'", "PROCESS-NAME,'/Applications/Foo,Bar'",
        ])
        self.assertEqual(out["fin.yaml"], "# dirt rules: 0\npayload:\n")
        self.assertEqual(out["fin-qx.txt"], "# dirt rules: 0\n")
        self.assertEqual(skipped["fin.yaml:PROCESS-NAME"], 1)
        self.assertEqual(skipped["fin.yaml:PROCESS-PATH"], 1)

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
        self.assertIn("/^.*ads.*$/\n", out["fin-adb.txt"])
        self.assertNotIn("fin-adb.txt:DOMAIN-KEYWORD", skipped)

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
            {f"{kind},{value}" + (",no-resolve" if kind == "IP-SUFFIX" else "")
             for kind, value in entries},
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
        self.assertIn("AND,((DOMAIN,ads.example.com),(PROTOCOL,UDP))\n", out["fin.txt"])
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertNotIn("RULE-SET", out["fin.yaml"])

    def test_logical_network_alias_is_supported_in_both_surge_rulesets(self):
        out, skipped = render("a3", [Rule("AND", "((NETWORK,udp),(DOMAIN,a.example.com))")])
        expected = "# a3 rules: 1\nAND,((PROTOCOL,UDP),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "AND,((NETWORK,udp),(DOMAIN,a.example.com))"\n')
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped, {
            "fin-qx.txt:AND": 1, "fin-adb.txt:AND": 1, "fin-surge-ds.txt:AND": 1,
        })

    def test_logical_destination_port_alias_is_supported_in_mihomo(self):
        out, skipped = render("a3", [Rule("AND", "((DEST-PORT,443),(DOMAIN,a.example.com))")])
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nAND,((DEST-PORT,443),(DOMAIN,a.example.com))\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "AND,((DST-PORT,443),(DOMAIN,a.example.com))"\n')
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_source_ip_and_protocol_aliases_keep_match_direction(self):
        source = Rule("AND", "((SRC-IP,192.0.2.1),(PROTOCOL,UDP))")
        out, skipped = render("a3", [source])
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nAND,((SRC-IP,192.0.2.1),(PROTOCOL,UDP))\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "AND,((SRC-IP-CIDR,192.0.2.1/32),(NETWORK,udp))"\n')
        self.assertNotIn("no-resolve", out["fin.yaml"])
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_source_ip_cidr_preserves_ipv4_and_ipv6_ranges_in_mihomo(self):
        from rules import parse

        parsed, messages = parse(
            "AND,((SRC-IP,192.0.2.0/24),(DOMAIN,a.example.com)),REJECT\n"
            "AND,((SRC-IP,2001:db8::/32),(DOMAIN,a.example.com)),REJECT",
            purpose="block",
        )
        self.assertEqual(messages, [])
        out, skipped = render("a3", parsed, no_resolve="add")
        self.assertEqual(out["fin.yaml"].splitlines()[2:], [
            '  - "AND,((SRC-IP-CIDR,192.0.2.0/24),(DOMAIN,a.example.com))"',
            '  - "AND,((SRC-IP-CIDR,2001:db8::/32),(DOMAIN,a.example.com))"',
        ])
        self.assertEqual(out["fin.txt"], out["fin-surge.txt"])
        self.assertIn("AND,((SRC-IP,192.0.2.0/24),(DOMAIN,a.example.com))\n", out["fin.txt"])
        self.assertIn("AND,((SRC-IP,2001:db8::/32),(DOMAIN,a.example.com))\n", out["fin.txt"])
        self.assertNotIn("no-resolve", out["fin.yaml"])
        self.assertEqual(skipped["fin-qx.txt:AND"], 2)
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_quoted_process_comma_is_preserved_for_surge_only(self):
        from rules import parse

        parsed, messages = parse('AND,((PROCESS-NAME,"Foo,Bar"),(DOMAIN,a.example.com)),PROXY', purpose="proxy")
        self.assertEqual(messages, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        expected = "# cdn rules: 1\nAND,((PROCESS-NAME,'Foo,Bar'),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(out["fin.yaml"], "# cdn rules: 0\npayload:\n")
        self.assertEqual(out["fin-surge-ds.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped["fin.yaml:AND"], 1)

    def test_logical_quoted_url_regex_comma_is_preserved_for_surge_only(self):
        from rules import parse

        parsed, messages = parse(r'OR,((URL-REGEX,"^https://ads\.example/a,b$"),(DOMAIN,a.example.com)),PROXY', purpose="proxy")
        self.assertEqual(messages, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        expected = "# cdn rules: 1\nOR,((URL-REGEX,'^https://ads\\.example/a,b$'),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(out["fin.yaml"], "# cdn rules: 0\npayload:\n")
        self.assertEqual(skipped["fin.yaml:OR"], 1)

    def test_mihomo_logical_regex_comma_retains_required_quotes(self):
        from rules import parse

        source = 'AND,((DOMAIN-REGEX,"^ads,[0-9]+[.]example$"),(DOMAIN,a.example.com)),REJECT'
        parsed, messages = parse(source, purpose="block")
        self.assertEqual(messages, [])
        out, skipped = render("a3", parsed, no_resolve="keep")
        self.assertEqual(out["fin.yaml"],
                         '# a3 rules: 1\npayload:\n  - "AND,((DOMAIN-REGEX,^ads,[0-9]+[.]example$),(DOMAIN,a.example.com))"\n')
        round_trip, warnings = parse(out["fin.yaml"], purpose="block")
        self.assertEqual(warnings, [])
        self.assertEqual(round_trip, [Rule("AND", "((DOMAIN-REGEX,^ads,[0-9]+[.]example$),(DOMAIN,a.example.com))", native_fields=True)])
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_no_resolve_add_strip_keep_changes_only_destination_ip_leaves(self):
        source = Rule("OR", "((IP-CIDR,192.0.2.0/24),(GEOIP,CN,no-resolve))")
        for mode, first, second in (
            ("add", "IP-CIDR,192.0.2.0/24,no-resolve", "GEOIP,CN,no-resolve"),
            ("strip", "IP-CIDR,192.0.2.0/24", "GEOIP,CN"),
            ("keep", "IP-CIDR,192.0.2.0/24", "GEOIP,CN,no-resolve"),
        ):
            with self.subTest(mode=mode):
                out, skipped = render("a3", [source], no_resolve=mode)
                expected = f"# a3 rules: 1\nOR,(({first}),({second}))\n"
                self.assertEqual(out["fin.txt"], expected)
                self.assertEqual(out["fin-surge.txt"], expected)
                self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - ' +
                                 json.dumps(f"OR,(({first}),({second}))") + "\n")
                self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
                self.assertNotIn("fin.txt:OR", skipped)
                self.assertNotIn("fin.yaml:OR", skipped)

    def test_nested_not_no_resolve_does_not_touch_source_ip_or_domain(self):
        source = Rule("AND", "((OR,((SRC-IP-CIDR,192.0.2.0/24),(NOT,((IP-ASN,64500,no-resolve))))),(DOMAIN,a.example.com))")
        out, skipped = render("a3", [source], no_resolve="strip")
        expected = "AND,((OR,((SRC-IP,192.0.2.0/24),(NOT,((IP-ASN,64500))))),(DOMAIN,a.example.com))"
        self.assertEqual(out["fin.txt"], f"# a3 rules: 1\n{expected}\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "AND,((OR,((SRC-IP-CIDR,192.0.2.0/24),(NOT,((IP-ASN,64500))))),(DOMAIN,a.example.com))"\n')
        self.assertNotIn("no-resolve", out["fin.txt"])
        self.assertNotIn("fin.txt:AND", skipped)

    def test_logical_ip_suffix_no_resolve_is_mihomo_only(self):
        source = Rule("NOT", "((IP-SUFFIX,8.8.8.8/24,no-resolve))")
        for mode, suffix in (("add", ",no-resolve"), ("strip", ""), ("keep", ",no-resolve")):
            with self.subTest(mode=mode):
                out, skipped = render("a3", [source], no_resolve=mode)
                self.assertEqual(out["fin.yaml"],
                                 '# a3 rules: 1\npayload:\n  - "NOT,((IP-SUFFIX,8.8.8.8/24' + suffix + '))"\n')
                self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
                self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
                self.assertEqual(skipped["fin.txt:NOT"], 1)
                self.assertEqual(skipped["fin-surge.txt:NOT"], 1)
                self.assertNotIn("fin.yaml:NOT", skipped)

    def test_logical_duplicate_no_resolve_flags_emit_once(self):
        source = Rule("AND", "((IP-CIDR,192.0.2.0/24,no-resolve,no-resolve),(DOMAIN,a.example.com))")
        out, _ = render("a3", [source], no_resolve="add")
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nAND,((IP-CIDR,192.0.2.0/24,no-resolve),(DOMAIN,a.example.com))\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "AND,((IP-CIDR,192.0.2.0/24,no-resolve),(DOMAIN,a.example.com))"\n')

    def test_unsupported_source_ip_child_skips_whole_surge_rule(self):
        source = Rule("AND", "((SRC-GEOIP,CN),(DOMAIN,a.example.com))")
        out, skipped = render("a3", [source])
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin.yaml"], '# a3 rules: 1\npayload:\n  - "AND,((SRC-GEOIP,CN),(DOMAIN,a.example.com))"\n')
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin-surge.txt:AND"], 1)

    def test_nested_process_path_wildcard_maps_to_surge_process_name(self):
        source = Rule("AND", "((PROCESS-PATH-WILDCARD,/Applications/Foo*/bin),(DOMAIN,a.example.com))")
        out, skipped = render("cdn", [source], purpose="proxy", no_resolve="keep")
        expected = "# cdn rules: 1\nAND,((PROCESS-NAME,/Applications/Foo*/bin),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(out["fin.yaml"], '# cdn rules: 1\npayload:\n  - "AND,((PROCESS-PATH-WILDCARD,/Applications/Foo*/bin),(DOMAIN,a.example.com))"\n')
        self.assertNotIn("fin.txt:AND", skipped)

    def test_surge_translates_nested_source_cidr_and_destination_port(self):
        value = "((SRC-IP-CIDR,2001:db8::/32),(DST-PORT,443))"
        out, skipped = render("a3", [Rule("AND", value)])
        expected = "AND,((SRC-IP,2001:db8::/32),(DEST-PORT,443))\n"
        self.assertIn(expected, out["fin.txt"])
        self.assertIn(expected, out["fin-surge.txt"])
        self.assertIn('  - "AND,' + value + '"\n', out["fin.yaml"])
        self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_mihomo_converts_surge_process_glob_inside_logic(self):
        value = "((PROCESS-NAME,qbittorrent*),(DOMAIN,ads.example.org))"
        out, skipped = render("dirt", [Rule("AND", value)], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"], f"# dirt rules: 1\nAND,{value}\n")
        self.assertEqual(out["fin-surge.txt"], f"# dirt rules: 1\nAND,{value}\n")
        self.assertEqual(out["fin.yaml"], '# dirt rules: 1\npayload:\n  - "AND,((PROCESS-NAME-WILDCARD,qbittorrent*),(DOMAIN,ads.example.org))"\n')
        self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_surge_ipv6_cidr_inside_logic_uses_ipv6_matcher(self):
        value = "((IP-CIDR,2001:db8::/32),(DOMAIN,ads.example.com))"
        out, _ = render("a3", [Rule("OR", value)])
        self.assertIn("OR,((IP-CIDR6,2001:db8::/32,no-resolve),(DOMAIN,ads.example.com))\n", out["fin.txt"])
        self.assertIn('  - "OR,((IP-CIDR6,2001:db8::/32,no-resolve),(DOMAIN,ads.example.com))"\n', out["fin.yaml"])

    def test_mihomo_ipv6_cidr_inside_nested_logic_uses_ipv6_matcher(self):
        from rules import parse

        source = "AND,((OR,((IP-CIDR,2001:db8::/32),(IP-CIDR,192.0.2.0/24))),(DOMAIN,ads.example.com)),REJECT"
        parsed, messages = parse(source, purpose="block")
        self.assertEqual(messages, [])
        self.assertEqual(len(parsed), 1)

        out, _ = render("a3", parsed)
        expected = "AND,((OR,((IP-CIDR6,2001:db8::/32,no-resolve),(IP-CIDR,192.0.2.0/24,no-resolve))),(DOMAIN,ads.example.com))"
        self.assertEqual(out["fin.yaml"], f'# a3 rules: 1\npayload:\n  - "{expected}"\n')
        self.assertEqual(out["fin.txt"], f"# a3 rules: 1\n{expected}\n")
        self.assertEqual(out["fin-surge.txt"], f"# a3 rules: 1\n{expected}\n")

    def test_logical_regex_character_class_parenthesis_is_not_structural(self):
        expression = r"((DOMAIN-REGEX,^[a)b]\.example$),(DOMAIN,ads.example))"
        out, _ = render("a3", [Rule("AND", expression)])
        self.assertIn(
            f"AND,{expression}",
            [json.loads(line.removeprefix("  - ")) for line in out["fin.yaml"].splitlines()[2:]],
        )

    def test_process_name_with_comma_skips_incompatible_logical_rule_as_a_whole(self):
        safe = "((DOMAIN,a.org),(DOMAIN,b.org))"
        out, skipped = render("dirt", [
            Rule("AND", "((PROCESS-NAME,Foo,Bar),(DOMAIN,ads.example.org))"),
            Rule("OR", safe),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"], f"# dirt rules: 1\nOR,{safe}\n")
        self.assertEqual(out["fin-surge.txt"], f"# dirt rules: 1\nOR,{safe}\n")
        self.assertEqual(out["fin.yaml"], f'# dirt rules: 1\npayload:\n  - "OR,{safe}"\n')
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin.yaml:AND"], 1)

    def test_blank_logical_child_skips_entire_rule_without_dropping_valid_logic(self):
        valid = "((DOMAIN,a.org),(DOMAIN,b.org))"
        out, skipped = render("dirt", [
            Rule("AND", "((DOMAIN,ads.example.com),(PROCESS-NAME,   ))"),
            Rule("OR", valid),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"], f"# dirt rules: 1\nOR,{valid}\n")
        self.assertEqual(out["fin-surge.txt"], f"# dirt rules: 1\nOR,{valid}\n")
        self.assertEqual(out["fin.yaml"], f'# dirt rules: 1\npayload:\n  - "OR,{valid}"\n')
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin.yaml:AND"], 1)

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

    def test_mihomo_converts_surge_only_wildcard_class_inside_logic(self):
        value = "((DOMAIN-WILDCARD,api-[0-9].example.com),(DOMAIN,ads.example.com))"
        out, skipped = render("a3", [Rule("AND", value)])
        self.assertEqual([json.loads(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [r"AND,((DOMAIN-REGEX,^api\-[0-9]\.example\.com$),(DOMAIN,ads.example.com))"])
        self.assertIn("AND," + value + "\n", out["fin.txt"])
        self.assertNotIn("fin.yaml:AND", skipped)

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

    def test_whitelist_keyword_and_wildcard_preserve_dns_match_scope(self):
        out, skipped = render("a3", [], whitelist=[
            Rule("DOMAIN-KEYWORD", "ad.track"),
            Rule("DOMAIN-WILDCARD", "api-*.example.org"),
            Rule("DOMAIN-WILDCARD", "api-[0-9].example.org"),
        ])
        lines = out["fin-adb.txt"].splitlines()[7:]
        self.assertEqual(len(lines), 3)
        expressions = [re.compile(line[3:-1]) for line in lines]
        self.assertTrue(all(line.startswith("@@/^") and line.endswith("$/") for line in lines))
        self.assertEqual([bool(expression.fullmatch("api-v2.example.org")) for expression in expressions],
                         [False, True, False])
        self.assertEqual([bool(expression.fullmatch("api-7.example.org")) for expression in expressions],
                         [False, True, True])
        self.assertEqual([bool(expression.fullmatch("api-a.example.org")) for expression in expressions],
                         [False, True, False])
        self.assertEqual([bool(expression.fullmatch("cdn.ad.track.example.org")) for expression in expressions],
                         [True, False, False])
        self.assertTrue(all(not expression.fullmatch("api-v2.example.org.evil") for expression in expressions))
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

    def test_custom_block_purpose_emits_dns_and_proxy_group_name_does_not(self):
        custom, _ = render("custom", [Rule("DOMAIN", "ads.example.org")],
                           purpose="block", no_resolve="keep")
        self.assertIn("\nads.example.org\n", custom["fin-adb.txt"])
        proxy, _ = render("a3", [Rule("DOMAIN", "ads.example.org")],
                          purpose="proxy", no_resolve="keep")
        self.assertNotIn("ads.example.org", proxy["fin-adb.txt"])

    def test_group_name_does_not_override_add_or_strip_no_resolve(self):
        rule = Rule("IP-CIDR", "203.0.113.0/24", ("no-resolve",))
        added, _ = render("dirt", [rule], purpose="direct", no_resolve="add")
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", added["fin.txt"])
        stripped, _ = render("a3", [rule], purpose="block", no_resolve="strip")
        self.assertIn("IP-CIDR,203.0.113.0/24\n", stripped["fin.txt"])
        self.assertNotIn("no-resolve", stripped["fin.txt"])

    def test_new_whitelist_uses_exact_and_suffix_dns_exceptions_only_for_block_groups(self):
        whitelist = [
            Rule("DOMAIN", "safe.example.org"), Rule("DOMAIN-SUFFIX", "safe.org"),
            Rule("IP-CIDR", "192.0.2.0/24"),
        ]
        out, _ = render("a3", [Rule("DOMAIN-SUFFIX", "example.org")], whitelist=whitelist)
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 3", "@@||safe.org^", "@@|safe.example.org|", "||example.org^"])
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nDOMAIN-SUFFIX,example.org\n")
        proxy, _ = render("cdn", [], whitelist=whitelist, purpose="proxy")
        self.assertEqual(proxy["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 0", "! No AdBlock rules for non-advertising group."])

    def test_simple_allow_rule_is_only_emitted_as_adblock_exception(self):
        out, skipped = render("a3", [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN", "exact.example.com", allow=True),
        ])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 2", "@@|exact.example.com|", "@@||safe.example.com^"])
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin.yaml"], "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertNotIn("fin-adb.txt:DOMAIN", skipped)
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)

    def test_unknown_and_wildcard_omissions_are_counted_per_file(self):
        out, skipped = render("a3", [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"), Rule("UNKNOWN-TYPE", "opaque"),
        ])
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)
        self.assertIn("/^api\\-.*\\.example\\.com$/\n", out["fin-adb.txt"])
        self.assertEqual(skipped.get("fin-surge-ds.txt:DOMAIN-WILDCARD"), 1)
        self.assertTrue(all(skipped.get(f"{name}:UNKNOWN-TYPE") == 1 for name in out))
        self.assertNotIn("fin-surge.txt:DOMAIN-WILDCARD", skipped)
        self.assertEqual(out["fin.txt"].splitlines()[0], "# a3 rules: 1")

    def test_non_advertising_groups_emit_only_adblock_explanation(self):
        for group in ("cdn", "big-data", "dirt"):
            with self.subTest(group=group):
                out, skipped = render(group, [Rule("DOMAIN-SUFFIX", "legitimate.example.com")], purpose="direct" if group == "dirt" else "proxy")
                self.assertEqual(out["fin-adb.txt"].splitlines()[1], f"! Title: {group}")
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                self.assertIn("DOMAIN-SUFFIX,legitimate.example.com\n", out["fin.txt"])
                self.assertEqual(skipped["fin-adb.txt:DOMAIN-SUFFIX"], 1)

    def test_non_dirt_destination_cidr_adds_no_resolve_on_supported_targets(self):
        rule = Rule("IP-CIDR", "203.0.113.0/24")
        out, _ = render("a3", [rule])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin-surge.txt"])
        self.assertIn("IP-CIDR,203.0.113.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('"IP-CIDR,203.0.113.0/24,no-resolve"', out["fin.yaml"])
        domestic, _ = render("dirt", [rule], purpose="direct", no_resolve="strip")
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
