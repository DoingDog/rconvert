import unittest

from formats import render
from rules import Rule, parse


class NativeYamlOutputTests(unittest.TestCase):
    def test_render_emits_only_native_yaml_payload(self):
        output, _ = render(
            'fixture', [Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',))],
            purpose='proxy', no_resolve='keep',
        )
        self.assertEqual(
            output['fin.yaml'],
            '# fixture rules: 1\npayload:\n  - "IP-CIDR,192.0.2.0/24,no-resolve"\n',
        )

    def test_parse_ignores_metadata_shaped_yaml_comment(self):
        parsed, warnings = parse(
            'payload:\n  - "IP-CIDR,192.0.2.0/24,no-resolve" # rconvert-rule-v1 not-json\n',
            purpose='proxy',
        )
        self.assertEqual(warnings, [])
        self.assertEqual(len(parsed), 1)
        rule = parsed[0]
        self.assertEqual(
            (rule.kind, rule.value, rule.options),
            ('IP-CIDR', '192.0.2.0/24', ('no-resolve',)),
        )

    def test_parse_ignores_any_comment_without_restoring_source_identity(self):
        for comment in ('rconvert-rule-v1 []', 'rconvert-rule-v2 {}',
                        'rconvert-rule-v1 [["DEST-PORT","443",[],false,false,false,"qx"]]'):
            with self.subTest(comment=comment):
                self.assertEqual(
                    parse('payload:\n  - "DST-PORT,443" # ' + comment + '\n', purpose='proxy'),
                    ([Rule('DST-PORT', '443')], []),
                )

    def test_invalid_native_yaml_warns_and_keeps_valid_neighbor(self):
        scalars = ('"DOMAIN,keep.example.org\\q"', '"DOMAIN,keep.example.org\\uD800"',
                   '"DOMAIN,keep.example.org" junk', '&a DOMAIN,keep.example.org')
        scalars += tuple('"DOMAIN,keep.example.org' + char + '"'
                         for char in ('\0', '\v', '\f', '\x85', ' ', ' ', '\x7f', '\udcff'))
        for scalar in scalars:
            with self.subTest(scalar=scalar):
                parsed, warnings = parse(
                    'payload:\n  - ' + scalar + ' # rconvert-rule-v1 []\n  - DOMAIN,neighbor.example.org\n',
                    purpose='proxy',
                )
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')])
                reason = ('unsupported physical line separator' if any(
                    char in scalar for char in '\0\v\f\x85  ') else 'invalid YAML payload')
                self.assertEqual(warnings, ['line 2: ' + reason])
