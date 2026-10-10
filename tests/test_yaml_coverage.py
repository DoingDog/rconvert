import json
import unittest

from formats import render
from rules import Rule, parse


SURGE_SUFFIX = r'DOMAIN-REGEX,(?-i:(?:\A|\.)[eE][xX][aA][mM][pP][lL][eE]\.[cC][oO][mM]\.?\z)'
SURGE_EXACT = r'DOMAIN-REGEX,(?-i:\A[eE][xX][aA][mM][pP][lL][eE]\.[cC][oO][mM]\.?\z)'


class YamlCoverageTests(unittest.TestCase):
    def test_public_render_removes_native_suffix_covered_by_surge(self):
        surge, surge_warnings = parse('DOMAIN-SUFFIX,example.com\n', purpose='proxy')
        native, native_warnings = parse('payload:\n  - DOMAIN-SUFFIX,example.com\n', purpose='proxy')
        self.assertEqual((surge_warnings, native_warnings), ([], []))

        output, skipped = render('fixture', surge + native, purpose='proxy', no_resolve='keep')

        self.assertEqual(output['fin.yaml'],
                         '# fixture rules: 1\npayload:\n  - ' + json.dumps(SURGE_SUFFIX) + '\n')
        self.assertEqual(output['fin.txt'], '# fixture rules: 1\nDOMAIN-SUFFIX,example.com\n')
        self.assertEqual(output['fin-qx.txt'], '# fixture rules: 1\nHOST-SUFFIX,example.com,LIST\n')
        self.assertEqual(output['fin-surge-ds.txt'], '# fixture rules: 1\n.example.com\n')
        self.assertEqual(output['fin-surge.txt'], '# fixture rules: 0\n')
        self.assertFalse(any(key.startswith('fin.yaml:') for key in skipped))

    def test_public_render_removes_native_exact_covered_by_surge_exact(self):
        surge, surge_warnings = parse('DOMAIN,example.com\n', purpose='proxy')
        native, native_warnings = parse('payload:\n  - DOMAIN,example.com\n', purpose='proxy')
        self.assertEqual((surge_warnings, native_warnings), ([], []))

        output, _ = render('fixture', surge + native, purpose='proxy', no_resolve='keep')

        self.assertEqual(output['fin.yaml'],
                         '# fixture rules: 1\npayload:\n  - ' + json.dumps(SURGE_EXACT) + '\n')

    def test_surge_suffix_covers_native_exact_and_child_suffix(self):
        surge, surge_warnings = parse('DOMAIN-SUFFIX,example.com\n', purpose='proxy')
        native, native_warnings = parse(
            'payload:\n  - DOMAIN,EXAMPLE.COM\n  - DOMAIN,child.example.com\n'
            '  - DOMAIN-SUFFIX,child.example.com\n  - DOMAIN-SUFFIX,grand.child.example.com\n',
            purpose='proxy',
        )
        self.assertEqual((surge_warnings, native_warnings), ([], []))

        output, _ = render('fixture', surge + native, purpose='proxy', no_resolve='keep')

        self.assertEqual(output['fin.yaml'],
                         '# fixture rules: 1\npayload:\n  - ' + json.dumps(SURGE_SUFFIX) + '\n')
        self.assertEqual(output['fin-surge-ds.txt'],
                         '# fixture rules: 5\nEXAMPLE.COM\n.example.com\nchild.example.com\n'
                         '.child.example.com\n.grand.child.example.com\n')

    def test_surge_projection_covers_qx_literal_domains(self):
        for kind, qx_text, expected in (
                ('DOMAIN', 'HOST,example.com,PROXY\n', SURGE_EXACT),
                ('DOMAIN-SUFFIX', 'HOST,example.com,PROXY\nHOST-SUFFIX,child.example.com,PROXY\n',
                 SURGE_SUFFIX)):
            with self.subTest(kind=kind):
                surge, surge_warnings = parse(kind + ',example.com\n', purpose='proxy')
                qx, qx_warnings = parse(qx_text, purpose='proxy')
                self.assertEqual((surge_warnings, qx_warnings), ([], []))

                output, _ = render('fixture', surge + qx, purpose='proxy', no_resolve='keep')

                self.assertEqual(output['fin.yaml'],
                                 '# fixture rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')

    def test_unknown_source_preserves_shared_native_payload(self):
        rules = [Rule('DOMAIN-SUFFIX', 'example.com'),
                 Rule('DOMAIN', 'example.com', domain_source='mihomo'),
                 Rule('DOMAIN', 'example.com', domain_source='unknown')]

        output, _ = render('fixture', rules, purpose='proxy', no_resolve='keep')

        self.assertEqual(output['fin.yaml'],
                         '# fixture rules: 2\npayload:\n  - "DOMAIN,example.com"\n  - '
                         + json.dumps(SURGE_SUFFIX) + '\n')

    def test_single_label_domains_use_existing_public_validation(self):
        for kind, expected in (
                ('DOMAIN', r'DOMAIN-REGEX,(?-i:\A[cC][oO][mM]\.?\z)'),
                ('DOMAIN-SUFFIX', r'DOMAIN-REGEX,(?-i:(?:\A|\.)[cC][oO][mM]\.?\z)')):
            with self.subTest(kind=kind):
                surge, surge_warnings = parse(kind + ',com\n', purpose='proxy')
                native, native_warnings = parse('payload:\n  - DOMAIN,com\n', purpose='proxy')
                self.assertEqual((surge_warnings, native_warnings), ([], []))

                output, _ = render('fixture', surge + native, purpose='proxy', no_resolve='keep')

                self.assertEqual(output['fin.yaml'],
                                 '# fixture rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')

    def assert_yaml_payloads(self, rules, expected, *, no_resolve='keep', purpose='proxy'):
        output, skipped = render('fixture', rules, purpose=purpose, no_resolve=no_resolve)
        yaml_lines = output['fin.yaml'].splitlines()
        self.assertEqual(yaml_lines[:2], ['# fixture rules: ' + str(len(expected)), 'payload:'])
        self.assertCountEqual([json.loads(line[4:]) for line in yaml_lines[2:]], expected)
        return output, skipped

    def test_coverage_uses_effective_interface_options(self):
        for broad_options, literal_options in (
                (('force-cellular',), ()), ((), ('multi-interface',)),
                (('via-interface=en1',), ('multi-interface-balance',))):
            with self.subTest(broad_options=broad_options, literal_options=literal_options):
                self.assert_yaml_payloads(
                    [Rule('DOMAIN-SUFFIX', 'example.com', broad_options),
                     Rule('DOMAIN', 'example.com', literal_options, domain_source='qx')],
                    [SURGE_SUFFIX],
                )

    def test_unemittable_options_or_allow_cannot_cover_literal(self):
        for attributes in ({'allow': True}, {'options': ('unsupported',)},
                           {'options': ('no-resolve',)},
                           {'options': ('force-cellular', 'unsupported')}):
            for source in ('mihomo', 'qx'):
                with self.subTest(attributes=attributes, source=source):
                    output, skipped = self.assert_yaml_payloads(
                        [Rule('DOMAIN-SUFFIX', 'example.com', **attributes),
                         Rule('DOMAIN', 'example.com', domain_source=source)],
                        ['DOMAIN,example.com'], purpose='block',
                    )
                    self.assertEqual(skipped['fin.yaml:DOMAIN-SUFFIX'], 1)
                    if attributes == {'allow': True}:
                        self.assertIn('@@||example.com^\n', output['fin-adb.txt'])
        output, skipped = self.assert_yaml_payloads(
            [Rule('DOMAIN-SUFFIX', 'example.com'),
             Rule('DOMAIN', 'example.com', allow=True, domain_source='mihomo')],
            [SURGE_SUFFIX], purpose='block',
        )
        self.assertEqual(skipped['fin.yaml:DOMAIN'], 1)
        self.assertIn('@@|example.com|\n', output['fin-adb.txt'])

    def test_no_resolve_mode_is_applied_before_coverage(self):
        rules = [Rule('DOMAIN-SUFFIX', 'example.com', ('no-resolve',)),
                 Rule('DOMAIN', 'example.com', domain_source='mihomo'),
                 Rule('IP-CIDR', '192.0.2.0/24')]
        for mode, expected in (
                ('keep', ['DOMAIN,example.com', 'IP-CIDR,192.0.2.0/24']),
                ('add', ['DOMAIN,example.com', 'IP-CIDR,192.0.2.0/24,no-resolve']),
                ('strip', [SURGE_SUFFIX, 'IP-CIDR,192.0.2.0/24'])):
            with self.subTest(mode=mode):
                _, skipped = self.assert_yaml_payloads(rules, expected, no_resolve=mode)
                self.assertEqual(skipped.get('fin.yaml:DOMAIN-SUFFIX', 0), int(mode != 'strip'))
        self.assert_yaml_payloads(
            [Rule('DOMAIN-SUFFIX', 'example.com'),
             Rule('DOMAIN', 'example.com', ('no-resolve',), domain_source='mihomo')],
            [SURGE_SUFFIX], no_resolve='strip',
        )

    def test_exact_and_reverse_coverage_preserve_broader_rules(self):
        child_suffix = (r'DOMAIN-REGEX,(?-i:(?:\A|\.)[cC][hH][iI][lL][dD]\.'
                        r'[eE][xX][aA][mM][pP][lL][eE]\.[cC][oO][mM]\.?\z)')
        cases = (
            ([Rule('DOMAIN', 'example.com'),
              Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')],
             [SURGE_EXACT, 'DOMAIN-SUFFIX,example.com']),
            ([Rule('DOMAIN', 'example.com'),
              Rule('DOMAIN', 'child.example.com', domain_source='mihomo')],
             [SURGE_EXACT, 'DOMAIN,child.example.com']),
            ([Rule('DOMAIN-SUFFIX', 'child.example.com'),
              Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')],
             [child_suffix, 'DOMAIN-SUFFIX,example.com']),
            ([Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo'),
              Rule('DOMAIN', 'child.example.com', domain_source='qx')],
             ['DOMAIN-SUFFIX,example.com', 'DOMAIN,child.example.com']),
        )
        for rules, expected in cases:
            with self.subTest(rules=rules):
                self.assert_yaml_payloads(rules, expected)
        for value in ('notexample.com', 'example.com.evil'):
            for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                with self.subTest(kind=kind, value=value):
                    self.assert_yaml_payloads(
                        [Rule('DOMAIN-SUFFIX', 'example.com'),
                         Rule(kind, value, domain_source='mihomo')],
                        [SURGE_SUFFIX, kind + ',' + value],
                    )

    def test_unknown_sources_cannot_participate_in_coverage(self):
        for source in ('unknown', 'SURGE'):
            with self.subTest(source=source):
                self.assert_yaml_payloads(
                    [Rule('DOMAIN-SUFFIX', 'example.com', domain_source=source),
                     Rule('DOMAIN', 'child.example.com', domain_source='mihomo')],
                    ['DOMAIN-SUFFIX,example.com', 'DOMAIN,child.example.com'],
                )
                self.assert_yaml_payloads(
                    [Rule('DOMAIN-SUFFIX', 'example.com'),
                     Rule('DOMAIN', 'child.example.com', domain_source=source)],
                    [SURGE_SUFFIX, 'DOMAIN,child.example.com'],
                )

    def test_unicode_domains_keep_unproven_cross_source_relationships(self):
        for source in ('mihomo', 'qx'):
            for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                for value in ('K.example.com', 'İ.example.com', '例子.example.com'):
                    with self.subTest(source=source, kind=kind, value=value):
                        self.assert_yaml_payloads(
                            [Rule('DOMAIN-SUFFIX', 'example.com'),
                             Rule(kind, value, domain_source=source)],
                            [SURGE_SUFFIX, kind + ',' + value],
                        )
        self.assert_yaml_payloads(
            [Rule('DOMAIN-SUFFIX', 'K.example.com'),
             Rule('DOMAIN-SUFFIX', 'k.example.com', domain_source='mihomo')],
            ['DOMAIN-SUFFIX,K.example.com', 'DOMAIN-SUFFIX,k.example.com'],
        )

    def test_native_root_dot_is_preserved(self):
        surge, surge_warnings = parse('DOMAIN-SUFFIX,example.com\n', purpose='proxy')
        native, native_warnings = parse(
            'payload:\n  - DOMAIN,example.com.\n  - DOMAIN-SUFFIX,child.example.com.\n',
            purpose='proxy',
        )
        self.assertEqual((surge_warnings, native_warnings), ([], []))

        self.assert_yaml_payloads(
            surge + native,
            [SURGE_SUFFIX, 'DOMAIN,example.com.', 'DOMAIN-SUFFIX,child.example.com.'],
        )

    def test_wildcard_keyword_and_arbitrary_regex_relationships_are_preserved(self):
        matchers = [Rule('DOMAIN-WILDCARD', '*.example.com', domain_source='mihomo'),
                    Rule('DOMAIN-WILDCARD', '*.example.com', domain_source='qx'),
                    Rule('DOMAIN-KEYWORD', 'example.com', domain_source='mihomo'),
                    Rule('DOMAIN-REGEX', r'.*example\.com')]
        for matcher in matchers:
            with self.subTest(matcher=matcher):
                literal = matcher.kind + ',' + matcher.value
                self.assert_yaml_payloads(
                    [matcher, Rule('DOMAIN', 'child.example.com', domain_source='mihomo')],
                    [literal, 'DOMAIN,child.example.com'],
                )
                self.assert_yaml_payloads(
                    [Rule('DOMAIN-SUFFIX', 'example.com'), matcher],
                    [SURGE_SUFFIX, literal],
                )

    def test_existing_domain_validation_limits_coverage(self):
        self.assert_yaml_payloads(
            [Rule('DOMAIN-SUFFIX', 'example.com'),
             Rule('DOMAIN', '-child.example.com', domain_source='mihomo')],
            [SURGE_SUFFIX, 'DOMAIN,-child.example.com'],
        )
        self.assert_yaml_payloads(
            [Rule('DOMAIN-SUFFIX', '192.0.2.1'),
             Rule('DOMAIN', 'child.192.0.2.1', domain_source='mihomo')],
            [r'DOMAIN-REGEX,(?-i:(?:\A|\.)192\.0\.2\.1\.?\z)', 'DOMAIN,child.192.0.2.1'],
        )

    def test_mixed_sources_preserve_all_other_target_bodies(self):
        rules = [Rule('DOMAIN-SUFFIX', 'example.com'),
                 Rule('DOMAIN', 'child.example.com', domain_source='mihomo'),
                 Rule('DOMAIN-SUFFIX', 'child.example.com', domain_source='mihomo'),
                 Rule('DOMAIN', 'example.com', domain_source='qx'),
                 Rule('DOMAIN-SUFFIX', 'grand.example.com', domain_source='qx')]
        output, skipped = self.assert_yaml_payloads(rules, [SURGE_SUFFIX], purpose='block')
        expected = {
            'fin.txt': ['DOMAIN,example.com', 'DOMAIN,child.example.com',
                        'DOMAIN-SUFFIX,example.com', 'DOMAIN-SUFFIX,child.example.com',
                        'DOMAIN-SUFFIX,grand.example.com'],
            'fin-qx.txt': ['HOST,example.com,LIST', 'HOST,child.example.com,LIST',
                           'HOST-SUFFIX,example.com,LIST', 'HOST-SUFFIX,child.example.com,LIST',
                           'HOST-SUFFIX,grand.example.com,LIST'],
            'fin-surge-ds.txt': ['example.com', '.example.com', 'child.example.com',
                                 '.child.example.com', '.grand.example.com'],
            'fin-surge.txt': [],
        }
        for name, body in expected.items():
            with self.subTest(name=name):
                self.assertEqual(output[name], '# fixture rules: ' + str(len(body)) + '\n'
                                 + ''.join(line + '\n' for line in body))
        self.assertEqual(output['fin-adb.txt'].splitlines()[6], '! Total count: 5')
        self.assertCountEqual(output['fin-adb.txt'].splitlines()[7:],
                              ['||example.com^', '||child.example.com^', '||grand.example.com^',
                               '0.0.0.0 example.com', '0.0.0.0 child.example.com'])
        self.assertFalse(any(key.startswith('fin.yaml:') for key in skipped))

    def test_covering_projection_must_be_in_same_render_call(self):
        surge = Rule('DOMAIN-SUFFIX', 'example.com')
        self.assert_yaml_payloads([surge], [SURGE_SUFFIX])

        output, _ = render('separate', [Rule('DOMAIN', 'example.com', domain_source='mihomo')],
                           whitelist=[surge], purpose='block', no_resolve='keep')

        self.assertEqual(output['fin.yaml'],
                         '# separate rules: 1\npayload:\n  - "DOMAIN,example.com"\n')
        self.assertIn('@@||example.com^\n', output['fin-adb.txt'])


if __name__ == '__main__':
    unittest.main()
