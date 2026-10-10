import unittest

from rules import Rule, exclude_covered


class DomainCoverageTests(unittest.TestCase):
    def test_surge_suffix_whitelist_covers_qx_ms_suffixes(self):
        rules = [
            Rule('DOMAIN-SUFFIX', 'ms', domain_source='qx'),
            Rule('DOMAIN-SUFFIX', 'sm.ms', domain_source='qx'),
        ]
        self.assertEqual(exclude_covered(rules, [Rule('DOMAIN-SUFFIX', 'ms')]), [])

    def test_surge_exact_whitelist_covers_only_matching_native_exact(self):
        for source in ('qx', 'mihomo'):
            with self.subTest(source=source):
                covered = Rule('DOMAIN', 'ADS.Example.COM', domain_source=source)
                keep = [
                    Rule('DOMAIN', 'child.ads.example.com', domain_source=source),
                    Rule('DOMAIN', 'notads.example.com', domain_source=source),
                    Rule('DOMAIN-SUFFIX', 'ads.example.com', domain_source=source),
                    Rule('DOMAIN-SUFFIX', 'example.com', domain_source=source),
                ]
                self.assertEqual(exclude_covered([covered, *keep],
                                 [Rule('DOMAIN', 'Ads.Example.Com.')]), keep)

    def test_native_exact_whitelist_preserves_broader_surge_rule(self):
        rule = Rule('DOMAIN', 'Example.COM')
        whitelist = [Rule('DOMAIN', 'example.com', domain_source='mihomo')]
        self.assertEqual(exclude_covered([rule], whitelist), [rule])

    def test_unicode_whitelist_lowercase_does_not_prove_ascii_coverage(self):
        for source in ('qx', 'mihomo'):
            for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                with self.subTest(source=source, kind=kind):
                    rule = Rule('DOMAIN', 'k.ms', domain_source=source)
                    self.assertEqual(exclude_covered([rule], [Rule(kind, 'K.ms')]), [rule])

    def test_cross_source_unicode_and_wildcard_are_preserved(self):
        rules = [
            Rule('DOMAIN', '例子.ms', domain_source='qx'),
            Rule('DOMAIN-WILDCARD', '*.ms', domain_source='qx'),
        ]
        self.assertEqual(exclude_covered(rules, [Rule('DOMAIN-SUFFIX', 'ms')]), rules)

    def test_surge_suffix_covers_native_ascii_case_and_complete_labels(self):
        for source in ('qx', 'mihomo'):
            with self.subTest(source=source):
                covered = [Rule(kind, value, domain_source=source)
                           for kind in ('DOMAIN', 'DOMAIN-SUFFIX')
                           for value in ('MS', 'Sm.Ms', 'grand.child.SM.MS')]
                keep = [Rule(kind, value, domain_source=source)
                        for kind in ('DOMAIN', 'DOMAIN-SUFFIX')
                        for value in ('s', 'smms', 'ms.other', 'sm.ms.other')]
                self.assertEqual(exclude_covered(covered + keep,
                                 [Rule('DOMAIN-SUFFIX', 'Ms.')]), keep)

    def test_confirmed_a3_a4_native_suffixes_are_whitelisted(self):
        examples = (
            ('datarouter.ol.epicgames.com', 'ol.epicgames.com'),
            ('featureassets.org', 'featureassets.org'),
            ('galileotelemetry.tencent.com', 'galileotelemetry.tencent.com'),
            ('googletraveladservices.com', 'googletraveladservices.com'),
            ('localhost.localdomain', 'localdomain'),
            ('nexusrules.officeapps.live.com', 'nexusrules.officeapps.live.com'),
            ('p.data.cctv.com', 'p.data.cctv.com'),
            ('rs.sinajs.cn', 'rs.sinajs.cn'),
            ('wpad.www.tendawifi.com', 'tendawifi.com'),
        )
        for value, parent in examples:
            with self.subTest(value=value, parent=parent):
                rule = Rule('DOMAIN-SUFFIX', value, domain_source='qx')
                self.assertEqual(exclude_covered([rule], [Rule('DOMAIN-SUFFIX', parent)]), [])

    def test_native_root_dot_literals_are_preserved_cross_source(self):
        for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
            with self.subTest(kind=kind):
                rules = [Rule(kind, value, domain_source='mihomo')
                         for value in ('MS.', 'Sm.Ms.')]
                self.assertEqual(exclude_covered(rules, [Rule('DOMAIN-SUFFIX', 'ms')]), rules)

    def test_native_whitelist_preserves_surge_suffix_and_other_source(self):
        for source, other in (('qx', 'mihomo'), ('mihomo', 'qx')):
            for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                with self.subTest(source=source, kind=kind):
                    keep = [Rule(kind, 'MS'), Rule(kind, 'MS', domain_source=other)]
                    whitelist = [Rule('DOMAIN-SUFFIX', 'ms', domain_source=source)]
                    self.assertEqual(exclude_covered(keep, whitelist), keep)

    def test_cross_source_unknown_matcher_ranges_are_preserved(self):
        for source in ('qx', 'mihomo'):
            with self.subTest(source=source):
                rules = [
                    Rule('DOMAIN', 'K.ms', domain_source=source),
                    Rule('DOMAIN-SUFFIX', '例子.ms', domain_source=source),
                    Rule('DOMAIN-WILDCARD', '*.ms', domain_source=source),
                    Rule('DOMAIN-WILDCARD', 'ads.ms', domain_source=source),
                    Rule('DOMAIN-KEYWORD', 'ads.ms', domain_source=source),
                    Rule('DOMAIN-REGEX', r'^ads\.ms$', domain_source=source),
                ]
                self.assertEqual(exclude_covered(rules, [Rule('DOMAIN-SUFFIX', 'ms')]), rules)
                literal = Rule('DOMAIN', 'ads.ms', domain_source=source)
                for kind, value in (('DOMAIN-KEYWORD', 'ms'), ('DOMAIN-WILDCARD', '*.ms'),
                                    ('DOMAIN-REGEX', r'^ads\.ms$')):
                    with self.subTest(whitelist_kind=kind):
                        self.assertEqual(exclude_covered([literal], [Rule(kind, value)]), [literal])

    def test_cross_source_coverage_requires_valid_ascii_literal_labels(self):
        for source in ('qx', 'mihomo'):
            with self.subTest(source=source):
                rules = [Rule('DOMAIN', value, domain_source=source)
                         for value in ('*.ms', 'bad..ms', '-bad.ms', 'bad_.ms')]
                self.assertEqual(exclude_covered(rules, [Rule('DOMAIN-SUFFIX', 'ms')]), rules)
                literal = Rule('DOMAIN', 'ads.ms', domain_source=source)
                self.assertEqual(exclude_covered([literal], [Rule('DOMAIN-SUFFIX', 'ms..')]), [literal])

    def test_cross_source_coverage_preserves_allow_flags_order_and_iterables(self):
        allowed = Rule('DOMAIN', 'ads.ms', ('no-resolve',), allow=True,
                       literal_process=True, native_fields=True, domain_source='mihomo')
        neighbor = Rule('DOMAIN-SUFFIX', 'other.test', ('via-interface=en1',), domain_source='qx')
        covered = Rule('DOMAIN', 'ads.ms', ('via-interface=en1',), domain_source='qx')
        self.assertEqual(exclude_covered(iter([allowed, covered, neighbor]),
                         iter([Rule('DOMAIN-SUFFIX', 'ms')])), [allowed, neighbor])


if __name__ == '__main__':
    unittest.main()
