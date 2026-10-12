import unittest

from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests import test_functional_audit_rules as audit_rules


class UnderscoreCoverageAuditTests(unittest.TestCase):
    def test_underscore_suffix_and_exact_whites_preserve_complete_label_boundaries(self):
        for source in ('surge', 'qx', 'mihomo'):
            for value in audit_rules.UnderscoreDomainAuditTests.suffixes:
                with self.subTest(source=source, value=value):
                    suffix = Rule('DOMAIN-SUFFIX', value, domain_source=source)
                    exact = Rule('DOMAIN', value, domain_source=source)
                    child = Rule('DOMAIN', 'sub.' + value, domain_source=source)
                    child_suffix = Rule('DOMAIN-SUFFIX', 'sub.' + value, domain_source=source)
                    neighbor = Rule('DOMAIN', 'not' + value, domain_source=source)
                    neighbor_tail = Rule('DOMAIN', value + '.other', domain_source=source)
                    allowed = Rule('DOMAIN', value, allow=True, domain_source=source)
                    text = (audit_rules.native_text('DOMAIN-SUFFIX,' + value) if source == 'mihomo' else
                            ('HOST-SUFFIX' if source == 'qx' else 'DOMAIN-SUFFIX') + ',' + value + ',DIRECT')
                    white = parse_whitelist(text)
                    self.assertEqual(white, [suffix])
                    rules = [exact, suffix, child, child_suffix, neighbor, allowed, neighbor_tail]
                    self.assertEqual(exclude_covered(iter(rules), iter(white)), [neighbor, allowed, neighbor_tail])
                    self.assertEqual(exclude_covered(rules, [exact]), rules[1:])
                    self.assertEqual(set(normalize(rules * 2)), {suffix, neighbor, allowed, neighbor_tail})

    def test_underscore_provenance_case_root_dot_and_cross_source_direction_remain(self):
        for source in ('qx', 'mihomo'):
            with self.subTest(source=source):
                covered = [Rule(kind, value, domain_source=source) for kind in ('DOMAIN', 'DOMAIN-SUFFIX')
                           for value in ('AD_CORE.CCTV.COM', 'sub.ad_core.cctv.com')]
                white = parse_whitelist('DOMAIN-SUFFIX,ad_core.cctv.com')
                self.assertEqual(exclude_covered(covered, white), [])
                keep = [Rule('DOMAIN', value, domain_source=source)
                        for value in ('notad_core.cctv.com', 'ad_core.cctv.com.other')]
                self.assertEqual(exclude_covered(keep, white), keep)
                original = Rule('DOMAIN-SUFFIX', 'ad_core.cctv.com')
                self.assertEqual(exclude_covered([original], [Rule('DOMAIN-SUFFIX', original.value,
                                                                  domain_source=source)]), [original])
                self.assertEqual(len(normalize([original, *covered])), 2)
        native = [Rule(kind, 'AD_CORE.CCTV.COM.', domain_source='mihomo') for kind in ('DOMAIN', 'DOMAIN-SUFFIX')]
        self.assertEqual(exclude_covered(native, parse_whitelist('DOMAIN-SUFFIX,ad_core.cctv.com')), native)
        self.assertEqual([rule.value for rule in native], ['AD_CORE.CCTV.COM.', 'AD_CORE.CCTV.COM.'])
        for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'):
            value = 'ad_core' if kind == 'DOMAIN-KEYWORD' else 'ad_core-??.example.org'
            surge = Rule(kind, value)
            native = Rule(kind, value, domain_source='mihomo')
            qx = Rule(kind, value, domain_source='qx')
            self.assertEqual(exclude_covered([surge, native, qx], [native]), [surge, qx])
            if kind == 'DOMAIN-WILDCARD':
                self.assertEqual(exclude_covered([surge, native, qx], [surge]), [native, qx])

    def test_underscore_wildcards_keep_native_byte_and_literal_class_identity(self):
        for source, matcher in (('surge', 'DOMAIN-WILDCARD,ad_core-[ab].example.org'),
                                ('mihomo', 'DOMAIN-WILDCARD,ad_core-[ab].example.org'),
                                ('qx', 'HOST-WILDCARD,ad_core-[ab].example.org,PROXY')):
            text = audit_rules.native_text(matcher) if source == 'mihomo' else matcher
            with self.subTest(source=source):
                rules, messages = parse(text, purpose='proxy')
                self.assertEqual((rules, messages), ([Rule('DOMAIN-WILDCARD', 'ad_core-[ab].example.org',
                                                          domain_source=source)], []))
                self.assertEqual(exclude_covered(rules, parse_whitelist(text)), [])
        white = parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,ad_core-??.example.org'))
        native = Rule('DOMAIN', 'ad_core-é.example.org', domain_source='mihomo')
        surge = Rule('DOMAIN', native.value)
        qx = Rule('DOMAIN', native.value, domain_source='qx')
        self.assertEqual(exclude_covered([native, surge, qx], white), [surge, qx])
        literal = Rule('DOMAIN', 'ad_core-[ab].example.org', domain_source='mihomo')
        neighbor = Rule('DOMAIN', 'ad_core-a.example.org', domain_source='mihomo')
        self.assertEqual(exclude_covered([literal, neighbor], parse_whitelist(
            audit_rules.native_text('DOMAIN-WILDCARD,ad_core-[ab].example.org'))), [neighbor])
