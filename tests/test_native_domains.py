import json
import unittest

from formats import render
from rules import Rule, normalize, parse, parse_whitelist


class NativeDomainTests(unittest.TestCase):
    def test_ordinary_domains_use_compact_native_rows_and_deduplicate_source_formats(self):
        for kind, qx_kind in (("DOMAIN", "HOST"), ("DOMAIN-SUFFIX", "HOST-SUFFIX")):
            with self.subTest(kind=kind):
                rules = []
                for text in (kind + ",Example.COM", qx_kind + ",example.com,PROXY",
                             "payload:\n  - " + kind + ",example.com"):
                    parsed, warnings = parse(text, purpose="proxy")
                    self.assertEqual(warnings, [])
                    rules.extend(parsed)
                rules = normalize(rules)
                self.assertEqual({rule.domain_source for rule in rules}, {"surge", "qx", "mihomo"})
                output, skipped = render("native", rules, purpose="proxy", no_resolve="keep")
                self.assertEqual(output["fin.yaml"], '# native rules: 1\npayload:\n  - "' +
                                 kind + ',example.com"\n')
                self.assertFalse(any(key.startswith("fin.yaml:") for key in skipped))

    def test_ordinary_domains_render_compact_native_mihomo_rows(self):
        rules, warnings = parse("DOMAIN,Example.COM\nDOMAIN-SUFFIX,24.eu", purpose="proxy")
        self.assertEqual(warnings, [])
        output, _ = render("native", rules, purpose="proxy", no_resolve="keep")
        self.assertEqual(output["fin.yaml"], '# native rules: 2\npayload:\n'
                         '  - "DOMAIN,example.com"\n  - "DOMAIN-SUFFIX,24.eu"\n')

    def test_raw_regex_native_literals_and_required_conversions_keep_actual_rows(self):
        raw = r'DOMAIN-REGEX,(?-i:\A[aA]\.[tT][eE][sS][tT]\.?\z)'
        texts = (raw, 'DOMAIN,a.test', 'DOMAIN-KEYWORD,track', 'DOMAIN-WILDCARD,*.ads.test',
                 'payload:\n  - DOMAIN,Mixed.TEST.')
        rules = []
        for text in texts:
            parsed, warnings = parse(text, purpose='proxy')
            self.assertEqual(warnings, [])
            rules.extend(parsed)
        output, _ = render('native', rules, purpose='block', no_resolve='keep')
        self.assertEqual({json.loads(line[4:]) for line in output['fin.yaml'].splitlines()[2:]},
                         {raw, 'DOMAIN,a.test', 'DOMAIN,Mixed.TEST.', 'DOMAIN-REGEX,track',
                          r'DOMAIN-REGEX,^.*\.ads\.test\.?$'})
        self.assertIn(r'/(?-i:\Aa\.test\z)/', output['fin-adb.txt'].splitlines()[7:])

    def test_class_white_covers_valid_ascii_exact_without_expanding_root_or_suffix_scope(self):
        white = parse_whitelist('DOMAIN-WILDCARD,[ab]*.*')
        for kind, value, covered in (('DOMAIN', 'a.test', True),
                                     ('DOMAIN', 'a.', False),
                                     ('DOMAIN', 'a..test', False),
                                     ('DOMAIN', 'a.K.test', False),
                                     ('DOMAIN-SUFFIX', 'a.test', False)):
            with self.subTest(kind=kind, value=value):
                output, skipped = render('native', [Rule(kind, value, domain_source='mihomo')],
                                         whitelist=white, purpose='proxy', no_resolve='keep')
                self.assertEqual(output['fin.yaml'], '# native rules: 0\npayload:\n' if covered else
                                 '# native rules: 1\npayload:\n  - ' + json.dumps(kind + ',' + value, ensure_ascii=False) + '\n')
                self.assertEqual(skipped.get('fin.yaml:' + kind + ':whitelist-covered', 0), int(covered))


if __name__ == "__main__":
    unittest.main()
