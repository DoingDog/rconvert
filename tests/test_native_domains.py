import json
import unittest

from formats import render
from rules import parse
from tests.test_formats import expected_domain


class NativeDomainTests(unittest.TestCase):
    def test_surge_suffix_renders_as_paired_mihomo_regex(self):
        rules, warnings = parse("DOMAIN-SUFFIX,24.eu", purpose="proxy")
        self.assertEqual(warnings, [])
        output, _ = render("native", rules, purpose="proxy", no_resolve="keep")
        self.assertEqual(output["fin.yaml"], '# native rules: 1\npayload:\n  - ' +
                         json.dumps(expected_domain('DOMAIN-SUFFIX', '24.eu')) + '\n')

    def test_surge_projection_preserves_distinct_qx_mihomo_literal(self):
        for kind, qx_kind in (("DOMAIN", "HOST"), ("DOMAIN-SUFFIX", "HOST-SUFFIX")):
            with self.subTest(kind=kind):
                rules = []
                for text in (kind + ",24.eu", qx_kind + ",24.eu,PROXY",
                             "payload:\n  - " + kind + ",24.eu"):
                    parsed, warnings = parse(text, purpose="proxy")
                    self.assertEqual(warnings, [])
                    self.assertEqual(len(parsed), 1)
                    rules.extend(parsed)
                output, skipped = render("native", rules, purpose="proxy", no_resolve="keep")
                payloads = sorted((kind + ',24.eu', expected_domain(kind, '24.eu')),
                                  key=lambda value: (value.partition(',')[0], len(json.dumps(value)), value))
                self.assertEqual(output["fin.yaml"], '# native rules: 2\npayload:\n' +
                                 ''.join('  - ' + json.dumps(value) + '\n' for value in payloads))
                self.assertFalse(any(key.startswith("fin.yaml:") for key in skipped))


if __name__ == "__main__":
    unittest.main()
