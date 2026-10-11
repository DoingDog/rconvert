import unittest

from formats import render
from rules import parse


class NativeDomainTests(unittest.TestCase):
    def test_surge_suffix_renders_as_native_mihomo_rule(self):
        rules, warnings = parse("DOMAIN-SUFFIX,24.eu", purpose="proxy")
        self.assertEqual(warnings, [])
        output, _ = render("native", rules, purpose="proxy", no_resolve="keep")
        self.assertEqual(output["fin.yaml"], '# native rules: 1\npayload:\n  - "DOMAIN-SUFFIX,24.eu"\n')

    def test_shared_surge_qx_mihomo_payload_is_emitted_once(self):
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
                self.assertEqual(output["fin.yaml"],
                                 '# native rules: 1\npayload:\n  - "' + kind + ',24.eu"\n')
                self.assertFalse(any(key.startswith("fin.yaml:") for key in skipped))


if __name__ == "__main__":
    unittest.main()
