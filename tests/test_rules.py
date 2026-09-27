import unittest

from rules import Rule


class RuleTests(unittest.TestCase):
    def test_domain_canonicalization_preserves_process_case(self):
        self.assertEqual(Rule("domain", "Ads.Example.COM."), Rule("DOMAIN", "ads.example.com"))
        self.assertNotEqual(Rule("PROCESS-NAME", "FooApp"), Rule("PROCESS-NAME", "fooapp"))
        self.assertEqual(len({Rule("DOMAIN", "EXAMPLE.COM"), Rule("domain", "example.com")}), 1)
