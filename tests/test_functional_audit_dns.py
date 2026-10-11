import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from formats import render
from generate import generate, publish
from rules import Rule, normalize, parse


class DnsExactConstructorTests(unittest.TestCase):
    def test_native_uppercase_exact_hosts_lowercase_only_dns(self):
        parsed, warnings = parse('payload:\n  - DOMAIN,ADS.EXAMPLE.COM', purpose='block')
        self.assertEqual(warnings, [])
        out, skipped = render('dns', normalize(parsed), purpose='block', no_resolve='keep')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], ['0.0.0.0 ads.example.com'])
        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,ADS.EXAMPLE.COM')
        self.assertEqual(parsed, [Rule('DOMAIN', 'ADS.EXAMPLE.COM', domain_source='mihomo')])
        self.assertNotIn('fin-adb.txt:DOMAIN', skipped)

    def test_exact_hosts_use_simple_lowercase_without_context_or_length_change(self):
        for value, expected in (('İΟΣ.K.EXAMPLE', 'iοσ.k.example'),
                                ('ſ.ẞ.EXAMPLE', 'ſ.ß.example'),
                                ('Ᲊ.EXAMPLE', 'Ᲊ.example')):
            source = Rule('DOMAIN', value, domain_source='mihomo')
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(value=value, purpose=purpose, mode=mode):
                        out, _ = render('dns', [source], purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                         ['0.0.0.0 ' + expected] if purpose == 'block' else
                                         ['! No AdBlock rules for non-advertising group.'])
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,' + value)
                        self.assertEqual(source.value, value)

    def test_exact_network_allow_and_white_preserve_original_payload(self):
        value = 'ADS.EXAMPLE.COM'
        for caller in ('allow', 'whitelist'):
            with self.subTest(caller=caller):
                source = Rule('DOMAIN', value, allow=caller == 'allow', domain_source='mihomo')
                out, _ = render('dns', [source] if caller == 'allow' else [], purpose='block',
                                no_resolve='keep', whitelist=[source] if caller == 'whitelist' else [])
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], ['@@|ADS.EXAMPLE.COM|'])
                self.assertEqual(source.value, value)

    def test_uppercase_exact_generate_publish_and_yaml_dependencies_preserve_native(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['native.yaml'], 'whitelist': []},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['parent/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'native.yaml').write_text('payload:\n  - DOMAIN,ADS.EXAMPLE.COM\n'
                                                     '  - DOMAIN,neighbor.example.com\n', encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        out = generate(root, lambda url: self.fail(url))
                    for group in ('parent', 'child'):
                        dns = out[root / group / 'fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(set(dns), {'0.0.0.0 ads.example.com', '0.0.0.0 neighbor.example.com'}
                                         if purpose == 'block' else {'! No AdBlock rules for non-advertising group.'})
                        self.assertIn('DOMAIN,ADS.EXAMPLE.COM',
                                      [json.loads(line[4:]) for line in out[root / group / 'fin.yaml'].splitlines()[2:]])
                    publish(out, root=root)
                    self.assertEqual({path: path.read_bytes() for path in out},
                                     {path: text.encode('utf-8') for path, text in out.items()})
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, lambda url: self.fail(url))
                    for name in ('fin.yaml', 'fin-adb.txt'):
                        header = 2 if name == 'fin.yaml' else 6
                        self.assertEqual(disk[root / 'child' / name].splitlines()[header:],
                                         out[root / 'child' / name].splitlines()[header:])
