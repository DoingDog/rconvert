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


class DnsRegexLiteralTests(unittest.TestCase):
    def test_replace_literal_uses_equivalent_hex_and_preserves_native_payload(self):
        value = r'^(?:replace=)?ads\.example\.com$'
        parsed, warnings = parse('DOMAIN-REGEX,' + value + ',REJECT', purpose='block')
        self.assertEqual(warnings, [])
        out, skipped = render('dns', parsed, purpose='block', no_resolve='keep')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                         [r'/^(?:replace\x{3D})?ads\.example\.com$/'])
        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)

    def test_literal_contexts_share_block_allow_and_white_without_changing_groups(self):
        cases = ((r'^(?:replace=)?ads\.example\.com$', r'^(?:replace\x{3D})?ads\.example\.com$'),
                 (r'^[=]replace=$', r'^[\x{3D}]replace\x{3D}$'),
                 (r'^replace\x{3D}$', r'^replace\x{3D}$'),
                 (r'^\\replace=$', r'^\\replace\x{3D}$'),
                 (r'^(?i:replace=)$', r'^(?i:replace\x{3D})$'),
                 (r'^(?<name>replace=)$', r'^(?<name>replace\x{3D})$'))
        for value, expected in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    source = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    line = ('@@' if caller != 'block' else '') + '/' + expected + '/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [line])
                    self.assertNotIn('replace=', line)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    self.assertEqual(source.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]),
                                         'DOMAIN-REGEX,' + value)

    def test_generated_keyword_literals_remove_sentinel_in_three_consumers(self):
        for native in (False, True):
            value = 'REPLACE=' if native else 'replace='
            text = 'payload:\n  - DOMAIN-KEYWORD,' + value if native else 'DOMAIN-KEYWORD,' + value
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual(warnings, [])
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(native=native, caller=caller):
                    source = Rule(parsed[0].kind, parsed[0].value, allow=caller == 'allow',
                                  domain_source=parsed[0].domain_source)
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    expected = (r'/(?s-i:\A.*replace\x{3D}.*\z)/' if native else
                                r'/^.*replace\x{3D}.*$/')
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [('@@' if caller != 'block' else '') + expected])
                    self.assertNotIn('fin-adb.txt:DOMAIN-KEYWORD', skipped)
                    self.assertEqual(source.value, value)

    def test_lookaround_headers_stay_unsupported_with_original_mihomo_matcher(self):
        for value in (r'^ads(?=track)$', r'^(?<=replace=)ads$'):
            with self.subTest(value=value):
                out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)],
                                      purpose='block', no_resolve='keep')
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_literal_regex_generate_and_publish_keep_neighbors_and_real_exceptions(self):
        value = r'^(?:replace=)?ads\.example\.com$'
        expected = r'/^(?:replace\x{3D})?ads\.example\.com$/'
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for caller in ('block', 'whitelist'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(caller=caller, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = [{'name': 'dns', 'purpose': 'block', 'no_resolve': mode,
                               'sources': ['rules.list'],
                               'whitelist': ['white.list'] if caller == 'whitelist' else []}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    source = 'DOMAIN,neighbor.example.com\n'
                    if caller != 'whitelist':
                        source += 'DOMAIN-REGEX,' + value + '\n'
                    else:
                        (root / 'white.list').write_text('DOMAIN-REGEX,' + value, encoding='utf-8')
                    (root / 'rules.list').write_text(source, encoding='utf-8')
                    (root / 'dns').mkdir()
                    old = {root / 'dns' / name: b'old\x00' + name.encode('ascii') for name in names}
                    for path, data in old.items():
                        path.write_bytes(data)
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        out = generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    self.assertEqual(set(out[root / 'dns' / 'fin-adb.txt'].splitlines()[7:]),
                                     {'0.0.0.0 neighbor.example.com',
                                      ('@@' if caller != 'block' else '') + expected})
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', stderr.getvalue())
                    native = [json.loads(line[4:]) for line in out[root / 'dns' / 'fin.yaml'].splitlines()[2:]]
                    self.assertIn('DOMAIN,neighbor.example.com', native)
                    if caller == 'block':
                        self.assertIn('DOMAIN-REGEX,' + value, native)
                    publish(out, root=root)
                    self.assertEqual({path: path.read_bytes() for path in out},
                                     {path: text.encode('utf-8') for path, text in out.items()})
