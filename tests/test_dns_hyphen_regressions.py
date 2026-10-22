import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import normalize, parse, parse_whitelist
from tests.test_formats import dns_regex


class DnsEscapedHyphenTests(unittest.TestCase):
    def source(self, patterns, native):
        if native:
            return 'payload:\n' + ''.join('  - ' + json.dumps('DOMAIN-REGEX,' + value) + '\n' for value in patterns)
        return ''.join("DOMAIN-REGEX,'" + value + "'\n" for value in patterns)

    def test_escaped_hyphen_range_endpoint_is_dns_unsupported(self):
        source = r"DOMAIN-REGEX,'[!-\-9]x'"
        rules, warnings = parse(source, purpose='block')
        self.assertEqual(warnings, [])
        self.assertEqual(rules[0].value, r'[!-\-9]x')
        outputs, diagnostics = render('hyphen', normalize(rules), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [])
        self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-REGEX'], 1)
        self.assertIn(r'DOMAIN-REGEX,[!-\\-9]x', outputs['fin.yaml'])

    def test_all_escaped_range_shapes_share_block_allow_and_white_diagnostics(self):
        patterns = (r'[!-\-9]x', r'[^!-\-9]x', r'[\--9]x', r'[^\--9]x',
                    r'(?:[!-\-9]x)', r'(?i:[^\--9]x)', r'[!-\-\-9]x',
                    r'[\p{L}\--9]x', r'[\p{L}!-\-9]x', r'[^\p{L}\--9]x')
        for native in (False, True):
            for value in patterns:
                source = self.source([value], native)
                rules, warnings = parse(source, purpose='block')
                self.assertEqual(warnings, [])
                self.assertEqual([rule.value for rule in rules], [value])
                self.assertEqual(normalize(rules), rules)
                white = parse_whitelist(source)
                self.assertEqual(white, rules)
                for mode in ('add', 'strip', 'keep'):
                    for consumer in ('block', 'allow', 'white'):
                        with self.subTest(native=native, value=value, mode=mode, consumer=consumer):
                            inputs = rules if consumer == 'block' else [replace(rules[0], allow=True)] if consumer == 'allow' else []
                            outputs, diagnostics = render('hyphen', inputs, whitelist=white if consumer == 'white' else [],
                                                           purpose='block', no_resolve=mode)
                            self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [])
                            self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-REGEX'], 1)
                            self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
                            if consumer == 'block':
                                self.assertEqual([json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]],
                                                 ['DOMAIN-REGEX,' + value])
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    self.assertEqual(outputs[name], '# hyphen rules: 0\n')
                            self.assertEqual(rules[0].value, value)

    def test_safe_hyphens_hex_endpoints_and_properties_keep_dns_matches(self):
        controls = [(r'[-a]x', 'ax.test', '0x.test'), (r'[a-]x', 'ax.test', '0x.test'),
                    (r'[\-a]x', 'ax.test', '0x.test'), (r'[a\-]x', 'ax.test', '0x.test'),
                    (r'[\-a-c]x', 'bx.test', '0x.test'), (r'[--0]x', '0x.test', '1x.test'),
                    (r'[!-\x{2D}a]x', 'ax.test', '0x.test'), (r'[\x{2D}-a]x', '0x.test', 'x.test'),
                    (r'[!-\?a]x', '0x.test', 'bx.test'), (r'[!-\]a]x', 'bx.test', 'x.test'),
                    (r'[\p{L}-a]x', 'ax.test', '0x.test'), (r'[\p{L}--0]x', '0x.test', '1x.test'),
                    (r'[\p{L}-\x{30}]x', '0x.test', '1x.test')]
        for native in (False, True):
            for value, matched, missed in controls:
                rules, warnings = parse(self.source([value], native), purpose='block')
                self.assertEqual(warnings, [])
                self.assertEqual([rule.value for rule in rules], [value])
                for consumer in ('block', 'allow', 'white'):
                    with self.subTest(native=native, value=value, consumer=consumer):
                        inputs = rules if consumer == 'block' else [replace(rules[0], allow=True)] if consumer == 'allow' else []
                        outputs, diagnostics = render('hyphen', inputs, whitelist=rules if consumer == 'white' else [],
                                                       purpose='block', no_resolve='keep')
                        rows = outputs['fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(len(rows), 1)
                        self.assertEqual(rows[0].startswith('@@'), consumer != 'block')
                        self.assertIsNotNone(dns_regex(rows[0]).search(matched))
                        self.assertIsNone(dns_regex(rows[0]).search(missed))
                        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)
        for value in (r'[a-\p{L}]x', r'[!-\p{L}]x'):
            rules, warnings = parse(self.source([value], True), purpose='block')
            self.assertEqual(rules, [])
            self.assertEqual(len(warnings), 1)

    def test_generate_publish_external_and_generated_white_use_actual_yaml_bytes(self):
        patterns = (r'[!-\-9]x', r'[^!-\-9]x', r'[\--9]x', r'[^\--9]x')
        for native in (False, True):
            source = self.source(patterns, native) + ('  - DOMAIN,neighbor.example.org\n' if native else
                                                      'DOMAIN,neighbor.example.org\n')
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(native=native, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/input.list').write_text(source, encoding='utf-8')
                        (root / 'static/block.list').write_text("DOMAIN-REGEX,'.*'\nDOMAIN,keep.example.org\n", encoding='utf-8')
                        original = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                    'sources': sources, 'whitelist': white} for group, sources, white in
                                   (('parent', ['static/input.list'], []),
                                    ('sourcechild', ['parent/fin.yaml'], []),
                                    ('whitechild', ['static/block.list'], ['parent/fin.yaml']),
                                    ('external', ['static/block.list'], ['static/input.list']))]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        previous = {}
                        for config in configs:
                            (root / config['name']).mkdir()
                            for name in FILES:
                                path = root / config['name'] / name
                                previous[path] = ('old ' + name).encode()
                                path.write_bytes(previous[path])
                        with contextlib.redirect_stderr(io.StringIO()) as logs:
                            outputs = generate(root, self.fail)
                        self.assertEqual(len(outputs), 24)
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        self.assertNotIn(': line ', logs.getvalue())
                        self.assertNotIn('frozen', logs.getvalue())
                        for config in configs:
                            group = config['name']
                            rows = outputs[root / group / 'fin-adb.txt'].splitlines()[7:]
                            if purpose == 'block':
                                self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: 4', logs.getvalue())
                                if group in ('parent', 'sourcechild'):
                                    self.assertFalse(any(row.startswith('/') for row in rows))
                                    parsed, warnings = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                    self.assertEqual(warnings, [])
                                    self.assertEqual({rule.value for rule in parsed if rule.kind == 'DOMAIN-REGEX'}, set(patterns))
                                else:
                                    self.assertFalse(any(row.startswith('@@/') for row in rows))
                                    block_rows = [row for row in rows if row.startswith('/')]
                                    self.assertEqual(len(block_rows), 1)
                                    self.assertIsNotNone(dns_regex(block_rows[0]).search('0x.test'))
                            else:
                                self.assertEqual(rows, ['! No AdBlock rules for non-advertising group.'])
                        publish(outputs, root=root)
                        parent_bytes = {root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in FILES}
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as logs:
                            disk = generate(root, self.fail)
                        self.assertEqual(len(disk), 18)
                        self.assertNotIn(': line ', logs.getvalue())
                        for config in configs[1:]:
                            for name in FILES:
                                if name != 'fin-adb.txt':
                                    path = root / config['name'] / name
                                    self.assertEqual(disk[path], outputs[path])
                            path = root / config['name'] / 'fin-adb.txt'
                            self.assertEqual(disk[path].splitlines()[6:], outputs[path].splitlines()[6:])
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)
                        self.assertEqual({path: path.read_bytes() for path in original}, original)
