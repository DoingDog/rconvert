import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests.test_formats import DNS_BYTE_TOKEN


class NativeUnicodeCapabilityTests(unittest.TestCase):
    def test_native_case_variant_keyword_skips_surge_projection(self):
        parsed, messages = parse('payload:\n  - DOMAIN-KEYWORD,É', purpose='block')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('native', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# native rules: 0\n')
        self.assertEqual(outputs['fin-surge.txt'], '# native rules: 0\n')
        self.assertEqual(diagnostics['fin.txt:DOMAIN-KEYWORD'], 1)
        self.assertEqual(diagnostics['fin-surge.txt:DOMAIN-KEYWORD'], 1)

    def test_native_case_variant_wildcard_skips_surge_projection(self):
        parsed, messages = parse('payload:\n  - DOMAIN-WILDCARD,*é*', purpose='block')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('native', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# native rules: 0\n')
        self.assertEqual(outputs['fin-surge.txt'], '# native rules: 0\n')
        self.assertEqual(diagnostics['fin.txt:DOMAIN-WILDCARD'], 1)
        self.assertEqual(diagnostics['fin-surge.txt:DOMAIN-WILDCARD'], 1)

    def test_case_variant_scalar_and_logical_rules_skip_only_surge_targets(self):
        for value in ('É', 'Σ', 'ẞ', 'é', 'σ', 'ß', 'ΟΣ'):
            for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'):
                payload = value if kind == 'DOMAIN-KEYWORD' else '*' + value + '*'
                leaf = kind + ',' + payload
                expressions = (leaf, 'AND,((' + leaf + '),(DOMAIN,neighbor.example))',
                               'OR,((' + leaf + '),(DOMAIN,neighbor.example))', 'NOT,((' + leaf + '))')
                for expression in expressions:
                    source = 'payload:\n  - ' + json.dumps(expression, ensure_ascii=False)
                    parsed, messages = parse(source, purpose='block')
                    self.assertEqual(messages, [])
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(value=value, expression=expression, purpose=purpose, mode=mode):
                                outputs, diagnostics = render('native', normalize(iter(parsed)), purpose=purpose, no_resolve=mode)
                                self.assertEqual(outputs['fin.txt'], '# native rules: 0\n')
                                self.assertEqual(outputs['fin-surge.txt'], '# native rules: 0\n')
                                self.assertEqual(outputs['fin.yaml'], '# native rules: 1\npayload:\n  - ' +
                                                 json.dumps(expression, ensure_ascii=False) + '\n')
                                self.assertEqual(diagnostics['fin.txt:' + parsed[0].kind], 1)
                                self.assertEqual(diagnostics['fin-surge.txt:' + parsed[0].kind], 1)
                                self.assertEqual(set(outputs), set(FILES))
                                if expression == leaf:
                                    self.assertEqual(outputs['fin-qx.txt'], '# native rules: 1\n' +
                                                     kind.replace('DOMAIN-', 'HOST-') + ',' + payload + ',LIST\n')
        for value in ('123', '中文', '🙂'):
            for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'):
                payload = value if kind == 'DOMAIN-KEYWORD' else '*' + value + '*'
                parsed, messages = parse('payload:\n  - ' + json.dumps(kind + ',' + payload, ensure_ascii=False), purpose='proxy')
                self.assertEqual(messages, [])
                outputs, _ = render('safe', parsed, purpose='proxy', no_resolve='keep')
                self.assertEqual(outputs['fin.txt'], '# safe rules: 1\n' + kind + ',' + payload + '\n')

    def test_exact_six_format_native_sigma_keyword_bytes_and_whitelist_boundaries(self):
        parsed, messages = parse('payload:\n  - DOMAIN-KEYWORD,Σ', purpose='block')
        self.assertEqual(messages, [])
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with patch('formats.datetime') as clock:
                    clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                    outputs, diagnostics = render('sigma', parsed, purpose=purpose, no_resolve=mode)
                self.assertEqual(outputs['fin.txt'], '# sigma rules: 0\n')
                self.assertEqual(outputs['fin-surge.txt'], '# sigma rules: 0\n')
                self.assertEqual(outputs['fin-surge-ds.txt'], '# sigma rules: 0\n')
                self.assertEqual(outputs['fin-qx.txt'], '# sigma rules: 1\nHOST-KEYWORD,Σ,LIST\n')
                self.assertEqual(outputs['fin.yaml'], '# sigma rules: 1\npayload:\n  - "DOMAIN-KEYWORD,Σ"\n')
                self.assertEqual(outputs['fin-adb.txt'], '[Adblock Plus 2.0]\n! Title: sigma\n'
                                 '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                 '! License: Inherits upstream licenses\n! Version: 202610240000\n' + (
                                     '! Total count: 1\n' + r'/(?s-i:\A' + DNS_BYTE_TOKEN +
                                     r'*\\207\\131' + DNS_BYTE_TOKEN + r'*\z)/' + '\n'
                                     if purpose == 'block' else
                                     '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))
                self.assertEqual(diagnostics, {'fin.txt:DOMAIN-KEYWORD': 1, 'fin-surge.txt:DOMAIN-KEYWORD': 1,
                                               'fin-surge-ds.txt:DOMAIN-KEYWORD': 1} | (
                    {} if purpose == 'block' else {'fin-adb.txt:DOMAIN-KEYWORD': 1}))
        ordinary, messages = parse('DOMAIN-KEYWORD,Σ', purpose='proxy')
        self.assertEqual(messages, [])
        native_white = parse_whitelist('payload:\n  - DOMAIN-KEYWORD,Σ')
        self.assertEqual(exclude_covered(iter(ordinary), iter(native_white)), ordinary)
        outputs, _ = render('white', ordinary, purpose='proxy', no_resolve='keep', whitelist=native_white)
        self.assertEqual(outputs['fin.txt'], '# white rules: 1\nDOMAIN-KEYWORD,Σ\n')
        allowed = replace(parsed[0], allow=True)
        outputs, _ = render('allow', [*ordinary, allowed], purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# allow rules: 1\nDOMAIN-KEYWORD,Σ\n')

    def test_native_unicode_source_and_white_dependencies_publish_without_surge_widening(self):
        for kind, payload in (('DOMAIN-KEYWORD', 'É'), ('DOMAIN-WILDCARD', '*σ*')):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(kind=kind, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        source = root / 'static/source.yaml'
                        source.write_bytes(('﻿payload:\r\n  - ' + json.dumps(kind + ',' + payload, ensure_ascii=False) + '\r\n').encode('utf-8'))
                        consumer = root / 'static/consumer.list'
                        consumer.write_text(kind + ',' + payload + '\nDOMAIN,keep.other.org\n', encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (source, consumer)}
                        configs = [dict(name='parent', sources=['static/source.yaml'], whitelist=[]),
                                   dict(name='source', sources=['parent/fin.yaml'], whitelist=[]),
                                   dict(name='white', sources=['static/consumer.list'], whitelist=['parent/fin.yaml'])]
                        for config in configs:
                            config.update(purpose=purpose, no_resolve=mode)
                        config_path = root / 'rulesets.json'
                        config_path.write_text(json.dumps(configs), encoding='utf-8')
                        old = {root / config['name'] / name: b'old complete output\x00\xff\r\n'
                               for config in configs for name in FILES}
                        for path, data in old.items():
                            path.parent.mkdir(exist_ok=True)
                            path.write_bytes(data)
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as log:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            outputs = generate(root, self.fail)
                        self.assertEqual(set(outputs), set(old))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        self.assertNotIn('frozen', log.getvalue())
                        self.assertNotIn(': line ', log.getvalue())
                        for group in ('parent', 'source'):
                            self.assertEqual(outputs[root / group / 'fin.txt'], '# ' + group + ' rules: 0\n')
                            self.assertEqual(outputs[root / group / 'fin-surge.txt'], '# ' + group + ' rules: 0\n')
                            self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                             ([Rule(kind, payload, domain_source='mihomo')], []))
                        self.assertIn(kind + ',' + payload + '\n', outputs[root / 'white/fin.txt'])
                        publish(outputs, root=root)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in outputs.items()})
                        parents = {path: path.read_bytes() for path in outputs if path.parent.name == 'parent'}
                        self.assertTrue((root / 'parent/fin.yaml').read_bytes().splitlines()[2:])
                        config_path.write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            disk = generate(root, self.fail)
                        self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name != 'parent'})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in parents}, parents)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
