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


class SurgeUnicodeProjectionTests(unittest.TestCase):
    def test_surge_keyword_projection_uses_go_simple_lowercase(self):
        parsed, messages = parse('DOMAIN-KEYWORD,İ', purpose='block')
        self.assertEqual(messages, [])
        outputs, _ = render('unicode', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# unicode rules: 1\npayload:\n  - "DOMAIN-REGEX,i"\n')

    def test_surge_wildcard_projection_uses_go_simple_lowercase(self):
        parsed, messages = parse('DOMAIN-WILDCARD,*ΟΣ*', purpose='block')
        self.assertEqual(messages, [])
        outputs, _ = render('unicode', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# unicode rules: 1\npayload:\n'
                         '  - "DOMAIN-REGEX,^.*οσ.*\\\\.?$"\n')

    def test_surge_wildcard_preserves_raw_unicode_identity_before_projection(self):
        parsed, messages = parse('DOMAIN-WILDCARD,*İ*\nDOMAIN-WILDCARD,*i̇*', purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(set(normalize(iter(parsed))), set(parsed))

    def test_constructor_literals_identity_classes_and_root_boundaries(self):
        for value, literal in (('İ', 'i'), ('ΟΣ', 'οσ'), ('ΑΟΣ', 'αοσ'), ('ος', 'ος')):
            for kind, pattern in (('DOMAIN-KEYWORD', literal), ('DOMAIN-WILDCARD', '^.*' + literal + r'.*\.?$')):
                payload = value if kind == 'DOMAIN-KEYWORD' else '*' + value + '*'
                parsed, messages = parse(kind + ',' + payload, purpose='block')
                self.assertEqual(messages, [])
                outputs, _ = render('unicode', normalize(iter(parsed)), purpose='block', no_resolve='keep')
                self.assertEqual(parse(outputs['fin.yaml'], purpose='block'), ([Rule('DOMAIN-REGEX', pattern)], []))
        for values in (('*İ*', '*i̇*'), ('*ΟΣ*', '*ος*')):
            parsed, messages = parse(''.join('DOMAIN-WILDCARD,' + value + '\n' for value in values), purpose='block')
            self.assertEqual(messages, [])
            for change in ({}, {'allow': True}, {'options': ('force-cellular',)},
                           {'literal_process': True}, {'native_fields': True}):
                pair = [replace(rule, **change) for rule in parsed]
                for order in (pair, pair[::-1], pair + pair):
                    self.assertEqual(set(normalize(iter(order))), set(pair))
        for value, regex in (('[İ]', None), ('[İ-J]', None), ('[z-a]', None),
                             ('[ab]', r'^[ab]\.?$'), ('İ.', r'i\.(?=.)'),
                             ('İ?', r'^i.(?<!\.)\.?$')):
            kind = 'DOMAIN-KEYWORD' if value == 'İ.' else 'DOMAIN-WILDCARD'
            parsed, messages = parse(kind + ',' + value, purpose='block')
            self.assertEqual(messages, [])
            outputs, diagnostics = render('edge', parsed, purpose='block', no_resolve='keep')
            actual, messages = parse(outputs['fin.yaml'], purpose='block')
            self.assertEqual(messages, [])
            self.assertEqual(actual, [] if regex is None else [Rule('DOMAIN-REGEX', regex)])
            self.assertEqual(diagnostics.get('fin.yaml:' + kind, 0), int(regex is None))
        source, _ = parse('DOMAIN-WILDCARD,*İ*\nDOMAIN-WILDCARD,*i̇*', purpose='block')
        self.assertEqual(exclude_covered(source, parse_whitelist('DOMAIN-WILDCARD,*i̇*')), [])

    def test_scalar_logical_and_target_white_project_complete_matchers_in_nine_modes(self):
        for kind, value, projected in (('DOMAIN-KEYWORD', 'İ', 'i'),
                                       ('DOMAIN-WILDCARD', '*ΟΣ*', r'^.*οσ.*\.?$')):
            leaf, native_leaf = kind + ',' + value, 'DOMAIN-REGEX,' + projected
            cases = ((leaf, native_leaf),
                     ('AND,((' + leaf + '),(DOMAIN,neighbor.example))',
                      'AND,((' + native_leaf + '),(DOMAIN,neighbor.example))'),
                     ('OR,((' + leaf + '),(DOMAIN,neighbor.example))',
                      'OR,((' + native_leaf + '),(DOMAIN,neighbor.example))'),
                     ('NOT,((' + leaf + '))', 'NOT,((' + native_leaf + '))'))
            for source, expected in cases:
                for purpose in ('block', 'direct', 'proxy'):
                    parsed, messages = parse(source, purpose=purpose)
                    self.assertEqual(messages, [])
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(kind=kind, source=source, purpose=purpose, mode=mode):
                            outputs, diagnostics = render('unicode', normalize(iter(parsed)), purpose=purpose, no_resolve=mode)
                            self.assertEqual(outputs['fin.yaml'], '# unicode rules: 1\npayload:\n  - ' +
                                             json.dumps(expected, ensure_ascii=False) + '\n')
                            self.assertEqual(set(outputs), set(FILES))
                            self.assertNotIn('fin.yaml:' + parsed[0].kind, diagnostics)
            source, _ = parse(leaf, purpose='block')
            native, _ = parse('payload:\n  - ' + json.dumps(native_leaf, ensure_ascii=False), purpose='block')
            white = parse_whitelist(leaf)
            for rules, external in ((native, white), ([*native, replace(source[0], allow=True)], [])):
                outputs, diagnostics = render('white', normalize(iter(rules)), purpose='proxy', no_resolve='keep', whitelist=external)
                self.assertEqual(outputs['fin.yaml'], '# white rules: 1\npayload:\n  - ' +
                                 json.dumps(native_leaf, ensure_ascii=False) + '\n')
                self.assertNotIn('fin.yaml:DOMAIN-REGEX:whitelist-covered', diagnostics)
            outputs, diagnostics = render('white', source, purpose='proxy', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps(native_leaf, ensure_ascii=False)))
            self.assertEqual(outputs['fin.yaml'], '# white rules: 0\npayload:\n')
            self.assertEqual(diagnostics['fin.yaml:' + kind + ':whitelist-covered'], 1)

    def test_six_format_complete_keyword_bytes_in_nine_modes(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                source, messages = parse('DOMAIN-KEYWORD,İ', purpose=purpose)
                self.assertEqual(messages, [])
                with patch('formats.datetime') as clock:
                    clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                    outputs, diagnostics = render('unicode', normalize(iter(source)), purpose=purpose, no_resolve=mode)
                self.assertEqual(outputs, {
                    'fin.txt': '# unicode rules: 1\nDOMAIN-KEYWORD,İ\n',
                    'fin-surge.txt': '# unicode rules: 1\nDOMAIN-KEYWORD,İ\n',
                    'fin-qx.txt': '# unicode rules: 1\nHOST-KEYWORD,İ,LIST\n',
                    'fin-surge-ds.txt': '# unicode rules: 0\n',
                    'fin.yaml': '# unicode rules: 1\npayload:\n  - "DOMAIN-REGEX,i"\n',
                    'fin-adb.txt': '[Adblock Plus 2.0]\n! Title: unicode\n'
                                   '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                   '! License: Inherits upstream licenses\n! Version: 202610240000\n' +
                                   ('! Total count: 1\n/^.*İ.*$/\n' if purpose == 'block' else
                                    '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'),
                })
                self.assertEqual(diagnostics, {'fin-surge-ds.txt:DOMAIN-KEYWORD': 1} | (
                    {} if purpose == 'block' else {'fin-adb.txt:DOMAIN-KEYWORD': 1}))

    def test_projected_yaml_same_round_and_disk_dependencies_keep_unicode_regex_bytes(self):
        for kind, value, expected in (('DOMAIN-KEYWORD', 'İ', 'i'),
                                      ('DOMAIN-WILDCARD', '*ΟΣ*', r'^.*οσ.*\.?$')):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(kind=kind, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        source = root / 'static/source.list'
                        source.write_bytes(('﻿' + kind + ',' + value + '\r\n').encode('utf-8'))
                        consumer = root / 'static/consumer.list'
                        consumer.write_text('DOMAIN-REGEX,' + expected + '\nDOMAIN,keep.other.org\n', encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (source, consumer)}
                        configs = [dict(name='parent', sources=['static/source.list'], whitelist=[]),
                                   dict(name='source', sources=['parent/fin.yaml'], whitelist=[]),
                                   dict(name='white', sources=['static/consumer.list'], whitelist=['parent/fin.yaml'])]
                        for config in configs:
                            config.update(purpose=purpose, no_resolve=mode)
                        config_path = root / 'rulesets.json'
                        config_path.write_text(json.dumps(configs), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as log:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            outputs = generate(root, self.fail)
                        self.assertEqual(len(outputs), 18)
                        self.assertNotIn('frozen', log.getvalue())
                        self.assertNotIn(': line ', log.getvalue())
                        for group in ('parent', 'source'):
                            self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                             ([Rule('DOMAIN-REGEX', expected)], []))
                        self.assertEqual(parse(outputs[root / 'white/fin.yaml'], purpose=purpose),
                                         ([Rule('DOMAIN', 'keep.other.org', domain_source='mihomo')], []))
                        publish(outputs, root=root)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in outputs.items()})
                        parent = {path: path.read_bytes() for path in outputs if path.parent.name == 'parent'}
                        self.assertTrue((root / 'parent/fin.yaml').read_bytes().splitlines()[2:])
                        config_path.write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            disk = generate(root, self.fail)
                        self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name != 'parent'})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in parent}, parent)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
