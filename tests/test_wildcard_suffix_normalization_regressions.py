import contextlib
import io
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


class WildcardSuffixNormalizationTests(unittest.TestCase):
    def test_surge_suffix_keeps_wildcard_root_dot_projection(self):
        parsed, messages = parse('DOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,*.example.com', purpose='block')
        self.assertEqual(messages, [])
        outputs, _ = render('root', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# root rules: 2\npayload:\n'
                         '  - "DOMAIN-REGEX,^.*\\\\.example\\\\.com\\\\.?$"\n'
                         '  - "DOMAIN-SUFFIX,example.com"\n')
        pattern = re.compile(r'^.*\.example\.com\.?$')
        for host in ('ads.example.com.', 'ads.example.com'):
            self.assertIsNotNone(pattern.fullmatch(host))
        for host in ('example.com.', 'example.com', 'ads.other.com'):
            self.assertIsNone(pattern.fullmatch(host))

    def test_reduction_respects_source_projection_and_identity(self):
        from dataclasses import replace

        patterns = ('*.example.com', 'api-*.example.com', 'api-?.example.com',
                    'cdn[ab].example.com', 'cdn[AB].example.com', 'api.example.com')
        for source in ('surge', 'qx', 'mihomo'):
            for pattern in patterns:
                suffix = Rule('DOMAIN-SUFFIX', 'example.com', domain_source=source)
                wildcard = Rule('DOMAIN-WILDCARD', pattern, domain_source=source)
                expected = [suffix, wildcard] if source == 'surge' else [suffix]
                for order in ([wildcard, suffix], [suffix, wildcard], [wildcard, suffix, wildcard]):
                    with self.subTest(source=source, pattern=pattern, order=order):
                        self.assertEqual(normalize(iter(order)), expected)
                for change in ({'allow': True}, {'options': ('force-cellular',)},
                               {'literal_process': True}, {'native_fields': True}):
                    a, b = replace(suffix, **change), replace(wildcard, **change)
                    self.assertEqual(normalize(iter([b, a, b])), [a, b] if source == 'surge' else [a])
                    self.assertEqual(set(normalize(iter([suffix, b]))), {suffix, b})
        for pattern in ('[z-a].example.com', '[a--b].example.com',
                        '[İ].example.com', '[İ-J].example.com',
                        '[ſ].example.com', '[ı].example.com'):
            parsed, messages = parse('DOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,' + pattern,
                                     purpose='block')
            self.assertEqual(messages, [])
            self.assertEqual(normalize(iter(parsed)), parsed[:1])
        suffix = Rule('DOMAIN-SUFFIX', 'example.com', ('special',))
        wildcard = Rule('DOMAIN-WILDCARD', '*.example.com', ('special',))
        self.assertEqual(normalize(iter([wildcard, suffix])), [suffix])

    def test_allow_with_unprojectable_options_keeps_safe_reduction(self):
        suffix = Rule('DOMAIN-SUFFIX', 'example.com', ('force-cellular',), allow=True)
        wildcard = Rule('DOMAIN-WILDCARD', '*.example.com', ('force-cellular',), allow=True)
        self.assertEqual(normalize(iter([wildcard, suffix])), [suffix])

    def test_source_white_and_target_allow_have_separate_coverage(self):
        parsed, messages = parse('DOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,*.example.com', purpose='block')
        self.assertEqual(messages, [])
        white = parse_whitelist('DOMAIN-SUFFIX,example.com')
        self.assertEqual(exclude_covered(iter(parsed), iter(white)), [])
        outputs, diagnostics = render('white', normalize(parsed), purpose='proxy', no_resolve='keep',
                                      whitelist=white)
        self.assertEqual(outputs['fin.yaml'], '# white rules: 1\npayload:\n'
                         '  - "DOMAIN-REGEX,^.*\\\\.example\\\\.com\\\\.?$"\n')
        self.assertEqual(diagnostics['fin.yaml:DOMAIN-SUFFIX:whitelist-covered'], 1)
        suffix, wildcard = [Rule(rule.kind, rule.value, allow=True) for rule in parsed]
        blocked, messages = parse('payload:\n  - "DOMAIN-REGEX,^.*\\\\.example\\\\.com\\\\.?$"', purpose='block')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('allow', [*blocked, *normalize(iter([wildcard, suffix]))],
                                      purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# allow rules: 0\npayload:\n')
        self.assertEqual(diagnostics['fin.yaml:DOMAIN-REGEX:whitelist-covered'], 1)
        outputs, _ = render('allow', normalize(iter([wildcard, suffix])), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:],
                         ['@@||example.com^', r'@@/^.*\.example\.com$/'])

    def test_six_format_bodies_and_diagnostics_in_nine_modes(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    parsed, messages = parse('﻿DOMAIN-SUFFIX,example.com\r\n'
                                             'DOMAIN-WILDCARD,"*.example.com"\r\n', purpose=purpose)
                    self.assertEqual(messages, [])
                    with patch('formats.datetime') as clock:
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        outputs, diagnostics = render('root', normalize(iter(parsed)),
                                                      purpose=purpose, no_resolve=mode)
                    self.assertEqual(outputs, {
                        'fin.txt': '# root rules: 2\nDOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,*.example.com\n',
                        'fin-surge.txt': '# root rules: 1\nDOMAIN-WILDCARD,*.example.com\n',
                        'fin-surge-ds.txt': '# root rules: 1\n.example.com\n',
                        'fin-qx.txt': '# root rules: 2\nHOST-SUFFIX,example.com,LIST\nHOST-WILDCARD,*.example.com,LIST\n',
                        'fin.yaml': '# root rules: 2\npayload:\n'
                                    '  - "DOMAIN-REGEX,^.*\\\\.example\\\\.com\\\\.?$"\n'
                                    '  - "DOMAIN-SUFFIX,example.com"\n',
                        'fin-adb.txt': '[Adblock Plus 2.0]\n! Title: root\n'
                                       '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                       '! License: Inherits upstream licenses\n! Version: 202610240000\n' +
                                       ('! Total count: 2\n||example.com^\n/^.*\\.example\\.com$/\n'
                                        if purpose == 'block' else
                                        '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'),
                    })
                    self.assertEqual(diagnostics, {'fin-surge-ds.txt:DOMAIN-WILDCARD': 1} | (
                        {} if purpose == 'block' else
                        {'fin-adb.txt:DOMAIN-SUFFIX': 1, 'fin-adb.txt:DOMAIN-WILDCARD': 1}))

    def test_generated_source_and_white_use_real_same_round_and_disk_bytes(self):
        regex = Rule('DOMAIN-REGEX', r'^.*\.example\.com\.?$', domain_source='surge')
        for filename in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt', 'fin.yaml'):
            for role in ('source', 'white'):
                with self.subTest(filename=filename, role=role), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    source = root / 'static/source.list'
                    source.write_bytes(b'\xef\xbb\xbfDOMAIN-SUFFIX,example.com\r\nDOMAIN-WILDCARD,*.example.com\r\n')
                    consumer = root / 'static/consumer.list'
                    consumer.write_text('DOMAIN-REGEX,' + regex.value + '\nDOMAIN,keep.other.org\n', encoding='utf-8')
                    inputs = {path: path.read_bytes() for path in (source, consumer)}
                    parent = dict(name='parent', purpose='block', no_resolve='keep', sources=['static/source.list'], whitelist=[])
                    child = dict(name='child', purpose='block', no_resolve='keep',
                                 sources=['parent/' + filename] if role == 'source' else ['static/consumer.list'],
                                 whitelist=['parent/' + filename] if role == 'white' else [])
                    config = root / 'rulesets.json'
                    config.write_text(json.dumps([parent, child]), encoding='utf-8')
                    old = {root / group / name: b'old complete output\x00\xff\r\n'
                           for group in ('parent', 'child') for name in FILES}
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
                    parent_yaml = outputs[root / 'parent/fin.yaml']
                    self.assertEqual(parse(parent_yaml, purpose='block'),
                                     ([regex, Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')], []))
                    actual, messages = parse(outputs[root / 'child/fin.yaml'], purpose='block')
                    self.assertEqual(messages, [])
                    if role == 'source':
                        expected = ([] if filename == 'fin-qx.txt' else [regex]) + (
                            [] if filename == 'fin-surge.txt' else [Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')])
                    else:
                        expected = [Rule('DOMAIN', 'keep.other.org', domain_source='mihomo')] + (
                            [regex] if filename == 'fin-qx.txt' else [])
                    self.assertEqual(actual, expected)
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in old},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    parent_bytes = {path: path.read_bytes() for path in old if path.parent.name == 'parent'}
                    self.assertTrue((root / 'parent' / filename).read_bytes().splitlines()[1:])
                    self.assertTrue(parse_whitelist((root / 'parent' / filename).read_text(encoding='utf-8')))
                    config.write_text(json.dumps([child]), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_log:
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        disk = generate(root, self.fail)
                    self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                    self.assertEqual(disk_log.getvalue().splitlines(),
                                     [line for line in log.getvalue().splitlines() if line.startswith('child ')])
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in disk},
                                     {path: text.encode('utf-8') for path, text in disk.items()})
                    self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
