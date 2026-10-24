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
                    'cdn[ab].example.com', 'cdn[AB].example.com', 'api.example.com',
                    'İ*.EXAMPLE.COM', '*ΟΣ*.EXAMPLE.COM',
                    '中文*.EXAMPLE.COM', '[ab]İ*.EXAMPLE.COM')
        for source in ('surge', 'qx', 'mihomo'):
            for pattern in patterns:
                suffix = Rule('DOMAIN-SUFFIX', 'example.com', domain_source=source)
                wildcard = Rule('DOMAIN-WILDCARD', pattern, domain_source=source)
                keep = source == 'surge' or source == 'qx' and not pattern.isascii()
                expected = [suffix, wildcard] if keep else [suffix]
                for order in ([wildcard, suffix], [suffix, wildcard], [wildcard, suffix, wildcard]):
                    with self.subTest(source=source, pattern=pattern, order=order):
                        self.assertEqual(normalize(iter(order)), expected)
                for change in ({'allow': True}, {'options': ('force-cellular',)},
                               {'literal_process': True}, {'native_fields': True}):
                    a, b = replace(suffix, **change), replace(wildcard, **change)
                    self.assertEqual(normalize(iter([b, a, b])), [a, b] if keep else [a])
                    self.assertEqual(set(normalize(iter([suffix, b]))), {suffix, b})
        for prefix in ('[z-a]', '[a--b]', '[İ]', '[İ-J]', '[ſ]', '[ı]'):
            for tail in ('example.com', 'EXAMPLE.COM', 'ExAmPlE.CoM'):
                with self.subTest(prefix=prefix, tail=tail):
                    parsed, messages = parse('DOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,' + prefix + '.' + tail,
                                             purpose='block')
                    self.assertEqual(messages, [])
                    for order in (parsed, parsed[::-1], parsed + parsed):
                        self.assertEqual(normalize(iter(order)), parsed[:1])
                    self.assertEqual(normalize(iter(parsed[1:])), parsed[1:])
        parsed, messages = parse('HOST-SUFFIX,example.com\nHOST-WILDCARD,Σ*.EXAMPLE.COM', purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(normalize(iter(parsed)), parsed)
        suffix = Rule('DOMAIN-SUFFIX', 'example.com', ('special',))
        wildcard = Rule('DOMAIN-WILDCARD', '*.example.com', ('special',))
        self.assertEqual(normalize(iter([wildcard, suffix])), [suffix])

    def test_unicode_suffix_candidates_keep_distinct_projected_matchers(self):
        for values, regexes in ((('*İ*', '*i̇*'), (r'^.*i.*\.example\.com\.?$', r'^.*i̇.*\.example\.com\.?$')),
                               (('*ΟΣ*', '*ος*'), (r'^.*οσ.*\.example\.com\.?$', r'^.*ος.*\.example\.com\.?$'))):
            parsed, messages = parse('DOMAIN-SUFFIX,example.com\n' + ''.join(
                'DOMAIN-WILDCARD,' + value + '.EXAMPLE.COM\n' for value in values), purpose='block')
            self.assertEqual(messages, [])
            for order in (parsed, parsed[::-1], parsed + parsed):
                self.assertEqual(set(normalize(iter(order))), set(parsed))
                outputs, _ = render('identity', normalize(iter(order)), purpose='block', no_resolve='keep')
                actual, messages = parse(outputs['fin.yaml'], purpose='block')
                self.assertEqual(messages, [])
                self.assertEqual(set(actual), {Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo'),
                                              *(Rule('DOMAIN-REGEX', regex) for regex in regexes)})
        for value, regex in (('İ*', r'^i.*\.example\.com\.?$'), ('*ΟΣ*', r'^.*οσ.*\.example\.com\.?$'),
                             ('中文*', r'^中文.*\.example\.com\.?$'), ('[ab]İ*', r'^[ab]i.*\.example\.com\.?$')):
            parsed, messages = parse('DOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,' + value + '.EXAMPLE.COM',
                                     purpose='block')
            self.assertEqual(messages, [])
            outputs, _ = render('projection', normalize(iter(parsed)), purpose='block', no_resolve='keep')
            self.assertEqual(parse(outputs['fin.yaml'], purpose='block'),
                             ([Rule('DOMAIN-REGEX', regex),
                               Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')], []))

    def test_allow_with_interface_options_keeps_target_projection(self):
        blocker = Rule('DOMAIN-REGEX', r'^.*\.example\.com\.?$')
        for option in ('force-cellular', 'multi-interface', 'multi-interface-balance',
                       'via-interface=pdp_ip0', 'via-interface=en1', 'special'):
            suffix = Rule('DOMAIN-SUFFIX', 'example.com', (option,), allow=True)
            wildcard = Rule('DOMAIN-WILDCARD', '*.example.com', (option,), allow=True)
            expected_white = [suffix] if option == 'special' else [suffix, wildcard]
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(option=option, purpose=purpose, mode=mode):
                        direct, direct_diagnostics = render('allow', [blocker, suffix, wildcard],
                                                            purpose=purpose, no_resolve=mode)
                        normalized = normalize(iter([wildcard, blocker, suffix, wildcard]))
                        outputs, diagnostics = render('allow', normalized, purpose=purpose,
                                                      no_resolve=mode)
                        expected = ('# allow rules: 1\npayload:\n'
                                    '  - "DOMAIN-REGEX,^.*\\\\.example\\\\.com\\\\.?$"\n'
                                    if option == 'special' else '# allow rules: 0\npayload:\n')
                        self.assertEqual(direct['fin.yaml'].encode('utf-8'), expected.encode('utf-8'))
                        self.assertEqual(outputs['fin.yaml'].encode('utf-8'), expected.encode('utf-8'))
                        covered = 'fin.yaml:DOMAIN-REGEX:whitelist-covered'
                        self.assertEqual(direct_diagnostics.get(covered, 0), int(option != 'special'))
                        self.assertEqual(diagnostics.get(covered, 0), int(option != 'special'))
                        self.assertEqual(normalized, [blocker, *expected_white])

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

    def test_unsupported_unicode_class_has_suffix_only_outputs_in_nine_modes(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    parsed, messages = parse('DOMAIN-SUFFIX,example.com\nDOMAIN-WILDCARD,[İ].EXAMPLE.COM',
                                             purpose=purpose)
                    self.assertEqual(messages, [])
                    with patch('formats.datetime') as clock:
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        outputs, diagnostics = render('root', normalize(iter(parsed)),
                                                      purpose=purpose, no_resolve=mode)
                    self.assertEqual(outputs, {
                        'fin.txt': '# root rules: 1\nDOMAIN-SUFFIX,example.com\n',
                        'fin-surge.txt': '# root rules: 0\n',
                        'fin-surge-ds.txt': '# root rules: 1\n.example.com\n',
                        'fin-qx.txt': '# root rules: 1\nHOST-SUFFIX,example.com,LIST\n',
                        'fin.yaml': '# root rules: 1\npayload:\n  - "DOMAIN-SUFFIX,example.com"\n',
                        'fin-adb.txt': '[Adblock Plus 2.0]\n! Title: root\n'
                                       '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                       '! License: Inherits upstream licenses\n! Version: 202610240000\n' +
                                       ('! Total count: 1\n||example.com^\n' if purpose == 'block' else
                                        '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'),
                    })
                    self.assertEqual(diagnostics, {} if purpose == 'block' else {'fin-adb.txt:DOMAIN-SUFFIX': 1})

    def test_generated_source_and_white_use_real_same_round_and_disk_bytes(self):
        regex = Rule('DOMAIN-REGEX', r'^.*\.example\.com\.?$', domain_source='surge')
        cases = [(filename, role, 'block', 'keep', False)
                 for filename in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt', 'fin.yaml')
                 for role in ('source', 'white')]
        cases += [('fin.txt', role, purpose, mode, True) for role in ('source', 'white')
                  for purpose in ('block', 'direct', 'proxy') for mode in ('add', 'strip', 'keep')]
        for filename, role, purpose, mode, unsupported in cases:
            with self.subTest(filename=filename, role=role, purpose=purpose, mode=mode,
                              unsupported=unsupported), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                source = root / 'static/source.list'
                wildcard = '[İ].EXAMPLE.COM' if unsupported else '*.example.com'
                source.write_bytes(('﻿DOMAIN-SUFFIX,example.com\r\nDOMAIN-WILDCARD,' + wildcard + '\r\n').encode('utf-8'))
                consumer = root / 'static/consumer.list'
                consumer.write_text('DOMAIN-REGEX,' + regex.value + '\nDOMAIN,keep.other.org\n', encoding='utf-8')
                inputs = {path: path.read_bytes() for path in (source, consumer)}
                parent = dict(name='parent', purpose=purpose, no_resolve=mode, sources=['static/source.list'], whitelist=[])
                child = dict(name='child', purpose=purpose, no_resolve=mode,
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
                self.assertEqual(parse(parent_yaml, purpose=purpose),
                                 (([] if unsupported else [regex]) +
                                  [Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')], []))
                if unsupported:
                    expected_log = ([] if purpose == 'block' else ['parent fin-adb.txt:DOMAIN-SUFFIX: 1'] +
                                    (['child fin-adb.txt:DOMAIN-SUFFIX: 1'] if role == 'source' else
                                     ['child fin-adb.txt:DOMAIN: 1', 'child fin-adb.txt:DOMAIN-REGEX: 1']))
                    if role == 'white':
                        expected_log += ['child ' + name + ':DOMAIN-REGEX: 1' for name in
                                         ('fin-qx.txt', 'fin-surge-ds.txt', 'fin-surge.txt', 'fin.txt')]
                    self.assertEqual(log.getvalue().splitlines(), expected_log)
                    self.assertEqual(outputs[root / 'parent/fin.txt'],
                                     '# parent rules: 1\nDOMAIN-SUFFIX,example.com\n')
                actual, messages = parse(outputs[root / 'child/fin.yaml'], purpose=purpose)
                self.assertEqual(messages, [])
                if role == 'source':
                    expected = ([] if unsupported or filename == 'fin-qx.txt' else [regex]) + (
                        [] if filename == 'fin-surge.txt' else [Rule('DOMAIN-SUFFIX', 'example.com', domain_source='mihomo')])
                else:
                    expected = [Rule('DOMAIN', 'keep.other.org', domain_source='mihomo')] + (
                        [regex] if unsupported or filename == 'fin-qx.txt' else [])
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
