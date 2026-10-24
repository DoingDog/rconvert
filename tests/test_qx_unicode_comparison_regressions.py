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


class QxUnicodeComparisonTests(unittest.TestCase):
    def test_surge_equal_lowercase_keyword_keeps_supported_dns_line(self):
        first, second = 'İ' * 21843, 'i̇' * 21843
        parsed, messages = parse('DOMAIN-KEYWORD,' + first + '\nDOMAIN-KEYWORD,' + second, purpose='block')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('long', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], ['/^.*' + first + '.*$/'])
        self.assertEqual(len(outputs['fin-adb.txt'].splitlines()[7].encode('utf-8')) + 1, 43695)
        self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-KEYWORD'], 1)

    def test_keyword_reduction_requires_both_literal_and_source_comparison_substrings(self):
        cases = (('Σ', 'ΟΣ'), ('ΟΣ', 'ΟΣΑ'), ('İ', 'xİ'), ('中文', '中文广告'))
        for source in ('surge', 'qx', 'mihomo'):
            for short, long in cases:
                with self.subTest(source=source, short=short, long=long):
                    pair = [Rule('DOMAIN-KEYWORD', value, domain_source=source) for value in (short, long)]
                    expected = pair[:1] if (source == 'surge' and short in {'İ', '中文'} or
                                           source == 'mihomo') else pair
                    self.assertEqual(set(normalize(iter(pair))), set(expected))

    def test_surge_lowercase_only_keyword_substring_keeps_supported_dns_line(self):
        short, long = 'i̇' * 21843, 'x' + 'İ' * 21843
        parsed, messages = parse('DOMAIN-KEYWORD,' + short + '\nDOMAIN-KEYWORD,' + long, purpose='block')
        self.assertEqual(messages, [])
        outputs, _ = render('long', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], ['/^.*' + long + '.*$/'])
        self.assertEqual(len(outputs['fin-adb.txt'].splitlines()[7].encode('utf-8')) + 1, 43696)

    def test_long_keyword_block_allow_and_raw_white_keep_supported_dns_bytes(self):
        first, second = 'İ' * 21843, 'i̇' * 21843
        for prefix in ('DOMAIN-KEYWORD,', 'HOST-KEYWORD,'):
            for values in ((first, second), (second, 'x' + first)):
                parsed, messages = parse(''.join(prefix + value + '\n' for value in values), purpose='block')
                self.assertEqual(messages, [])
                supported = first if values[0] == first else values[1]
                for allow in (False, True):
                    rules = [replace(rule, allow=allow) for rule in parsed]
                    for order in (rules, rules[::-1], rules + rules):
                        with self.subTest(prefix=prefix, proper=values[0] != first, allow=allow):
                            normalized = normalize(iter(order))
                            self.assertEqual(set(normalized), set(rules))
                            outputs, diagnostics = render('long', normalized, purpose='block', no_resolve='keep')
                            expected = ('@@' if allow else '') + '/^.*' + supported + '.*$/'
                            self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [expected])
                            self.assertLessEqual(len(expected.encode('utf-8')) + 1, 65536)
                            self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-KEYWORD'], 1)
                white = parse_whitelist(''.join(prefix + value + '\n' for value in values))
                outputs, diagnostics = render('long', [], purpose='block', no_resolve='keep', whitelist=white)
                self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], ['@@/^.*' + supported + '.*$/'])
                self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-KEYWORD'], 1)
        for values in (('İ', 'xİ'), ('中文', '中文广告')):
            parsed, messages = parse(''.join('DOMAIN-KEYWORD,' + value + '\n' for value in values), purpose='block')
            self.assertEqual(messages, [])
            self.assertEqual(normalize(iter(parsed[::-1] + parsed)), parsed[:1])

    def test_long_keyword_source_and_generated_white_publish_supported_dns_bytes(self):
        first, second = 'İ' * 21843, 'i̇' * 21843
        for prefix in ('DOMAIN-KEYWORD,', 'HOST-KEYWORD,'):
            for values in ((first, second), (second, 'x' + first)):
                with self.subTest(prefix=prefix, proper=values[0] != first), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / 'source.list'
                    source.write_bytes(('﻿' + '\r\n'.join(prefix + value for value in values) + '\r\n').encode('utf-8'))
                    blocker = root / 'blocker.list'
                    blocker.write_bytes(b'DOMAIN,keep.other.org\n')
                    inputs = {path: path.read_bytes() for path in (source, blocker)}
                    configs = [dict(name='parent', sources=['source.list'], whitelist=[]),
                               dict(name='source', sources=['parent/fin-qx.txt'], whitelist=[]),
                               dict(name='white', sources=['blocker.list'], whitelist=['parent/fin-qx.txt'])]
                    for config in configs:
                        config.update(purpose='block', no_resolve='keep')
                    config_path = root / 'rulesets.json'
                    config_path.write_text(json.dumps(configs), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as log:
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 18)
                    self.assertNotIn('frozen', log.getvalue())
                    self.assertNotIn(': line ', log.getvalue())
                    supported = first if values[0] == first else values[1]
                    for group in ('parent', 'source'):
                        body = outputs[root / group / 'fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(body, ['/^.*' + supported + '.*$/'])
                    self.assertEqual(outputs[root / 'white/fin-adb.txt'].splitlines()[7:],
                                     ['@@/^.*' + supported + '.*$/', '0.0.0.0 keep.other.org'])
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    parent = {path: path.read_bytes() for path in outputs if path.parent.name == 'parent'}
                    config_path.write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        disk = generate(root, self.fail)
                    self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name != 'parent'})
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in parent}, parent)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)


    def test_greek_qx_keywords_keep_distinct_mihomo_matchers(self):
        parsed, messages = parse('HOST-KEYWORD,ΟΣ\nHOST-KEYWORD,ος', purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(normalize(iter(parsed)), parsed)
        outputs, _ = render('greek', normalize(iter(parsed)), purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# greek rules: 2\npayload:\n'
                         '  - "DOMAIN-KEYWORD,ΟΣ"\n  - "DOMAIN-KEYWORD,ος"\n')

    def test_non_ascii_qx_keyword_substrings_do_not_prove_reduction(self):
        for values in (('Σ', 'ΟΣ'), ('ΑΟΣ', 'ος'), ('İ', 'xİ'), ('ad', 'adΣ')):
            with self.subTest(values=values):
                parsed, messages = parse(''.join('HOST-KEYWORD,' + value + '\n' for value in values),
                                         purpose='block')
                self.assertEqual(messages, [])
                self.assertEqual(set(normalize(iter(parsed))), set(parsed))

    def test_qx_white_keeps_unproved_unicode_cross_value_coverage(self):
        cases = (
            ('HOST-KEYWORD,ΟΣ', 'HOST-KEYWORD,ος'),
            ('HOST-KEYWORD,ΟΣ', 'HOST-KEYWORD,Σ'),
            ('HOST-KEYWORD,adΣ', 'HOST-KEYWORD,ad'),
            ('HOST-KEYWORD,İ', 'HOST-KEYWORD,i̇'),
            ('HOST-WILDCARD,İ', 'HOST-WILDCARD,i̇'),
            ('HOST-WILDCARD,*ΟΣ*', 'HOST-WILDCARD,*ος*'),
            ('HOST-WILDCARD,adΣ.example.com', 'HOST-SUFFIX,example.com'),
            ('HOST-WILDCARD,Σ.example.com', 'HOST-WILDCARD,*.example.com'),
            ('HOST-WILDCARD,Σ.example.com', 'HOST-KEYWORD,Σ'),
            ('HOST,i.example.com', 'HOST-WILDCARD,*İ*'),
        )
        for source_text, white_text in cases:
            for source_text, white_text in ((source_text, white_text), (white_text, source_text)):
                with self.subTest(source=source_text, white=white_text):
                    candidate, messages = parse(source_text, purpose='block')
                    self.assertEqual(messages, [])
                    white = parse_whitelist(white_text)
                    self.assertEqual(exclude_covered(iter(candidate), iter(white)), candidate)
                    self.assertEqual(exclude_covered(iter(candidate), iter(parse_whitelist(source_text))), [])

    def test_keyword_and_wildcard_payload_identity_survives_case_collisions(self):
        for kind in ('KEYWORD', 'WILDCARD'):
            for values in (('ΟΣ', 'ος'), ('İ', 'i̇'), ('xİ', 'xi̇'), ('AΣ', 'aΣ')):
                for stars in (False, True) if kind == 'WILDCARD' else (False,):
                    payloads = tuple('*' + value + '*' if stars else value for value in values)
                    text = ''.join('HOST-' + kind + ',' + value + '\n' for value in payloads)
                    parsed, messages = parse(text, purpose='block')
                    self.assertEqual(messages, [])
                    expected = sorted(parsed, key=lambda rule: rule.value)
                    for order in (parsed, parsed[::-1], parsed + parsed):
                        with self.subTest(kind=kind, payloads=payloads, order=order):
                            actual = normalize(iter(order))
                            self.assertEqual(actual, expected)
                            self.assertEqual({rule.value for rule in actual}, set(payloads))
                    for candidate in parsed:
                        self.assertEqual(exclude_covered([candidate], iter(parse_whitelist(text))), [])

    def test_identity_groups_and_ascii_surge_native_controls_remain(self):
        pair = [Rule('DOMAIN-KEYWORD', value, domain_source='qx') for value in ('ΟΣ', 'ος')]
        for change in ({}, {'allow': True}, {'options': ('force-cellular',)},
                       {'literal_process': True}, {'native_fields': True}):
            protected = [replace(rule, **change) for rule in pair]
            self.assertEqual(set(normalize(iter(protected + protected[::-1]))), set(protected))
        source = Rule('DOMAIN-KEYWORD', 'ΟΣ', domain_source='qx')
        for change in ({'allow': True}, {'options': ('special',)}, {'literal_process': True},
                       {'native_fields': True}, {'domain_source': 'surge'}, {'domain_source': 'mihomo'}):
            other = replace(source, **change)
            self.assertEqual(set(normalize(iter([source, other, source]))), {source, other})
        for source_name in ('surge', 'mihomo'):
            pair = [Rule('DOMAIN-KEYWORD', value, domain_source=source_name) for value in ('ΟΣ', 'ος')]
            self.assertEqual(normalize(pair), pair)
        parsed, messages = parse('HOST-KEYWORD,ADS\nHOST-KEYWORD,ads\nHOST-KEYWORD,xads\n'
                                 'HOST-WILDCARD,*.example.com\nHOST-SUFFIX,example.com', purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(normalize(iter(parsed)), [Rule('DOMAIN-KEYWORD', 'ads', domain_source='qx'),
                                                  Rule('DOMAIN-SUFFIX', 'example.com', domain_source='qx')])
        self.assertEqual(exclude_covered(iter(parsed), iter(parse_whitelist('HOST-KEYWORD,ads\n'
                                                                         'HOST-SUFFIX,example.com'))), [])
        qx = Rule('DOMAIN-KEYWORD', 'Σ', domain_source='qx')
        self.assertEqual(exclude_covered([qx], [replace(qx, domain_source='mihomo')]), [qx])
        allowed = replace(qx, allow=True)
        self.assertEqual(exclude_covered([allowed, qx], [qx]), [allowed])

    def test_qx_unicode_wildcard_is_not_reduced_by_ascii_suffix(self):
        parsed, messages = parse('HOST-WILDCARD,Σ.example.com\nHOST-SUFFIX,example.com', purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(set(normalize(iter(parsed))), set(parsed))

    def test_public_allow_and_raw_target_white_preserve_unproved_qx_matchers(self):
        parsed, messages = parse('HOST-KEYWORD,İ\nHOST-KEYWORD,i̇', purpose='block')
        self.assertEqual(messages, [])
        allowed = replace(parsed[1], allow=True)
        self.assertEqual(exclude_covered(iter([parsed[0], allowed]), iter([allowed])), [parsed[0], allowed])
        native, messages = parse('payload:\n  - DOMAIN-KEYWORD,İ\n  - DOMAIN-KEYWORD,i̇', purpose='block')
        self.assertEqual(messages, [])
        for rules, white in (([parsed[0], allowed], []),
                             ([parsed[0]], parse_whitelist('HOST-KEYWORD,i̇')),
                             ([native[0]], parse_whitelist('payload:\n  - DOMAIN-KEYWORD,i̇'))):
            outputs, _ = render('white', normalize(iter(rules)), purpose='proxy', no_resolve='keep', whitelist=white)
            self.assertEqual(outputs['fin.yaml'], '# white rules: 1\npayload:\n  - "DOMAIN-KEYWORD,İ"\n')
        self.assertEqual(exclude_covered(native, parse_whitelist('payload:\n  - DOMAIN-KEYWORD,İ')), [])

    def test_exact_six_format_unicode_bodies_and_diagnostics_in_nine_modes(self):
        for kind in ('KEYWORD', 'WILDCARD'):
            for purpose in ('block', 'direct', 'proxy'):
                parsed, messages = parse('HOST-' + kind + ',İ\nHOST-' + kind + ',i̇', purpose=purpose)
                self.assertEqual(messages, [])
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(kind=kind, purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        outputs, diagnostics = render('unicode', normalize(iter(parsed)), purpose=purpose, no_resolve=mode)
                        body = 'DOMAIN-' + kind + ',İ\nDOMAIN-' + kind + ',i̇\n'
                        expected = {
                            'fin.txt': '# unicode rules: 2\n' + body,
                            'fin-surge.txt': '# unicode rules: 2\n' + body,
                            'fin-surge-ds.txt': '# unicode rules: 0\n',
                            'fin-qx.txt': '# unicode rules: 2\nHOST-' + kind + ',İ,LIST\nHOST-' + kind + ',i̇,LIST\n',
                            'fin.yaml': '# unicode rules: 2\npayload:\n  - "DOMAIN-' + kind + ',İ"\n'
                                        '  - "DOMAIN-' + kind + ',i̇"\n',
                            'fin-adb.txt': '[Adblock Plus 2.0]\n! Title: unicode\n'
                                           '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                           '! License: Inherits upstream licenses\n! Version: 202610240000\n' +
                                           ('! Total count: 2\n/^.*İ.*$/\n/^.*i̇.*$/\n'
                                            if kind == 'KEYWORD' and purpose == 'block' else '! Total count: 0\n' +
                                            ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n')),
                        }
                        self.assertEqual(outputs, expected)
                        skipped = {'fin-surge-ds.txt:DOMAIN-' + kind: 2}
                        if kind == 'WILDCARD' or purpose != 'block':
                            skipped['fin-adb.txt:DOMAIN-' + kind] = 2
                        self.assertEqual(diagnostics, skipped)
                        native, messages = parse(outputs['fin.yaml'], purpose=purpose)
                        self.assertEqual(messages, [])
                        self.assertEqual({rule.value for rule in native}, {'İ', 'i̇'})
                        self.assertTrue(all(rule.domain_source == 'mihomo' for rule in native))

    def test_generated_qx_source_and_white_keep_real_same_round_and_disk_matchers(self):
        cases = (('KEYWORD', 'ΟΣ', 'ος'), ('KEYWORD', 'İ', 'i̇'),
                 ('WILDCARD', 'İ', 'i̇'), ('WILDCARD', '*İ*', '*i̇*'),
                 ('WILDCARD', '*ΟΣ*', '*ος*'))
        for kind, first, second in cases:
            for mixed in (False, True):
                with self.subTest(kind=kind, first=first, mixed=mixed), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    source = root / 'static/source.list'
                    rows = ['HOST-' + kind + ',' + value + ',LIST' for value in (first, second)]
                    if mixed:
                        rows.append('HOST,neighbor.example.org,LIST')
                    source.write_bytes(('﻿' + '\r\n'.join(rows) + '\r\n').encode('utf-8'))
                    white = root / 'static/white.list'
                    white.write_bytes(('HOST-' + kind + ',' + second + ',LIST\r\n').encode('utf-8'))
                    inputs = {path: path.read_bytes() for path in (source, white)}
                    configs = [
                        dict(name='parent', sources=['static/source.list'], whitelist=[]),
                        dict(name='white', sources=['static/white.list'], whitelist=[]),
                        dict(name='source', sources=['parent/fin-qx.txt'], whitelist=[]),
                        dict(name='consumer', sources=['static/source.list'], whitelist=['white/fin-qx.txt']),
                        dict(name='external', sources=['static/source.list'], whitelist=['static/white.list']),
                        dict(name='native', sources=['parent/fin.yaml'], whitelist=[]),
                    ]
                    for config in configs:
                        config.update(purpose='block', no_resolve='keep')
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
                    for group in ('parent', 'source', 'consumer', 'external', 'native', 'white'):
                        actual, messages = parse(outputs[root / group / 'fin.yaml'], purpose='block')
                        self.assertEqual(messages, [])
                        values = {second} if group == 'white' else {first} if group in {'consumer', 'external'} else {first, second}
                        if group == 'native' and kind == 'KEYWORD' and first == 'İ':
                            values = {first}
                        if mixed and group != 'white':
                            values.add('neighbor.example.org')
                        self.assertEqual({rule.value for rule in actual}, values)
                        self.assertTrue(all(rule.domain_source == 'mihomo' for rule in actual))
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in old},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    parents = {path: path.read_bytes() for path in old if path.parent.name in {'parent', 'white'}}
                    qx_text = (root / 'parent/fin-qx.txt').read_text(encoding='utf-8')
                    self.assertTrue(qx_text.splitlines()[1:])
                    parsed, messages = parse(qx_text, purpose='block')
                    self.assertEqual(messages, [])
                    self.assertEqual({rule.value for rule in parsed if rule.kind == 'DOMAIN-' + kind}, {first, second})
                    self.assertEqual(parse_whitelist(qx_text), parsed)
                    config_path.write_text(json.dumps(configs[2:]), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_log:
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        disk = generate(root, self.fail)
                    self.assertEqual(disk, {path: text for path, text in outputs.items()
                                            if path.parent.name not in {'parent', 'white'}})
                    self.assertEqual(disk_log.getvalue().splitlines(),
                                     [line for line in log.getvalue().splitlines()
                                      if not line.startswith(('parent ', 'white '))])
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in disk},
                                     {path: text.encode('utf-8') for path, text in disk.items()})
                    self.assertEqual({path: path.read_bytes() for path in parents}, parents)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
