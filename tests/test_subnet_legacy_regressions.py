import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


def expected_outputs(group, matcher, purpose):
    empty = f'# {group} rules: 0\n'
    route = f'# {group} rules: 1\n{matcher}\n'
    return {'fin.txt': route, 'fin-surge.txt': route, 'fin-surge-ds.txt': empty,
            'fin-qx.txt': empty, 'fin.yaml': empty + 'payload:\n',
            'fin-adb.txt': ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                '! License: Inherits upstream licenses\n! Version: 202610240000\n! Total count: 0\n' +
                ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n'))}


class SubnetLegacyRegressionTests(unittest.TestCase):
    def test_bare_bssid_survives_public_parse_and_surge_roundtrip(self):
        expected = [Rule('SUBNET', 'aa:bb:cc:dd:ee:ff')]
        parsed, messages = parse('SUBNET,aa:bb:cc:dd:ee:ff', purpose='proxy')
        self.assertEqual((parsed, messages), (expected, []))
        outputs, _ = render('subnet', parsed, purpose='proxy', no_resolve='keep')
        for name in ('fin.txt', 'fin-surge.txt'):
            self.assertEqual(outputs[name], '# subnet rules: 1\nSUBNET,aa:bb:cc:dd:ee:ff\n')
            self.assertEqual(parse(outputs[name], purpose='proxy'), (expected, []))

    def test_bare_values_and_quoted_logical_fields_keep_matcher_and_target_boundaries(self):
        values = ('aa:bb:cc:dd:ee:ff', 'AA:bB:CC:dd:EE:fF', '2001:db8::1', '::1',
                  'Office', '192.0.2.1', 'Office-*', 'Office-?', ' Office ', '\t', '\xa0')
        templates = ('{leaf}', 'AND,(({leaf}),(PROTOCOL,TCP))',
                     'OR,((PROTOCOL,UDP),({leaf}))', 'NOT,(({leaf}))')
        for value in values:
            for template in templates:
                source = template.format(leaf='SUBNET,"' + value + '"')
                matcher = template.format(leaf='SUBNET,' + ("'" + value + "'" if value != value.strip() else value))
                for purpose in ('block', 'direct', 'proxy'):
                    parsed, messages = parse(source, purpose=purpose)
                    self.assertEqual(messages, [])
                    expected = Rule('SUBNET', value) if template == '{leaf}' else Rule(*source.split(',', 1))
                    self.assertEqual(parsed, [expected])
                    self.assertEqual(normalize(iter(parsed + parsed)), parsed)
                    self.assertEqual(exclude_covered(iter(parsed), iter([Rule('DOMAIN', 'elsewhere.test')])), parsed)
                    self.assertEqual(parse_whitelist(source), [])
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(value=value, template=template, purpose=purpose, mode=mode):
                            with patch('formats.datetime') as clock:
                                clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                                outputs, diagnostics = render('subnet', normalize(parsed), purpose=purpose, no_resolve=mode)
                            self.assertEqual(outputs, expected_outputs('subnet', matcher, purpose))
                            self.assertEqual(diagnostics, {name + ':' + parsed[0].kind: 1
                                for name in ('fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge-ds.txt')})
                            for name in ('fin.txt', 'fin-surge.txt'):
                                reread, warnings = parse(outputs[name], purpose=purpose)
                                self.assertEqual(warnings, [])
                                with patch('formats.datetime') as clock:
                                    clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                                    self.assertEqual(render('subnet', reread, purpose=purpose, no_resolve=mode)[0], outputs)

    def test_prefixed_validation_and_invalid_colon_values_keep_physical_line_warnings(self):
        valid = ('SSID:Office-*', 'BSSID:AA:bb:cc:*', 'ROUTER:192.0.2.1', 'ROUTER:2001:db8::1',
                 'TYPE:WIFI', 'TYPE:wired', 'TYPE:CELLULAR', 'MCCMNC:310260', 'MCCMNC:46001')
        invalid = ('unknown:value', 'ssid:Office', 'type:WIFI', 'aa:bb:cc:dd:ee',
                   'aa:bb:cc:dd:ee:gg', 'aa:bb:cc:dd:ee:ff:00', '2001:db8::zz', '2001:db8::1/64',
                   'TYPE:aa:bb:cc:dd:ee:ff', 'TYPE:INVALID', 'TYPE:', 'SSID:', 'BSSID:',
                   'ROUTER:', 'ROUTER:aa:bb:cc:dd:ee:ff', 'ROUTER:192.0.2.999',
                   'MCCMNC:', 'MCCMNC:1234', 'MCCMNC:1234567', 'MCCMNC:12a45', '', '<placeholder>')
        for value in valid + invalid:
            for template in ('{leaf}', 'AND,(({leaf}),(PROTOCOL,TCP))',
                             'OR,((PROTOCOL,UDP),({leaf}))', 'NOT,(({leaf}))'):
                matcher = template.format(leaf='SUBNET,' + json.dumps(value))
                text = '﻿# input\r\n' + matcher + '\r\nDOMAIN,neighbor.test\r\n'
                with self.subTest(value=value, template=template):
                    parsed, messages = parse(text, purpose='proxy')
                    if value in valid:
                        self.assertEqual(messages, [])
                        self.assertEqual(len(parsed), 2)
                    else:
                        self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.test')])
                        self.assertEqual(len(messages), 1)
                        if value == '<placeholder>':
                            self.assertEqual(messages, ['line 2: HTML markup'])
                        else:
                            self.assertTrue(messages[0].startswith('line 2: invalid '), messages)

    def test_real_publish_and_nonempty_disk_sources_keep_bare_matchers(self):
        for matcher in ('SUBNET,aa:bb:cc:dd:ee:ff', 'SUBNET,2001:db8::1',
                        'AND,((SUBNET,AA:bb:CC:dd:EE:ff),(PROTOCOL,TCP))',
                        'OR,((PROTOCOL,UDP),(SUBNET,aa:bb:cc:dd:ee:ff))',
                        'NOT,((SUBNET,aa:bb:cc:dd:ee:ff))'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(matcher=matcher, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        source = ('﻿' + matcher + '\r\n').encode('utf-8')
                        (root / 'static/input.list').write_bytes(source)
                        (root / 'static/white.list').write_bytes(b'IP-CIDR,198.51.100.0/24\r\n')
                        (root / 'static/marker').write_bytes(b'static\x00\xff\r\n')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [dict(name=group, purpose=purpose, no_resolve=mode,
                                        sources=sources, whitelist=['static/white.list'])
                                   for group, sources in (('parent', ['static/input.list']),
                                                          ('full', ['parent/fin.txt']),
                                                          ('split', ['parent/fin-surge.txt']))]
                        config = root / 'rulesets.json'
                        config.write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for group in ('parent', 'full', 'split'):
                            (root / group).mkdir()
                            for name in FILES:
                                path = root / group / name
                                old[path] = b'old complete product\x00\xff\r\n'
                                path.write_bytes(old[path])
                        expected = {root / group / name: text for group in ('parent', 'full', 'split')
                                    for name, text in expected_outputs(group, matcher, purpose).items()}
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            outputs = generate(root, self.fail)
                        self.assertEqual(outputs, expected)
                        self.assertNotIn('frozen', diagnostic.getvalue())
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        config.write_text(json.dumps([configs[0], dict(configs[1], whitelist=['parent/fin.txt'])]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'unsupported rule'):
                            generate(root, self.fail)
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode() for path, text in expected.items()})
                        config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            disk = generate(root, self.fail)
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name != 'parent'})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        config.write_text(json.dumps([dict(configs[1], sources=['static/input.list'],
                                                           whitelist=['parent/fin.txt'])]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            self.assertEqual(generate(root, self.fail), {path: text for path, text in outputs.items()
                                                                      if path.parent.name == 'full'})
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
