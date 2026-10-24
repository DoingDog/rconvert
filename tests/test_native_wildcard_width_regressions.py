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
from rules import exclude_covered, normalize, parse, parse_whitelist


class NativeWildcardWidthTests(unittest.TestCase):
    def test_native_wildcard_uses_lowercase_utf8_width_for_candidate(self):
        source, messages = parse('payload:\n  - DOMAIN-WILDCARD,ẞ.example', purpose='block')
        self.assertEqual(messages, [])
        white = parse_whitelist('payload:\n  - DOMAIN-WILDCARD,???.example')
        self.assertEqual(exclude_covered(iter(source), iter(white)), source)

    def test_three_constructor_widths_and_white_literals_cover_only_correct_bytes(self):
        for original, lowered, width, wrong in (('ẞ', 'ß', 2, 3), ('Ⱥ', 'ⱥ', 3, 2), ('Å', 'å', 2, 3)):
            self.assertEqual(len(lowered.encode('utf-8')), width)
            for source_value in (original + '.example', lowered + '.example'):
                candidate, messages = parse('payload:\n  - DOMAIN-WILDCARD,' + source_value, purpose='block')
                self.assertEqual(messages, [])
                for count in (wrong, width):
                    white = parse_whitelist('payload:\n  - DOMAIN-WILDCARD,' + '?' * count + '.example')
                    with self.subTest(original=original, source=source_value, count=count):
                        self.assertEqual(exclude_covered(iter(candidate), iter(white)), candidate if count == wrong else [])
            candidate, messages = parse('payload:\n  - DOMAIN-WILDCARD,' + lowered + '.example', purpose='block')
            self.assertEqual(messages, [])
            white = parse_whitelist('payload:\n  - DOMAIN-WILDCARD,' + original + '.*')
            self.assertEqual(exclude_covered(iter(candidate), iter(white)), [])
            allowed = replace(candidate[0], allow=True)
            self.assertEqual(exclude_covered([allowed, candidate[0]], white), [allowed])
            self.assertEqual(normalize(iter([candidate[0], candidate[0]])), candidate)

    def test_six_format_target_coverage_in_nine_modes(self):
        for original, width, wrong in (('ẞ', 2, 3), ('Ⱥ', 3, 2), ('Å', 2, 3)):
            source, messages = parse('payload:\n  - DOMAIN-WILDCARD,' + original + '.example', purpose='block')
            self.assertEqual(messages, [])
            for count in (wrong, width):
                white = parse_whitelist('payload:\n  - DOMAIN-WILDCARD,' + '?' * count + '.example')
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(original=original, count=count, purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            outputs, diagnostics = render('width', source, purpose=purpose, no_resolve=mode, whitelist=white)
                        covered = count == width
                        header = '# width rules: '
                        expected = {
                            'fin.txt': header + '0\n', 'fin-surge.txt': header + '0\n',
                            'fin-surge-ds.txt': header + '0\n',
                            'fin-qx.txt': header + '1\nHOST-WILDCARD,' + original + '.example,LIST\n',
                            'fin.yaml': header + ('0\npayload:\n' if covered else
                                                '1\npayload:\n  - "DOMAIN-WILDCARD,' + original + '.example"\n'),
                            'fin-adb.txt': '[Adblock Plus 2.0]\n! Title: width\n'
                                           '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                           '! License: Inherits upstream licenses\n! Version: 202610240000\n'
                                           '! Total count: 0\n' + ('' if purpose == 'block' else
                                           '! No AdBlock rules for non-advertising group.\n'),
                        }
                        self.assertEqual(outputs, expected)
                        skips = {name + ':DOMAIN-WILDCARD': 1 for name in
                                 ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt')}
                        skips['fin-adb.txt:DOMAIN-WILDCARD'] = 2 if purpose == 'block' else 1
                        if covered:
                            skips['fin.yaml:DOMAIN-WILDCARD:whitelist-covered'] = 1
                        self.assertEqual(diagnostics, skips)

    def test_native_source_and_white_same_round_and_disk_publish_real_bytes(self):
        for original, width, wrong in (('ẞ', 2, 3), ('Ⱥ', 3, 2), ('Å', 2, 3)):
            for count in (wrong, width):
                for mixed in (False, True):
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(original=original, count=count, mixed=mixed, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                                root = Path(directory)
                                (root / 'static').mkdir()
                                source = root / 'static/source.yaml'
                                source.write_bytes(('﻿rules:\r\n  - "DOMAIN-WILDCARD,' + original + '.example"\r\n' +
                                                   ('  - DOMAIN,keep.other.org\r\n' if mixed else '')).encode('utf-8'))
                                white = root / 'static/white.yaml'
                                white.write_bytes(('payload:\n  - DOMAIN-WILDCARD,' + '?' * count + '.example\n').encode('utf-8'))
                                inputs = {path: path.read_bytes() for path in (source, white)}
                                configs = [dict(name='parent', sources=['static/source.yaml'], whitelist=[]),
                                           dict(name='white', sources=['static/white.yaml'], whitelist=[]),
                                           dict(name='source', sources=['parent/fin.yaml'], whitelist=[]),
                                           dict(name='consumer', sources=['parent/fin.yaml'], whitelist=['white/fin.yaml'])]
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
                                for group in ('parent', 'source', 'consumer'):
                                    parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                    self.assertEqual(messages, [])
                                    values = {original + '.example'} if group != 'consumer' or count == wrong else set()
                                    if mixed:
                                        values.add('keep.other.org')
                                    self.assertEqual({rule.value for rule in parsed}, values)
                                publish(outputs, root=root)
                                self.assertEqual({path: path.read_bytes() for path in outputs},
                                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                                parents = {path: path.read_bytes() for path in old if path.parent.name in {'parent', 'white'}}
                                self.assertTrue((root / 'parent/fin.yaml').read_bytes().splitlines()[2:])
                                self.assertTrue(parse_whitelist((root / 'white/fin.yaml').read_text(encoding='utf-8')))
                                config_path.write_text(json.dumps(configs[2:]), encoding='utf-8')
                                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_log:
                                    clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                                    disk = generate(root, self.fail)
                                self.assertEqual(disk, {path: text for path, text in outputs.items()
                                                        if path.parent.name not in {'parent', 'white'}})
                                self.assertEqual(disk_log.getvalue().splitlines(),
                                                 [line for line in log.getvalue().splitlines()
                                                  if line.startswith(('source ', 'consumer '))])
                                publish(disk, root=root)
                                self.assertEqual({path: path.read_bytes() for path in disk},
                                                 {path: text.encode('utf-8') for path, text in disk.items()})
                                self.assertEqual({path: path.read_bytes() for path in parents}, parents)
                                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
