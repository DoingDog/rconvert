import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


ADDRESSES = ('0.0.0.0', '127.0.0.1', '::', '::1')
NONSTANDARD_SPACES = ('\x1c', '\x1d', '\x1e', '\x1f', '\xa0', ' ',
                      ' ', ' ', ' ', ' ', ' ', ' ',
                      ' ', ' ', ' ', ' ', ' ', ' ',
                      ' ', '　')


class HostsWhitespaceTests(unittest.TestCase):
    def test_nbsp_inside_alias_warns_without_creating_extra_domains(self):
        source = ('0.0.0.0 good.example bad.example protected.example sibling.example\n'
                  'DOMAIN,neighbor.example')
        self.assertEqual(parse(source, purpose='block'),
                         ([Rule('DOMAIN', value) for value in
                           ('good.example', 'sibling.example', 'neighbor.example')],
                          ['line 1: invalid hosts domain bad.example protected.example']))

    def test_nbsp_at_alias_end_survives_hosts_preprocessing(self):
        source = ('0.0.0.0 good.example sibling.example protected.example \n'
                  'DOMAIN,neighbor.example')
        self.assertEqual(parse(source, purpose='block'),
                         ([Rule('DOMAIN', value) for value in
                           ('good.example', 'sibling.example', 'neighbor.example')],
                          ['line 1: invalid hosts domain protected.example ']))

    def test_nonstandard_whitespace_positions_preserve_alias_and_line_boundaries(self):
        recovered = [Rule('DOMAIN', value) for value in
                     ('good.example', 'sibling.example', 'neighbor.example')]
        neighbor = [recovered[-1]]
        for space in NONSTANDARD_SPACES:
            for address in ADDRESSES:
                for newline in ('\n', '\r\n'):
                    cases = (
                        ('inside', address + ' good.example bad.example' + space +
                         'protected.example sibling.example', recovered,
                         'invalid hosts domain bad.example' + space + 'protected.example'),
                        ('trailing', address + ' good.example sibling.example protected.example' + space,
                         recovered, 'invalid hosts domain protected.example' + space),
                        ('before-comment', address + ' good.example sibling.example protected.example' +
                         space + '#<html>,"(', recovered, 'invalid hosts domain protected.example' + space),
                        ('after-address', address + space + 'protected.example sibling.example',
                         neighbor, 'invalid rule'),
                        ('leading', space + address + ' protected.example sibling.example',
                         neighbor, 'invalid rule'),
                    )
                    for position, line, expected, reason in cases:
                        with self.subTest(space=f'U+{ord(space):04X}', address=address,
                                          newline=repr(newline), position=position):
                            source = '﻿' + newline + '# header' + newline + line + newline + 'DOMAIN,neighbor.example'
                            messages = ['line 3: ' + reason]
                            self.assertEqual(parse(source, purpose='block'), (expected, messages))
                            with warnings.catch_warnings(record=True) as caught:
                                warnings.simplefilter('always')
                                self.assertEqual(parse_whitelist(source), expected)
                            self.assertEqual([str(item.message) for item in caught], messages)

    def test_nonstandard_separator_cannot_supply_ascii_address_boundary(self):
        neighbor = Rule('DOMAIN', 'neighbor.example')
        for space in NONSTANDARD_SPACES:
            for address in ADDRESSES:
                for suffix in ('protected.example', ' protected.example', '\tprotected.example'):
                    with self.subTest(space=f'U+{ord(space):04X}', address=address, suffix=suffix):
                        source = address + space + suffix + '\nDOMAIN,neighbor.example'
                        self.assertEqual(parse(source, purpose='block'),
                                         ([neighbor], ['line 1: invalid rule']))

    def test_ascii_space_tab_bom_comments_and_block_only_stay_supported(self):
        expected = [Rule('DOMAIN', value) for value in
                    ('good.example', 'sibling.example', 'neighbor.example')]
        for address in ADDRESSES:
            for separator in (' ', '\t', ' \t  \t'):
                for newline in ('\n', '\r\n'):
                    for comment in ('', ' ignored.example', '<html><div>,"(', '; //   protected.example'):
                        with self.subTest(address=address, separator=repr(separator),
                                          newline=repr(newline), comment=comment):
                            source = ('﻿' + newline + '# header' + newline + ' \t' + address + separator +
                                      'GOOD.EXAMPLE.' + separator + 'SIBLING.EXAMPLE.' + separator + '#' +
                                      comment + newline + 'DOMAIN,neighbor.example' + newline)
                            self.assertEqual(parse(source, purpose='block'), (expected, []))
                            self.assertEqual(parse_whitelist(source), expected)
                            for purpose in ('direct', 'proxy'):
                                self.assertEqual(parse(source, purpose=purpose),
                                                 ([expected[-1]], ['line 3: hosts entry is block-only']))

    def test_native_two_headers_three_scalars_keep_ascii_leading_hosts(self):
        expected = [Rule('DOMAIN', value) for value in
                    ('good.example', 'sibling.example', 'native.example', 'neighbor.example')]
        expected[2] = Rule('DOMAIN', 'native.example', domain_source='mihomo')
        for header in ('payload:', 'rules:'):
            for address in ADDRESSES:
                for prefix in ('', ' ', '\t', ' \t '):
                    for style in ('plain', 'single', 'double'):
                        value = prefix + address + ' \tGOOD.EXAMPLE.\t SIBLING.EXAMPLE. \t'
                        scalar = value if style == 'plain' else "'" + value + "'" if style == 'single' else json.dumps(value)
                        source = ('﻿' + header + '\r\n  - ' + scalar + '\r\n'
                                  '  - DOMAIN,native.example\r\nDOMAIN,neighbor.example\r\n')
                        yaml_invalid = style == 'plain' and (address.startswith(':') or '\t' in prefix)
                        wanted = expected[2:] if yaml_invalid else expected
                        messages = ['line 2: invalid YAML payload'] if yaml_invalid else []
                        with self.subTest(header=header, address=address, prefix=repr(prefix), style=style):
                            self.assertEqual(parse(source, purpose='block'), (wanted, messages))
                            with warnings.catch_warnings(record=True) as caught:
                                warnings.simplefilter('always')
                                self.assertEqual(parse_whitelist(source), wanted)
                            self.assertEqual([str(item.message) for item in caught], messages)
                            for purpose in ('direct', 'proxy'):
                                self.assertEqual(parse(source, purpose=purpose),
                                                 (expected[2:], messages if yaml_invalid else
                                                  ['line 2: hosts entry is block-only']))

    def test_native_nonstandard_aliases_keep_yaml_character_and_comment_rules(self):
        for header in ('payload:', 'rules:'):
            for style in ('plain', 'single', 'double'):
                for space in NONSTANDARD_SPACES:
                    for address in ADDRESSES:
                        value = address + ' good.example bad.example' + space + 'protected.example sibling.example'
                        scalar = value if style == 'plain' else "'" + value + "'" if style == 'single' else json.dumps(value)
                        source = header + '\n  - ' + scalar + '\n  - DOMAIN,native.example\nDOMAIN,neighbor.example'
                        neighbors = [Rule('DOMAIN', 'native.example', domain_source='mihomo'),
                                     Rule('DOMAIN', 'neighbor.example')]
                        yaml_invalid = (style == 'plain' and address.startswith(':') or
                                        style != 'double' and space in ('\x1c', '\x1d', '\x1e', '\x1f'))
                        expected = neighbors if yaml_invalid else [Rule('DOMAIN', 'good.example'),
                                                                   Rule('DOMAIN', 'sibling.example'), *neighbors]
                        reason = 'invalid YAML payload' if yaml_invalid else 'invalid hosts domain bad.example' + space + 'protected.example'
                        with self.subTest(header=header, style=style, space=f'U+{ord(space):04X}', address=address):
                            self.assertEqual(parse(source, purpose='block'), (expected, ['line 2: ' + reason]))
                            with warnings.catch_warnings(record=True) as caught:
                                warnings.simplefilter('always')
                                self.assertEqual(parse_whitelist(source), expected)
                            self.assertEqual([str(item.message) for item in caught], ['line 2: ' + reason])
        for scalar, expected, messages in (
                ('0.0.0.0 good.example # ignored', [Rule('DOMAIN', 'good.example')], []),
                ("'0.0.0.0 good.example#tag'", [], ['line 2: invalid hosts domain good.example#tag']),
                ('"0.0.0.0 good.example\\u00a0"', [], ['line 2: invalid hosts domain good.example '])):
            with self.subTest(scalar=scalar):
                self.assertEqual(parse('payload:\n  - ' + scalar, purpose='block'), (expected, messages))

    def test_physical_line_rejection_precedes_hosts_comment_trimming(self):
        neighbor = Rule('DOMAIN', 'neighbor.example')
        for control in ('\0', '\r', '\v', '\f', '\x85', ' ', ' '):
            for suffix in (' protected.example' + control + 'tail', '# ignored' + control + 'tail'):
                with self.subTest(control=repr(control), suffix=repr(suffix)):
                    source = '﻿\r\n# header\r\n::1 good.example' + suffix + '\r\nDOMAIN,neighbor.example'
                    self.assertEqual(parse(source, purpose='block'),
                                     ([neighbor], ['line 3: unsupported physical line separator']))

    def assert_products(self, outputs, group, values, white=(), purpose='block'):
        bodies = {
            'fin.txt': ['DOMAIN,' + value for value in values],
            'fin-qx.txt': ['HOST,' + value + ',LIST' for value in values],
            'fin.yaml': ['  - ' + json.dumps('DOMAIN,' + value) for value in values],
            'fin-surge.txt': [],
            'fin-surge-ds.txt': list(values),
            'fin-adb.txt': (['@@|' + value + '|' for value in white] +
                            ['0.0.0.0 ' + value for value in values]) if purpose == 'block' else [],
        }
        self.assertEqual(set(outputs), set(FILES))
        for name, body in bodies.items():
            header = ('[Adblock Plus 2.0]\n! Title: ' + group + '\n'
                      '! Homepage: https://github.com/DoingDog/rconvert\n'
                      '! Expires: 1 day\n! License: Inherits upstream licenses\n'
                      '! Version: 202610241200\n! Total count: ' + str(len(body)) + '\n'
                      if name == 'fin-adb.txt' else f'# {group} rules: {len(body)}\n')
            expected = header + ('payload:\n' if name == 'fin.yaml' else '') + ''.join(line + '\n' for line in body)
            if name == 'fin-adb.txt' and purpose != 'block':
                expected += '! No AdBlock rules for non-advertising group.\n'
            with self.subTest(group=group, file=name, purpose=purpose):
                self.assertEqual(outputs[name].encode('utf-8'), expected.encode('utf-8'))

    def test_public_white_normalize_and_six_formats_never_invent_protected_host(self):
        expected = [Rule('DOMAIN', value) for value in
                    ('good.example', 'sibling.example', 'neighbor.example')]
        normalized_expected = [expected[0], expected[2], expected[1]]
        for space in NONSTANDARD_SPACES:
            source = ('0.0.0.0 good.example bad.example' + space + 'protected.example sibling.example\n'
                      'DOMAIN,neighbor.example')
            parsed, messages = parse(source, purpose='block')
            self.assertEqual((parsed, messages), (expected, ['line 1: invalid hosts domain bad.example' + space + 'protected.example']))
            normalized = normalize(iter([*parsed, *reversed(parsed)]))
            self.assertEqual(normalized, normalized_expected)
            self.assertEqual(normalize(iter(reversed(normalized))), normalized_expected)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                white = parse_whitelist(source)
            self.assertEqual(white, expected)
            self.assertEqual([str(item.message) for item in caught], messages)
            candidates = [Rule('DOMAIN', value) for value in
                          ('bad.example', 'good.example', 'neighbor.example', 'sibling.example', 'protected.example')]
            remaining = exclude_covered(iter(candidates), iter(white))
            self.assertEqual(remaining, [candidates[0], candidates[-1]])
            self.assertIs(remaining[0], candidates[0])
            self.assertIs(remaining[1], candidates[-1])
            for purpose in ('block', 'direct', 'proxy'):
                direct_parsed, direct_messages = parse(source, purpose=purpose)
                self.assertEqual((direct_parsed, direct_messages), (expected, messages) if purpose == 'block' else
                                 ([expected[-1]], ['line 1: hosts entry is block-only']))
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(space=f'U+{ord(space):04X}', purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                        clock.now.return_value = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
                        outputs, diagnostics = render('hosts', iter(normalized), purpose=purpose, no_resolve=mode)
                        self.assertEqual(diagnostics, {} if purpose == 'block' else {'fin-adb.txt:DOMAIN': 3})
                        self.assert_products(outputs, 'hosts', ('good.example', 'sibling.example', 'neighbor.example'), purpose=purpose)
                        outputs, diagnostics = render('white', iter(remaining), whitelist=iter(white),
                                                      purpose=purpose, no_resolve=mode)
                        self.assertEqual(diagnostics, {} if purpose == 'block' else {'fin-adb.txt:DOMAIN': 2})
                        self.assert_products(outputs, 'white', ('bad.example', 'protected.example'),
                                             ('good.example', 'sibling.example', 'neighbor.example'), purpose)
                        self.assertNotIn('@@|protected.example|', outputs['fin-adb.txt'])

    def test_generate_direct_proxy_keep_block_only_and_protected_neighbor(self):
        for purpose in ('direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    hosts = root / 'static/hosts'
                    hosts.write_bytes(('﻿\r\n::1 good.example bad.example protected.example sibling.example#<html>,"(\r\n'
                                       'DOMAIN,protected.example\r\n').encode('utf-8'))
                    config_path = root / 'rulesets.json'
                    config_path.write_text(json.dumps([{'name': 'hosts', 'purpose': purpose, 'no_resolve': mode,
                                                       'sources': ['static/hosts'], 'whitelist': []}]), encoding='utf-8')
                    inputs = {path: path.read_bytes() for path in (hosts, config_path)}
                    (root / 'hosts').mkdir()
                    previous = {root / 'hosts' / name: b'old product\x00\xff\r\n' for name in FILES}
                    for path, data in previous.items():
                        path.write_bytes(data)
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as logs:
                        clock.now.return_value = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
                        outputs = generate(root, self.fail)
                    self.assertEqual(logs.getvalue().splitlines(),
                                     [str(hosts) + ': line 2: hosts entry is block-only', 'hosts fin-adb.txt:DOMAIN: 1'])
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    self.assert_products({name: outputs[root / 'hosts' / name] for name in FILES},
                                         'hosts', ('protected.example',), purpose=purpose)
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_standalone_hosts_publish_and_can_be_fully_whitelisted(self):
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                source = root / 'static/hosts'
                source.write_bytes('0.0.0.0 good.example bad.example protected.example sibling.example\n'.encode('utf-8'))
                original = source.read_bytes()
                configs = [{'name': group, 'purpose': 'block', 'no_resolve': mode,
                            'sources': ['static/hosts'], 'whitelist': white}
                           for group, white in (('hosts', []), ('cleared', ['static/hosts']))]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with patch('formats.datetime') as clock, warnings.catch_warnings(record=True) as caught, \
                        contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
                    warnings.simplefilter('always')
                    outputs = generate(root, self.fail)
                message = 'line 1: invalid hosts domain bad.example protected.example'
                self.assertEqual([str(item.message) for item in caught], [message])
                self.assertEqual(logs.getvalue().splitlines(), [str(source) + ': ' + message] * 2)
                self.assert_products({name: outputs[root / 'hosts' / name] for name in FILES},
                                     'hosts', ('good.example', 'sibling.example'))
                self.assert_products({name: outputs[root / 'cleared' / name] for name in FILES},
                                     'cleared', (), ('good.example', 'sibling.example'))
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual(source.read_bytes(), original)

    def test_all_invalid_hosts_fail_without_replacing_old_products(self):
        for invalid in ('bad.example protected.example', 'protected.example '):
            for mode in ('add', 'strip', 'keep'):
                for role in ('sources', 'whitelist'):
                    with self.subTest(invalid=invalid, mode=mode, role=role), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        bad = root / 'static/bad'
                        bad.write_bytes(('﻿\r\n0.0.0.0 ' + invalid + '#comment\r\n').encode('utf-8'))
                        good = root / 'static/good'
                        good.write_bytes(b'DOMAIN,protected.example\n')
                        config = {'name': 'hosts', 'purpose': 'block', 'no_resolve': mode,
                                  'sources': ['static/good'], 'whitelist': []}
                        config[role] = ['static/bad']
                        config_path = root / 'rulesets.json'
                        config_path.write_text(json.dumps([config]), encoding='utf-8')
                        (root / 'hosts').mkdir()
                        previous = {root / 'hosts' / name: b'old product\x00\xff\r\n' for name in FILES}
                        for path, data in previous.items():
                            path.write_bytes(data)
                        inputs = {path: path.read_bytes() for path in (bad, good, config_path)}
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ValueError) as caught:
                            publish(generate(root, self.fail), root=root)
                        prefix = 'No adaptable rules in ' if role == 'sources' else 'Invalid whitelist '
                        self.assertTrue(str(caught.exception).startswith(prefix), str(caught.exception))
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_invalid_remote_source_freezes_dependents_and_invalid_white_is_skipped(self):
        remote = 'https://example.org/invalid-hosts-whitespace'
        for role in ('sources', 'whitelist'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                good = root / 'static/good'
                good.write_bytes(b'DOMAIN,protected.example\n')
                configs = [{'name': 'parent', 'purpose': 'block', 'no_resolve': 'keep',
                            'sources': ['static/good'], 'whitelist': []},
                           {'name': 'sourcechild', 'purpose': 'block', 'no_resolve': 'keep',
                            'sources': ['parent/fin.txt'], 'whitelist': []},
                           {'name': 'whitechild', 'purpose': 'block', 'no_resolve': 'keep',
                            'sources': ['static/good'], 'whitelist': ['parent/fin.txt']}]
                configs[0][role] = [remote]
                config_path = root / 'rulesets.json'
                config_path.write_text(json.dumps(configs), encoding='utf-8')
                previous = {}
                for config in configs:
                    (root / config['name']).mkdir()
                    for name in FILES:
                        path = root / config['name'] / name
                        previous[path] = b'old product\x00\xff\r\n'
                        path.write_bytes(previous[path])
                inputs = {path: path.read_bytes() for path in (good, config_path)}

                def fetch(url):
                    self.assertEqual(url, remote)
                    return '0.0.0.0 bad.example protected.example\n'.encode('utf-8')

                with contextlib.redirect_stderr(io.StringIO()) as logs:
                    outputs = generate(root, fetch)
                if role == 'sources':
                    self.assertEqual(outputs, {})
                    self.assertEqual(logs.getvalue().splitlines(),
                                     [remote + ': line 1: invalid hosts domain bad.example protected.example',
                                      remote + ': no adaptable rules; skipped'])
                else:
                    self.assertIn(remote + ': invalid whitelist (line 1: invalid hosts domain bad.example protected.example); skipped',
                                  logs.getvalue().splitlines())
                    self.assertEqual(set(outputs), set(previous))
                    self.assertIn('DOMAIN,protected.example\n', outputs[root / 'parent/fin.txt'])
                    self.assertNotIn('@@|protected.example|', outputs[root / 'parent/fin-adb.txt'])
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                publish(outputs, root=root)
                if role == 'sources':
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                else:
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_real_bytes_raw_generated_source_white_and_nonempty_disk_dependencies(self):
        remote = 'https://example.org/hosts-whitespace'
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                mixed = root / 'static/mixed'
                mixed.write_bytes(('﻿\r\n# header\r\n0.0.0.0 good.example bad.example protected.example '
                                   'sibling.example#<html>,"(\r\nDOMAIN,neighbor.example\r\n').encode('utf-8'))
                blocked = root / 'static/blocked'
                blocked.write_bytes(b'0.0.0.0 bad.example good.example sibling.example neighbor.example protected.example\n')
                configs = [{'name': group, 'purpose': 'block', 'no_resolve': mode,
                            'sources': sources, 'whitelist': white} for group, sources, white in
                           (('parent', ['static/mixed'], []),
                            ('rawsource', [remote], []),
                            ('rawwhite', ['static/blocked'], ['static/mixed']),
                            ('remotewhite', ['static/blocked'], [remote]),
                            ('cleared', ['static/mixed'], ['static/mixed']),
                            ('sourcechild', ['parent/fin.txt'], []),
                            ('whitechild', ['static/blocked'], ['parent/fin.txt']))]
                consumers = ('sourcechild', 'whitechild')
                config_path = root / 'rulesets.json'
                config_path.write_text(json.dumps(configs), encoding='utf-8')
                inputs = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (mixed, blocked, config_path)}
                previous = {}
                for config in configs:
                    (root / config['name']).mkdir()
                    for filename in FILES:
                        path = root / config['name'] / filename
                        previous[path] = b'old product\x00\xff\r\n'
                        path.write_bytes(previous[path])
                calls = []

                def fetch(url):
                    self.assertEqual(url, remote)
                    calls.append(url)
                    return mixed.read_bytes()

                message = 'line 3: invalid hosts domain bad.example protected.example'
                with patch('formats.datetime') as clock, warnings.catch_warnings(record=True) as caught, \
                        contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
                    warnings.simplefilter('always')
                    outputs = generate(root, fetch)
                self.assertEqual(calls, [remote])
                self.assertEqual([str(item.message) for item in caught], [message] * 2)
                self.assertEqual(logs.getvalue().splitlines(), [str(source) + ': ' + message
                                                              for source in (mixed, remote, mixed)])
                self.assertEqual(set(outputs), set(previous))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                for config in configs:
                    group = config['name']
                    is_white = group in ('rawwhite', 'remotewhite', 'whitechild')
                    values = () if group == 'cleared' else ('bad.example', 'protected.example') if is_white else \
                             ('good.example', 'sibling.example', 'neighbor.example')
                    white = ('good.example', 'sibling.example', 'neighbor.example') if is_white or group == 'cleared' else ()
                    self.assert_products({name: outputs[root / group / name] for name in FILES}, group, values, white)
                    self.assertNotIn('@@|protected.example|', outputs[root / group / 'fin-adb.txt'])
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)
                published = {path: path.read_bytes() for path in outputs}
                for path, data in previous.items():
                    path.write_bytes(data)
                real_replace = os.replace
                replacements = []

                def fail_second_replace(source, destination):
                    replacements.append(destination)
                    if len(replacements) == 2:
                        raise OSError('injected publication failure')
                    return real_replace(source, destination)

                with patch('generate.os.replace', side_effect=fail_second_replace), \
                        self.assertRaisesRegex(OSError, 'injected publication failure'):
                    publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                parent = {root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in FILES}
                self.assertTrue(all(parent.values()))
                config_path.write_text(json.dumps([config for config in configs if config['name'] in consumers]),
                                       encoding='utf-8')
                inputs[config_path] = hashlib.sha256(config_path.read_bytes()).hexdigest()
                with patch('formats.datetime') as clock, warnings.catch_warnings(record=True) as caught, \
                        contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
                    warnings.simplefilter('always')
                    disk = generate(root, self.fail)
                self.assertEqual(caught, [])
                self.assertEqual(logs.getvalue(), '')
                self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name in consumers})
                publish(disk, root=root)
                self.assertEqual({path: path.read_bytes() for path in disk},
                                 {path: text.encode('utf-8') for path, text in disk.items()})
                self.assertEqual({path: path.read_bytes() for path in parent}, parent)
                self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)
