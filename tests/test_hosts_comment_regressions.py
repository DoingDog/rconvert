import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


class HostsCommentTests(unittest.TestCase):
    def test_invalid_comma_alias_keeps_valid_aliases_and_neighbor(self):
        source = '127.0.0.1 good.example bad(,x sibling.example\nDOMAIN,neighbor.example'
        expected = [Rule('DOMAIN', value) for value in
                    ('good.example', 'sibling.example', 'neighbor.example')]
        self.assertEqual(parse(source, purpose='block'),
                         (expected, ['line 1: invalid hosts domain bad(,x']))

    def test_malformed_aliases_recover_in_block_and_white_across_hosts_forms(self):
        invalid = ('bad(,x', "bad,'x", 'bad,"x', ';', '//')
        expected = [Rule('DOMAIN', value) for value in
                    ('good.example', 'sibling.example', 'neighbor.example')]
        messages = ['line 3: invalid hosts domain ' + value for value in invalid]
        for address in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            for separator in (' ', '\t'):
                for newline in ('\n', '\r\n'):
                    with self.subTest(address=address, separator=separator, newline=newline):
                        source = ('﻿' + newline + '# header' + newline + ' \t' + address + separator +
                                  separator.join(('GOOD.EXAMPLE.', *invalid, 'SIBLING.EXAMPLE.')) +
                                  '#<html>,\"(' + newline + 'DOMAIN,neighbor.example' + newline)
                        self.assertEqual(parse(source, purpose='block'), (expected, messages))
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            self.assertEqual(parse_whitelist(source), expected)
                        self.assertEqual([str(item.message) for item in caught], messages)
                        for purpose in ('direct', 'proxy'):
                            self.assertEqual(parse(source, purpose=purpose),
                                             ([expected[-1]], ['line 3: hosts entry is block-only']))

    def test_malformed_aliases_do_not_bypass_physical_or_html_guards(self):
        hosts = '127.0.0.1 good.example bad(,x sibling.example'
        neighbor = [Rule('DOMAIN', 'neighbor.example')]
        for separator in ('\0', '\r', '\v', '\f', '\x85', ' ', ' '):
            for suffix in (' ' + separator + ' inside', '#comment' + separator + 'inside'):
                with self.subTest(separator=repr(separator), suffix=suffix):
                    self.assertEqual(parse(hosts + suffix + '\nDOMAIN,neighbor.example', purpose='block'),
                                     (neighbor, ['line 1: unsupported physical line separator']))
        for source in ('<!doctype html>\n' + hosts, '<html>\n' + hosts + '\n</html>'):
            self.assertEqual(parse(source, purpose='block'), ([], ['line 1: HTML document']))
        self.assertEqual(parse(hosts + ' <div>#comment\nDOMAIN,neighbor.example', purpose='block'),
                         (neighbor, ['line 1: HTML markup']))
        source = hosts + '#<html><div>,\"(\nDOMAIN,neighbor.example\n::1 last.example#</div></html>'
        expected = [Rule('DOMAIN', value) for value in
                    ('good.example', 'sibling.example', 'neighbor.example', 'last.example')]
        self.assertEqual(parse(source, purpose='block'),
                         (expected, ['line 1: invalid hosts domain bad(,x']))

    def test_each_quote_alias_recovers_through_public_white_normalize_and_render(self):
        for invalid in ("bad,'x", 'bad,"x'):
            with self.subTest(invalid=invalid):
                source = '\n# header\n::1 B. ' + invalid + ' a#<html>,"(\nDOMAIN,c'
                parsed, messages = parse(source, purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', value) for value in ('b', 'a', 'c')])
                self.assertEqual(messages, ['line 3: invalid hosts domain ' + invalid])
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    white = parse_whitelist('0.0.0.0 A. ' + invalid + ' b#ignored')
                self.assertEqual(white, [Rule('DOMAIN', 'a'), Rule('DOMAIN', 'b')])
                self.assertEqual([str(item.message) for item in caught],
                                 ['line 1: invalid hosts domain ' + invalid])
                normalized = normalize(iter([*parsed, *reversed(parsed)]))
                self.assertEqual(normalized, [Rule('DOMAIN', value) for value in ('a', 'b', 'c')])
                remaining = exclude_covered(iter(normalized), iter(white))
                self.assertEqual(remaining, [normalized[-1]])
                self.assertIs(remaining[0], normalized[-1])
                for mode in ('add', 'strip', 'keep'):
                    outputs, diagnostics = render('hosts', remaining, purpose='block',
                                                  whitelist=white, no_resolve=mode)
                    self.assertEqual(diagnostics, {})
                    self.assert_products({Path('hosts') / name: text for name, text in outputs.items()},
                                         Path('.'), 'hosts', ('c',), ('a', 'b'))

    def test_adjacent_hash_ends_hosts_aliases(self):
        self.assertEqual(
            parse('127.0.0.1 ads.example# note bogus.example', purpose='block'),
            ([Rule('DOMAIN', 'ads.example')], []),
        )

    def test_comments_are_removed_before_lexer_and_html_checks(self):
        comments = ('', ' note bogus.example', ',"unterminated', ", 'unterminated",
                    ' (((,))', '<div>', '<html>', '<!doctype html>', '<!-- unfinished')
        expected = [Rule('DOMAIN', 'ads.example'), Rule('DOMAIN', 'alias.example'),
                    Rule('DOMAIN', 'neighbor.example')]
        for address in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            for separator in (' ', '\t'):
                for comment in comments:
                    with self.subTest(address=address, separator=separator, comment=comment):
                        source = ('﻿ \t' + address + separator + 'ADS.EXAMPLE. alias.example#' + comment +
                                  '\r\nDOMAIN,neighbor.example\r\n')
                        self.assertEqual(parse(source, purpose='block'), (expected, []))
                        self.assertEqual(parse_whitelist(source), expected)

    def test_cross_line_tags_in_hosts_comments_do_not_hide_neighbors(self):
        source = ('127.0.0.1 a.example#<html><div>\n'
                  'DOMAIN,neighbor.example\n::1 b.example#</div></html>')
        expected = [Rule('DOMAIN', 'a.example'), Rule('DOMAIN', 'neighbor.example'),
                    Rule('DOMAIN', 'b.example')]
        self.assertEqual(parse(source, purpose='block'), (expected, []))
        self.assertEqual(parse_whitelist(source), expected)

    def test_invalid_aliases_keep_physical_line_numbers_and_valid_neighbors(self):
        source = ('﻿\r\n# header\r\n127.0.0.1 a.example bad+name b.example#bogus.example\r\n'
                  '::1 c.example#\r\nDOMAIN,neighbor.example\r\n')
        expected = [Rule('DOMAIN', value) for value in
                    ('a.example', 'b.example', 'c.example', 'neighbor.example')]
        self.assertEqual(parse(source, purpose='block'),
                         (expected, ['line 3: invalid hosts domain bad+name']))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertEqual(parse_whitelist(source), expected)
        self.assertEqual([str(item.message) for item in caught],
                         ['line 3: invalid hosts domain bad+name'])

    def test_hosts_remain_block_only_after_comment_removal(self):
        for address in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            for purpose in ('direct', 'proxy'):
                with self.subTest(address=address, purpose=purpose):
                    source = '\n' + address + '\ta.example#<html>,"(\nDOMAIN,neighbor.example'
                    self.assertEqual(parse(source, purpose=purpose),
                                     ([Rule('DOMAIN', 'neighbor.example')],
                                      ['line 2: hosts entry is block-only']))

    def test_typed_regex_qx_and_native_hashes_keep_their_existing_meaning(self):
        cases = (
            ('DOMAIN-KEYWORD,ads#tag', Rule('DOMAIN-KEYWORD', 'ads#tag')),
            ('PROCESS-NAME,127.0.0.1 ads#tag', Rule('PROCESS-NAME', '127.0.0.1 ads#tag')),
            ("DOMAIN-REGEX,'^ads#tag$'", Rule('DOMAIN-REGEX', '^ads#tag$')),
            ('PROCESS-NAME-REGEX,^127.0.0.1#tag$', Rule('PROCESS-NAME-REGEX', '^127.0.0.1#tag$')),
            ('HOST-KEYWORD,127.0.0.1 ads #tag,REJECT',
             Rule('DOMAIN-KEYWORD', '127.0.0.1 ads #tag', domain_source='qx')),
            ('payload:\n  - DOMAIN-KEYWORD,ads#tag # YAML comment',
             Rule('DOMAIN-KEYWORD', 'ads#tag', domain_source='mihomo')),
            ("rules:\n  - 'DOMAIN-KEYWORD,127.0.0.1 ads #tag' # YAML comment",
             Rule('DOMAIN-KEYWORD', '127.0.0.1 ads #tag', domain_source='mihomo')),
            ('payload:\n  - "PROCESS-NAME,127.0.0.1 ads #tag"',
             Rule('PROCESS-NAME', '127.0.0.1 ads #tag', literal_process=True)),
            ('DOMAIN,a.example # ordinary comment', Rule('DOMAIN', 'a.example')),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(parse(source, purpose='block'), ([expected], []))
        self.assertEqual(parse("payload:\n  - '127.0.0.1 ads.example#tag'", purpose='block'),
                         ([], ['line 2: invalid hosts domain ads.example#tag']))

    def test_other_addresses_and_non_hosts_delimiters_are_not_expanded(self):
        for address in ('192.0.2.1', '127.0.0.10', '0.0.0.00', '::2', '::1ads'):
            with self.subTest(address=address):
                self.assertEqual(parse(address + ' a.example#note', purpose='block'),
                                 ([], ['line 1: invalid rule']))
        self.assertEqual(parse('127.0.0.1#a.example', purpose='block'),
                         ([], ['line 1: invalid rule']))
        self.assertEqual(parse('127.0.0.1,a.example#note', purpose='block'),
                         ([], ['line 1: unknown type 127.0.0.1']))

    def test_physical_line_and_real_markup_guards_remain(self):
        for separator in ('\0', '\r', '\v', '\f', '\x85', ' ', ' '):
            with self.subTest(separator=repr(separator)):
                source = '127.0.0.1 a.example#note' + separator + 'inside\nDOMAIN,neighbor.example'
                self.assertEqual(parse(source, purpose='block'),
                                 ([Rule('DOMAIN', 'neighbor.example')],
                                  ['line 1: unsupported physical line separator']))
        for source in ('<!doctype html>\n127.0.0.1 a.example#note',
                       '<html>\n127.0.0.1 a.example#note\n</html>'):
            self.assertEqual(parse(source, purpose='block'), ([], ['line 1: HTML document']))
        self.assertEqual(parse('127.0.0.1 a.example<div>#note\nDOMAIN,neighbor.example', purpose='block'),
                         ([Rule('DOMAIN', 'neighbor.example')], ['line 1: HTML markup']))

    def assert_products(self, outputs, root, group, values, white=(), purpose='block'):
        bodies = {'fin.txt': ['DOMAIN,' + value for value in values],
                  'fin-qx.txt': ['HOST,' + value + ',LIST' for value in values],
                  'fin.yaml': ['  - ' + json.dumps('DOMAIN,' + value) for value in values],
                  'fin-surge.txt': [], 'fin-surge-ds.txt': list(values),
                  'fin-adb.txt': (['@@|' + value + '|' for value in white] +
                                  ['0.0.0.0 ' + value for value in values]) if purpose == 'block' else []}
        for name in FILES:
            body = bodies[name]
            text = outputs[root / group / name]
            with self.subTest(group=group, name=name, purpose=purpose):
                if name == 'fin-adb.txt':
                    lines = text.splitlines()
                    self.assertRegex(lines[5], r'^! Version: [0-9]{12}$')
                    self.assertEqual(lines[:5], ['[Adblock Plus 2.0]', '! Title: ' + group,
                                     '! Homepage: https://github.com/DoingDog/rconvert',
                                     '! Expires: 1 day', '! License: Inherits upstream licenses'])
                    self.assertEqual(lines[6:], [f'! Total count: {len(body)}', *body] +
                                     (['! No AdBlock rules for non-advertising group.'] if purpose != 'block' else []))
                else:
                    expected = f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '')
                    self.assertEqual(text, expected + ''.join(line + '\n' for line in body))
                self.assertTrue(text.endswith('\n'))
                self.assertNotIn('\r', text)

    def test_public_normalize_render_and_white_keep_only_pre_comment_aliases(self):
        source = '0.0.0.0 b a#c bogus.example\n'
        parsed, messages = parse(source, purpose='block')
        self.assertEqual(messages, [])
        expected = [Rule('DOMAIN', 'a'), Rule('DOMAIN', 'b')]
        normalized = normalize(iter([*parsed, *reversed(parsed)]))
        self.assertEqual(normalized, expected)
        white = parse_whitelist('::1 a#b')
        self.assertEqual(exclude_covered(iter(normalized), iter(white)), [Rule('DOMAIN', 'b')])
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode):
                outputs, diagnostics = render('hosts', normalized, purpose='block', no_resolve=mode)
                self.assertEqual(diagnostics, {})
                self.assert_products({Path('hosts') / name: text for name, text in outputs.items()},
                                     Path('.'), 'hosts', ('a', 'b'))

    def test_generate_publish_same_round_and_nonempty_disk_source_and_white(self):
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                (root / 'static/hosts').write_bytes('﻿127.0.0.1 a b#c ,"<html>\r\n'.encode('utf-8'))
                (root / 'static/blocked').write_bytes(b'0.0.0.0 a b c d\n')
                static = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                configs = [{'name': group, 'purpose': 'block', 'no_resolve': mode,
                            'sources': sources, 'whitelist': white} for group, sources, white in
                           (('parent', ['static/hosts'], []),
                            ('sourcechild', ['parent/fin.txt'], []),
                            ('whitechild', ['static/blocked'], ['parent/fin.txt']),
                            ('externalwhite', ['static/blocked'], ['static/hosts']),
                            ('cleared', ['static/hosts'], ['static/hosts']))]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                previous = {}
                for config in configs:
                    (root / config['name']).mkdir()
                    for name in FILES:
                        path = root / config['name'] / name
                        previous[path] = b'old product\x00\xff\r\n'
                        path.write_bytes(previous[path])
                with contextlib.redirect_stderr(io.StringIO()) as logs:
                    outputs = generate(root, self.fail)
                self.assertEqual(len(outputs), 30)
                self.assertNotIn(': line ', logs.getvalue())
                self.assertNotIn('frozen', logs.getvalue())
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                expected = {'parent': (('a', 'b'), ()), 'sourcechild': (('a', 'b'), ()),
                            'whitechild': (('c', 'd'), ('a', 'b')),
                            'externalwhite': (('c', 'd'), ('a', 'b')), 'cleared': ((), ('a', 'b'))}
                for group, (values, white) in expected.items():
                    self.assert_products(outputs, root, group, values, white)
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                parent = {root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in FILES}
                self.assertTrue(all(parent.values()))
                self.assertEqual(parse(parent[root / 'parent/fin.txt'].decode('utf-8'), purpose='block'),
                                 ([Rule('DOMAIN', 'a'), Rule('DOMAIN', 'b')], []))
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as logs:
                    disk = generate(root, self.fail)
                self.assertEqual(len(disk), 24)
                self.assertNotIn(': line ', logs.getvalue())
                self.assertNotIn('frozen', logs.getvalue())
                for group, (values, white) in expected.items():
                    if group != 'parent':
                        self.assert_products(disk, root, group, values, white)
                publish(disk, root=root)
                self.assertEqual({path: path.read_bytes() for path in parent}, parent)
                self.assertEqual({path: path.read_bytes() for path in static}, static)

    def test_malformed_hosts_generate_raw_and_generated_source_white_six_bytes(self):
        invalid = ('bad(,x', "bad,'x", 'bad,"x')
        messages = ['line 3: invalid hosts domain ' + value for value in invalid]
        remote = 'https://example.org/hosts'
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                mixed = root / 'static/mixed'
                mixed.write_bytes(('﻿\r\n# header\r\n127.0.0.1 B. ' + ' '.join(invalid) +
                                   ' A.#<html>,\"(\r\nDOMAIN,c\r\n').encode('utf-8'))
                (root / 'static/blocked').write_bytes(b'0.0.0.0 a b c d\n')
                configs = [{'name': group, 'purpose': 'block', 'no_resolve': mode,
                            'sources': sources, 'whitelist': white} for group, sources, white in
                           (('parent', ['static/mixed'], []),
                            ('sourcechild', ['parent/fin.txt'], []),
                            ('whitechild', ['static/blocked'], ['parent/fin.txt']),
                            ('rawwhite', ['static/blocked'], ['static/mixed']),
                            ('remotewhite', ['static/blocked'], [remote]),
                            ('remotesource', [remote], []),
                            ('cleared', ['static/mixed'], ['static/mixed']))]
                config_path = root / 'rulesets.json'
                config_path.write_text(json.dumps(configs), encoding='utf-8')
                inputs = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (config_path, mixed, root / 'static/blocked')}
                previous = {}
                for config in configs:
                    (root / config['name']).mkdir()
                    for name in FILES:
                        path = root / config['name'] / name
                        previous[path] = b'old product\x00\xff\r\n'
                        path.write_bytes(previous[path])
                calls = []

                def fetch(url):
                    self.assertEqual(url, remote)
                    calls.append(url)
                    return mixed.read_bytes()

                with patch('formats.datetime') as clock, warnings.catch_warnings(record=True) as caught, \
                        contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
                    warnings.simplefilter('always')
                    outputs = generate(root, fetch)
                self.assertEqual(calls, [remote])
                self.assertEqual([str(item.message) for item in caught], messages * 2)
                self.assertEqual(logs.getvalue().splitlines(),
                                 [str(source) + ': ' + message for source in (mixed, remote, mixed)
                                  for message in messages])
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                expected = {'parent': (('a', 'b', 'c'), ()), 'sourcechild': (('a', 'b', 'c'), ()),
                            'whitechild': (('d',), ('a', 'b', 'c')), 'rawwhite': (('d',), ('a', 'b', 'c')),
                            'remotewhite': (('d',), ('a', 'b', 'c')), 'remotesource': (('a', 'b', 'c'), ()),
                            'cleared': ((), ('a', 'b', 'c'))}
                self.assertEqual(set(outputs), set(previous))
                for group, (values, white) in expected.items():
                    self.assert_products(outputs, root, group, values, white)
                    self.assertEqual(outputs[root / group / 'fin-adb.txt'].splitlines()[5],
                                     '! Version: 202610231200')
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)
                parent = {root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in FILES}
                config_path.write_text(json.dumps(configs[1:4]), encoding='utf-8')
                inputs[config_path] = hashlib.sha256(config_path.read_bytes()).hexdigest()
                with patch('formats.datetime') as clock, warnings.catch_warnings(record=True) as caught, \
                        contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
                    warnings.simplefilter('always')
                    disk = generate(root, self.fail)
                self.assertEqual([str(item.message) for item in caught], messages)
                self.assertEqual(logs.getvalue(), '')
                self.assertEqual(disk, {path: text for path, text in outputs.items()
                                        if path.parent.name in ('sourcechild', 'whitechild', 'rawwhite')})
                publish(disk, root=root)
                self.assertEqual({path: path.read_bytes() for path in disk},
                                 {path: text.encode('utf-8') for path, text in disk.items()})
                self.assertEqual({path: path.read_bytes() for path in parent}, parent)
                self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)

    def test_malformed_hosts_cli_publishes_exact_bytes_and_rejects_all_invalid_local_input(self):
        trusted = Path(__file__).resolve().parents[1]
        code = '''
import runpy
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
trusted, fixture = map(Path, sys.argv[1:])
sys.path.insert(0, str(trusted))
sys.argv = [str(trusted / 'generate.py'), '--root', str(fixture)]
with patch('formats.datetime') as clock:
    clock.now.return_value = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    runpy.run_path(sys.argv[0], run_name='__main__')
'''
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                mixed = root / 'static/mixed'
                mixed.write_bytes(b'\n# header\n::1 b bad,\'x a bad,"x#<html>,(\n')
                (root / 'static/blocked').write_bytes(b'0.0.0.0 a b c\n')
                configs = [{'name': group, 'purpose': 'block', 'no_resolve': mode,
                            'sources': sources, 'whitelist': white} for group, sources, white in
                           (('parent', ['static/mixed'], []),
                            ('sourcechild', ['parent/fin.txt'], []),
                            ('whitechild', ['static/blocked'], ['parent/fin.txt']),
                            ('rawwhite', ['static/blocked'], ['static/mixed']))]
                config_path = root / 'rulesets.json'
                config_path.write_text(json.dumps(configs), encoding='utf-8')
                inputs = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (config_path, mixed, root / 'static/blocked')}
                result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(trusted), str(root)],
                                        cwd=trusted, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('frozen', result.stderr)
                for invalid in ("bad,'x", 'bad,"x'):
                    self.assertEqual(result.stderr.count('line 3: invalid hosts domain ' + invalid), 2)
                outputs = {root / group / name: (root / group / name).read_bytes().decode('utf-8')
                           for group in ('parent', 'sourcechild', 'whitechild', 'rawwhite') for name in FILES}
                for group in ('parent', 'sourcechild', 'whitechild', 'rawwhite'):
                    self.assert_products(outputs, root, group, ('a', 'b') if group in ('parent', 'sourcechild') else ('c',),
                                         () if group in ('parent', 'sourcechild') else ('a', 'b'))
                    self.assertEqual(outputs[root / group / 'fin-adb.txt'].splitlines()[5],
                                     '! Version: 202610231200')
                self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)
                previous = {path: path.read_bytes() for path in outputs}
                mixed.write_bytes(b'::1 bad(,x\n')
                for role in ('sources', 'whitelist'):
                    bad = {'name': 'parent', 'purpose': 'block', 'no_resolve': mode,
                           'sources': ['static/blocked'], 'whitelist': []}
                    bad[role] = ['static/mixed']
                    config_path.write_text(json.dumps([bad]), encoding='utf-8')
                    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(trusted), str(root)],
                                            cwd=trusted, capture_output=True, text=True, timeout=8)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('No adaptable rules in ' if role == 'sources' else 'Invalid whitelist ', result.stderr)
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    self.assertEqual(mixed.read_bytes(), b'::1 bad(,x\n')

    def test_all_invalid_remote_hosts_freeze_source_white_dependents_but_mixed_hosts_publish(self):
        invalid = ('bad(,x', "bad,'x", 'bad,"x')
        bad_url, mixed_url = 'https://example.org/bad-hosts', 'https://example.org/mixed-hosts'
        for mode in ('add', 'strip', 'keep'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                blocked = root / 'static/blocked'
                blocked.write_bytes(b'0.0.0.0 a b c\n')
                configs = [{'name': group, 'purpose': 'block', 'no_resolve': mode,
                            'sources': sources, 'whitelist': white} for group, sources, white in
                           (('frozen', [bad_url], []),
                            ('sourcechild', ['frozen/fin.txt'], []),
                            ('whitechild', ['static/blocked'], ['frozen/fin.txt']),
                            ('healthy', [mixed_url], []))]
                config_path = root / 'rulesets.json'
                config_path.write_text(json.dumps(configs), encoding='utf-8')
                inputs = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (config_path, blocked)}
                previous = {}
                for config in configs:
                    (root / config['name']).mkdir()
                    for name in FILES:
                        path = root / config['name'] / name
                        previous[path] = ('old ' + config['name'] + ' ' + name + '\n').encode('utf-8')
                        path.write_bytes(previous[path])
                calls = []

                def fetch(url):
                    self.assertIn(url, (bad_url, mixed_url))
                    calls.append(url)
                    aliases = invalid if url == bad_url else ('b', *invalid, 'a')
                    return ('\n# header\n127.0.0.1 ' + ' '.join(aliases) + '#<html>,"(\n').encode('utf-8')

                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
                    outputs = generate(root, fetch)
                self.assertEqual(calls, [bad_url, mixed_url])
                self.assertEqual(logs.getvalue().splitlines(),
                                 [bad_url + ': line 3: invalid hosts domain ' + value for value in invalid] +
                                 [bad_url + ': no adaptable rules; skipped'] +
                                 [mixed_url + ': line 3: invalid hosts domain ' + value for value in invalid])
                self.assertEqual(set(outputs), {root / 'healthy' / name for name in FILES})
                self.assert_products(outputs, root, 'healthy', ('a', 'b'))
                self.assertEqual(outputs[root / 'healthy/fin-adb.txt'].splitlines()[5], '! Version: 202610231200')
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in previous if path.parent.name != 'healthy'},
                                 {path: data for path, data in previous.items() if path.parent.name != 'healthy'})
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)

    def test_all_invalid_local_hosts_and_other_bad_whitelists_remain_strict(self):
        for source in ('127.0.0.1 bad(,x', "127.0.0.1 bad,'x", '127.0.0.1 bad,"x',
                       'DOMAIN,bad+name', 'DOMAIN-REGEX,(', '<div>bad.example</div>'):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                bad = root / 'static/bad'
                bad.write_bytes((source + '\n').encode('utf-8'))
                good = root / 'static/good'
                good.write_bytes(b'DOMAIN,good.example\n')
                (root / 'route').mkdir()
                previous = {root / 'route' / name: b'old product\x00\xff\r\n' for name in FILES}
                for path, data in previous.items():
                    path.write_bytes(data)
                for role in ('sources', 'whitelist'):
                    config = {'name': 'route', 'purpose': 'block', 'no_resolve': 'keep',
                              'sources': ['static/good'], 'whitelist': []}
                    config[role] = ['static/bad']
                    config_path = root / 'rulesets.json'
                    config_path.write_text(json.dumps([config]), encoding='utf-8')
                    inputs = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (bad, good, config_path)}
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ValueError) as caught:
                        publish(generate(root, self.fail), root=root)
                    self.assertTrue(str(caught.exception).startswith(
                        'No adaptable rules in ' if role == 'sources' else 'Invalid whitelist '), str(caught.exception))
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, inputs)

    def test_generate_direct_proxy_keeps_block_only_diagnostics_and_old_bytes(self):
        for purpose in ('direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    path = root / 'static/hosts'
                    original = '﻿\r\n::1 a#<html>,"\r\nDOMAIN,d\r\n'.encode('utf-8')
                    path.write_bytes(original)
                    configs = [{'name': 'route', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['static/hosts'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'route').mkdir()
                    previous = {root / 'route' / name: b'old product\n' for name in FILES}
                    for product, data in previous.items():
                        product.write_bytes(data)
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(logs.getvalue().splitlines(),
                                     [str(path) + ': line 2: hosts entry is block-only', 'route fin-adb.txt:DOMAIN: 1'])
                    self.assertEqual({product: product.read_bytes() for product in previous}, previous)
                    self.assert_products(outputs, root, 'route', ('d',), purpose=purpose)
                    publish(outputs, root=root)
                    self.assertEqual(path.read_bytes(), original)
                    self.assertEqual({product: product.read_bytes() for product in outputs},
                                     {product: text.encode('utf-8') for product, text in outputs.items()})
