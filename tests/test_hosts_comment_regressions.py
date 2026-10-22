import contextlib
import io
import json
import tempfile
import unittest
import warnings
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


class HostsCommentTests(unittest.TestCase):
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
