import contextlib
import io
import json
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from itertools import product
from pathlib import Path
from unittest.mock import patch

from formats import render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


CASES = (
    ('PROCESS-NAME', 'Game', 'PROCESS-NAME,Game',
     r'PROCESS-NAME-REGEX,(?-i:\A\x{47}\x{61}\x{6D}\x{65}\z)'),
    ('PROCESS-PATH', '/123/456', 'PROCESS-NAME,/123/456', 'PROCESS-PATH,/123/456'),
    ('PROCESS-NAME-WILDCARD', '*Game*', None, 'PROCESS-NAME-WILDCARD,*Game*'),
    ('PROCESS-PATH-WILDCARD', '/123/*', None, 'PROCESS-PATH-WILDCARD,/123/*'),
)
PURPOSES = ('block', 'direct', 'proxy')
MODES = ('add', 'strip', 'keep')
CLOCK = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)


def products(group, purpose, surge, mihomo):
    return {
        'fin.txt': f'# {group} rules: {int(surge is not None)}\n' + (surge + '\n' if surge else ''),
        'fin-surge.txt': f'# {group} rules: {int(surge is not None)}\n' + (surge + '\n' if surge else ''),
        'fin-qx.txt': f'# {group} rules: 0\n',
        'fin-surge-ds.txt': f'# {group} rules: 0\n',
        'fin.yaml': f'# {group} rules: 1\npayload:\n  - ' + json.dumps(mihomo) + '\n',
        'fin-adb.txt': ('[Adblock Plus 2.0]\n'
                        f'! Title: {group}\n'
                        '! Homepage: https://github.com/DoingDog/rconvert\n'
                        '! Expires: 1 day\n'
                        '! License: Inherits upstream licenses\n'
                        '! Version: 202601021104\n'
                        '! Total count: 0\n' +
                       ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n')),
    }


def diagnostics(kind, surge):
    names = ['fin-qx.txt', 'fin-adb.txt', 'fin-surge-ds.txt']
    if surge is None:
        names.extend(('fin.txt', 'fin-surge.txt'))
    return {name + ':' + kind: 1 for name in names}


class ProcessCommentRegressionTests(unittest.TestCase):
    def test_closed_quoted_process_stops_before_tail_comment(self):
        self.assertEqual(parse('PROCESS-NAME,"Game" # tail', purpose='proxy'),
                         ([Rule('PROCESS-NAME', 'Game')], []))

    def test_four_kinds_quotes_markers_purposes_and_modes_match_literal_products(self):
        for (kind, value, surge, mihomo), quote, marker, purpose in product(
                CASES, ("'", '"'), ('#', ';', '//'), PURPOSES):
            source = f'{kind},{quote}{value}{quote}'
            expected = [Rule(kind, value)]
            with self.subTest(kind=kind, quote=quote, marker=marker, purpose=purpose):
                self.assertEqual(parse(source, purpose=purpose), (expected, []))
                parsed, messages = parse(source + ' ' + marker + ' tail', purpose=purpose)
                self.assertEqual((parsed, messages), (expected, []))
                self.assertEqual(normalize(iter(parsed + parsed)), expected)
                self.assertEqual(normalize(reversed(parsed)), expected)
                for mode in MODES:
                    with self.subTest(mode=mode), patch('formats.datetime') as clock:
                        clock.now.return_value = CLOCK
                        actual = render('comments', normalize(iter(parsed)), purpose=purpose, no_resolve=mode)
                        control = render('comments', expected, purpose=purpose, no_resolve=mode)
                        wanted = products('comments', purpose, surge, mihomo), diagnostics(kind, surge)
                        self.assertEqual(actual, wanted)
                        self.assertEqual(control, wanted)

    def test_comment_punctuation_does_not_consume_closed_fields_or_neighbors(self):
        neighbor = Rule('DOMAIN', 'keep.example.org')
        bodies = ("tail,'unclosed", 'tail,"unclosed', 'tail,([)',
                  '<html><body>ignored</body></html>', '<!doctype html>', '\\')
        for (kind, value, _, _), quote, marker, body, gap in product(
                CASES, ("'", '"'), ('#', ';', '//'), bodies, (' ', '\t', '\xa0')):
            source = f'{kind},{quote}{value}{quote}{gap}{marker} {body}'
            for text, expected in ((source, [Rule(kind, value)]),
                                   ('\ufeff# header\r\n' + source + '\r\nDOMAIN,keep.example.org\r\n',
                                    [Rule(kind, value), neighbor])):
                with self.subTest(source=source, neighbors=len(expected) > 1):
                    self.assertEqual(parse(text, purpose='proxy'), (expected, []))

    def test_unclosed_source_quotes_keep_physical_warning_lines(self):
        for (kind, _, _, _), quote in product(CASES, ("'", '"')):
            text = (f'\ufeff# header\r\n\r\n{kind},{quote}Game # tail\r\n'
                    'DOMAIN,keep.example.org\r\n'
                    f'{kind},{quote}Game\\{quote} # still unclosed\r\n'
                    'DOMAIN,next.example.org\r\n')
            with self.subTest(kind=kind, quote=quote):
                self.assertEqual(parse(text, purpose='proxy'),
                                 ([Rule('DOMAIN', 'keep.example.org'), Rule('DOMAIN', 'next.example.org')],
                                  ['line 3: unbalanced delimiters', 'line 5: unbalanced delimiters']))

    def test_quoted_literals_decode_without_comment_or_escape_changes(self):
        fields = (
            ("'\"Game\"'", '"Game"'),
            (r'"Game\" Deluxe"', 'Game" Deluxe'),
            (r'"C:\\Games\\Game.exe"', r'C:\Games\Game.exe'),
            (r'"Game\q"', r'Game\q'),
            (r'"Game\\"', 'Game\\'),
            (r'"Game\\\\"', 'Game\\\\'),
            ("'Game,Inc'", 'Game,Inc'),
            ('"Game,Inc"', 'Game,Inc'),
            ("' Game '", ' Game '),
            ('"\tGame\t"', '\tGame\t'),
        )
        for (kind, _, _, _), (field, value), marker in product(CASES, fields, ('#', ';', '//')):
            expected = [Rule(kind, value)]
            for comment in ('', ' ' + marker + ' tail,"unclosed'):
                source = kind + ',' + field + comment
                with self.subTest(source=source):
                    self.assertEqual(parse(source, purpose='proxy'), (expected, []))
        for quote in ("'", '"'):
            source = 'PROCESS-NAME,' + quote + 'Game' + quote + '#literal'
            self.assertEqual(parse(source, purpose='proxy'),
                             ([Rule('PROCESS-NAME', quote + 'Game' + quote + '#literal')], []))

    def test_bare_markers_quoted_inner_markers_and_policy_comments_keep_scope(self):
        for (kind, _, _, _), marker in product(CASES, ('#', ';', '//')):
            value = 'Game ' + marker + ' literal'
            for quote in ('', "'", '"'):
                source = kind + ',' + quote + value + quote
                with self.subTest(source=source):
                    self.assertEqual(parse(source, purpose='proxy'), ([Rule(kind, value)], []))
            for purpose, action in (('block', 'REJECT'), ('direct', 'DIRECT'), ('proxy', 'PROXY')):
                for field in (value, "'" + value + "'", '"' + value + '"'):
                    source = kind + ',' + field + ',' + action + ' ' + marker + ' tail,"unclosed('
                    with self.subTest(source=source, purpose=purpose):
                        self.assertEqual(parse(source, purpose=purpose), ([Rule(kind, value)], []))
        for quote in ("'", '"'):
            source = 'HOST-KEYWORD,' + quote + '中文' + quote + ' # literal'
            self.assertEqual(parse(source, purpose='proxy'),
                             ([Rule('DOMAIN-KEYWORD', quote + '中文' + quote + ' # literal', domain_source='qx')], []))

    def test_logical_children_and_native_yaml_keep_distinct_quote_roles(self):
        for (kind, _, _, _), quote, marker in product(CASES, ("'", '"'), ('#', ';', '//')):
            value = 'Game ' + marker + ' literal'
            leaf = f'({kind},{quote}{value}{quote})'
            for operator in ('AND', 'OR', 'NOT'):
                expression = '(' + leaf + ('' if operator == 'NOT' else ',(NETWORK,tcp)') + ')'
                source = operator + ',' + expression + ' ' + marker + ' tail,"unclosed('
                with self.subTest(source=source):
                    self.assertEqual(parse(source, purpose='proxy'), ([Rule(operator, expression)], []))
            for header in ('payload', 'rules'):
                matchers = ((kind + ',' + value, value),
                            (kind + ',' + quote + value + quote, quote + value + quote))
                for matcher, expected_value in matchers:
                    scalars = (json.dumps(matcher), "'" + matcher.replace("'", "''") + "'")
                    for scalar in scalars:
                        source = header + ': # header\n  - ' + scalar + ' # outer,"unclosed('
                        with self.subTest(source=source):
                            self.assertEqual(parse(source, purpose='proxy'),
                                             ([Rule(kind, expected_value, literal_process=kind == 'PROCESS-NAME')], []))
        self.assertEqual(parse('payload:\n  - PROCESS-NAME,Game # outer\n'
                               '  - PROCESS-NAME,Game ; literal\n  - PROCESS-NAME,Game // literal\n',
                               purpose='proxy'),
                         ([Rule('PROCESS-NAME', 'Game', literal_process=True),
                           Rule('PROCESS-NAME', 'Game ; literal', literal_process=True),
                           Rule('PROCESS-NAME', 'Game // literal', literal_process=True)], []))

    def test_process_comments_do_not_add_whitelist_support(self):
        for (kind, value, _, _), quote, marker in product(CASES, ("'", '"'), ('#', ';', '//')):
            source = f'{kind},{quote}{value}{quote} {marker} tail,"unclosed('
            with self.subTest(source=source), warnings.catch_warnings(record=True) as seen:
                self.assertEqual(parse_whitelist(source), [])
                self.assertEqual(parse_whitelist(source + '\nDOMAIN,keep.example.org'),
                                 [Rule('DOMAIN', 'keep.example.org')])
            self.assertEqual(seen, [])

    def test_real_sources_publish_same_round_and_nonempty_disk_dependencies(self):
        for purpose, mode, dependency in product(PURPOSES, MODES, ('fin.txt', 'fin.yaml')):
            with self.subTest(purpose=purpose, mode=mode, dependency=dependency), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                            'sources': sources, 'whitelist': []} for group, sources in
                           (('parent', ['input.list']), ('child', ['parent/' + dependency]))]
                config = root / 'rulesets.json'
                config.write_text(json.dumps(configs), encoding='utf-8')
                source = root / 'input.list'
                source.write_bytes('\ufeffPROCESS-NAME,"Game" # 尾注释,"unclosed(\r\n'.encode('utf-8'))
                static = root / 'static' / 'keep.list'
                static.parent.mkdir()
                static.write_bytes('用户原文件\r\n'.encode('utf-8'))
                inputs = {path: path.read_bytes() for path in (source, static)}
                old = {}
                for group in ('parent', 'child'):
                    (root / group).mkdir()
                    for name in products(group, purpose, 'PROCESS-NAME,Game', CASES[0][3]):
                        path = root / group / name
                        old[path] = ('old ' + group + '/' + name + '\r\n').encode('utf-8')
                        path.write_bytes(old[path])
                child_kind = 'PROCESS-NAME' if dependency == 'fin.txt' else 'PROCESS-NAME-REGEX'
                child_surge = 'PROCESS-NAME,Game' if dependency == 'fin.txt' else None
                expected = {root / 'parent' / name: text for name, text in
                            products('parent', purpose, 'PROCESS-NAME,Game', CASES[0][3]).items()}
                child = {root / 'child' / name: text for name, text in
                         products('child', purpose, child_surge, CASES[0][3]).items()}
                expected.update(child)
                logs = ''.join(f'{group} {key}: {count}\n'
                               for group, kind, surge in (('parent', 'PROCESS-NAME', 'PROCESS-NAME,Game'),
                                                         ('child', child_kind, child_surge))
                               for key, count in sorted(diagnostics(kind, surge).items()))
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    clock.now.return_value = CLOCK
                    outputs = generate(root, self.fail)
                self.assertEqual(outputs, expected)
                self.assertEqual(stderr.getvalue(), logs)
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                self.assertEqual(config.read_bytes(), json.dumps(configs).encode('utf-8'))
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                publish(outputs, root=root)
                published = {path: text.encode('utf-8') for path, text in expected.items()}
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    clock.now.return_value = CLOCK
                    disk = generate(root, self.fail)
                self.assertEqual(disk, child)
                self.assertEqual(stderr.getvalue(), ''.join(f'child {key}: {count}\n'
                                 for key, count in sorted(diagnostics(child_kind, child_surge).items())))
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                publish(disk, root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_generated_process_whitelist_and_unclosed_source_preserve_old_bytes(self):
        for dependency in ('fin.txt', 'fin.yaml'):
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = [{'name': 'parent', 'purpose': 'proxy', 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': []},
                           {'name': 'child', 'purpose': 'proxy', 'no_resolve': 'keep',
                            'sources': ['neighbor.list'], 'whitelist': ['parent/' + dependency]}]
                config = root / 'rulesets.json'
                config.write_text(json.dumps(configs), encoding='utf-8')
                (root / 'input.list').write_text('PROCESS-NAME,"Game" # 注释,"unclosed(\n', encoding='utf-8')
                (root / 'neighbor.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
                (root / 'static').mkdir()
                (root / 'static' / 'keep.list').write_bytes(b'old static\r\n')
                for group in ('parent', 'child'):
                    (root / group).mkdir()
                    for name in products(group, 'proxy', 'PROCESS-NAME,Game', CASES[0][3]):
                        (root / group / name).write_bytes(('old ' + name + '\r\n').encode('utf-8'))
                before = {path: path.read_bytes() for path in root.rglob('*') if path.is_file()}
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = CLOCK
                    with self.assertRaisesRegex(ValueError, r'Invalid whitelist .*parent/fin\.(txt|yaml): line [23]: unsupported rule'):
                        generate(root, self.fail)
                self.assertEqual({path: path.read_bytes() for path in before}, before)
                config.write_text(json.dumps(configs[:1]), encoding='utf-8')
                (root / 'input.list').write_text('PROCESS-NAME,"Game # truly unclosed\n', encoding='utf-8')
                failed = {path: path.read_bytes() for path in before}
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    with self.assertRaisesRegex(ValueError, 'No adaptable rules in '):
                        generate(root, self.fail)
                self.assertEqual(stderr.getvalue(), f'{root / "input.list"}: line 1: unbalanced delimiters\n')
                self.assertEqual({path: path.read_bytes() for path in failed}, failed)
                config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                for name, text in products('parent', 'proxy', 'PROCESS-NAME,Game', CASES[0][3]).items():
                    (root / 'parent' / name).write_bytes(text.encode('utf-8'))
                disk_before = {path: path.read_bytes() for path in before}
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    clock.now.return_value = CLOCK
                    disk = generate(root, self.fail)
                expected = products('child', 'proxy', None, 'DOMAIN,keep.example.org')
                expected.update({'fin.txt': '# child rules: 1\nDOMAIN,keep.example.org\n',
                                 'fin-qx.txt': '# child rules: 1\nHOST,keep.example.org,LIST\n',
                                 'fin-surge-ds.txt': '# child rules: 1\nkeep.example.org\n'})
                self.assertEqual(disk, {root / 'child' / name: text for name, text in expected.items()})
                self.assertEqual(stderr.getvalue(), 'child fin-adb.txt:DOMAIN: 1\n')
                self.assertEqual({path: path.read_bytes() for path in disk_before}, disk_before)
