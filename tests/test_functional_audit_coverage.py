import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from formats import FILES, render
from generate import generate, publish

from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests import test_functional_audit_rules as audit_rules


class NativeWildcardBoundaryAuditTests(unittest.TestCase):
    def test_native_dotless_pattern_preserves_raw_matcher_and_neighbor(self):
        self.assertEqual(parse(audit_rules.native_text('DOMAIN-WILDCARD,*ads*',
                                                      'DOMAIN,neighbor.example.org'), purpose='block'),
                         ([Rule('DOMAIN-WILDCARD', '*ads*', domain_source='mihomo'),
                           Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')], []))

    def test_native_spaced_type_keeps_literal_angle_payload(self):
        cases = (
            ('DOMAIN-WILDCARD ,*<ads>*', 'DOMAIN-WILDCARD', '*<ads>*'),
            (' DOMAIN-WILDCARD   ,  *<ads>*  ,ignored', 'DOMAIN-WILDCARD', '*<ads>*'),
            ('domain-wildcard ,"*<ads>*"', 'DOMAIN-WILDCARD', '"*<ads>*"'),
            ('NOT,((DOMAIN-WILDCARD ,*<ads>*))', 'NOT', '((DOMAIN-WILDCARD,*<ads>*))'),
            ('NOT ,((DOMAIN-WILDCARD,*<ads>*))', 'NOT', '((DOMAIN-WILDCARD,*<ads>*))'),
            ('AND ,((DOMAIN-WILDCARD ,*<ads>*),(NETWORK,tcp))', 'AND', '((DOMAIN-WILDCARD,*<ads>*),(NETWORK,tcp))'),
            ('OR ,((NETWORK,tcp),(DOMAIN-WILDCARD ,*<ads>*))', 'OR', '((NETWORK,tcp),(DOMAIN-WILDCARD,*<ads>*))'),
            ('AND ,((NOT ,((DOMAIN-WILDCARD ,*<ads>*))),(OR ,((NETWORK,tcp),(DOMAIN,neighbor.example.org))))',
             'AND', '((NOT,((DOMAIN-WILDCARD,*<ads>*))),(OR,((NETWORK,tcp),(DOMAIN,neighbor.example.org))))'),
        )
        for matcher, kind, value in cases:
            wanted = Rule(kind, value, native_fields=kind in {'AND', 'OR', 'NOT'}, domain_source='mihomo')
            neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')
            source = audit_rules.native_text(matcher, 'DOMAIN,neighbor.example.org')
            for purpose in ('block', 'direct', 'proxy'):
                with self.subTest(matcher=matcher, purpose=purpose):
                    self.assertEqual(parse(source, purpose=purpose), ([wanted, neighbor], []))
                    self.assertEqual(parse_whitelist(source), ([wanted] if kind == 'DOMAIN-WILDCARD' else []) + [neighbor])
                    if kind == 'DOMAIN-WILDCARD':
                        self.assertEqual(parse_whitelist(audit_rules.native_text(matcher)), [wanted])
                    for mode in ('add', 'strip', 'keep'):
                        outputs, skipped = render('spaced', [wanted], purpose=purpose, no_resolve=mode)
                        self.assertEqual(outputs['fin.yaml'], '# spaced rules: 1\npayload:\n  - ' + json.dumps(kind + ',' + value) + '\n')
                        self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([wanted], []))
                        self.assertFalse(any(key.startswith('fin.yaml:') for key in skipped))

    def test_native_spaced_literal_fields_keep_ascii_boundary_and_html_document_guards(self):
        for matcher, wanted in (
                ('DOMAIN-KEYWORD ,<ads>', Rule('DOMAIN-KEYWORD', '<ads>', domain_source='mihomo')),
                ('DOMAIN-REGEX ,^<ads>$', Rule('DOMAIN-REGEX', '^<ads>$')),
                ('PROCESS-NAME ,<ads>', Rule('PROCESS-NAME', '<ads>', literal_process=True)),
                ('NOT ,((DOMAIN-REGEX ,^<ads>$))', Rule('NOT', '((DOMAIN-REGEX,^<ads>$))', native_fields=True))):
            with self.subTest(matcher=matcher):
                self.assertEqual(parse(audit_rules.native_text(matcher), purpose='proxy'), ([wanted], []))
        for matcher in ('DOMAIN-WILDCARD\t,*<ads>*', 'DOMAIN-WILDCARD\xa0,*<ads>*',
                        'NOT\t,((DOMAIN-WILDCARD,*<ads>*))', 'NOT,((DOMAIN-WILDCARD\t,*<ads>*))',
                        'DOMAIN ,<ads>', 'DOMAIN-SUFFIX ,<ads>'):
            with self.subTest(matcher=matcher):
                parsed, messages = parse(audit_rules.native_text(matcher, 'DOMAIN,neighbor.example.org'), purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith('line 2:'))
        for document in ('<!doctype html>\nDOMAIN-WILDCARD ,*<ads>*',
                         '<html>\npayload:\n  - "DOMAIN-WILDCARD ,*<ads>*"\n</html>',
                         '<main>\nDOMAIN,hidden.example.org\n</main>'):
            with self.subTest(document=document):
                self.assertEqual(parse(document, purpose='proxy'), ([], ['line 1: HTML document']))
                with self.assertRaisesRegex(ValueError, 'HTML document'):
                    parse_whitelist(document)
        self.assertEqual(parse('DOMAIN-WILDCARD ,*<ads>*\nDOMAIN,neighbor.example.org', purpose='proxy'),
                         ([Rule('DOMAIN', 'neighbor.example.org')], ['line 1: HTML markup']))

    def test_native_wildcard_angle_text_is_a_literal_payload(self):
        for matcher in ('DOMAIN-WILDCARD,*<ads>*', 'NOT,((DOMAIN-WILDCARD,*<ads>*))'):
            with self.subTest(matcher=matcher):
                kind, _, value = matcher.partition(',')
                self.assertEqual(parse(audit_rules.native_text(matcher), purpose='block'),
                                 ([Rule(kind, value, native_fields=kind == 'NOT', domain_source='mihomo')], []))

    def test_native_patterns_use_scalar_and_field_boundaries_without_hostname_limits(self):
        patterns = ('*ads*', '*', 'a?', '?', '??', '[ab]', '[', ']', 'a[0-9]*',
                    'AD?S.', 'AD?S..', 'é?', '中*', '😀?', 'a/ads', 'a\\ads', 'a+b', '-ads', 'ads-',
                    'a..ads', '.', '..', '192.0.2.1', '2001:db8::1', '\tads\t',
                    "'ads'", '"ads"', '*<ads>*', 'a(ads)', 'x' * 5000)
        for purpose in ('block', 'direct', 'proxy'):
            for pattern in patterns:
                with self.subTest(purpose=purpose, pattern=pattern):
                    wanted = Rule('DOMAIN-WILDCARD', pattern, domain_source='mihomo')
                    text = 'payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + pattern, ensure_ascii=False)
                    self.assertEqual(parse(text, purpose=purpose), ([wanted], []))
                    self.assertEqual(parse_whitelist(text), [wanted])
            self.assertEqual(parse(audit_rules.native_text('DOMAIN-WILDCARD,  *ads*  ,ignored,REJECT'), purpose=purpose),
                             ([Rule('DOMAIN-WILDCARD', '*ads*', domain_source='mihomo')], []))
            self.assertEqual(parse(audit_rules.native_text('DOMAIN-WILDCARD,"a,b"'), purpose=purpose),
                             ([Rule('DOMAIN-WILDCARD', '"a', domain_source='mihomo')], []))
        for invalid in ('', '   ', '\0', '\r', '\n', '\v', '\f', '\x7f', '\x85', ' ', ' ', '\ud800', '￿'):
            with self.subTest(invalid=repr(invalid)):
                text = audit_rules.native_text('DOMAIN-WILDCARD,' + invalid, 'DOMAIN,neighbor.example.org')
                parsed, messages = parse(text, purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith('line 2:'))
                with self.assertRaises(ValueError):
                    parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,' + invalid))
        for scalar in ('["DOMAIN-WILDCARD,*ads*"]', '{rule: "DOMAIN-WILDCARD,*ads*"}'):
            self.assertEqual(parse('payload:\n  - ' + scalar, purpose='block')[0], [])
        for source in ('DOMAIN-WILDCARD,', 'HOST-WILDCARD,'):
            for pattern in ('*ads*', '*', 'a?', '[ab]', 'a..ads', '-ads.example', 'ads-.example', 'x' * 5000):
                with self.subTest(source=source, pattern=pattern):
                    parsed, messages = parse(source + pattern, purpose='block')
                    self.assertEqual(parsed, [])
                    self.assertEqual(len(messages), 1)

    def test_native_logical_raw_quotes_order_ip_direction_and_no_resolve_survive(self):
        for pattern in ('*ads*', '*', 'a?', '[ab]', '"a?"', "'a?'", '*<ads>*', 'a(ads)', 'é?'):
            for operator, value in (
                ('AND', f'((DOMAIN-WILDCARD,{pattern}),(IP-CIDR,192.0.2.7/24),(SRC-IP-CIDR,198.51.100.7/24,no-resolve))'),
                ('OR', f'((DOMAIN-WILDCARD,{pattern}),(NETWORK,tcp))'),
                ('NOT', f'((DOMAIN-WILDCARD,{pattern}))'),
                ('AND', f'((NOT,((DOMAIN-WILDCARD,{pattern}))),(OR,((NETWORK,tcp),(DOMAIN,neighbor.example.org))))')):
                for purpose in ('block', 'direct', 'proxy'):
                    with self.subTest(pattern=pattern, operator=operator, purpose=purpose):
                        parsed, messages = parse(audit_rules.native_text(operator + ',' + value), purpose=purpose)
                        normalized = value.replace('192.0.2.7/24', '192.0.2.0/24').replace('198.51.100.7/24,no-resolve', '198.51.100.0/24')
                        self.assertEqual(parsed, [Rule(operator, normalized, native_fields=True, domain_source='mihomo')])
                        self.assertEqual(messages, [])
                        for mode in ('add', 'strip', 'keep'):
                            outputs, _ = render('wildcard', parsed, purpose=purpose, no_resolve=mode)
                            emitted = normalized.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)') if mode == 'add' else normalized
                            self.assertEqual(outputs['fin.yaml'], '# wildcard rules: 1\npayload:\n  - ' + json.dumps(operator + ',' + emitted, ensure_ascii=False) + '\n')
                            self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose),
                                             ([Rule(operator, emitted, native_fields=True, domain_source='mihomo')], []))
        for value in ('((DOMAIN-WILDCARD,))', '((DOMAIN-WILDCARD,a(b))', '((DOMAIN-WILDCARD,a)b))'):
            parsed, messages = parse(audit_rules.native_text('NOT,' + value, 'DOMAIN,neighbor.example.org'), purpose='block')
            self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')])
            self.assertEqual(len(messages), 1)
        for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
            for pattern in ('[ab]', 'a..ads', '-ads.example', 'ads-.example', 'a?', 'é?'):
                self.assertEqual(parse(audit_rules.native_text(kind + ',' + pattern), purpose='block')[0], [])

    def test_native_short_wildcards_match_bytes_and_literal_brackets_without_cross_source_merging(self):
        cases = (('*ads*', ('ads', 'xads', 'ads.x', 'éads中'), ('ad', 'other')),
                 ('*', ('localhost', 'localhost.', 'é', '中', '😀'), ()),
                 ('a?', ('aa', 'a.'), ('a', 'aé', 'a中', 'a😀')),
                 ('a??', ('aé', 'aı', 'aab'), ('aa', 'a中', 'a😀')),
                 ('a???', ('a中', 'aabc'), ('aé', 'a😀')),
                 ('a????', ('a😀', 'aabcd'), ('a中',)),
                 ('a?*?', ('aé', 'a中', 'a😀', 'aab'), ('aa',)),
                 ('[ab]', ('[ab]',), ('a', 'b', '[a]')),
                 ('*[ab]?', ('x[ab]a', '[ab]b'), ('xa', 'xab', '[ab]é')),
                 ('[', ('[',), (']', 'a')),
                 ('AD?S.', ('adxs.',), ('adxs', 'adéS.')),
                 ('é*', ('é', 'é中'), ('e', 'xn--9ca')))
        for pattern, covered, kept in cases:
            with self.subTest(pattern=pattern):
                white = parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,' + pattern))
                same = [Rule('DOMAIN-WILDCARD', pattern, domain_source='mihomo')]
                native = [Rule('DOMAIN', host, domain_source='mihomo') for host in covered + kept]
                foreign = [Rule('DOMAIN', host, domain_source=source) for source in ('surge', 'qx') for host in covered]
                allowed = Rule('DOMAIN', covered[0], allow=True, domain_source='mihomo')
                self.assertEqual(exclude_covered(iter([*native, *same, *foreign, allowed]), iter(white)),
                                 [*native[len(covered):], *foreign, allowed])
                self.assertEqual(set(normalize([*same, *foreign, allowed] * 2)), {*same, *foreign, allowed})
        for count in range(1, 5):
            native = parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,' + '?' * count))
            for character, width in (('a', 1), ('é', 2), ('中', 3), ('😀', 4)):
                blocker = Rule('DOMAIN', character, domain_source='mihomo')
                self.assertEqual(exclude_covered([blocker], native), [] if count == width else [blocker])
        for source in ('surge', 'qx'):
            white = parse_whitelist(('DOMAIN-WILDCARD,' if source == 'surge' else 'HOST-WILDCARD,') + 'a?.example.org')
            blocker = Rule('DOMAIN', 'aé.example.org', domain_source=source)
            self.assertEqual(exclude_covered([blocker], white), [])
        native = Rule('DOMAIN-WILDCARD', 'a?.example.org', domain_source='mihomo')
        surge = Rule('DOMAIN-WILDCARD', 'a?.example.org')
        qx = Rule('DOMAIN-WILDCARD', 'a?.example.org', domain_source='qx')
        self.assertEqual(set(normalize([native, surge, qx])), {native, surge, qx})
        self.assertEqual(exclude_covered([native, surge, qx], [native]), [surge, qx])
        self.assertEqual(exclude_covered([native, surge, qx], [surge]), [native, qx])

    def test_mihomo_reimport_preserves_short_patterns_case_quotes_and_single_root_dot(self):
        matchers = ('DOMAIN-WILDCARD,*ads*', 'DOMAIN-WILDCARD,*', 'DOMAIN-WILDCARD,a?',
                    'DOMAIN-WILDCARD,[ab]', 'DOMAIN-WILDCARD,AD?S.', 'DOMAIN-WILDCARD,AD?S..',
                    'DOMAIN-WILDCARD,é?', 'DOMAIN-WILDCARD,"a?"', 'DOMAIN-WILDCARD,*<ads>*')
        for purpose in ('block', 'direct', 'proxy'):
            parsed, messages = parse(audit_rules.native_text(*matchers), purpose=purpose)
            self.assertEqual(messages, [])
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    outputs, skipped = render('wildcard', normalize(parsed), purpose=purpose, no_resolve=mode)
                    self.assertEqual(set(outputs), set(FILES))
                    self.assertEqual({json.loads(line[4:]) for line in outputs['fin.yaml'].splitlines()[2:]}, set(matchers))
                    repeated, warnings = parse(outputs['fin.yaml'], purpose=purpose)
                    self.assertEqual((set(repeated), warnings), (set(parsed), []))
                    self.assertFalse(any(key.startswith('fin.yaml:') for key in skipped))
        for quote in ('\'', '"'):
            source = 'DOMAIN-WILDCARD,' + quote + 'API-?.EXAMPLE.ORG.' + quote
            parsed, messages = parse(source, purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-WILDCARD', 'api-?.example.org')], []))
        for source in ('surge', 'qx'):
            prefix = 'DOMAIN-WILDCARD,' if source == 'surge' else 'HOST-WILDCARD,'
            self.assertEqual(parse(prefix + 'API-[ab].EXAMPLE.ORG.', purpose='block'),
                             ([Rule('DOMAIN-WILDCARD', 'api-[ab].example.org', domain_source=source)], []))

    def test_native_long_patterns_and_deep_logical_keep_original_bounds_under_eight_seconds(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
long_pattern = 'x' * 5000 + '*'
for matcher in ('DOMAIN-WILDCARD,' + long_pattern, 'DOMAIN-WILDCARD,*ads*'):
    source = 'payload:\\n  - ' + json.dumps(matcher)
    parsed, messages = parse(source, purpose='proxy')
    assert (parsed, messages) == ([Rule('DOMAIN-WILDCARD', matcher.split(',', 1)[1], domain_source='mihomo')], [])
    output, skips = render('long', parsed, purpose='proxy', no_resolve='keep')
    assert 'fin.yaml:DOMAIN-WILDCARD' not in skips
    assert parse(output['fin.yaml'], purpose='proxy') == (parsed, [])
for depth in (600, 1000):
    for leaf in ('DOMAIN-WILDCARD,a?', 'DOMAIN-WILDCARD ,*<ads>*'):
        matcher, canonical = leaf, leaf.replace('DOMAIN-WILDCARD ,', 'DOMAIN-WILDCARD,')
        for _ in range(depth):
            matcher = 'NOT ,((' + matcher + '))'
            canonical = 'NOT,((' + canonical + '))'
        parsed, messages = parse('payload:\\n  - ' + json.dumps(matcher), purpose='proxy')
        expected = Rule('NOT', canonical[4:], native_fields=True, domain_source='mihomo')
        assert (parsed, messages) == ([expected], [])
        output, skips = render('deep', parsed, purpose='proxy', no_resolve='keep')
        assert 'fin.yaml:NOT' not in skips
        assert parse(output['fin.yaml'], purpose='proxy') == ([expected], [])
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generate_short_patterns_and_generated_white_keep_actual_yaml_dependency_bytes(self):
        matchers = ('DOMAIN-WILDCARD,*ads*', 'DOMAIN-WILDCARD,*', 'DOMAIN-WILDCARD,a?',
                    'DOMAIN-WILDCARD,[ab]', 'DOMAIN-WILDCARD,AD?S.', 'DOMAIN-WILDCARD ,*<ads>*',
                    'DOMAIN-WILDCARD,*white*', 'DOMAIN-WILDCARD ,*white*<ads>*',
                    'DOMAIN,white.example.org', 'DOMAIN,neighbor.example.org',
                    'IP-CIDR,192.0.2.0/24', 'SRC-IP-CIDR,198.51.100.0/24',
                    'OR ,((DOMAIN-WILDCARD ,*<ads>*),(NETWORK,tcp))',
                    'AND ,((NOT ,((DOMAIN-WILDCARD ,a?))),(IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))')
        source = audit_rules.native_text(*matchers) + '\n@@||allow.example.org^\n'
        white = audit_rules.native_text('DOMAIN-WILDCARD,*white*', 'DOMAIN-WILDCARD ,*white*<ads>*')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/source.list').write_text(source, encoding='utf-8')
                        (root / 'static/white.list').write_text(white, encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                        configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['https://example.com/white' if remote else 'static/white.list'], 'whitelist': []},
                                   {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['https://example.com/source' if remote else 'static/source.list'],
                                    'whitelist': ['white/fin.yaml']},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for group in ('white', 'source', 'child'):
                            (root / group).mkdir()
                            for name in FILES:
                                path = root / group / name
                                path.write_bytes(b'old product\x00\xff\r\n')
                                old[path] = path.read_bytes()
                        responses = {'https://example.com/white': white.encode(), 'https://example.com/source': source.encode()}
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: responses[url])
                        self.assertNotIn('invalid ', diagnostic.getvalue())
                        self.assertEqual(list(outputs), [root / group / name for group in ('white', 'source', 'child') for name in FILES])
                        logic = '((NOT,((DOMAIN-WILDCARD,a?))),(IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))'
                        if mode == 'add':
                            logic = logic.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)')
                        expected = {*(Rule('DOMAIN-WILDCARD', value, domain_source='mihomo') for value in
                                      ('*ads*', '*', 'a?', '[ab]', 'AD?S.', '*<ads>*')),
                                    Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'),
                                    Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if mode == 'add' else ()),
                                    Rule('SRC-IP-CIDR', '198.51.100.0/24'),
                                    Rule('OR', '((DOMAIN-WILDCARD,*<ads>*),(NETWORK,tcp))', native_fields=True, domain_source='mihomo'),
                                    Rule('AND', logic, native_fields=True, domain_source='mihomo')}
                        self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                                         [Rule('DOMAIN-WILDCARD', '*white*', domain_source='mihomo'),
                                          Rule('DOMAIN-WILDCARD', '*white*<ads>*', domain_source='mihomo')])
                        for group in ('source', 'child'):
                            self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                             (sorted(expected, key=lambda rule: (rule.kind in {'IP-CIDR', 'SRC-IP-CIDR'},
                                                                                 rule.kind, len(rule.value), rule.value)), []))
                            self.assertNotIn('white.example.org', outputs[root / group / 'fin.yaml'])
                            for name in FILES:
                                lines = outputs[root / group / name].splitlines()
                                header = 7 if name == 'fin-adb.txt' else 2 if name == 'fin.yaml' else 1
                                body = lines[header:]
                                if name == 'fin-adb.txt' and purpose != 'block':
                                    body = []
                                self.assertEqual(lines[6] if name == 'fin-adb.txt' else lines[0],
                                                 f'! Total count: {len(body)}' if name == 'fin-adb.txt' else f'# {group} rules: {len(body)}')
                                self.assertEqual(len(body), len(set(body)))
                        if purpose == 'block':
                            self.assertIn('@@||allow.example.org^\n', outputs[root / 'source/fin-adb.txt'])
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                        self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                        (root / 'static/source.list').unlink()
                        (root / 'static/white.list').unlink()
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_short_wildcard_white_all_covered_empty_outputs_and_unavailable_dependency_freeze(self):
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = audit_rules.native_text('DOMAIN-WILDCARD,*', 'DOMAIN,localhost', 'DOMAIN,neighbor.example.org')
                white = audit_rules.native_text('DOMAIN-WILDCARD,*')
                (root / 'input.list').write_text(source, encoding='utf-8')
                (root / 'white.list').write_text(white, encoding='utf-8')
                configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': 'keep', 'sources': ['white.list'], 'whitelist': []},
                           {'name': 'source', 'purpose': purpose, 'no_resolve': 'keep', 'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep', 'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda url: self.fail(url))
                for group in ('source', 'child'):
                    self.assertEqual(outputs[root / group / 'fin.yaml'], f'# {group} rules: 0\npayload:\n')
                publish(outputs, root=root)
                published = {path: path.read_bytes() for path in outputs}
                configs[1]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'No adaptable rules in '):
                    generate(root, lambda url: self.fail(url))
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                configs[1]['sources'] = ['input.list']
                configs[1]['whitelist'] = ['white.list']
                (root / 'white.list').write_text(audit_rules.native_text('DOMAIN-WILDCARD,'), encoding='utf-8')
                (root / 'rulesets.json').write_text(json.dumps(configs[1:2]), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                    generate(root, lambda url: self.fail(url))
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                configs[1]['whitelist'] = ['https://example.com/bad-white']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:2]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    repaired = generate(root, lambda url: audit_rules.native_text('DOMAIN-WILDCARD,').encode())
                self.assertIn('invalid whitelist', diagnostic.getvalue())
                self.assertIn('"DOMAIN-WILDCARD,*"', repaired[root / 'source/fin.yaml'])
                self.assertEqual({path: path.read_bytes() for path in published}, published)


class UnderscoreCoverageAuditTests(unittest.TestCase):
    def test_underscore_suffix_and_exact_whites_preserve_complete_label_boundaries(self):
        for source in ('surge', 'qx', 'mihomo'):
            for value in audit_rules.UnderscoreDomainAuditTests.suffixes:
                with self.subTest(source=source, value=value):
                    suffix = Rule('DOMAIN-SUFFIX', value, domain_source=source)
                    exact = Rule('DOMAIN', value, domain_source=source)
                    child = Rule('DOMAIN', 'sub.' + value, domain_source=source)
                    child_suffix = Rule('DOMAIN-SUFFIX', 'sub.' + value, domain_source=source)
                    neighbor = Rule('DOMAIN', 'not' + value, domain_source=source)
                    neighbor_tail = Rule('DOMAIN', value + '.other', domain_source=source)
                    allowed = Rule('DOMAIN', value, allow=True, domain_source=source)
                    text = (audit_rules.native_text('DOMAIN-SUFFIX,' + value) if source == 'mihomo' else
                            ('HOST-SUFFIX' if source == 'qx' else 'DOMAIN-SUFFIX') + ',' + value + ',DIRECT')
                    white = parse_whitelist(text)
                    self.assertEqual(white, [suffix])
                    rules = [exact, suffix, child, child_suffix, neighbor, allowed, neighbor_tail]
                    self.assertEqual(exclude_covered(iter(rules), iter(white)), [neighbor, allowed, neighbor_tail])
                    self.assertEqual(exclude_covered(rules, [exact]), rules[1:])
                    self.assertEqual(set(normalize(rules * 2)), {suffix, neighbor, allowed, neighbor_tail})

    def test_underscore_provenance_case_root_dot_and_cross_source_direction_remain(self):
        for source in ('qx', 'mihomo'):
            with self.subTest(source=source):
                covered = [Rule(kind, value, domain_source=source) for kind in ('DOMAIN', 'DOMAIN-SUFFIX')
                           for value in ('AD_CORE.CCTV.COM', 'sub.ad_core.cctv.com')]
                white = parse_whitelist('DOMAIN-SUFFIX,ad_core.cctv.com')
                self.assertEqual(exclude_covered(covered, white), [])
                keep = [Rule('DOMAIN', value, domain_source=source)
                        for value in ('notad_core.cctv.com', 'ad_core.cctv.com.other')]
                self.assertEqual(exclude_covered(keep, white), keep)
                original = Rule('DOMAIN-SUFFIX', 'ad_core.cctv.com')
                self.assertEqual(exclude_covered([original], [Rule('DOMAIN-SUFFIX', original.value,
                                                                  domain_source=source)]), [original])
                self.assertEqual(len(normalize([original, *covered])), 2)
        native = [Rule(kind, 'AD_CORE.CCTV.COM.', domain_source='mihomo') for kind in ('DOMAIN', 'DOMAIN-SUFFIX')]
        self.assertEqual(exclude_covered(native, parse_whitelist('DOMAIN-SUFFIX,ad_core.cctv.com')), native)
        self.assertEqual([rule.value for rule in native], ['AD_CORE.CCTV.COM.', 'AD_CORE.CCTV.COM.'])
        for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'):
            value = 'ad_core' if kind == 'DOMAIN-KEYWORD' else 'ad_core-??.example.org'
            surge = Rule(kind, value)
            native = Rule(kind, value, domain_source='mihomo')
            qx = Rule(kind, value, domain_source='qx')
            self.assertEqual(exclude_covered([surge, native, qx], [native]), [surge, qx])
            if kind == 'DOMAIN-WILDCARD':
                self.assertEqual(exclude_covered([surge, native, qx], [surge]), [native, qx])

    def test_underscore_wildcards_keep_native_byte_and_literal_class_identity(self):
        for source, matcher in (('surge', 'DOMAIN-WILDCARD,ad_core-[ab].example.org'),
                                ('mihomo', 'DOMAIN-WILDCARD,ad_core-[ab].example.org'),
                                ('qx', 'HOST-WILDCARD,ad_core-[ab].example.org,PROXY')):
            text = audit_rules.native_text(matcher) if source == 'mihomo' else matcher
            with self.subTest(source=source):
                rules, messages = parse(text, purpose='proxy')
                self.assertEqual((rules, messages), ([Rule('DOMAIN-WILDCARD', 'ad_core-[ab].example.org',
                                                          domain_source=source)], []))
                self.assertEqual(exclude_covered(rules, parse_whitelist(text)), [])
        white = parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,ad_core-??.example.org'))
        native = Rule('DOMAIN', 'ad_core-é.example.org', domain_source='mihomo')
        surge = Rule('DOMAIN', native.value)
        qx = Rule('DOMAIN', native.value, domain_source='qx')
        self.assertEqual(exclude_covered([native, surge, qx], white), [surge, qx])
        literal = Rule('DOMAIN', 'ad_core-[ab].example.org', domain_source='mihomo')
        neighbor = Rule('DOMAIN', 'ad_core-a.example.org', domain_source='mihomo')
        self.assertEqual(exclude_covered([literal, neighbor], parse_whitelist(
            audit_rules.native_text('DOMAIN-WILDCARD,ad_core-[ab].example.org'))), [neighbor])
