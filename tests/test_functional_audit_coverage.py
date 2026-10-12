import contextlib
from datetime import datetime, timezone
from fnmatch import fnmatchcase
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


class CrossSourceCoverageAuditTests(unittest.TestCase):
    def test_surge_keyword_covers_native_required_keyword_literal(self):
        parsed, messages = parse(audit_rules.native_text('DOMAIN-KEYWORD,MICROSOFT',
                                                        'DOMAIN-KEYWORD,xMicrosoftY',
                                                        'DOMAIN,neighbor.example.org'), purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(exclude_covered(iter(parsed), iter(parse_whitelist('DOMAIN-KEYWORD,"Microsoft",DIRECT'))),
                         parsed[-1:])
        self.assertEqual([rule.value for rule in parsed], ['MICROSOFT', 'xMicrosoftY', 'neighbor.example.org'])

    def test_surge_keyword_covers_native_domain_suffix_and_required_wildcard_text(self):
        matchers = ('DOMAIN,MICROSOFT.COM', 'DOMAIN,sub.microsoft.com',
                    'DOMAIN-SUFFIX,MICROSOFT.COM', 'DOMAIN-SUFFIX,sub.microsoft.com',
                    'DOMAIN-WILDCARD,Microsoft-*.com', 'DOMAIN,neighbor.example.org')
        parsed, messages = parse(audit_rules.native_text(*matchers), purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(exclude_covered(parsed, parse_whitelist('DOMAIN-KEYWORD,microsoft')),
                         parsed[-1:])

    def test_surge_star_wildcard_covers_native_same_pattern_and_exact_only(self):
        parsed, messages = parse(audit_rules.native_text('DOMAIN-WILDCARD,WINDOWS-*.NET',
                                                        'DOMAIN,Windows-abc.net',
                                                        'DOMAIN-SUFFIX,windows-abc.net',
                                                        'DOMAIN,x.windows-abc.net',
                                                        'DOMAIN,windows-abc.net.other'), purpose='direct')
        self.assertEqual(messages, [])
        white = parse_whitelist("DOMAIN-WILDCARD,'Windows-*.NET',DIRECT")
        self.assertEqual(exclude_covered(iter(parsed), iter(white)), parsed[2:])
        self.assertEqual([rule.value for rule in parsed[:2]], ['WINDOWS-*.NET', 'Windows-abc.net'])

    def test_native_root_dot_wildcards_and_exact_are_permanently_preserved(self):
        for pattern, matcher, host in (('*.*', 'DOMAIN-WILDCARD,*.*', 'localhost.'),
                                       ('*.123.*', 'DOMAIN-WILDCARD,*.123.*', 'cdn.123.'),
                                       ('*.*', 'DOMAIN,localhost.', 'localhost.')):
            with self.subTest(pattern=pattern, matcher=matcher, host=host):
                parsed, messages = parse(audit_rules.native_text(matcher), purpose='block')
                self.assertEqual(messages, [])
                self.assertTrue(fnmatchcase(host.encode(), pattern.encode()) if matcher.startswith('DOMAIN-WILDCARD,')
                                else parsed[0].value == host)
                self.assertFalse(fnmatchcase(host.removesuffix('.'), pattern))
                self.assertEqual(exclude_covered(parsed, parse_whitelist('DOMAIN-WILDCARD,' + pattern)), parsed)
                self.assertEqual(normalize(parsed), parsed)
                outputs, _ = render('root', parsed, purpose='proxy', no_resolve='keep')
                self.assertEqual(outputs['fin.yaml'], '# root rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n')

    def test_surge_wildcard_proof_ignores_single_host_root_dot_without_rewriting_native(self):
        matchers = ('DOMAIN,WINDOWS-abc.NET.', 'DOMAIN-WILDCARD,WINDOWS-abc.NET.',
                    'DOMAIN,localhost.', 'DOMAIN,windows-abc.net..')
        parsed, messages = parse(audit_rules.native_text(*matchers), purpose='proxy')
        self.assertEqual(parsed, [Rule(kind, value, domain_source='mihomo') for kind, value in
                                 (('DOMAIN', 'WINDOWS-abc.NET.'), ('DOMAIN-WILDCARD', 'WINDOWS-abc.NET.'),
                                  ('DOMAIN', 'localhost.'))])
        self.assertEqual(messages, ['line 5: invalid domain windows-abc.net..'])
        self.assertEqual(exclude_covered(parsed, parse_whitelist('DOMAIN-WILDCARD,windows-*.net')), parsed[2:])
        self.assertEqual(exclude_covered(parsed[2:], parse_whitelist('DOMAIN-WILDCARD,*.*')), parsed[2:])
        self.assertEqual([rule.value for rule in parsed], ['WINDOWS-abc.NET.', 'WINDOWS-abc.NET.', 'localhost.'])
        outputs, _ = render('root', parsed, purpose='proxy', no_resolve='keep')
        self.assertIn('  - "DOMAIN,WINDOWS-abc.NET."\n', outputs['fin.yaml'])
        self.assertIn('  - "DOMAIN-WILDCARD,WINDOWS-abc.NET."\n', outputs['fin.yaml'])

    def test_unicode_white_constructor_lowercase_does_not_prove_ascii_native_keyword_coverage(self):
        native = Rule('DOMAIN-KEYWORD', 'k', domain_source='mihomo')
        white = parse_whitelist('DOMAIN-KEYWORD,K')
        self.assertEqual(white, [Rule('DOMAIN-KEYWORD', 'K')])
        self.assertEqual(exclude_covered([native], white), [native])

    def test_keyword_proof_uses_required_literal_without_terminal_root_dot(self):
        cases = (
            ('microsoft', 'DOMAIN,microsoft.com.', True),
            ('microsoft.', 'DOMAIN,microsoft.com.', True),
            ('microsoft.', 'DOMAIN,microsoft.', False),
            ('microsoft.', 'DOMAIN-SUFFIX,microsoft.', False),
            ('microsoft.', 'DOMAIN-KEYWORD,microsoft.', False),
            ('microsoft.', 'DOMAIN-KEYWORD,microsoft..', True),
            ('microsoft.', 'DOMAIN-WILDCARD,microsoft.*', False),
            ('microsoft.', 'DOMAIN-WILDCARD,*microsoft.*', False),
            ('microsoft.', 'DOMAIN-WILDCARD,microsoft.**', False),
            ('microsoft.', 'DOMAIN-WILDCARD,microsoft..*', True),
            ('microsoft.', 'DOMAIN-WILDCARD,microsoft.?*', True),
            ('microsoft.', 'DOMAIN-WILDCARD,microsoft.*.com', True),
            ('micro', 'DOMAIN-WILDCARD,mi*cro.com', False),
            ('ads', 'DOMAIN-WILDCARD,*[ads]*', True),
            ('[ads]', 'DOMAIN-WILDCARD,*[ads]*', True),
            ('microsoft', 'DOMAIN-KEYWORD,"MICROSOFT"', True),
            ('microsoft', 'DOMAIN-WILDCARD,"MICROSOFT-*"', True),
            ('microsoft', 'DOMAIN-KEYWORD,xMICROSOFTé', False),
            ('microsoft', 'DOMAIN-WILDCARD,microsoft-é*', False),
            ('', 'DOMAIN-KEYWORD,microsoft', False),
        )
        for keyword, matcher, covered in cases:
            with self.subTest(keyword=keyword, matcher=matcher):
                parsed, messages = parse(audit_rules.native_text(matcher), purpose='proxy')
                self.assertEqual(messages, [])
                white = [Rule('DOMAIN-KEYWORD', keyword)]
                self.assertEqual(exclude_covered(parsed, white), [] if covered else parsed)
                self.assertEqual(parsed[0].value, matcher.partition(',')[2])

    def test_plain_star_subset_is_one_way_and_rejects_unproved_questions_classes_unicode(self):
        for pattern, covered in (('windows-*.net', True), ('*.ms', True), ('*', True),
                                 ('*.*123*', True), ('123**', True), ('**', True),
                                 ('*.*', False), ('*.123.*', False), ('*.123', True),
                                 ('*.??*', False), ('windows-??.net', False),
                                 ('api-[0-9].example.com', False), ('api-é*.example.com', False)):
            with self.subTest(pattern=pattern):
                native = Rule('DOMAIN-WILDCARD', pattern, domain_source='mihomo')
                surge = Rule('DOMAIN-WILDCARD', pattern)
                qx = Rule('DOMAIN-WILDCARD', pattern, domain_source='qx')
                self.assertEqual(exclude_covered([native, qx], [surge]), [qx] if covered else [native, qx])
                self.assertEqual(exclude_covered([surge, qx], [native]), [surge, qx])
                self.assertEqual(set(normalize([surge, native, qx] * 2)), {surge, native, qx})
        cases = (('windows-??.net', 'windows-ab.net', True),
                 ('windows-??.net', 'windows-é.net', False),
                 ('api-[0-9].example.com', 'api-[0-9].example.com', False),
                 ('api-[0-9].example.com', 'api-7.example.com', False),
                 ('*.*', 'localhost.', False), ('*.123.*', 'cdn.123.', False),
                 ('windows-*.net', 'windows-abc.net.', True),
                 ('windows-*.net', 'x.windows-abc.net', False),
                 ('windows-*.net', 'windows-abc.net.other', False),
                 ('windows-*.net', 'K.windows-abc.net', False))
        for pattern, host, covered in cases:
            with self.subTest(pattern=pattern, host=host):
                blocker = Rule('DOMAIN', host, domain_source='mihomo')
                self.assertEqual(exclude_covered([blocker], [Rule('DOMAIN-WILDCARD', pattern)]),
                                 [] if covered else [blocker])
        unicode_white = Rule('DOMAIN-WILDCARD', 'K-*.net')
        native = Rule('DOMAIN', 'k-abc.net', domain_source='mihomo')
        self.assertEqual(exclude_covered([native], [unicode_white]), [native])

    def test_source_flags_iterables_allow_and_whole_logical_conditions_keep_identity(self):
        native = Rule('DOMAIN-KEYWORD', 'MICROSOFT', ('via-interface=en1',),
                      literal_process=True, native_fields=True, domain_source='mihomo')
        allowed = Rule('DOMAIN-KEYWORD', 'MICROSOFT', ('no-resolve',), allow=True,
                       literal_process=True, native_fields=True, domain_source='mihomo')
        qx = Rule('DOMAIN-KEYWORD', 'microsoft', domain_source='qx')
        neighbor = Rule('DOMAIN', 'neighbor.example.org', ('force-cellular',), domain_source='qx')
        source = [allowed, qx, native, neighbor, native]
        self.assertEqual(exclude_covered(iter(source), iter(parse_whitelist('DOMAIN-KEYWORD,microsoft'))),
                         [allowed, qx, neighbor])
        for native_source in (False, True):
            for operator, value in (
                    ('AND', '((DOMAIN-KEYWORD,microsoft),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'),
                    ('OR', '((DOMAIN-KEYWORD,microsoft),(NETWORK,tcp))'),
                    ('NOT', '((DOMAIN-KEYWORD,microsoft))'),
                    ('AND', '((NOT,((DOMAIN-KEYWORD,microsoft))),(OR,((NETWORK,tcp),(DOMAIN,neighbor.example.org))))')):
                for purpose in ('block', 'direct', 'proxy'):
                    with self.subTest(native=native_source, operator=operator, purpose=purpose):
                        matcher = operator + ',' + value
                        parsed, messages = parse(audit_rules.native_text(matcher) if native_source else matcher,
                                                 purpose=purpose)
                        self.assertEqual(messages, [])
                        self.assertEqual(exclude_covered(parsed, parse_whitelist('DOMAIN-KEYWORD,microsoft')), parsed)
                        for mode in ('add', 'strip', 'keep'):
                            outputs, skipped = render('logical', parsed, purpose=purpose, no_resolve=mode)
                            repeated, warnings = parse(outputs['fin.yaml'], purpose=purpose)
                            self.assertEqual(warnings, [])
                            self.assertEqual(len(repeated), 1)
                            self.assertEqual(repeated[0].domain_source,
                                             'mihomo' if native_source or '(DOMAIN,neighbor.example.org)' in value else 'surge')
                            expected = value.replace(',no-resolve)', ')') if mode == 'strip' else value
                            if not native_source:
                                expected = expected.replace('DOMAIN-KEYWORD,microsoft', 'DOMAIN-REGEX,microsoft')
                            self.assertEqual(repeated[0].value, expected)
                            self.assertNotIn('fin.yaml:' + operator, skipped)
        self.assertEqual(exclude_covered([Rule('DOMAIN-REGEX', '^microsoft$')],
                                        parse_whitelist('DOMAIN-KEYWORD,microsoft')),
                         [Rule('DOMAIN-REGEX', '^microsoft$')])

    def test_generate_publish_source_proof_keeps_native_root_and_actual_yaml_dependencies(self):
        cases = (
            ('DOMAIN-KEYWORD,microsoft\nDOMAIN-WILDCARD,windows-*.net\n',
             ('DOMAIN-KEYWORD,MICROSOFT', 'DOMAIN-KEYWORD,xmicrosofty',
              'DOMAIN,microsoft.com', 'DOMAIN,sub.microsoft.com', 'DOMAIN-SUFFIX,microsoft.com',
              'DOMAIN-SUFFIX,sub.microsoft.com', 'DOMAIN-WILDCARD,microsoft-*.com',
              'DOMAIN-WILDCARD,windows-*.net', 'DOMAIN,WINDOWS-abc.NET.',
              'DOMAIN-SUFFIX,windows-abc.net', 'DOMAIN-SUFFIX,neighbor.example.org',
              'DOMAIN-WILDCARD,windows-??.net', 'DOMAIN-WILDCARD,api-[0-9].example.org',
              'DOMAIN-KEYWORD,é', 'DOMAIN-WILDCARD,"windows-*.net"',
              'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24', 'IP-ASN,00'),
             ('DOMAIN-SUFFIX,windows-abc.net', 'DOMAIN-SUFFIX,neighbor.example.org',
              'DOMAIN-WILDCARD,windows-??.net', 'DOMAIN-WILDCARD,api-[0-9].example.org',
              'DOMAIN-KEYWORD,é', 'DOMAIN-WILDCARD,"windows-*.net"',
              'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24', 'IP-ASN,00')),
            ('DOMAIN-WILDCARD,*.*\n', ('DOMAIN-WILDCARD,*.*', 'DOMAIN,localhost.'),
             ('DOMAIN-WILDCARD,*.*', 'DOMAIN,localhost.')),
            ('DOMAIN-WILDCARD,*.123.*\n', ('DOMAIN-WILDCARD,*.123.*', 'DOMAIN,cdn.123.'),
             ('DOMAIN-WILDCARD,*.123.*', 'DOMAIN,cdn.123.')),
        )
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    for white, matchers, kept in cases:
                        with self.subTest(purpose=purpose, mode=mode, remote=remote, white=white), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'static').mkdir()
                            source = audit_rules.native_text(*matchers)
                            (root / 'static/source.list').write_text(source, encoding='utf-8')
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/white' if remote else 'static/white.list'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'static/source.list'],
                                        'whitelist': ['white/fin.txt']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.txt']}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            responses = {'https://example.com/white': white.encode(), 'https://example.com/source': source.encode()}
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                                clock.now.return_value = datetime(2026, 10, 13, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            self.assertEqual(set(outputs), {root / group / name for group in ('white', 'source', 'child') for name in FILES})
                            self.assertNotIn('invalid ', diagnostics.getvalue())
                            self.assertNotIn('frozen', diagnostics.getvalue())
                            expected = set()
                            for matcher in kept:
                                if mode == 'strip':
                                    matcher = matcher.removesuffix(',no-resolve')
                                elif mode == 'add' and matcher.startswith('IP-ASN,'):
                                    matcher += ',no-resolve'
                                expected.add(matcher)
                            for group in ('source', 'child'):
                                body = [json.loads(line[4:]) for line in outputs[root / group / 'fin.yaml'].splitlines()[2:]]
                                self.assertEqual(set(body), expected)
                                self.assertEqual(len(body), len(expected))
                                self.assertEqual(outputs[root / group / 'fin.yaml'].splitlines()[0], f'# {group} rules: {len(expected)}')
                                for matcher in kept:
                                    if matcher.startswith('DOMAIN,'):
                                        self.assertIn('  - ' + json.dumps(matcher) + '\n', outputs[root / group / 'fin.yaml'])
                                for name in FILES:
                                    lines = outputs[root / group / name].splitlines()
                                    header = 7 if name == 'fin-adb.txt' else 2 if name == 'fin.yaml' else 1
                                    count = len(lines[header:]) if name != 'fin-adb.txt' or purpose == 'block' else 0
                                    self.assertEqual(lines[6] if name == 'fin-adb.txt' else lines[0],
                                                     f'! Total count: {count}' if name == 'fin-adb.txt' else f'# {group} rules: {count}')
                                    self.assertEqual(len(lines[header:]), len(set(lines[header:])))
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(data.endswith(b'\n') and b'\r' not in data for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                            (root / 'static/source.list').unlink()
                            (root / 'static/white.list').unlink()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 13, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_source_all_covered_empty_outputs_strict_white_and_frozen_dependencies(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = audit_rules.native_text('DOMAIN-KEYWORD,microsoft', 'DOMAIN-WILDCARD,windows-*.net',
                                                     'DOMAIN,windows-abc.net', 'DOMAIN-SUFFIX,microsoft.com')
                    (root / 'input.list').write_text(source, encoding='utf-8')
                    (root / 'white.list').write_text('DOMAIN-KEYWORD,microsoft\nDOMAIN-WILDCARD,windows-*.net\n', encoding='utf-8')
                    configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode, 'sources': ['input.list'], 'whitelist': ['white.list']},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode, 'sources': ['source/fin.yaml'], 'whitelist': ['white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(len(outputs), 12)
                    for group in ('source', 'child'):
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(outputs[root / group / name], f'# {group} rules: 0\n')
                        self.assertEqual(outputs[root / group / 'fin.yaml'], f'# {group} rules: 0\npayload:\n')
                        if purpose == 'block':
                            self.assertIn('@@', outputs[root / group / 'fin-adb.txt'])
                    publish(outputs, root=root)
                    published = {path: path.read_bytes() for path in outputs}
                    configs[0]['sources'] = ['https://example.com/missing']
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')

                    def unavailable(url):
                        raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                    with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                        self.assertEqual(generate(root, unavailable), {})
                    self.assertIn('HTTP 404; skipped', diagnostics.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    configs[0]['sources'] = ['input.list']
                    (root / 'white.list').write_text('DOMAIN-WILDCARD,', encoding='utf-8')
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    configs[0]['whitelist'] = ['https://example.com/bad-white']
                    (root / 'rulesets.json').write_text(json.dumps(configs[:1]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                        unfiltered = generate(root, lambda url: b'DOMAIN-WILDCARD,')
                    self.assertIn('invalid whitelist', diagnostics.getvalue())
                    self.assertIn('  - "DOMAIN-KEYWORD,microsoft"\n', unfiltered[root / 'source/fin.yaml'])
                    (root / 'input.list').write_text(audit_rules.native_text('DEVICE-NAME,\x00'), encoding='utf-8')
                    (root / 'white.list').write_text('DOMAIN-KEYWORD,microsoft\nDOMAIN-WILDCARD,windows-*.net\n', encoding='utf-8')
                    configs[0]['whitelist'] = []
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                        self.assertEqual(generate(root, lambda url: self.fail(url)), {})
                    self.assertIn('no routable rules; frozen', diagnostics.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                        publish({root / 'static/forbidden.txt': 'x'}, root=root)
                    with self.assertRaisesRegex(ValueError, 'Source escapes root'):
                        configs[0]['sources'] = ['../input.list']
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_long_literals_and_deep_logical_keep_original_limits_under_eight_seconds(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, exclude_covered, parse, parse_whitelist
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
white = parse_whitelist('DOMAIN-KEYWORD,microsoft')
for matcher in ('DOMAIN-WILDCARD,' + 'a' * 5000 + 'MICROSOFT*',
                'DOMAIN-KEYWORD,' + '0' * 5000 + 'MICROSOFT.'):
    parsed, messages = parse('payload:\\n  - ' + json.dumps(matcher), purpose='proxy')
    assert not messages and len(parsed) == 1
    assert exclude_covered(parsed, white) == []
    assert parsed[0].value == matcher.partition(',')[2]
for depth in (600, 1000):
    matcher = 'DOMAIN-KEYWORD,microsoft'
    for _ in range(depth):
        matcher = 'NOT,((' + matcher + '))'
    parsed, messages = parse('payload:\\n  - ' + json.dumps(matcher), purpose='proxy')
    wanted = Rule('NOT', matcher[4:], native_fields=True, domain_source='mihomo')
    assert (parsed, messages) == ([wanted], [])
    assert exclude_covered(iter(parsed), iter(white)) == parsed
    output, skips = render('deep', parsed, purpose='proxy', no_resolve='keep')
    assert 'fin.yaml:NOT' not in skips
    assert parse(output['fin.yaml'], purpose='proxy') == ([wanted], [])
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)


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
