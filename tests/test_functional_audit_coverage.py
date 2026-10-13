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


class RawRegexWhitelistAuditTests(unittest.TestCase):
    def test_identical_raw_regex_white_removes_ordinary_blocker(self):
        value = r'^ADS\.Example\.com$'
        blocked, messages = parse('DOMAIN-REGEX,' + value, purpose='block')
        self.assertEqual((blocked, messages), ([Rule('DOMAIN-REGEX', value)], []))
        white = parse_whitelist(audit_rules.native_text('DOMAIN-REGEX,' + value))
        self.assertEqual(white, blocked)
        self.assertEqual(exclude_covered(iter(blocked), iter(white)), [])

    def test_ordinary_native_quotes_policies_and_purposes_share_raw_white_identity(self):
        values = (r'^ads\.example\.com$', r'^(?i:ADS)[.]example[.]com$', r'^(a,b)[)]$',
                  r'^\x{0000061}ds$', r'^a{00001}$', r'^(?<name>a)\k<name>$', '^广告[.]例子$')
        for value in values:
            sources = ['DOMAIN-REGEX,' + quote + value + quote for quote in ('', "'", '"')]
            sources += [audit_rules.native_text('DOMAIN-REGEX,' + value),
                        'rules:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)]
            whites = [parse_whitelist(text + (',DIRECT' if not text.startswith(('payload:', 'rules:')) else ''),
                                      domain_set=domain_set)
                      for text in sources for domain_set in (False, True)]
            for purpose in ('block', 'direct', 'proxy'):
                for source in sources:
                    with self.subTest(value=value, purpose=purpose, source=source):
                        blocked, messages = parse(source, purpose=purpose)
                        self.assertEqual((blocked, messages), ([Rule('DOMAIN-REGEX', value)], []))
                        for white in whites:
                            self.assertEqual(white, blocked)
                            self.assertEqual(exclude_covered(iter(blocked), iter(white)), [])

    def test_raw_case_escape_group_and_kind_differences_keep_neighbors_and_allow(self):
        value = r'^ads\.example\.com$'
        different = (r'^ADS\.example\.com$', r'^ads[.]example[.]com$',
                     r'^(?:ads)\.example\.com$', r'(?i)^ads\.example\.com$',
                     r'^ads\.example\.com\z', r'^ads\.example\.com$.')
        original = [Rule('DOMAIN-REGEX', matcher, options, allow, literal, fields, source)
                    for matcher in (value, *different) for source in ('surge', 'qx', 'mihomo')
                    for options in ((), ('no-resolve',), ('via-interface=en1',)) for allow in (False, True)
                    for literal in (False, True) for fields in (False, True)]
        neighbors = [Rule(kind, value) for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
                     'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX', 'URL-REGEX')]
        neighbors += [Rule('DOMAIN', 'ads.example.com'), Rule('DOMAIN-SUFFIX', 'example.com'),
                      Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',)),
                      Rule('SRC-IP-CIDR', '192.0.2.0/24'),
                      Rule('IP-ASN', '00'), Rule('IP-ASN', '0'),
                      Rule('PROCESS-NAME', 'Foo*Bar', literal_process=True),
                      Rule('DOMAIN-WILDCARD', 'api-[ab].example.com', domain_source='mihomo'),
                      Rule('DOMAIN', 'neighbor.example.org.', domain_source='mihomo')]
        white = parse_whitelist('DOMAIN-REGEX,' + value)
        expected = [rule for rule in original if rule.allow or rule.value != value] + neighbors
        self.assertEqual(exclude_covered(iter(original + neighbors), iter(white * 2)), expected)
        self.assertEqual(exclude_covered(iter(original + neighbors), iter(())), original + neighbors)
        self.assertEqual(set(normalize(original * 2)), set(original))
        self.assertEqual(exclude_covered([Rule('DOMAIN-REGEX', value)], neighbors), [Rule('DOMAIN-REGEX', value)])

    def test_long_numeric_hex_literal_and_deep_raw_identity_keeps_distinct_text_and_global_limits(self):
        limits = sys.get_int_max_str_digits(), sys.getrecursionlimit()
        pairs = ((r'^\x{' + '0' * 5000 + '61}$', r'^\x{61}$'),
                 ('^a{' + '0' * 5000 + '1}$', '^a{1}$'),
                 ('^a{,' + '9' * 5000 + '}$', '^a{,9}$'),
                 *[('^' + opening * depth + 'a' + ')' * depth + '$',
                    '^' + opening * depth + 'b' + ')' * depth + '$')
                   for depth in (600, 1000) for opening in ('(', '(?:', '(?i:', '(?n:', '(?x:')])
        for value, different in pairs:
            for native in (False, True):
                source = (audit_rules.native_text('DOMAIN-REGEX,' + value, 'DOMAIN-REGEX,' + different) if native else
                          'DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN-REGEX,' + json.dumps(different))
                white_text = 'DOMAIN-REGEX,' + json.dumps(value) if native else audit_rules.native_text('DOMAIN-REGEX,' + value)
                with self.subTest(length=len(value), native=native):
                    parsed, messages = parse(source, purpose='proxy')
                    self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN-REGEX', different)], []))
                    white = parse_whitelist(white_text)
                    self.assertEqual(white, [Rule('DOMAIN-REGEX', value)])
                    self.assertEqual(exclude_covered(iter(parsed), iter(white)), [Rule('DOMAIN-REGEX', different)])
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_native_inner_quotes_remain_literal_and_invalid_white_still_warns(self):
        value = '^ads$'
        ordinary = parse_whitelist('DOMAIN-REGEX,"' + value + '"')
        for quote in ("'", '"'):
            native, messages = parse(audit_rules.native_text('DOMAIN-REGEX,' + quote + value + quote), purpose='block')
            self.assertEqual(messages, [])
            self.assertEqual(native, [Rule('DOMAIN-REGEX', quote + value + quote)])
            self.assertEqual(exclude_covered(native, ordinary), native)
            self.assertEqual(exclude_covered(native, parse_whitelist(audit_rules.native_text(
                'DOMAIN-REGEX,' + quote + value + quote))), [])
        for purpose in ('block', 'direct', 'proxy'):
            for text, line in (('DOMAIN-REGEX,*ads\nDOMAIN,neighbor.example.org', 1),
                               (audit_rules.native_text('DOMAIN-REGEX,*ads', 'DOMAIN,neighbor.example.org'), 2)):
                parsed, messages = parse(text, purpose=purpose)
                self.assertEqual(len(parsed), 1)
                self.assertEqual(parsed[0].value, 'neighbor.example.org')
                self.assertEqual(messages, [f'line {line}: invalid DOMAIN-REGEX *ads'])
                with self.assertWarnsRegex(UserWarning, 'invalid DOMAIN-REGEX'):
                    self.assertEqual(parse_whitelist(text), parsed)
            parsed, messages = parse('DOMAIN-REGEX,"^ads$",no-resolve\nDOMAIN,neighbor.example.org', purpose=purpose)
            self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
            self.assertEqual(messages, ['line 1: unsupported no-resolve for DOMAIN-REGEX'])
        with self.assertRaisesRegex(ValueError, 'invalid DOMAIN-REGEX'):
            parse_whitelist('DOMAIN-REGEX,*ads')

    def test_external_raw_white_preserves_full_logical_structure_and_ip_flags(self):
        value = '^ads[.]example[.]org$'
        expressions = (
            ('AND', '((DOMAIN-REGEX,' + value + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'),
            ('OR', '((DOMAIN-REGEX,' + value + '),(DOMAIN,neighbor.example.org))'),
            ('NOT', '((DOMAIN-REGEX,' + value + '))'),
            ('AND', '((NOT,((DOMAIN-REGEX,' + value + '))),(OR,((DOMAIN,neighbor.example.org),(NETWORK,tcp))))'),
        )
        for operator, expression in expressions:
            for native in (False, True):
                source = operator + ',' + expression
                if native:
                    source = audit_rules.native_text(source)
                for purpose in ('block', 'direct', 'proxy'):
                    parsed, messages = parse(source, purpose=purpose)
                    self.assertEqual(messages, [])
                    self.assertEqual(len(parsed), 1)
                    self.assertEqual(parsed[0].value, expression)
                    white = parse_whitelist('DOMAIN-REGEX,' + value)
                    self.assertEqual(exclude_covered(iter(parsed), iter(white)), parsed)
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(operator=operator, native=native, purpose=purpose, mode=mode):
                            outputs, skipped = render('logical', normalize(exclude_covered(parsed, white)),
                                                      purpose=purpose, no_resolve=mode, whitelist=white)
                            expected = expression.replace(',no-resolve)', ')') if mode == 'strip' else expression
                            self.assertEqual(outputs['fin.yaml'], '# logical rules: 1\npayload:\n  - ' +
                                             json.dumps(operator + ',' + expected) + '\n')
                            self.assertEqual(skipped.get('fin.txt:' + operator), 1)
                            self.assertNotIn('whitelist-covered:' + operator, skipped)
                            self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose)[0][0].value, expected)
                            self.assertNotIn('SRC-IP-CIDR,198.51.100.0/24,no-resolve', outputs['fin.yaml'])

    def test_generate_raw_white_preserves_six_outputs_neighbors_and_actual_dependency_bytes(self):
        value = '^ads[.]example[.]org$'
        variant = '^ADS[.]example[.]org$'
        expression = ('((DOMAIN-REGEX,' + value + '),(IP-CIDR,203.0.113.0/24,no-resolve),'
                      '(SRC-IP-CIDR,198.51.100.0/24),(PROCESS-NAME,Foo*Bar))')
        source = audit_rules.native_text('DOMAIN-REGEX,' + value, 'DOMAIN-REGEX,' + variant,
            'AND,' + expression, 'DOMAIN,neighbor.example.org', 'IP-ASN,00',
            'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24')
        white = audit_rules.native_text('DOMAIN-REGEX,' + value)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        paths = (root / 'static/source.list', root / 'static/white.list')
                        for path, text in zip(paths, (source, white)):
                            path.write_bytes(b'\xef\xbb\xbf' + text.replace('\n', '\r\n').encode('utf-8'))
                        inputs = {path: path.read_bytes() for path in paths}
                        source_input = 'https://example.com/source' if remote else 'static/source.list'
                        white_input = 'https://example.com/white' if remote else 'static/white.list'
                        configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': [white_input], 'whitelist': []},
                                   {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': [source_input], 'whitelist': [white_input]},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for group in ('white', 'source', 'child'):
                            (root / group).mkdir()
                            for name in FILES:
                                path = root / group / name
                                path.write_bytes(b'old complete product\x00\xff\r\n')
                                old[path] = path.read_bytes()
                        responses = {'https://example.com/source': inputs[paths[0]], 'https://example.com/white': inputs[paths[1]]}
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 13, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: responses[url])
                        self.assertEqual(set(outputs), set(old))
                        self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']), [Rule('DOMAIN-REGEX', value)])
                        flag = '' if mode == 'strip' else ',no-resolve'
                        asn_flag = ',no-resolve' if mode == 'add' else ''
                        logic = expression.replace(',no-resolve)', ')') if mode == 'strip' else expression
                        ip, asn = 'IP-CIDR,192.0.2.0/24' + flag, 'IP-ASN,00' + asn_flag
                        yaml_lines = ['AND,' + logic, 'DOMAIN,neighbor.example.org', 'DOMAIN-REGEX,' + variant,
                                      asn, ip, 'SRC-IP-CIDR,198.51.100.0/24']
                        bodies = {
                            'fin.txt': ['DOMAIN,neighbor.example.org', asn, ip, 'SRC-IP,198.51.100.0/24'],
                            'fin-qx.txt': ['HOST,neighbor.example.org,LIST', 'IP-ASN,00,LIST' + asn_flag,
                                           'IP-CIDR,192.0.2.0/24,LIST' + flag],
                            'fin.yaml': ['  - ' + json.dumps(line) for line in yaml_lines],
                            'fin-surge.txt': [asn, ip, 'SRC-IP,198.51.100.0/24'],
                            'fin-surge-ds.txt': ['neighbor.example.org'],
                        }
                        expected = {}
                        for group in ('white', 'source', 'child'):
                            for name in FILES:
                                if name == 'fin-adb.txt':
                                    dns = (['@@/' + value + '/'] if group != 'white' else []) if purpose == 'block' else []
                                    if purpose == 'block':
                                        dns += (['/' + value + '/'] if group == 'white' else
                                                ['/' + variant + '/', '0.0.0.0 neighbor.example.org'])
                                    text = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                            '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                            '! License: Inherits upstream licenses\n! Version: 202610130000\n' +
                                            f'! Total count: {len(dns)}\n' + ''.join(line + '\n' for line in dns) +
                                            ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n'))
                                else:
                                    body = (['  - ' + json.dumps('DOMAIN-REGEX,' + value)] if name == 'fin.yaml' else []) if group == 'white' else bodies[name]
                                    text = f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '') + ''.join(line + '\n' for line in body)
                                expected[root / group / name] = text
                        self.assertEqual(outputs, expected)
                        skips = {}
                        supported = {'AND': {'fin.yaml'}, 'DOMAIN-REGEX': {'fin.yaml', *(['fin-adb.txt'] if purpose == 'block' else [])},
                                     'IP-ASN': {'fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-surge.txt'},
                                     'IP-CIDR': {'fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-surge.txt'},
                                     'SRC-IP-CIDR': {'fin.txt', 'fin.yaml', 'fin-surge.txt'}}
                        for kind, names in supported.items():
                            for name in FILES:
                                if name not in names:
                                    skips[name + ':' + kind] = 1
                        if purpose != 'block':
                            skips['fin-adb.txt:DOMAIN'] = 1
                        white_skips = {name + ':DOMAIN-REGEX': 1 for name in FILES
                                       if name not in {'fin.yaml', *(['fin-adb.txt'] if purpose == 'block' else [])}}
                        self.assertEqual(diagnostic.getvalue().splitlines(), [f'{group} {key}: {count}'
                            for group, counts in (('white', white_skips), ('source', skips), ('child', skips))
                            for key, count in sorted(counts.items())])
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode('utf-8') for path, text in expected.items()})
                        self.assertTrue(all(data.endswith(b'\n') and b'\r' not in data for data in published.values()))
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        wanted = [Rule('AND', logic, literal_process=True, native_fields=True),
                                  Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'),
                                  Rule('DOMAIN-REGEX', variant), Rule('IP-ASN', '00', ('no-resolve',) if asn_flag else ()),
                                  Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                  Rule('SRC-IP-CIDR', '198.51.100.0/24')]
                        self.assertEqual(parse(outputs[root / 'child/fin.yaml'], purpose=purpose), (wanted, []))
                        (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 13, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name == 'child'})
                        self.assertEqual(diagnostic.getvalue().splitlines(), [f'child {key}: {count}' for key, count in sorted(skips.items())])
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_all_covered_regex_publishes_empty_routes_dns_exceptions_and_empty_same_round_dependency(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for value, portable in (('^ads[.]example[.]org$', True), ('^(?=ads)ads[.]example[.]org$', False)):
                        with self.subTest(purpose=purpose, mode=mode, native=native, portable=portable), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            matcher = 'DOMAIN-REGEX,' + value
                            (root / 'input.list').write_text(audit_rules.native_text(matcher) if native else matcher, encoding='utf-8')
                            (root / 'white.list').write_text(matcher if native else audit_rules.native_text(matcher), encoding='utf-8')
                            configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['input.list'] if group == 'source' else ['source/fin.yaml'],
                                        'whitelist': ['white.list']} for group in ('source', 'child')]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old complete product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 13, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual(set(outputs), set(old))
                            self.assertEqual(diagnostic.getvalue().splitlines(), [f'{group} fin-adb.txt:DOMAIN-REGEX: 1'
                                for group in ('source', 'child')] if purpose == 'block' and not portable else [])
                            for group in ('source', 'child'):
                                for name in FILES:
                                    if name != 'fin-adb.txt':
                                        self.assertEqual(outputs[root / group / name], f'# {group} rules: 0\n' +
                                                         ('payload:\n' if name == 'fin.yaml' else ''))
                                dns = ['@@/' + value + '/'] if purpose == 'block' and portable else []
                                self.assertEqual(outputs[root / group / 'fin-adb.txt'], '[Adblock Plus 2.0]\n' +
                                    f'! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                    '! License: Inherits upstream licenses\n! Version: 202610130000\n' +
                                    f'! Total count: {len(dns)}\n' + ''.join(line + '\n' for line in dns) +
                                    ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n'))
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with self.assertRaisesRegex(ValueError, 'No adaptable rules in '):
                                generate(root, lambda url: self.fail(url))
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_covered_regex_does_not_hide_unusable_sources_unsupported_rules_or_strict_white_errors(self):
        value = '^ads[.]example[.]org$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'input.list').write_text(audit_rules.native_text('DOMAIN-REGEX,' + value, 'DEVICE-NAME,a\x00b'), encoding='utf-8')
                    (root / 'white.list').write_text('DOMAIN-REGEX,' + value, encoding='utf-8')
                    configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['input.list'] if group == 'source' else ['source/fin.yaml'],
                                'whitelist': ['white.list']} for group in ('source', 'child')]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('source', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            path.write_bytes(b'old complete product\x00\xff\r\n')
                            old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, lambda url: self.fail(url)), {})
                    self.assertEqual(diagnostic.getvalue().splitlines(), ['source: no routable rules; frozen'])
                    (root / 'input.list').write_text('DOMAIN-REGEX,' + value, encoding='utf-8')
                    configs[0]['sources'].append('https://example.com/missing')
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')

                    def unavailable(url):
                        raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, unavailable), {})
                    self.assertEqual(diagnostic.getvalue().splitlines(), ['https://example.com/missing: HTTP 404; skipped',
                                                                          'source: no routable rules; frozen'])
                    configs[0]['sources'] = ['input.list']
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    for invalid in ('DOMAIN-REGEX,*ads', ''):
                        (root / 'white.list').write_text(invalid, encoding='utf-8')
                        with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                            generate(root, lambda url: self.fail(url))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                    configs[0]['whitelist'] = ['https://example.com/bad-white']
                    (root / 'rulesets.json').write_text(json.dumps(configs[:1]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        recovered = generate(root, lambda url: b'DOMAIN-REGEX,*ads')
                    self.assertIn('invalid whitelist', diagnostic.getvalue())
                    self.assertEqual(recovered[root / 'source/fin.yaml'], '# source rules: 1\npayload:\n  - ' +
                                     json.dumps('DOMAIN-REGEX,' + value) + '\n')
                    def unexpected(url):
                        raise RuntimeError('unexpected endpoint')

                    with self.assertRaisesRegex(RuntimeError, 'unexpected endpoint'):
                        generate(root, unexpected)
                    self.assertEqual({path: path.read_bytes() for path in old}, old)


class SurgeClassWhitelistAuditTests(unittest.TestCase):
    def test_surge_class_white_covers_matching_exact_hosts_and_keeps_label_neighbors(self):
        source = ('DOMAIN,cdn-a.example.com\nDOMAIN,cdn-b.example.com\n'
                  'DOMAIN,cdn-z.example.com\nDOMAIN,x.cdn-a.example.com\n'
                  'DOMAIN,cdn-a.example.com.other\nDOMAIN-WILDCARD,cdn-[ab].example.com')
        parsed, messages = parse(source, purpose='block')
        self.assertEqual(messages, [])
        white = parse_whitelist('DOMAIN-WILDCARD,cdn-[ab].example.com,DIRECT')
        self.assertEqual(white, [Rule('DOMAIN-WILDCARD', 'cdn-[ab].example.com')])
        self.assertEqual(exclude_covered(iter(parsed), iter(white)), parsed[2:5])

    def test_ascii_classes_ranges_and_stars_keep_full_match_boundaries(self):
        cases = (
            ('cdn-[ab].example.com', ('cdn-a.example.com', 'cdn-b.example.com'),
             ('cdn-z.example.com', 'cdn-aa.example.com', 'cdn-.example.com')),
            ('cdn-[0-9].example.com', ('cdn-0.example.com', 'cdn-7.example.com', 'cdn-9.example.com'),
             ('cdn-a.example.com', 'cdn-10.example.com')),
            ('cdn-[a-c0-2].example.com', ('cdn-a.example.com', 'cdn-c.example.com', 'cdn-0.example.com', 'cdn-2.example.com'),
             ('cdn-d.example.com', 'cdn-3.example.com', 'cdn-ac.example.com')),
            ('cdn[a-]x.example.com', ('cdnax.example.com', 'cdn-x.example.com'), ('cdnbx.example.com',)),
            ('cdn[-a]x.example.com', ('cdnax.example.com', 'cdn-x.example.com'), ('cdnbx.example.com',)),
            ('cdn-[ab]?.example.com', ('cdn-aa.example.com', 'cdn-b9.example.com'),
             ('cdn-a.example.com', 'cdn-aaa.example.com')),
            ('cdn-[ab]*.example.com', ('cdn-a.example.com', 'cdn-b9.example.com', 'cdn-a.b.example.com'),
             ('cdn-z.example.com', 'cdn-.example.com')),
            ('cdn-[a][b].example.com', ('cdn-ab.example.com',), ('cdn-a.example.com', 'cdn-ba.example.com')),
        )
        for pattern, covered, kept in cases:
            white = parse_whitelist('DOMAIN-WILDCARD,' + pattern)
            for kind in ('DOMAIN', 'DOMAIN-WILDCARD'):
                with self.subTest(pattern=pattern, kind=kind):
                    hosts = [Rule(kind, host) for host in (*covered, *kept, 'x.' + covered[0], covered[0] + '.other')]
                    self.assertEqual(exclude_covered(iter(hosts), iter(white)), hosts[len(covered):])
            wider = [Rule('DOMAIN-SUFFIX', covered[0]), Rule('DOMAIN-WILDCARD', 'cdn-*.example.com')]
            self.assertEqual(exclude_covered(wider, white), wider)

    def test_class_coverage_keeps_source_identity_native_literals_and_unicode_boundaries(self):
        pattern = 'cdn-[ab].example.com'
        surge = parse_whitelist('DOMAIN-WILDCARD,' + pattern)
        qx = parse_whitelist('HOST-WILDCARD,' + pattern + ',DIRECT')
        native = parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,' + pattern))
        for white, source in ((surge, 'surge'), (qx, 'qx'), (native, 'mihomo')):
            wildcard = Rule('DOMAIN-WILDCARD', pattern, domain_source=source)
            exact = Rule('DOMAIN', 'cdn-a.example.com', domain_source=source)
            foreign = [Rule('DOMAIN', 'cdn-a.example.com', domain_source=other)
                       for other in ('surge', 'qx', 'mihomo') if other != source]
            with self.subTest(source=source):
                self.assertEqual(exclude_covered([exact, wildcard, *foreign], white),
                                 foreign if source == 'surge' else [exact, *foreign])
                self.assertEqual(white[0].domain_source, source)
        literal = Rule('DOMAIN-WILDCARD', pattern, domain_source='mihomo')
        self.assertEqual(exclude_covered([literal], surge), [literal])
        self.assertEqual(exclude_covered([Rule('DOMAIN', pattern, domain_source='mihomo')], native), [])
        for character in ('é', '中', '😀', 'ſ', 'ı'):
            for source in ('surge', 'qx', 'mihomo'):
                blocker = Rule('DOMAIN', 'cdn-' + character + '.example.com', domain_source=source)
                self.assertEqual(exclude_covered([blocker], surge), [blocker])
        byte_white = parse_whitelist(audit_rules.native_text('DOMAIN-WILDCARD,cdn-??.example.com'))
        native_host = Rule('DOMAIN', 'cdn-é.example.com', domain_source='mihomo')
        self.assertEqual(exclude_covered([native_host], byte_white), [])
        self.assertEqual(exclude_covered([native_host], parse_whitelist('DOMAIN-WILDCARD,cdn-??.example.com')),
                         [native_host])

    def test_quotes_ascii_case_single_root_dot_flags_and_allow_preserve_input_order(self):
        for quote in ('', "'", '"'):
            white = parse_whitelist('DOMAIN-WILDCARD,' + quote + 'CDN-[AB].EXAMPLE.COM.' + quote + ',DIRECT')
            self.assertEqual(white, [Rule('DOMAIN-WILDCARD', 'cdn-[ab].example.com')])
            for purpose in ('block', 'direct', 'proxy'):
                with self.subTest(quote=quote, purpose=purpose):
                    parsed, messages = parse('DOMAIN,' + quote + 'CDN-A.EXAMPLE.COM.' + quote +
                                             '\nDOMAIN,cdn-z.example.com\n@@||cdn-a.example.com^', purpose=purpose)
                    self.assertEqual(messages, [])
                    self.assertEqual(exclude_covered(iter(parsed), iter(white)), parsed[1:])
                    self.assertEqual(parsed[0].value, 'cdn-a.example.com')
            original = [Rule('DOMAIN', host, options, allow, literal, fields, source)
                        for source in ('surge', 'qx', 'mihomo')
                        for host in ('cdn-a.example.com', 'cdn-z.example.com')
                        for options in ((), ('via-interface=en1',)) for allow in (False, True)
                        for literal in (False, True) for fields in (False, True)]
            expected = [rule for rule in original if rule.allow or rule.domain_source != 'surge'
                        or rule.value == 'cdn-z.example.com']
            self.assertEqual(exclude_covered(iter(original), iter(white)), expected)
            self.assertEqual(set(normalize(original * 2)), set(original))
        native_root = Rule('DOMAIN', 'CDN-A.EXAMPLE.COM.', domain_source='mihomo')
        self.assertEqual(exclude_covered([native_root], white), [native_root])
        self.assertEqual(native_root.value, 'CDN-A.EXAMPLE.COM.')
        processes = [Rule(kind, 'cdn-[ab].example.com', literal_process=literal, native_fields=fields)
                     for kind in ('PROCESS-NAME', 'PROCESS-NAME-WILDCARD', 'PROCESS-PATH-WILDCARD')
                     for literal in (False, True) for fields in (False, True)]
        self.assertEqual(exclude_covered(processes, white), processes)

    def test_unsupported_negation_escape_unicode_and_incomplete_classes_still_warn(self):
        patterns = ('cdn-[!ab].example.com', 'cdn-[^ab].example.com', r'cdn-\[ab\].example.com',
                    'cdn-[é].example.com', 'cdn-[中].example.com', 'cdn-[].example.com',
                    'cdn-[ab.example.com', 'cdn-ab].example.com', 'cdn-[[ab]].example.com')
        for purpose in ('block', 'direct', 'proxy'):
            for pattern in patterns:
                with self.subTest(purpose=purpose, pattern=pattern):
                    source = 'DOMAIN-WILDCARD,' + pattern
                    parsed, messages = parse(source + '\nDOMAIN,neighbor.example.org', purpose=purpose)
                    self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                    self.assertEqual(messages, ['line 1: invalid domain ' + pattern])
                    with self.assertRaisesRegex(ValueError, 'line 1: invalid domain'):
                        parse_whitelist(source)
                    self.assertEqual(parse('NOT,((DOMAIN-WILDCARD,' + pattern + '))', purpose=purpose)[0], [])
                    native, warnings = parse(audit_rules.native_text(source), purpose=purpose)
                    self.assertEqual(warnings, [])
                    self.assertEqual(native, [Rule('DOMAIN-WILDCARD', pattern, domain_source='mihomo')])

    def test_logical_children_are_not_removed_or_reordered_by_external_class_white(self):
        white = parse_whitelist('DOMAIN-WILDCARD,"CDN-[AB].EXAMPLE.COM.",DIRECT')
        for operator, value in (
                ('AND', '((DOMAIN,"cdn-a.example.com"),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'),
                ('OR', '((DOMAIN-WILDCARD,"cdn-[ab].example.com"),(DOMAIN,neighbor.example.org))'),
                ('NOT', '((DOMAIN,"cdn-a.example.com"))'),
                ('AND', '((NOT,((DOMAIN,"cdn-a.example.com"))),(OR,((DOMAIN,neighbor.example.org),(NETWORK,tcp))))')):
            for purpose in ('block', 'direct', 'proxy'):
                parsed, messages = parse(operator + ',' + value, purpose=purpose)
                self.assertEqual(messages, [])
                self.assertEqual(parsed, [Rule(operator, value)])
                self.assertEqual(exclude_covered(iter(parsed), iter(white)), parsed)
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(operator=operator, purpose=purpose, mode=mode):
                        outputs, _ = render('logical', parsed, purpose=purpose, no_resolve=mode, whitelist=white)
                        expected = value.replace('"', '')
                        if mode == 'strip':
                            expected = expected.replace(',no-resolve)', ')')
                        if operator == 'OR':
                            expected = expected.replace('DOMAIN-WILDCARD,cdn-[ab].example.com',
                                                        r'DOMAIN-REGEX,^cdn\-[ab]\.example\.com\.?$')
                        self.assertEqual(outputs['fin.yaml'], '# logical rules: 1\npayload:\n  - ' +
                                         json.dumps(operator + ',' + expected) + '\n')
                        repeated, warnings = parse(outputs['fin.yaml'], purpose=purpose)
                        self.assertEqual(warnings, [])
                        self.assertEqual(len(repeated), 1)
                        self.assertEqual(repeated[0].value, expected)
                        self.assertIn(operator + ',', outputs['fin.txt'])
                        self.assertNotIn('SRC-IP-CIDR,198.51.100.0/24,no-resolve', outputs['fin.yaml'])

    def test_generate_class_white_keeps_actual_surge_and_mihomo_dependency_bytes(self):
        source = ('DOMAIN,cdn-a.example.com\nDOMAIN,cdn-b.example.com\nDOMAIN,cdn-z.example.com\n'
                  'DOMAIN,neighbor.example.org\nDOMAIN-WILDCARD,cdn-[ab].example.com\n'
                  'IP-CIDR,192.0.2.0/24,no-resolve\nSRC-IP-CIDR,198.51.100.0/24\n@@||allow.example.org^\n')
        white = 'DOMAIN-WILDCARD,"CDN-[AB].EXAMPLE.COM."\n'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/source.list').write_text(source, encoding='utf-8')
                        (root / 'static/white.list').write_text(white, encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                        white_input = 'https://example.com/white' if remote else 'static/white.list'
                        configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': [white_input], 'whitelist': []},
                                   {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['https://example.com/source' if remote else 'static/source.list'],
                                    'whitelist': [white_input, 'white/fin.txt']},
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
                        self.assertEqual(set(outputs), set(old))
                        self.assertNotIn('invalid ', diagnostics.getvalue())
                        self.assertNotIn('frozen', diagnostics.getvalue())
                        self.assertEqual(outputs[root / 'white/fin.txt'],
                                         '# white rules: 1\nDOMAIN-WILDCARD,cdn-[ab].example.com\n')
                        self.assertEqual(parse_whitelist(outputs[root / 'white/fin.txt']),
                                         [Rule('DOMAIN-WILDCARD', 'cdn-[ab].example.com')])
                        self.assertEqual(outputs[root / 'white/fin.yaml'], '# white rules: 1\npayload:\n  - ' +
                                         json.dumps(r'DOMAIN-REGEX,^cdn\-[ab]\.example\.com\.?$') + '\n')
                        option = '' if mode == 'strip' else ',no-resolve'
                        surge_ip = 'IP-CIDR,192.0.2.0/24' + option
                        source_ip = 'SRC-IP,198.51.100.0/24'
                        for group in ('source', 'child'):
                            bodies = {
                                'fin.txt': ['DOMAIN,cdn-z.example.com', 'DOMAIN,neighbor.example.org', surge_ip, source_ip],
                                'fin-surge.txt': [surge_ip, source_ip],
                                'fin-surge-ds.txt': ['cdn-z.example.com', 'neighbor.example.org'],
                                'fin-qx.txt': ['HOST,cdn-z.example.com,LIST', 'HOST,neighbor.example.org,LIST',
                                               'IP-CIDR,192.0.2.0/24,LIST' + option],
                                'fin.yaml': ['  - "DOMAIN,cdn-z.example.com"', '  - "DOMAIN,neighbor.example.org"',
                                             '  - ' + json.dumps(surge_ip), '  - "SRC-IP-CIDR,198.51.100.0/24"'],
                            }
                            for name, body in bodies.items():
                                self.assertEqual(outputs[root / group / name], f'# {group} rules: {len(body)}\n' +
                                                 ('payload:\n' if name == 'fin.yaml' else '') +
                                                 ''.join(line + '\n' for line in body))
                            dns_body = ([*(['@@||allow.example.org^'] if group == 'source' else []),
                                         r'@@/^cdn\-[ab]\.example\.com$/',
                                         '0.0.0.0 cdn-z.example.com', '0.0.0.0 neighbor.example.org'] if purpose == 'block' else [])
                            dns = outputs[root / group / 'fin-adb.txt'].splitlines()
                            self.assertEqual(dns[6], f'! Total count: {len(dns_body)}')
                            self.assertEqual(dns[7:], dns_body if purpose == 'block' else
                                             ['! No AdBlock rules for non-advertising group.'])
                            self.assertNotIn('cdn-a.example.com', outputs[root / group / 'fin.yaml'])
                            self.assertNotIn('cdn-b.example.com', outputs[root / group / 'fin.yaml'])
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        self.assertTrue(all(data.endswith(b'\n') and b'\r' not in data for data in published.values()))
                        (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                        (root / 'static/source.list').unlink()
                        (root / 'static/white.list').unlink()
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 13, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_class_all_covered_empty_generation_freeze_strict_white_path_and_rollback(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    (root / 'static/input.list').write_text('DOMAIN,cdn-a.example.com\nDOMAIN,cdn-b.example.com\n', encoding='utf-8')
                    (root / 'static/white.list').write_text('DOMAIN-WILDCARD,cdn-[ab].example.com\n', encoding='utf-8')
                    config = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['static/input.list'], 'whitelist': ['static/white.list']},
                              {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['source/fin.yaml'], 'whitelist': ['static/white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(len(outputs), 12)
                    for group in ('source', 'child'):
                        for name in FILES:
                            text = outputs[root / group / name]
                            if name == 'fin-adb.txt':
                                self.assertEqual(text.splitlines()[6:],
                                                 ['! Total count: 1', r'@@/^cdn\-[ab]\.example\.com$/'] if purpose == 'block' else
                                                 ['! Total count: 0', '! No AdBlock rules for non-advertising group.'])
                            else:
                                self.assertEqual(text, f'# {group} rules: 0\n' + ('payload:\n' if name == 'fin.yaml' else ''))
                    publish(outputs, root=root)
                    published = {path: path.read_bytes() for path in outputs}
                    config[0]['sources'] = ['https://example.com/missing']
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')

                    def unavailable(url):
                        raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                    with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                        self.assertEqual(generate(root, unavailable), {})
                    self.assertIn('HTTP 404; skipped', diagnostics.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    config[0]['sources'] = ['static/input.list']
                    (root / 'static/white.list').write_text('DOMAIN-WILDCARD,cdn-[!ab].example.com\n', encoding='utf-8')
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                        publish({root / 'static/forbidden.txt': 'x'}, root=root)
                    config[0]['sources'] = ['../outside.list']
                    (root / 'static/white.list').write_text('DOMAIN-WILDCARD,cdn-[ab].example.com\n', encoding='utf-8')
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, 'Source escapes root'):
                        generate(root, lambda url: self.fail(url))
                    (root / 'not-a-directory').write_bytes(b'unchanged')
                    with self.assertRaises(OSError):
                        publish({root / 'source/fin.txt': 'replacement\n', root / 'not-a-directory/new.txt': 'x'}, root=root)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    self.assertEqual((root / 'not-a-directory').read_bytes(), b'unchanged')

    def test_long_classes_and_deep_logical_preserve_original_limits_under_eight_seconds(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, exclude_covered, parse, parse_whitelist
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
pattern = 'cdn-[' + 'a' * 5000 + 'b].example.com'
white = parse_whitelist('DOMAIN-WILDCARD,' + pattern)
assert white == [Rule('DOMAIN-WILDCARD', pattern)]
assert exclude_covered([Rule('DOMAIN', 'cdn-b.example.com')], white) == []
assert exclude_covered([Rule('DOMAIN', 'cdn-z.example.com')], white) == [Rule('DOMAIN', 'cdn-z.example.com')]
for depth in (600, 1000):
    matcher = 'DOMAIN-WILDCARD,cdn-[ab].example.com'
    for _ in range(depth):
        matcher = 'NOT,((' + matcher + '))'
    parsed, warnings = parse(matcher, purpose='proxy')
    assert not warnings and parsed == [Rule('NOT', matcher[4:])]
    assert exclude_covered(iter(parsed), iter(white)) == parsed
    outputs, skips = render('deep', parsed, purpose='proxy', no_resolve='keep')
    expected = matcher.replace('DOMAIN-WILDCARD,cdn-[ab].example.com', r'DOMAIN-REGEX,^cdn\\-[ab]\\.example\\.com\\.?$')
    assert outputs['fin.yaml'] == '# deep rules: 1\\npayload:\\n  - ' + json.dumps(expected) + '\\n'
    assert parse(outputs['fin.yaml'], purpose='proxy')[1] == []
    assert skips['fin.txt:NOT'] == 1 and skips['fin-surge.txt:NOT'] == 1
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)


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
