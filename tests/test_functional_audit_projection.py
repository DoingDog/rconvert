import contextlib
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


class SurgeRootDotProjectionTests(unittest.TestCase):
    def test_native_keyword_terminal_root_dot_skips_only_surge(self):
        parsed, messages = parse('payload:\n  - "DOMAIN-KEYWORD,123."', purpose='block')
        self.assertEqual((parsed, messages), ([Rule('DOMAIN-KEYWORD', '123.', domain_source='mihomo')], []))
        self.assertEqual(normalize(parsed), parsed)
        out, skipped = render('root', parsed, purpose='block', no_resolve='keep')
        for name in ('fin.txt', 'fin-surge.txt'):
            self.assertEqual(out[name], '# root rules: 0\n')
            self.assertEqual(skipped[name + ':DOMAIN-KEYWORD'], 1)
        self.assertEqual(out['fin.yaml'], '# root rules: 1\npayload:\n  - "DOMAIN-KEYWORD,123."\n')
        self.assertEqual(out['fin-qx.txt'], '# root rules: 1\nHOST-KEYWORD,123.,LIST\n')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [r'/(?s-i:\A.*123\..*\z)/'])
        self.assertEqual(skipped, {name + ':DOMAIN-KEYWORD': 1 for name in
                                  ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt')})

    def test_native_wildcard_root_dot_counterexamples_skip_only_surge(self):
        for value in ('*.*', '*.123', '*.123.*', '*.??*'):
            with self.subTest(value=value):
                matcher = 'DOMAIN-WILDCARD,' + value
                parsed, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose='block')
                self.assertEqual((parsed, messages), ([Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')], []))
                self.assertEqual(exclude_covered(normalize(parsed), []), parsed)
                out, skipped = render('root', parsed, purpose='block', no_resolve='keep')
                for name in ('fin.txt', 'fin-surge.txt'):
                    self.assertEqual(out[name], '# root rules: 0\n')
                    self.assertEqual(skipped[name + ':DOMAIN-WILDCARD'], 1)
                self.assertEqual(out['fin.yaml'], '# root rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n')
                self.assertEqual(out['fin-qx.txt'], '# root rules: 1\nHOST-WILDCARD,' + value + ',LIST\n')
                self.assertEqual(len(out['fin-adb.txt'].splitlines()[7:]), 1)
                self.assertEqual(skipped, {name + ':DOMAIN-WILDCARD': 1 for name in
                                          ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt')})

    def test_native_questions_require_independent_byte_character_equivalence(self):
        cases = (('*??123*', 'é123.example.', True, False), ('?123*', 'é123.example.', False, True),
                 ('*123?4*', 'cdn.123é4.example.', False, True), ('*?*?123*', 'é123.example.', True, False))
        for value, host, native, surge in cases:
            with self.subTest(value=value):
                self.assertEqual(fnmatchcase(host.encode('utf-8'), value.encode('utf-8')), native)
                self.assertEqual(fnmatchcase(host.removesuffix('.'), value), surge)
                rule = Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')
                out, skipped = render('root', [rule], purpose='proxy', no_resolve='keep')
                for name in ('fin.txt', 'fin-surge.txt'):
                    self.assertEqual(out[name], '# root rules: 0\n')
                    self.assertEqual(skipped[name + ':DOMAIN-WILDCARD'], 1)
                self.assertEqual(parse(out['fin.yaml'], purpose='proxy'), ([rule], []))
                self.assertEqual(out['fin-qx.txt'], '# root rules: 1\nHOST-WILDCARD,' + value + ',LIST\n')

    def test_root_invariant_native_literals_and_star_question_runs_remain_supported(self):
        hosts = ('123.example', '123.example.', 'cdn.123.', 'x.123.example.',
                 'é123.example.', '中123.example.', '😀123.example.', 'é中123.example.',
                 'x.é123.example.', 'localhost.', '1.2.', 'x1234.example.', 'a.b.')
        matchers = ('DOMAIN-KEYWORD,123', 'DOMAIN-WILDCARD,*', 'DOMAIN-WILDCARD,*.*123*',
                    'DOMAIN-WILDCARD,*?123*', 'DOMAIN-WILDCARD,?*123*',
                    'DOMAIN-WILDCARD,*?*123*', 'DOMAIN-WILDCARD,**123**')
        for matcher in matchers:
            kind, _, value = matcher.partition(',')
            for host in hosts:
                native = (value.encode() in host.encode() if kind == 'DOMAIN-KEYWORD' else
                          fnmatchcase(host.encode(), value.encode()))
                surge = (value in host.removesuffix('.') if kind == 'DOMAIN-KEYWORD' else
                         fnmatchcase(host.removesuffix('.'), value))
                self.assertEqual(native, surge, (matcher, host))
            parsed, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose='proxy')
            self.assertEqual((parsed, messages), ([Rule(kind, value, domain_source='mihomo')], []))
            out, skipped = render('root', normalize(parsed), purpose='proxy', no_resolve='keep')
            for name in ('fin.txt', 'fin-surge.txt'):
                self.assertEqual(out[name], '# root rules: 1\n' + matcher + '\n')
                self.assertNotIn(name + ':' + kind, skipped)
            self.assertEqual(parse(out['fin.yaml'], purpose='proxy'), (parsed, []))

    def assert_counts_and_split(self, out, purpose, group='root'):
        self.assertEqual(set(out), set(FILES))
        for name, text in out.items():
            lines = text.splitlines()
            header = 7 if name == 'fin-adb.txt' else 2 if name == 'fin.yaml' else 1
            body = lines[header:]
            if name == 'fin-adb.txt' and purpose != 'block':
                self.assertEqual(body, ['! No AdBlock rules for non-advertising group.'])
                body = []
            self.assertEqual(lines[6] if name == 'fin-adb.txt' else lines[0],
                             f'! Total count: {len(body)}' if name == 'fin-adb.txt' else f'# {group} rules: {len(body)}')
            self.assertEqual(len(body), len(set(body)))
            self.assertTrue(text.endswith('\n'))
            self.assertNotIn('\r', text)
            if name == 'fin-adb.txt':
                self.assertTrue(all(len(line.encode('utf-8')) + 1 <= 65536 for line in lines))
        full = set(out['fin.txt'].splitlines()[1:])
        split = set(out['fin-surge.txt'].splitlines()[1:])
        domainset = {('DOMAIN-SUFFIX,' + line[1:] if line.startswith('.') else 'DOMAIN,' + line)
                     for line in out['fin-surge-ds.txt'].splitlines()[1:]}
        self.assertEqual(full, split | domainset)
        self.assertFalse(split & domainset)

    def test_five_fixed_host_counterexamples_use_native_bytes_and_single_root_dot(self):
        cases = (('DOMAIN-KEYWORD,123.', 'cdn.123.', True, False),
                 ('DOMAIN-WILDCARD,*.*', 'localhost.', True, False),
                 ('DOMAIN-WILDCARD,*.123', 'cdn.123.', False, True),
                 ('DOMAIN-WILDCARD,*.123.*', 'cdn.123.', True, False),
                 ('DOMAIN-WILDCARD,*.??*', 'a.b.', True, False))
        for matcher, host, native_expected, surge_expected in cases:
            kind, _, value = matcher.partition(',')
            native = (value.encode() in host.encode() if kind == 'DOMAIN-KEYWORD' else fnmatchcase(host.encode(), value.encode()))
            surge = (value in host.removesuffix('.') if kind == 'DOMAIN-KEYWORD' else fnmatchcase(host.removesuffix('.'), value))
            self.assertEqual((native, surge), (native_expected, surge_expected), matcher)
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(matcher=matcher, purpose=purpose, mode=mode):
                        rule = Rule(kind, value, domain_source='mihomo')
                        neighbor = Rule('DOMAIN', 'keep.example.org', domain_source='mihomo')
                        out, skipped = render('root', iter(normalize([rule, neighbor, rule])), purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin.txt'], '# root rules: 1\nDOMAIN,keep.example.org\n')
                        self.assertEqual(out['fin-surge.txt'], '# root rules: 0\n')
                        self.assertEqual(parse(out['fin.yaml'], purpose=purpose), ([neighbor, rule], []))
                        self.assertEqual(skipped['fin.txt:' + kind], 1)
                        self.assertEqual(skipped['fin-surge.txt:' + kind], 1)
                        self.assertNotIn('fin.yaml:' + kind, skipped)
                        self.assertNotIn('fin-qx.txt:' + kind, skipped)
                        self.assert_counts_and_split(out, purpose)

    def test_unsupported_native_leaf_skips_whole_logical_rule_once_with_child_order_intact(self):
        leaves = ('DOMAIN-KEYWORD,123.', 'DOMAIN-WILDCARD,*.*', 'DOMAIN-WILDCARD,*.123',
                  'DOMAIN-WILDCARD,*.123.*', 'DOMAIN-WILDCARD,*.??*')
        for leaf in leaves:
            matchers = ('AND,((' + leaf + '),(DOMAIN-KEYWORD,456),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))',
                        'OR,((DOMAIN-KEYWORD,456),(' + leaf + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))',
                        'NOT,((' + leaf + '))',
                        'AND,((OR,((DOMAIN-KEYWORD,456),(' + leaf + '))),(NOT,((DOMAIN-WILDCARD,*?789*))),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))',
                        'OR,((' + leaf + '),(NOT,((' + leaf + '))))')
            for matcher in matchers:
                operator, _, value = matcher.partition(',')
                for purpose in ('block', 'direct', 'proxy'):
                    parsed, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose=purpose)
                    self.assertEqual((parsed, messages), ([Rule(operator, value, native_fields=True, domain_source='mihomo')], []))
                    self.assertEqual(normalize(exclude_covered(parsed, [])), parsed)
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(leaf=leaf, matcher=matcher, purpose=purpose, mode=mode):
                            out, skipped = render('root', parsed, purpose=purpose, no_resolve=mode)
                            expected = matcher.replace(',no-resolve)', ')') if mode == 'strip' else matcher
                            self.assertEqual(out['fin.yaml'], '# root rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                            self.assertEqual(skipped, {name + ':' + operator: 1 for name in FILES if name != 'fin.yaml'})
                            self.assertEqual(out['fin.txt'], '# root rules: 0\n')
                            self.assertEqual(out['fin-surge.txt'], '# root rules: 0\n')
                            self.assertEqual(parse(out['fin.yaml'], purpose=purpose),
                                             ([Rule(operator, expected.partition(',')[2], native_fields=True, domain_source='mihomo')], []))
                            self.assert_counts_and_split(out, purpose)

    def test_supported_native_logical_rules_keep_order_and_change_only_destination_ip_option(self):
        pairs = (
            ('AND,((DOMAIN-WILDCARD,*?123*),(DOMAIN-KEYWORD,456),(IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))',
             'AND,((DOMAIN-WILDCARD,*?123*),(DOMAIN-KEYWORD,456),(IP-CIDR,192.0.2.0/24),(SRC-IP,198.51.100.0/24))'),
            ('OR,((DOMAIN-KEYWORD,123),(DOMAIN-WILDCARD,*.*123*))',
             'OR,((DOMAIN-KEYWORD,123),(DOMAIN-WILDCARD,*.*123*))'),
            ('NOT,((DOMAIN-WILDCARD,*))', 'NOT,((DOMAIN-WILDCARD,*))'),
            ('AND,((NOT,((DOMAIN-WILDCARD,*?123*))),(OR,((DOMAIN-KEYWORD,456),(DOMAIN-WILDCARD,*))))',
             'AND,((NOT,((DOMAIN-WILDCARD,*?123*))),(OR,((DOMAIN-KEYWORD,456),(DOMAIN-WILDCARD,*))))'),
        )
        for matcher, surge in pairs:
            for purpose in ('block', 'direct', 'proxy'):
                parsed, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose=purpose)
                self.assertEqual(messages, [])
                self.assertEqual(parsed[0].value, matcher.partition(',')[2])
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(matcher=matcher, purpose=purpose, mode=mode):
                        native_expected = matcher.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)') if mode == 'add' else matcher
                        surge_expected = surge.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)') if mode == 'add' else surge
                        out, skipped = render('root', normalize(parsed), purpose=purpose, no_resolve=mode)
                        for name in ('fin.txt', 'fin-surge.txt'):
                            self.assertEqual(out[name], '# root rules: 1\n' + surge_expected + '\n')
                            self.assertNotIn(name + ':' + parsed[0].kind, skipped)
                        self.assertEqual(out['fin.yaml'], '# root rules: 1\npayload:\n  - ' + json.dumps(native_expected) + '\n')
                        self.assert_counts_and_split(out, purpose)

    def test_ordinary_surge_and_qx_same_text_do_not_gain_native_projection_skips(self):
        matchers = ('DOMAIN-KEYWORD,123.', 'DOMAIN-WILDCARD,*.*', 'DOMAIN-WILDCARD,*.123',
                    'DOMAIN-WILDCARD,*.123.*', 'DOMAIN-WILDCARD,*.??*', 'DOMAIN-WILDCARD,*??123*')
        for matcher in matchers:
            for source in ('surge', 'qx'):
                text = matcher if source == 'surge' else matcher.replace('DOMAIN-', 'HOST-', 1) + ',REJECT'
                parsed, messages = parse(text, purpose='block')
                kind, _, value = matcher.partition(',')
                if value == '*??123*':
                    self.assertEqual((parsed, messages), ([], ['line 1: invalid domain *??123*']))
                    continue
                self.assertEqual((parsed, messages), ([Rule(kind, value, domain_source=source)], []))
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(matcher=matcher, source=source, purpose=purpose, mode=mode):
                            out, skipped = render('root', normalize(parsed), purpose=purpose, no_resolve=mode)
                            for name in ('fin.txt', 'fin-surge.txt'):
                                self.assertEqual(out[name], '# root rules: 1\n' + matcher + '\n')
                                self.assertNotIn(name + ':' + kind, skipped)
                            self.assert_counts_and_split(out, purpose)

    def test_existing_native_case_bracket_and_unicode_boundaries_keep_source_identity(self):
        for kind, value, supported in (('DOMAIN-KEYWORD', 'ads', False), ('DOMAIN-WILDCARD', '*[12]*', False),
                                       ('DOMAIN-KEYWORD', '广告', True), ('DOMAIN-WILDCARD', '*广告*', True)):
            rule = Rule(kind, value, literal_process=True, native_fields=True, domain_source='mihomo')
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(kind=kind, value=value, mode=mode):
                    out, skipped = render('root', [rule], purpose='proxy', no_resolve=mode)
                    matcher = kind + ',' + value
                    for name in ('fin.txt', 'fin-surge.txt'):
                        self.assertEqual(out[name], '# root rules: ' + ('1\n' + matcher + '\n' if supported else '0\n'))
                        self.assertEqual(skipped.get(name + ':' + kind, 0), int(not supported))
                    self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), matcher)
                    self.assertEqual(rule, Rule(kind, value, literal_process=True, native_fields=True, domain_source='mihomo'))

    def test_generate_publish_empty_surge_valid_mihomo_same_round_and_disk_nine_modes(self):
        leaves = ('DOMAIN-KEYWORD,123.', 'DOMAIN-WILDCARD,*.*', 'DOMAIN-WILDCARD,*.123',
                  'DOMAIN-WILDCARD,*.123.*', 'DOMAIN-WILDCARD,*.??*')
        for leaf in leaves:
            matchers = (leaf, 'AND,((' + leaf + '),(IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))',
                        'OR,((IP-CIDR,192.0.2.0/24),(' + leaf + '))', 'NOT,((' + leaf + '))',
                        'AND,((OR,((DOMAIN-KEYWORD,456),(' + leaf + '))),(NOT,((DOMAIN-WILDCARD,*?789*))))')
            for matcher in matchers:
                operator = matcher.partition(',')[0]
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(matcher=matcher, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'static').mkdir()
                            source = root / 'static/source.yaml'
                            source.write_text('payload:\n  - ' + json.dumps(matcher), encoding='utf-8')
                            before = source.read_bytes()
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['static/source.yaml'], 'whitelist': []},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old artifact\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                                out = generate(root, lambda url: self.fail(url))
                            self.assertEqual(list(out), [root / group / name for group in ('source', 'child') for name in FILES])
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            expected = matcher.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)') if mode == 'add' else matcher
                            for group in ('source', 'child'):
                                products = {name: out[root / group / name] for name in FILES}
                                self.assertEqual(products['fin.yaml'], f'# {group} rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                                self.assertEqual(products['fin.txt'], f'# {group} rules: 0\n')
                                self.assertEqual(products['fin-surge.txt'], f'# {group} rules: 0\n')
                                self.assertIn(group + ' fin.txt:' + operator + ': 1\n', diagnostic.getvalue())
                                self.assertIn(group + ' fin-surge.txt:' + operator + ': 1\n', diagnostic.getvalue())
                                self.assert_counts_and_split(products, purpose, group)
                                readback, warnings = parse(products['fin.yaml'], purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual(readback[0].value, expected.partition(',')[2])
                                self.assertEqual(readback[0].domain_source, 'mihomo')
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(out, root=root)
                            self.assertEqual({path: path.read_bytes() for path in out},
                                             {path: text.encode('utf-8') for path, text in out.items()})
                            self.assertEqual(source.read_bytes(), before)
                            source.unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in out.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in disk},
                                             {path: text.encode('utf-8') for path, text in disk.items()})

    def test_mixed_local_remote_generation_keeps_neighbors_native_identity_and_partial_source_behavior(self):
        matchers = ('DOMAIN-KEYWORD,123.', 'DOMAIN-WILDCARD,*.*', 'DOMAIN-KEYWORD,123',
                    'DOMAIN-WILDCARD,*?123*', 'DOMAIN-WILDCARD,*[12]*', 'DOMAIN,neighbor.example.org.',
                    'IP-ASN,0', 'IP-ASN,00', 'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24',
                    'PROCESS-NAME,Foo*Bar')
        source_text = 'payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)
        white_text = 'payload:\n  - "DOMAIN-KEYWORD,999."\n'
        for remote in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(remote=remote, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/source.yaml').write_bytes(source_text.encode())
                        (root / 'static/white.yaml').write_bytes(white_text.encode())
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['https://example.org/white' if remote else 'static/white.yaml'], 'whitelist': []},
                                   {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['https://example.org/source' if remote else 'static/source.yaml', 'https://example.org/missing'],
                                    'whitelist': ['white/fin.yaml']},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        responses = {'https://example.org/source': source_text.encode(), 'https://example.org/white': white_text.encode()}

                        def fetch(url):
                            if url == 'https://example.org/missing':
                                raise RuntimeError('missing') from HTTPError(url, 404, 'missing', {}, None)
                            return responses[url]

                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                            out = generate(root, fetch)
                        self.assertEqual(len(out), 18)
                        self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                        self.assertNotIn('frozen', diagnostic.getvalue())
                        parsed, warnings = parse(source_text, purpose=purpose)
                        self.assertEqual(warnings, [])
                        self.assertEqual({rule.kind + ',' + rule.value + (',' + ','.join(rule.options) if rule.options else '')
                                          for rule in parsed}, set(matchers))
                        expected = set(matchers) - {'DOMAIN-KEYWORD,123.'}
                        self.assertNotIn('123.', [rule.value for rule in normalize(parsed) if rule.kind == 'DOMAIN-KEYWORD'])
                        if mode == 'strip':
                            expected.remove('IP-CIDR,192.0.2.0/24,no-resolve')
                            expected.add('IP-CIDR,192.0.2.0/24')
                        elif mode == 'add':
                            expected.difference_update(('IP-ASN,0', 'IP-ASN,00'))
                            expected.update(('IP-ASN,0,no-resolve', 'IP-ASN,00,no-resolve'))
                        for group in ('source', 'child'):
                            products = {name: out[root / group / name] for name in FILES}
                            self.assertEqual(set(json.loads(line[4:]) for line in products['fin.yaml'].splitlines()[2:]), expected)
                            self.assertEqual(parse_whitelist(out[root / 'white/fin.yaml']),
                                             [Rule('DOMAIN-KEYWORD', '999.', domain_source='mihomo')])
                            for name in ('fin.txt', 'fin-surge.txt'):
                                self.assertNotIn('DOMAIN-KEYWORD,123.\n', products[name])
                                self.assertNotIn('DOMAIN-WILDCARD,*.*\n', products[name])
                                self.assertIn('DOMAIN-KEYWORD,123\n', products[name])
                                self.assertIn('DOMAIN-WILDCARD,*?123*\n', products[name])
                                self.assertIn('SRC-IP,198.51.100.0/24\n', products[name])
                            self.assert_counts_and_split(products, purpose, group)
                            if purpose == 'block':
                                self.assertIn(r'@@/(?s-i:\A.*999\..*\z)/' + '\n', products['fin-adb.txt'])
                        publish(out, root=root)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        self.assertEqual({path: path.read_bytes() for path in out},
                                         {path: text.encode('utf-8') for path, text in out.items()})
                        (root / 'rulesets.json').write_text(json.dumps(configs[-1:]), encoding='utf-8')
                        for path in inputs:
                            path.unlink()
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in out.items() if path.parent.name == 'child'})
                        publish(disk, root=root)

    def test_strict_whitelist_and_unavailable_source_still_preserve_old_products(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    (root / 'static/source.yaml').write_text('payload:\n  - "DOMAIN-WILDCARD,*.*"', encoding='utf-8')
                    white = root / 'static/white.list'
                    white.write_text('DOMAIN,bad..example', encoding='utf-8')
                    config = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['static/source.yaml'], 'whitelist': ['static/white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'source').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'source' / name
                        path.write_bytes(b'old\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    config[0]['sources'] = ['https://example.org/missing']
                    config[0]['whitelist'] = []
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')

                    def unavailable(url):
                        raise RuntimeError('missing') from HTTPError(url, 404, 'missing', {}, None)

                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, unavailable), {})
                    self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                        publish({white: 'DOMAIN,keep.example.org\n'}, root=root)
                    self.assertEqual(white.read_text(encoding='utf-8'), 'DOMAIN,bad..example')
