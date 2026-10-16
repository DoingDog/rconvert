import contextlib
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import io
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests.test_formats import expected_domain


class NativeExactSuffixKeywordProjectionTests(unittest.TestCase):
    def test_native_exact_suffix_with_keyword_keeps_whole_logical_scope(self):
        for leaf in ('DOMAIN,a.test', 'DOMAIN,a.test.', 'DOMAIN,123.test',
                     'DOMAIN,_a.test', 'DOMAIN-SUFFIX,a.test', 'DOMAIN-SUFFIX,a.test.'):
            for matcher in (leaf, 'AND,((' + leaf + '),(DOMAIN-KEYWORD,123))',
                            'OR,((DOMAIN-KEYWORD,123),(' + leaf + '))',
                            'NOT,((' + leaf + '))',
                            'AND,((NOT,((' + leaf + '))),(OR,((DOMAIN-KEYWORD,123),(DOMAIN-KEYWORD,456))))'):
                parsed, warnings = parse('payload:\n  - ' + json.dumps(matcher), purpose='proxy')
                self.assertEqual(warnings, [])
                out, skipped = render('literal', normalize(exclude_covered(parsed, [])),
                                      purpose='proxy', no_resolve='keep')
                for name in ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                    self.assertEqual(out[name], '# literal rules: 0\n')
                self.assertEqual(out['fin.yaml'], '# literal rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n')
                self.assertNotIn('whitelist-covered:' + parsed[0].kind, skipped)


class ExactSuffixRoutingProjectionTests(unittest.TestCase):
    def test_native_exact_suffix_skip_checked_surge_full_domainset_and_whole_logical(self):
        for leaf in ('DOMAIN,A.test', 'DOMAIN,a.test.', 'DOMAIN,123.test',
                     'DOMAIN,ad_core.test', 'DOMAIN-SUFFIX,A.test', 'DOMAIN-SUFFIX,a.test.'):
            matchers = (leaf, 'AND,((' + leaf + '),(DST-PORT,443))',
                        'OR,((DST-PORT,443),(' + leaf + '))', 'NOT,((' + leaf + '))',
                        'AND,((OR,((DST-PORT,443),(' + leaf + '))),(NOT,((NETWORK,udp))))')
            for matcher in matchers:
                for purpose in ('block', 'direct', 'proxy'):
                    parsed, warnings = parse('payload:\n  - ' + json.dumps(matcher), purpose=purpose)
                    self.assertEqual(warnings, [])
                    self.assertEqual(len(parsed), 1)
                    rule = parsed[0]
                    self.assertEqual(rule.value, matcher.partition(',')[2])
                    self.assertEqual(rule.domain_source, 'mihomo')
                    self.assertEqual(rule.native_fields, rule.kind in {'AND', 'OR', 'NOT'})
                    self.assertEqual(normalize(exclude_covered(parsed, [])), parsed)
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(matcher=matcher, purpose=purpose, mode=mode):
                            out, skipped = render('exact', iter(parsed), purpose=purpose, no_resolve=mode)
                            for name in ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                self.assertEqual(out[name], '# exact rules: 0\n')
                            self.assertEqual(skipped['fin.txt:' + rule.kind], 1)
                            self.assertEqual(skipped['fin-surge-ds.txt:' + rule.kind], 1)
                            self.assertEqual(skipped.get('fin-surge.txt:' + rule.kind, 0),
                                             int(rule.kind not in {'DOMAIN', 'DOMAIN-SUFFIX'}))
                            self.assertEqual(parse(out['fin.yaml'], purpose=purpose), (parsed, []))
                            self.assertNotIn('fin.yaml:' + rule.kind, skipped)
                            self.assertFalse(any('whitelist-covered' in key for key in skipped))
                            SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'exact')


class SurgePairedExactProjectionTests(unittest.TestCase):
    def test_surge_exact_uses_ascii_pairs_and_keeps_qx_native_and_unicode_payloads(self):
        expected = r'DOMAIN-REGEX,(?-i:\A[aA]\.[tT][eE][sS][tT]\.?\z)'
        for text in ('DOMAIN,a.test', 'DOMAIN,"A.TEST."', "DOMAIN,'a.test'"):
            for purpose in ('block', 'direct', 'proxy'):
                parsed, warnings = parse(text, purpose=purpose)
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN', 'a.test')], []))
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(text=text, purpose=purpose, mode=mode):
                        out, skipped = render('paired', parsed, purpose=purpose, no_resolve=mode)
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), expected)
                        self.assertNotIn('fin.yaml:DOMAIN', skipped)
                        self.assertEqual(out['fin.txt'], '# paired rules: 1\nDOMAIN,a.test\n')
                        self.assertEqual(out['fin-surge-ds.txt'], '# paired rules: 1\na.test\n')
                        payload = expected.partition(',')[2]
                        # 只检查明确模板在有限 Host 字面值上的目标语义，不运行 regexp2。
                        target = re.compile(payload.replace(r'\z', r'\Z'))
                        for host, matches in (('a.test', True), ('A.TEST', True), ('a.test.', True),
                                              ('A.test.', True), ('a.test..', False), ('x.a.test', False),
                                              ('é.a.test', False)):
                            self.assertEqual(target.search(host) is not None, matches, host)
        for source in ('qx', 'mihomo', 'unknown'):
            out, _ = render('paired', [Rule('DOMAIN', 'a.test', domain_source=source)],
                            purpose='proxy', no_resolve='keep')
            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,a.test')
        for value in ('K.test', 'İ.test', '例子.test'):
            out, _ = render('paired', [Rule('DOMAIN', value)], purpose='proxy', no_resolve='keep')
            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,' + value)


class SurgePairedSuffixProjectionTests(unittest.TestCase):
    def test_surge_suffix_keeps_legacy_arm_and_adds_bounded_ascii_case_root_profile(self):
        expected = (r'DOMAIN-REGEX,(?-i:(?:\A|\.)a\.test\z|'
                    r'\A(?=[A-Za-z0-9_.-]{1,253}\.?\z)'
                    r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*'
                    r'[aA]\.[tT][eE][sS][tT]\.?\z)')
        rules, warnings = parse('DOMAIN-SUFFIX,"A.TEST."', purpose='proxy')
        self.assertEqual((rules, warnings), ([Rule('DOMAIN-SUFFIX', 'a.test')], []))
        out, _ = render('suffix', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), expected)
        target = re.compile(expected.partition(',')[2].replace(r'\z', r'\Z'))
        for host, matches in (('a.test', True), ('A.TEST', True), ('X.a.test.', True), ('x.A.TEST', True),
                              ('é.a.test', True), ('é.a.test.', False), ('é.A.TEST', False),
                              ('K.a.test', True), ('K.A.TEST', False), ('K.a.test.', False),
                              ('a.test..', False), ('x..a.test', True), ('x..A.TEST', False),
                              ('-x.a.test', True), ('-x.A.TEST', False), ('xa.test', False),
                              ('a.test.evil', False), ('a' * 64 + '.a.test', True),
                              ('a' * 64 + '.A.TEST', False), ('x_.A.TEST.', True),
                              ('a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 54 + '.A.TEST.', True),
                              ('a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 55 + '.A.TEST', False)):
            with self.subTest(host=host):
                self.assertEqual(target.search(host) is not None, matches)
        logical, warnings = parse('AND,((DOMAIN-SUFFIX,"A.TEST."),(NOT,((DOMAIN,\'b.test\'))))', purpose='proxy')
        self.assertEqual(warnings, [])
        out, _ = render('suffix', logical, purpose='proxy', no_resolve='keep')
        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]),
                         'AND,((' + expected + '),(NOT,((DOMAIN-REGEX,(?-i:\\A[bB]\\.[tT][eE][sS][tT]\\.?\\z)))))')


class PairedActualWhitelistTests(unittest.TestCase):
    def test_paired_exact_and_suffix_are_covered_by_complete_actual_parent_suffix(self):
        for text in ('DOMAIN,"A.TEST."', 'DOMAIN-SUFFIX,a.test'):
            kind = text.partition(',')[0]
            parsed, warnings = parse(text, purpose='proxy')
            self.assertEqual(warnings, [])
            white = parse_whitelist('DOMAIN-SUFFIX,test')
            self.assertEqual(exclude_covered(parsed, white), [])
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(text=text, purpose=purpose, mode=mode):
                        out, skipped = render('paired-white', iter(parsed), whitelist=iter(white),
                                              purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin.yaml'], '# paired-white rules: 0\npayload:\n')
                        self.assertEqual(skipped['fin.yaml:' + kind + ':whitelist-covered'], 1)
                        self.assertEqual(skipped['whitelist-covered:' + kind], 1)
                        self.assertNotIn('fin.yaml:' + kind, skipped)
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(out[name], '# paired-white rules: 0\n')
                            self.assertEqual(skipped[name + ':' + kind + ':whitelist-covered'], 1)
                        SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'paired-white')

    def test_necessary_keyword_and_exact_wildcard_cover_complete_actual_paired_matchers(self):
        cases = (('DOMAIN,a.test', 'DOMAIN-KEYWORD,a', True),
                 ('DOMAIN-SUFFIX,a.test', 'DOMAIN-KEYWORD,a', True),
                 ('DOMAIN,a.test', 'DOMAIN-KEYWORD,a.', True),
                 ('DOMAIN,a.test', 'DOMAIN-WILDCARD,*.test', True),
                 ('DOMAIN,a.test', 'DOMAIN-WILDCARD,*.*', True),
                 ('DOMAIN,a.test', 'DOMAIN-WILDCARD,a.tes?', True),
                 ('DOMAIN,a.test', 'DOMAIN-WILDCARD,a.*', True),
                 ('DOMAIN,a.test', 'DOMAIN-WILDCARD,[ab].test', True),
                 ('DOMAIN,123.test', 'payload:\n  - DOMAIN-KEYWORD,123', True),
                 ('DOMAIN-SUFFIX,123.test', 'payload:\n  - DOMAIN-KEYWORD,123', True),
                 ('DOMAIN,a.test', 'payload:\n  - DOMAIN-KEYWORD,a', False),
                 ('DOMAIN-SUFFIX,a.test', 'DOMAIN-WILDCARD,*.test', False),
                 ('DOMAIN,a.test', 'DOMAIN-KEYWORD,test.', False))
        for text, white_text, covered in cases:
            parsed, warnings = parse(text, purpose='proxy')
            self.assertEqual(warnings, [])
            white = parse_whitelist(white_text)
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(text=text, white=white_text, purpose=purpose, mode=mode):
                        baseline, _ = render('literal-white', parsed, purpose=purpose, no_resolve=mode)
                        out, skipped = render('literal-white', iter(parsed), whitelist=iter(white),
                                              purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin.yaml'], '# literal-white rules: 0\npayload:\n'
                                         if covered else baseline['fin.yaml'])
                        self.assertEqual(skipped.get('fin.yaml:' + parsed[0].kind + ':whitelist-covered', 0), int(covered))
                        self.assertNotIn('fin.yaml:' + parsed[0].kind, skipped)

    def test_family_shape_subset_options_and_canonical_kelvin_counterexamples_remain(self):
        exact = r'(?-i:\A[aA]\.[tT][eE][sS][tT]\.?\z)'
        suffix = (r'(?-i:(?:\A|\.)test\z|\A(?=[A-Za-z0-9_.-]{1,253}\.?\z)'
                  r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*'
                  r'[tT][eE][sS][tT]\.?\z)')
        canonical = Rule('DOMAIN-REGEX', r'(?i:\Ak\.test\.?\z)')
        white = parse_whitelist('DOMAIN-SUFFIX,test')
        for host in ('K.TEST', 'K.test.'):
            self.assertIsNotNone(re.search(r'(?i:\Ak\.test\.?\Z)', host))
            self.assertIsNone(re.search(suffix.replace(r'\z', r'\Z'), host))
        variants = (canonical, Rule('DOMAIN-REGEX', exact.replace('[aA]', '[aB]')),
                    Rule('DOMAIN-REGEX', exact + '|z'),
                    Rule('DOMAIN-REGEX', suffix.replace('{1,253}', '{1,254}')),
                    Rule('DOMAIN-REGEX', suffix.replace(r'(?:\A|\.)test\z', r'(?:\A|\.)wide\z')),
                    Rule('DOMAIN-SUFFIX', 'test'))
        for rule in variants:
            with self.subTest(rule=rule):
                usable_white = parse_whitelist('DOMAIN,a.test') if rule.kind == 'DOMAIN-SUFFIX' else white
                baseline, _ = render('shape', [rule], purpose='proxy', no_resolve='keep')
                out, skipped = render('shape', [rule], whitelist=usable_white, purpose='proxy', no_resolve='keep')
                self.assertEqual(out['fin.yaml'], baseline['fin.yaml'])
                self.assertNotIn('fin.yaml:' + rule.kind + ':whitelist-covered', skipped)
        for attributes in ({'options': ('unsupported',)}, {'options': ('no-resolve',)},
                           {'domain_source': 'mihomo'}, {'domain_source': 'qx'}):
            rule = Rule('DOMAIN', 'a.test')
            out, skipped = render('scope', [rule], whitelist=[Rule('DOMAIN-SUFFIX', 'test', **attributes)],
                                  purpose='proxy', no_resolve='keep')
            self.assertIn('DOMAIN-REGEX,', out['fin.yaml'])
            self.assertNotIn('fin.yaml:DOMAIN:whitelist-covered', skipped)
        for operator, value in (('AND', '((DOMAIN,a.test),(DST-PORT,443))'),
                                ('OR', '((DST-PORT,443),(DOMAIN,a.test))'),
                                ('NOT', '((DOMAIN,a.test))')):
            rule = Rule(operator, value)
            baseline, _ = render('logical', [rule], purpose='proxy', no_resolve='keep')
            out, skipped = render('logical', [rule], whitelist=white, purpose='proxy', no_resolve='keep')
            self.assertEqual(out['fin.yaml'], baseline['fin.yaml'])
            self.assertNotIn('whitelist-covered:' + operator, skipped)

    def test_generated_paired_source_white_and_canonical_blocker_use_identical_round_and_disk_bytes(self):
        canonical = r'DOMAIN-REGEX,(?i:\Ak\.test\.?\z)'
        paired_exact = r'DOMAIN-REGEX,(?-i:\A[aA]\.[tT][eE][sS][tT]\.?\z)'
        paired_white = (r'DOMAIN-REGEX,(?-i:(?:\A|\.)test\z|\A(?=[A-Za-z0-9_.-]{1,253}\.?\z)'
                        r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*'
                        r'[tT][eE][sS][tT]\.?\z)')
        for name in ('fin.yaml', 'fin.txt', 'fin-surge-ds.txt'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(name=name, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/white.list').write_bytes(b'\xef\xbb\xbfDOMAIN-SUFFIX,test\r\n')
                        (root / 'static/source.list').write_text('DOMAIN,a.test\n' + canonical + '\n', encoding='utf-8')
                        (root / 'static/blocker.list').write_text(canonical + '\n', encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [dict(name=group, purpose=purpose, no_resolve=mode, sources=sources, whitelist=white)
                                   for group, sources, white in (
                                       ('white', ['static/white.list'], []),
                                       ('source', ['static/source.list'], []),
                                       ('consumer', ['source/' + name], ['white/' + name]),
                                       ('canonical', ['static/blocker.list'], ['white/' + name]))]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertNotIn('frozen', diagnostics.getvalue())
                        self.assertEqual(json.loads(outputs[root / 'white/fin.yaml'].splitlines()[2][4:]), paired_white)
                        source_yaml = outputs[root / 'source/fin.yaml']
                        self.assertIn(json.dumps(paired_exact), source_yaml)
                        self.assertIn(json.dumps(canonical), source_yaml)
                        canonical_yaml = '# canonical rules: 1\npayload:\n  - ' + json.dumps(canonical) + '\n'
                        self.assertEqual(outputs[root / 'canonical/fin.yaml'], canonical_yaml)
                        expected_consumer = ('# consumer rules: 1\npayload:\n  - ' + json.dumps(canonical) + '\n'
                                             if name == 'fin.yaml' else '# consumer rules: 0\npayload:\n')
                        self.assertEqual(outputs[root / 'consumer/fin.yaml'], expected_consumer)
                        self.assertNotIn('canonical fin.yaml:DOMAIN-REGEX:whitelist-covered', diagnostics.getvalue())
                        if name == 'fin.yaml':
                            self.assertIn('consumer fin.yaml:DOMAIN-REGEX:whitelist-covered: 1', diagnostics.getvalue())
                            self.assertIn('consumer whitelist-covered:DOMAIN-REGEX: 1', diagnostics.getvalue())
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        # 同文用户文件与生成依赖必须消费相同 bytes。
                        for group in ('source', 'white'):
                            path = root / 'static' / (group + '.copy')
                            path.write_bytes(published[root / group / name])
                        (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as disk_diagnostics:
                            disk = generate(root, lambda url: self.fail(url))
                        expected = {path: text for path, text in outputs.items() if path.parent.name in {'consumer', 'canonical'}}
                        self.assertEqual(disk, expected)
                        consumer_diagnostics = '\n'.join(line for line in diagnostics.getvalue().splitlines()
                                                        if line.startswith(('consumer ', 'canonical '))) + '\n'
                        self.assertEqual(disk_diagnostics.getvalue(), consumer_diagnostics)
                        copied_configs = [dict(configs[2], sources=['static/source.copy'], whitelist=['static/white.copy']),
                                          dict(configs[3], whitelist=['static/white.copy'])]
                        (root / 'rulesets.json').write_text(json.dumps(copied_configs), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as copied_diagnostics:
                            copied = generate(root, lambda url: self.fail(url))
                        self.assertEqual(copied, expected)
                        self.assertEqual(copied_diagnostics.getvalue(), consumer_diagnostics)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)


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
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
        self.assertEqual(skipped, {name + ':DOMAIN-KEYWORD': 1 for name in
                                  ('fin.txt', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')})

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
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped, {name + ':DOMAIN-WILDCARD': 1 for name in
                                          ('fin.txt', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')})

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
                        self.assertEqual(out['fin.txt'], '# root rules: 0\n')
                        self.assertEqual(skipped['fin.txt:DOMAIN'], 1)
                        self.assertEqual(skipped['fin-surge-ds.txt:DOMAIN'], 1)
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
                                self.assertFalse(any(line.startswith('@@') for line in products['fin-adb.txt'].splitlines()[7:]))
                                self.assertIn(f'{group} fin-adb.txt:DOMAIN-KEYWORD: 1', diagnostic.getvalue())
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


class SurgeWildcardBodyBoundaryTests(unittest.TestCase):
    def test_logical_wildcard_body_boundary_preserves_order_direction_and_no_resolve(self):
        cases = (('*.*', r'^.*\..*(?<!\.)\.?$'),
                 ('*.123.*', r'^.*\.123\..*(?<!\.)\.?$'),
                 ('*.123?', r'^.*\.123.(?<!\.)\.?$'),
                 ('*.com.*', r'^.*\.com\..*(?<!\.)\.?$'))
        for pattern, regex in cases:
            pairs = (
                ('AND,((DOMAIN-WILDCARD,' + pattern + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP,198.51.100.0/24))',
                 'AND,((DOMAIN-REGEX,' + regex + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'),
                ('OR,((DOMAIN,keep.example.org),(DOMAIN-WILDCARD,' + pattern + '))',
                 'OR,((DOMAIN,keep.example.org),(DOMAIN-REGEX,' + regex + '))'),
                ('NOT,((DOMAIN-WILDCARD,' + pattern + '))', 'NOT,((DOMAIN-REGEX,' + regex + '))'),
                ('AND,((NOT,((DOMAIN-WILDCARD,' + pattern + '))),(OR,((DOMAIN,keep.example.org),(DEST-PORT,443))))',
                 'AND,((NOT,((DOMAIN-REGEX,' + regex + '))),(OR,((DOMAIN,keep.example.org),(DST-PORT,443))))'),
            )
            for source, expected in pairs:
                for purpose in ('block', 'direct', 'proxy'):
                    parsed, warnings = parse(source, purpose=purpose)
                    self.assertEqual(warnings, [])
                    self.assertEqual(len(parsed), 1)
                    self.assertEqual(parsed[0].domain_source, 'surge')
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(pattern=pattern, source=source, purpose=purpose, mode=mode):
                            out, diagnostic = render('body', normalize(exclude_covered(parsed, [])),
                                                     purpose=purpose, no_resolve=mode)
                            actual = expected.replace(',no-resolve', '') if mode == 'strip' else expected
                            actual = actual.replace('DOMAIN,keep.example.org', expected_domain('DOMAIN', 'keep.example.org'))
                            self.assertEqual(out['fin.yaml'], '# body rules: 1\npayload:\n  - ' + json.dumps(actual) + '\n')
                            original = source.replace(',no-resolve', '') if mode == 'strip' else source
                            self.assertEqual(out['fin.txt'], '# body rules: 1\n' + original + '\n')
                            self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
                            operator = parsed[0].kind
                            self.assertEqual(diagnostic, {name + ':' + operator: 1 for name in
                                                         ('fin-qx.txt', 'fin-adb.txt', 'fin-surge-ds.txt')})
                            readback, warnings = parse(out['fin.yaml'], purpose=purpose)
                            self.assertEqual(warnings, [])
                            self.assertEqual(readback, [Rule(operator, actual.partition(',')[2], native_fields=True,
                                                            domain_source='surge')])
                            SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'body')

    def test_corrected_raw_regex_does_not_relax_external_or_input_allow_white_guard(self):
        cases = (('*.*', r'^.*\..*(?<!\.)\.?$'),
                 ('*.123.*', r'^.*\.123\..*(?<!\.)\.?$'),
                 ('*.123?', r'^.*\.123.(?<!\.)\.?$'),
                 ('*.com.*', r'^.*\.com\..*(?<!\.)\.?$'))
        for pattern, regex in cases:
            white = parse_whitelist('DOMAIN-WILDCARD,' + pattern)
            blocker = Rule('DOMAIN-REGEX', regex, domain_source='mihomo')
            self.assertEqual(exclude_covered([blocker], white), [blocker])
            for allowed in (False, True):
                rules = [blocker] + ([Rule('DOMAIN-WILDCARD', pattern, allow=True)] if allowed else [])
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(pattern=pattern, allowed=allowed, purpose=purpose, mode=mode):
                            out, diagnostic = render('guard', iter(rules), purpose=purpose, no_resolve=mode,
                                                     whitelist=iter([] if allowed else white))
                            self.assertEqual(out['fin.yaml'], '# guard rules: 1\npayload:\n  - ' +
                                             json.dumps('DOMAIN-REGEX,' + regex) + '\n')
                            self.assertNotIn('fin.yaml:DOMAIN-REGEX:whitelist-covered', diagnostic)
                            self.assertNotIn('whitelist-covered:DOMAIN-REGEX', diagnostic)
                            self.assertEqual(diagnostic['fin-adb.txt:DOMAIN-REGEX'], 1)
                            if purpose == 'block':
                                self.assertEqual(len(out['fin-adb.txt'].splitlines()[7:]), 1)
                                self.assertTrue(out['fin-adb.txt'].splitlines()[7].startswith('@@/'))
                            SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'guard')

    def test_generate_publish_body_boundary_same_round_and_disk_in_nine_modes(self):
        cases = (('*.*', r'^.*\..*(?<!\.)\.?$'),
                 ('*.123.*', r'^.*\.123\..*(?<!\.)\.?$'),
                 ('*.123?', r'^.*\.123.(?<!\.)\.?$'),
                 ('*.com.*', r'^.*\.com\..*(?<!\.)\.?$'))
        pairs = []
        for pattern, regex in cases:
            leaf, target = 'DOMAIN-WILDCARD,' + pattern, 'DOMAIN-REGEX,' + regex
            pairs.extend(((leaf, target),
                          ('AND,((' + leaf + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))',
                           'AND,((' + target + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'),
                          ('OR,((' + leaf + '),(DOMAIN,keep.example.org))',
                           'OR,((' + target + '),(DOMAIN,keep.example.org))'),
                          ('NOT,((' + leaf + '))', 'NOT,((' + target + '))')))
        source = '\n'.join(row for row, _ in pairs) + (
            '\nDOMAIN,keep.example.org\nIP-CIDR,203.0.113.0/24\nSRC-IP-CIDR,198.51.100.0/24\n')
        responses = {'https://example.org/body.list': source.encode('utf-8')}
        for purpose in ('block', 'direct', 'proxy'):
            parsed, warnings = parse(source, purpose=purpose)
            self.assertEqual((len(parsed), warnings), (19, []))
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['https://example.org/body.list'], 'whitelist': []},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source/fin.yaml'], 'whitelist': []}]
                    config_path = root / 'rulesets.json'
                    config_path.write_text(json.dumps(configs), encoding='utf-8')
                    config_before = config_path.read_bytes()
                    old = {}
                    for group in ('source', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            path.write_bytes(b'old artifact\x00\xff\r\n')
                            old[path] = path.read_bytes()
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        clock.now.return_value = datetime(2026, 10, 15, tzinfo=timezone.utc)
                        products = generate(root, responses.__getitem__)
                    self.assertEqual(list(products), [root / group / name for group in ('source', 'child') for name in FILES])
                    self.assertNotIn('frozen', diagnostic.getvalue())
                    self.assertNotIn('whitelist-covered', diagnostic.getvalue())
                    expected = {(target.replace(',no-resolve', '') if mode == 'strip' else target).replace(
                        'DOMAIN,keep.example.org', expected_domain('DOMAIN', 'keep.example.org')) for _, target in pairs}
                    expected.update((expected_domain('DOMAIN', 'keep.example.org'), 'SRC-IP-CIDR,198.51.100.0/24',
                                     'IP-CIDR,203.0.113.0/24' + (',no-resolve' if mode == 'add' else '')))
                    for group in ('source', 'child'):
                        output = {name: products[root / group / name] for name in FILES}
                        self.assertEqual({json.loads(line[4:]) for line in output['fin.yaml'].splitlines()[2:]}, expected)
                        readback, warnings = parse(output['fin.yaml'], purpose=purpose)
                        self.assertEqual((len(readback), warnings), (19, []))
                        self.assertFalse(any(rule.kind == 'SRC-IP-CIDR' and rule.options for rule in readback))
                        self.assertNotIn(group + ' fin.yaml:', diagnostic.getvalue())
                        SurgeRootDotProjectionTests.assert_counts_and_split(self, output, purpose, group)
                        for operator in ('AND', 'OR', 'NOT'):
                            self.assertIn(group + ' fin-adb.txt:' + operator + ': 4\n', diagnostic.getvalue())
                    self.assertIn('child fin-adb.txt:DOMAIN-REGEX: 5\n', diagnostic.getvalue())
                    if purpose == 'block':
                        self.assertEqual(set(products[root / 'source/fin-adb.txt'].splitlines()[7:]),
                                         {r'/^.*\..*$/', r'/^.*\.123\..*$/', r'/^.*\.123.$/',
                                          r'/^.*\.com\..*$/', '0.0.0.0 keep.example.org'})
                        self.assertEqual(products[root / 'child/fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    self.assertEqual(config_path.read_bytes(), config_before)
                    publish(products, root=root)
                    self.assertEqual({path: path.read_bytes() for path in products},
                                     {path: text.encode('utf-8') for path, text in products.items()})
                    config_path.write_text(json.dumps(configs[-1:]), encoding='utf-8')
                    config_before = config_path.read_bytes()
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        clock.now.return_value = datetime(2026, 10, 15, tzinfo=timezone.utc)
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(disk, {path: text for path, text in products.items() if path.parent.name == 'child'})
                    self.assertNotIn('frozen', diagnostic.getvalue())
                    self.assertEqual(config_path.read_bytes(), config_before)
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in products},
                                     {path: text.encode('utf-8') for path, text in products.items()})


class ActualTargetWhitelistTests(unittest.TestCase):
    def test_input_allow_interface_options_keep_native_byte_and_root_dot_white_scope(self):
        cases = ((Rule('DOMAIN-WILDCARD', 'windows-??.net', domain_source='mihomo'),
                  Rule('DOMAIN-WILDCARD', 'windows-??.net', ('force-cellular',), allow=True)),
                 (Rule('DOMAIN-WILDCARD', 'api-[0-9].example.com', domain_source='mihomo'),
                  Rule('DOMAIN-WILDCARD', 'api-[0-9].example.com', ('force-cellular',), allow=True)),
                 (Rule('DOMAIN', 'localhost.', domain_source='mihomo'),
                  Rule('DOMAIN-WILDCARD', '*.*', ('force-cellular',), allow=True)))
        self.assertTrue(fnmatchcase(b'windows-\xc3\xa9.net', b'windows-??.net'))
        self.assertFalse(fnmatchcase('windows-é.net', 'windows-??.net'))
        self.assertFalse(fnmatchcase('localhost', '*.*'))
        for blocked, allowed in cases:
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(blocked=blocked, purpose=purpose, mode=mode):
                        out, diagnostic = render('bounds', iter([blocked, allowed]), purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin.yaml'], '# bounds rules: 1\npayload:\n  - ' +
                                         json.dumps(blocked.kind + ',' + blocked.value) + '\n')
                        self.assertNotIn('fin.yaml:' + blocked.kind + ':whitelist-covered', diagnostic)
                        self.assertNotIn('whitelist-covered:' + blocked.kind, diagnostic)
                        if purpose == 'block':
                            self.assertTrue(any(line.startswith('@@') for line in out['fin-adb.txt'].splitlines()[7:]))
                        self.assertEqual(allowed.options, ('force-cellular',))
                        SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'bounds')
        blocked = Rule('DOMAIN-REGEX', r'^.*\..*\.?$')
        allowed = Rule('DOMAIN-WILDCARD', '*.*', ('force-cellular',), allow=True)
        out, diagnostic = render('regex', [blocked, allowed], purpose='block', no_resolve='keep')
        self.assertEqual(out['fin.yaml'], '# regex rules: 1\npayload:\n  - "DOMAIN-REGEX,^.*\\\\..*\\\\.?$"\n')
        self.assertNotIn('fin.yaml:DOMAIN-REGEX:whitelist-covered', diagnostic)
        self.assertNotIn('whitelist-covered:DOMAIN-REGEX', diagnostic)

    def test_external_whitelist_options_keep_route_guard_and_dns_exceptions(self):
        cases = (('DOMAIN', 'HOST', 'ads.example.org', ['@@|ads.example.org|', '0.0.0.0 ads.example.org']),
                 ('DOMAIN-SUFFIX', 'HOST-SUFFIX', 'ads.example.org', ['@@||ads.example.org^', '||ads.example.org^']),
                 ('DOMAIN-KEYWORD', 'HOST-KEYWORD', 'microsoft', ['@@/^.*microsoft.*$/', '/^.*microsoft.*$/']))
        for kind, qx_kind, value, dns_body in cases:
            for source in ('surge', 'qx'):
                for options in (('force-cellular',), ('multi-interface',), ('multi-interface-balance',),
                                ('via-interface=pdp_ip0',), ('via-interface=en1',),
                                ('force-cellular', 'unsupported'), ('force-cellular', 'no-resolve')):
                    blocked = Rule(kind, value, ('multi-interface',), domain_source='qx')
                    white = Rule(kind, value, options, domain_source=source)
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(kind=kind, source=source, options=options, purpose=purpose, mode=mode):
                                out, diagnostic = render('external', iter([blocked]), purpose=purpose,
                                                         no_resolve=mode, whitelist=iter([white]))
                                self.assertEqual(out['fin-qx.txt'], '# external rules: 1\n' + qx_kind + ',' + value + ',LIST\n')
                                self.assertEqual(out['fin.txt'], '# external rules: 1\n' + kind + ',' + value + '\n')
                                self.assertEqual(out['fin.yaml'], '# external rules: 1\npayload:\n  - ' + json.dumps(kind + ',' + value) + '\n')
                                self.assertFalse(any('whitelist-covered' in key for key in diagnostic))
                                self.assertEqual(diagnostic['fin-qx.txt:' + kind + ':interface-option'], 1)
                                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], dns_body if purpose == 'block' else
                                                 ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(white.options, tuple(sorted(options)))
                                self.assertEqual(white.domain_source, source)
                                SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'external')

    def test_input_allow_interface_options_cover_same_qx_matcher_with_source_scope_preserved(self):
        cases = (('DOMAIN', 'HOST', 'ads.example.org', ['@@|ads.example.org|', '0.0.0.0 ads.example.org']),
                 ('DOMAIN-SUFFIX', 'HOST-SUFFIX', 'ads.example.org', ['@@||ads.example.org^', '||ads.example.org^']),
                 ('DOMAIN-KEYWORD', 'HOST-KEYWORD', 'microsoft', ['@@/^.*microsoft.*$/', '/^.*microsoft.*$/']),
                 ('DOMAIN-KEYWORD', 'HOST-KEYWORD', 'ads', ['@@/^.*ads.*$/', '/^.*ads.*$/']))
        for kind, qx_kind, value, dns_body in cases:
            blocker = Rule(kind, value, domain_source='qx')
            for source in ('surge', 'qx'):
                for options in ((), ('force-cellular',), ('multi-interface',), ('multi-interface-balance',),
                                ('via-interface=pdp_ip0',), ('via-interface=en1',)):
                    allowed = Rule(kind, value, options, allow=True, domain_source=source)
                    self.assertEqual(exclude_covered([blocker, allowed], [allowed]),
                                     [allowed] if source == 'qx' or kind != 'DOMAIN-KEYWORD' else [blocker, allowed])
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(kind=kind, value=value, source=source, options=options, purpose=purpose, mode=mode):
                                out, diagnostic = render('allow', iter([blocker, allowed]), purpose=purpose,
                                                         no_resolve=mode, whitelist=iter(()))
                                expected = {name + ':' + kind: 1 for name in FILES if name != 'fin-adb.txt'}
                                if kind == 'DOMAIN-KEYWORD':
                                    expected['fin-surge-ds.txt:' + kind] = 2
                                if purpose != 'block':
                                    expected['fin-adb.txt:' + kind] = 2
                                targets = (('fin.txt', 'fin-qx.txt', 'fin.yaml',
                                            'fin-surge.txt' if kind == 'DOMAIN-KEYWORD' else 'fin-surge-ds.txt')
                                           if source == 'surge' else ('fin-qx.txt',))
                                for name in targets:
                                    expected[name + ':' + kind + ':whitelist-covered'] = 1
                                if source == 'surge':
                                    expected['whitelist-covered:' + kind] = 1
                                self.assertEqual(diagnostic, expected)
                                bodies = {
                                    'fin.txt': [kind + ',' + value] if source == 'qx' else [],
                                    'fin-qx.txt': [],
                                    'fin.yaml': ['  - ' + json.dumps(kind + ',' + value)] if source == 'qx' else [],
                                    'fin-surge.txt': [kind + ',' + value] if source == 'qx' and kind == 'DOMAIN-KEYWORD' else [],
                                    'fin-surge-ds.txt': [('.' if kind == 'DOMAIN-SUFFIX' else '') + value]
                                                      if source == 'qx' and kind != 'DOMAIN-KEYWORD' else [],
                                }
                                for name, body in bodies.items():
                                    header = '# allow rules: ' + str(len(body)) + '\n' + ('payload:\n' if name == 'fin.yaml' else '')
                                    self.assertEqual(out[name], header + ''.join(line + '\n' for line in body))
                                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], dns_body if purpose == 'block' else
                                                 ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual((allowed.options, allowed.allow, allowed.domain_source, blocker.domain_source),
                                                 (options, True, source, 'qx'))
                                SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'allow')
                                control, skipped = render('control', iter([blocker]), purpose=purpose, no_resolve=mode,
                                                          whitelist=iter(parse_whitelist(qx_kind + ',' + value)))
                                self.assertEqual(control['fin-qx.txt'], '# control rules: 0\n')
                                self.assertEqual(skipped['fin-qx.txt:' + kind + ':whitelist-covered'], 1)

    def test_allow_interface_white_keeps_unknown_options_and_no_resolve_boundary(self):
        for options in (('force-cellular', 'multi-interface', 'via-interface=en1'),
                        ('force-cellular', 'unsupported'), ('force-cellular', 'no-resolve')):
            blocked = Rule('DOMAIN', 'ads.example.org', ('multi-interface',), domain_source='qx')
            allowed = Rule('DOMAIN', 'ads.example.org', options, allow=True, domain_source='qx')
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(options=options, purpose=purpose, mode=mode):
                        covered = 'unsupported' not in options and ('no-resolve' not in options or mode == 'strip')
                        out, diagnostic = render('options', iter([blocked, allowed]), purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin-qx.txt'], '# options rules: ' +
                                         ('0\n' if covered else '1\nHOST,ads.example.org,LIST\n'))
                        self.assertEqual(diagnostic.get('fin-qx.txt:DOMAIN:whitelist-covered', 0), int(covered))
                        self.assertEqual(diagnostic.get('fin-qx.txt:DOMAIN:interface-option', 0), int(not covered))
                        self.assertNotIn('whitelist-covered:DOMAIN', diagnostic)
                        if purpose == 'block':
                            self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                             (['@@|ads.example.org|'] if covered else []) + ['0.0.0.0 ads.example.org'])
                        self.assertEqual(allowed.options, tuple(sorted(options)))
                        self.assertEqual(blocked.options, ('multi-interface',))

    def test_allow_interface_white_keeps_qx_source_payload_and_per_rule_diagnostics(self):
        for blocked, allowed in (
                (Rule('DOMAIN-KEYWORD', 'Σ', domain_source='qx'),
                 Rule('DOMAIN-KEYWORD', 'σ', ('force-cellular',), allow=True, domain_source='qx')),
                (Rule('DOMAIN-KEYWORD', 'σ', domain_source='qx'),
                 Rule('DOMAIN-KEYWORD', 'σ', ('force-cellular',), allow=True, domain_source='mihomo')),
                (Rule('DOMAIN', 'localhost.', domain_source='mihomo'),
                 Rule('DOMAIN', 'localhost', ('force-cellular',), allow=True, domain_source='qx'))):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(blocked=blocked, allowed=allowed, purpose=purpose, mode=mode):
                        out, diagnostic = render('scope', iter([blocked, allowed]), purpose=purpose, no_resolve=mode)
                        qx_kind = 'HOST' if blocked.kind == 'DOMAIN' else 'HOST-KEYWORD'
                        self.assertEqual(out['fin-qx.txt'], '# scope rules: 1\n' + qx_kind + ',' + blocked.value + ',LIST\n')
                        self.assertNotIn('fin-qx.txt:' + blocked.kind + ':whitelist-covered', diagnostic)
                        self.assertNotIn('whitelist-covered:' + blocked.kind, diagnostic)
        blocked = [Rule('DOMAIN', 'ads.example.org', options, domain_source='qx')
                   for options in ((), ('force-cellular',))]
        neighbor = Rule('DOMAIN', 'keep.example.net', ('multi-interface',), domain_source='qx')
        allowed = Rule('DOMAIN', 'ads.example.org', ('multi-interface-balance',), allow=True, domain_source='qx')
        out, diagnostic = render('counts', iter(normalize([*blocked, neighbor, allowed, allowed])),
                                 purpose='block', no_resolve='keep')
        self.assertEqual(out['fin-qx.txt'], '# counts rules: 1\nHOST,keep.example.net,LIST\n')
        self.assertEqual(diagnostic['fin-qx.txt:DOMAIN:whitelist-covered'], 2)
        self.assertEqual(diagnostic['fin-qx.txt:DOMAIN:interface-option'], 1)
        self.assertEqual(diagnostic['fin-qx.txt:DOMAIN'], 1)
        self.assertNotIn('whitelist-covered:DOMAIN', diagnostic)
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                         ['@@|ads.example.org|', '0.0.0.0 ads.example.org', '0.0.0.0 keep.example.net'])

    def test_surge_wildcard_white_regex_projection_preserves_root_dot_scope(self):
        cases = (
            ('*.*', r'^.*\..*\.?$', 'localhost.', False),
            ('*.123.*', r'^.*\.123\..*\.?$', 'cdn.123.', False),
            ('*.123?', r'^.*\.123.\.?$', 'cdn.123.', False),
            ('windows-*.net', r'^windows\-.*\.net\.?$', 'windows-abc.net.', True),
            ('*.*123*', r'^.*\..*123.*\.?$', 'cdn.123.', True),
            ('api-[0-9].example.com', r'^api\-[0-9]\.example\.com\.?$', 'api-7.example.com.', True),
            ('*.[12]*', r'^.*\.[12].*\.?$', 'cdn.1.', True),
        )
        for pattern, regex, host, covered in cases:
            white = parse_whitelist('DOMAIN-WILDCARD,' + pattern + '\n')
            self.assertEqual(white, [Rule('DOMAIN-WILDCARD', pattern)])
            self.assertEqual(fnmatchcase(host.removesuffix('.'), pattern), covered)
            self.assertIsNotNone(re.fullmatch(regex, host))
            for purpose in ('block', 'direct', 'proxy'):
                blocked, warnings = parse('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + regex) + '\n', purpose=purpose)
                self.assertEqual((blocked, warnings), ([Rule('DOMAIN-REGEX', regex)], []))
                self.assertEqual(exclude_covered(blocked, white), blocked)
                for allow in (False, True):
                    rules = blocked + ([Rule('DOMAIN-WILDCARD', pattern, allow=True)] if allow else [])
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(pattern=pattern, purpose=purpose, allow=allow, mode=mode):
                            out, diagnostic = render('root', iter(rules), purpose=purpose, no_resolve=mode,
                                                     whitelist=iter([] if allow else white))
                            expected = ('# root rules: 0\npayload:\n' if covered else
                                        '# root rules: 1\npayload:\n  - ' + json.dumps('DOMAIN-REGEX,' + regex) + '\n')
                            self.assertEqual(out['fin.yaml'], expected)
                            self.assertEqual(diagnostic.get('fin.yaml:DOMAIN-REGEX:whitelist-covered', 0), int(covered))
                            self.assertEqual(diagnostic.get('whitelist-covered:DOMAIN-REGEX', 0), int(covered))
                            self.assertEqual(diagnostic.get('fin.yaml:DOMAIN-REGEX', 0), 0)
                            if purpose == 'block':
                                dns = out['fin-adb.txt'].splitlines()[7:]
                                self.assertIn('/' + regex + '/', dns)
                                self.assertTrue(any(line.startswith('@@/') for line in dns))
                            SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'root')
                            self.assertEqual(blocked[0].value, regex)
                            self.assertEqual(white[0], Rule('DOMAIN-WILDCARD', pattern))

    def test_surge_wildcard_root_dot_regex_keeps_generate_publish_and_dependency_bytes(self):
        for pattern, regex in (('*.*', r'^.*\..*\.?$'), ('*.123.*', r'^.*\.123\..*\.?$')):
            source_text = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + regex) + '\n'
            white_text = 'DOMAIN-WILDCARD,' + pattern + '\n'
            for generated_white in (False, True):
                for remote in (False, True):
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(pattern=pattern, generated_white=generated_white, remote=remote,
                                              purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                                root = Path(directory)
                                (root / 'static').mkdir()
                                (root / 'static/source.yaml').write_bytes(source_text.encode())
                                (root / 'static/white.list').write_bytes(white_text.encode())
                                inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                                source_entry = 'https://example.org/source' if remote else 'static/source.yaml'
                                white_entry = 'https://example.org/white' if remote else 'static/white.list'
                                configs = ([{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                             'sources': [white_entry], 'whitelist': []}] if generated_white else [])
                                selected_white = 'white/fin.txt' if generated_white else white_entry
                                configs += [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                             'sources': [source_entry], 'whitelist': [selected_white]},
                                            {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                             'sources': ['source/fin.yaml'], 'whitelist': [selected_white]}]
                                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                                old = {}
                                for config in configs:
                                    (root / config['name']).mkdir()
                                    for name in FILES:
                                        path = root / config['name'] / name
                                        path.write_bytes(b'old artifact\x00\xff\r\n')
                                        old[path] = path.read_bytes()
                                responses = {'https://example.org/source': source_text.encode(),
                                             'https://example.org/white': white_text.encode()}
                                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                    clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                                    out = generate(root, responses.__getitem__)
                                self.assertEqual(len(out), len(configs) * 6)
                                self.assertNotIn('frozen', diagnostic.getvalue())
                                self.assertNotIn(':whitelist-covered', diagnostic.getvalue())
                                self.assertNotIn(' whitelist-covered:', diagnostic.getvalue())
                                if generated_white:
                                    self.assertEqual(out[root / 'white/fin.txt'], '# white rules: 1\n' + white_text)
                                    self.assertEqual(parse_whitelist(out[root / 'white/fin.txt']),
                                                     [Rule('DOMAIN-WILDCARD', pattern)])
                                for group in ('source', 'child'):
                                    products = {name: out[root / group / name] for name in FILES}
                                    self.assertEqual(products['fin.yaml'], f'# {group} rules: 1\npayload:\n  - ' +
                                                     json.dumps('DOMAIN-REGEX,' + regex) + '\n')
                                    self.assertEqual(parse(products['fin.yaml'], purpose=purpose),
                                                     ([Rule('DOMAIN-REGEX', regex)], []))
                                    SurgeRootDotProjectionTests.assert_counts_and_split(self, products, purpose, group)
                                    if purpose == 'block':
                                        self.assertIn('/' + regex + '/', products['fin-adb.txt'].splitlines()[7:])
                                        self.assertTrue(any(line.startswith('@@/') for line in products['fin-adb.txt'].splitlines()[7:]))
                                self.assertEqual({path: path.read_bytes() for path in old}, old)
                                publish(out, root=root)
                                self.assertEqual({path: path.read_bytes() for path in out},
                                                 {path: text.encode() for path, text in out.items()})
                                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                                (root / 'rulesets.json').write_text(json.dumps(configs[-1:]), encoding='utf-8')
                                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                    clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                                    disk = generate(root, responses.__getitem__)
                                self.assertEqual(disk, {path: text for path, text in out.items() if path.parent.name == 'child'})
                                self.assertNotIn(':whitelist-covered', diagnostic.getvalue())
                                self.assertNotIn(' whitelist-covered:', diagnostic.getvalue())
                                publish(disk, root=root)
                                self.assertEqual({path: path.read_bytes() for path in out},
                                                 {path: text.encode() for path, text in out.items()})
                                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_native_unicode_white_does_not_expand_surge_case_scope(self):
        for value, dns_value in (('σ', r'\\207\\131'), ('Σ', r'\\207\\131'), ('ς', r'\\207\\130')):
            blocked, warnings = parse('DOMAIN-KEYWORD,' + value, purpose='block')
            white = parse_whitelist('payload:\n  - "DOMAIN-KEYWORD,' + value + '"\n')
            self.assertEqual((blocked, warnings), ([Rule('DOMAIN-KEYWORD', value)], []))
            self.assertEqual(white, [Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')])
            self.assertEqual(exclude_covered(blocked, white), blocked)
            for allow in (False, True):
                allowed = Rule('DOMAIN-KEYWORD', value, allow=True, domain_source='mihomo')
                rules = blocked + ([allowed] if allow else [])
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(value=value, allow=allow, purpose=purpose, mode=mode):
                            out, diagnostic = render('unicode', iter(rules), purpose=purpose, no_resolve=mode,
                                                     whitelist=iter([] if allow else white))
                            for name in ('fin.txt', 'fin-surge.txt'):
                                self.assertEqual(out[name], '# unicode rules: 1\nDOMAIN-KEYWORD,' + value + '\n')
                                self.assertNotIn(name + ':DOMAIN-KEYWORD:whitelist-covered', diagnostic)
                            self.assertNotIn('whitelist-covered:DOMAIN-KEYWORD', diagnostic)
                            self.assertEqual(blocked[0].value, value)
                            self.assertEqual(white[0].domain_source, 'mihomo')
                            if purpose == 'block':
                                token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
                                self.assertIn(r'@@/(?s-i:\A' + token + '*' + dns_value + token + r'*\z)/',
                                              out['fin-adb.txt'].splitlines()[7:])

    def test_qx_unicode_lowercase_does_not_prove_different_payload_coverage(self):
        for value, white_value in (('Σ', 'σ'), ('σ', 'Σ'), ('K', 'k'), ('k', 'K')):
            blocked, warnings = parse('payload:\n  - "DOMAIN-KEYWORD,' + value + '"\n', purpose='block')
            white = parse_whitelist('HOST-KEYWORD,' + white_value + '\n')
            self.assertEqual((blocked, warnings), ([Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')], []))
            self.assertEqual(white, [Rule('DOMAIN-KEYWORD', white_value, domain_source='qx')])
            self.assertEqual(exclude_covered(blocked, white), blocked)
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(value=value, white=white_value, purpose=purpose, mode=mode):
                        out, diagnostic = render('unicode', iter(blocked), purpose=purpose, no_resolve=mode,
                                                 whitelist=iter(white))
                        self.assertEqual(out['fin-qx.txt'], '# unicode rules: 1\nHOST-KEYWORD,' + value + ',LIST\n')
                        self.assertNotIn('fin-qx.txt:DOMAIN-KEYWORD:whitelist-covered', diagnostic)
                        self.assertNotIn('whitelist-covered:DOMAIN-KEYWORD', diagnostic)
                        self.assertEqual(blocked[0].value, value)
                        self.assertEqual(white[0].value, white_value)
        same, diagnostic = render('same', [Rule('DOMAIN-KEYWORD', 'σ', domain_source='mihomo')],
                                  purpose='proxy', no_resolve='keep',
                                  whitelist=parse_whitelist('HOST-KEYWORD,σ'))
        self.assertEqual(same['fin-qx.txt'], '# same rules: 0\n')
        self.assertEqual(diagnostic['fin-qx.txt:DOMAIN-KEYWORD:whitelist-covered'], 1)
        native_white = parse_whitelist('payload:\n  - "DOMAIN-KEYWORD,σ"\n')
        qx, diagnostic = render('native', [Rule('DOMAIN-KEYWORD', 'σ', domain_source='qx')],
                               purpose='proxy', no_resolve='keep', whitelist=native_white)
        self.assertEqual(qx['fin-qx.txt'], '# native rules: 1\nHOST-KEYWORD,σ,LIST\n')
        self.assertNotIn('fin-qx.txt:DOMAIN-KEYWORD:whitelist-covered', diagnostic)

    def test_unicode_whitelist_counterexamples_keep_real_generation_and_dependency_bytes(self):
        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        native_dns = r'/(?s-i:\A' + token + r'*\\207\\131' + token + r'*\z)/'
        cases = (
            ('DOMAIN-KEYWORD,σ\n', 'payload:\n  - "DOMAIN-KEYWORD,σ"\n', 'fin.yaml',
             'fin.txt', 'DOMAIN-KEYWORD,σ', 'DOMAIN-REGEX,σ',
             ['@@' + native_dns, '/^.*σ.*$/']),
            ('payload:\n  - "DOMAIN-KEYWORD,Σ"\n', 'HOST-KEYWORD,σ\n', 'fin-qx.txt',
             'fin-qx.txt', 'HOST-KEYWORD,Σ,LIST', 'DOMAIN-KEYWORD,Σ',
             ['@@/^.*σ.*$/', native_dns]),
        )
        for source_text, white_text, white_file, target, expected_target, expected_yaml, expected_dns in cases:
            for generated_white in (False, True):
                for remote in (False, True):
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(target=target, generated_white=generated_white, remote=remote,
                                              purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                                root = Path(directory)
                                (root / 'static').mkdir()
                                (root / 'static/source.list').write_bytes(source_text.encode('utf-8'))
                                (root / 'static/white.list').write_bytes(white_text.encode('utf-8'))
                                inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                                source_entry = 'https://example.org/source' if remote else 'static/source.list'
                                white_entry = 'https://example.org/white' if remote else 'static/white.list'
                                configs = ([{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                             'sources': [white_entry], 'whitelist': []}] if generated_white else [])
                                selected_white = 'white/' + white_file if generated_white else white_entry
                                configs += [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                             'sources': [source_entry], 'whitelist': [selected_white]},
                                            {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                             'sources': ['source/fin.yaml'], 'whitelist': [selected_white]}]
                                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                                old = {}
                                for config in configs:
                                    (root / config['name']).mkdir()
                                    for name in FILES:
                                        path = root / config['name'] / name
                                        path.write_bytes(b'old artifact\x00\xff\r\n')
                                        old[path] = path.read_bytes()
                                responses = {'https://example.org/source': source_text.encode('utf-8'),
                                             'https://example.org/white': white_text.encode('utf-8')}
                                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                    clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                                    products = generate(root, responses.__getitem__)
                                self.assertEqual(len(products), len(configs) * 6)
                                self.assertNotIn('frozen', diagnostic.getvalue())
                                self.assertNotIn(':whitelist-covered', diagnostic.getvalue())
                                self.assertNotIn(' whitelist-covered:', diagnostic.getvalue())
                                self.assertEqual(products[root / 'source' / target],
                                                 '# source rules: 1\n' + expected_target + '\n')
                                if target == 'fin.txt':
                                    self.assertEqual(products[root / 'source/fin-surge.txt'],
                                                     '# source rules: 1\nDOMAIN-KEYWORD,σ\n')
                                for group in ('source', 'child'):
                                    output = {name: products[root / group / name] for name in FILES}
                                    self.assertEqual([json.loads(line[4:]) for line in output['fin.yaml'].splitlines()[2:]],
                                                     [expected_yaml])
                                    parsed, warnings = parse(output['fin.yaml'], purpose=purpose)
                                    self.assertEqual(warnings, [])
                                    self.assertEqual(parsed[0].value, expected_yaml.partition(',')[2])
                                    SurgeRootDotProjectionTests.assert_counts_and_split(self, output, purpose, group)
                                if purpose == 'block':
                                    self.assertEqual(products[root / 'source/fin-adb.txt'].splitlines()[7:], expected_dns)
                                self.assertEqual({path: path.read_bytes() for path in old}, old)
                                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                                publish(products, root=root)
                                self.assertEqual({path: path.read_bytes() for path in products},
                                                 {path: text.encode('utf-8') for path, text in products.items()})
                                (root / 'rulesets.json').write_text(json.dumps(configs[-1:]), encoding='utf-8')
                                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                    clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                                    disk = generate(root, responses.__getitem__)
                                self.assertEqual(disk, {path: text for path, text in products.items() if path.parent.name == 'child'})
                                self.assertNotIn(':whitelist-covered', diagnostic.getvalue())
                                publish(disk, root=root)
                                self.assertEqual({path: path.read_bytes() for path in products},
                                                 {path: text.encode('utf-8') for path, text in products.items()})
                                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_qx_actual_payload_does_not_gain_unproved_case_or_root_dot_normalization(self):
        cases = (('DOMAIN', 'localhost.', 'DOMAIN,localhost'),
                 ('DOMAIN', 'ADS.EXAMPLE.org', 'DOMAIN,ads.example.org'),
                 ('DOMAIN-WILDCARD', '*.123.*.', 'DOMAIN-WILDCARD,*.123.*'))
        for kind, value, white_text in cases:
            with self.subTest(kind=kind, value=value):
                rule = Rule(kind, value, domain_source='mihomo')
                out, skipped = render('qx', [rule], purpose='proxy', no_resolve='keep',
                                      whitelist=parse_whitelist(white_text))
                qx_kind = 'HOST-WILDCARD' if kind == 'DOMAIN-WILDCARD' else 'HOST'
                self.assertEqual(out['fin-qx.txt'], '# qx rules: 1\n' + qx_kind + ',' + value + ',LIST\n')
                self.assertNotIn('fin-qx.txt:' + kind + ':whitelist-covered', skipped)
                self.assertNotIn('whitelist-covered:' + kind, skipped)
                self.assertEqual(rule.value, value)

    def test_distinct_interface_rules_each_count_as_covered_after_actual_projection_deduplicates(self):
        rules = [Rule('DOMAIN-KEYWORD', 'microsoft', ('force-cellular',), domain_source='qx'),
                 Rule('DOMAIN-KEYWORD', 'microsoft', ('multi-interface',), domain_source='qx')]
        white = parse_whitelist('DOMAIN-KEYWORD,microsoft')
        self.assertEqual(len(normalize(rules)), 2)
        out, skipped = render('covered', normalize(rules), purpose='block', no_resolve='keep', whitelist=white)
        self.assertEqual(out['fin.yaml'], '# covered rules: 0\npayload:\n')
        self.assertEqual(skipped['whitelist-covered:DOMAIN-KEYWORD'], 2)
        self.assertEqual(skipped['fin-qx.txt:DOMAIN-KEYWORD:whitelist-covered'], 2)
        self.assertNotIn('fin-qx.txt:DOMAIN-KEYWORD:interface-option', skipped)
        for purpose, policy in (('block', 'REJECT'), ('direct', 'DIRECT'), ('proxy', 'PROXY')):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    text = ('HOST-KEYWORD,microsoft,' + policy + ',force-cellular\n'
                            'HOST-KEYWORD,microsoft,' + policy + ',multi-interface\n')
                    (root / 'static/source.list').write_text(text, encoding='utf-8')
                    (root / 'static/white.list').write_text('DOMAIN-KEYWORD,microsoft\n', encoding='utf-8')
                    self.assertEqual(parse(text, purpose=purpose), (rules, []))
                    config = [{'name': 'covered', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['static/source.list'], 'whitelist': ['static/white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        products = generate(root, lambda url: self.fail(url))
                    self.assertEqual(len(products), 6)
                    self.assertIn('covered whitelist-covered:DOMAIN-KEYWORD: 2\n', diagnostic.getvalue())
                    self.assertNotIn('frozen', diagnostic.getvalue())
                    publish(products, root=root)
                    self.assertEqual({path: path.read_bytes() for path in products},
                                     {path: text.encode() for path, text in products.items()})

    def test_identical_raw_regex_white_is_source_independent_and_does_not_remove_logical_children(self):
        regex = Rule('DOMAIN-REGEX', '^ads$')
        logical = Rule('AND', '((DOMAIN-REGEX,^ads$),(DST-PORT,443))')
        for source in ('surge', 'mihomo', 'qx', 'unknown'):
            white = Rule('DOMAIN-REGEX', '^ads$', domain_source=source)
            self.assertEqual(exclude_covered([regex, logical], [white]), [logical])
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(source=source, purpose=purpose, mode=mode):
                        out, skipped = render('raw', [regex, logical], purpose=purpose, no_resolve=mode, whitelist=[white])
                        self.assertEqual(out['fin.yaml'], '# raw rules: 1\npayload:\n  - "AND,((DOMAIN-REGEX,^ads$),(DST-PORT,443))"\n')
                        self.assertEqual(skipped['fin.yaml:DOMAIN-REGEX:whitelist-covered'], 1)
                        self.assertEqual(skipped['whitelist-covered:DOMAIN-REGEX'], 1)
                        self.assertNotIn('fin.yaml:AND:whitelist-covered', skipped)

    def test_allow_whitelist_uses_effective_strip_options_without_mutating_input(self):
        blocked = Rule('DOMAIN', 'ads.example.org')
        allowed = Rule('DOMAIN-SUFFIX', 'example.org', ('no-resolve',), allow=True)
        out, skipped = render('strip', iter([blocked, allowed]), purpose='block', no_resolve='strip')
        self.assertEqual(out['fin.yaml'], '# strip rules: 0\npayload:\n')
        self.assertEqual(skipped['whitelist-covered:DOMAIN'], 1)
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], ['@@||example.org^', '0.0.0.0 ads.example.org'])
        self.assertEqual(allowed.options, ('no-resolve',))

    def test_qx_keyword_is_covered_at_actual_targets_without_changing_source_identity(self):
        rule = Rule('DOMAIN-KEYWORD', 'microsoft', domain_source='qx')
        white = parse_whitelist('DOMAIN-KEYWORD,microsoft')
        self.assertEqual(exclude_covered([rule], white), [rule])
        out, skipped = render('covered', iter([rule]), purpose='block', no_resolve='keep', whitelist=iter(white))
        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt', 'fin-surge-ds.txt'):
            self.assertEqual(out[name], '# covered rules: 0\n')
        self.assertEqual(out['fin.yaml'], '# covered rules: 0\npayload:\n')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], ['@@/^.*microsoft.*$/', '/^.*microsoft.*$/'])
        self.assertEqual(skipped, {'fin.txt:DOMAIN-KEYWORD:whitelist-covered': 1,
                                  'fin-surge.txt:DOMAIN-KEYWORD:whitelist-covered': 1,
                                  'fin-qx.txt:DOMAIN-KEYWORD:whitelist-covered': 1,
                                  'fin.yaml:DOMAIN-KEYWORD:whitelist-covered': 1,
                                  'fin-surge-ds.txt:DOMAIN-KEYWORD': 1,
                                  'whitelist-covered:DOMAIN-KEYWORD': 1})

    def test_converted_white_compares_actual_raw_regex_and_keeps_different_matchers(self):
        rules = [Rule('DOMAIN-REGEX', 'microsoft', domain_source='mihomo'),
                 Rule('DOMAIN-REGEX', '^microsoft$', domain_source='mihomo')]
        white = parse_whitelist('DOMAIN-KEYWORD,microsoft')
        self.assertEqual(exclude_covered(rules, white), rules)
        out, skipped = render('raw', rules, purpose='block', no_resolve='keep', whitelist=white)
        self.assertEqual(out['fin.yaml'], '# raw rules: 1\npayload:\n  - "DOMAIN-REGEX,^microsoft$"\n')
        self.assertEqual(skipped['fin.yaml:DOMAIN-REGEX:whitelist-covered'], 1)
        self.assertEqual(skipped['whitelist-covered:DOMAIN-REGEX'], 1)
        self.assertEqual(skipped['fin.txt:DOMAIN-REGEX'], 2)
        self.assertNotIn('fin.yaml:DOMAIN-REGEX', skipped)
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                         ['@@/^.*microsoft.*$/', '/microsoft/', '/^microsoft$/'])

    def test_allow_and_one_shot_white_filter_routes_but_keep_dns_block_and_exceptions(self):
        blocked = Rule('DOMAIN', 'ads.example.org')
        allowed = Rule('DOMAIN-SUFFIX', 'example.org', allow=True)
        white = Rule('DOMAIN', 'white.example.net')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    out, skipped = render('allow', iter([blocked, allowed]), purpose=purpose, no_resolve=mode,
                                          whitelist=iter([white]))
                    for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                        self.assertEqual(out[name], '# allow rules: 0\n')
                    self.assertEqual(out['fin.yaml'], '# allow rules: 0\npayload:\n')
                    self.assertEqual(skipped['whitelist-covered:DOMAIN'], 1)
                    self.assertEqual(skipped['fin.yaml:DOMAIN:whitelist-covered'], 1)
                    self.assertNotIn('whitelist-covered:DOMAIN-SUFFIX', skipped)
                    if purpose == 'block':
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                         ['@@||example.org^', '@@|white.example.net|', '0.0.0.0 ads.example.org'])
                    else:
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                         ['! No AdBlock rules for non-advertising group.'])

    def test_native_white_does_not_expand_case_or_root_dot_through_surge_projection(self):
        pairs = ((Rule('DOMAIN', 'ads.example.org'), Rule('DOMAIN', 'ads.example.org', domain_source='mihomo')),
                 (Rule('DOMAIN', 'ads.example.org'), Rule('DOMAIN', 'ads.example.org.', domain_source='mihomo')),
                 (Rule('DOMAIN-KEYWORD', 'ads'), Rule('DOMAIN-KEYWORD', 'ads', domain_source='mihomo')),
                 (Rule('DOMAIN-WILDCARD', '*.*'), Rule('DOMAIN-WILDCARD', '*.*', domain_source='mihomo')))
        for rule, white in pairs:
            with self.subTest(rule=rule, white=white):
                self.assertEqual(exclude_covered([rule], [white]), [rule])
                out, skipped = render('scope', [rule], purpose='proxy', no_resolve='keep', whitelist=[white])
                self.assertEqual(out['fin.txt'], '# scope rules: 1\n' + rule.kind + ',' + rule.value + '\n')
                self.assertNotIn('fin.txt:' + rule.kind + ':whitelist-covered', skipped)
                self.assertNotIn('whitelist-covered:' + rule.kind, skipped)

    def test_root_dot_counterexamples_and_one_way_wildcard_positive_keep_native_text(self):
        pairs = (('DOMAIN-WILDCARD', '*.*', '*.*', 'localhost.', True),
                 ('DOMAIN-WILDCARD', '*.123.*', '*.123.*', 'cdn.123.', True),
                 ('DOMAIN', 'localhost.', '*.*', 'localhost.', True),
                 ('DOMAIN-WILDCARD', 'windows-*.net', 'windows-*.net', 'windows-abc.net', False),
                 ('DOMAIN', 'windows-abc.net.', 'windows-*.net', 'windows-abc.net.', False),
                 ('DOMAIN-SUFFIX', 'windows-abc.net', 'windows-*.net', 'x.windows-abc.net', True))
        for kind, value, pattern, host, kept in pairs:
            rule = Rule(kind, value, domain_source='mihomo')
            white = parse_whitelist('DOMAIN-WILDCARD,' + pattern)
            self.assertTrue(fnmatchcase(host.encode(), value.encode()) if kind == 'DOMAIN-WILDCARD' else
                            host == value if kind == 'DOMAIN' else host.endswith('.' + value))
            self.assertEqual(fnmatchcase(host.removesuffix('.'), pattern), not kept)
            self.assertEqual(exclude_covered([rule], white), [rule] if kept else [])
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(kind=kind, value=value, purpose=purpose, mode=mode):
                        out, skipped = render('root', [rule], purpose=purpose, no_resolve=mode, whitelist=white)
                        self.assertEqual(out['fin.yaml'], '# root rules: ' +
                                         ('1\npayload:\n  - ' + json.dumps(kind + ',' + value) + '\n' if kept else '0\npayload:\n'))
                        self.assertEqual(skipped.get('fin.yaml:' + kind + ':whitelist-covered', 0), int(not kept))
                        if kept:
                            self.assertNotIn('whitelist-covered:' + kind, skipped)
                        if purpose == 'block':
                            self.assertTrue(any(line.startswith('@@') for line in out['fin-adb.txt'].splitlines()[7:]))
                            self.assertFalse(any(not line.startswith('@@') for line in out['fin-adb.txt'].splitlines()[7:]))
                            self.assertEqual(skipped['fin-adb.txt:' + kind], 1)

    def test_qx_partial_targets_only_identical_or_existing_safe_coverage(self):
        rule = Rule('DOMAIN-KEYWORD', 'xmicrosofty', ('force-cellular',), domain_source='qx')
        white = parse_whitelist('DOMAIN-KEYWORD,microsoft')
        self.assertEqual(exclude_covered([rule], white), [rule])
        out, skipped = render('partial', [rule], purpose='proxy', no_resolve='keep', whitelist=white)
        self.assertEqual(out['fin.txt'], '# partial rules: 0\n')
        self.assertEqual(out['fin.yaml'], '# partial rules: 0\npayload:\n')
        self.assertEqual(out['fin-qx.txt'], '# partial rules: 1\nHOST-KEYWORD,xmicrosofty,LIST\n')
        self.assertEqual(skipped['fin-qx.txt:DOMAIN-KEYWORD:interface-option'], 1)
        self.assertNotIn('whitelist-covered:DOMAIN-KEYWORD', skipped)
        same, diagnostic = render('same', [Rule('DOMAIN-KEYWORD', 'microsoft', ('force-cellular',), domain_source='qx')],
                                  purpose='proxy', no_resolve='keep', whitelist=white)
        self.assertEqual(same['fin-qx.txt'], '# same rules: 0\n')
        self.assertNotIn('fin-qx.txt:DOMAIN-KEYWORD:interface-option', diagnostic)
        self.assertEqual(diagnostic['whitelist-covered:DOMAIN-KEYWORD'], 1)

    def test_generate_all_actual_routes_covered_publishes_empty_dependency_and_disk_bytes(self):
        text = 'HOST-KEYWORD,microsoft\nHOST-KEYWORD,microsoft\n'
        white_text = 'DOMAIN-KEYWORD,microsoft\n'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    (root / 'static/source.list').write_text(text, encoding='utf-8')
                    (root / 'static/white.list').write_text(white_text, encoding='utf-8')
                    inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                    parsed, warnings = parse(text, purpose=purpose)
                    self.assertEqual(warnings, [])
                    self.assertTrue(parsed)
                    self.assertEqual(normalize(exclude_covered(parsed, parse_whitelist(white_text))),
                                     [Rule('DOMAIN-KEYWORD', 'microsoft', domain_source='qx')])
                    configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['static/source.list'], 'whitelist': ['static/white.list']},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('source', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            path.write_bytes(b'old\x00\xff\r\n')
                            old[path] = path.read_bytes()
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                        out = generate(root, lambda url: self.fail(url))
                    self.assertEqual(list(out), [root / group / name for group in ('source', 'child') for name in FILES])
                    self.assertNotIn('frozen', diagnostic.getvalue())
                    self.assertIn('source whitelist-covered:DOMAIN-KEYWORD: 1\n', diagnostic.getvalue())
                    self.assertIn('source fin.yaml:DOMAIN-KEYWORD:whitelist-covered: 1\n', diagnostic.getvalue())
                    for group in ('source', 'child'):
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(out[root / group / name], f'# {group} rules: 0\n')
                        self.assertEqual(out[root / group / 'fin.yaml'], f'# {group} rules: 0\npayload:\n')
                    if purpose == 'block':
                        self.assertEqual(out[root / 'source/fin-adb.txt'].splitlines()[7:],
                                         ['@@/^.*microsoft.*$/', '/^.*microsoft.*$/'])
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    publish(out, root=root)
                    self.assertEqual({path: path.read_bytes() for path in out},
                                     {path: text.encode() for path, text in out.items()})
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                    (root / 'rulesets.json').write_text(json.dumps(configs[-1:]), encoding='utf-8')
                    published = {path: path.read_bytes() for path in out}
                    with self.assertRaisesRegex(ValueError, 'No adaptable rules in .*fin.yaml'):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_raw_regex_diagnostics_distinguish_values_duplicates_allow_and_wholly_unsupported(self):
        rules = [Rule('DOMAIN-REGEX', '^ads$'), Rule('DOMAIN-REGEX', '^ads$'),
                 Rule('DOMAIN-REGEX', '^ADS$'), Rule('DOMAIN-REGEX', '^ads$', allow=True),
                 Rule('DEVICE-NAME', '\x00'), Rule('DOMAIN', 'neighbor.example.org')]
        white = parse_whitelist('DOMAIN-REGEX,^ads$')
        normalized = normalize(rules)
        self.assertEqual(len(normalized), 5)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    out, skipped = render('raw', normalized, purpose=purpose, no_resolve=mode, whitelist=white)
                    self.assertEqual(out['fin.yaml'], '# raw rules: 2\npayload:\n  - "DOMAIN-REGEX,^ADS$"\n  - ' +
                                     json.dumps(expected_domain('DOMAIN', 'neighbor.example.org')) + '\n')
                    self.assertEqual(skipped['fin.yaml:DOMAIN-REGEX:whitelist-covered'], 1)
                    self.assertEqual(skipped['fin.yaml:DOMAIN-REGEX'], 1)
                    self.assertEqual(skipped['whitelist-covered:DOMAIN-REGEX'], 1)
                    for name in FILES:
                        self.assertEqual(skipped[name + ':DEVICE-NAME'], 1)
                    self.assertNotIn('whitelist-covered:DEVICE-NAME', skipped)
                    self.assertNotIn('whitelist-covered:DOMAIN', skipped)
                    SurgeRootDotProjectionTests.assert_counts_and_split(self, out, purpose, 'raw')
                    if purpose == 'block':
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                         ['@@/^ads$/', '/^ADS$/', '/^ads$/', '0.0.0.0 neighbor.example.org'])

    def test_keyword_suffix_wildcard_literal_byte_and_unknown_qx_boundaries(self):
        white = parse_whitelist('DOMAIN-KEYWORD,microsoft\nDOMAIN-WILDCARD,windows-*.net\n'
                                'DOMAIN-WILDCARD,windows-??.net\nDOMAIN-WILDCARD,api-[0-9].example.com')
        pairs = (('DOMAIN', 'microsoft.com', False), ('DOMAIN-SUFFIX', 'sub.microsoft.com', False),
                 ('DOMAIN-KEYWORD', 'xmicrosofty', False), ('DOMAIN-WILDCARD', 'microsoft-*.com', False),
                 ('DOMAIN-WILDCARD', 'windows-??.net', True),
                 ('DOMAIN-WILDCARD', 'api-[0-9].example.com', True),
                 ('DOMAIN-SUFFIX', 'windows-abc.net', True), ('DOMAIN-KEYWORD', '广告microsoft', True))
        for kind, value, kept in pairs:
            rule = Rule(kind, value, domain_source='mihomo')
            out, skipped = render('bounds', [rule], purpose='proxy', no_resolve='keep', whitelist=white)
            self.assertEqual(out['fin.yaml'], '# bounds rules: ' +
                             ('1\npayload:\n  - ' + json.dumps(kind + ',' + value, ensure_ascii=False) + '\n'
                              if kept else '0\npayload:\n'))
            self.assertEqual(skipped.get('fin.yaml:' + kind + ':whitelist-covered', 0), int(not kept))
        self.assertTrue(fnmatchcase('windows-é.net'.encode(), b'windows-??.net'))
        self.assertFalse(fnmatchcase('windows-é.net', 'windows-??.net'))
        qx = Rule('DOMAIN-WILDCARD', 'windows-??.net', domain_source='qx')
        out, skipped = render('qx', [qx], purpose='proxy', no_resolve='keep',
                              whitelist=[Rule('DOMAIN-WILDCARD', 'windows-?.net', domain_source='mihomo')])
        self.assertIn('HOST-WILDCARD,windows-??.net,LIST\n', out['fin-qx.txt'])
        self.assertNotIn('fin-qx.txt:DOMAIN-WILDCARD:whitelist-covered', skipped)

    def test_generate_root_dot_negatives_keep_mihomo_same_round_and_disk_with_literal_asn_direction(self):
        matchers = ('DOMAIN,localhost.', 'DOMAIN-WILDCARD,*.*', 'DOMAIN-WILDCARD,*.123.*',
                    'DOMAIN-WILDCARD,windows-*.net', 'DOMAIN,windows-abc.net',
                    'IP-ASN,0', 'IP-ASN,00', 'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24')
        text = 'payload:\n' + ''.join('  - ' + json.dumps(value) + '\n' for value in matchers)
        white_text = 'DOMAIN-WILDCARD,*.*\nDOMAIN-WILDCARD,*.123.*\nDOMAIN-WILDCARD,windows-*.net\n'
        for remote in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(remote=remote, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/source.yaml').write_text(text, encoding='utf-8')
                        (root / 'static/white.list').write_text(white_text, encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['https://example.org/source' if remote else 'static/source.yaml'],
                                    'whitelist': ['https://example.org/white' if remote else 'static/white.list']},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'],
                                    'whitelist': ['https://example.org/white' if remote else 'static/white.list']}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        responses = {'https://example.org/source': text.encode(), 'https://example.org/white': white_text.encode()}
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                            out = generate(root, responses.__getitem__)
                        expected = {'DOMAIN,localhost.', 'DOMAIN-WILDCARD,*.*', 'DOMAIN-WILDCARD,*.123.*',
                                    'IP-ASN,0' + (',no-resolve' if mode == 'add' else ''),
                                    'IP-ASN,00' + (',no-resolve' if mode == 'add' else ''),
                                    'IP-CIDR,192.0.2.0/24' + (',no-resolve' if mode != 'strip' else ''),
                                    'SRC-IP-CIDR,198.51.100.0/24'}
                        self.assertEqual(len(out), 12)
                        self.assertNotIn('whitelist-covered:DOMAIN: ', diagnostic.getvalue())
                        self.assertNotIn('whitelist-covered:DOMAIN-WILDCARD: ', diagnostic.getvalue())
                        for group in ('source', 'child'):
                            products = {name: out[root / group / name] for name in FILES}
                            self.assertEqual({json.loads(line[4:]) for line in products['fin.yaml'].splitlines()[2:]}, expected)
                            self.assertNotIn(group + ' fin.yaml:DOMAIN:whitelist-covered', diagnostic.getvalue())
                            self.assertNotIn(group + ' fin.yaml:DOMAIN-WILDCARD:whitelist-covered', diagnostic.getvalue())
                            readback, warnings = parse(products['fin.yaml'], purpose=purpose)
                            self.assertEqual(warnings, [])
                            self.assertTrue(any(rule.value == 'localhost.' and rule.domain_source == 'mihomo' for rule in readback))
                            self.assertEqual({rule.value for rule in readback if rule.kind == 'IP-ASN'}, {'0', '00'})
                            SurgeRootDotProjectionTests.assert_counts_and_split(self, products, purpose, group)
                        publish(out, root=root)
                        self.assertEqual({path: path.read_bytes() for path in out}, {path: text.encode() for path, text in out.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        (root / 'rulesets.json').write_text(json.dumps(configs[-1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                            disk = generate(root, responses.__getitem__)
                        self.assertEqual(disk, {path: text for path, text in out.items() if path.parent.name == 'child'})
                        publish(disk, root=root)

    def test_generate_mixed_unsupported_unavailable_partial_source_and_allow_only_keep_freeze_boundaries(self):
        for scenario in ('unsupported', '404-covered', '404-partial', 'allow-only'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(scenario=scenario, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        text = ('@@||safe.example.org^\n' if scenario == 'allow-only' else
                                'HOST-KEYWORD,microsoft\n' + ('HOST,keep.example.net\n' if scenario == '404-partial' else ''))
                        (root / 'static/source.list').write_text(text, encoding='utf-8')
                        (root / 'static/white.list').write_text('DOMAIN-KEYWORD,microsoft\n', encoding='utf-8')
                        sources = ['static/source.list']
                        if scenario == 'unsupported':
                            (root / 'static/native.yaml').write_text('payload:\n  - "DEVICE-NAME,\\u0000"\n', encoding='utf-8')
                            self.assertEqual(parse((root / 'static/native.yaml').read_text(), purpose=purpose),
                                             ([Rule('DEVICE-NAME', '\x00')], []))
                            sources.append('static/native.yaml')
                        elif scenario.startswith('404-'):
                            sources.append('https://example.org/missing')
                        configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': sources, 'whitelist': ['static/white.list']},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'], 'whitelist': []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for group in ('source', 'child'):
                            (root / group).mkdir()
                            for name in FILES:
                                path = root / group / name
                                path.write_bytes(b'old\x00\xff\r\n')
                                old[path] = path.read_bytes()
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        def missing(url):
                            raise RuntimeError('missing') from HTTPError(url, 404, 'missing', {}, None)
                        with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            out = generate(root, missing)
                        published = scenario == '404-partial' or scenario == 'allow-only' and purpose == 'block'
                        self.assertEqual(len(out), 12 if published else 0)
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        if scenario.startswith('404-'):
                            self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                        if not published and scenario != 'allow-only':
                            self.assertIn('source: no routable rules; frozen', diagnostic.getvalue())
                        publish(out, root=root)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        if not published:
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                        elif scenario == '404-partial':
                            for group in ('source', 'child'):
                                self.assertEqual(out[root / group / 'fin.yaml'], f'# {group} rules: 1\npayload:\n  - "DOMAIN,keep.example.net"\n')
                        else:
                            self.assertEqual(out[root / 'source/fin-adb.txt'].splitlines()[7:], ['@@/^.*microsoft.*$/', '@@||safe.example.org^'])

    def test_generated_white_uses_current_target_bytes_and_disk_format_without_sidecar(self):
        for white_file in ('fin.txt', 'fin.yaml'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(white_file=white_file, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/white.list').write_text('DOMAIN-KEYWORD,microsoft\n', encoding='utf-8')
                        (root / 'static/source.list').write_text('HOST-KEYWORD,microsoft\n', encoding='utf-8')
                        configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['static/white.list'], 'whitelist': []},
                                   {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['static/source.list'], 'whitelist': ['white/' + white_file]}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                            out = generate(root, lambda url: self.fail(url))
                        self.assertEqual(len(out), 12)
                        self.assertEqual(out[root / 'white/fin.txt'], '# white rules: 1\nDOMAIN-KEYWORD,microsoft\n')
                        self.assertEqual(out[root / 'white/fin.yaml'], '# white rules: 1\npayload:\n  - "DOMAIN-REGEX,microsoft"\n')
                        expected = ('# source rules: 0\npayload:\n' if white_file == 'fin.txt' else
                                    '# source rules: 1\npayload:\n  - "DOMAIN-KEYWORD,microsoft"\n')
                        self.assertEqual(out[root / 'source/fin.yaml'], expected)
                        self.assertEqual('source whitelist-covered:DOMAIN-KEYWORD: 1\n' in diagnostic.getvalue(),
                                         white_file == 'fin.txt')
                        publish(out, root=root)
                        published = {path: path.read_bytes() for path in out}
                        (root / 'rulesets.json').write_text(json.dumps(configs[-1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 14, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in out.items() if path.parent.name == 'source'})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_covered_products_still_use_strict_white_paths_static_protection_and_real_rollback(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    (root / 'static/source.list').write_text('HOST-KEYWORD,microsoft\n', encoding='utf-8')
                    white = root / 'static/white.list'
                    white.write_text('DOMAIN-KEYWORD,microsoft\n', encoding='utf-8')
                    config = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['static/source.list'], 'whitelist': ['static/white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'source').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'source' / name
                        path.write_bytes(b'old\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()):
                        out = generate(root, lambda url: self.fail(url))
                    self.assertEqual(len(out), 6)
                    barrier = root / 'barrier'
                    barrier.write_bytes(b'parent is a file')
                    with self.assertRaises(OSError):
                        publish({root / 'source/fin.txt': out[root / 'source/fin.txt'],
                                 barrier / 'fin.yaml': 'payload:\n'}, root=root)
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    self.assertEqual(barrier.read_bytes(), b'parent is a file')
                    with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                        publish({white: 'DOMAIN,changed.example.org\n'}, root=root)
                    with self.assertRaisesRegex(ValueError, 'Output path escapes root'):
                        publish({root.parent / 'outside.txt': 'changed'}, root=root)
                    for value in ('DOMAIN,bad..example\n', '', '<html>denied</html>'):
                        white.write_text(value, encoding='utf-8')
                        with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                            generate(root, lambda url: self.fail(url))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        self.assertEqual(white.read_text(encoding='utf-8'), value)
                    white.unlink()
                    with self.assertRaises(FileNotFoundError):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
