import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


KINDS = ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX')
R3_CASES = (('^(?(?:ads)ads|other)$', True),
            ('^(?(?>ads)ads|other)$', True),
            ('^(?(?:a|b|c)ads|other)$', True),
            ('^(?(?>a|b|c)ads|other)$', True),
            ('^(?(?:ads)(?i)ads|other)$', False),
            ('^(?(?>ads)ads|other|third)$', False))
R2_CASES = (('^(?(?=ads)(?i)ads|other)$', False),
            ('^(?(missing)(?i)ads|other)$', False),
            ('^(a)(?(1)(?i)ads|other)$', True),
            ('^(?(later)(?i)ads|other)(?<later>x)$', True),
            ('^(?(?=ads)(?:(?i)ads)|other)$', True))


def check_generated_regex(testcase, valid, invalid):
    for purpose in ('block', 'direct', 'proxy'):
        for mode in ('keep', 'add', 'strip'):
            with testcase.subTest(valid=valid, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                (root / 'static/input.yaml').write_bytes(('﻿payload:\r\n  - ' +
                    json.dumps('DOMAIN-REGEX,' + valid) + '\r\n').encode('utf-8'))
                (root / 'static/blocked.list').write_bytes(('DOMAIN-REGEX,' + valid +
                    '\r\nDOMAIN-REGEX,^other$\r\n').encode('utf-8'))
                static = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                            'sources': sources, 'whitelist': white} for group, sources, white in (
                    ('parent', ['static/input.yaml'], []),
                    ('sourcechild', ['parent/fin.yaml'], []),
                    ('whitechild', ['static/blocked.list'], ['parent/fin.yaml']),
                    ('cleared', ['static/input.yaml'], ['parent/fin.yaml']))]
                config_path = root / 'rulesets.json'
                config_path.write_text(json.dumps(configs), encoding='utf-8')
                old = {}
                for config in configs:
                    (root / config['name']).mkdir()
                    for name in FILES:
                        path = root / config['name'] / name
                        old[path] = b'old complete\r\n\0' + name.encode('ascii')
                        path.write_bytes(old[path])
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as logs:
                    clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                    outputs = generate(root, testcase.fail)
                testcase.assertEqual({path: path.read_bytes() for path in old}, old)
                testcase.assertNotIn(': line ', logs.getvalue())
                testcase.assertNotIn('frozen', logs.getvalue())
                rows = {'parent': ['DOMAIN-REGEX,' + valid], 'sourcechild': ['DOMAIN-REGEX,' + valid],
                        'whitechild': ['DOMAIN-REGEX,^other$'], 'cleared': []}
                for group, matchers in rows.items():
                    text = outputs[root / group / 'fin.yaml']
                    testcase.assertEqual(text, f'# {group} rules: {len(matchers)}\npayload:\n' +
                                     ''.join('  - ' + json.dumps(row) + '\n' for row in matchers))
                    testcase.assertEqual(parse(text, purpose=purpose),
                                     ([Rule('DOMAIN-REGEX', row.partition(',')[2]) for row in matchers], []))
                    for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                        testcase.assertEqual(outputs[root / group / name], f'# {group} rules: 0\n')
                    testcase.assertEqual(outputs[root / group / 'fin-adb.txt'].splitlines()[6:], ['! Total count: 0'] +
                                     ([] if purpose == 'block' else ['! No AdBlock rules for non-advertising group.']))
                testcase.assertEqual(len(outputs), 24)
                publish(outputs, root=root)
                testcase.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                parent = {root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in FILES}
                testcase.assertEqual(parse_whitelist((root / 'parent/fin.yaml').read_text(encoding='utf-8')),
                                 [Rule('DOMAIN-REGEX', valid)])
                config_path.write_text(json.dumps(configs[1:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_logs:
                    clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                    disk = generate(root, testcase.fail)
                testcase.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name != 'parent'})
                testcase.assertNotIn(': line ', disk_logs.getvalue())
                testcase.assertNotIn('frozen', disk_logs.getvalue())
                publish(disk, root=root)
                testcase.assertEqual({path: path.read_bytes() for path in parent}, parent)
                testcase.assertEqual({path: path.read_bytes() for path in static}, static)
    for role in ('source', 'white', 'disk-source', 'disk-white', 'remote'):
        with testcase.subTest(invalid=invalid, role=role), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            document = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + invalid) + '\n').encode('utf-8')
            bad = 'disk/fin.yaml' if role.startswith('disk') else 'static/bad.yaml'
            path = root / bad
            path.parent.mkdir(exist_ok=True)
            path.write_bytes((b'# disk rules: 1\n' if role.startswith('disk') else b'') + document)
            (root / 'static/good.list').write_bytes(b'DOMAIN,keep.example.org\n')
            config = [{'name': 'child', 'purpose': 'block', 'no_resolve': 'keep',
                       'sources': ['https://example.org/bad.yaml' if role == 'remote' else
                                   bad if role.endswith('source') else 'static/good.list'],
                       'whitelist': [bad] if role.endswith('white') else []}]
            (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
            (root / 'child').mkdir()
            for name in FILES:
                (root / 'child' / name).write_bytes(b'old complete\r\n\0' + name.encode('ascii'))
            before = {item: item.read_bytes() for item in root.rglob('*') if item.is_file()}
            with contextlib.redirect_stderr(io.StringIO()):
                if role == 'remote':
                    outputs = generate(root, lambda url: document)
                    testcase.assertEqual(outputs, {})
                    publish(outputs, root=root)
                else:
                    with testcase.assertRaisesRegex(ValueError, 'No adaptable rules|Invalid whitelist'):
                        generate(root, testcase.fail)
            testcase.assertEqual({item: item.read_bytes() for item in before}, before)


class Regexp2ConditionalTests(unittest.TestCase):
    def test_noncapture_expression_condition_preserves_matcher(self):
        value = '^(?(?:ads)ads|other)$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_atomic_expression_condition_preserves_matcher(self):
        value = '^(?(?>ads)ads|other)$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_condition_headers_alternation_and_forbidden_neighbors(self):
        valid = ('^(?(ads|other|third)ads|other)$', '^(?(?=ads)ads|other)$',
                 '^(?(?!ads)ads|other)$', '^(?(?<=ads)ads|other)$', '^(?(?<!ads)ads|other)$',
                 '^(?(?:ads)(?:(?i)ads)|other)$', '^(?(?>(?i)ads)ads|other)$',
                 '^(?((?(?=ads)ads|other))ads|other)$',
                 r'^(?(?:(a))ads|other)\1$', r'^(?(?>(a))ads|other)\1$')
        invalid = ('^(?(?:ads)ads|other|third)$', '^(?(?:ads)+ads|other)$',
                   '^(?(?>ads){1}ads|other)$', '^(?(?:ads)(?#note)+ads|other)$',
                   '^(?(?:ads)ads|(?i:other))$', '^(?(?i:ads)ads|other)$',
                   '^(?(?#ads)ads|other)$', '^(?(?<word>ads)ads|other)$',
                   "^(?(?'word'ads)ads|other)$", '^(?(?:ads)ads|other$',
                   r'^(?(?:ads)ads|other)\1$', r'^(?(?:(a))ads|other)\2$')
        for accepted, values in ((True, valid), (False, invalid)):
            for value in values:
                with self.subTest(value=value):
                    self.assertEqual(parse('DOMAIN-REGEX,' + json.dumps(value), purpose='block'),
                                     ([Rule('DOMAIN-REGEX', value)], []) if accepted else
                                     ([], [f'line 1: invalid DOMAIN-REGEX {value}']))
        self._check_scalar_forms(R3_CASES)
        self._check_logical(R3_CASES[:2] + R3_CASES[4:])

    def test_condition_headers_do_not_expand_dns_or_url_support(self):
        for value, _ in R3_CASES[:4]:
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('keep', 'add', 'strip'):
                    for kind in KINDS:
                        parsed, messages = parse(kind + ',' + value, purpose=purpose)
                        self.assertEqual(messages, [])
                        outputs, skipped = render('conditional', parsed, purpose=purpose, no_resolve=mode)
                        self.assertEqual(outputs['fin.yaml'], '# conditional rules: 1\npayload:\n  - ' +
                                         json.dumps(kind + ',' + value) + '\n')
                        self.assertEqual(skipped, {name + ':' + kind: 1 for name in FILES if name != 'fin.yaml'})
            for consumer in ('allow', 'white'):
                outputs, skipped = render('conditional', [Rule('DOMAIN-REGEX', value, allow=consumer == 'allow')],
                                          whitelist=[Rule('DOMAIN-REGEX', value)] if consumer == 'white' else [],
                                          purpose='block', no_resolve='keep')
                self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:], ['! Total count: 0'])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1 if consumer == 'allow' else 2)
        for value in (R3_CASES[0][0], R3_CASES[1][0], R2_CASES[0][0]):
            self.assertEqual(parse('URL-REGEX,' + value, purpose='proxy'),
                             ([], [f'line 1: invalid URL-REGEX {value}']))
        value = r'^(?:ads|other)$'
        self.assertEqual(parse('URL-REGEX,' + value, purpose='proxy'), ([Rule('URL-REGEX', value)], []))

    def test_condition_header_white_generation_and_nonempty_disk_readback(self):
        for value, _ in R3_CASES[:2]:
            self.assertEqual(parse_whitelist('DOMAIN-REGEX,' + value), [Rule('DOMAIN-REGEX', value)])
            check_generated_regex(self, value, R3_CASES[4][0])

    def test_expression_direct_options_reject_matcher_and_keep_neighbor(self):
        value = '^(?(?=ads)(?i)ads|other)$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value + '\nDOMAIN,keep.example.org', purpose='block'),
                         ([Rule('DOMAIN', 'keep.example.org')],
                          [f'line 1: invalid DOMAIN-REGEX {value}']))

    def test_undefined_word_condition_applies_expression_options_guard(self):
        value = '^(?(missing)(?i)ads|other)$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([], [f'line 1: invalid DOMAIN-REGEX {value}']))

    def test_options_follow_direct_parent_and_complete_capture_set(self):
        valid = (R2_CASES[2][0], R2_CASES[3][0], R2_CASES[4][0],
                 '^(?(?=ads)((?i)ads)|other)$', '^(?(?=ads)(?=(?i)ads)ads|other)$',
                 '^(?(?=(?i)ads)ads|other)$', '^(?(?!(?i)ads)ads|other)$',
                 '^(?(?<=(?i)ads)ads|other)$', '^(?(?<!(?i)ads)ads|other)$',
                 '^(?(ads(?i))ads|other)$', '^(?(missing)ads|other)$',
                 '^(?(?=ads)(?<word>(?i)ads)|other)$',
                 '^(a)(?(1)(?-i:ads)|(?i:other))$',
                 '^(?(later)ads|(?-i)other)(?<later>x)$',
                 '^(?(1)(?i)ads|other)(a)$', '^(?(0)(?i)ads|other)$',
                 r'^(?(missing)(a)|(b))\2$', r'^(?(?=(a))(b)|(c))\3$',
                 r'(?n)^(?(?=ads)(?<word>(?i)ads)|other)\1\k<word>$',
                 '(?x)^(?(?= ads)(?#note)(?: (?i) ads)|other)$',
                 '^(?(?=ads)(?(later)(?i)ads|other)|other)(?<later>x)$')
        invalid = ('^(?(?i:ads)ads|other)$', '^(?(?-i)ads|other)$',
                   '^(?(?=ads)(?i:ads)|other)$', '^(?(?=ads)(?-i)ads|other)$',
                   '^(?(?=ads)ads|(?i)other)$', '^(?(?=ads)ads(?-i:ads)|other)$',
                   '^(?(?=ads)ads|other(?i:more))$', '^(?(missing)ads|(?i)other)$',
                   '(?x)^(?(?=ads)(?#note) (?i)ads|other)$',
                   '^(?(?=ads)(?(?=other)(?i)ads|other)|other)$',
                   r'^(?(missing)ads|other)\1$', '^(?(1)ads|other)$',
                   '^(a)(?(2)(?i)ads|other)$', '^(?(2147483648)ads|other)$')
        for accepted, values in ((True, valid), (False, invalid)):
            for value in values:
                for kind in KINDS:
                    with self.subTest(kind=kind, value=value):
                        self.assertEqual(parse(kind + ',' + json.dumps(value), purpose='proxy'),
                                         ([Rule(kind, value)], []) if accepted else
                                         ([], [f'line 1: invalid {kind} {value}']))

    def _check_scalar_forms(self, cases, depth=0):
        for atom, accepted in cases:
            value = '(?:' * depth + atom + ')' * depth
            for kind in KINDS:
                matcher = kind + ',' + value
                sources = [(kind + ',' + field + '\nDOMAIN,keep.example.org', 1, 'surge')
                           for field in (value, "'" + value + "'", json.dumps(value))]
                sources += [('﻿' + header + ':\r\n  # context\r\n  - ' + scalar +
                             '\r\n  - DOMAIN,keep.example.org\r\n', 3, 'mihomo')
                            for header in ('payload', 'rules')
                            for scalar in (matcher, "'" + matcher + "'", json.dumps(matcher))]
                for source, line, domain_source in sources:
                    with self.subTest(depth=depth, value=atom, kind=kind, source=source[:32]):
                        expected = ([Rule(kind, value)] if accepted else []) + [
                            Rule('DOMAIN', 'keep.example.org', domain_source=domain_source)]
                        self.assertEqual(parse(source, purpose='proxy'),
                                         (expected, [] if accepted else [f'line {line}: invalid {kind} {value}']))

    def test_three_kinds_ordinary_quotes_native_headers_and_scalars(self):
        self._check_scalar_forms(R2_CASES)

    def _check_logical(self, cases, depth=0):
        for atom, accepted in cases:
            value = '(?:' * depth + atom + ')' * depth
            for kind in KINDS:
                leaf = f'({kind},{value})'
                for operator in ('AND', 'OR', 'NOT'):
                    expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(IP-CIDR,203.0.113.0/24,no-resolve))'
                    for native in (False, True):
                        matcher = operator + ',' + expression
                        source = ('payload:\n  - ' + json.dumps(matcher) + '\n  - DOMAIN,keep.example.org\n'
                                  if native else matcher + '\nDOMAIN,keep.example.org')
                        for purpose in ('block', 'direct', 'proxy'):
                            rules, messages = parse(source, purpose=purpose)
                            expected = ([Rule(operator, expression, native_fields=native)] if accepted else []) + [
                                Rule('DOMAIN', 'keep.example.org', domain_source='mihomo' if native else 'surge')]
                            self.assertEqual((rules, messages), (expected, [] if accepted else
                                             [f'line {2 if native else 1}: invalid logical expression {expression}']))
                            for mode in ('keep', 'add', 'strip'):
                                with self.subTest(depth=depth, kind=kind, atom=atom, operator=operator,
                                                  native=native, purpose=purpose, mode=mode):
                                    outputs, skipped = render('conditional', iter(rules), purpose=purpose, no_resolve=mode)
                                    wanted = matcher.replace(',no-resolve', '') if mode == 'strip' else matcher
                                    rows = [json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]]
                                    self.assertCountEqual(rows, ([wanted] if accepted else []) + ['DOMAIN,keep.example.org'])
                                    restored, warnings = parse(outputs['fin.yaml'], purpose=purpose)
                                    self.assertEqual(warnings, [])
                                    if accepted:
                                        self.assertIn(Rule(operator, wanted.partition(',')[2], native_fields=True), restored)
                                        for name in FILES:
                                            if name != 'fin.yaml':
                                                self.assertEqual(skipped[name + ':' + operator], 1)

    def test_logical_modes_and_purposes_revalidate_the_complete_expression(self):
        self._check_logical(R2_CASES[:3])

    def test_white_identity_normalization_and_target_support_remain_separate(self):
        valid = R2_CASES[4][0]
        invalid = R2_CASES[0][0]
        source = 'DOMAIN-REGEX,' + valid + '\nDOMAIN-REGEX,' + invalid + '\nDOMAIN,keep.example.org'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            white = parse_whitelist(source)
        self.assertEqual(white, [Rule('DOMAIN-REGEX', valid), Rule('DOMAIN', 'keep.example.org')])
        self.assertEqual([str(item.message) for item in caught], [f'line 2: invalid DOMAIN-REGEX {invalid}'])
        self.assertEqual(normalize(iter(reversed(white + white))), list(reversed(white)))
        different = Rule('DOMAIN-REGEX', '^(?(?=ads)((?i)ads)|other)$')
        self.assertEqual(exclude_covered(iter([*white, different]), iter(white)), [different])
        self.assertEqual(parse_whitelist('PROCESS-NAME-REGEX,' + valid + '\nPROCESS-PATH-REGEX,' + valid), [])
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('keep', 'add', 'strip'):
                for kind in KINDS:
                    outputs, skipped = render('conditional', [Rule(kind, valid)], purpose=purpose, no_resolve=mode)
                    self.assertEqual(outputs['fin.yaml'], '# conditional rules: 1\npayload:\n  - ' + json.dumps(kind + ',' + valid) + '\n')
                    self.assertEqual(skipped, {name + ':' + kind: 1 for name in FILES if name != 'fin.yaml'})
                    for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                        self.assertEqual(outputs[name], '# conditional rules: 0\n')
                    self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:], ['! Total count: 0'] +
                                     ([] if purpose == 'block' else ['! No AdBlock rules for non-advertising group.']))

    def test_deep_conditions_keep_parent_scopes_captures_and_original_limits(self):
        script = r'''
import sys
sys.path.insert(0, sys.argv[1])
from tests.test_regexp2_conditional_regressions import Regexp2ConditionalTests, R2_CASES, R3_CASES
from formats import render
from rules import Rule, parse
assert sys.getrecursionlimit() == 1000
case = Regexp2ConditionalTests()
depth = int(sys.argv[2])
case._check_scalar_forms(R2_CASES + R3_CASES[:2] + R3_CASES[4:], depth)
for atom, accepted in R3_CASES[:2] + R2_CASES[:1]:
    value = '(?:' * depth + atom + ')' * depth
    expression = f'((DOMAIN-REGEX,{value}),(IP-CIDR,203.0.113.0/24,no-resolve))'
    source = 'AND,' + expression
    parsed, messages = parse(source, purpose='proxy')
    assert parsed == ([Rule('AND', expression)] if accepted else [])
    assert messages == ([] if accepted else [f'line 1: invalid logical expression {expression}'])
    if accepted:
        for mode in ('keep', 'add', 'strip'):
            outputs, _ = render('conditional', parsed, purpose='proxy', no_resolve=mode)
            restored, messages = parse(outputs['fin.yaml'], purpose='proxy')
            assert messages == [] and len(restored) == 1
assert sys.getrecursionlimit() == 1000
'''
        root = Path(__file__).resolve().parents[1]
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root), str(depth)],
                                        cwd=root, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


    def test_generate_publish_nonempty_source_white_disk_bytes_and_invalid_freeze(self):
        check_generated_regex(self, R2_CASES[4][0], R2_CASES[0][0])

