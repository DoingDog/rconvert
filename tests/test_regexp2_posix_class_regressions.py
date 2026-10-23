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
CASES = ((r'^[[:alpha:](]$', True), (r'^[[:alpha:]-!]$', False),
         (r'^[[:alpha:]()]\1$', False))
PRESCAN_CASES = ((r'^[a-\-[][:alpha:]]](a)\1$', True),
                 (r'^[a-\-[][:alpha:](?n)]](a)\1$', False),
                 (r'^[a-\-[][:alpha:](?n)]](?<word>a)\k<word>$', True))
PREFIX_CASES = ((r'^[a-\-[][:alpha:](?n)(?-n]](a)\1$', True),
                (r'^[a-\-[][:alpha:](?(?#x)]](a)\1$', True),
                (r'^[a-\-[][:alpha:](?n(a))]](b)\2$', False),
                (r'^[a-\-[][:alpha:](?n(a))]](b)\1$', True),
                (r'^[a-\-[][:alpha:](?n]](a)\1$', False))
NUMERIC_CASES = tuple((r'^[a-\-[][:alpha:](?<' + digits + '>)]](a)' + reference + '$', valid)
                      for digits, valid in (('2147483647', True), ('2147483648', False), ('9' * 5001, False),
                                            ('0', True), ('01', True), ('02147483648', True),
                                            ('0' * 5001 + '2147483648', True))
                      for reference in ('', r'\1')) + tuple(
    (r'^[[:alpha:](?<' + digits + '>)](a)' + reference + '$', True)
    for digits in ('2147483648', '9' * 5001) for reference in ('', r'\1')) + tuple(
    ('^(?<' + digits + '>)(a)$', valid) for digits, valid in
    (('2147483647', True), ('2147483648', False), ('9' * 5001, False), ('02147483648', False), ('0', False))) + (
    (r'^(?<1>a)(?<01>b)\1$', True),)


class Regexp2PosixClassTests(unittest.TestCase):
    def test_prescan_numeric_overflow_rejects_referenced_class_literal(self):
        value = r'^[a-\-[][:alpha:](?<2147483648>)]](a)\1$'
        self.assertEqual(len(value), 40)
        self.assertEqual([index for index, char in enumerate(value) if char == '\\'], [4, 37])
        self.assertEqual(
            parse('DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example', purpose='block'),
            ([Rule('DOMAIN', 'neighbor.example')], [f'line 1: invalid DOMAIN-REGEX {value}']),
        )

    def test_prescan_numeric_overflow_rejects_unreferenced_class_literal(self):
        value = r'^[a-\-[][:alpha:](?<2147483648>)]](a)$'
        self.assertEqual(
            parse('DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example', purpose='block'),
            ([Rule('DOMAIN', 'neighbor.example')], [f'line 1: invalid DOMAIN-REGEX {value}']),
        )

    def test_capture_slots_follow_prescan_class_boundary(self):
        value = PRESCAN_CASES[1][0]
        self.assertEqual(len(value), 29)
        self.assertEqual([index for index, char in enumerate(value) if char == '\\'], [4, 26])
        self.assertEqual(
            parse('DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example', purpose='block'),
            ([Rule('DOMAIN', 'neighbor.example')], [f'line 1: invalid DOMAIN-REGEX {value}']),
        )

    def test_prescan_applies_options_prefix_before_nonheader_character(self):
        value = r'^[a-\-[][:alpha:](?n)(?-n]](a)\1$'
        self.assertEqual(
            parse('DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example', purpose='block'),
            ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'neighbor.example')], []),
        )

    def test_prescan_comment_clears_conditional_capture_suppression(self):
        value = r'^[a-\-[][:alpha:](?(?#x)]](a)\1$'
        self.assertEqual(
            parse('DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example', purpose='block'),
            ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'neighbor.example')], []),
        )

    def test_pending_range_survives_escaped_hyphen_before_subtraction(self):
        valid = r'^[a-\-[:alpha:]]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + valid, purpose='block'),
                         ([Rule('DOMAIN-REGEX', valid)], []))
        value = r'^[a-\-[:alpha:]()]\1$'
        for field in (value, "'" + value + "'"):
            with self.subTest(field=field):
                self.assertEqual(
                    parse('DOMAIN-REGEX,' + field + '\nDOMAIN,neighbor.example', purpose='block'),
                    ([Rule('DOMAIN', 'neighbor.example')], [f'line 1: invalid DOMAIN-REGEX {value}']),
                )

    def test_unquoted_scalar_keeps_literal_open_parenthesis(self):
        value = r'^[[:alpha:](]$'
        self.assertEqual(
            parse('DOMAIN-REGEX,' + value + '\nDOMAIN,neighbor.example', purpose='block'),
            ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'neighbor.example')], []),
        )

    def test_complete_token_keeps_literal_range_endpoint(self):
        value = r'^[[:alpha:]-!]$'
        self.assertEqual(
            parse("DOMAIN-REGEX,'" + value + "'\nDOMAIN,neighbor.example", purpose='block'),
            ([Rule('DOMAIN', 'neighbor.example')], [f'line 1: invalid DOMAIN-REGEX {value}']),
        )

    def test_class_parentheses_do_not_allocate_capture_slots(self):
        value = r'^[[:alpha:]()]\1$'
        self.assertEqual(
            parse("DOMAIN-REGEX,'" + value + "'\nDOMAIN,neighbor.example", purpose='block'),
            ([Rule('DOMAIN', 'neighbor.example')], [f'line 1: invalid DOMAIN-REGEX {value}']),
        )

    def _check_scalar_matrix(self, depth, cases=CASES, kinds=KINDS):
        for kind in kinds:
            for atom, valid in cases:
                value = '(?:' * depth + atom + ')' * depth
                matcher = kind + ',' + value
                sources = [(f'# scope\n{kind},{field},PROXY\nDOMAIN,neighbor.example,PROXY\n', 2, 'surge')
                           for field in (value, "'" + value + "'", json.dumps(value))]
                sources += [(f'﻿{header}:\r\n  # scope\r\n  - {scalar}\r\n  - DOMAIN,neighbor.example\r\n',
                             3, 'mihomo') for header in ('payload', 'rules')
                            for scalar in (matcher, "'" + matcher + "'", json.dumps(matcher))]
                for source, line, domain_source in sources:
                    neighbor = Rule('DOMAIN', 'neighbor.example', domain_source=domain_source)
                    expected = ([Rule(kind, value)] if valid else []) + [neighbor]
                    with self.subTest(depth=depth, kind=kind, value=value, source=source[:40]):
                        parsed, messages = parse(source, purpose='proxy')
                        self.assertEqual((parsed, messages),
                                         (expected, [] if valid else [f'line {line}: invalid {kind} {value}']))
                        outputs, _ = render('posix', parsed, purpose='proxy', no_resolve='keep')
                        self.assertEqual({json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]},
                                         ({matcher} if valid else set()) | {'DOMAIN,neighbor.example'})
                        restored, messages = parse(outputs['fin.yaml'], purpose='proxy')
                        self.assertEqual(messages, [])
                        self.assertEqual(set(restored), ({Rule(kind, value)} if valid else set()) |
                                         {Rule('DOMAIN', 'neighbor.example', domain_source='mihomo')})

    def test_three_kinds_ordinary_quotes_and_native_scalar_forms(self):
        self._check_scalar_matrix(0)

    def test_prescan_slots_across_three_kinds_quotes_and_native_forms(self):
        self._check_scalar_matrix(0, PRESCAN_CASES)

    def test_deep_matrix_consumes_probe_with_original_limits_and_timeout(self):
        script = r'''
import cProfile
import sys
sys.path.insert(0, sys.argv[1])
from tests.test_regexp2_posix_class_regressions import CASES, PRESCAN_CASES, Regexp2PosixClassTests
import rules
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
with cProfile.Profile() as profiler:
    Regexp2PosixClassTests()._check_scalar_matrix(int(sys.argv[2]), CASES + PRESCAN_CASES[:2])
assert any(entry.code is rules._valid_deep_regex.__code__ and entry.callcount > 0
           for entry in profiler.getstats())
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
'''
        root = Path(__file__).resolve().parents[1]
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root), str(depth)],
                                        cwd=root, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_deep_prefix_scopes_keep_capture_slots_and_original_limits(self):
        script = r'''
import cProfile
import json
import sys
sys.path.insert(0, sys.argv[1])
from tests.test_regexp2_posix_class_regressions import KINDS, PREFIX_CASES
from rules import Rule, parse
import rules
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
depth = int(sys.argv[2])
cases = PREFIX_CASES + ((r'^(?:[a-\-[][:alpha:](?n]](a))(b)\1$', True),
                        (r'^[a-\-[][:alpha:](?n(a))]](?<word>b)\1\k<word>$', True))
with cProfile.Profile() as profiler:
    for kind in KINDS:
        for atom, valid in cases:
            value = '(?:' * depth + atom + ')' * depth
            for native in (False, True):
                source = ('payload:\n  - ' + json.dumps(kind + ',' + value) if native else
                          kind + ',' + json.dumps(value))
                parsed, messages = parse(source, purpose='block')
                assert parsed == ([Rule(kind, value)] if valid else []), (kind, atom, native, parsed)
                assert messages == ([] if valid else [f'line {2 if native else 1}: invalid {kind} {value}'])
assert any(entry.code is rules._valid_deep_regex.__code__ and entry.callcount > 0
           for entry in profiler.getstats())
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
'''
        root = Path(__file__).resolve().parents[1]
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root), str(depth)],
                                        cwd=root, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_deep_prefix_complete_scalar_forms_render_and_yaml_roundtrip(self):
        script = r'''
import cProfile
import sys
sys.path.insert(0, sys.argv[1])
from tests.test_regexp2_posix_class_regressions import PREFIX_CASES, Regexp2PosixClassTests
import rules
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
cases = PREFIX_CASES + ((r'^(?:[a-\-[][:alpha:](?n]](a))(b)\1$', True),
                        (r'^[a-\-[][:alpha:](?n(a))]](?<word>b)\1\k<word>$', True))
with cProfile.Profile(builtins=False) as profiler:
    Regexp2PosixClassTests()._check_scalar_matrix(int(sys.argv[2]), cases)
assert any(entry.code is rules._valid_deep_regex.__code__ and entry.callcount > 0
           for entry in profiler.getstats())
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
'''
        root = Path(__file__).resolve().parents[1]
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root), str(depth)],
                                        cwd=root, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_numeric_overflow_across_three_kinds_quotes_and_native_forms(self):
        self._check_scalar_matrix(0, tuple(case for case in NUMERIC_CASES[:4] if not case[1]))

    def test_numeric_boundaries_preserve_first_digit_and_class_scope_under_integer_limits(self):
        script = r'''
import sys
sys.path.insert(0, sys.argv[1])
from tests.test_regexp2_posix_class_regressions import NUMERIC_CASES, Regexp2PosixClassTests
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == 4300
limit = int(sys.argv[2])
sys.set_int_max_str_digits(limit)
Regexp2PosixClassTests()._check_scalar_matrix(0, NUMERIC_CASES, kinds=('DOMAIN-REGEX',))
assert sys.getrecursionlimit() == 1000 and sys.get_int_max_str_digits() == limit
'''
        root = Path(__file__).resolve().parents[1]
        for limit in (1000, 4300):
            with self.subTest(int_max_str_digits=limit):
                result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root), str(limit)],
                                        cwd=root, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_names_use_fixed_go_word_characters_without_name_lookup(self):
        # regexp2 v1.12.0 parser.go:1538-1565 消费完整 token，但仍把 [ 当作 literal。
        for name in ('alpha', 'unknown', '', '0a', '123', '_', '中', 'á', '‌‍', '＿'):
            for negate in ('', '^'):
                token = '[:' + negate + name + ':]'
                for kind in KINDS:
                    valid = '^[' + token + '(]$'
                    invalid = '^[' + token + r'()]\1$'
                    for value, accepted in ((valid, True), (invalid, False)):
                        with self.subTest(kind=kind, name=name, negate=negate, accepted=accepted):
                            with warnings.catch_warnings(record=True) as caught:
                                warnings.simplefilter('always')
                                self.assertEqual(parse(kind + ',' + json.dumps(value, ensure_ascii=False), purpose='block'),
                                                 ([Rule(kind, value)], []) if accepted else
                                                 ([], [f'line 1: invalid {kind} {value}']))
                            self.assertEqual(caught, [])
                            self.assertEqual(parse(kind + ',' + value, purpose='block'),
                                             ([Rule(kind, value)], []) if accepted else
                                             ([], [f'line 1: invalid {kind} {value}']))

    def test_incomplete_escaped_and_nonword_tokens_keep_original_boundaries(self):
        valid = (r'^[[:alpha]() ]\1$', r'^[\[:alpha:]()]\1$',
                 r'^[[:a-b:]()]\1$', r'^[[:a b:]()]\1$', r'^[[:a!b:]()]\1$',
                 r'^[[:a\b:]()]\1$', '^[[:²:]()]\\1$', '^[[:ा:]()]\\1$')
        invalid = (r'^[[:alpha:]$', r'^[[:alpha:](', r'^[[:a-b:](]$',
                   r'^[\[:alpha:](]$', r'^[[:alpha')
        for kind in KINDS:
            for values, accepted in ((valid, True), (invalid, False)):
                for value in values:
                    with self.subTest(kind=kind, value=value):
                        expected = ([Rule(kind, value)], []) if accepted else ([], [f'line 1: invalid {kind} {value}'])
                        self.assertEqual(parse(kind + ',' + json.dumps(value, ensure_ascii=False), purpose='block'), expected)

    def test_subtraction_ranges_negation_and_first_literal_bracket(self):
        valid = (r'^[a-[:alpha:]]$', r'^[a-\-[:alpha:]]$', r'^[a-\-\-[:alpha:]]$',
                 r'^[[:alpha:]-[x]]$', r'^[a-z-[[:alpha:](]]$', r'^[\d-[:alpha:]]$',
                 r'^[[:alpha:]-z]$', r'^[[:alpha:]\-!]$', r'^[-[:alpha:](]$',
                 r'^[^[:alpha:](]$', r'^[][:alpha:](]$', r'^[^][:alpha:](]$')
        invalid = (r'^[[:alpha:]-[x]y]$', r'^[[:alpha:]-!]$',
                   r'^[a-\-[:alpha:]()]\1$', r'^[[:alpha:]-[x]')
        for kind in KINDS:
            for values, accepted in ((valid, True), (invalid, False)):
                for value in values:
                    for field in (value, json.dumps(value)) if accepted else (json.dumps(value),):
                        with self.subTest(kind=kind, value=value, field=field):
                            self.assertEqual(parse(kind + ',' + field + '\nDOMAIN,neighbor.example', purpose='proxy'),
                                             (([Rule(kind, value)] if accepted else []) + [Rule('DOMAIN', 'neighbor.example')],
                                              [] if accepted else [f'line 1: invalid {kind} {value}']))

    def test_capture_slots_named_references_class_hash_and_quantifiers(self):
        valid = (r'^[[:alpha:]()](a)\1$', r'^[[:alpha:]()](?<word>a)\k<word>$',
                 r'(?n)^[[:alpha:]()](?<word>a)\1$', r'^[[:alpha:]\1{2,1}]$',
                 r'(?x)^[[:alpha:]#(]$', r'(?x:^[[:alpha:]#()]$)',
                 r'(?x)^[[:alpha:]#()]$ # ignored \q', r'^[[:alpha:]()]{1,2}?$*',
                 r'^[[:alpha:]()](?(?=a)b|c)$', r'(?<word>a)[[:alpha:]()](?(word)b|c)\k<word>')
        invalid = (r'^[[:alpha:]()]\1$', r'^[[:alpha:]()](a)\2$',
                   r'^[[:alpha:]()]\k<missing>$', r'(?n)^[[:alpha:]()](a)\1$',
                   r'(?x)^[[:alpha:]#()]\q$', r'^[[:alpha:]()]++$',
                   r'^[[:alpha:]()]{2,1}$', r'^[[:alpha:]()](?(?=a)+b|c)$')
        for kind in KINDS:
            for values, accepted in ((valid, True), (invalid, False)):
                for value in values:
                    source = 'payload:\n  - ' + json.dumps(kind + ',' + value) + '\n  - DOMAIN,neighbor.example\n'
                    expected = ([Rule(kind, value)] if accepted else []) + [Rule('DOMAIN', 'neighbor.example', domain_source='mihomo')]
                    with self.subTest(kind=kind, value=value):
                        self.assertEqual(parse(source, purpose='block'),
                                         (expected, [] if accepted else [f'line 2: invalid {kind} {value}']))
                        fields = (json.dumps(value),) if ' # ignored' in value else (value, json.dumps(value))
                        for field in fields:
                            ordinary = kind + ',' + field + '\nDOMAIN,neighbor.example'
                            self.assertEqual(parse(ordinary, purpose='block'),
                                             (([Rule(kind, value)] if accepted else []) + [Rule('DOMAIN', 'neighbor.example')],
                                              [] if accepted else [f'line 1: invalid {kind} {value}']))

    def test_url_regex_keeps_python_lexer_and_validator_including_mixed_logical_leaves(self):
        value = r'^[[:alpha:]()$'
        for field in (value, "'" + value + "'", json.dumps(value)):
            self.assertEqual(parse('URL-REGEX,' + field, purpose='proxy'), ([Rule('URL-REGEX', value)], []))
        regexp2 = r'^[[:alpha:](][)]$'
        for leaves in ((f'(DOMAIN-REGEX,{regexp2})', f'(URL-REGEX,{value})'),
                       (f'(URL-REGEX,{value})', f'(PROCESS-NAME-REGEX,{regexp2})')):
            expression = '(' + ','.join(leaves) + ')'
            self.assertEqual(parse('AND,' + expression + ',PROXY', purpose='proxy'), ([Rule('AND', expression)], []))
        self.assertEqual(parse('DOMAIN-REGEX,' + json.dumps(value), purpose='proxy'),
                         ([], [f'line 1: invalid DOMAIN-REGEX {value}']))

    def test_ordinary_logical_encodes_literal_parentheses_and_native_keeps_balance_limit(self):
        for kind in KINDS:
            for operator in ('AND', 'OR', 'NOT'):
                for native in (False, True):
                    value = r'^[[:alpha:](][)]$' if native else r'^[[:alpha:](]$'
                    field = value if native else "'" + value + "'"
                    leaf = f'({kind},{field})'
                    expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                    source = ('payload:\n  - ' + json.dumps(operator + ',' + expression) if native else
                              operator + ',' + expression + ',PROXY')
                    with self.subTest(kind=kind, operator=operator, native=native):
                        parsed, messages = parse(source, purpose='proxy')
                        self.assertEqual((parsed, messages), ([Rule(operator, expression, native_fields=native)], []))
                        outputs, skipped = render('posix', parsed, purpose='proxy', no_resolve='keep')
                        encoded = value if native else r'^[[:alpha:]\x{28}]$'
                        projected_leaf = f'({kind},{encoded})'
                        projected = f'({projected_leaf})' if operator == 'NOT' else f'({projected_leaf},(NETWORK,tcp))'
                        self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), operator + ',' + projected)
                        self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                                         ([Rule(operator, projected, native_fields=True)], []))
                        self.assertEqual(skipped, {name + ':' + operator: 1 for name in FILES if name != 'fin.yaml'})
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(outputs[name], '# posix rules: 0\n')
                for value in (r'^[[:alpha:](]$', r'^[[:alpha:]()]\1$', r'^[[:alpha:]-!]$'):
                    leaf = f'({kind},{value})'
                    expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                    document = 'payload:\n  - ' + json.dumps(operator + ',' + expression) + '\n  - DOMAIN,neighbor.example\n'
                    self.assertEqual(parse(document, purpose='proxy'),
                                     ([Rule('DOMAIN', 'neighbor.example', domain_source='mihomo')],
                                      [f'line 2: invalid logical expression {expression}']))
                for value in (r'^[[:alpha:]()]\1$', r'^[[:alpha:]-!]$'):
                    leaf = f'({kind},{json.dumps(value)})'
                    expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                    self.assertEqual(parse(operator + ',' + expression, purpose='proxy'),
                                     ([], [f'line 1: invalid logical expression {expression}']))

    def test_prescan_option_scopes_numbered_and_named_references(self):
        cases = ((r'^[a-\-[][:alpha:](?n)]](?<7>a)\7$', True),
                 (r'^[a-\-[][:alpha:](?n)]](?<7>a)\1$', False),
                 (r'^(?:[a-\-[][:alpha:](?n)]](a))(b)\1$', True),
                 (r'^(?:[a-\-[][:alpha:](?n)]](a))(b)\2$', False),
                 (r'^[a-\-[][:alpha:](?x:(?n))]](a)\1$', True),
                 (r'^[a-\-[][:alpha:](?x)]](a)\1$', True),
                 (r'^[a-\-[][:alpha:](?x)]]#(a)\1$', False),
                 (r'^[a-\-[][:alpha:](?n)]](a)\k<missing>$', False),
                 (r'^[a-\-[][:alpha:](?n)]](?<word>a)\2$', False))
        self._check_scalar_matrix(0, cases)

    def test_prefix_witnesses_keep_actual_characters_and_all_scalar_forms(self):
        for (value, _), length, reference in zip(PREFIX_CASES, (33, 32, 32, 32, 28), (30, 29, 29, 29, 25)):
            self.assertEqual(len(value), length)
            self.assertEqual([index for index, char in enumerate(value) if char == '\\'], [4, reference])
            self.assertEqual(value[4:6], r'\-')
            self.assertIn(value[reference:reference + 2], (r'\1', r'\2'))
        self._check_scalar_matrix(0, PREFIX_CASES)

    def test_prescan_prefix_stops_signs_case_and_scoped_options(self):
        prefix = r'^[a-\-[][:alpha:]'
        headers = (('(?n)(?-n', True), ('(?n)(?-n:', True), ('(?n)(?-nQ', True),
                   ('(?n)(?-n0', True), ('(?n)(?-n!', True), ('(?n)(?-n.', True),
                   ('(?n)(?-n#', True), ('(?n)(?-n[', True), (r'(?n)(?-n\(', True),
                   ('(?n)(?-n)', True), ('(?n)(?)(?-n', True),
                   ('(?iMnSdUn', False), ('(?IMNSXDU', False), ('(?n)(?+n-n', True),
                   ('(?n)(?-+n-n', False),
                   ('(?n)(?-n+n', False), ('(?-n+n-n+n', False),
                   ('(?nr-n', False), ('(?ne-n', False), ('(?nc-n', False),
                   ('(?nR-n', False), ('(?nE-n', False), ('(?nC-n', False),
                   ('(?x#(?n)', False), ('(?x)(?-x', True),
                   ('(?n:foo)', True), ('(?n:foo', False),
                   ('(?n)(?-n:foo)', False), ('(?n)(?-n:foo', True))
        self._check_scalar_matrix(0, tuple((prefix + header + r']](a)\1$', accepted)
                                           for header, accepted in headers))
        for header in ('(?c)', '(?r)', '(?e)', '(?n]]'):
            value = header + r'(a)\1'
            self.assertEqual(parse('DOMAIN-REGEX,' + json.dumps(value), purpose='block'),
                             ([], [f'line 1: invalid DOMAIN-REGEX {value}']))

    def test_prescan_stack_comment_reset_and_reference_neighbors(self):
        cases = ((r'^(?:[a-\-[][:alpha:](?n]](a))(b)\1$', True),
                 (r'^(?:[a-\-[][:alpha:](?n]](a))(b)\2$', False),
                 (r'^[a-\-[][:alpha:](?(?#x))]](a)\1$', True),
                 (r'^[a-\-[][:alpha:](?n)(?(?#x)]](a)\1$', False),
                 (r'^[a-\-[][:alpha:](?n)(?(?#x)(?-n]](a)\1$', True),
                 (r'^[a-\-[][:alpha:](?n(a))]](b)\k<1>$', True),
                 (r'^[a-\-[][:alpha:](?n(a))]](b)\k<2>$', False),
                 (r'^[a-\-[][:alpha:](?n(a))]](?<word>b)\1\k<word>$', True),
                 (r'^[a-\-[][:alpha:](?n(a))]](?<word>b)\2$', False),
                 (r'^[a-\-[][:alpha:](?n(a))]](?<7>b)(?<word>c)\1\7\k<word>$', True),
                 (r'^[a-\-[][:alpha:](?n(a))]](?<7>b)(?<word>c)\2$', False),
                 (r'^(?(a)(b)|(c))\2$', True), (r'^(?(a)(b)|(c))\3$', False),
                 (r'^(?(?=(a))(b)|(c))\3$', True))
        self._check_scalar_matrix(0, cases)

    def test_prescan_logical_leaves_keep_native_balance_and_ordinary_encoding(self):
        for kind in KINDS:
            for operator in ('AND', 'OR', 'NOT'):
                for native in (False, True):
                    for value, accepted in PRESCAN_CASES:
                        field = value if native else json.dumps(value)
                        leaf = f'({kind},{field})'
                        expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                        record = operator + ',' + expression
                        source = ('payload:\n  - ' + json.dumps(record) + '\n  - DOMAIN,neighbor.example\n' if native else
                                  record + ',PROXY\nDOMAIN,neighbor.example,PROXY\n')
                        neighbor = Rule('DOMAIN', 'neighbor.example', domain_source='mihomo' if native else 'surge')
                        expected = ([Rule(operator, expression, native_fields=native)] if accepted else []) + [neighbor]
                        with self.subTest(kind=kind, operator=operator, native=native, value=value):
                            parsed, messages = parse(source, purpose='proxy')
                            self.assertEqual((parsed, messages), (expected, [] if accepted else
                                             [f'line {2 if native else 1}: invalid logical expression {expression}']))
                            outputs, _ = render('posix', parsed, purpose='proxy', no_resolve='keep')
                            encoded = value if native else value.replace('(?n)', r'\x{28}?n\x{29}')
                            projected_leaf = f'({kind},{encoded})'
                            projected = f'({projected_leaf})' if operator == 'NOT' else f'({projected_leaf},(NETWORK,tcp))'
                            self.assertCountEqual([json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]],
                                                  ([operator + ',' + projected] if accepted else []) + ['DOMAIN,neighbor.example'])
                            restored, messages = parse(outputs['fin.yaml'], purpose='proxy')
                            self.assertEqual(messages, [])
                            self.assertCountEqual(restored, ([Rule(operator, projected, native_fields=True)] if accepted else []) +
                                                  [Rule('DOMAIN', 'neighbor.example', domain_source='mihomo')])

    def test_prefix_logical_leaves_keep_encoding_and_native_balance_limit(self):
        projections = (r'^[a-\-[][:alpha:]\x{28}?n\x{29}\x{28}?-n]](a)\1$',
                       r'^[a-\-[][:alpha:]\x{28}?\x{28}?#x\x{29}]](a)\1$', None,
                       r'^[a-\-[][:alpha:]\x{28}?n\x{28}a\x{29}\x{29}]](b)\1$', None)
        for kind in KINDS:
            for operator in ('AND', 'OR', 'NOT'):
                for native in (False, True):
                    for index, ((value, valid), encoded) in enumerate(zip(PREFIX_CASES, projections)):
                        accepted = valid and (not native or index == 3)
                        leaf = f'({kind},{value if native else json.dumps(value)})'
                        expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                        record = operator + ',' + expression
                        source = ('payload:\n  - ' + json.dumps(record) + '\n  - DOMAIN,neighbor.example\n' if native else
                                  record + ',PROXY\nDOMAIN,neighbor.example,PROXY\n')
                        neighbor = Rule('DOMAIN', 'neighbor.example', domain_source='mihomo' if native else 'surge')
                        with self.subTest(kind=kind, operator=operator, native=native, value=value):
                            parsed, messages = parse(source, purpose='proxy')
                            self.assertEqual((parsed, messages),
                                             (([Rule(operator, expression, native_fields=native)] if accepted else []) + [neighbor],
                                              [] if accepted else [f'line {2 if native else 1}: invalid logical expression {expression}']))
                            outputs, _ = render('posix', parsed, purpose='proxy', no_resolve='keep')
                            projected_leaf = f'({kind},{value if native else encoded})'
                            projected = f'({projected_leaf})' if operator == 'NOT' else f'({projected_leaf},(NETWORK,tcp))'
                            self.assertCountEqual([json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]],
                                                  ([operator + ',' + projected] if accepted else []) + ['DOMAIN,neighbor.example'])
                            restored, messages = parse(outputs['fin.yaml'], purpose='proxy')
                            self.assertEqual(messages, [])
                            self.assertCountEqual(restored, ([Rule(operator, projected, native_fields=True)] if accepted else []) +
                                                  [Rule('DOMAIN', 'neighbor.example', domain_source='mihomo')])

    def test_numeric_logical_leaves_keep_class_literals_and_reject_overflow(self):
        for kind in KINDS:
            for value, accepted in NUMERIC_CASES:
                for operator in ('AND', 'OR', 'NOT'):
                    for native in (False, True):
                        leaf = f'({kind},{value if native else json.dumps(value)})'
                        expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                        record = operator + ',' + expression
                        source = ('payload:\n  - ' + json.dumps(record) + '\n  - DOMAIN,neighbor.example\n' if native else
                                  record + ',PROXY\nDOMAIN,neighbor.example,PROXY\n')
                        neighbor = Rule('DOMAIN', 'neighbor.example', domain_source='mihomo' if native else 'surge')
                        with self.subTest(kind=kind, operator=operator, native=native, value=value):
                            parsed, messages = parse(source, purpose='proxy')
                            self.assertEqual((parsed, messages),
                                             (([Rule(operator, expression, native_fields=native)] if accepted else []) + [neighbor],
                                              [] if accepted else [f'line {2 if native else 1}: invalid logical expression {expression}']))
                            encoded = value
                            if not native and value.startswith(('^[a-', '^[[:')):
                                encoded = value.replace('(?<', r'\x{28}?<').replace('>)', r'>\x{29}')
                            projected_leaf = f'({kind},{encoded})'
                            projected = f'({projected_leaf})' if operator == 'NOT' else f'({projected_leaf},(NETWORK,tcp))'
                            outputs, _ = render('posix', parsed, purpose='proxy', no_resolve='keep')
                            self.assertCountEqual([json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]],
                                                  ([operator + ',' + projected] if accepted else []) + ['DOMAIN,neighbor.example'])
                            restored, messages = parse(outputs['fin.yaml'], purpose='proxy')
                            self.assertEqual(messages, [])
                            self.assertCountEqual(restored, ([Rule(operator, projected, native_fields=True)] if accepted else []) +
                                                  [Rule('DOMAIN', 'neighbor.example', domain_source='mihomo')])

    def _check_white_identity_and_render(self, cases):
        value = cases[0][0]
        for native in (False, True):
            records = ['DOMAIN-REGEX,' + item for item, _ in cases] + ['DOMAIN,neighbor.example']
            source = ('payload:\n' + ''.join('  - ' + json.dumps(item) + '\n' for item in records) if native else
                      '\n'.join(kind + ',' + json.dumps(item) for kind, _, item in
                                (record.partition(',') for record in records)))
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                white = parse_whitelist(source)
            neighbor = Rule('DOMAIN', 'neighbor.example', domain_source='mihomo' if native else 'surge')
            self.assertEqual(white, [Rule('DOMAIN-REGEX', value), neighbor])
            self.assertEqual(normalize(white + white), [neighbor, Rule('DOMAIN-REGEX', value)])
            self.assertEqual([str(item.message) for item in caught],
                             [f'line {number + int(native)}: invalid DOMAIN-REGEX {invalid}'
                              for number, (invalid, _) in enumerate(cases[1:], 2)])
            self.assertEqual(exclude_covered([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'other.example')], white),
                             [Rule('DOMAIN', 'other.example')])
        for kind in KINDS:
            if kind != 'DOMAIN-REGEX':
                self.assertEqual(parse_whitelist(kind + ',' + json.dumps(value)), [])
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    outputs, skipped = render('posix', [Rule(kind, value)], purpose=purpose, no_resolve=mode)
                    self.assertEqual(outputs['fin.yaml'], '# posix rules: 1\npayload:\n  - ' + json.dumps(kind + ',' + value) + '\n')
                    self.assertEqual(skipped, {name + ':' + kind: 1 for name in FILES if name != 'fin.yaml'})
                    self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:], ['! Total count: 0'] +
                                     ([] if purpose == 'block' else ['! No AdBlock rules for non-advertising group.']))
        for consumer in ('allow', 'white'):
            outputs, skipped = render('posix', [Rule('DOMAIN-REGEX', value, allow=consumer == 'allow')],
                                      whitelist=[Rule('DOMAIN-REGEX', value)] if consumer == 'white' else [],
                                      purpose='block', no_resolve='keep')
            self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:], ['! Total count: 0'])
            self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1 if consumer == 'allow' else 2)

    def test_white_identity_process_boundary_and_direct_rule_render_keep_matcher(self):
        self._check_white_identity_and_render(CASES)

    def test_prescan_white_identity_and_direct_render_keep_legal_matcher(self):
        self._check_white_identity_and_render(PRESCAN_CASES[:2])

    def test_prefix_white_and_direct_render_keep_legal_matchers_and_reject_neighbors(self):
        invalid = tuple(case for case in PREFIX_CASES if not case[1])
        for case in PREFIX_CASES:
            if case[1]:
                with self.subTest(value=case[0]):
                    self._check_white_identity_and_render((case,) + invalid)

    def test_numeric_white_and_direct_render_preserve_legal_boundaries(self):
        invalid = tuple(case for case in NUMERIC_CASES if not case[1])
        for case in NUMERIC_CASES:
            if case[1]:
                with self.subTest(value=case[0]):
                    self._check_white_identity_and_render((case,) + invalid)

    def _products(self, group, matchers, purpose, neighbor=None):
        route = neighbor == 'surge'
        dns = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n'
               '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
               '! License: Inherits upstream licenses\n! Version: 202601021104\n')
        return {
            'fin.txt': f'# {group} rules: {int(route)}\n' + ('DOMAIN,neighbor.example\n' if route else ''),
            'fin-surge.txt': f'# {group} rules: 0\n',
            'fin-surge-ds.txt': f'# {group} rules: {int(route)}\n' + ('neighbor.example\n' if route else ''),
            'fin-qx.txt': f'# {group} rules: {int(neighbor is not None)}\n' +
                          ('HOST,neighbor.example,LIST\n' if neighbor is not None else ''),
            'fin.yaml': f'# {group} rules: {len(matchers)}\npayload:\n' +
                        ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers),
            'fin-adb.txt': dns + (f'! Total count: {int(route)}\n' +
                                 ('0.0.0.0 neighbor.example\n' if route else '') if purpose == 'block' else
                                 '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'),
        }

    def _check_generation(self, cases, logic):
        value = cases[0][0]
        valid = [kind + ',' + value for kind in KINDS]
        source_rows = [kind + ',' + atom for kind in KINDS for atom, _ in cases] + [logic]
        remote = {'https://example.org/posix.yaml': ('payload:\n' + ''.join(
                    '  - ' + json.dumps(row) + '\n' for row in source_rows)).encode('utf-8'),
                  'https://example.org/white.list': ('\n'.join('DOMAIN-REGEX,' + json.dumps(atom)
                                                              for atom, _ in cases) + '\n').encode('utf-8')}
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    (root / 'static/neighbor.list').write_bytes(b'DOMAIN,neighbor.example\r\n')
                    (root / 'static/white.list').write_bytes(('DOMAIN-REGEX,' + json.dumps(value) + '\r\n').encode('utf-8'))
                    static = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                    configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                'sources': sources, 'whitelist': white} for group, sources, white in (
                        ('parent', ['https://example.org/posix.yaml', 'static/neighbor.list'], []),
                        ('whiteparent', ['static/white.list'], []),
                        ('sourcechild', ['parent/fin.yaml'], []),
                        ('whitechild', ['parent/fin.yaml'], ['whiteparent/fin.yaml']),
                        ('rawwhite', ['parent/fin.yaml'], ['https://example.org/white.list']),
                        ('cleared', ['static/white.list'], ['whiteparent/fin.yaml']))]
                    config_path = root / 'rulesets.json'
                    config_path.write_text(json.dumps(configs), encoding='utf-8')
                    config_bytes = config_path.read_bytes()
                    previous = {}
                    for config in configs:
                        (root / config['name']).mkdir()
                        for name in FILES:
                            path = root / config['name'] / name
                            previous[path] = b'old complete\r\n\0' + name.encode('ascii')
                            path.write_bytes(previous[path])
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as logs:
                        clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            outputs = generate(root, remote.__getitem__)
                    self.assertEqual([str(item.message) for item in caught],
                                     [f'line {number}: invalid DOMAIN-REGEX {atom}'
                                      for number, (atom, _) in enumerate(cases[1:], 2)])
                    parent_rows = [logic, 'DOMAIN,neighbor.example', *valid]
                    white_rows = [logic, 'DOMAIN,neighbor.example', *valid[1:]]
                    rows = {'parent': parent_rows, 'whiteparent': valid[:1], 'sourcechild': parent_rows,
                            'whitechild': white_rows, 'rawwhite': white_rows, 'cleared': []}
                    expected = {root / group / name: text for group, matchers in rows.items()
                                for name, text in self._products(group, matchers, purpose,
                                    'surge' if group == 'parent' else 'mihomo' if group in
                                    {'sourcechild', 'whitechild', 'rawwhite'} else None).items()}
                    self.assertEqual(outputs, expected)
                    for group, matchers in rows.items():
                        yaml = outputs[root / group / 'fin.yaml']
                        self.assertEqual([json.loads(row[4:]) for row in yaml.splitlines()[2:]], matchers)
                        self.assertEqual(parse(yaml, purpose=purpose)[1], [])
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    expected_warnings = [f'https://example.org/posix.yaml: line {number}: invalid {kind} {atom}'
                                         for number, (kind, atom, accepted) in enumerate(
                                             ((kind, atom, accepted) for kind in KINDS for atom, accepted in cases), 2)
                                         if not accepted]
                    diagnostics = {}
                    for group, matchers in rows.items():
                        counts = {}
                        for matcher in matchers:
                            kind = matcher.partition(',')[0]
                            if kind != 'DOMAIN':
                                omitted = ('fin.txt', 'fin-qx.txt', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
                            elif group != 'parent':
                                omitted = ('fin.txt', 'fin-adb.txt', 'fin-surge-ds.txt')
                            else:
                                omitted = ('fin-adb.txt',) if purpose != 'block' else ()
                            for name in omitted:
                                key = name + ':' + kind
                                counts[key] = counts.get(key, 0) + 1
                        if purpose == 'block' and group in {'whitechild', 'rawwhite', 'cleared'}:
                            counts['fin-adb.txt:DOMAIN-REGEX'] = counts.get('fin-adb.txt:DOMAIN-REGEX', 0) + 1
                        diagnostics[group] = ''.join(f'{group} {key}: {count}\n' for key, count in sorted(counts.items()))
                    source_warnings = expected_warnings[:5]
                    if len(expected_warnings) > 5:
                        source_warnings += [f'https://example.org/posix.yaml: {len(expected_warnings)} skipped lines; first five shown']
                    self.assertEqual(logs.getvalue(), '\n'.join(source_warnings) + '\n' +
                                     ''.join(diagnostics[config['name']] for config in configs))
                    self.assertEqual(config_path.read_bytes(), config_bytes)
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in expected.items()})
                    parents = {root / group / name: (root / group / name).read_bytes()
                               for group in ('parent', 'whiteparent') for name in FILES}
                    self.assertEqual(parse_whitelist((root / 'whiteparent/fin.yaml').read_text(encoding='utf-8')),
                                     [Rule('DOMAIN-REGEX', value)])
                    disk_configs = [config for config in configs if config['name'] in
                                    {'sourcechild', 'whitechild', 'cleared'}]
                    config_path.write_text(json.dumps(disk_configs), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_logs:
                        clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                        disk = generate(root, self.fail)
                    self.assertEqual(disk, {path: text for path, text in expected.items()
                                            if path.parent.name in {'sourcechild', 'whitechild', 'cleared'}})
                    self.assertEqual(disk_logs.getvalue(), ''.join(diagnostics[config['name']] for config in disk_configs))
                    publish(disk, root=root)
                    if purpose == 'block' and mode == 'keep':
                        script = r'''
from datetime import datetime, timezone
from pathlib import Path
import runpy
import sys
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
script = str(Path(sys.argv[1]) / 'generate.py')
sys.argv = [script, '--root', sys.argv[2]]
with patch('formats.datetime') as clock:
    clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
    runpy.run_path(script, run_name='__main__')
'''
                        project = Path(__file__).resolve().parents[1]
                        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(project), str(root)],
                                                cwd=project, capture_output=True, text=True, timeout=8)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(result.stderr, disk_logs.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in disk},
                                     {path: text.encode('utf-8') for path, text in disk.items()})
                    self.assertEqual({path: path.read_bytes() for path in parents}, parents)
                    self.assertEqual({path: path.read_bytes() for path in static}, static)

    def test_generate_publish_raw_same_round_disk_yaml_and_cli_use_actual_bytes(self):
        self._check_generation(CASES, r'AND,((DOMAIN-REGEX,^[[:alpha:](][)]$),(NETWORK,tcp))')

    def test_prescan_generate_publish_and_yaml_dependencies_use_actual_matchers(self):
        self._check_generation(PRESCAN_CASES[:2],
                               'AND,((DOMAIN-REGEX,' + PRESCAN_CASES[0][0] + '),(NETWORK,tcp))')

    def test_prefix_generate_publish_yaml_dependencies_and_cli_keep_actual_matchers(self):
        invalid = tuple(case for case in PREFIX_CASES if not case[1])
        for case in PREFIX_CASES:
            if case[1]:
                with self.subTest(value=case[0]):
                    self._check_generation((case,) + invalid,
                                           r'AND,((DOMAIN-REGEX,^[[:alpha:](][)]$),(NETWORK,tcp))')

    def test_numeric_generate_publish_yaml_dependencies_and_cli_keep_actual_matchers(self):
        for reference in ('', r'\1'):
            cases = tuple((r'^[a-\-[][:alpha:](?<' + digits + '>)]](a)' + reference + '$', accepted)
                          for digits, accepted in (('2147483647', True), ('2147483648', False), ('9' * 5001, False)))
            with self.subTest(reference=reference):
                self._check_generation(cases, r'AND,((DOMAIN-REGEX,^[[:alpha:](][)]$),(NETWORK,tcp))')

    def test_invalid_local_source_white_and_disk_yaml_preserve_old_outputs(self):
        for kind in KINDS:
            for value, _ in CASES[1:] + PRESCAN_CASES[1:2] + tuple(case for case in PREFIX_CASES + NUMERIC_CASES if not case[1]):
                for role in ('source', 'white', 'disk-source', 'disk-white'):
                    with self.subTest(kind=kind, value=value, role=role), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        invalid = ('payload:\n  - ' + json.dumps(kind + ',' + value) + '\n').encode('utf-8')
                        bad = 'parent/fin.yaml' if role.startswith('disk') else 'static/bad.yaml'
                        path = root / bad
                        path.parent.mkdir(exist_ok=True)
                        path.write_bytes(invalid if not role.startswith('disk') else b'# parent rules: 1\n' + invalid)
                        (root / 'static/good.list').write_bytes(b'DOMAIN,neighbor.example\n')
                        config = [{'name': 'child', 'sources': [bad if role.endswith('source') else 'static/good.list'],
                                   'whitelist': [bad] if role.endswith('white') else [],
                                   'purpose': 'block', 'no_resolve': 'keep'}]
                        (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                        (root / 'child').mkdir()
                        for name in FILES:
                            (root / 'child' / name).write_bytes(b'old complete\r\n\0' + name.encode('ascii'))
                        before = {item: item.read_bytes() for item in root.rglob('*') if item.is_file()}
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaisesRegex(ValueError, 'No adaptable rules|Invalid whitelist'):
                                generate(root, self.fail)
                        self.assertEqual({item: item.read_bytes() for item in before}, before)
