import json
from pathlib import Path
import subprocess
import sys
import unittest
import warnings

from formats import FILES, render
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests.test_regexp2_conditional_regressions import check_generated_regex


KINDS = ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX')
CLASS_ESCAPES = (r'\d', r'\D', r'\w', r'\W', r'\s', r'\S', r'\pL', r'\PL', r'\p{L}', r'\P{Nd}')


class Regexp2CompletedRangeTests(unittest.TestCase):
    def test_escaped_range_endpoint_is_consumed_once(self):
        value = r'^[\cA-\e-\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_braced_hex_endpoint_completes_range(self):
        value = r'^[a-\x{7A}-\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_octal_endpoint_completes_range(self):
        value = r'^[a-\172-\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_punctuation_endpoint_completes_range(self):
        value = r'^[!-\?-\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_fixed_width_hex_endpoint_does_not_reuse_its_last_digit(self):
        value = r'^[a-\x7A-\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_class_escapes_negation_and_all_endpoint_paths_share_state(self):
        ranges = ('a-z', r'\cA-\e', r'\cA-\cZ', r'a-\x{7A}', r'a-\x7A', '!--',
                  'a-' + chr(92) + 'u007A', r'a-\172', r'!-\?', r'!-\]', r'!-\[', r'\a-\t')
        for endpoint in ranges:
            for negate in ('', '^'):
                for escape in CLASS_ESCAPES:
                    for hyphens, accepted in (('-', True), ('--', False)):
                        value = '^[' + negate + endpoint + hyphens + escape + ']$'
                        for kind in KINDS:
                            with self.subTest(endpoint=endpoint, negate=negate, escape=escape, hyphens=hyphens, kind=kind):
                                self.assertEqual(parse(kind + ',' + json.dumps(value), purpose='proxy'),
                                                 ([Rule(kind, value)], []) if accepted else
                                                 ([], [f'line 1: invalid {kind} {value}']))

    def test_pending_completed_literal_posix_and_subtraction_boundaries(self):
        valid = (r'^[a-z-!]$', r'^[a-z-]$', r'^[a-z--a]$', r'^[a-z--z]$', r'^[a-z-b-z]$',
                 r'^[a-z-\-\d]$', r'^[a-\-z-\d]$', r'^[a-z\-\d]$',
                 r'^[a-z!\d]$', r'^[a-z\x7A]$', r'^[a-z-[:alpha:]]$',
                 r'^[a-z-[0-9]]$', r'^[a-z-\-[0-9]]$', r'^[a-z--[0-9]]$',
                 r'^[a-z-[\p{L}]]$', r'^[a-z--[:alpha:]]$', r'^[[:alpha:]-z]$',
                 r'^[a-z[:alpha:]-z]$', r'^[a-\-]$', r'^[a-z0-9]$',
                 r'^[a-z\x7A0-9]$', r'^[a-\1720-9]$', r'^[a-z-\x30]$')
        invalid = (r'^[a-\d]$', r'^[a-\p{L}]$', r'^[z-a]$',
                   r'^[a-z--!]$', r'^[a-z0-\d]$', r'^[a-z--\-\d]$',
                   r'^[a-\-\d]$', r'^[a-\x7A0-\d]$',
                   r'^[a-z-[0-9]x]$', r'^[a-z-[0-9]$', r'^[a-z-[z-a]]$',
                   r'^[a-z-[a-\d]]$', r'^[[:alpha:]-!]$', r'^[a-z[:alpha:]-!]$',
                   r'^[a-\x7]$', r'^[a-\u007]$', r'^[a-\xGG]$', r'^[a-\uZZZZ]$')
        for accepted, values in ((True, valid), (False, invalid)):
            for value in values:
                for kind in KINDS:
                    with self.subTest(value=value, kind=kind):
                        self.assertEqual(parse(kind + ',' + json.dumps(value) + '\nDOMAIN,keep.example.org', purpose='block'),
                                         (([Rule(kind, value)] if accepted else []) + [Rule('DOMAIN', 'keep.example.org')],
                                          [] if accepted else [f'line 1: invalid {kind} {value}']))

    def _check_public_paths(self, depth=0):
        for atom, accepted in ((r'^[a-z-\d]$', True), (r'^[a-z--\d]$', False),
                               (r'^[a-\x7A-\d]$', True), (r'^[a-\x7A--\d]$', False)):
            value = '(?:' * depth + atom + ')' * depth
            for kind in KINDS:
                matcher = kind + ',' + value
                sources = [(kind + ',' + field + '\nDOMAIN,keep.example.org', 1, False)
                           for field in (value, "'" + value + "'", json.dumps(value))]
                sources += [('﻿' + header + ':\r\n  # context\r\n  - ' + scalar +
                             '\r\n  - DOMAIN,keep.example.org\r\n', 3, True)
                            for header in ('payload', 'rules')
                            for scalar in (matcher, "'" + matcher + "'", json.dumps(matcher))]
                for source, line, native in sources:
                    with self.subTest(depth=depth, kind=kind, atom=atom, source=source[:24]):
                        self.assertEqual(parse(source, purpose='proxy'),
                                         (([Rule(kind, value)] if accepted else []) + [Rule('DOMAIN', 'keep.example.org',
                                          domain_source='mihomo' if native else 'surge')],
                                          [] if accepted else [f'line {line}: invalid {kind} {value}']))
                leaf = f'({kind},{value})'
                for operator in ('AND', 'OR', 'NOT'):
                    expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(IP-CIDR,203.0.113.0/24,no-resolve))'
                    record = operator + ',' + expression
                    for native in (False, True):
                        source = 'payload:\n  - ' + json.dumps(record) if native else record
                        parsed, messages = parse(source, purpose='proxy')
                        self.assertEqual((parsed, messages), ([Rule(operator, expression, native_fields=native)], []) if accepted else
                                         ([], [f'line {2 if native else 1}: invalid logical expression {expression}']))
                        for mode in ('keep', 'add', 'strip'):
                            if not accepted:
                                continue
                            outputs, skipped = render('range', parsed, purpose='proxy', no_resolve=mode)
                            wanted = record.replace(',no-resolve', '') if mode == 'strip' else record
                            self.assertEqual(outputs['fin.yaml'], '# range rules: 1\npayload:\n  - ' + json.dumps(wanted) + '\n')
                            self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                                             ([Rule(operator, wanted.partition(',')[2], native_fields=True)], []))
                            self.assertEqual(skipped, {name + ':' + operator: 1 for name in FILES if name != 'fin.yaml'})

    def test_ordinary_native_scalar_and_logical_public_paths(self):
        self._check_public_paths()

    def test_deep_completed_ranges_keep_limits_and_no_resolve_revalidation(self):
        script = r'''
import sys
sys.path.insert(0, sys.argv[1])
from tests.test_regexp2_completed_range_regressions import Regexp2CompletedRangeTests
assert sys.getrecursionlimit() == 1000
Regexp2CompletedRangeTests()._check_public_paths(int(sys.argv[2]))
assert sys.getrecursionlimit() == 1000
'''
        root = Path(__file__).resolve().parents[1]
        for depth in (600, 1000):
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root), str(depth)],
                                    cwd=root, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_white_identity_and_scalar_nine_modes_keep_dns_and_url_boundaries(self):
        valid, invalid = r'^[a-z-\d]$', r'^[a-z--\d]$'
        for native in (False, True):
            source = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + valid) + '\n  - ' + json.dumps('DOMAIN-REGEX,' + invalid)
                      if native else 'DOMAIN-REGEX,' + valid + '\nDOMAIN-REGEX,' + invalid)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                white = parse_whitelist(source)
            self.assertEqual(white, [Rule('DOMAIN-REGEX', valid)])
            self.assertEqual([str(item.message) for item in caught], [f'line {3 if native else 2}: invalid DOMAIN-REGEX {invalid}'])
            self.assertEqual(normalize(iter(reversed(white + white))), white)
            different = Rule('DOMAIN-REGEX', r'^[a-z\-\d]$')
            self.assertEqual(exclude_covered(iter(white + [different]), iter(white)), [different])
        for kind in KINDS:
            if kind != 'DOMAIN-REGEX':
                self.assertEqual(parse_whitelist(kind + ',' + valid), [])
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('keep', 'add', 'strip'):
                    parsed, messages = parse(kind + ',' + valid, purpose=purpose)
                    self.assertEqual(messages, [])
                    outputs, skipped = render('range', parsed, purpose=purpose, no_resolve=mode)
                    self.assertEqual(outputs['fin.yaml'], '# range rules: 1\npayload:\n  - ' + json.dumps(kind + ',' + valid) + '\n')
                    self.assertEqual(skipped, {name + ':' + kind: 1 for name in FILES if name != 'fin.yaml'})
                    for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                        self.assertEqual(outputs[name], '# range rules: 0\n')
                    self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:], ['! Total count: 0'] +
                                     ([] if purpose == 'block' else ['! No AdBlock rules for non-advertising group.']))
        for consumer in ('allow', 'white'):
            outputs, skipped = render('range', [Rule('DOMAIN-REGEX', valid, allow=consumer == 'allow')],
                                      whitelist=[Rule('DOMAIN-REGEX', valid)] if consumer == 'white' else [],
                                      purpose='block', no_resolve='keep')
            self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:], ['! Total count: 0'])
            self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1 if consumer == 'allow' else 2)
        for value in (r'^[a-z-\d]$', r'^[a-z-\w]$', r'^[a-z-\s]$', r'^[a-z\-\d]$'):
            self.assertEqual(parse('URL-REGEX,' + value, purpose='proxy'), ([Rule('URL-REGEX', value)], []))
        for value in (invalid, r'^[a-z-\p{L}]$', r'^[a-\d]$'):
            self.assertEqual(parse('URL-REGEX,' + value, purpose='proxy'),
                             ([], [f'line 1: invalid URL-REGEX {value}']))

    def test_generate_publish_single_regex_source_white_disk_and_invalid_freeze(self):
        check_generated_regex(self, r'^[a-z-\d]$', r'^[a-z--\d]$')

    def test_completed_range_then_single_hyphen_and_class_is_valid(self):
        value = r'^[a-z-\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([Rule('DOMAIN-REGEX', value)], []))

    def test_completed_range_then_double_hyphen_cannot_end_at_class(self):
        value = r'^[a-z--\d]$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value, purpose='block'),
                         ([], [f'line 1: invalid DOMAIN-REGEX {value}']))
