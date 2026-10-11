import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch

from generate import generate, publish
from rules import Rule, parse, parse_whitelist


def native_text(*matchers):
    return 'payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)


class QuantifierAuditTests(unittest.TestCase):
    kinds = ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX')
    cases = (
        ('a{' + '9' * 5000 + '}', False),
        ('a{' + '0' * 5000 + '1}', True),
        ('a{2147483648}', False), ('a{1,2147483648}', False),
        ('a{2147483648,}', False), ('a{2147483648,2147483648}', False),
        ('a{2,1}', False), ('a{0}', True), ('a{0,}', True),
        ('a{2147483647}', True), ('a{0001,0002}', True),
        ('a{xyz}', True), ('a{,4294967295}', True),
        ('a{,' + '9' * 5000 + '}', True),
        ('a{,' + '0' * 5000 + '1}', True),
    )

    def test_regexp2_quantifiers_preserve_raw_matchers_and_line_warnings(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            for value, valid in self.cases:
                for native in (False, True):
                    for logical in (False, True):
                        expression = f'(({kind},{value}),(NETWORK,tcp))'
                        matcher = f'AND,{expression}' if logical else f'{kind},{value}'
                        source = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                  (matcher if logical else f'{kind},\'{value}\'') + '\nDOMAIN,keep.example.com')
                        neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                        expected = Rule('AND', expression, native_fields=native) if logical else Rule(kind, value)
                        with self.subTest(kind=kind, length=len(value), native=native, logical=logical):
                            parsed, messages = parse(source, purpose='block')
                            self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                            if valid:
                                self.assertEqual(parsed[0].value, expression if logical else value)
                            self.assertEqual(len(messages), int(not valid))
                            if messages:
                                self.assertTrue(messages[0].startswith(f'line {2 if native else 1}: invalid '))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_domain_white_and_url_regex_numeric_failures_do_not_stop_neighbors(self):
        for value, valid in self.cases[:6] + self.cases[-3:]:
            for native in (False, True):
                text = (native_text('DOMAIN-REGEX,' + value, 'DOMAIN,keep.example.com') if native else
                        f"DOMAIN-REGEX,'{value}'\nDOMAIN,keep.example.com")
                with self.subTest(length=len(value), valid=valid, native=native), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    white = parse_whitelist(text)
                    self.assertEqual([rule.value for rule in white], ([value] if valid else []) + ['keep.example.com'])
                    self.assertEqual(len(caught), int(not valid))
        for value in ('a{' + '9' * 5000 + '}', 'a{' + '0' * 5000 + '1}'):
            with self.subTest(url_length=len(value)):
                parsed, messages = parse(f"URL-REGEX,'{value}'\nDOMAIN,keep.example.com", purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.com')])
                self.assertEqual(messages, ['line 1: invalid URL-REGEX ' + value])
        self.assertEqual(parse("URL-REGEX,'a{2147483648}'", purpose='proxy'),
                         ([Rule('URL-REGEX', 'a{2147483648}')], []))

    def test_unexpected_compiler_value_error_propagates_from_public_parse(self):
        for kind in (*self.kinds, 'URL-REGEX'):
            failure = ValueError('unexpected regex compiler failure')
            with self.subTest(kind=kind), patch('rules.re.compile', side_effect=failure):
                with self.assertRaises(ValueError) as caught:
                    parse(f"{kind},'^ok$'\nDOMAIN,keep.example.com", purpose='proxy')
                self.assertIs(caught.exception, failure)

    def test_generate_local_remote_white_and_yaml_dependencies_keep_legal_long_zero(self):
        legal = 'a{' + '0' * 5000 + '1}'
        invalid = 'a{' + '9' * 5000 + '}'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.yaml'], 'whitelist': ['https://example.com/white' if remote else 'white.txt']},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'], 'whitelist': []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        source = native_text(*(kind + ',' + legal for kind in self.kinds), 'DOMAIN-REGEX,' + invalid, 'DOMAIN,keep.example.com')
                        (root / 'input.yaml').write_text(source, encoding='utf-8')
                        white = f"DOMAIN-REGEX,'{legal}'\nDOMAIN-REGEX,'{invalid}'\nDOMAIN,other.example.com\n"
                        (root / 'white.txt').write_text(white, encoding='utf-8')
                        with warnings.catch_warnings(record=True), contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            warnings.simplefilter('always')
                            outputs = generate(root, lambda url: white.encode('utf-8'))
                        self.assertIn('invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                        expected = {*(Rule(kind, legal) for kind in self.kinds), Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')}
                        for group in ('source', 'child'):
                            for kind in self.kinds:
                                self.assertIn(json.dumps(kind + ',' + legal), outputs[root / group / 'fin.yaml'])
                            parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                            self.assertEqual(set(parsed), expected)
                            self.assertEqual(messages, [])
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()):
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk[root / 'child' / 'fin.yaml'], outputs[root / 'child' / 'fin.yaml'])
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
