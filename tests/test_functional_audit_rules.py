import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch
from urllib.error import HTTPError

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


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


class InlineOptionsAuditTests(unittest.TestCase):
    kinds = QuantifierAuditTests.kinds
    cases = (
        (r'^(?n)ads\.example\.com$', True), (r'^(?-n)ads\.example\.com$', True),
        (r'^(?in:ads)\.example\.com$', True), (r'^(?I)ads\.example\.com$', True),
        (r'^(?x+i)ads\.example\.com$', True),
        (r'^(?IMNSXDU:ads)\.example\.com$', True),
        (r'^(?imnsxdu)ads\.example\.com$', True),
        (r'^(?+-N++X--x+n-n+i:ads)\.example\.com$', True),
        (r'^(?+)ads$', True), (r'^(?---:)ads$', True),
        (r'^(?D-U)(?u-d:ads)+$', True), (r'^(?m-s:i)+$', True),
        (r'^(?n)(a)\k<1>$', False), (r'^(?N)(a)\1$', False),
        (r'^(?-n)(a)\k<1>$', True), (r'^(?n)(?-n:(a))\k<1>$', True),
        (r'^(?n:(a))(b)\k<1>$', True), (r'^(?n:(a))(b)\k<2>$', False),
        (r'^((?N)(a))(b)\k<2>$', True),
        (r'^(?N)((?-n)(a))(b)\k<1>$', True),
        (r'^(?<name>c)(?n:(a))(?-n:(b))\k<2>$', True),
        (r'^(?n)(?<7>a)(?-n:(b))(?<name>c)\k<1>\k<2>\k<7>$', True),
        (r'^(?N)(?-n:(a))(b)\k<2>$', False),
        (r'^(?n:(?<name>a))\k<name>\k<1>$', True),
        (r"^(?N:(?'name'a))\k'name'$", True),
        (r'^(?n)(?<name>a)(?<name>b)\k<1>$', True),
        (r'^(?n)(?<7>a)\k<7>$', True), (r'^(?n)(?<7>a)\k<1>$', False),
        (r'^(?n)(?<2147483647>a)\k<2147483647>$', True),
        (r'^(?n)(?<2147483648>a)$', False), (r'^(?n)(?<0>a)$', False),
        (r'^(?n)(?<name>a)(b)\k<2>$', False),
        (r'^(?n)(?-n:(a))(?<name>b)\k<1>\k<2>$', True),
        (r'^(?n)(a)(?(1)b|c)$', False),
        (r'^(?n)(?<name>a)(?(name)b|c)$', True),
        (r'^(?n)(?<7>a)(?(7)b|c)$', True),
        (r'^(?n)(?<7>a)(?(8)b|c)$', False),
        (r'^(?n)(?<name>a)(?(name)b|c|d)$', False),
        (r'^(?n)(?<name>a)(?<out-name>b)\k<out>$', True),
        (r'^(?n)(?<name>a)(?<out-missing>b)$', False),
        (r'^(?X:a[ # ])(?-X:b#c)$', True),
        (r'^(?X:a)(b)# [c]$', True), (r'^(?X:a)(b)# [', False),
        (r'^(?X)(?-x: +a) # ignored,PROXY [ #', True),
        (r'^(?X)(?#ignored,#) a+$', True),
        (r'^(?X)a(?-X) # [b]$', True), (r'^(?X)a(?-X) # [', False),
        (r'^(?X) +a$', False), (r'^(?n)+a$', False),
        (r'^a(?D){2}$', False), (r'^a(?+x-n)(?#note)+$', False),
        (r'^(?n:a)+$', True), (r'^(?d:)+a$', True),
        (r'^(?r)a$', False), (r'^(?e:a)$', False),
        (r'^(?R)a$', False), (r'^(?E:a)$', False),
        (r'^(?a:a)$', False), (r'^(?ia:a)$', False), (r'^(?ai:a)$', False),
        (r'^(?L)a$', False), (r'^(?c:a)$', False),
        (r'^(?inZ:a)$', False), (r'^(?n a)$', False), (r'^(?n:a$', False),
        (r'^(?n)(?(?i:a)b|c)$', False),
        (r'^(?n)\u{61}$', False),
        (r'^[(?n)]+(a)\k<1>$', True), (r'^\(\?n\)(a)\k<1>$', True),
    )

    def test_public_parse_keeps_regexp2_inline_options_raw(self):
        for value, valid in self.cases[:5]:
            with self.subTest(value=value):
                self.assertEqual(parse('DOMAIN-REGEX,' + value + '\nDOMAIN,keep.example.com', purpose='block'),
                                 ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'keep.example.com')], []))

    def test_options_capture_and_scope_follow_fixed_regexp2_at_public_parse(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            for value, valid in self.cases:
                for native in (False, True):
                    for quoted in (False, True):
                        field = ('"' + value + '"' if native else json.dumps(value)) if quoted else value
                        checked = field if native else value
                        expression = f'(({kind},{field}),(NETWORK,tcp))'
                        for operator in ('top', 'AND', 'OR', 'NOT'):
                            if not native and not quoted and operator == 'top' and ' #' in value:
                                continue
                            logic = f'(({kind},{field}))' if operator == 'NOT' else expression
                            matcher = kind + ',' + field if operator == 'top' else operator + ',' + logic
                            text = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                    matcher + '\nDOMAIN,keep.example.com')
                            expected = Rule(kind, checked) if operator == 'top' else Rule(operator, logic, native_fields=native)
                            neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                            with self.subTest(kind=kind, value=value, native=native, quoted=quoted, operator=operator):
                                parsed, messages = parse(text, purpose='proxy')
                                self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                                self.assertEqual(len(messages), int(not valid))
                                if messages:
                                    self.assertTrue(messages[0].startswith(f'line {2 if native else 1}:'))
                                self.assertEqual(set(normalize(parsed)), set(parsed))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_native_newline_comments_restore_x_and_n_state(self):
        for value, valid in (
                ('^(?XN:ads # ignored,(#)\n)(a)\\k<1>$', True),
                ('^(?XN:ads # ignored,(#)\n)(a)\\k<2>$', False),
                ('^(?XN)(?-x-n: +a)(b)\\k<1>$', False),
                ('^(?XN)(?-x-n:(a))(b)\\k<1>$', True),
                ('^(?X)(?-x: +a) # ignored\n+$', True),
                ('^(?X)(?n) # ignored\n+$', False)):
            for kind in self.kinds:
                with self.subTest(value=value, kind=kind):
                    parsed, messages = parse(native_text(kind + ',' + value, 'DOMAIN,keep.example.com'), purpose='block')
                    self.assertEqual(parsed, ([Rule(kind, value)] if valid else []) +
                                     [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')])
                    self.assertEqual(messages, [] if valid else [f'line 2: invalid {kind} {value}'])

    def test_x_comments_keep_logical_siblings_and_source_policy_boundaries(self):
        value = r'^(?X+N)ads # ignored,PROXY [ #'
        for operator in ('AND', 'OR', 'NOT'):
            expression = f'((DOMAIN-REGEX,{value}))' if operator == 'NOT' else f'((DOMAIN-REGEX,{value}),(NETWORK,tcp))'
            for policy, purpose in (('REJECT', 'block'), ('DIRECT', 'direct'), ('PROXY', 'proxy')):
                with self.subTest(operator=operator, purpose=purpose):
                    self.assertEqual(parse(f'{operator},{expression},{policy} # tail (\nDOMAIN,keep.example.com,{policy}',
                                           purpose=purpose),
                                     ([Rule(operator, expression), Rule('DOMAIN', 'keep.example.com')], []))
        self.assertEqual(parse('DOMAIN-REGEX,' + value + '\nDOMAIN,keep.example.com', purpose='proxy'),
                         ([Rule('DOMAIN', 'keep.example.com')], ['line 1: ambiguous unquoted regex comment']))
        value = r'^(?X+N)(?#note(,)ads$'
        expression = f'((DOMAIN-REGEX,{value}),(NETWORK,tcp))'
        parsed, messages = parse('AND,' + expression, purpose='proxy')
        self.assertEqual((parsed, messages), ([Rule('AND', expression)], []))
        outputs, _ = render('options', parsed, purpose='proxy', no_resolve='keep')
        wanted = r'((DOMAIN-REGEX,^(?X+N)(?#note\x{28},)ads$),(NETWORK,tcp))'
        self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'), ([Rule('AND', wanted, native_fields=True)], []))

    def test_whitelist_and_long_options_keep_raw_capture_identity(self):
        values = [(value, valid) for value, valid in self.cases]
        values += [(r'^(?' + '+N-x+i-' * 1000 + r'n)(a)\k<1>$', True),
                   (r'^(?N)(?<name>a)\k<' + '0' * 5000 + '1>$', True),
                   (r'^(?N)(a)\k<' + '0' * 5000 + '1>$', False)]
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for value, valid in values:
            for native in (False, True):
                text = (native_text('DOMAIN-REGEX,' + value, 'DOMAIN,keep.example.com') if native else
                        'DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,keep.example.com')
                with self.subTest(value=value[:80], length=len(value), native=native), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    selected = parse_whitelist(text)
                    self.assertEqual(selected, ([Rule('DOMAIN-REGEX', value)] if valid else []) +
                                     [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')])
                    self.assertEqual([str(item.message) for item in caught],
                                     [] if valid else [f'line {2 if native else 1}: invalid DOMAIN-REGEX {value}'])
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_url_regex_keeps_independent_python_options_and_capture_rules(self):
        for value, valid in ((r'(?i)^ads$', True), (r'^(?i:ads)$', True),
                             (r'^(?u:ads)$', True), (r'^(?a:ads)$', True),
                             (r'^(?P<name>ads)(?P=name)$', True),
                             (r'^(?n)ads$', False), (r'^(?-n)ads$', False),
                             (r'^(?I)ads$', False), (r'^(?x+i)ads$', False),
                             (r'^(?d:ads)$', False), (r'^(?N:(a))\k<1>$', False)):
            with self.subTest(value=value):
                self.assertEqual(parse('URL-REGEX,' + json.dumps(value) + '\nDOMAIN,keep.example.com', purpose='proxy'),
                                 (([Rule('URL-REGEX', value)] if valid else []) + [Rule('DOMAIN', 'keep.example.com')],
                                  [] if valid else ['line 1: invalid URL-REGEX ' + value]))

    def test_render_preserves_options_allow_white_and_source_identity(self):
        value = r'^(?IN-D+u)(?<ad>ads)(?-n:(a))\k<1>\k<2>$'
        blocker = Rule('DOMAIN-REGEX', value)
        allowed = Rule('DOMAIN-REGEX', value, allow=True)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    outputs, skipped = render('options', iter([blocker, allowed]), purpose=purpose, no_resolve=mode,
                                              whitelist=iter([Rule('DOMAIN-REGEX', r'^(?N)other$')]))
                    self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([blocker], []))
                    self.assertIn(json.dumps('DOMAIN-REGEX,' + value), outputs['fin.yaml'])
                    self.assertEqual(normalize([allowed, blocker]), [blocker, allowed])
                    self.assertEqual(allowed.value, value)
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 3 if purpose == 'block' else 2)

    def test_generate_options_white_publish_and_same_round_disk_dependencies(self):
        value = r'^(?IN-D+u)(?<ad>ads)(?-n:(a))\k<1>\k<2>(?X:(?#note,#)[ #]+)$'
        invalid = r'^(?N)(ads)\k<1>$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            flag = '' if mode == 'strip' else ',no-resolve'
                            initial = '' if mode == 'add' else ',no-resolve'
                            field = value if native else json.dumps(value)
                            logic = f'((NOT,((DOMAIN-REGEX,{field}))),(OR,((PROCESS-NAME-REGEX,{field}),(NETWORK,tcp))),'
                            logic += f'(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            wanted = f'((NOT,((DOMAIN-REGEX,{value}))),(OR,((PROCESS-NAME-REGEX,{value}),(NETWORK,tcp))),'
                            wanted += f'(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = [*(kind + ',' + field for kind in self.kinds), 'AND,' + logic,
                                        'IP-CIDR,192.0.2.0/24' + initial, 'SRC-IP-CIDR,198.51.100.0/24',
                                        'DOMAIN-REGEX,' + invalid, 'DOMAIN,covered.example.com', 'DOMAIN,keep.example.com']
                            source = (native_text(*matchers) if native else '\n'.join(matchers)) + '\n@@||allow.example.com^\n'
                            white = (native_text('DOMAIN-REGEX,^(?N)other$', 'DOMAIN,covered.example.com') if native else
                                     "DOMAIN-REGEX,'^(?N)other$'\nDOMAIN,covered.example.com\n")
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'input.list'],
                                        'whitelist': ['https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            (root / 'input.list').write_text(source, encoding='utf-8')
                            (root / 'static').mkdir()
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'input.list', root / 'static/white.list')}
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            self.assertIn('invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            expected = {*(Rule(kind, value) for kind in self.kinds), Rule('AND', wanted, native_fields=True),
                                        Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                        Rule('SRC-IP-CIDR', '198.51.100.0/24'),
                                        Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')}
                            self.assertEqual(list(outputs), [root / group / name for group in ('source', 'child') for name in FILES])
                            for group in ('source', 'child'):
                                self.assertEqual(set(parse(outputs[root / group / 'fin.yaml'], purpose=purpose)[0]), expected)
                                self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose)[1], [])
                                for kind in self.kinds:
                                    self.assertIn(json.dumps(kind + ',' + value), outputs[root / group / 'fin.yaml'])
                                self.assertNotIn('covered.example.com', outputs[root / group / 'fin.yaml'])
                                self.assertEqual(outputs[root / group / 'fin.txt'].splitlines()[1:],
                                                 ['DOMAIN,keep.example.com', 'IP-CIDR,192.0.2.0/24' + flag,
                                                  'SRC-IP,198.51.100.0/24'])
                                self.assertEqual(outputs[root / group / 'fin-surge-ds.txt'].splitlines()[1:], ['keep.example.com'])
                            if purpose == 'block':
                                self.assertIn('@@||allow.example.com^\n', outputs[root / 'source/fin-adb.txt'])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'input.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_options_in_generated_white_use_same_round_and_disk_bytes(self):
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['white.list'], 'whitelist': []},
                           {'name': 'source', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                value, white_value = r'^(?N)(?<ad>ads)\k<1>$', r'^(?XN:other)$'
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                (root / 'white.list').write_text(native_text('DOMAIN-REGEX,' + white_value,
                                                            'DOMAIN,covered.example.com'), encoding='utf-8')
                (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value,
                                                            'DOMAIN,covered.example.com', 'DOMAIN,keep.example.com'), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                                 [Rule('DOMAIN', 'covered.example.com', domain_source='mihomo'), Rule('DOMAIN-REGEX', white_value)])
                for group in ('source', 'child'):
                    self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                     ([Rule('DOMAIN', 'keep.example.com', domain_source='mihomo'), Rule('DOMAIN-REGEX', value)], []))
                publish(outputs, root=root)
                published = {path: path.read_bytes() for path in outputs}
                (root / 'input.list').unlink()
                (root / 'white.list').unlink()
                (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    disk = generate(root, lambda url: self.fail(url))
                self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({root / 'static/white.list': outputs[root / 'white/fin.yaml']}, root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                configs[1]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_invalid_options_white_keeps_local_error_and_remote_skip(self):
        for invalid in (r'^(?R)ads$', r'^(?N)(ads)\k<1>$'):
            for remote in (False, True):
                with self.subTest(invalid=invalid, remote=remote), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = [{'name': 'source', 'purpose': 'block', 'no_resolve': 'keep',
                               'sources': ['input.list'],
                               'whitelist': ['https://example.com/white' if remote else 'white.list']}]
                    value = r'^(?N)ads$'
                    white = native_text('DOMAIN-REGEX,' + invalid)
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value), encoding='utf-8')
                    (root / 'white.list').write_text(white, encoding='utf-8')
                    (root / 'source').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'source' / name
                        path.write_bytes(b'old product\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        if remote:
                            outputs = generate(root, lambda url: white.encode('utf-8'))
                            self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose='block'), ([Rule('DOMAIN-REGEX', value)], []))
                            self.assertIn('invalid whitelist (line 2: invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                        else:
                            with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                                generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)


class BracedHexAuditTests(unittest.TestCase):
    kinds = QuantifierAuditTests.kinds
    cases = (
        (r'^\x{000061}$', True), (r'^\x{0000061}$', True),
        (r'^\x{' + '0' * 5000 + '61}$', True),
        (r'^\x{' + '0' * 5000 + '}$', True),
        (r'^\x{' + '0' * 5000 + '10fFFF}$', True),
        (r'^\x{10FFFF}$', True), (r'^\x{D800}$', True),
        (r'^\x{000002E}+$', True), (r'^\x{0000061}{1,2}$', True),
        (r'^[\x{0000061}-\x{0000063}]$', True),
        (r'^[\x{0000028}-\x{0000029}]$', True),
        (r'^[\x{000005C}\x{000005D}\x{000005E}\x{000002D}]$', True),
        (r'^\\x{0000061}$', True), (r'^\\x{110000}$', True),
        (r'^\\x{' + 'F' * 5000 + '}$', True),
        (r'^[\x{0000063}-\x{0000061}]$', False),
        (r'^[\x{0000061}-\d]$', False),
        (r'^\x{110000}$', False),
        (r'^\x{' + '0' * 5000 + '110000}$', False),
        (r'^\x{' + 'F' * 5000 + '}$', False),
        (r'^\x{}$', False), (r'^\x{0_61}$', False),
        (r'^\x{+61}$', False), (r'^\x{-61}$', False),
        (r'^\x{0x61}$', False), (r'^\x{６１}$', False),
        (r'^\x{' + '0' * 5000 + 'g}$', False),
        (r'^\x{ 61}$', False), (r'^\x{61$', False),
    )

    def test_public_parse_and_normalize_preserve_raw_hex_with_quoted_and_logical_fields(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            for value, valid in self.cases:
                for native in (False, True):
                    for quoted in (False, True):
                        for logical in (False, True):
                            field = f"'{value}'" if quoted else value
                            checked = field if native else value
                            expression = f'(({kind},{field}),(NETWORK,tcp))'
                            matcher = f'AND,{expression}' if logical else f'{kind},{field}'
                            source = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                      matcher + '\nDOMAIN,keep.example.com')
                            neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                            expected = Rule('AND', expression, native_fields=native) if logical else Rule(kind, checked)
                            with self.subTest(kind=kind, length=len(value), native=native, quoted=quoted, logical=logical):
                                parsed, messages = parse(source, purpose='proxy')
                                self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                                self.assertEqual(set(normalize(parsed)), set(parsed))
                                if valid:
                                    self.assertEqual(parsed[0].value, expression if logical else checked)
                                self.assertEqual(len(messages), int(not valid))
                                if messages:
                                    self.assertTrue(messages[0].startswith(f'line {2 if native else 1}: invalid '))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_domain_whitelist_preserves_legal_hex_and_warns_only_for_invalid_lines(self):
        for value, valid in self.cases:
            for native in (False, True):
                for quoted in (False, True):
                    field = f"'{value}'" if quoted else value
                    text = (native_text('DOMAIN-REGEX,' + field, 'DOMAIN,keep.example.com') if native else
                            f'DOMAIN-REGEX,{field}\nDOMAIN,keep.example.com')
                    with self.subTest(length=len(value), native=native, quoted=quoted), warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        white = parse_whitelist(text)
                        checked = field if native else value
                        self.assertEqual([rule.value for rule in white], ([checked] if valid else []) + ['keep.example.com'])
                        self.assertEqual(len(caught), int(not valid))

    def test_generated_hex_white_uses_same_round_and_disk_bytes(self):
        value = r'^\x{' + '0' * 5000 + '61}$'
        white_value = r'^\x{' + '0' * 5000 + '62}$'
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['white.list'], 'whitelist': []},
                           {'name': 'source', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                (root / 'white.list').write_text(native_text('DOMAIN-REGEX,' + white_value,
                                                            'DOMAIN,covered.example.com'), encoding='utf-8')
                (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value, 'DOMAIN,covered.example.com',
                                                            'DOMAIN,keep.example.com'), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                                 [Rule('DOMAIN', 'covered.example.com', domain_source='mihomo'),
                                  Rule('DOMAIN-REGEX', white_value)])
                for group in ('source', 'child'):
                    self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                     ([Rule('DOMAIN', 'keep.example.com', domain_source='mihomo'),
                                       Rule('DOMAIN-REGEX', value)], []))
                publish(outputs, root=root)
                published = {path: path.read_bytes() for path in outputs}
                (root / 'input.list').unlink()
                (root / 'white.list').unlink()
                (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    disk = generate(root, lambda url: self.fail(url))
                self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({root / 'static/white.list': outputs[root / 'white/fin.yaml']}, root=root)
                self.assertFalse((root / 'static').exists())
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                configs[1]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_invalid_hex_white_keeps_local_error_and_remote_skip_boundaries(self):
        value = r'^\x{' + '0' * 5000 + '61}$'
        for invalid in (r'^\x{}$', r'^\x{110000}$', r'^\x{' + '0' * 5000 + 'g}$'):
            for remote in (False, True):
                with self.subTest(length=len(invalid), remote=remote), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = [{'name': 'source', 'purpose': 'block', 'no_resolve': 'keep',
                               'sources': ['input.list'],
                               'whitelist': ['https://example.com/white' if remote else 'white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value), encoding='utf-8')
                    white = native_text('DOMAIN-REGEX,' + invalid)
                    (root / 'white.list').write_text(white, encoding='utf-8')
                    (root / 'source').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'source' / name
                        path.write_bytes(b'old product\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        if remote:
                            outputs = generate(root, lambda url: white.encode('utf-8'))
                            self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose='block'),
                                             ([Rule('DOMAIN-REGEX', value)], []))
                            self.assertIn('invalid whitelist (line 2: invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                        else:
                            with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                                generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)

    def test_double_quoted_fields_decode_only_ordinary_source(self):
        for kind in self.kinds:
            for value in (r'^\x{000061}$', r'^\x{' + '0' * 5000 + '61}$'):
                for native in (False, True):
                    field = '"' + value + '"' if native else json.dumps(value)
                    expression = f'(({kind},{field}),(NETWORK,tcp))'
                    for matcher in (kind + ',' + field, 'AND,' + expression):
                        document = native_text(matcher) if native else matcher
                        expected = (Rule('AND', expression, native_fields=native) if matcher.startswith('AND,') else
                                    Rule(kind, field if native else value))
                        with self.subTest(kind=kind, length=len(value), native=native, logical=matcher.startswith('AND,')):
                            self.assertEqual(parse(document, purpose='proxy'), ([expected], []))
                            if kind == 'DOMAIN-REGEX' and not matcher.startswith('AND,'):
                                self.assertEqual(parse_whitelist(document), [expected])

    def test_direct_render_preserves_hex_matcher_and_allow_identity(self):
        value = r'^\x{' + '0' * 5000 + '61}$'
        blocker = Rule('DOMAIN-REGEX', value)
        allowed = Rule('DOMAIN-REGEX', value, allow=True)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    outputs, _ = render('hex', [blocker, allowed], purpose=purpose, no_resolve=mode,
                                        whitelist=[Rule('DOMAIN-REGEX', r'^\x{0000062}$')])
                    self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([blocker], []))
                    self.assertEqual(normalize([allowed, blocker]), [blocker, allowed])
                    self.assertEqual(allowed.value, value)

    def test_url_regex_keeps_python_hex_semantics(self):
        for value in (r'^\x{0000061}$', r'^\x{' + '0' * 5000 + '61}$'):
            with self.subTest(length=len(value)):
                parsed, messages = parse(f"URL-REGEX,'{value}'\nDOMAIN,keep.example.com", purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.com')])
                self.assertEqual(messages, ['line 1: invalid URL-REGEX ' + value])
        value = r'^\x61$'
        self.assertEqual(parse(f"URL-REGEX,'{value}'", purpose='proxy'), ([Rule('URL-REGEX', value)], []))

    def test_generate_local_remote_white_publish_and_yaml_dependencies_preserve_raw_hex(self):
        legal = r'^\x{' + '0' * 5000 + '61}$'
        legal_white = r'^\x{' + '0' * 5000 + '62}$'
        invalid = r'^\x{110000}$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            flag = '' if mode == 'strip' else ',no-resolve'
                            initial = '' if mode == 'add' else ',no-resolve'
                            leaf = legal if native else f"'{legal}'"
                            logic = f'((NOT,((DOMAIN-REGEX,{leaf}))),(OR,((PROCESS-NAME-REGEX,{leaf}),(NETWORK,tcp))),'
                            logic += f'(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            wanted = f'((NOT,((DOMAIN-REGEX,{legal}))),(OR,((PROCESS-NAME-REGEX,{legal}),(NETWORK,tcp))),'
                            wanted += f'(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = [*(kind + ',' + leaf for kind in self.kinds), 'AND,' + logic,
                                        'IP-CIDR,192.0.2.0/24' + initial, 'SRC-IP-CIDR,198.51.100.0/24',
                                        'DOMAIN-REGEX,' + invalid, 'DOMAIN,keep.example.com']
                            source = (native_text(*matchers) if native else '\n'.join(matchers)) + '\n@@||allow.example.com^\n'
                            white = (native_text('DOMAIN-REGEX,' + legal_white, 'DOMAIN,other.example.com') if native else
                                     f"DOMAIN-REGEX,'{legal_white}'\nDOMAIN,other.example.com\n")
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'input.list'],
                                        'whitelist': ['https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            (root / 'input.list').write_text(source, encoding='utf-8')
                            (root / 'static').mkdir()
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'input.list', root / 'static/white.list')}
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            self.assertIn('invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            expected = {*(Rule(kind, legal) for kind in self.kinds),
                                        Rule('AND', wanted, native_fields=True),
                                        Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                        Rule('SRC-IP-CIDR', '198.51.100.0/24'),
                                        Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')}
                            self.assertEqual(list(outputs), [root / group / name for group in ('source', 'child') for name in FILES])
                            for group in ('source', 'child'):
                                parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(set(parsed), expected)
                                self.assertEqual(messages, [])
                                for kind in self.kinds:
                                    self.assertIn(json.dumps(kind + ',' + legal), outputs[root / group / 'fin.yaml'])
                            if purpose == 'block':
                                self.assertIn('@@||allow.example.com^\n', outputs[root / 'source/fin-adb.txt'])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'input.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
