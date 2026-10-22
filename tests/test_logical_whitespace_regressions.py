import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


class LogicalWhitespaceRegressionTests(unittest.TestCase):
    def assert_projection(self, rules, surge, mihomo):
        outputs, diagnostics = render('space', normalize(iter(rules)), purpose='proxy', no_resolve='keep')
        top = rules[0].kind
        for name in ('fin.txt', 'fin-surge.txt'):
            self.assertEqual(outputs[name], '# space rules: 0\n' if surge is None else '# space rules: 1\n' + surge + '\n')
            if surge is None:
                self.assertEqual(diagnostics[name + ':' + top], 1)
            else:
                self.assertNotIn(name + ':' + top, diagnostics)
                self.assertEqual(parse(outputs[name], purpose='proxy')[1], [])
        self.assertEqual([json.loads(line[4:]) for line in outputs['fin.yaml'].splitlines()[2:]],
                         [] if mihomo is None else [mihomo])
        if mihomo is None:
            self.assertEqual(diagnostics['fin.yaml:' + top], 1)
        else:
            self.assertNotIn('fin.yaml:' + top, diagnostics)
            self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy')[1], [])
        self.assertEqual(outputs['fin-qx.txt'], '# space rules: 0\n')
        self.assertEqual(diagnostics['fin-qx.txt:' + top], 1)
        self.assertEqual(outputs['fin-surge-ds.txt'], '# space rules: 0\n')
        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
        return outputs

    def test_quoted_process_space_is_preserved_in_complete_logical_output(self):
        scalar, messages = parse('PROCESS-NAME," "', purpose='proxy')
        self.assertEqual(messages, [])
        scalar_output, _ = render('space', scalar, purpose='proxy', no_resolve='keep')
        self.assertEqual(scalar_output['fin.txt'], "# space rules: 1\nPROCESS-NAME,' '\n")
        self.assertEqual(json.loads(scalar_output['fin.yaml'].splitlines()[2][4:]),
                         r'PROCESS-NAME-REGEX,(?-i:\A\x{20}\z)')
        rules, messages = parse('OR,((PROCESS-NAME," "),(DOMAIN,keep.example.org))', purpose='proxy')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('space', normalize(iter(rules)), purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], "# space rules: 1\nOR,((PROCESS-NAME,' '),(DOMAIN,keep.example.org))\n")
        self.assertEqual(outputs['fin-surge.txt'], outputs['fin.txt'])
        self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]),
                         r'OR,((PROCESS-NAME-REGEX,(?-i:\A\x{20}\z)),(DOMAIN,keep.example.org))')
        self.assertNotIn('fin.txt:OR', diagnostics)
        self.assertNotIn('fin.yaml:OR', diagnostics)

    def test_thirteen_kinds_keep_their_existing_scalar_and_complete_logical_capabilities(self):
        values = [
            (' ', r'\ (?:)', r'^\ \.?$', '(?:) (?:)', r'(?-i:\A\x{20}\z)', False),
            ('\t', '\\\t', '^\\\t\\.?$', '\t', r'(?-i:\A\x{9}\z)', True),
            ('\xa0', '\xa0', '^\xa0\\.?$', '\xa0', r'(?-i:\A\x{A0}\z)', True),
            (' \t\xa0', '\\ \\\t\xa0', '^\\ \\\t\xa0\\.?$', '(?:) \t\xa0',
             r'(?-i:\A\x{20}\x{9}\x{A0}\z)', False),
        ]
        templates = ['AND,({leaf},(DOMAIN,keep.example.org))',
                     'OR,({leaf},(DOMAIN,keep.example.org))', 'NOT,({leaf})',
                     'NOT,((OR,({leaf},(DOMAIN,keep.example.org))))']
        for value, keyword, wildcard, regex, process, native_process in values:
            cases = [
                ('DOMAIN-KEYWORD', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX,' + keyword),
                ('DOMAIN-WILDCARD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX,' + wildcard),
                ('DOMAIN-REGEX', None, 'DOMAIN-REGEX,' + regex),
                ('URL-REGEX', 'URL-REGEX', None),
                ('PROCESS-NAME', 'PROCESS-NAME', 'PROCESS-NAME-REGEX,' + process),
                ('PROCESS-PATH', None, 'PROCESS-PATH,' + value if native_process else None),
                ('PROCESS-NAME-WILDCARD', 'PROCESS-NAME', 'PROCESS-NAME-WILDCARD,' + value if native_process else None),
                ('PROCESS-PATH-WILDCARD', None, 'PROCESS-PATH-WILDCARD,' + value if native_process else None),
                ('PROCESS-NAME-REGEX', None, 'PROCESS-NAME-REGEX,' + regex),
                ('PROCESS-PATH-REGEX', None, 'PROCESS-PATH-REGEX,' + regex),
                ('USER-AGENT', 'USER-AGENT', None), ('DEVICE-NAME', 'DEVICE-NAME', None),
                ('SUBNET', 'SUBNET', None),
            ]
            for kind, surge_kind, mihomo in cases:
                surge = surge_kind + ",'" + value + "'" if surge_kind else None
                for quote in ("'", '"'):
                    source = kind + ',' + quote + value + quote
                    parsed, messages = parse(source, purpose='proxy')
                    self.assertEqual(messages, [])
                    self.assertEqual(parsed[0].value, value)
                    with self.subTest(kind=kind, value=value, quote=quote, expression='scalar'):
                        self.assert_projection(parsed, surge, mihomo)
                    for template in templates:
                        expression = template.format(leaf='(' + source + ')')
                        parsed, messages = parse(expression, purpose='proxy')
                        self.assertEqual(messages, [])
                        expected_surge = template.format(leaf='(' + surge + ')') if surge else None
                        expected_mihomo = template.format(leaf='(' + mihomo + ')') if mihomo else None
                        with self.subTest(kind=kind, value=value, quote=quote, expression=template):
                            self.assert_projection(parsed, expected_surge, expected_mihomo)

    def test_true_empty_values_are_rejected_without_losing_independent_rules(self):
        kinds = ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX', 'URL-REGEX',
                 'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-NAME-WILDCARD', 'PROCESS-PATH-WILDCARD',
                 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX', 'USER-AGENT', 'DEVICE-NAME', 'SUBNET')
        for kind in kinds:
            for value in ("''", '""', '', ' ', '\t', '\xa0'):
                for template in ('NOT,(({leaf}))', 'OR,(({leaf}),(DOMAIN,keep.example.org))'):
                    text = template.format(leaf=kind + ',' + value) + '\nDOMAIN,neighbor.example.org\n'
                    with self.subTest(kind=kind, value=value, template=template):
                        parsed, messages = parse(text, purpose='proxy')
                        self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                        self.assertEqual(len(messages), 1)
                        self.assertTrue(messages[0].startswith('line 1: invalid logical expression '))

    def test_native_ascii_trim_and_literal_quotes_remain_distinct_from_ordinary_fields(self):
        cases = [('DOMAIN-KEYWORD', 'DOMAIN-KEYWORD', True),
                 ('DOMAIN-WILDCARD', None, True), ('DOMAIN-REGEX', None, True),
                 ('URL-REGEX', 'URL-REGEX', False), ('PROCESS-NAME', 'PROCESS-NAME', True),
                 ('PROCESS-PATH', None, True), ('PROCESS-NAME-WILDCARD', 'PROCESS-NAME', True),
                 ('PROCESS-PATH-WILDCARD', None, True), ('PROCESS-NAME-REGEX', None, True),
                 ('PROCESS-PATH-REGEX', None, True), ('USER-AGENT', 'USER-AGENT', False),
                 ('DEVICE-NAME', 'DEVICE-NAME', False), ('SUBNET', 'SUBNET', False)]
        for kind, surge_kind, mihomo_supported in cases:
            for value in ('\t', '\xa0'):
                expected_surge = surge_kind + ",'" + value + "'" if surge_kind else None
                expected_mihomo = kind + ',' + value if mihomo_supported else None
                expressions = [kind + ',' + value, 'NOT,((' + kind + ',' + value + '))']
                for expression in expressions:
                    native = 'payload:\n  - ' + json.dumps(expression)
                    parsed, messages = parse(native, purpose='proxy')
                    self.assertEqual(messages, [])
                    logical = expression.startswith('NOT,')
                    with self.subTest(kind=kind, value=value, logical=logical):
                        self.assert_projection(parsed,
                                               'NOT,((' + expected_surge + '))' if logical and expected_surge else expected_surge,
                                               'NOT,((' + expected_mihomo + '))' if logical and expected_mihomo else expected_mihomo)
            for expression in (kind + ', ', 'NOT,((' + kind + ', ))'):
                parsed, messages = parse('payload:\n  - ' + json.dumps(expression), purpose='proxy')
                self.assertEqual(parsed, [])
                self.assertEqual(len(messages), 1)
        source = 'payload:\n  - ' + json.dumps("NOT,((PROCESS-NAME,' '))")
        parsed, messages = parse(source, purpose='proxy')
        self.assertEqual(messages, [])
        self.assertTrue(parsed[0].literal_process)
        outputs, _ = render('space', parsed, purpose='proxy', no_resolve='keep')
        self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), "NOT,((PROCESS-NAME,' '))")
        self.assertNotIn('PROCESS-NAME-REGEX', outputs['fin.yaml'])

    def test_name_lists_uid_and_dscp_keep_their_special_empty_and_range_checks(self):
        for kind in ('IN-NAME', 'IN-USER', 'REMATCH-NAME'):
            for value in (' ', '\t', '\xa0', 'good/ ', '/good', 'good//other'):
                parsed, messages = parse('NOT,((' + kind + ',"' + value + '"))', purpose='proxy')
                self.assertEqual(parsed, [])
                self.assertEqual(len(messages), 1)
            for value in ('\x1c', '\x1d', '\x1e', '\x1f', 'good/\x1c'):
                parsed, messages = parse('NOT,((' + kind + ',"' + value + '"))', purpose='proxy')
                self.assertEqual(messages, [])
                self.assert_projection(parsed, None, 'NOT,((' + kind + ',' + value + '))')
        for kind in ('UID', 'DSCP'):
            for value in ("''", '""', "' '"):
                self.assertEqual(parse('NOT,((' + kind + ',' + value + '))', purpose='proxy')[0], [])
        for source, expected in (("NOT,((UID,'1000,2000'))", 'NOT,((UID,1000/2000))'),
                                 ('NOT,((UID,4294967296))', 'NOT,((UID,4294967296))'),
                                 ("NOT,((DSCP,'0,1'))", 'NOT,((DSCP,0/1))'),
                                 ("NOT,((DSCP,'\t'))", 'NOT,((DSCP,\t))')):
            parsed, messages = parse(source, purpose='proxy')
            self.assertEqual(messages, [])
            self.assert_projection(parsed, None, expected)
        for source in ("NOT,((UID,'\t'))", 'NOT,((UID,-1))', 'NOT,((DSCP,64))'):
            self.assertEqual(parse(source, purpose='proxy')[0], [])

    def test_target_depth_and_unsupported_leaf_never_publish_partial_logical_rules(self):
        leaf = '(PROCESS-NAME," ")'
        for depth in (10, 11):
            expression = leaf
            for _ in range(depth):
                expression = '(NOT,(' + expression + '))'
            parsed, messages = parse(expression[1:-1], purpose='proxy')
            self.assertEqual(messages, [])
            surge = expression[1:-1].replace('" "', "' '") if depth == 10 else None
            mihomo = expression[1:-1].replace('PROCESS-NAME," "', r'PROCESS-NAME-REGEX,(?-i:\A\x{20}\z)')
            self.assert_projection(parsed, surge, mihomo)
        source = 'OR,((PROCESS-PATH," "),(DOMAIN,inside.example.org))\nDOMAIN,neighbor.example.org\n'
        parsed, messages = parse(source, purpose='proxy')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('space', parsed, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# space rules: 1\nDOMAIN,neighbor.example.org\n')
        self.assertEqual(outputs['fin.yaml'], '# space rules: 1\npayload:\n  - "DOMAIN,neighbor.example.org"\n')
        for name in ('fin.txt', 'fin-surge.txt', 'fin.yaml', 'fin-qx.txt'):
            self.assertEqual(diagnostics[name + ':OR'], 1)
        for kind in ('URL-REGEX', 'PROCESS-NAME', 'PROCESS-PATH', 'USER-AGENT', 'DEVICE-NAME', 'SUBNET'):
            self.assertEqual(parse_whitelist(kind + '," "'), [])
        self.assertEqual(parse_whitelist('NOT,((PROCESS-NAME," "))'), [])
        for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX'):
            self.assertEqual(parse_whitelist(kind + '," "'), [Rule(kind, ' ')])

    def test_generate_publish_and_disk_sources_preserve_whitespace_and_ip_direction(self):
        source = ('\ufeffAND,((PROCESS-NAME," \t\xa0"),(IP-CIDR,192.0.2.0/24),'
                  '(SRC-IP-CIDR,198.51.100.0/24))\r\n').encode('utf-8')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'input.list').write_bytes(source)
                    (root / 'static').mkdir()
                    marker = root / 'static' / 'marker'
                    marker.write_bytes(b'static\x00')
                    configs = [dict(name=name, purpose=purpose, no_resolve=mode, sources=sources, whitelist=[])
                               for name, sources in (('parent', ['input.list']),
                                                     ('surge', ['parent/fin.txt']), ('yaml', ['parent/fin.yaml']))]
                    config = root / 'rulesets.json'
                    config.write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('parent', 'surge', 'yaml'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            old[path] = b'old product\n'
                            path.write_bytes(old[path])
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 18)
                    self.assertNotIn('frozen', logs.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    flag = ',no-resolve' if mode == 'add' else ''
                    surge = ("AND,((PROCESS-NAME,' \t\xa0'),(IP-CIDR,192.0.2.0/24" + flag +
                             '),(SRC-IP,198.51.100.0/24))')
                    mihomo = (r'AND,((PROCESS-NAME-REGEX,(?-i:\A\x{20}\x{9}\x{A0}\z)),'
                              '(IP-CIDR,192.0.2.0/24' + flag + '),(SRC-IP-CIDR,198.51.100.0/24))')
                    for group in ('parent', 'surge', 'yaml'):
                        self.assertEqual([json.loads(line[4:]) for line in outputs[root / group / 'fin.yaml'].splitlines()[2:]],
                                         [mihomo])
                        expected_surge = f'# {group} rules: 0\n' if group == 'yaml' else f'# {group} rules: 1\n' + surge + '\n'
                        self.assertEqual(outputs[root / group / 'fin.txt'], expected_surge)
                        self.assertEqual(outputs[root / group / 'fin-surge.txt'], expected_surge)
                        self.assertEqual(outputs[root / group / 'fin-qx.txt'], f'# {group} rules: 0\n')
                        self.assertEqual(outputs[root / group / 'fin-surge-ds.txt'], f'# {group} rules: 0\n')
                        self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose)[1], [])
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as disk_logs:
                        disk = generate(root, self.fail)
                    self.assertEqual(len(disk), 12)
                    self.assertNotIn('frozen', disk_logs.getvalue())
                    for path, text in disk.items():
                        self.assertEqual([line for line in text.splitlines() if not line.startswith('! Version:')],
                                         [line for line in outputs[path].splitlines() if not line.startswith('! Version:')])
                    before = {path: path.read_bytes() for path in outputs}
                    invalid_white = dict(configs[1], whitelist=['parent/fin.yaml'])
                    config.write_text(json.dumps([configs[0], invalid_white]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'unsupported rule'):
                        generate(root, self.fail)
                    self.assertEqual({path: path.read_bytes() for path in outputs}, before)
                    self.assertEqual((root / 'input.list').read_bytes(), source)
                    self.assertEqual(marker.read_bytes(), b'static\x00')

    def test_only_unsupported_logical_rules_freeze_all_old_products(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input.list').write_text('OR,((PROCESS-PATH," "),(DOMAIN,inside.example.org))\n', encoding='utf-8')
            config = dict(name='space', purpose='proxy', no_resolve='keep', sources=['input.list'], whitelist=[])
            (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
            (root / 'space').mkdir()
            old = {root / 'space' / name: b'old product\n' for name in FILES}
            for path, data in old.items():
                path.write_bytes(data)
            with contextlib.redirect_stderr(io.StringIO()) as logs:
                self.assertEqual(generate(root, self.fail), {})
            self.assertIn('no routable rules; frozen', logs.getvalue())
            self.assertEqual({path: path.read_bytes() for path in old}, old)
