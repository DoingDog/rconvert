import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


class RoutingFieldTests(unittest.TestCase):
    def parsed(self, source, purpose='proxy'):
        rules, warnings = parse(source, purpose=purpose)
        self.assertEqual(warnings, [])
        return normalize(rules)

    def yaml_body(self, outputs):
        return [json.loads(line[4:]) for line in outputs['fin.yaml'].splitlines()[2:]]


class MihomoProcessSpaceTests(RoutingFieldTests):
    def test_quoted_trailing_space_is_target_local_unsupported(self):
        rules = self.parsed("PROCESS-PATH,'/123/456 ',PROXY")
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(rules[0].value, '/123/456 ')
        self.assertEqual(outputs['fin.yaml'], '# fields rules: 0\npayload:\n')
        self.assertEqual(diagnostics['fin.yaml:PROCESS-PATH'], 1)
        self.assertEqual(outputs['fin.txt'], "# fields rules: 1\nPROCESS-NAME,'/123/456 '\n")
        self.assertEqual(outputs['fin-surge.txt'], outputs['fin.txt'])
        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_ascii_space_matrix_skips_whole_logical_once(self):
        for kind, base in (('PROCESS-PATH', '/123/456'), ('PROCESS-NAME-WILDCARD', '*'),
                           ('PROCESS-PATH-WILDCARD', '/123/*')):
            for value in (' ' + base, base + ' ', ' ' + base + ' ', '   '):
                for quote in ("'", '"'):
                    leaf = f'{kind},{quote}{value}{quote}'
                    cases = ((kind, leaf), ('AND', f'AND,(({leaf}),(NETWORK,tcp))'),
                             ('OR', f'OR,(({leaf}),(NETWORK,udp))'), ('NOT', f'NOT,(({leaf}))'),
                             ('NOT', f'NOT,((AND,(({leaf}),({leaf}),(IP-CIDR,192.0.2.0/24))))'))
                    for top, source in cases:
                        for purpose in ('block', 'direct', 'proxy'):
                            for mode in ('add', 'strip', 'keep'):
                                with self.subTest(kind=kind, value=value, top=top, purpose=purpose, mode=mode):
                                    rules = self.parsed(source, purpose)
                                    outputs, diagnostics = render('fields', rules, purpose=purpose, no_resolve=mode)
                                    self.assertEqual(self.yaml_body(outputs), [])
                                    self.assertEqual(diagnostics['fin.yaml:' + top], 1)
                                    self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
        outputs, diagnostics = render('fields', [Rule('PROCESS-NAME', '123 ', literal_process=True)],
                                      purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), [])
        self.assertEqual(diagnostics['fin.yaml:PROCESS-NAME'], 1)

    def test_other_whitespace_and_literal_hex_process_keep_existing_support(self):
        for kind, base in (('PROCESS-NAME', '123'), ('PROCESS-PATH', '/123/456'),
                           ('PROCESS-NAME-WILDCARD', '123'), ('PROCESS-PATH-WILDCARD', '/123/456')):
            for value in (base[:2] + ' ' + base[2:], '\t' + base, base + '\t', '\xa0' + base,
                          base + '\u2000', base + '\u2003', base + '\u3000', base + "'\"\\"):
                with self.subTest(kind=kind, value=value):
                    rules = self.parsed('payload:\n  - ' + json.dumps(kind + ',' + value))
                    outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
                    self.assertEqual(self.yaml_body(outputs), [kind + ',' + value])
                    self.assertNotIn('fin.yaml:' + kind, diagnostics)
        rules = self.parsed("PROCESS-NAME,'123 ',PROXY")
        outputs, _ = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), [r'PROCESS-NAME-REGEX,(?-i:\A\x{31}\x{32}\x{33}\x{20}\z)'])
        native = self.parsed('payload:\n  - "PROCESS-PATH, /123/456 "')
        outputs, _ = render('fields', native, purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), ['PROCESS-PATH,/123/456'])
        self.assertEqual(parse_whitelist("PROCESS-PATH,'/123/456 '"), [])
        blocker = Rule('PROCESS-PATH', '/123/456 ')
        outputs, diagnostics = render('fields', [blocker, Rule('PROCESS-PATH', '/123/456 ', allow=True)],
                                      purpose='block', no_resolve='keep', whitelist=[blocker])
        self.assertEqual(diagnostics['fin.yaml:PROCESS-PATH'], 2)
        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_generated_and_disk_yaml_keep_only_safe_matchers(self):
        source = ("PROCESS-PATH,'/123/456 '\nPROCESS-NAME-WILDCARD,'* '\n"
                  "PROCESS-PATH-WILDCARD,'/123/* '\nDOMAIN,keep.example.org\n")
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    configs = [{'name': name, 'purpose': purpose, 'no_resolve': mode,
                                'sources': sources, 'whitelist': []} for name, sources in
                               (('parent', ['input.list']), ('child', ['parent/fin.yaml']))]
                    (root / 'input.list').write_text(source, encoding='utf-8')
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 12)
                    for group in ('parent', 'child'):
                        self.assertEqual(outputs[root / group / 'fin.yaml'],
                                         f'# {group} rules: 1\npayload:\n  - "DOMAIN,keep.example.org"\n')
                    self.assertIn('parent fin.yaml:PROCESS-PATH: 1', logs.getvalue())
                    self.assertIn("PROCESS-NAME,'/123/456 '\n", outputs[root / 'parent' / 'fin.txt'])
                    publish(outputs, root=root)
                    self.assertEqual((root / 'input.list').read_text(encoding='utf-8'), source)
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, self.fail)
                    self.assertEqual(disk[root / 'child' / 'fin.yaml'], outputs[root / 'child' / 'fin.yaml'])

    def test_fully_unsupported_process_freezes_old_products(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input.list').write_text("PROCESS-PATH,'/tmp/foo ',PROXY\n", encoding='utf-8')
            (root / 'rulesets.json').write_text(json.dumps([{'name': 'parent', 'purpose': 'proxy',
                'no_resolve': 'keep', 'sources': ['input.list'], 'whitelist': []}]), encoding='utf-8')
            (root / 'parent').mkdir()
            old = {root / 'parent' / name: ('old ' + name).encode() for name in FILES}
            for path, data in old.items():
                path.write_bytes(data)
            with contextlib.redirect_stderr(io.StringIO()) as logs:
                self.assertEqual(generate(root, self.fail), {})
            self.assertIn('no routable rules; frozen', logs.getvalue())
            self.assertEqual({path: path.read_bytes() for path in old}, old)


class MihomoCommaTests(RoutingFieldTests):
    def test_quoted_inbound_comma_is_target_local_unsupported(self):
        rules = self.parsed("IN-NAME,'foo,bar'")
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(rules[0].value, 'foo,bar')
        self.assertEqual(self.yaml_body(outputs), [])
        self.assertEqual(diagnostics['fin.yaml:IN-NAME'], 1)
        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_final_payload_comma_matrix_and_public_native_matchers(self):
        for kind in ('IN-NAME', 'IN-USER', 'REMATCH-NAME'):
            for value in ('foo,bar', ',foo', 'foo,', 'foo/,bar', r'foo\,bar'):
                for quote in ("'", '"'):
                    leaf = f'{kind},{quote}{value}{quote}'
                    cases = ((kind, leaf), ('AND', f'AND,(({leaf}),(NETWORK,tcp))'),
                             ('OR', f'OR,(({leaf}),(NETWORK,udp))'), ('NOT', f'NOT,(({leaf}))'),
                             ('NOT', f'NOT,((AND,(({leaf}),({leaf}),(SRC-IP-CIDR,192.0.2.0/24))))'))
                    for top, source in cases:
                        for purpose in ('block', 'direct', 'proxy'):
                            for mode in ('add', 'strip', 'keep'):
                                with self.subTest(source=source, purpose=purpose, mode=mode):
                                    rules = self.parsed(source, purpose)
                                    outputs, diagnostics = render('fields', rules, purpose=purpose, no_resolve=mode)
                                    self.assertEqual(self.yaml_body(outputs), [])
                                    self.assertEqual(diagnostics['fin.yaml:' + top], 1)
                                    self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
            self.assertEqual(parse_whitelist(f"{kind},'foo,bar'"), [])
        rules = self.parsed('HOST-KEYWORD,"foo,bar",LIST')
        self.assertEqual(rules[0].domain_source, 'qx')
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), [])
        self.assertEqual(diagnostics['fin.yaml:DOMAIN-KEYWORD'], 1)
        for kind, value in (('DOMAIN-KEYWORD', '123,45'), ('DOMAIN-WILDCARD', '*123,45*')):
            rule = Rule(kind, value, domain_source='mihomo')
            outputs, diagnostics = render('fields', [rule], purpose='block', no_resolve='keep')
            self.assertEqual(self.yaml_body(outputs), [])
            self.assertEqual(diagnostics['fin.yaml:' + kind], 1)
            self.assertEqual(rule.value, value)

    def test_native_params_name_lists_and_transformed_commas_stay_supported(self):
        cases = [('payload:\n  - IN-NAME,foo,bar', 'IN-NAME,foo'),
                 ("UID,'1000,2000'", 'UID,1000/2000'),
                 ("AND,((DSCP,'0,1'),(NETWORK,tcp))", 'AND,((DSCP,0/1),(NETWORK,tcp))'),
                 ("PROCESS-NAME,'123,45'", r'PROCESS-NAME-REGEX,(?-i:\A\x{31}\x{32}\x{33}\x{2C}\x{34}\x{35}\z)')]
        for kind in ('IN-NAME', 'IN-USER', 'REMATCH-NAME'):
            cases.append((f"{kind},'foo / \tbar\u00a0'", kind + ',foo / \tbar\u00a0'))
            for value in ('foo bar', 'foo\tbar', "foo'bar", 'foo"bar', 'foo\\', 'foo\u2003bar'):
                cases.append(('payload:\n  - ' + json.dumps(kind + ',' + value), kind + ',' + value))
        for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX'):
            cases.append(('payload:\n  - ' + json.dumps(kind + ',^foo,bar$'), kind + ',^foo,bar$'))
        for source, expected in cases:
            with self.subTest(source=source):
                rules = self.parsed(source)
                outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
                self.assertEqual(self.yaml_body(outputs), [expected])
                self.assertNotIn('fin.yaml:' + rules[0].kind, diagnostics)
                self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy')[1], [])
        blocker = Rule('DOMAIN-KEYWORD', '123', domain_source='mihomo')
        white = Rule('DOMAIN-KEYWORD', '123,45', domain_source='mihomo')
        outputs, diagnostics = render('fields', [blocker, Rule(white.kind, white.value, allow=True,
                                      domain_source='mihomo')], whitelist=[white], purpose='block', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), ['DOMAIN-KEYWORD,123'])
        self.assertEqual(diagnostics['fin.yaml:DOMAIN-KEYWORD'], 1)
        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_generated_yaml_dependencies_and_frozen_comma_only_group(self):
        source = ("IN-NAME,'foo,bar'\nIN-USER,',foo'\nREMATCH-NAME,'foo,'\n"
                  "AND,((IN-NAME,'foo,bar'),(NETWORK,tcp))\nDOMAIN,keep.example.org\n")
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode, 'sources': sources,
                                'whitelist': []} for group, sources in
                               (('parent', ['input.list']), ('child', ['parent/fin.yaml']))]
                    (root / 'input.list').write_text(source, encoding='utf-8')
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('parent', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            old[path] = ('old ' + name).encode()
                            path.write_bytes(old[path])
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 12)
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    for group in ('parent', 'child'):
                        self.assertEqual(outputs[root / group / 'fin.yaml'],
                                         f'# {group} rules: 1\npayload:\n  - "DOMAIN,keep.example.org"\n')
                    self.assertIn('parent fin.yaml:IN-NAME: 1', logs.getvalue())
                    self.assertIn('parent fin.yaml:AND: 1', logs.getvalue())
                    publish(outputs, root=root)
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, self.fail)
                    self.assertEqual(disk[root / 'child' / 'fin.yaml'], outputs[root / 'child' / 'fin.yaml'])
                    (root / 'input.list').write_text("IN-NAME,'foo,bar'\n", encoding='utf-8')
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    saved = {path: path.read_bytes() for path in old}
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        self.assertEqual(generate(root, self.fail), {})
                    self.assertIn('no routable rules; frozen', logs.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in old}, saved)


class QxFieldTests(RoutingFieldTests):
    def field_source(self, kind, value):
        if kind == 'USER-AGENT':
            return kind + ',"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"\n'
        return 'payload:\n  - ' + json.dumps(kind + ',' + value) + '\n'

    def test_literal_leading_quote_is_target_local_unsupported(self):
        rules = self.parsed('payload:\n  - ' + json.dumps("DOMAIN-KEYWORD,'123"))
        outputs, diagnostics = render('fields', rules, purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
        self.assertEqual(diagnostics['fin-qx.txt:DOMAIN-KEYWORD'], 1)
        self.assertEqual(self.yaml_body(outputs), ["DOMAIN-KEYWORD,'123"])
        self.assertEqual(rules[0].value, "'123")

    def test_boundary_whitespace_is_target_local_unsupported(self):
        rules = self.parsed('payload:\n  - ' + json.dumps('DOMAIN-KEYWORD,\t123'))
        outputs, diagnostics = render('fields', rules, purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
        self.assertEqual(diagnostics['fin-qx.txt:DOMAIN-KEYWORD'], 1)
        self.assertEqual(self.yaml_body(outputs), ['DOMAIN-KEYWORD,\t123'])
        self.assertEqual(rules[0].value, '\t123')

    def test_user_agent_odd_trailing_backslash_is_unsupported(self):
        rules = self.parsed('USER-AGENT,"Client\\\\"')
        self.assertEqual(rules[0].value, 'Client\\')
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
        self.assertEqual(diagnostics['fin-qx.txt:USER-AGENT'], 1)
        self.assertEqual(outputs['fin.txt'], '# fields rules: 1\nUSER-AGENT,"Client\\\\"\n')

    def test_user_agent_whitespace_marker_is_unsupported(self):
        for marker in ('#', ';', '//'):
            with self.subTest(marker=marker):
                rules = self.parsed(f"USER-AGENT,'Client {marker}1'")
                outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
                self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
                self.assertEqual(diagnostics['fin-qx.txt:USER-AGENT'], 1)
                self.assertEqual(rules[0].value, 'Client ' + marker + '1')

    def test_quote_whitespace_and_user_agent_matrix_preserves_source(self):
        for kind in ('DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'USER-AGENT'):
            values = ["'123", '"123', "'123'", '"123"', '\t123', '123\t', ' 123',
                      '123 ', ' 123', '123 ', '123　']
            if kind == 'USER-AGENT':
                values += [' 123', '123 ', '123' + '\\' * 3, '123\t#4', '123 ;4', '123 //4']
            for value in values:
                rules = self.parsed(self.field_source(kind, value))
                self.assertEqual(rules[0].value, value)
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(kind=kind, value=value, purpose=purpose, mode=mode):
                            outputs, diagnostics = render('fields', rules, purpose=purpose, no_resolve=mode)
                            self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
                            self.assertEqual(diagnostics['fin-qx.txt:' + kind], 1)
                            self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
                            if kind != 'USER-AGENT':
                                self.assertEqual(self.yaml_body(outputs), [kind + ',' + value])
            for value in (' 123', '123 '):
                rule = Rule(kind, value, domain_source='mihomo' if kind != 'USER-AGENT' else 'surge')
                outputs, diagnostics = render('fields', [rule], purpose='block', no_resolve='keep')
                self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
                self.assertEqual(diagnostics['fin-qx.txt:' + kind], 1)

    def test_safe_internal_fields_keyword_markers_and_slashes_roundtrip(self):
        controls = {
            'DOMAIN-KEYWORD': ["12'3", '12"3', '12 3', r'12\3', '123\\', '123\\\\', '123\\\\\\',
                               '12 #3', '12 ;3', '12 //3'],
            'USER-AGENT': ["12'3", '12"3', '12 3', r'12\3', '123\\\\', '12#3', '12;3', '12//3'],
            'DOMAIN-WILDCARD': ['*.123.test', '123.*'],
        }
        for kind, values in controls.items():
            for value in values:
                with self.subTest(kind=kind, value=value):
                    rules = self.parsed(self.field_source(kind, value))
                    outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
                    qx_kind = {'DOMAIN-KEYWORD': 'HOST-KEYWORD', 'DOMAIN-WILDCARD': 'HOST-WILDCARD',
                               'USER-AGENT': 'USER-AGENT'}[kind]
                    self.assertEqual(outputs['fin-qx.txt'], f'# fields rules: 1\n{qx_kind},{value},LIST\n')
                    reparsed, warnings = parse(outputs['fin-qx.txt'], purpose='proxy')
                    self.assertEqual(warnings, [])
                    self.assertEqual([(rule.kind, rule.value) for rule in reparsed], [(kind, value)])
                    self.assertNotIn('fin-qx.txt:' + kind, diagnostics)
        for value, emitted in (("'123", False), ('123', True)):
            rule = Rule('DOMAIN-KEYWORD', value, ('force-cellular',), domain_source='qx')
            outputs, diagnostics = render('fields', [rule], purpose='proxy', no_resolve='keep')
            self.assertEqual(diagnostics.get('fin-qx.txt:DOMAIN-KEYWORD:interface-option', 0), int(emitted))
            self.assertEqual(diagnostics.get('fin-qx.txt:DOMAIN-KEYWORD', 0), int(not emitted))
        for operator, value in (('AND', "((DOMAIN-KEYWORD,'123'),(NETWORK,tcp))"),
                                ('OR', "((DOMAIN-KEYWORD,'123'),(NETWORK,tcp))"),
                                ('NOT', "((DOMAIN-KEYWORD,'123'))")):
            rules = self.parsed(operator + ',' + value)
            outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
            self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
            self.assertEqual(diagnostics['fin-qx.txt:' + operator], 1)
            self.assertNotIn('fin-qx.txt:DOMAIN-KEYWORD', diagnostics)
        self.assertEqual(parse_whitelist("USER-AGENT,'Client #1'"), [])

    def test_generated_and_disk_qx_sources_keep_only_safe_fields(self):
        for kind, values in (('DOMAIN-KEYWORD', ["'123", '"123"', '\t123']),
                             ('DOMAIN-WILDCARD', ["'123*", '"123*"', '\t123*']),
                             ('USER-AGENT', ["'Client", '\tClient', 'Client\\', 'Client #1', 'Client ;1', 'Client //1'])):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(kind=kind, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        if kind == 'USER-AGENT':
                            source = ''.join(self.field_source(kind, value) for value in values) + 'DOMAIN,keep.example.org\n'
                        else:
                            source = 'payload:\n' + ''.join('  - ' + json.dumps(kind + ',' + value) + '\n'
                                                           for value in values) + '  - DOMAIN,keep.example.org\n'
                        configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode, 'sources': sources,
                                    'whitelist': []} for group, sources in
                                   (('parent', ['input.list']), ('child', ['parent/fin-qx.txt']))]
                        (root / 'input.list').write_text(source, encoding='utf-8')
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for group in ('parent', 'child'):
                            (root / group).mkdir()
                            for name in FILES:
                                path = root / group / name
                                old[path] = ('old ' + name).encode()
                                path.write_bytes(old[path])
                        with contextlib.redirect_stderr(io.StringIO()) as logs:
                            outputs = generate(root, self.fail)
                        self.assertEqual(len(outputs), 12)
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        self.assertIn(f'parent fin-qx.txt:{kind}: {len(values)}', logs.getvalue())
                        self.assertNotIn(': line ', logs.getvalue())
                        for group in ('parent', 'child'):
                            self.assertEqual(outputs[root / group / 'fin-qx.txt'],
                                             f'# {group} rules: 1\nHOST,keep.example.org,LIST\n')
                        publish(outputs, root=root)
                        self.assertEqual((root / 'input.list').read_text(encoding='utf-8'), source)
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()):
                            disk = generate(root, self.fail)
                        for name in FILES:
                            if name != 'fin-adb.txt':
                                self.assertEqual(disk[root / 'child' / name], outputs[root / 'child' / name])

    def test_narrow_generated_qx_whitelist_never_becomes_bare_matcher(self):
        cases = [('DOMAIN-KEYWORD', value, 'HOST-KEYWORD,123x,LIST') for value in
                 ("'123'", '"123"', '\t123', '123 ')]
        cases += [('DOMAIN-WILDCARD', value, 'HOST,a123.test,LIST') for value in
                  ("'*123.test'", '"*123.test"', '\t*123.test', '*123.test ')]
        for kind, value, blocker in cases:
            white_text = self.field_source(kind, value)
            white = parse_whitelist(white_text)
            self.assertEqual([entry.value for entry in white], [value])
            rules = self.parsed(blocker)
            allowed = Rule(kind, value, allow=True, domain_source='mihomo')
            direct, diagnostics = render('fields', rules + [allowed], whitelist=white,
                                         purpose='block', no_resolve='keep')
            self.assertIn(blocker + '\n', direct['fin-qx.txt'])
            self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(kind=kind, value=value, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = white_text + '  - DOMAIN,white.neighbor.test\n'
                        (root / 'white.yaml').write_text(source, encoding='utf-8')
                        (root / 'input.list').write_text(blocker + '\nHOST,keep.example.org,LIST\n', encoding='utf-8')
                        configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['white.yaml'], 'whitelist': []},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.list'], 'whitelist': ['white/fin-qx.txt']}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as logs:
                            outputs = generate(root, self.fail)
                        self.assertEqual(len(outputs), 12)
                        self.assertIn(blocker + '\n', outputs[root / 'child' / 'fin-qx.txt'])
                        self.assertNotIn('whitelist-covered', logs.getvalue())
                        self.assertNotIn(': line ', logs.getvalue())
                        publish(outputs, root=root)
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()):
                            disk = generate(root, self.fail)
                        self.assertEqual(disk[root / 'child' / 'fin-qx.txt'], outputs[root / 'child' / 'fin-qx.txt'])
                        self.assertEqual((root / 'white.yaml').read_text(encoding='utf-8'), source)
