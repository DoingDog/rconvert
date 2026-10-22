import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


class TargetFieldTests(unittest.TestCase):
    def parsed(self, text, purpose='proxy'):
        rules, messages = parse(text, purpose=purpose)
        self.assertEqual(messages, [])
        return rules

    def yaml_body(self, outputs):
        return [json.loads(line[4:]) for line in outputs['fin.yaml'].split('\n')[2:-1]]


class OrdinaryTargetFieldsTests(TargetFieldTests):
    def test_native_keyword_markup_is_not_emitted_to_ordinary_readers(self):
        rules = self.parsed('payload:\n  - DOMAIN-KEYWORD,<tag>')
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
        self.assertEqual(diagnostics['fin-qx.txt:DOMAIN-KEYWORD'], 1)
        self.assertEqual(self.yaml_body(outputs), ['DOMAIN-KEYWORD,<tag>'])

    def test_native_user_agent_angle_literal_is_not_emitted_to_ordinary_readers(self):
        rules = self.parsed('payload:\n  - USER-AGENT,<123>')
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# fields rules: 0\n')
        self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
        self.assertEqual(diagnostics['fin.txt:USER-AGENT'], 1)
        self.assertEqual(diagnostics['fin-qx.txt:USER-AGENT'], 1)

    def test_native_wildcard_numeric_angle_literal_is_not_ordinary_domain(self):
        rules = self.parsed('payload:\n  - DOMAIN-WILDCARD,*<123>*')
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt'):
            self.assertEqual(outputs[name], '# fields rules: 0\n')
            self.assertEqual(diagnostics[name + ':DOMAIN-WILDCARD'], 1)
        self.assertEqual(self.yaml_body(outputs), ['DOMAIN-WILDCARD,*<123>*'])

    def test_markup_process_and_literal_controls_matrix(self):
        cases = [('DOMAIN-KEYWORD', '<tag>'), ('DOMAIN-KEYWORD', '<!--123-->'),
                 ('DOMAIN-WILDCARD', '*<123>*'), ('DOMAIN-WILDCARD', '*<tag>*'),
                 ('USER-AGENT', '<123>'), ('DEVICE-NAME', '<123>'),
                 ('PROCESS-NAME', '<123>'), ('PROCESS-NAME-WILDCARD', '<123>'),
                 ('PROCESS-PATH', '/123/<123>'), ('PROCESS-PATH-WILDCARD', '/123/<123>')]
        for kind, value in cases:
            leaf = kind + ',' + value
            expressions = [leaf, f'AND,(({leaf}),(DOMAIN-KEYWORD,123))',
                           f'OR,(({leaf}),(DOMAIN-KEYWORD,123))', f'NOT,(({leaf}))',
                           f'NOT,((AND,(({leaf}),(DOMAIN-KEYWORD,123))))']
            for expression in expressions:
                rules = self.parsed('payload:\n  - ' + json.dumps(expression))
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(expression=expression, purpose=purpose, mode=mode):
                            outputs, diagnostics = render('fields', rules, purpose=purpose, no_resolve=mode)
                            for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
                                self.assertEqual(outputs[name], '# fields rules: 0\n')
                                self.assertEqual(diagnostics[name + ':' + rules[0].kind], 1)
                            if kind not in ('USER-AGENT', 'DEVICE-NAME'):
                                self.assertEqual(self.yaml_body(outputs), [expression])
                            self.assertEqual(rules[0].value, expression.partition(',')[2])
        for kind in ('USER-AGENT', 'DEVICE-NAME'):
            expression = f'AND,(({kind},<tag>),(DOMAIN-KEYWORD,123))'
            outputs, diagnostics = render('fields', self.parsed('payload:\n  - ' + json.dumps(expression)),
                                          purpose='proxy', no_resolve='keep')
            self.assertEqual(outputs['fin.txt'], '# fields rules: 0\n')
            self.assertEqual(diagnostics['fin.txt:AND'], 1)
        for source in ('DOMAIN-KEYWORD,<123>', 'HOST-KEYWORD,<123>,LIST', 'payload:\n  - DOMAIN-KEYWORD,<123>'):
            outputs, _ = render('fields', self.parsed(source), purpose='proxy', no_resolve='keep')
            self.assertEqual(outputs['fin.txt'], '# fields rules: 1\nDOMAIN-KEYWORD,<123>\n')
            self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 1\nHOST-KEYWORD,<123>,LIST\n')
            for name in ('fin.txt', 'fin-qx.txt', 'fin.yaml'):
                self.assertEqual(self.parsed(outputs[name])[0].value, '<123>')
        for source in ('DOMAIN-KEYWORD,<tag>', 'USER-AGENT,<123>', 'DEVICE-NAME,<123>',
                       'payload:\n  - USER-AGENT,<tag>', 'payload:\n  - DEVICE-NAME,<tag>'):
            rules, messages = parse(source, purpose='proxy')
            self.assertEqual(rules, [])
            self.assertTrue(messages)
        outputs, _ = render('fields', self.parsed('URL-REGEX,<tag>'), purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# fields rules: 1\nURL-REGEX,<tag>\n')
        self.assertEqual(self.parsed(outputs['fin.txt'])[0].value, '<tag>')
        white = Rule('DOMAIN-KEYWORD', '<!--123-->', domain_source='mihomo')
        blocker = Rule('DOMAIN-KEYWORD', '9<!--123-->8', domain_source='mihomo')
        outputs, diagnostics = render('fields', [blocker, replace(white, allow=True)], whitelist=[white],
                                      purpose='block', no_resolve='keep')
        self.assertNotIn('fin.txt:DOMAIN-KEYWORD:whitelist-covered', diagnostics)
        self.assertNotIn('fin-qx.txt:DOMAIN-KEYWORD:whitelist-covered', diagnostics)

    def test_actual_generated_ordinary_sources_and_whitelists_remain_readable(self):
        source = ('payload:\n  - DOMAIN-KEYWORD,<tag>\n  - DOMAIN-KEYWORD,<!--123-->\n'
                  '  - DOMAIN-WILDCARD,*<123>*\n  - USER-AGENT,<123>\n  - DEVICE-NAME,<123>\n'
                  '  - PROCESS-NAME,<123>\n  - PROCESS-PATH,/123/<123>\n'
                  '  - AND,((PROCESS-NAME,<123>),(DOMAIN-KEYWORD,123))\n'
                  'DOMAIN,white.neighbor.test\n')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'input.yaml').write_text(source, encoding='utf-8')
                    (root / 'block.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
                    configs = [dict(name='parent', purpose=purpose, no_resolve=mode, sources=['input.yaml'], whitelist=[])]
                    for suffix, filename in (('surge', 'fin.txt'), ('qx', 'fin-qx.txt')):
                        configs += [dict(name='source-' + suffix, purpose=purpose, no_resolve=mode,
                                         sources=['parent/' + filename], whitelist=[]),
                                    dict(name='white-' + suffix, purpose=purpose, no_resolve=mode,
                                         sources=['block.list'], whitelist=['parent/' + filename])]
                    config = root / 'rulesets.json'
                    config.write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for item in configs:
                        (root / item['name']).mkdir()
                        for name in FILES:
                            path = root / item['name'] / name
                            old[path] = b'old product\r\n'
                            path.write_bytes(old[path])
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 30)
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    for name, expected in (('fin.txt', 'DOMAIN,white.neighbor.test'),
                                           ('fin-qx.txt', 'HOST,white.neighbor.test,LIST')):
                        self.assertEqual(outputs[root / 'parent' / name], '# parent rules: 1\n' + expected + '\n')
                    self.assertNotIn(': line ', logs.getvalue())
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, self.fail)
                    for item in configs[1:]:
                        for name in ('fin.txt', 'fin-qx.txt', 'fin.yaml'):
                            path = root / item['name'] / name
                            self.assertEqual(disk[path], outputs[path])
                    self.assertEqual((root / 'input.yaml').read_text(encoding='utf-8'), source)


class MihomoDomainSpaceTests(TargetFieldTests):
    def test_qx_literal_space_keyword_is_mihomo_unsupported(self):
        rules = self.parsed("HOST-KEYWORD,' 123 ',LIST")
        self.assertEqual(rules[0].value, ' 123 ')
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), [])
        self.assertEqual(diagnostics['fin.yaml:DOMAIN-KEYWORD'], 1)
        self.assertEqual(rules[0].value, ' 123 ')

    def test_raw_domain_spaces_scalar_and_logical_are_target_local(self):
        for kind, base in (('DOMAIN', '123.test'), ('DOMAIN-SUFFIX', '123.test'),
                           ('DOMAIN-KEYWORD', '123'), ('DOMAIN-WILDCARD', '*123*')):
            for value in (' ' + base, base + ' ', ' ' + base + ' '):
                for source in ('mihomo', 'qx'):
                    rules = [Rule(kind, value, domain_source=source)]
                    leaf = kind + ',"' + value + '"'
                    rules += [Rule(operator, expression, domain_source=source) for operator, expression in
                              (('AND', f'(({leaf}),(NETWORK,tcp))'), ('OR', f'(({leaf}),(NETWORK,udp))'),
                               ('NOT', f'(({leaf}))'), ('NOT', f'((AND,(({leaf}),(NOT,(({leaf}))))))'))]
                    for rule in rules:
                        for purpose in ('block', 'direct', 'proxy'):
                            for mode in ('add', 'strip', 'keep'):
                                with self.subTest(kind=kind, value=value, source=source, top=rule.kind,
                                                  purpose=purpose, mode=mode):
                                    outputs, diagnostics = render('fields', [rule], purpose=purpose, no_resolve=mode)
                                    self.assertEqual(self.yaml_body(outputs), [])
                                    self.assertEqual(diagnostics['fin.yaml:' + rule.kind], 1)
        for value in ('1 23', '\t123', '123\t', '\xa0123', '123 '):
            rule = Rule('DOMAIN-KEYWORD', value, domain_source='qx')
            outputs, diagnostics = render('fields', [rule], purpose='proxy', no_resolve='keep')
            self.assertEqual(self.yaml_body(outputs), ['DOMAIN-KEYWORD,' + value])
            self.assertNotIn('fin.yaml:DOMAIN-KEYWORD', diagnostics)
            self.assertEqual(self.parsed(outputs['fin.yaml'])[0].value, value)
        for source, expected in (("DOMAIN-KEYWORD,' 123 '", r'DOMAIN-REGEX,\ 123\ (?:)'),
                                 ("AND,((DOMAIN-KEYWORD,' 123 '),(NETWORK,tcp))", r'AND,((DOMAIN-REGEX,\ 123\ (?:)),(NETWORK,tcp))')):
            outputs, _ = render('fields', self.parsed(source), purpose='proxy', no_resolve='keep')
            self.assertEqual(self.yaml_body(outputs), [expected])
        native = self.parsed('payload:\n  - "DOMAIN-KEYWORD, 123 "')
        self.assertEqual(native[0].value, '123')

    def test_generated_mihomo_white_does_not_trim_keyword(self):
        for value in (' 123', '123 ', ' 123 '):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(value=value, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = f"HOST-KEYWORD,'{value}',LIST\nHOST,white.neighbor.test,LIST\n"
                        (root / 'white.list').write_text(source, encoding='utf-8')
                        (root / 'input.yaml').write_text('payload:\n  - DOMAIN-KEYWORD,123x\n  - DOMAIN,keep.example.org\n', encoding='utf-8')
                        configs = [dict(name='parent', purpose=purpose, no_resolve=mode, sources=['white.list'], whitelist=[]),
                                   dict(name='child', purpose=purpose, no_resolve=mode, sources=['input.yaml'], whitelist=['parent/fin.yaml']),
                                   dict(name='direct', purpose=purpose, no_resolve=mode, sources=['input.yaml'], whitelist=['white.list']),
                                   dict(name='source', purpose=purpose, no_resolve=mode, sources=['parent/fin.yaml'], whitelist=[])]
                        config = root / 'rulesets.json'
                        config.write_text(json.dumps(configs), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as logs:
                            outputs = generate(root, self.fail)
                        self.assertEqual(len(outputs), 24)
                        self.assertEqual(outputs[root / 'parent' / 'fin.yaml'],
                                         '# parent rules: 1\npayload:\n  - "DOMAIN,white.neighbor.test"\n')
                        for group in ('child', 'direct'):
                            self.assertIn('"DOMAIN-KEYWORD,123x"', outputs[root / group / 'fin.yaml'])
                        self.assertNotIn(': line ', logs.getvalue())
                        self.assertNotIn('whitelist-covered', logs.getvalue())
                        publish(outputs, root=root)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in outputs.items()})
                        config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()):
                            disk = generate(root, self.fail)
                        for group in ('child', 'direct', 'source'):
                            self.assertEqual(disk[root / group / 'fin.yaml'], outputs[root / group / 'fin.yaml'])
                        self.assertEqual((root / 'white.list').read_text(encoding='utf-8'), source)
        blocker = Rule('DOMAIN-KEYWORD', '123x', domain_source='mihomo')
        for source in ('mihomo', 'qx'):
            white = Rule('DOMAIN-KEYWORD', ' 123 ', domain_source=source)
            outputs, diagnostics = render('fields', [blocker, replace(white, allow=True)], whitelist=[white],
                                          purpose='block', no_resolve='keep')
            self.assertEqual(self.yaml_body(outputs), ['DOMAIN-KEYWORD,123x'])
            self.assertNotIn('fin.yaml:DOMAIN-KEYWORD:whitelist-covered', diagnostics)


class GoNameFieldsTests(TargetFieldTests):
    def test_ordinary_logical_preserves_go_nonempty_control_name(self):
        rules = self.parsed("AND,((IN-NAME,'\x1c'),(NETWORK,tcp))")
        outputs, diagnostics = render('fields', rules, purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), ['AND,((IN-NAME,\x1c),(NETWORK,tcp))'])
        self.assertNotIn('fin.yaml:AND', diagnostics)
        self.assertIn('\\u001c', outputs['fin.yaml'])
        self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy')[1], [])

    def test_name_lists_scalar_logical_and_native_unicode_matrix(self):
        for kind in ('IN-NAME', 'IN-USER', 'REMATCH-NAME'):
            for char in ('\x1c', '\x1d', '\x1e', '\x1f'):
                for value in (char, '\t' + char + '\xa0', char + '/ \t' + char + ' '):
                    leaf = kind + ',"' + value + '"'
                    expressions = [leaf, f'AND,(({leaf}),(NETWORK,tcp))',
                                   f'OR,(({leaf}),(NETWORK,udp))', f'NOT,(({leaf}))',
                                   f'NOT,((AND,(({leaf}),(OR,(({leaf}),(NETWORK,tcp))))))']
                    for expression in expressions:
                        native = expression.replace('"' + value + '"', value)
                        for source in (expression, 'payload:\n  - ' + json.dumps(native)):
                            rules = self.parsed(source)
                            for purpose in ('block', 'proxy', 'direct'):
                                for mode in ('add', 'strip', 'keep'):
                                    with self.subTest(kind=kind, char=repr(char), source=source,
                                                      purpose=purpose, mode=mode):
                                        outputs, diagnostics = render('fields', rules, purpose=purpose, no_resolve=mode)
                                        self.assertEqual(self.yaml_body(outputs), [native])
                                        self.assertNotIn('fin.yaml:' + rules[0].kind, diagnostics)
                                        again = self.parsed(outputs['fin.yaml'], purpose)
                                        repeated, _ = render('fields', again, purpose=purpose, no_resolve=mode)
                                        self.assertEqual(repeated['fin.yaml'], outputs['fin.yaml'])
                                        self.assertEqual(outputs['fin.txt'], '# fields rules: 0\n')
                                        self.assertEqual(outputs['fin-qx.txt'], '# fields rules: 0\n')
        for kind in ('IN-NAME', 'IN-USER', 'REMATCH-NAME'):
            for value in (' ', '\t\xa0 ', 'ok/', '/ok', 'ok/\t\xa0'):
                for source in (f'{kind},"{value}"', 'payload:\n  - ' + json.dumps(kind + ',' + value)):
                    rules, messages = parse(source, purpose='proxy')
                    self.assertEqual(rules, [])
                    self.assertTrue(messages)
        controls = self.parsed("AND,((IN-NAME,'foo / bar'),(UID,'1000,2000'),(DSCP,'0,1'),(NETWORK,tcp))")
        outputs, _ = render('fields', controls, purpose='proxy', no_resolve='keep')
        self.assertEqual(self.yaml_body(outputs), ['AND,((IN-NAME,foo / bar),(UID,1000/2000),(DSCP,0/1),(NETWORK,tcp))'])

    def test_name_generation_publish_disk_and_empty_dependencies(self):
        source = ('IN-NAME,"\x1c"\nAND,((IN-USER,"\x1d"),(NETWORK,tcp))\n'
                  'NOT,((REMATCH-NAME,"\x1e/\x1f"))\n')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    original = source.encode('utf-8')
                    (root / 'input.list').write_bytes(original)
                    (root / 'healthy.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
                    configs = [dict(name='parent', purpose=purpose, no_resolve=mode, sources=['input.list'], whitelist=[]),
                               dict(name='child', purpose=purpose, no_resolve=mode, sources=['parent/fin.yaml'], whitelist=[]),
                               dict(name='empty', purpose=purpose, no_resolve=mode, sources=['parent/fin.txt'], whitelist=[]),
                               dict(name='white', purpose=purpose, no_resolve=mode, sources=['healthy.list'], whitelist=['parent/fin.txt'])]
                    config = root / 'rulesets.json'
                    config.write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 24)
                    expected = ['AND,((IN-USER,\x1d),(NETWORK,tcp))', 'IN-NAME,\x1c', 'NOT,((REMATCH-NAME,\x1e/\x1f))']
                    for group in ('parent', 'child'):
                        texts = {name: outputs[root / group / name] for name in FILES}
                        self.assertEqual(self.yaml_body(texts), expected)
                    self.assertEqual(outputs[root / 'empty' / 'fin.yaml'], '# empty rules: 0\npayload:\n')
                    self.assertIn('DOMAIN,keep.example.org', outputs[root / 'white' / 'fin.txt'])
                    self.assertNotIn(': line ', logs.getvalue())
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    self.assertEqual((root / 'input.list').read_bytes(), original)
                    config.write_text(json.dumps(configs[1:2]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, self.fail)
                    self.assertEqual(disk[root / 'child' / 'fin.yaml'], outputs[root / 'child' / 'fin.yaml'])
                    for dependency in ('parent/fin.txt',):
                        for white in (False, True):
                            item = dict(name='invalid', purpose=purpose, no_resolve=mode,
                                        sources=['healthy.list'] if white else [dependency],
                                        whitelist=[dependency] if white else [])
                            config.write_text(json.dumps([item]), encoding='utf-8')
                            with self.assertRaises(ValueError), contextlib.redirect_stderr(io.StringIO()):
                                generate(root, self.fail)
                    configs[-1]['whitelist'] = ['parent/fin.yaml']
                    config.write_text(json.dumps([configs[0], configs[-1]]), encoding='utf-8')
                    saved = {path: path.read_bytes() for path in outputs}
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist.*unsupported rule'), contextlib.redirect_stderr(io.StringIO()):
                        generate(root, self.fail)
                    self.assertEqual({path: path.read_bytes() for path in saved}, saved)
