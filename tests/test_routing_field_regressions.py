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
