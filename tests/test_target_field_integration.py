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
