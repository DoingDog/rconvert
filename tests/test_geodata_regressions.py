import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


class GeositeRegressionTests(unittest.TestCase):
    def test_repeated_attributes_preserve_the_original_matcher(self):
        rules, messages = parse('GEOSITE,google@cn@cn', purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(rules, [Rule('GEOSITE', 'google@cn@cn')])
        outputs, diagnostics = render('geo', normalize(iter(rules)), purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# geo rules: 1\npayload:\n  - "GEOSITE,google@cn@cn"\n')
        self.assertEqual(outputs['fin.txt'], '# geo rules: 0\n')
        self.assertEqual(diagnostics['fin.txt:GEOSITE'], 1)

    def test_all_attribute_segments_and_list_name_trim_keep_literal_payloads(self):
        values = ['google@', 'google@@cn', 'google@cn@@', 'google@!cn',
                  'google@ CN @\tcn\xa0@', 'google@键!?/=:功', 'geolocation-!cn@cn',
                  '!google@cn@cn', '!!google@cn', '\t!@cn', '\xa0!@cn',
                  '\tgoogle\xa0@cn', ' !google@cn ', ' !\tgoogle\xa0@cn ']
        for value in values:
            for native in (False, True):
                source = ('payload:\n  - ' + json.dumps('GEOSITE,' + value) if native
                          else 'GEOSITE,"' + value + '"')
                with self.subTest(value=value, native=native):
                    parsed, messages = parse(source, purpose='proxy')
                    self.assertEqual(messages, [])
                    expected = value.strip(' ') if native else value
                    self.assertEqual(parsed, [Rule('GEOSITE', expected)])
                    outputs, diagnostics = render('geo', parsed, purpose='proxy', no_resolve='keep')
                    self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), 'GEOSITE,' + expected)
                    self.assertEqual(outputs['fin.txt'], '# geo rules: 0\n')
                    self.assertEqual(outputs['fin-qx.txt'], '# geo rules: 0\n')
                    self.assertEqual(outputs['fin-surge.txt'], '# geo rules: 0\n')
                    self.assertEqual(outputs['fin-surge-ds.txt'], '# geo rules: 0\n')
                    self.assertEqual(diagnostics['fin-adb.txt:GEOSITE'], 1)
                    self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy')[1], [])
                    self.assertEqual(parse_whitelist(source), [])

    def test_empty_effective_list_names_warn_and_preserve_neighbor_line_numbers(self):
        for value in ('!', '!@cn', '@cn', ' ', ' \t\xa0@cn', ' ! ', ' !@cn ',
                      '!\t@cn', '!\xa0@cn', 'google.cn@cn', 'google+@cn', '\x1c@cn'):
            for native in (False, True):
                source = ('payload:\n  - ' + json.dumps('GEOSITE,' + value) if native
                          else 'GEOSITE,"' + value + '"') + '\nDOMAIN,keep.example.org\n'
                with self.subTest(value=value, native=native):
                    parsed, messages = parse(source, purpose='proxy')
                    self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.org')])
                    self.assertEqual(len(messages), 1)
                    self.assertTrue(messages[0].startswith(f'line {2 if native else 1}: invalid GEOSITE '))

    def test_attributes_in_complete_logical_expressions_use_the_same_validation(self):
        expressions = ['AND,((GEOSITE,google@cn@cn),(NETWORK,tcp))',
                       'OR,((GEOSITE,google@@cn),(NETWORK,udp))',
                       'NOT,((GEOSITE,!google@cn@@))',
                       'NOT,((OR,((GEOSITE,google@!cn),(GEOSITE,geolocation-!cn@))))']
        deep = '(GEOSITE,google@cn@cn)'
        for _ in range(128):
            deep = '(NOT,(' + deep + '))'
        expressions.append(deep[1:-1])
        for expression in expressions:
            for native in (False, True):
                source = 'rules:\n  - ' + json.dumps(expression) if native else expression
                with self.subTest(expression=expression, native=native):
                    parsed, messages = parse(source, purpose='proxy')
                    self.assertEqual(messages, [])
                    self.assertEqual(parsed[0].value, expression.partition(',')[2])
                    outputs, diagnostics = render('geo', parsed, purpose='proxy', no_resolve='add')
                    self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), expression)
                    self.assertEqual(outputs['fin.txt'], '# geo rules: 0\n')
                    self.assertEqual(diagnostics['fin.txt:' + parsed[0].kind], 1)
                    self.assertNotIn('fin.yaml:' + parsed[0].kind, diagnostics)
        for expression in ('AND,((GEOSITE,!@cn),(NETWORK,tcp))', 'NOT,((GEOSITE,!))'):
            self.assertEqual(parse(expression, purpose='proxy')[0], [])

    def test_native_scalar_styles_and_generic_field_boundaries_are_unchanged(self):
        for header in ('payload', 'rules'):
            for scalar in ('GEOSITE,google@cn@@', "'GEOSITE,google@cn@@'", '"GEOSITE,google@cn@@"'):
                self.assertEqual(parse(header + ':\n  - ' + scalar, purpose='proxy'),
                                 ([Rule('GEOSITE', 'google@cn@@')], []))
        for source in ('GEOSITE,google@cn,extra,other', 'GEOSITE,google@<html>',
                       'payload:\n  - "GEOSITE,google@cn', 'GEOSITE,google@cn '):
            parsed, messages = parse(source, purpose='proxy')
            self.assertEqual(parsed, [])
            self.assertTrue(messages)

    def test_real_yaml_source_dependencies_preserve_attributes_and_old_products(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = b'\xef\xbb\xbfGEOSITE,google@cn@cn\r\n'
                    (root / 'input.list').write_bytes(source)
                    (root / 'static').mkdir()
                    marker = root / 'static' / 'untouched'
                    marker.write_bytes(b'static\x00')
                    configs = [dict(name=name, purpose=purpose, no_resolve=mode, sources=sources, whitelist=[])
                               for name, sources in (('parent', ['input.list']), ('child', ['parent/fin.yaml']))]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('parent', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            old[path] = b'old product\n'
                            path.write_bytes(old[path])
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 12)
                    self.assertNotIn('frozen', logs.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    for group in ('parent', 'child'):
                        self.assertEqual(outputs[root / group / 'fin.yaml'],
                                         f'# {group} rules: 1\npayload:\n  - "GEOSITE,google@cn@cn"\n')
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, self.fail)
                    for name in FILES:
                        if name != 'fin-adb.txt':
                            self.assertEqual(disk[root / 'child' / name], outputs[root / 'child' / name])
                    self.assertEqual((root / 'input.list').read_bytes(), source)
                    self.assertEqual(marker.read_bytes(), b'static\x00')
