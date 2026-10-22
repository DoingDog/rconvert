import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests.test_formats import DNS_BYTE_TOKEN


DNS_12345 = r'/(?s-i:\A' + DNS_BYTE_TOKEN + r'*123\.45' + DNS_BYTE_TOKEN + r'*\z)/'


class KeywordProjectionTests(unittest.TestCase):
    def test_native_root_dot_keyword_does_not_remove_supported_projection(self):
        parsed, warnings = parse('payload:\n  - DOMAIN-KEYWORD,123.\n  - DOMAIN-KEYWORD,123.45\n',
                                 purpose='block')
        self.assertEqual(warnings, [])
        outputs, diagnostics = render('keyword', normalize(parsed), purpose='block', no_resolve='keep')
        for name in ('fin.txt', 'fin-surge.txt'):
            self.assertEqual(outputs[name], '# keyword rules: 1\nDOMAIN-KEYWORD,123.45\n')
        self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [DNS_12345])
        self.assertEqual(outputs['fin.yaml'], '# keyword rules: 2\npayload:\n'
                         '  - "DOMAIN-KEYWORD,123."\n  - "DOMAIN-KEYWORD,123.45"\n')
        self.assertEqual(outputs['fin-qx.txt'], '# keyword rules: 2\n'
                         'HOST-KEYWORD,123.,LIST\nHOST-KEYWORD,123.45,LIST\n')
        self.assertEqual(outputs['fin-surge-ds.txt'], '# keyword rules: 0\n')
        self.assertEqual(diagnostics, {'fin.txt:DOMAIN-KEYWORD': 1, 'fin-surge.txt:DOMAIN-KEYWORD': 1,
                                      'fin-adb.txt:DOMAIN-KEYWORD': 1, 'fin-surge-ds.txt:DOMAIN-KEYWORD': 2})

    def test_substring_positions_yaml_scalars_and_modes_keep_supported_long_keyword(self):
        cases = (('.', '123.45', r'123\.45'), ('23.', '123.45', r'123\.45'),
                 ('123.', '00123.45', r'00123\.45'), ('45.', '123.45.67', r'123\.45\.67'),
                 ('12.34.', '0012.34.56', r'0012\.34\.56'))
        for short, long, dns_literal in cases:
            for header in ('payload', 'rules'):
                for quote in ('', "'", '"'):
                    source = header + ':\n' + ''.join('  - ' + quote + 'DOMAIN-KEYWORD,' + value + quote + '\n'
                                                       for value in (short, long))
                    for purpose in ('block', 'direct', 'proxy'):
                        parsed, warnings = parse(source, purpose=purpose)
                        self.assertEqual(warnings, [])
                        self.assertEqual([rule.domain_source for rule in parsed], ['mihomo', 'mihomo'])
                        for mode in ('add', 'strip', 'keep'):
                            for order in (parsed, parsed[::-1], parsed + parsed[::-1]):
                                with self.subTest(short=short, long=long, header=header, quote=quote,
                                                  purpose=purpose, mode=mode, order=order):
                                    normalized = normalize(iter(order))
                                    self.assertEqual(set(normalized), set(parsed))
                                    outputs, diagnostics = render('keyword', normalized, purpose=purpose, no_resolve=mode)
                                    for name in ('fin.txt', 'fin-surge.txt'):
                                        self.assertEqual(outputs[name], '# keyword rules: 1\nDOMAIN-KEYWORD,' + long + '\n')
                                    dns = [r'/(?s-i:\A' + DNS_BYTE_TOKEN + '*' + dns_literal + DNS_BYTE_TOKEN + r'*\z)/']
                                    self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], dns if purpose == 'block' else
                                                     ['! No AdBlock rules for non-advertising group.'])
                                    self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_safe_and_ordinary_keyword_containment_still_reduces(self):
        for source in ('surge', 'qx', 'mihomo'):
            cases = [(('123', '123.', '123.45'), '123')]
            if source == 'mihomo':
                cases.append((('123.', '123.45.'), '123.'))
            else:
                cases.append((('123.', '123.45'), '123.'))
            for values, expected in cases:
                rules = [Rule('DOMAIN-KEYWORD', value, domain_source=source) for value in values]
                for order in (rules, rules[::-1], rules + rules):
                    with self.subTest(source=source, values=values, order=order):
                        self.assertEqual(normalize(iter(order)), [Rule('DOMAIN-KEYWORD', expected, domain_source=source)])
        for text in ('DOMAIN-KEYWORD,123.\nDOMAIN-KEYWORD,123.45',
                     'HOST-KEYWORD,123.,LIST\nHOST-KEYWORD,123.45,LIST'):
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual(warnings, [])
            outputs, _ = render('ordinary', normalize(parsed), purpose='block', no_resolve='keep')
            self.assertEqual(outputs['fin.txt'], '# ordinary rules: 1\nDOMAIN-KEYWORD,123.\n')
            self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [r'/^.*123\..*$/'])

    def test_containment_keeps_each_rule_identity_group_separate(self):
        short = Rule('DOMAIN-KEYWORD', '123', domain_source='mihomo')
        long = Rule('DOMAIN-KEYWORD', '123.45', domain_source='mihomo')
        for attribute in ({'allow': True}, {'options': ('special',)}, {'literal_process': True},
                          {'native_fields': True}, {'domain_source': 'surge'}, {'domain_source': 'qx'}):
            changed = replace(long, **attribute)
            for order in ([short, changed], [changed, short, changed]):
                with self.subTest(attribute=attribute, order=order):
                    self.assertEqual(set(normalize(iter(order))), {short, changed})
        for attribute in ({'allow': True}, {'options': ('special',)}, {'literal_process': True}, {'native_fields': True}):
            pair = [replace(short, **attribute), replace(long, **attribute)]
            self.assertEqual(normalize(iter(pair)), [pair[0]])

    def test_public_native_allow_keeps_dns_exception_before_blocker(self):
        parsed, warnings = parse('payload:\n  - DOMAIN-KEYWORD,123.\n  - DOMAIN-KEYWORD,123.45\n', purpose='block')
        self.assertEqual(warnings, [])
        rules = [replace(rule, allow=True) for rule in parsed] + [Rule('DOMAIN-KEYWORD', '45')]
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for order in (rules, rules[::-1]):
                    with self.subTest(purpose=purpose, mode=mode, order=order):
                        outputs, diagnostics = render('allow', normalize(iter(order)), purpose=purpose, no_resolve=mode)
                        self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:],
                                         ['@@' + DNS_12345, r'/^.*45.*$/'] if purpose == 'block' else
                                         ['! No AdBlock rules for non-advertising group.'])
                        self.assertEqual(outputs['fin.txt'], '# allow rules: 1\nDOMAIN-KEYWORD,45\n')
                        if purpose == 'block':
                            self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-KEYWORD'], 1)
                        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_literal_characters_in_long_keyword_keep_existing_target_encoding(self):
        for value in ("123.'45", '123."45', r'123.\45', '123. 45', '123.\t45', '123. 45', '123. 45'):
            source = 'payload:\n  - DOMAIN-KEYWORD,123.\n  - ' + json.dumps('DOMAIN-KEYWORD,' + value) + '\n'
            with self.subTest(value=value):
                parsed, warnings = parse(source, purpose='block')
                self.assertEqual(warnings, [])
                outputs, _ = render('literal', normalize(parsed), purpose='block', no_resolve='keep')
                for name in ('fin.txt', 'fin-surge.txt'):
                    self.assertEqual(outputs[name], '# literal rules: 1\nDOMAIN-KEYWORD,' + value + '\n')
                supported, _ = render('literal', [Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')],
                                      purpose='block', no_resolve='keep')
                self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], supported['fin-adb.txt'].splitlines()[7:])
                self.assertTrue(outputs['fin-adb.txt'].splitlines()[7:])
                self.assertEqual(parse(outputs['fin.yaml'], purpose='block'), (parsed, []))

    def test_native_comma_and_decoded_controls_keep_existing_safety_guards(self):
        parsed, warnings = parse('payload:\n  - "DOMAIN-KEYWORD,123.,45"\n', purpose='block')
        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-KEYWORD', '123.', domain_source='mihomo')], []))
        for char in ('\x00', '\n', '\x7f', '\x85', ' '):
            value = '123.' + char + '45'
            source = 'payload:\n  - ' + json.dumps('DOMAIN-KEYWORD,' + value) + '\n'
            with self.subTest(char=repr(char)):
                parsed, warnings = parse(source, purpose='block')
                self.assertEqual(warnings, [])
                self.assertEqual(parsed[0].value, value)
                outputs, diagnostics = render('control', normalize(parsed), purpose='block', no_resolve='keep')
                self.assertEqual(outputs['fin.txt'], '# control rules: 0\n')
                self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(diagnostics['fin.txt:DOMAIN-KEYWORD'], 1)
                self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-KEYWORD'], 1)
                self.assertEqual(parse(outputs['fin.yaml'], purpose='block'), (parsed, []))

    def test_keyword_containment_does_not_change_neighbors_or_logical_leaves(self):
        matchers = ['DOMAIN,123.45.example.org', 'DOMAIN-SUFFIX,123.45.other.org',
                    'DOMAIN-WILDCARD,*123.45*', r'DOMAIN-REGEX,^123\.45$',
                    'IP-CIDR,192.0.2.0/24', 'PROCESS-NAME,123.45',
                    'AND,((DOMAIN-KEYWORD,123.),(DOMAIN-KEYWORD,123.45))',
                    'OR,((DOMAIN-KEYWORD,123.45),(DOMAIN-KEYWORD,123.))',
                    'NOT,((DOMAIN-KEYWORD,123.))',
                    'AND,((NOT,((DOMAIN-KEYWORD,123.))),(OR,((DOMAIN-KEYWORD,123.45),(NETWORK,tcp))))']
        source = 'payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)
        parsed, warnings = parse(source, purpose='block')
        self.assertEqual(warnings, [])
        normalized = normalize(iter(parsed[::-1] + parsed))
        self.assertEqual(set(normalized), set(parsed))
        outputs, diagnostics = render('neighbors', normalized, purpose='block', no_resolve='keep')
        before, before_diagnostics = render('neighbors', parsed, purpose='block', no_resolve='keep')
        for name in FILES:
            self.assertEqual(outputs[name].splitlines()[7:] if name == 'fin-adb.txt' else outputs[name],
                             before[name].splitlines()[7:] if name == 'fin-adb.txt' else before[name])
        self.assertEqual(diagnostics, before_diagnostics)
        for matcher in matchers[6:]:
            self.assertIn('  - ' + json.dumps(matcher) + '\n', outputs['fin.yaml'])
        for operator, count in (('AND', 2), ('OR', 1), ('NOT', 1)):
            self.assertEqual(diagnostics['fin.txt:' + operator], count)
            self.assertNotIn('fin.yaml:' + operator, diagnostics)


class KeywordGenerationTests(unittest.TestCase):
    def assert_product_counts(self, outputs, root, group, purpose):
        from tests.test_functional_audit_projection import SurgeRootDotProjectionTests

        texts = {name: outputs[root / group / name] for name in FILES}
        SurgeRootDotProjectionTests.assert_counts_and_split(self, texts, purpose, group)
        return texts

    def test_generated_yaml_sources_keep_long_keyword_same_round_and_from_disk(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    source = root / 'static/source.yaml'
                    data = b'\xef\xbb\xbfpayload:\r\n  - DOMAIN-KEYWORD,123.\r\n  - DOMAIN-KEYWORD,123.45\r\n'
                    source.write_bytes(data)
                    configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['static/source.yaml'], 'whitelist': []},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['parent/fin.yaml'], 'whitelist': []}]
                    config = root / 'rulesets.json'
                    config.write_text(json.dumps(configs), encoding='utf-8')
                    old = {root / group / name: b'old\x00\xff\r\n' + name.encode() for group in ('parent', 'child') for name in FILES}
                    for path, content in old.items():
                        path.parent.mkdir(exist_ok=True)
                        path.write_bytes(content)
                    with contextlib.redirect_stderr(io.StringIO()) as messages:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), set(old))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    for group in ('parent', 'child'):
                        texts = self.assert_product_counts(outputs, root, group, purpose)
                        self.assertEqual(texts['fin.txt'], f'# {group} rules: 1\nDOMAIN-KEYWORD,123.45\n')
                        self.assertEqual(texts['fin.yaml'], f'# {group} rules: 2\npayload:\n'
                                         '  - "DOMAIN-KEYWORD,123."\n  - "DOMAIN-KEYWORD,123.45"\n')
                        self.assertEqual(texts['fin-adb.txt'].splitlines()[7:], [DNS_12345] if purpose == 'block' else
                                         ['! No AdBlock rules for non-advertising group.'])
                    skips = {'fin.txt:DOMAIN-KEYWORD': 1, 'fin-surge.txt:DOMAIN-KEYWORD': 1,
                             'fin-surge-ds.txt:DOMAIN-KEYWORD': 2, 'fin-adb.txt:DOMAIN-KEYWORD': 1 if purpose == 'block' else 2}
                    expected_log = [f'{group} {key}: {count}' for group in ('parent', 'child') for key, count in sorted(skips.items())]
                    self.assertEqual(messages.getvalue().splitlines(), expected_log)
                    publish(outputs, root=root)
                    published = {path: text.encode('utf-8') for path, text in outputs.items()}
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    self.assertEqual(source.read_bytes(), data)
                    config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as disk_messages:
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk), {root / 'child' / name for name in FILES})
                    for path, text in disk.items():
                        self.assertEqual(text.splitlines()[:5] + text.splitlines()[6:] if path.name == 'fin-adb.txt' else text,
                                         outputs[path].splitlines()[:5] + outputs[path].splitlines()[6:] if path.name == 'fin-adb.txt' else outputs[path])
                    self.assertEqual(disk_messages.getvalue().splitlines(), [f'child {key}: {count}' for key, count in sorted(skips.items())])
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in disk}, {path: text.encode('utf-8') for path, text in disk.items()})
                    self.assertEqual(source.read_bytes(), data)

    def test_generated_yaml_whitelist_keeps_dns_exception_same_round_and_from_disk(self):
        blockers = (('DOMAIN,cdn.45.example.org', '0.0.0.0 cdn.45.example.org'),
                    ('DOMAIN-SUFFIX,45.example.org', '||45.example.org^'),
                    ('DOMAIN-KEYWORD,45', r'/^.*45.*$/'), ('DOMAIN-WILDCARD,*.45.example.org', r'/^.*\.45\.example\.org$/'),
                    (r'DOMAIN-REGEX,^45\.?$', r'/(?-i:\A45\z)/'))
        for blocker, dns in blockers:
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(blocker=blocker, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/white.yaml').write_text('payload:\n  - DOMAIN-KEYWORD,123.\n  - DOMAIN-KEYWORD,123.45\n', encoding='utf-8')
                        (root / 'static/source.list').write_text(blocker + '\n', encoding='utf-8')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        white = parse_whitelist((root / 'static/white.yaml').read_text())
                        self.assertEqual([rule.value for rule in white], ['123.', '123.45'])
                        parsed, warnings = parse(blocker, purpose=purpose)
                        self.assertEqual(warnings, [])
                        self.assertEqual(exclude_covered(parsed, white), parsed)
                        configs = [{'name': 'whiteparent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['static/white.yaml'], 'whitelist': []},
                                   {'name': 'consumer', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['static/source.list'], 'whitelist': ['whiteparent/fin.yaml']},
                                   {'name': 'external', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['static/source.list'], 'whitelist': ['static/white.yaml']}]
                        config = root / 'rulesets.json'
                        config.write_text(json.dumps(configs), encoding='utf-8')
                        old = {root / group / name: b'old\x00\xff' for group in ('whiteparent', 'consumer', 'external') for name in FILES}
                        for path, content in old.items():
                            path.parent.mkdir(exist_ok=True)
                            path.write_bytes(content)
                        with contextlib.redirect_stderr(io.StringIO()) as messages:
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(set(outputs), set(old))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        for group in ('consumer', 'external'):
                            texts = self.assert_product_counts(outputs, root, group, purpose)
                            self.assertEqual(texts['fin-adb.txt'].splitlines()[7:], ['@@' + DNS_12345, dns] if purpose == 'block' else
                                             ['! No AdBlock rules for non-advertising group.'])
                            if not blocker.startswith('DOMAIN-REGEX,'):
                                self.assertEqual(texts['fin.txt'], f'# {group} rules: 1\n' + blocker + '\n')
                        self.assertNotIn('frozen', messages.getvalue())
                        self.assertNotIn('whitelist-covered', messages.getvalue())
                        publish(outputs, root=root)
                        self.assertEqual({path: path.read_bytes() for path in outputs}, {path: text.encode('utf-8') for path, text in outputs.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        config.write_text(json.dumps(configs[1:2]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as disk_messages:
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(set(disk), {root / 'consumer' / name for name in FILES})
                        for path, text in disk.items():
                            self.assertEqual(text.splitlines()[:5] + text.splitlines()[6:] if path.name == 'fin-adb.txt' else text,
                                             outputs[path].splitlines()[:5] + outputs[path].splitlines()[6:] if path.name == 'fin-adb.txt' else outputs[path])
                        self.assertEqual(disk_messages.getvalue().splitlines(),
                                         [line for line in messages.getvalue().splitlines() if line.startswith('consumer ')])
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in disk}, {path: text.encode('utf-8') for path, text in disk.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
