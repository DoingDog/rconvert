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


class GeoipRegressionTests(unittest.TestCase):
    def test_native_named_category_is_mihomo_only(self):
        parsed, messages = parse('payload:\n  - GEOIP,telegram', purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(parsed, [Rule('GEOIP', 'telegram')])
        outputs, diagnostics = render('geo', parsed, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# geo rules: 1\npayload:\n  - "GEOIP,telegram"\n')
        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
            self.assertEqual(outputs[name], '# geo rules: 0\n')
            self.assertEqual(diagnostics[name + ':GEOIP'], 1)
        self.assertEqual(diagnostics['fin-adb.txt:GEOIP'], 1)

    def test_unicode_dat_category_is_not_the_ascii_country_identity(self):
        parsed, messages = parse('payload:\n  - "GEOIP,ß"', purpose='proxy')
        self.assertEqual(messages, [])
        white = parse_whitelist('payload:\n  - GEOIP,SS')
        self.assertEqual(exclude_covered(iter(parsed), iter(white)), parsed)
        outputs, diagnostics = render('geo', parsed, whitelist=white, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# geo rules: 1\npayload:\n  - "GEOIP,ß"\n')
        self.assertFalse(any('whitelist-covered' in key for key in diagnostics))

    def test_native_categories_keep_direction_tail_parameters_and_literal_characters(self):
        forms = [('GEOIP', '', 'GEOIP', (), []),
                 ('SRC-GEOIP', ',no-resolve', 'SRC-GEOIP', (), []),
                 ('GEOIP', ',src', 'SRC-GEOIP', (), []),
                 ('GEOIP', ',no-resolve', 'GEOIP', ('no-resolve',), []),
                 ('GEOIP', ',DIRECT,src,no-resolve', 'SRC-GEOIP', (),
                  ['line 2: unsupported no-resolve for SRC-GEOIP']),
                 ('GEOIP', ',REJECT,unknown,NO-RESOLVE,SRC', 'GEOIP', (), [])]
        for value in ('private', 'cloudflare', '!CN', '!telegram', 'a!b', '!!',
                      '\t', '\xa0', '\t!telegram', '!\t', '!\xa0', 'some category'):
            for head, tail, kind, options, expected_messages in forms:
                text = 'rules:\n  - ' + json.dumps(head + ', ' + value + ' ' + tail)
                with self.subTest(value=value, head=head, tail=tail):
                    parsed, messages = parse(text, purpose='direct')
                    self.assertEqual(messages, expected_messages)
                    self.assertEqual(parsed, [Rule(kind, value, options)])
                    for mode, flag in (('add', ',no-resolve' if kind == 'GEOIP' else ''),
                                       ('strip', ''), ('keep', ',no-resolve' if options else '')):
                        outputs, diagnostics = render('geo', parsed, purpose='direct', no_resolve=mode)
                        self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), kind + ',' + value + flag)
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(outputs[name], '# geo rules: 0\n')
                            self.assertEqual(diagnostics[name + ':' + kind], 1)
                    if expected_messages:
                        with self.assertWarnsRegex(UserWarning, 'line 2: unsupported no-resolve for SRC-GEOIP'):
                            self.assertEqual(parse_whitelist(text), [Rule(kind, value)])
                    else:
                        self.assertEqual(parse_whitelist(text), [Rule(kind, value)])

    def test_ordinary_country_lan_unknown_and_native_unknown_boundaries(self):
        for value in ('telegram', 'private', '!CN', '!telegram', '!', 'ß', 'a!b'):
            for kind in ('GEOIP', 'SRC-GEOIP'):
                with self.subTest(value=value, kind=kind):
                    parsed, messages = parse(f'{kind},{value},PROXY\nDOMAIN,keep.example.org', purpose='proxy')
                    self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.org')])
                    self.assertEqual(messages, [f'line 1: invalid {kind} {value}'])
        for value in ('', ' ', '!', ' ! ', 'UNKNOWN', 'unknown'):
            for kind in ('GEOIP', 'SRC-GEOIP'):
                parsed, messages = parse('payload:\n  - ' + json.dumps(kind + ',' + value) +
                                         '\nDOMAIN,keep.example.org', purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.org')])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith('line 2: invalid ' + kind))
        for value in ('CN', 'cn', 'LAN', 'lan', 'UNKNOWN'):
            parsed, messages = parse('GEOIP,' + value, purpose='proxy')
            self.assertEqual(messages, [])
            for mode, flag in (('add', ',no-resolve'), ('strip', ''), ('keep', '')):
                outputs, _ = render('geo', parsed, purpose='proxy', no_resolve=mode)
                self.assertEqual(outputs['fin.txt'], '# geo rules: 1\nGEOIP,' + value + flag + '\n')
                self.assertEqual(outputs['fin-qx.txt'], '# geo rules: 1\nGEOIP,' + value + ',LIST' + flag + '\n')
                if value == 'UNKNOWN':
                    self.assertEqual(outputs['fin.yaml'], '# geo rules: 0\npayload:\n')
                else:
                    self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), 'GEOIP,' + value + flag)
        self.assertEqual(parse('SRC-GEOIP,UNKNOWN', purpose='proxy')[0], [])
        for kind in ('GEOIP', 'SRC-GEOIP'):
            for value in ('CN', 'LAN'):
                self.assertEqual(parse('payload:\n  - ' + kind + ',' + value, purpose='proxy'),
                                 ([Rule(kind, value)], []))
        for source in ('payload:\n  - "GEOIP,telegram\n"', 'payload:\n  - GEOIP,<html>',
                       'payload:\n  - "GEOIP,telegram'):
            self.assertEqual(parse(source, purpose='proxy')[0], [])

    def test_native_logical_categories_are_complete_and_target_local(self):
        for value in ('telegram', 'private', '!CN', '!telegram', 'ß', '\t', '\xa0'):
            for kind in ('GEOIP', 'SRC-GEOIP'):
                leaf = '(' + kind + ',' + value + (',no-resolve' if kind == 'GEOIP' else '') + ')'
                templates = ['AND,({leaf},(IP-CIDR,192.0.2.0/24{flag}))',
                             'OR,({leaf},(IP-CIDR,192.0.2.0/24{flag}))',
                             'NOT,({leaf})',
                             'NOT,((AND,({leaf},(IP-CIDR,192.0.2.0/24{flag}))))']
                for template in templates:
                    expression = template.format(leaf=leaf, flag='')
                    source = 'payload:\n  - ' + json.dumps(expression)
                    parsed, messages = parse(source, purpose='proxy')
                    self.assertEqual(messages, [])
                    self.assertTrue(parsed[0].native_fields)
                    self.assertFalse(parse_whitelist(source))
                    for mode, ip_flag in (('add', ',no-resolve'), ('strip', ''), ('keep', '')):
                        output_leaf = '(' + kind + ',' + value + (',no-resolve' if kind == 'GEOIP' and mode != 'strip' else '') + ')'
                        expected = template.format(leaf=output_leaf, flag=ip_flag)
                        with self.subTest(value=value, kind=kind, template=template, mode=mode):
                            outputs, diagnostics = render('geo', parsed, purpose='proxy', no_resolve=mode)
                            self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), expected)
                            self.assertEqual(outputs['fin.txt'], '# geo rules: 0\n')
                            self.assertEqual(diagnostics['fin.txt:' + parsed[0].kind], 1)
                            self.assertEqual(diagnostics['fin-qx.txt:' + parsed[0].kind], 1)
                            self.assertNotIn('fin.yaml:' + parsed[0].kind, diagnostics)
                            self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy')[1], [])
        for leaf, expected_messages in (('GEOIP,telegram,src,no-resolve',
                                         ['line 2: unsupported no-resolve for SRC-GEOIP']),
                                        ('SRC-GEOIP,telegram,no-resolve', [])):
            parsed, messages = parse('payload:\n  - ' + json.dumps('NOT,((' + leaf + '))'), purpose='proxy')
            self.assertEqual(messages, expected_messages)
            self.assertEqual(parsed[0].value, '((SRC-GEOIP,telegram))')
        deep = '(GEOIP,telegram,no-resolve)'
        for _ in range(128):
            deep = '(NOT,(' + deep + '))'
        parsed, messages = parse('payload:\n  - ' + json.dumps(deep[1:-1]), purpose='proxy')
        self.assertEqual(messages, [])
        outputs, diagnostics = render('geo', parsed, purpose='proxy', no_resolve='strip')
        self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), deep[1:-1].replace(',no-resolve', ''))
        self.assertEqual(diagnostics['fin.txt:NOT'], 1)

    def test_geoip_identity_is_directional_literal_for_unicode_and_case_insensitive_for_ascii(self):
        for kind in ('GEOIP', 'SRC-GEOIP'):
            for prefix in ('', '!'):
                for first, second in (('ß', 'SS'), ('SS', 'ß'), ('İ', 'i̇')):
                    white = parse_whitelist('payload:\n  - ' + json.dumps(kind + ',' + prefix + second))
                    source, messages = parse('payload:\n  - ' + json.dumps(kind + ',' + prefix + first), purpose='proxy')
                    self.assertEqual(messages, [])
                    for options in ((), ('no-resolve',), ('unsupported',)):
                        rule = replace(source[0], options=options)
                        self.assertEqual(exclude_covered(iter([rule]), iter(white)), [rule])
                        self.assertEqual(normalize(iter([rule, rule])), [rule])
                        allow = replace(rule, allow=True)
                        self.assertEqual(exclude_covered([allow], white), [allow])
                        self.assertEqual(exclude_covered([rule], [replace(rule, options=())]), [])
                    other_kind = 'SRC-GEOIP' if kind == 'GEOIP' else 'GEOIP'
                    self.assertEqual(exclude_covered(source, [replace(source[0], kind=other_kind)]), source)
                    self.assertEqual(exclude_covered(source, [replace(source[0], value=('' if prefix else '!') + first)]), source)
        for value, white in (('cn', 'CN'), ('lan', 'LAN'), ('UNKNOWN', 'unknown'), ('telegram', 'TELEGRAM')):
            self.assertEqual(exclude_covered([Rule('GEOIP', value)], [Rule('GEOIP', white)]), [])

    def test_raw_white_allow_and_options_do_not_invent_unsupported_target_coverage(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for white in (Rule('GEOIP', 'ß'), Rule('GEOIP', '!SS'), Rule('SRC-GEOIP', 'SS')):
                    rules = [Rule('GEOIP', 'SS'), replace(white, allow=True)]
                    outputs, diagnostics = render('geo', rules, whitelist=[white], purpose=purpose, no_resolve=mode)
                    flag = ',no-resolve' if mode == 'add' else ''
                    self.assertEqual(outputs['fin.txt'], '# geo rules: 1\nGEOIP,SS' + flag + '\n')
                    self.assertEqual(outputs['fin-qx.txt'], '# geo rules: 1\nGEOIP,SS,LIST' + flag + '\n')
                    self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), 'GEOIP,SS' + flag)
                    self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
        rule = Rule('GEOIP', 'telegram')
        for options in ((), ('no-resolve',), ('unsupported',), ('force-cellular',)):
            source = replace(rule, options=options)
            allow = replace(source, allow=True)
            outputs, diagnostics = render('geo', [source, allow], purpose='block', no_resolve='keep')
            self.assertEqual(outputs['fin.txt'], '# geo rules: 0\n')
            self.assertEqual(outputs['fin-qx.txt'], '# geo rules: 0\n')
            if options == ('unsupported',):
                self.assertFalse(any('whitelist-covered' in key for key in diagnostics))
            else:
                self.assertEqual(diagnostics['fin.yaml:GEOIP:whitelist-covered'], 1)
                self.assertEqual(diagnostics['whitelist-covered:GEOIP'], 1)
                self.assertFalse(any(key.startswith(('fin.txt:', 'fin-qx.txt:')) and 'whitelist-covered' in key
                                     for key in diagnostics))

    def test_generated_source_and_white_use_actual_nonempty_yaml_bytes(self):
        for kind in ('GEOIP', 'SRC-GEOIP'):
            for first, second in (('ß', 'SS'), ('SS', 'ß'), ('!ß', '!SS'),
                                  ('!SS', '!ß'), ('telegram', 'telegram')):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(kind=kind, first=first, second=second, purpose=purpose, mode=mode), \
                                tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            input_bytes = ('﻿payload:\r\n  - ' + json.dumps(kind + ',' + first, ensure_ascii=False) + '\r\n').encode('utf-8')
                            white_bytes = ('rules:\n  - ' + json.dumps(kind + ',' + second, ensure_ascii=False) + '\n').encode('utf-8')
                            (root / 'input.yaml').write_bytes(input_bytes)
                            (root / 'white.yaml').write_bytes(white_bytes)
                            (root / 'static').mkdir()
                            marker = root / 'static' / 'marker'
                            marker.write_bytes(b'unchanged')
                            configs = [dict(name=name, purpose=purpose, no_resolve=mode, sources=sources, whitelist=white)
                                       for name, sources, white in (
                                           ('parent', ['white.yaml'], []), ('source', ['input.yaml'], []),
                                           ('mirror', ['source/fin.yaml'], []),
                                           ('child', ['input.yaml'], ['parent/fin.yaml']),
                                           ('raw', ['input.yaml'], ['white.yaml']))]
                            config = root / 'rulesets.json'
                            config.write_text(json.dumps(configs), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()) as logs:
                                outputs = generate(root, self.fail)
                            self.assertEqual(len(outputs), 30)
                            self.assertNotIn('frozen', logs.getvalue())
                            flag = ',no-resolve' if kind == 'GEOIP' and mode == 'add' else ''
                            for group in ('source', 'mirror', 'child', 'raw'):
                                text = outputs[root / group / 'fin.yaml']
                                expected = [] if first == second and group in ('child', 'raw') else [kind + ',' + first + flag]
                                self.assertEqual([json.loads(line[4:]) for line in text.splitlines()[2:]], expected)
                                self.assertEqual(parse(text, purpose=purpose)[1], [])
                                if first != 'SS' or kind != 'GEOIP':
                                    self.assertEqual(outputs[root / group / 'fin.txt'], f'# {group} rules: 0\n')
                                    self.assertEqual(outputs[root / group / 'fin-qx.txt'], f'# {group} rules: 0\n')
                            publish(outputs, root=root)
                            self.assertEqual({path: path.read_bytes() for path in outputs},
                                             {path: text.encode('utf-8') for path, text in outputs.items()})
                            config.write_text(json.dumps(configs[2:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()) as disk_logs:
                                disk = generate(root, self.fail)
                            self.assertEqual(len(disk), 18)
                            self.assertNotIn('frozen', disk_logs.getvalue())
                            for group in ('mirror', 'child', 'raw'):
                                for name in FILES:
                                    if name != 'fin-adb.txt':
                                        self.assertEqual(disk[root / group / name], outputs[root / group / name])
                            self.assertEqual((root / 'input.yaml').read_bytes(), input_bytes)
                            self.assertEqual((root / 'white.yaml').read_bytes(), white_bytes)
                            self.assertEqual(marker.read_bytes(), b'unchanged')

    def test_supported_native_categories_publish_while_unsupported_only_groups_freeze(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input.yaml').write_text('payload:\n  - GEOIP,!telegram\n', encoding='utf-8')
            configs = [dict(name='geo', purpose='proxy', no_resolve='keep', sources=['input.yaml'], whitelist=[])]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'geo').mkdir()
            old = {root / 'geo' / name: b'old product\n' for name in FILES}
            for path, data in old.items():
                path.write_bytes(data)
            with contextlib.redirect_stderr(io.StringIO()) as logs:
                outputs = generate(root, self.fail)
            self.assertEqual(len(outputs), 6)
            self.assertNotIn('frozen', logs.getvalue())
            self.assertEqual({path: path.read_bytes() for path in old}, old)
            self.assertEqual(outputs[root / 'geo' / 'fin.yaml'], '# geo rules: 1\npayload:\n  - "GEOIP,!telegram"\n')
            publish(outputs, root=root)
            before = {path: path.read_bytes() for path in old}
            (root / 'input.yaml').write_text('OR,((GEOIP,UNKNOWN),(PROCESS-PATH,\'/tmp/foo \'))\n', encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()) as logs:
                self.assertEqual(generate(root, self.fail), {})
            self.assertIn('no routable rules; frozen', logs.getvalue())
            self.assertEqual({path: path.read_bytes() for path in old}, before)
