import contextlib
from dataclasses import replace
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


ROOT = Path(__file__).resolve().parents[1]


class ASNProjectionTests(unittest.TestCase):
    def test_native_padded_scalar_keeps_yaml_without_decimal_route_projection(self):
        parsed, messages = parse('payload:\n  - IP-ASN,0013335\n', purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(parsed[0].value, '0013335')
        self.assertEqual((parsed[0].domain_source, parsed[0].native_fields), ('surge', False))
        outputs, skipped = render('asn', parsed, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - "IP-ASN,0013335"\n')
        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
            self.assertEqual(outputs[name], '# asn rules: 0\n')
            self.assertEqual(skipped[name + ':IP-ASN'], 1)
        self.assertFalse(any('whitelist-covered' in key for key in skipped))

    def test_native_padded_logical_leaf_skips_whole_surge_rule(self):
        for matcher in ('NOT,((IP-ASN,0013335))',
                        'AND,((IP-ASN,0013335),(NETWORK,tcp))',
                        'OR,((NETWORK,tcp),(IP-ASN,0013335))',
                        'AND,((NOT,((IP-ASN,0013335))),(OR,((NETWORK,tcp),(IP-ASN,0))))'):
            with self.subTest(matcher=matcher):
                parsed, messages = parse('rules:\n  - ' + json.dumps(matcher), purpose='proxy')
                self.assertEqual(messages, [])
                outputs, skipped = render('asn', parsed, purpose='proxy', no_resolve='strip')
                kind = parsed[0].kind
                self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n')
                for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
                    self.assertEqual(outputs[name], '# asn rules: 0\n')
                    self.assertEqual(skipped[name + ':' + kind], 1)
                self.assertFalse(any('whitelist-covered' in key for key in skipped))

    def test_native_provider_encodings_preserve_padded_scalar_and_logical_strings(self):
        limits = sys.getrecursionlimit(), sys.get_int_max_str_digits()
        templates = ('{leaf}', 'NOT,(({leaf}))', 'AND,(({leaf}),(NETWORK,tcp))',
                     'OR,((NETWORK,tcp),({leaf}))',
                     'AND,((NOT,(({leaf}))),(OR,((NETWORK,tcp),(IP-ASN,0))))')
        for header in ('payload', 'rules'):
            for scalar in ('plain', 'single', 'double'):
                for value in ('00', '0013335', '0' * 5000, '0' * 5000 + '13335'):
                    for option in ('', ',no-resolve'):
                        for template in templates:
                            matcher = template.format(leaf='IP-ASN,' + value + option)
                            item = matcher if scalar == 'plain' else ("'" + matcher + "'" if scalar == 'single' else json.dumps(matcher))
                            with self.subTest(header=header, scalar=scalar, value=value[:20], option=option, template=template):
                                parsed, messages = parse(header + ':\n  - ' + item, purpose='proxy')
                                self.assertEqual(messages, [])
                                self.assertEqual(len(parsed), 1)
                                outputs, skipped = render('asn', normalize(parsed * 2), purpose='proxy', no_resolve='keep')
                                self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n')
                                self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'), (parsed, []))
                                for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
                                    self.assertEqual(outputs[name], '# asn rules: 0\n')
                                    self.assertEqual(skipped[name + ':' + parsed[0].kind], 1)
                                self.assertFalse(any('whitelist-covered' in key for key in skipped))
        self.assertEqual((sys.getrecursionlimit(), sys.get_int_max_str_digits()), limits)

    def test_padded_projection_all_purposes_modes_options_and_source_directions(self):
        templates = ('{leaf}', 'NOT,(({leaf}))', 'AND,(({leaf}),(SRC-IP-ASN,0013335))',
                     'OR,((NETWORK,tcp),({leaf}))',
                     'AND,((NOT,(({leaf}))),(OR,((NETWORK,tcp),(SRC-IP-ASN,00))))')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for original in ('', ',no-resolve'):
                    flag = ',no-resolve' if mode == 'add' or mode == 'keep' and original else ''
                    for template in templates:
                        matcher = template.format(leaf='IP-ASN,0013335' + original)
                        expected = template.format(leaf='IP-ASN,0013335' + flag)
                        with self.subTest(purpose=purpose, mode=mode, original=original, template=template):
                            parsed, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose=purpose)
                            self.assertEqual(messages, [])
                            outputs, skipped = render('asn', normalize(parsed), purpose=purpose, no_resolve=mode)
                            self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                            for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
                                self.assertEqual(outputs[name], '# asn rules: 0\n')
                                self.assertEqual(skipped[name + ':' + parsed[0].kind], 1)
                            self.assertFalse(any('whitelist-covered' in key for key in skipped))

    def test_canonical_asn_projection_and_ordinary_decimal_normalization_stay_supported(self):
        for raw, canonical in (('0', '0'), ('00', '0'), ('0013335', '13335'),
                               ('AS0013335', '13335'), ('4294967295', '4294967295')):
            for text in ('IP-ASN,' + raw, 'payload:\n  - IP-ASN,' + canonical):
                parsed, messages = parse(text, purpose='proxy')
                self.assertEqual((parsed, messages), ([Rule('IP-ASN', canonical)], []))
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(raw=raw, text=text, mode=mode):
                        flag = ',no-resolve' if mode == 'add' else ''
                        outputs, skipped = render('asn', normalize(parsed), purpose='proxy', no_resolve=mode)
                        for name in ('fin.txt', 'fin-surge.txt'):
                            self.assertEqual(outputs[name], '# asn rules: 1\nIP-ASN,' + canonical + flag + '\n')
                            self.assertNotIn(name + ':IP-ASN', skipped)
                        self.assertEqual(outputs['fin-qx.txt'], '# asn rules: 1\nIP-ASN,' + canonical + ',LIST' + flag + '\n')
                        self.assertNotIn('fin-qx.txt:IP-ASN', skipped)
                        self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - "IP-ASN,' + canonical + flag + '"\n')

    def test_projection_checks_final_fields_independently_of_provenance(self):
        for origin in ('surge', 'mihomo', 'qx'):
            for native_fields in (False, True):
                for kind, value, options in (('IP-ASN', '0013335', ()),
                                              ('IP-ASN', '0013335', ('no-resolve',)),
                                              ('NOT', '((IP-ASN,0013335))', ())):
                    with self.subTest(origin=origin, native_fields=native_fields, options=options, kind=kind):
                        rule = Rule(kind, value, options, native_fields=native_fields, domain_source=origin)
                        outputs, skipped = render('asn', [rule], purpose='proxy', no_resolve='keep')
                        matcher = kind + ',' + value + (',no-resolve' if options else '')
                        self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n')
                        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
                            self.assertEqual(outputs[name], '# asn rules: 0\n')
                            self.assertEqual(skipped[name + ':' + kind], 1)

    def test_target_white_and_allow_keep_padded_and_canonical_identities_separate(self):
        for canonical, padded in (('0', '00'), ('13335', '0013335')):
            native, messages = parse('payload:\n  - IP-ASN,' + padded, purpose='proxy')
            self.assertEqual(messages, [])
            source = [Rule('IP-ASN', canonical), native[0]]
            white = parse_whitelist('payload:\n  - IP-ASN,' + padded + ',no-resolve')
            self.assertEqual(white, native)
            self.assertEqual(exclude_covered(source, white), source[:1])
            allowed = replace(native[0], allow=True, options=('no-resolve',))
            self.assertEqual(exclude_covered([allowed], white), [allowed])
            for mode in ('add', 'strip', 'keep'):
                flag = ',no-resolve' if mode == 'add' else ''
                for as_allow in (False, True):
                    with self.subTest(canonical=canonical, mode=mode, as_allow=as_allow):
                        outputs, skipped = render('asn', source + ([allowed] if as_allow else []),
                            purpose='proxy', no_resolve=mode, whitelist=() if as_allow else white)
                        self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - "IP-ASN,' + canonical + flag + '"\n')
                        for name in ('fin.txt', 'fin-surge.txt'):
                            self.assertEqual(outputs[name], '# asn rules: 1\nIP-ASN,' + canonical + flag + '\n')
                        self.assertEqual(outputs['fin-qx.txt'], '# asn rules: 1\nIP-ASN,' + canonical + ',LIST' + flag + '\n')
                        self.assertEqual(skipped['fin.yaml:IP-ASN:whitelist-covered'], 1)
                        self.assertEqual(skipped['whitelist-covered:IP-ASN'], 1)
                        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
                            self.assertNotIn(name + ':IP-ASN:whitelist-covered', skipped)
                outputs, skipped = render('asn', native, purpose='proxy', no_resolve=mode,
                                           whitelist=[Rule('IP-ASN', canonical)])
                self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - "IP-ASN,' + padded + flag + '"\n')
                self.assertFalse(any('whitelist-covered' in key for key in skipped))
        unsupported = Rule('IP-ASN', '0013335', ('unsupported',))
        outputs, skipped = render('asn', [unsupported], purpose='proxy', no_resolve='keep',
                                   whitelist=[Rule('IP-ASN', '0013335')])
        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
            self.assertEqual(outputs[name], '# asn rules: 0\n')
        self.assertEqual(outputs['fin.yaml'], '# asn rules: 0\npayload:\n')
        self.assertFalse(any('whitelist-covered' in key for key in skipped))

    def test_native_padded_no_resolve_scalar_uses_same_projection_boundary(self):
        parsed, messages = parse('rules:\n  - IP-ASN,0013335,no-resolve\n', purpose='block')
        self.assertEqual(messages, [])
        outputs, skipped = render('asn', parsed, purpose='block', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# asn rules: 1\npayload:\n  - "IP-ASN,0013335,no-resolve"\n')
        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
            self.assertEqual(outputs[name], '# asn rules: 0\n')
            self.assertEqual(skipped[name + ':IP-ASN'], 1)
        self.assertFalse(any('whitelist-covered' in key for key in skipped))


class ASNGenerationTests(unittest.TestCase):
    def test_parent_surge_source_does_not_rewrite_native_asn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input.list').write_text('payload:\n  - IP-ASN,0013335\n', encoding='utf-8')
            configs = [{'name': name, 'purpose': 'proxy', 'no_resolve': 'strip',
                        'sources': source, 'whitelist': []} for name, source in (
                            ('parent', ['input.list']), ('child', ['parent/fin.txt']))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda url: self.fail(url))
            publish(outputs, root=root)
            self.assertEqual((root / 'child/fin.yaml').read_bytes(), b'# child rules: 0\npayload:\n')
            self.assertEqual((root / 'parent/fin.yaml').read_bytes(), b'# parent rules: 1\npayload:\n  - "IP-ASN,0013335"\n')

    def test_cli_publishes_actual_empty_dependencies_and_rejects_disk_empty_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            (root / 'static/input.list').write_bytes(b'payload:\r\n  - IP-ASN,0013335\r\n')
            (root / 'static/unchanged').write_bytes(b'static sentinel\x00\xff\r\n')
            inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
            configs = [{'name': name, 'purpose': 'proxy', 'no_resolve': 'strip',
                        'sources': source, 'whitelist': []} for name, source in (
                ('parent', ['static/input.list']), ('child', ['parent/fin.txt']), ('yamlchild', ['parent/fin.yaml']))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            command = [sys.executable, '-I', '-B', '-c',
                "import runpy, sys; root = sys.argv.pop(1); sys.path.insert(0, root); runpy.run_path(root + '/generate.py', run_name='__main__')",
                str(ROOT), '--root', str(root)]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.stderr.splitlines(), [f'{group} {name}:IP-ASN: 1'
                for group in ('parent', 'yamlchild') for name in sorted(FILES) if name != 'fin.yaml'])
            published = {}
            for group in ('parent', 'child', 'yamlchild'):
                for name in FILES:
                    data = (root / group / name).read_bytes()
                    published[root / group / name] = data
                    if name == 'fin-adb.txt':
                        self.assertRegex(data, (r'\A\[Adblock Plus 2\.0\]\n! Title: ' + group + r'\n'
                            r'! Homepage: https://github\.com/DoingDog/rconvert\n! Expires: 1 day\n'
                            r'! License: Inherits upstream licenses\n! Version: [0-9]{12}\n! Total count: 0\n'
                            r'! No AdBlock rules for non-advertising group\.\n\Z').encode())
                    elif name == 'fin.yaml':
                        self.assertEqual(data, (f'# {group} rules: {int(group != "child")}\npayload:\n' +
                            ('  - "IP-ASN,0013335"\n' if group != 'child' else '')).encode())
                    else:
                        self.assertEqual(data, f'# {group} rules: 0\n'.encode())
            invalid = [configs[1], {'name': 'whitechild', 'purpose': 'proxy', 'no_resolve': 'strip',
                                   'sources': ['static/input.list'], 'whitelist': ['parent/fin.txt']}]
            for config, message in zip(invalid, ('No adaptable rules in', 'Invalid whitelist')):
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=8)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                self.assertFalse((root / 'whitechild').exists())
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_unavailable_source_freezes_covered_parent_and_dependencies_without_partial_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            native = b'payload:\n  - IP-ASN,0013335\n'
            (root / 'static/white.list').write_bytes(native)
            (root / 'static/healthy.list').write_bytes(b'DOMAIN,healthy.example\n')
            inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
            configs = [{'name': group, 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': sources, 'whitelist': white} for group, sources, white in (
                ('parent', ['https://example.com/asn', 'https://example.com/missing'], ['static/white.list']),
                ('sourcechild', ['parent/fin.yaml'], []),
                ('whitechild', ['static/healthy.list'], ['parent/fin.yaml']),
                ('healthy', ['static/healthy.list'], []))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            old = {}
            for config in configs:
                (root / config['name']).mkdir()
                for name in FILES:
                    path = root / config['name'] / name
                    path.write_bytes(b'old complete product\x00\xff\r\n')
                    old[path] = path.read_bytes()

            def fetch(url):
                if url.endswith('/missing'):
                    raise RuntimeError('missing') from HTTPError(url, 404, 'missing', {}, None)
                self.assertEqual(url, 'https://example.com/asn')
                return native

            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                outputs = generate(root, fetch)
            self.assertEqual(set(outputs), {root / 'healthy' / name for name in FILES})
            self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
            self.assertIn('parent: no routable rules; frozen', diagnostic.getvalue())
            self.assertEqual(outputs[root / 'healthy/fin.txt'], '# healthy rules: 1\nDOMAIN,healthy.example\n')
            publish(outputs, root=root)
            self.assertEqual({path: path.read_bytes() for path in old if path.parent.name != 'healthy'},
                             {path: data for path, data in old.items() if path.parent.name != 'healthy'})
            published = {path: path.read_bytes() for path in old}
            (root / 'static/white.list').write_bytes(b'IP-ASN,4294967296\n')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                publish(generate(root, lambda url: self.fail(url)), root=root)
            self.assertEqual({path: path.read_bytes() for path in published}, published)
            (root / 'static/white.list').write_bytes(native)
            missing = root / 'sourcechild/fin-qx.txt'
            missing.unlink()
            remaining = {path: data for path, data in published.items() if path != missing}
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'Cannot freeze sourcechild: missing complete old file'):
                publish(generate(root, fetch), root=root)
            self.assertEqual({path: path.read_bytes() for path in remaining}, remaining)
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_parent_yaml_identity_empty_route_dependencies_and_disk_boundaries(self):
        for logical in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(logical=logical, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        original = 'IP-ASN,0013335,no-resolve'
                        matcher = 'NOT,((' + original + '))' if logical else original
                        (root / 'static/input.list').write_text('payload:\n  - ' + json.dumps(matcher) + '\n', encoding='utf-8')
                        (root / 'static/unchanged').write_bytes(b'static sentinel\x00\xff\r\n')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                    'sources': sources, 'whitelist': white} for group, sources, white in (
                            ('parent', ['static/input.list'], []),
                            ('textchild', ['parent/fin.txt'], []),
                            ('qxchild', ['parent/fin-qx.txt'], []),
                            ('yamlchild', ['parent/fin.yaml'], []),
                            ('emptywhite', ['static/input.list'], ['parent/fin.txt']))]
                        if not logical:
                            configs.append({'name': 'yamlwhite', 'purpose': purpose, 'no_resolve': mode,
                                            'sources': ['static/input.list'], 'whitelist': ['parent/fin.yaml']})
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for config in configs:
                            (root / config['name']).mkdir()
                            for name in FILES:
                                path = root / config['name'] / name
                                path.write_bytes(b'old complete product\x00\xff\r\n')
                                old[path] = path.read_bytes()
                        leaf = 'IP-ASN,0013335' + ('' if mode == 'strip' else ',no-resolve')
                        expected_matcher = 'NOT,((' + leaf + '))' if logical else leaf
                        expected = {}
                        for config in configs:
                            group = config['name']
                            has_yaml = group in ('parent', 'yamlchild', 'emptywhite')
                            for name in FILES:
                                if name == 'fin-adb.txt':
                                    text = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                        '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                        '! License: Inherits upstream licenses\n! Version: 202610230000\n! Total count: 0\n' +
                                        ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n'))
                                elif name == 'fin.yaml':
                                    text = f'# {group} rules: {int(has_yaml)}\npayload:\n' + (
                                        '  - ' + json.dumps(expected_matcher) + '\n' if has_yaml else '')
                                else:
                                    text = f'# {group} rules: 0\n'
                                expected[root / group / name] = text
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 23, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(outputs, expected)
                        kind = 'NOT' if logical else 'IP-ASN'
                        self.assertEqual(diagnostic.getvalue().splitlines(), [f'{group} {name}:{kind}: 1'
                            for group in ('parent', 'yamlchild', 'emptywhite') for name in sorted(FILES) if name != 'fin.yaml'])
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode('utf-8') for path, text in expected.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        disk_configs = [config for config in configs if config['name'] in ('yamlchild', 'yamlwhite')]
                        (root / 'rulesets.json').write_text(json.dumps(disk_configs), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 23, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items()
                                                if path.parent.name in ('yamlchild', 'yamlwhite')})
                        publish(disk, root=root)
                        for role, name in (('sources', 'textchild'), ('whitelist', 'emptywhite')):
                            config = next(config for config in configs if config['name'] == name)
                            (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(
                                    ValueError, 'No adaptable rules in' if role == 'sources' else 'Invalid whitelist'):
                                publish(generate(root, lambda url: self.fail(url)), root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
