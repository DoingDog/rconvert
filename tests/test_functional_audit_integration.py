import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from formats import FILES
from generate import generate, publish
from sources import load_config, resolve_source
from tests.test_formats import expected_domain, expected_paired_dns


class GeneratedDomainBytesIntegrationTests(unittest.TestCase):
    def test_production_text_dependency_reads_empty_native_parent_bytes_without_yaml_recovery(self):
        from tests.test_functional_audit_projection import SurgeRootDotProjectionTests

        production = {config['name']: config for config in load_config(Path(__file__).resolve().parents[1])}
        dependency = production['big-data']['sources'][0]
        self.assertEqual(dependency, 'cdn/fin.txt')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            inputs = {root / 'static/native.yaml': b'\xef\xbb\xbfpayload:\r\n  - DOMAIN,A.test\r\n  - DOMAIN-SUFFIX,b.test\r\n',
                      root / 'static/neighbor.list': b'DOMAIN,neighbor.example.org\n'}
            for path, data in inputs.items():
                path.write_bytes(data)
            configs = [dict(production['cdn'], sources=['static/native.yaml'], whitelist=[]),
                       dict(production['big-data'], sources=[dependency], whitelist=[]),
                       dict(name='yaml-child', purpose='proxy', no_resolve='add', sources=['cdn/fin.yaml'], whitelist=[]),
                       dict(name='white-child', purpose='proxy', no_resolve='add',
                            sources=['static/neighbor.list'], whitelist=[dependency])]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            self.assertEqual(load_config(root), configs)
            self.assertEqual(resolve_source(root, dependency), root / 'cdn/fin.txt')
            old = {}
            for config in configs:
                (root / config['name']).mkdir()
                for name in FILES:
                    path = root / config['name'] / name
                    old[path] = b'stale native artifact\x00\xff\r\n'
                    path.write_bytes(old[path])
            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                outputs = generate(root, lambda url: self.fail(url))
            self.assertEqual(set(outputs), set(old))
            for config in configs:
                group = config['name']
                products = {name: outputs[root / group / name] for name in FILES}
                SurgeRootDotProjectionTests.assert_counts_and_split(self, products, 'proxy', group)
                if group in {'cdn', 'yaml-child'}:
                    self.assertEqual(products['fin.yaml'], f'# {group} rules: 2\npayload:\n'
                                     '  - "DOMAIN,A.test"\n  - "DOMAIN-SUFFIX,b.test"\n')
                    self.assertEqual(products['fin-qx.txt'], f'# {group} rules: 2\n'
                                     'HOST,A.test,LIST\nHOST-SUFFIX,b.test,LIST\n')
                    for name in ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                        self.assertEqual(products[name], f'# {group} rules: 0\n')
                elif group == 'big-data':
                    for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                        self.assertEqual(products[name], '# big-data rules: 0\n')
                    self.assertEqual(products['fin.yaml'], '# big-data rules: 0\npayload:\n')
                else:
                    self.assertEqual(products['fin.txt'], '# white-child rules: 1\nDOMAIN,neighbor.example.org\n')
                    self.assertEqual(products['fin.yaml'], '# white-child rules: 1\npayload:\n  - ' +
                                     json.dumps(expected_domain('DOMAIN', 'neighbor.example.org')) + '\n')
            expected_diagnostics = [f'{group} {name}:{kind}: 1' for group in ('cdn', 'yaml-child')
                                    for name in ('fin-adb.txt', 'fin-surge-ds.txt', 'fin.txt')
                                    for kind in ('DOMAIN', 'DOMAIN-SUFFIX')]
            expected_diagnostics.append('white-child fin-adb.txt:DOMAIN: 1')
            self.assertEqual(diagnostic.getvalue().splitlines(), expected_diagnostics)
            self.assertEqual({path: path.read_bytes() for path in old}, old)
            publish(outputs, root=root)
            published = {path: path.read_bytes() for path in outputs}
            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
            # 未声明父组的磁盘空文件仍按严格本地输入校验。
            for config, message in ((configs[1], 'No adaptable rules in .*cdn.*fin.txt'),
                                    (configs[3], 'Invalid whitelist .*cdn.*fin.txt.*no rules')):
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                self.assertEqual(load_config(root), [config])
                with self.assertRaisesRegex(ValueError, message):
                    publish(generate(root, lambda url: self.fail(url)), root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_six_outputs_and_diagnostics_follow_same_round_disk_and_copied_source_white_bytes(self):
        from tests.test_functional_audit_projection import SurgeRootDotProjectionTests

        for filename in ('fin.yaml', 'fin.txt', 'fin-surge-ds.txt'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(filename=filename, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        inputs = {root / 'static/source.list': b'\xef\xbb\xbf# editable fixture\r\nDOMAIN,A.TEST.\r\nDOMAIN-SUFFIX,B.TEST.\r\n',
                                  root / 'static/white.list': b'# independent whitelist\r\nDOMAIN-SUFFIX,test\r\n'}
                        for path, data in inputs.items():
                            path.write_bytes(data)
                        configs = [dict(name=group, purpose=purpose, no_resolve=mode, sources=sources, whitelist=white)
                                   for group, sources, white in (
                                       ('parent', ['static/source.list'], []),
                                       ('white', ['static/white.list'], []),
                                       ('source-child', ['parent/' + filename], []),
                                       ('filtered', ['parent/' + filename], ['white/' + filename]))]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        self.assertEqual(load_config(root), configs)
                        for config in configs:
                            for entry in config['sources'] + config['whitelist']:
                                self.assertEqual(resolve_source(root, entry), (root / entry).resolve())
                        old = {}
                        for config in configs:
                            (root / config['name']).mkdir()
                            for name in FILES:
                                path = root / config['name'] / name
                                old[path] = b'old artifact\x00\xff\r\n'
                                path.write_bytes(old[path])
                        raw = filename == 'fin.yaml'
                        ordinary = {
                            'fin.txt': ['DOMAIN,a.test', 'DOMAIN-SUFFIX,b.test'],
                            'fin-qx.txt': ['HOST,a.test,LIST', 'HOST-SUFFIX,b.test,LIST'],
                            'fin.yaml': [expected_domain('DOMAIN', 'a.test'), expected_domain('DOMAIN-SUFFIX', 'b.test')],
                            'fin-adb.txt': ['||b.test^', '0.0.0.0 a.test'],
                            'fin-surge.txt': [], 'fin-surge-ds.txt': ['a.test', '.b.test'],
                        }
                        source_bodies = {name: list(rows) for name, rows in ordinary.items()}
                        if raw:
                            source_bodies = {name: ordinary[name] if name == 'fin.yaml' else [] for name in FILES}
                            source_bodies['fin-adb.txt'] = [expected_paired_dns('a.test')]
                        filtered_bodies = {name: [] for name in FILES}
                        filtered_bodies['fin-adb.txt'] = [expected_paired_dns('a.test')] if raw else ['@@||test^']
                        white_bodies = {
                            'fin.txt': ['DOMAIN-SUFFIX,test'], 'fin-qx.txt': ['HOST-SUFFIX,test,LIST'],
                            'fin.yaml': [expected_domain('DOMAIN-SUFFIX', 'test')], 'fin-adb.txt': ['||test^'],
                            'fin-surge.txt': [], 'fin-surge-ds.txt': ['.test'],
                        }
                        expected = {'parent': ordinary, 'white': white_bodies,
                                    'source-child': source_bodies, 'filtered': filtered_bodies}
                        diagnostics = {}
                        if purpose != 'block':
                            diagnostics.update({'parent fin-adb.txt:DOMAIN': 1, 'parent fin-adb.txt:DOMAIN-SUFFIX': 1,
                                                'white fin-adb.txt:DOMAIN-SUFFIX': 1})
                        if raw:
                            for group in ('source-child', 'filtered'):
                                diagnostics.update({group + ' ' + name + ':DOMAIN-REGEX': 2 for name in
                                                    ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt')})
                            diagnostics.update({'filtered fin.yaml:DOMAIN-REGEX:whitelist-covered': 2,
                                                'filtered whitelist-covered:DOMAIN-REGEX': 2,
                                                'source-child fin-adb.txt:DOMAIN-REGEX': 1 if purpose == 'block' else 2,
                                                'filtered fin-adb.txt:DOMAIN-REGEX': 2})
                        elif purpose != 'block':
                            diagnostics.update({'source-child fin-adb.txt:DOMAIN': 1, 'source-child fin-adb.txt:DOMAIN-SUFFIX': 1})

                        def check(products, messages, groups):
                            self.assertEqual(set(products), {root / group / name for group in groups for name in FILES})
                            wanted_messages = [f'{key}: {count}' for group in groups
                                               for key, count in sorted(diagnostics.items()) if key.startswith(group + ' ')]
                            self.assertEqual(messages.splitlines(), wanted_messages)
                            for group in groups:
                                output = {name: products[root / group / name] for name in FILES}
                                SurgeRootDotProjectionTests.assert_counts_and_split(self, output, purpose, group)
                                for name, rows in expected[group].items():
                                    lines = output[name].splitlines()
                                    if name == 'fin.yaml':
                                        actual = [json.loads(line[4:]) for line in lines[2:]]
                                    else:
                                        actual = lines[7 if name == 'fin-adb.txt' else 1:]
                                    wanted = (['! No AdBlock rules for non-advertising group.']
                                              if name == 'fin-adb.txt' and purpose != 'block' else rows)
                                    self.assertEqual(actual, wanted, (group, name))

                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as messages:
                            clock.now.return_value = datetime(2026, 10, 15, 12, 34, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        check(outputs, messages.getvalue(), ['parent', 'white', 'source-child', 'filtered'])
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        # 副本保留真实 DOMAIN-SET 文件名上下文，不恢复上游 Rule。
                        for group in ('parent', 'white'):
                            path = root / 'static' / group / filename
                            path.parent.mkdir()
                            path.write_bytes(published[root / group / filename])
                            inputs[path] = path.read_bytes()
                        for copied in (False, True):
                            children = configs[2:]
                            if copied:
                                children = [dict(configs[2], sources=['static/parent/' + filename]),
                                            dict(configs[3], sources=['static/parent/' + filename],
                                                 whitelist=['static/white/' + filename])]
                            (root / 'rulesets.json').write_text(json.dumps(children), encoding='utf-8')
                            self.assertEqual(load_config(root), children)
                            for config in children:
                                for entry in config['sources'] + config['whitelist']:
                                    self.assertEqual(resolve_source(root, entry).read_bytes(),
                                                     inputs[root / entry] if copied else published[root / entry])
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_messages:
                                clock.now.return_value = datetime(2026, 10, 15, 12, 34, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            check(disk, disk_messages.getvalue(), ['source-child', 'filtered'])
                            self.assertEqual(disk, {path: text for path, text in outputs.items()
                                                    if path.parent.name in {'source-child', 'filtered'}})
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
