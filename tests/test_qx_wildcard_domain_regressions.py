import contextlib
import io
import json
import tempfile
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist
from tests.test_target_field_integration import TargetFieldTests


class QxWildcardDomainTests(TargetFieldTests):
    def test_native_repeated_root_dots_skip_qx_and_keep_yaml_and_neighbor(self):
        for value in ('*..', '..', '*123..', 'a...'):
            with self.subTest(value=value):
                parsed = self.parsed('payload:\n  - DOMAIN-WILDCARD,' + value + '\n'
                                     'DOMAIN,neighbor.example.org\n', purpose='block')
                rules = normalize(parsed)
                self.assertIn(Rule('DOMAIN-WILDCARD', value, domain_source='mihomo'), rules)
                outputs, diagnostics = render('dots', rules, purpose='block', no_resolve='keep')
                self.assertEqual(outputs['fin-qx.txt'], '# dots rules: 1\nHOST,neighbor.example.org,LIST\n')
                self.assertEqual(diagnostics, {name + ':DOMAIN-WILDCARD': 1 for name in
                                              ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt',
                                               'fin-qx.txt', 'fin-adb.txt')})
                self.assertEqual(self.yaml_body(outputs), ['DOMAIN,neighbor.example.org',
                                                          'DOMAIN-WILDCARD,' + value])
                self.assertEqual(parse(outputs['fin.yaml'], purpose='block'),
                                 ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'),
                                   Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')], []))

    def fixture(self, root, role):
        (root / 'static').mkdir()
        inputs = {
            root / 'static/pattern.yaml': b'payload:\n  - DOMAIN-WILDCARD,*..\nDOMAIN,neighbor.example.org\n',
            root / 'static/consumer.yaml': b'payload:\n  - DOMAIN-WILDCARD,*..\n'
                                           b'HOST,neighbor.example.org,LIST\nHOST,keep.example.org,LIST\n',
            root / 'static/untouched.bin': b'untouched\x00\xff\r\n',
        }
        for path, data in inputs.items():
            path.write_bytes(data)
        parent = dict(name='parent', purpose='block', no_resolve='keep',
                      sources=['static/pattern.yaml'], whitelist=[])
        child = dict(name='child', purpose='block', no_resolve='keep',
                     sources=['parent/fin-qx.txt'] if role == 'source' else ['static/consumer.yaml'],
                     whitelist=['parent/fin-qx.txt'] if role == 'white' else [])
        old = {}
        for group in ('parent', 'child'):
            (root / group).mkdir()
            for name in FILES:
                path = root / group / name
                old[path] = b'old complete output\x00\xff\r\n' + name.encode('ascii')
                path.write_bytes(old[path])
        return parent, child, inputs, old

    def assert_child(self, root, role, outputs):
        value = 'neighbor.example.org' if role == 'source' else 'keep.example.org'
        self.assertEqual(outputs[root / 'child/fin-qx.txt'], '# child rules: 1\nHOST,' + value + ',LIST\n')
        self.assertEqual(outputs[root / 'child/fin.yaml'],
                         '# child rules: 1\npayload:\n  - "DOMAIN,neighbor.example.org"\n' if role == 'source' else
                         '# child rules: 2\npayload:\n  - "DOMAIN,keep.example.org"\n  - "DOMAIN-WILDCARD,*.."\n')

    def test_same_round_qx_source_and_white_publish_only_representable_rules(self):
        for role in ('source', 'white'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent, child, inputs, old = self.fixture(root, role)
                config = root / 'rulesets.json'
                config.write_text(json.dumps([parent, child]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as log:
                    outputs = generate(root, self.fail)
                self.assertEqual(set(outputs), set(old))
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                self.assertNotIn(': line ', log.getvalue())
                self.assertNotIn('frozen', log.getvalue())
                self.assertIn('parent fin-qx.txt:DOMAIN-WILDCARD: 1\n', log.getvalue())
                self.assertEqual(outputs[root / 'parent/fin-qx.txt'],
                                 '# parent rules: 1\nHOST,neighbor.example.org,LIST\n')
                self.assert_child(root, role, outputs)
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in old},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                qx = (root / 'parent/fin-qx.txt').read_bytes().decode('utf-8')
                expected = [Rule('DOMAIN', 'neighbor.example.org', domain_source='qx')]
                self.assertEqual(parse(qx, purpose='block'), (expected, []))
                self.assertEqual(parse_whitelist(qx), expected)
                if role == 'white':
                    published = {path: path.read_bytes() for path in old}
                    config.write_text(json.dumps([dict(child, whitelist=['static/pattern.yaml'])]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        direct = generate(root, self.fail)
                    self.assertEqual(direct[root / 'child/fin.yaml'],
                                     '# child rules: 1\npayload:\n  - "DOMAIN,keep.example.org"\n')
                    self.assertEqual({path: path.read_bytes() for path in old}, published)
                    publish(direct, root=root)
                    self.assertEqual({path: path.read_bytes() for path in direct},
                                     {path: text.encode('utf-8') for path, text in direct.items()})
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_disk_only_qx_source_and_white_read_published_nonempty_subset(self):
        for role in ('source', 'white'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent, child, inputs, old = self.fixture(root, role)
                config = root / 'rulesets.json'
                config.write_text(json.dumps([parent]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()):
                    publish(generate(root, self.fail), root=root)
                published = {path: path.read_bytes() for path in old}
                config.write_text(json.dumps([child]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as log:
                    outputs = generate(root, self.fail)
                self.assertNotIn('invalid domain', log.getvalue())
                self.assertNotIn('frozen', log.getvalue())
                self.assertEqual(set(outputs), {root / 'child' / name for name in FILES})
                self.assertEqual({path: path.read_bytes() for path in old}, published)
                self.assert_child(root, role, outputs)
                qx = (root / 'parent/fin-qx.txt').read_bytes().decode('utf-8')
                self.assertEqual(qx, '# parent rules: 1\nHOST,neighbor.example.org,LIST\n')
                expected = [Rule('DOMAIN', 'neighbor.example.org', domain_source='qx')]
                self.assertEqual(parse(qx, purpose='block'), (expected, []))
                self.assertEqual(parse_whitelist(qx), expected)
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual({path: path.read_bytes() for path in published if path.parent.name == 'parent'},
                                 {path: data for path, data in published.items() if path.parent.name == 'parent'})
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
