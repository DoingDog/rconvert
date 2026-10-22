import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from formats import FILES
from generate import generate, publish
from tests.test_generate import r25_old_files


class StaticDescendantAliasTests(unittest.TestCase):
    def test_generate_rejects_physical_static_directory_target_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            previous = r25_old_files(root, ('healthy', 'sample'))
            (root / 'static').mkdir()
            alias = root / 'static/main'
            alias.symlink_to('../sample', target_is_directory=True)
            configs = [dict(name=group, purpose='block', no_resolve='keep',
                            sources=['https://example.org/rules'], whitelist=[])
                       for group in ('healthy', 'sample')]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                generate(root, lambda url: self.fail('preflight must precede fetch: ' + url))
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertEqual(alias.readlink(), Path('../sample'))
            self.assertFalse((root / '.tmp').exists())

    def test_publish_protects_exact_static_file_target_and_allows_siblings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            previous = r25_old_files(root, ('healthy', 'sample'))
            (root / 'static').mkdir()
            alias = root / 'static/white.list'
            alias.symlink_to('../sample/fin.txt')
            target = root / 'sample/fin.txt'
            new = root / 'new-group/fin.txt'
            with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                publish({new: 'new group\n', root / 'healthy/fin.txt': 'healthy\n',
                         target: 'replacement\n'}, root=root)
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertFalse(new.parent.exists())
            self.assertFalse((root / '.tmp').exists())
            sibling = root / 'sample/fin-qx.txt'
            publish({sibling: 'sibling\n'}, root=root)
            self.assertEqual(sibling.read_bytes(), b'sibling\n')
            self.assertEqual(target.read_bytes(), previous[target])
            self.assertEqual(alias.readlink(), Path('../sample/fin.txt'))

    def test_publish_rejects_directory_subtrees_through_physical_and_other_aliases(self):
        for entry in ('sample/fin.txt', 'sample/deep/fin.txt', 'relay/deep/fin.txt'):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                previous = r25_old_files(root, ('healthy', 'sample'))
                (root / 'static').mkdir()
                (root / 'sample/deep').mkdir()
                deep = root / 'sample/deep/fin.txt'
                previous[deep] = b'maintained deep\r\n\x00\xff'
                deep.write_bytes(previous[deep])
                links = {root / 'static/main': Path('../sample'), root / 'relay': Path('sample')}
                for alias, target in links.items():
                    alias.symlink_to(target, target_is_directory=True)
                new = root / 'new-group/fin.txt'
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({new: 'new\n', root / 'healthy/fin.txt': 'healthy\n',
                             root / entry: 'replacement\n'}, root=root)
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                self.assertEqual({path: path.readlink() for path in links}, links)
                self.assertFalse(new.parent.exists())
                self.assertFalse((root / '.tmp').exists())

    def test_generate_rejects_each_physical_static_file_target(self):
        for name in FILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                previous = r25_old_files(root, ('healthy', 'sample'))
                (root / 'static').mkdir()
                alias = root / 'static/input.list'
                alias.symlink_to('../sample/' + name)
                configs = [dict(name=group, purpose='block', no_resolve='keep',
                                sources=['https://example.org/rules'], whitelist=[])
                           for group in ('healthy', 'sample')]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    generate(root, lambda url: self.fail('preflight must precede fetch: ' + url))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                self.assertEqual(alias.readlink(), Path('../sample/' + name))
                self.assertFalse((root / '.tmp').exists())

    def test_publish_rejects_physical_and_aliased_static_staging(self):
        for aliased in (False, True):
            with self.subTest(aliased=aliased), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                previous = r25_old_files(root, ('healthy',))
                (root / 'static').mkdir()
                staging = root / ('cache' if aliased else '.tmp')
                staging.mkdir()
                marker = staging / 'input.list'
                previous[marker] = b'maintained staging\r\n'
                marker.write_bytes(previous[marker])
                links = {root / 'static/main': Path('../cache' if aliased else '../.tmp')}
                if aliased:
                    links[root / '.tmp'] = Path('cache')
                for alias, target in links.items():
                    alias.symlink_to(target, target_is_directory=True)
                new = root / 'new-group/fin.txt'
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({new: 'new\n', root / 'healthy/fin.txt': 'healthy\n'}, root=root)
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                self.assertEqual(set(staging.iterdir()), {marker})
                self.assertEqual({path: path.readlink() for path in links}, links)
                self.assertFalse(new.parent.exists())

    def test_nested_static_targets_and_directory_cycles_terminate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            previous = r25_old_files(root, ('healthy', 'sample'))
            for name in ('static', 'storage', 'archive'):
                (root / name).mkdir()
            links = {root / 'static/main': Path('../storage'),
                     root / 'static/duplicate': Path('../storage'),
                     root / 'storage/back': Path('../static'),
                     root / 'storage/deep': Path('../archive'),
                     root / 'archive/input.list': Path('../sample/fin.txt')}
            for alias, target in links.items():
                alias.symlink_to(target, target_is_directory=alias.name != 'input.list')
            code = '''
import sys
from pathlib import Path
from generate import publish
root = Path(sys.argv[1])
try:
    publish({root / 'healthy/fin.txt': 'changed\\n', root / 'sample/fin.txt': 'changed\\n'}, root=root)
except ValueError as exc:
    assert str(exc) == 'Output path targets static', exc
else:
    raise AssertionError('nested file target was accepted')
publish({root / 'new-group/fin.txt': 'allowed\\n'}, root=root)
'''
            result = subprocess.run([sys.executable, '-B', '-c', code, str(root)],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'new-group/fin.txt').read_bytes(), b'allowed\n')
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertEqual({path: path.readlink() for path in links}, links)

    def test_calls_refresh_static_targets_and_allow_same_directory_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'static').mkdir()
            (root / 'sample').mkdir()
            source = root / 'sample/input.list'
            alias = root / 'static/source.list'
            alias.symlink_to('../sample/input.list')
            config = dict(name='sample', purpose='block', no_resolve='keep',
                          sources=['static/source.list'], whitelist=[])
            (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
            for data, expected in ((b'DOMAIN,first.example.org\n', '# sample rules: 1\nDOMAIN,first.example.org\n'),
                                   (b'\xef\xbb\xbf# edited\r\nDOMAIN,edited.example.org\r\n',
                                    '# sample rules: 1\nDOMAIN,edited.example.org\n')):
                source.write_bytes(data)
                outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(outputs[root / 'sample/fin.txt'], expected)
                self.assertEqual(set(outputs), {root / 'sample' / name for name in FILES})
                visible = root / 'static/main'
                visible.symlink_to('../sample', target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish(outputs, root=root)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    generate(root, lambda url: self.fail(url))
                visible.unlink()
                publish(outputs, root=root)
                self.assertEqual({path: path.read_bytes() for path in outputs},
                                 {path: text.encode('utf-8') for path, text in outputs.items()})
                self.assertEqual(source.read_bytes(), data)
                self.assertEqual(alias.readlink(), Path('../sample/input.list'))


class DomainSetFileAliasTests(unittest.TestCase):
    def test_same_round_source_uses_generated_domain_set_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            previous = r25_old_files(root, ('parent', 'child'))
            (root / 'storage').mkdir()
            alias = root / 'parent/fin-surge-ds.txt'
            alias.unlink()
            previous.pop(alias)
            alias.symlink_to('../storage/saved-output.list')
            target = root / 'storage/saved-output.list'
            previous[target] = b'# stale\nold.example.org\n'
            target.write_bytes(previous[target])
            (root / 'input.list').write_bytes(b'DOMAIN,localhost\n')
            configs = [dict(name=group, purpose='block', no_resolve='keep',
                            sources=[source], whitelist=[])
                       for group, source in (('parent', 'input.list'),
                                             ('child', 'parent/fin-surge-ds.txt'))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()) as messages:
                outputs = generate(root, lambda url: self.fail(url))
            self.assertEqual(messages.getvalue(), '')
            self.assertEqual(outputs[target], '# parent rules: 1\nlocalhost\n')
            self.assertEqual(outputs[root / 'child/fin.txt'], '# child rules: 1\nDOMAIN,localhost\n')
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            publish(outputs, root=root)
            self.assertEqual({path: path.read_bytes() for path in outputs},
                             {path: text.encode('utf-8') for path, text in outputs.items()})
            self.assertEqual(alias.readlink(), Path('../storage/saved-output.list'))

    def test_disk_only_source_keeps_explicit_domain_set_entry_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'parent').mkdir()
            (root / 'storage').mkdir()
            alias = root / 'parent/fin-surge-ds.txt'
            alias.symlink_to('../storage/saved-output.list')
            (root / 'input.list').write_bytes(b'DOMAIN,localhost\n')
            parent = dict(name='parent', purpose='block', no_resolve='keep',
                          sources=['input.list'], whitelist=[])
            child = dict(name='child', purpose='block', no_resolve='keep',
                         sources=['parent/fin-surge-ds.txt'], whitelist=[])
            (root / 'rulesets.json').write_text(json.dumps([parent]), encoding='utf-8')
            outputs = generate(root, lambda url: self.fail(url))
            publish(outputs, root=root)
            published = {path: path.read_bytes() for path in outputs}
            (root / 'input.list').unlink()
            (root / 'rulesets.json').write_text(json.dumps([child]), encoding='utf-8')
            disk = generate(root, lambda url: self.fail(url))
            self.assertEqual(disk[root / 'child/fin.txt'], '# child rules: 1\nDOMAIN,localhost\n')
            publish(disk, root=root)
            self.assertEqual({path: path.read_bytes() for path in published}, published)
            self.assertEqual(alias.readlink(), Path('../storage/saved-output.list'))

    def test_whitelist_alias_context_is_not_shared_with_plain_entries(self):
        for entries in (['parent/fin-surge-ds.txt', 'storage/saved-output.list'],
                        ['storage/saved-output.list', 'parent/fin-surge-ds.txt']):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                previous = r25_old_files(root, ('child',))
                (root / 'parent').mkdir()
                (root / 'storage').mkdir()
                alias = root / 'parent/fin-surge-ds.txt'
                alias.symlink_to('../storage/saved-output.list')
                target = root / 'storage/saved-output.list'
                target.write_bytes(b'# parent rules: 1\nlocalhost\n')
                (root / 'input.list').write_bytes(b'DOMAIN,localhost\nDOMAIN,keep.example.org\n')
                config = dict(name='child', purpose='block', no_resolve='keep',
                              sources=['input.list'], whitelist=entries)
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'Invalid whitelist .*line 2: invalid rule'):
                    publish(generate(root, lambda url: self.fail(url)), root=root)
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                self.assertEqual(target.read_bytes(), b'# parent rules: 1\nlocalhost\n')
                self.assertEqual(alias.readlink(), Path('../storage/saved-output.list'))
                self.assertFalse((root / '.tmp').exists())

    @patch('formats.datetime')
    def test_single_labels_alias_source_and_whitelist_same_round_and_disk_matrix(self, clock):
        clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for label in ('localhost', 'x', '123'):
                    for destination in ('saved-output.list', 'fin.yaml'):
                        with self.subTest(purpose=purpose, mode=mode, label=label, destination=destination), \
                                tempfile.TemporaryDirectory() as directory:
                            root = Path(directory).resolve()
                            previous = r25_old_files(root, ('parent', 'source', 'white'))
                            (root / 'storage').mkdir()
                            alias = root / 'parent/fin-surge-ds.txt'
                            alias.unlink()
                            previous.pop(alias)
                            alias.symlink_to('../storage/' + destination)
                            uppercase = root / 'parent/FIN-SURGE-DS.TXT'
                            uppercase.symlink_to('../storage/' + destination)
                            target = root / 'storage' / destination
                            previous[target] = b'# stale\nold.example.org\n'
                            target.write_bytes(previous[target])
                            original = ('DOMAIN,' + label + '\n').encode('ascii')
                            routes = ('DOMAIN,' + label + '\nDOMAIN,child.' + label + '\n').encode('ascii')
                            (root / 'input.list').write_bytes(original)
                            (root / 'routes.list').write_bytes(routes)
                            configs = [dict(name=group, purpose=purpose, no_resolve=mode,
                                            sources=sources, whitelist=white)
                                       for group, sources, white in (
                                           ('parent', ['input.list'], []),
                                           ('source', ['storage/' + destination], []),
                                           ('white', ['routes.list'], ['storage/' + destination]))]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual(set(outputs), set(previous))
                            self.assertEqual(outputs[target], '# parent rules: 1\n' + label + '\n')
                            source_body = {
                                'fin.txt': ['DOMAIN,' + label],
                                'fin-qx.txt': ['HOST,' + label + ',LIST'],
                                'fin.yaml': ['  - "DOMAIN,' + label + '"'],
                                'fin-adb.txt': ['0.0.0.0 ' + label] if purpose == 'block' else
                                               ['! No AdBlock rules for non-advertising group.'],
                                'fin-surge.txt': [], 'fin-surge-ds.txt': [label],
                            }
                            white_body = {
                                'fin.txt': ['DOMAIN,child.' + label],
                                'fin-qx.txt': ['HOST,child.' + label + ',LIST'],
                                'fin.yaml': ['  - "DOMAIN,child.' + label + '"'],
                                'fin-adb.txt': ['@@|' + label + '|', '0.0.0.0 child.' + label]
                                               if purpose == 'block' else
                                               ['! No AdBlock rules for non-advertising group.'],
                                'fin-surge.txt': [], 'fin-surge-ds.txt': ['child.' + label],
                            }
                            for group, bodies in (('source', source_body), ('white', white_body)):
                                for name, body in bodies.items():
                                    text = outputs[root / group / name]
                                    self.assertEqual(text.splitlines()[7 if name == 'fin-adb.txt' else
                                                                      2 if name == 'fin.yaml' else 1:], body)
                                    self.assertTrue(text.endswith('\n'))
                            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                            publish(outputs, root=root)
                            published = {path: text.encode('utf-8') for path, text in outputs.items()}
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            (root / 'input.list').unlink()
                            configs = configs[1:]
                            configs[0]['sources'] = [r'parent\.\fin-surge-ds.txt']
                            configs[1]['whitelist'] = [r'parent\.\FIN-SURGE-DS.TXT']
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: self.fail(url))
                            expected = {path: text for path, text in outputs.items()
                                        if path.parent.name in ('source', 'white')}
                            self.assertEqual(disk, expected)
                            publish(disk, root=root)
                            self.assertEqual(target.read_bytes(), published[target])
                            self.assertEqual(alias.readlink(), Path('../storage/' + destination))
                            self.assertEqual(uppercase.readlink(), Path('../storage/' + destination))
                            self.assertEqual((root / 'routes.list').read_bytes(), routes)

    def test_single_domain_set_whitelist_alias_uses_new_bytes_and_disk_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'parent').mkdir()
            (root / 'storage').mkdir()
            alias = root / 'parent/fin-surge-ds.txt'
            alias.symlink_to('../storage/fin.yaml')
            (root / 'storage/fin.yaml').write_bytes(b'# stale\nchild.localhost\n')
            (root / 'input.list').write_bytes(b'DOMAIN,localhost\n')
            routes = b'DOMAIN,localhost\nDOMAIN,child.localhost\nDOMAIN-SUFFIX,localhost\n'
            (root / 'routes.list').write_bytes(routes)
            configs = [dict(name='parent', purpose='block', no_resolve='keep',
                            sources=['input.list'], whitelist=[]),
                       dict(name='child', purpose='block', no_resolve='keep',
                            sources=['routes.list'], whitelist=['parent/fin-surge-ds.txt'])]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda url: self.fail(url))
            expected = '# child rules: 1\nDOMAIN-SUFFIX,localhost\n'
            self.assertEqual(outputs[root / 'child/fin.txt'], expected)
            self.assertIn('@@|localhost|\n', outputs[root / 'child/fin-adb.txt'])
            publish(outputs, root=root)
            (root / 'input.list').unlink()
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                disk = generate(root, lambda url: self.fail(url))
            self.assertEqual(disk[root / 'child/fin.txt'], expected)
            self.assertIn('@@|localhost|\n', disk[root / 'child/fin-adb.txt'])
            self.assertEqual((root / 'storage/fin.yaml').read_bytes(), b'# parent rules: 1\nlocalhost\n')
            self.assertEqual((root / 'routes.list').read_bytes(), routes)
            self.assertEqual(alias.readlink(), Path('../storage/fin.yaml'))

    def test_generated_format_precedes_entry_and_target_domain_set_names(self):
        for entry in ('parent/fin.yaml', 'storage/fin-surge-ds.txt'):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / 'parent').mkdir()
                (root / 'storage').mkdir()
                alias = root / 'parent/fin.yaml'
                alias.symlink_to('../storage/fin-surge-ds.txt')
                (root / 'input.list').write_bytes(b'DOMAIN,localhost\n')
                configs = [dict(name=group, purpose='block', no_resolve='keep',
                                sources=[source], whitelist=[])
                           for group, source in (('parent', 'input.list'), ('child', entry))]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(outputs[root / 'storage/fin-surge-ds.txt'],
                                 '# parent rules: 1\npayload:\n  - "DOMAIN,localhost"\n')
                self.assertEqual(outputs[root / 'child/fin.txt'], '# child rules: 0\n')
                self.assertEqual(outputs[root / 'child/fin-surge-ds.txt'], '# child rules: 0\n')
                self.assertEqual(outputs[root / 'child/fin.yaml'],
                                 '# child rules: 1\npayload:\n  - "DOMAIN,localhost"\n')
                publish(outputs, root=root)
                self.assertEqual(alias.readlink(), Path('../storage/fin-surge-ds.txt'))

    def test_domain_set_alias_preserves_multilabel_suffix_and_ipv4_shaped_domains(self):
        for destination in ('saved-output.list', 'fin.yaml'):
            with self.subTest(destination=destination), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / 'parent').mkdir()
                (root / 'storage').mkdir()
                alias = root / 'parent/fin-surge-ds.txt'
                alias.symlink_to('../storage/' + destination)
                (root / 'input.list').write_bytes(b'DOMAIN,01.2.3.4\nDOMAIN,256.1.1.1\n'
                                                  b'DOMAIN,example.org\nDOMAIN-SUFFIX,local\n')
                configs = [dict(name=group, purpose='block', no_resolve='keep',
                                sources=[source], whitelist=[])
                           for group, source in (('parent', 'input.list'),
                                                 ('child', 'parent/fin-surge-ds.txt'))]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                outputs = generate(root, lambda url: self.fail(url))
                expected = '# child rules: 4\nDOMAIN,01.2.3.4\nDOMAIN,256.1.1.1\nDOMAIN,example.org\nDOMAIN-SUFFIX,local\n'
                self.assertEqual(outputs[root / 'child/fin.txt'], expected)
                self.assertEqual(outputs[root / 'child/fin-surge-ds.txt'],
                                 '# child rules: 4\n.local\n01.2.3.4\n256.1.1.1\nexample.org\n')
                publish(outputs, root=root)
                target_bytes = (root / 'storage' / destination).read_bytes()
                (root / 'input.list').unlink()
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                disk = generate(root, lambda url: self.fail(url))
                self.assertEqual(disk[root / 'child/fin.txt'], expected)
                self.assertEqual((root / 'storage' / destination).read_bytes(), target_bytes)
                self.assertEqual(alias.readlink(), Path('../storage/' + destination))

    def test_disk_context_keeps_resolved_name_and_uppercase_explicit_entry(self):
        for resolved in (False, True):
            with self.subTest(resolved=resolved), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (root / 'storage').mkdir()
                target = root / 'storage' / ('FIN-SURGE-DS.TXT' if resolved else 'saved-output.list')
                target.write_bytes(b'# maintained\nlocalhost\n')
                alias = root / ('source.list' if resolved else 'FIN-SURGE-DS.TXT')
                alias.symlink_to(target.relative_to(root))
                config = dict(name='child', purpose='block', no_resolve='keep',
                              sources=[alias.name], whitelist=[])
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(outputs[root / 'child/fin.txt'], '# child rules: 1\nDOMAIN,localhost\n')
                publish(outputs, root=root)
                self.assertEqual(target.read_bytes(), b'# maintained\nlocalhost\n')
                self.assertTrue(alias.is_symlink())

    def test_plain_single_labels_true_ips_and_empty_disk_aliases_remain_strict(self):
        for body, explicit in ((b'localhost\n', False), (b'x\n', False), (b'123\n', False),
                               (b'192.0.2.1\n', True), (b'# empty\n', True)):
            for whitelist in (False, True):
                with self.subTest(body=body, explicit=explicit, whitelist=whitelist), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    previous = r25_old_files(root, ('child',))
                    (root / 'storage').mkdir()
                    target = root / 'storage/saved-output.list'
                    target.write_bytes(body)
                    alias = root / ('fin-surge-ds.txt' if explicit else 'source.list')
                    alias.symlink_to('storage/saved-output.list')
                    (root / 'input.list').write_bytes(b'DOMAIN,keep.example.org\n')
                    config = dict(name='child', purpose='block', no_resolve='keep',
                                  sources=['input.list'] if whitelist else [alias.name],
                                  whitelist=[alias.name] if whitelist else [])
                    (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(
                            ValueError, 'Invalid whitelist' if whitelist else 'No adaptable rules'):
                        publish(generate(root, lambda url: self.fail(url)), root=root)
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    self.assertEqual(target.read_bytes(), body)
                    self.assertTrue(alias.is_symlink())
                    self.assertFalse((root / '.tmp').exists())
