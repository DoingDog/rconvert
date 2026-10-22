import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
