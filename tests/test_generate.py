import contextlib
import gzip
import hashlib
import io
import json
from datetime import datetime, timedelta, timezone
from http.client import IncompleteRead
import os
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib import error, request

from generate import fetch_https, generate, publish
from tests.test_formats import (expected_domain, expected_ordinary_payload, expected_ordinary_text,
                                generated_payload, generated_text, generated_texts)


ROOT = Path(__file__).resolve().parents[1]
GROUPS = ("cdn", "a3", "big-data", "dirt")
NAMES = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")


def configure_groups(root, sources=None, whitelist=None):
    sources = sources or {}
    whitelist = whitelist or {}
    (root / "rulesets.json").write_text(json.dumps([
        {"name": group, "purpose": "block" if group == "a3" else
         "direct" if group == "dirt" else "proxy",
         "no_resolve": "strip" if group == "dirt" else "add",
         "sources": sources.get(group, [f"{group}/rules.txt"]),
         "whitelist": whitelist.get(group, [])}
        for group in GROUPS
    ]), encoding="utf-8")
    for group in GROUPS:
        (root / group).mkdir(exist_ok=True)


class NativeArityGenerateTests(unittest.TestCase):
    def test_native_arity_preserves_six_dependencies_publish_and_disk_for_nine_options(self):
        from tests.test_formats import native_arity_products

        for purpose in ('block', 'proxy', 'direct'):
            for mode in ('add', 'strip', 'keep'):
                flag = '' if mode == 'strip' else ',no-resolve'
                matchers = ['AND,()', 'AND,((DOMAIN,x.example.com))',
                            f'AND,((IP-CIDR,203.0.113.0/24{flag}))',
                            'DOMAIN,keep.example.com', 'NOT,((OR,()))', 'OR,()',
                            'OR,((DOMAIN,x.example.com))']
                for dependency in NAMES:
                    with self.subTest(purpose=purpose, mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.yaml'], 'whitelist': []},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['parent/' + dependency], 'whitelist': []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        source = ['AND,()', 'OR,()', 'AND,((DOMAIN,x.example.com))',
                                  'OR,((DOMAIN,x.example.com))', 'NOT,((OR,()))',
                                  'AND,((IP-CIDR,203.0.113.7/24,no-resolve,no-resolve))',
                                  'DOMAIN,keep.example.com']
                        (root / 'input.yaml').write_text('payload:\n' + ''.join('  - ' + json.dumps(item) + '\n' for item in source), encoding='utf-8')
                        old = {}
                        for group in ('parent', 'child'):
                            (root / group).mkdir()
                            for name in NAMES:
                                path = root / group / name
                                old[path] = b'old\r\ncomplete\x00' + name.encode('ascii')
                                path.write_bytes(old[path])
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        parent = native_arity_products('parent', matchers, purpose, domain_source='mihomo')
                        empty = dependency == 'fin-surge.txt' or dependency == 'fin-adb.txt' and purpose != 'block'
                        child_matchers = matchers if dependency == 'fin.yaml' else ['DOMAIN,keep.example.com']
                        child = native_arity_products('child', child_matchers, purpose,
                                                      domain_source='mihomo' if dependency == 'fin.yaml' else
                                                      'qx' if dependency == 'fin-qx.txt' else 'surge')
                        if empty:
                            child = {name: '# child rules: 0\n' for name in NAMES}
                            child['fin.yaml'] += 'payload:\n'
                            child['fin-adb.txt'] = native_arity_products('child', [], purpose)['fin-adb.txt'].replace(
                                '! Total count: 1\n0.0.0.0 keep.example.com\n', '! Total count: 0\n')
                        expected = {root / 'parent' / name: text for name, text in parent.items()}
                        expected.update({root / 'child' / name: text for name, text in child.items()})
                        self.assertEqual(outputs, expected)
                        skips = {f'{name}:{kind}': count for name in
                                 ('fin.txt', 'fin-qx.txt', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
                                 for kind, count in (('AND', 3), ('NOT', 1), ('OR', 2))}
                        if purpose != 'block':
                            skips['fin-adb.txt:DOMAIN'] = 1
                        child_skips = skips if dependency == 'fin.yaml' else (
                            {'fin-adb.txt:DOMAIN': 1} if not empty and purpose != 'block' else {})
                        source_warnings = (''.join(f'{root / "parent" / dependency}: line {number}: invalid rule\n'
                                                  for number in range(1, 6)) +
                                           f'{root / "parent" / dependency}: {7 if purpose == "block" else 8} skipped lines; first five shown\n'
                                           if dependency == 'fin-adb.txt' else '')
                        self.assertEqual(stderr.getvalue(),
                                         ''.join(f'parent {key}: {count}\n' for key, count in sorted(skips.items())) +
                                         source_warnings +
                                         ''.join(f'child {key}: {count}\n' for key, count in sorted(child_skips.items())))
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in expected.items()})
                        published = {path: path.read_bytes() for path in outputs}
                        (root / 'input.yaml').unlink()
                        (root / 'rulesets.json').unlink()
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            if empty:
                                with self.assertRaisesRegex(ValueError, 'No adaptable rules in '):
                                    generate(root, lambda url: self.fail(url))
                            else:
                                disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk_stderr.getvalue(), source_warnings +
                                         ('' if empty else ''.join(f'child {key}: {count}\n' for key, count in sorted(child_skips.items()))))
                        if empty:
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            continue
                        self.assertEqual(disk, {root / 'child' / name: text for name, text in child.items()})
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in disk}, {path: text.encode('utf-8') for path, text in disk.items()})

    def test_invalid_native_not_wrapper_is_not_published_or_reimported(self):
        from tests.test_formats import native_arity_products

        for child in ('OR,()', 'AND,()'):
            for purpose in ('block', 'proxy', 'direct'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(child=child, purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.yaml'], 'whitelist': []},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['parent/fin.yaml'], 'whitelist': []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        invalid = 'NOT,(' + child + ')'
                        (root / 'input.yaml').write_text('payload:\n  - ' + invalid + '\n  - DOMAIN,keep.example.com\n', encoding='utf-8')
                        old = {}
                        for group in ('parent', 'child'):
                            (root / group).mkdir()
                            for name in NAMES:
                                path = root / group / name
                                old[path] = b'old complete\r\n\x00' + name.encode('ascii')
                                path.write_bytes(old[path])
                        skips = ''.join(f'{group} fin-adb.txt:DOMAIN: 1\n' for group in ('parent', 'child')) if purpose != 'block' else ''
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as messages:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(messages.getvalue(), f'{root / "input.yaml"}: line 2: invalid logical expression ({child})\n' + skips)
                        expected = {root / group / name: text for group in ('parent', 'child')
                                    for name, text in native_arity_products(group, ['DOMAIN,keep.example.com'], purpose, domain_source='mihomo').items()}
                        self.assertEqual(outputs, expected)
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs)
                        published = {path: text.encode('utf-8') for path, text in expected.items()}
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        (root / 'input.yaml').unlink()
                        (root / 'rulesets.json').unlink()
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_messages:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name == 'child'})
                        self.assertEqual(disk_messages.getvalue(), 'child fin-adb.txt:DOMAIN: 1\n' if purpose != 'block' else '')
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        (root / 'input.yaml').write_text('payload:\n  - ' + invalid + '\n', encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as rejected:
                            with self.assertRaisesRegex(ValueError, 'No adaptable rules in '):
                                generate(root, lambda url: self.fail(url))
                        self.assertEqual(rejected.getvalue(), f'{root / "input.yaml"}: line 2: invalid logical expression ({child})\n')
                        self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_logical_generated_whitelist_rejection_preserves_all_old_bytes(self):
        from rules import GeneratedRuleError

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configs = [{'name': 'parent', 'purpose': 'block', 'no_resolve': 'keep', 'sources': ['input.yaml'], 'whitelist': []},
                       {'name': 'child', 'purpose': 'block', 'no_resolve': 'keep', 'sources': ['input.yaml'], 'whitelist': ['parent/fin.yaml']}]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'input.yaml').write_text('payload:\n  - AND,()\n  - DOMAIN,keep.example.com\n', encoding='utf-8')
            previous = {}
            for group in ('parent', 'child'):
                (root / group).mkdir()
                for name in NAMES:
                    path = root / group / name
                    previous[path] = b'old complete\r\n\x00' + name.encode('ascii')
                    path.write_bytes(previous[path])
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaisesRegex(GeneratedRuleError, r'Invalid whitelist .*fin.yaml: line 3: unsupported whitelist rule AND'):
                    generate(root, lambda url: self.fail(url))
            self.assertNotIn(': line ', stderr.getvalue())
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_deep_native_single_generation_publishes_complete_twelve_files_within_eight_seconds(self):
        for operator in ('AND', 'OR'):
            for depth in (600, 1000):
                with self.subTest(operator=operator, depth=depth):
                    code = f'''
import contextlib
import io
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from generate import generate, publish
from tests.test_formats import native_arity_products
limit = sys.getrecursionlimit()
with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
    root = Path(directory)
    for purpose in ('block', 'proxy', 'direct'):
        for mode in ('add', 'strip', 'keep'):
            flag = '' if mode == 'strip' else ',no-resolve'
            def chain(flag):
                condition = '(IP-CIDR,203.0.113.0/24' + flag + ')'
                for _ in range({depth}):
                    condition = '({operator},(' + condition + '))'
                return condition[1:-1]
            matcher = chain(flag)
            ordered = [matcher, 'DOMAIN,keep.example.com'] if '{operator}' == 'AND' else ['DOMAIN,keep.example.com', matcher]
            configs = [{{'name': 'parent', 'purpose': purpose, 'no_resolve': mode, 'sources': ['input.yaml'], 'whitelist': []}},
                       {{'name': 'child', 'purpose': purpose, 'no_resolve': mode, 'sources': ['parent/fin.yaml'], 'whitelist': []}}]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'input.yaml').write_text('payload:\\n  - ' + json.dumps(chain(',no-resolve')) + '\\n  - DOMAIN,keep.example.com\\n', encoding='utf-8')
            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as messages:
                clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                outputs = generate(root, lambda url: (_ for _ in ()).throw(AssertionError(url)))
            expected = {{root / group / name: text for group in ('parent', 'child')
                        for name, text in native_arity_products(group, ordered, purpose, domain_source='mihomo').items()}}
            assert outputs == expected
            assert ': line ' not in messages.getvalue() and 'frozen' not in messages.getvalue()
            publish(outputs)
            assert {{path: path.read_bytes() for path in outputs}} == {{path: text.encode('utf-8') for path, text in expected.items()}}
            (root / 'input.yaml').unlink()
            (root / 'rulesets.json').unlink()
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                disk = generate(root, lambda url: (_ for _ in ()).throw(AssertionError(url)))
            assert disk == {{root / 'child' / name: text for name, text in native_arity_products('child', ordered, purpose, domain_source='mihomo').items()}}
            publish(disk)
            assert all(path.read_bytes() == text.encode('utf-8') for path, text in disk.items())
assert sys.getrecursionlimit() == limit
'''
                    result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                            capture_output=True, text=True, timeout=8)
                    self.assertEqual(result.returncode, 0, result.stderr)


class DomainSetSingleLabelGenerateTests(unittest.TestCase):
    def assert_products(self, outputs, root, group, purpose, exact, suffix=(), whitelist=()):
        from rules import Rule, parse

        ordered = lambda lines: sorted(lines, key=lambda line: (line.partition(",")[0], len(line), line))
        typed = ordered([f"DOMAIN,{value}" for value in exact] + [f"DOMAIN-SUFFIX,{value}" for value in suffix])
        qx = ordered([f"HOST,{value},LIST" for value in exact] + [f"HOST-SUFFIX,{value},LIST" for value in suffix])
        ds = sorted([*exact, *("." + value for value in suffix)], key=lambda line: (len(line), line))
        dns = sorted([*("@@|" + value + "|" for value in whitelist),
                      *("0.0.0.0 " + value for value in exact), *("||" + value + "^" for value in suffix)],
                     key=lambda line: (not line.startswith("@@"), len(line), line)) if purpose == "block" else []
        yaml = []
        for kind, values in (("DOMAIN", exact), ("DOMAIN-SUFFIX", suffix)):
            for value in values:
                scalar = "  - " + json.dumps(expected_domain(kind, value))
                record = [[kind, value, [], False, False, False, "surge"]]
                yaml.append((scalar, record))
        yaml.sort(key=lambda entry: (len(entry[0]), entry[0]))
        yaml_body = [scalar + ' # rconvert-rule-v1 ' + json.dumps(record, separators=(',', ':'))
                     for scalar, record in yaml]
        bodies = {"fin.txt": typed, "fin-qx.txt": qx, "fin.yaml": yaml_body,
                  "fin-adb.txt": dns, "fin-surge.txt": [], "fin-surge-ds.txt": ds}
        for name, body in bodies.items():
            text = outputs[root / group / name]
            if name == "fin-adb.txt":
                lines = text.splitlines()
                self.assertEqual(lines[:5], ["[Adblock Plus 2.0]", f"! Title: {group}",
                    "! Homepage: https://github.com/DoingDog/rconvert", "! Expires: 1 day",
                    "! License: Inherits upstream licenses"])
                self.assertRegex(lines[5], r"^! Version: [0-9]{12}$")
                datetime.strptime(lines[5].removeprefix("! Version: "), "%Y%m%d%H%M")
                self.assertEqual(lines[6:], [f"! Total count: {len(body)}", *body] if purpose == "block" else
                                 ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                self.assertTrue(text.endswith("\n"))
                self.assertEqual(text, '\n'.join(["[Adblock Plus 2.0]", f"! Title: {group}",
                    "! Homepage: https://github.com/DoingDog/rconvert", "! Expires: 1 day",
                    "! License: Inherits upstream licenses", lines[5],
                    *([f"! Total count: {len(body)}", *body] if purpose == "block" else
                      ["! Total count: 0", "! No AdBlock rules for non-advertising group."])]) + '\n')
                continue
            header = f"# {group} rules: {len(body)}\n" + ("payload:\n" if name == "fin.yaml" else "")
            self.assertEqual(text, header + "".join(line + "\n" for line in body))
            expected = ([Rule("DOMAIN", value, domain_source="qx" if name == "fin-qx.txt" else "surge") for value in exact] +
                        [Rule("DOMAIN-SUFFIX", value, domain_source="qx" if name == "fin-qx.txt" else "surge") for value in suffix])
            parsed, messages = parse(text, purpose=purpose, domain_set=name == "fin-surge-ds.txt")
            self.assertEqual(set(parsed), set(expected) if name != "fin-surge.txt" else set())
            self.assertEqual(len(parsed), len(expected) if name != "fin-surge.txt" else 0)
            if name == "fin.yaml":
                self.assertEqual(parsed, [Rule(record[0][0], record[0][1]) for _, record in yaml])
                for line, (_, record) in zip(body, yaml):
                    generated_payload(line[4:], record)
            self.assertEqual(messages, [])

    def seed(self, root, groups):
        previous = {}
        for group in groups:
            (root / group).mkdir()
            for name in NAMES:
                path = root / group / name
                previous[path] = (group + "/" + name + " old\n").encode() + bytes(range(256))
                path.write_bytes(previous[path])
        return previous

    def test_all_labels_six_products_same_round_and_only_disk_matrix(self):
        from tests.test_rules import DOMAIN_SET_LABELS

        values = (*DOMAIN_SET_LABELS, "keep.example.org")
        source = "".join(f"DOMAIN,{value.upper()}.\n" for value in values)
        routes = source + "DOMAIN,child.localhost\nDOMAIN-SUFFIX,localhost\nDOMAIN,retained.example.net\n"
        for purpose in ("block", "direct", "proxy"):
            for mode in ("keep", "add", "strip"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": "parent", "purpose": purpose, "no_resolve": mode,
                                "sources": ["original.list"], "whitelist": []},
                               {"name": "source", "purpose": purpose, "no_resolve": mode,
                                "sources": ["parent/FIN-SURGE-DS.TXT"], "whitelist": []},
                               {"name": "white", "purpose": purpose, "no_resolve": mode,
                                "sources": ["routes.list"], "whitelist": ["parent/FIN-SURGE-DS.TXT"]},
                               {"name": "yaml-source", "purpose": purpose, "no_resolve": mode,
                                "sources": ["parent/fin.yaml"], "whitelist": []},
                               {"name": "yaml-white", "purpose": purpose, "no_resolve": mode,
                                "sources": ["routes.list"], "whitelist": ["parent/fin.yaml"]}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "original.list").write_text(source, encoding="utf-8")
                    (root / "routes.list").write_text(routes, encoding="utf-8")
                    previous = self.seed(root, ("parent", "source", "white", "yaml-source", "yaml-white"))
                    skips = [] if purpose == "block" else [
                        f"{group} fin-adb.txt:{kind}: {count}" for group, kind, count in
                        (("parent", "DOMAIN", len(values)), ("source", "DOMAIN", len(values)),
                         ("white", "DOMAIN", 1), ("white", "DOMAIN-SUFFIX", 1),
                         ("yaml-source", "DOMAIN", len(values)), ("yaml-white", "DOMAIN", 1),
                         ("yaml-white", "DOMAIN-SUFFIX", 1))]
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(stderr.getvalue().splitlines(), skips)
                    self.assertEqual(set(outputs), set(previous))
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    for group in ("parent", "source"):
                        self.assert_products(outputs, root, group, purpose, values)
                    self.assert_products(outputs, root, "white", purpose, ("retained.example.net",),
                                         ("localhost",), values)
                    self.assert_products(outputs, root, "yaml-source", purpose, values)
                    self.assert_products(outputs, root, "yaml-white", purpose, ("retained.example.net",),
                                         ("localhost",), values)
                    publish(outputs)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode("utf-8") for path, text in outputs.items()})
                    parent = {path: path.read_bytes() for path in outputs if path.parent.name == "parent"}
                    (root / "original.list").unlink()
                    (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                    for path in outputs:
                        if path.parent.name != "parent":
                            path.write_bytes(previous[path])
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk), {root / group / name for group in
                                                 ("source", "white", "yaml-source", "yaml-white") for name in NAMES})
                    self.assertEqual(disk_stderr.getvalue().splitlines(), [line for line in skips if not line.startswith("parent ")])
                    self.assert_products(disk, root, "source", purpose, values)
                    self.assert_products(disk, root, "white", purpose, ("retained.example.net",), ("localhost",), values)
                    self.assert_products(disk, root, "yaml-source", purpose, values)
                    self.assert_products(disk, root, "yaml-white", purpose, ("retained.example.net",), ("localhost",), values)
                    self.assertEqual({path: path.read_bytes() for path in disk}, {path: previous[path] for path in disk})
                    publish(disk)
                    self.assertEqual({path: path.read_bytes() for path in disk}, {path: text.encode() for path, text in disk.items()})
                    self.assertEqual({path: path.read_bytes() for path in parent}, parent)

    def test_https_path_context_and_default_source_boundary(self):
        urls = ("https://example.org/FIN-SURGE-DS.TXT?raw=1#data",
                "https://example.org/parent/%66in-surge-ds.txt",
                "https://example.org/fin.txt?name=fin-surge-ds.txt",
                "https://fin-surge-ds.txt.example.org/list.txt",
                "https://example.org/fin-surge-ds.txt.bak", "https://example.org/fin-surge-ds.txt/",
                "https://example.org/other%2Ffin-surge-ds.txt",
                "https://example.org/other%5Cfin-surge-ds.txt",
                "https://example.org/fin-surge-ds.txt/.")
        for url in urls:
            for whitelist in (False, True):
                with self.subTest(url=url, whitelist=whitelist), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    (root / "routes.list").write_text("DOMAIN,localhost\nDOMAIN,keep.example.org\nDOMAIN,child.localhost", encoding="utf-8")
                    (root / "rulesets.json").write_text(json.dumps([{"name": "group", "purpose": "block", "no_resolve": "keep",
                        "sources": ["routes.list"] if whitelist else [url], "whitelist": [url] if whitelist else []}]), encoding="utf-8")
                    expected_context = url in urls[:2]
                    calls = []
                    def fetch(source):
                        calls.append(source)
                        return b"# group rules: 2\nlocalhost\nkeep.example.org\n"
                    with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertWarnsRegex(UserWarning, r"^line 2: invalid rule$") if whitelist and not expected_context else contextlib.nullcontext():
                        outputs = generate(root, fetch)
                    self.assertEqual(calls, [url])
                    if whitelist:
                        self.assert_products(outputs, root, "group", "block",
                            ("child.localhost",) if expected_context else ("localhost", "child.localhost"),
                            whitelist=("localhost", "keep.example.org") if expected_context else ("keep.example.org",))
                        self.assertEqual(stderr.getvalue(), "")
                    else:
                        self.assert_products(outputs, root, "group", "block",
                                             ("localhost", "keep.example.org") if expected_context else ("keep.example.org",))
                        self.assertEqual(stderr.getvalue(), "" if expected_context else f"{url}: line 2: invalid rule\n")

    def test_resolved_disk_context_keeps_legal_neighbors_and_exact_warnings(self):
        for purpose in ("block", "direct", "proxy"):
            for whitelist in (False, True):
                with self.subTest(purpose=purpose, whitelist=whitelist), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    (root / "sub").mkdir()
                    source = root / "FIN-SURGE-DS.TXT"
                    source.write_text("# parent rules: 3\nLOCALHOST.\nbad-\nkeep.example.org\n", encoding="utf-8")
                    (root / "routes.list").write_text("DOMAIN,localhost\nDOMAIN,keep.example.org\nDOMAIN,child.localhost", encoding="utf-8")
                    (root / "rulesets.json").write_text(json.dumps([{"name": "group", "purpose": purpose, "no_resolve": "keep",
                        "sources": ["routes.list"] if whitelist else ["./sub/../FIN-SURGE-DS.TXT"],
                        "whitelist": ["./sub/../FIN-SURGE-DS.TXT"] if whitelist else []}]), encoding="utf-8")
                    previous = self.seed(root, ("group",))
                    warning_check = self.assertWarnsRegex(UserWarning, r"^line 3: invalid rule$") if whitelist else contextlib.nullcontext()
                    with contextlib.redirect_stderr(io.StringIO()) as stderr, warning_check:
                        outputs = generate(root, lambda url: self.fail(url))
                    expected_messages = [] if whitelist else [f"{source}: line 3: invalid rule"]
                    if purpose != "block":
                        expected_messages.append("group fin-adb.txt:DOMAIN: " + ("1" if whitelist else "2"))
                    self.assertEqual(stderr.getvalue().splitlines(), expected_messages)
                    self.assert_products(outputs, root, "group", purpose,
                        ("child.localhost",) if whitelist else ("localhost", "keep.example.org"),
                        whitelist=("localhost", "keep.example.org") if whitelist else ())
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    source_bytes = source.read_bytes()
                    publish(outputs)
                    self.assertEqual({path: path.read_bytes() for path in outputs}, {path: text.encode() for path, text in outputs.items()})
                    self.assertEqual(source.read_bytes(), source_bytes)

    def test_invalid_only_disk_source_and_whitelist_preserve_every_old_byte(self):
        for whitelist in (False, True):
            with self.subTest(whitelist=whitelist), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "fin-surge-ds.txt").write_text("# bad body\nbad-\n", encoding="utf-8")
                (root / "routes.list").write_text("DOMAIN,localhost\n", encoding="utf-8")
                (root / "rulesets.json").write_text(json.dumps([{"name": "group", "purpose": "block", "no_resolve": "keep",
                    "sources": ["routes.list"] if whitelist else ["fin-surge-ds.txt"], "whitelist": ["fin-surge-ds.txt"] if whitelist else []}]), encoding="utf-8")
                previous = self.seed(root, ("group",))
                with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaisesRegex(ValueError,
                        r"Invalid whitelist .*line 2: invalid rule" if whitelist else "No adaptable rules"):
                    publish(generate(root, lambda url: self.fail(url)))
                self.assertEqual(stderr.getvalue(), "" if whitelist else f"{root / 'fin-surge-ds.txt'}: line 2: invalid rule\n")
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_domain_set_named_marked_source_and_whitelist_errors_keep_binary_outputs(self):
        from rules import GeneratedRuleError

        marked = b'payload:\n  - "DOMAIN,localhost" # rconvert-rule-v1 [["DOMAIN","other.localhost",[],false,false,false,"mihomo"]]\n'
        for remote in (False, True):
            for whitelist in (False, True):
                for data in (marked, marked.replace(b'other.localhost', b'\xff'), b'<html>\n' + marked):
                    with self.subTest(remote=remote, whitelist=whitelist, data=data), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        source = "https://example.org/%66in-surge-ds.txt?raw=1" if remote else "FIN-SURGE-DS.TXT"
                        (root / "rulesets.json").write_text(json.dumps([{
                            "name": "child", "purpose": "block", "no_resolve": "keep",
                            "sources": ["neighbor.txt"] if whitelist else [source],
                            "whitelist": [source] if whitelist else []}]), encoding="utf-8")
                        (root / "neighbor.txt").write_text("DOMAIN,child.localhost\n", encoding="utf-8")
                        (root / "FIN-SURGE-DS.TXT").write_bytes(data)
                        previous = self.seed(root, ("child",))
                        calls = []
                        def fetch(url):
                            calls.append(url)
                            return data
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(GeneratedRuleError):
                            publish(generate(root, fetch))
                        self.assertEqual(stderr.getvalue(), "")
                        self.assertEqual(calls, [source] if remote else [])
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        self.assertEqual((root / "FIN-SURGE-DS.TXT").read_bytes(), data)

    def test_domain_set_generated_publish_failure_restores_all_bytes_and_new_directory(self):
        import os
        from unittest.mock import patch

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": name, "purpose": "block", "no_resolve": "keep",
                 "sources": ["fin-surge-ds.txt"], "whitelist": []} for name in ("old", "new")]), encoding="utf-8")
            (root / "fin-surge-ds.txt").write_bytes(b'\xef\xbb\xbf# source\r\nLOCALHOST.\r\nkeep.example.org\r\n')
            previous = self.seed(root, ("old",))
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                outputs = generate(root, lambda url: self.fail(url))
            self.assertEqual(stderr.getvalue(), "")
            for group in ("old", "new"):
                self.assert_products(outputs, root, group, "block", ("localhost", "keep.example.org"))
            replace = os.replace
            calls = []
            def fail_after_new_directory(source, destination):
                calls.append((source, destination))
                if len(calls) == 8:
                    raise OSError("domain-set publish failure")
                return replace(source, destination)
            with patch("generate.os.replace", fail_after_new_directory), self.assertRaisesRegex(OSError, "domain-set publish failure"):
                publish(outputs)
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertFalse((root / "new").exists())
            self.assertEqual(len(calls), 14)
            publish(outputs)
            self.assertEqual({path: path.read_bytes() for path in outputs},
                             {path: text.encode("utf-8") for path, text in outputs.items()})


class PublicStateRestorationGenerateTests(unittest.TestCase):
    def test_generated_ascii_yaml_same_round_and_disk_preserve_six_targets(self):
        from rules import Rule, parse

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configs = [{'name': 'parent', 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': ['input.txt'], 'whitelist': []},
                       {'name': 'child', 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': ['parent/fin.yaml'], 'whitelist': []}]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'input.txt').write_text('DOMAIN,keep.example.org\nDOMAIN-SUFFIX,broad.example.org', encoding='utf-8')
            for disk in (False, True):
                if disk:
                    (root / 'input.txt').unlink()
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()):
                    output = generate(root, lambda url: self.fail(url))
                wanted = [Rule('DOMAIN', 'keep.example.org'), Rule('DOMAIN-SUFFIX', 'broad.example.org')]
                self.assertEqual(parse(output[root / 'child/fin.yaml'], purpose='proxy'), (wanted, []))
                self.assertEqual(output[root / 'child/fin-surge-ds.txt'], '# child rules: 2\nkeep.example.org\n.broad.example.org\n')
                self.assertIn(' # rconvert-rule-v1 ', output[root / 'child/fin.yaml'])
                publish(output)

    def test_marked_local_remote_source_and_whitelist_errors_protect_old_bytes(self):
        declared = b'payload:\n  - "DOMAIN,keep.example.org" # rconvert-rule-v1 []\n'
        for remote in (False, True):
            for whitelist in (False, True):
                for data in (declared, declared.replace(b'[]', b'\xff')):
                    with self.subTest(remote=remote, whitelist=whitelist, data=data), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        source = 'https://example.org/generated.yaml' if remote else 'input.yaml'
                        config = [{'name': 'child', 'purpose': 'block', 'no_resolve': 'keep',
                                   'sources': ['neighbor.txt'] if whitelist else [source],
                                   'whitelist': [source] if whitelist else []}]
                        (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                        (root / 'neighbor.txt').write_text('DOMAIN,neighbor.example.org', encoding='utf-8')
                        (root / 'input.yaml').write_bytes(data)
                        (root / 'child').mkdir()
                        old = {root / 'child' / name: bytes(range(256)) for name in NAMES}
                        for path, value in old.items():
                            path.write_bytes(value)
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'line 2:'):
                            publish(generate(root, lambda url: data))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)


R25_SOURCE = ("DOMAIN,current.example.org\nIP-CIDR,192.0.2.0/24,no-resolve\n"
              "IP-CIDR,198.51.100.0/24\n")


def r25_expected(group, purpose, mode, version, empty=False):
    marked = ",no-resolve" if mode != "strip" else ""
    unmarked = ",no-resolve" if mode == "add" else ""
    bodies = {
        "fin.txt": ("DOMAIN,current.example.org\n"
                    f"IP-CIDR,192.0.2.0/24{marked}\nIP-CIDR,198.51.100.0/24{unmarked}\n"),
        "fin-qx.txt": ("HOST,current.example.org,LIST\n"
                       f"IP-CIDR,192.0.2.0/24,LIST{marked}\nIP-CIDR,198.51.100.0/24,LIST{unmarked}\n"),
        "fin-surge.txt": f"IP-CIDR,192.0.2.0/24{marked}\nIP-CIDR,198.51.100.0/24{unmarked}\n",
        "fin-surge-ds.txt": "current.example.org\n",
    }
    if mode == "keep":
        bodies.update({
            "fin.txt": "DOMAIN,current.example.org\nIP-CIDR,198.51.100.0/24\nIP-CIDR,192.0.2.0/24,no-resolve\n",
            "fin-qx.txt": "HOST,current.example.org,LIST\nIP-CIDR,198.51.100.0/24,LIST\nIP-CIDR,192.0.2.0/24,LIST,no-resolve\n",
            "fin-surge.txt": "IP-CIDR,198.51.100.0/24\nIP-CIDR,192.0.2.0/24,no-resolve\n",
        })
    ip_rules = [("192.0.2.0/24", marked), ("198.51.100.0/24", unmarked)]
    if mode == "keep":
        ip_rules.reverse()
    yaml_rules = [("DOMAIN", "current.example.org", ""),
                  *(("IP-CIDR", value, options) for value, options in ip_rules)]
    bodies["fin.yaml"] = "".join(
        "  - " + json.dumps(expected_domain(kind, value) if kind == "DOMAIN" else
                            f"{kind},{value}{options}") + " # rconvert-rule-v1 " +
        json.dumps([[kind, value, ["no-resolve"] if options else [], False, False, False, "surge"]],
                   separators=(',', ':')) + "\n" for kind, value, options in yaml_rules)
    counts = {"fin.txt": 3, "fin-qx.txt": 3, "fin.yaml": 3,
              "fin-surge.txt": 2, "fin-surge-ds.txt": 1}
    expected = {name: f"# {group} rules: {0 if empty else counts[name]}\n" +
                ("payload:\n" if name == "fin.yaml" else "") + ("" if empty else body)
                for name, body in bodies.items()}
    dns = "0.0.0.0 current.example.org\n" if purpose == "block" and not empty else ""
    expected["fin-adb.txt"] = (
        f"[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n"
        "! Expires: 1 day\n! License: Inherits upstream licenses\n" + version + "\n" +
        f"! Total count: {1 if dns else 0}\n" + dns +
        ("" if purpose == "block" else "! No AdBlock rules for non-advertising group.\n"))
    return {name: expected[name] for name in NAMES}


def r25_old_files(root, groups):
    previous = {}
    for group in groups:
        (root / group).mkdir()
        for name in NAMES:
            path = root / group / name
            previous[path] = f"OLD::{group}::{name}\r\n".encode() + b"\x00\x80\xff"
            path.write_bytes(previous[path])
    return previous


class DnsDeepRegexGenerateTests(unittest.TestCase):
    def _expected(self, group, value, dns_value, purpose, *, neighbor=False, whitelist=False, dns_supported=True):
        domain = 'DOMAIN,keep.example.test\n' if neighbor else ''
        expected = {
            'fin.txt': f'# {group} rules: {int(neighbor)}\n' + domain,
            'fin-qx.txt': f'# {group} rules: {int(neighbor)}\n' + ('HOST,keep.example.test,LIST\n' if neighbor else ''),
            'fin.yaml': f'# {group} rules: {1 + int(neighbor)}\npayload:\n' +
                        (('  - ' + json.dumps(expected_domain('DOMAIN', 'keep.example.test')) +
                          ' # rconvert-rule-v1 [["DOMAIN","keep.example.test",[],false,false,false,"surge"]]\n')
                         if neighbor else '') + '  - ' + json.dumps('DOMAIN-REGEX,' + value) +
                        ' # rconvert-rule-v1 ' + json.dumps(
                            [['DOMAIN-REGEX', value, [], False, False, False, 'surge']], separators=(',', ':')) + '\n',
            'fin-surge.txt': f'# {group} rules: 0\n',
            'fin-surge-ds.txt': f'# {group} rules: {int(neighbor)}\n' + ('keep.example.test\n' if neighbor else ''),
        }
        dns = ''
        if purpose == 'block':
            dns = ('@@/' + dns_value + '/\n' if whitelist and dns_supported else '')
            dns += '0.0.0.0 keep.example.test\n' if neighbor else ''
            dns += '/' + dns_value + '/\n' if dns_supported else ''
        expected['fin-adb.txt'] = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
            '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
            '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
            f'! Total count: {len(dns.splitlines())}\n' + dns +
            ('! No AdBlock rules for non-advertising group.\n' if purpose != 'block' else ''))
        return {name: expected[name] for name in NAMES}

    def _check_generate(self, depth, *, prefix='(', atom='audit[.]example[.]test', suffix=')',
                        dns_prefix='(?:', dns_supported=True):
        from rules import Rule, parse

        value = '^' + prefix * depth + atom + suffix * depth + '$'
        dns_value = '^' + dns_prefix * depth + atom + suffix * depth + '$'
        rule = Rule('DOMAIN-REGEX', value)
        for purpose in ('block', 'proxy', 'direct'):
            for mode in ('add', 'strip', 'keep'):
                for whitelist in (False, True):
                    with self.subTest(depth=depth, purpose=purpose, mode=mode, whitelist=whitelist), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.yaml'], 'whitelist': []},
                                   {'name': 'dependent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml', 'neighbor.list'],
                                    'whitelist': ['source/fin.yaml'] if whitelist else []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        (root / 'input.yaml').write_text('payload:\n  - DOMAIN-REGEX,' + value + '\n', encoding='utf-8')
                        (root / 'neighbor.list').write_text('DOMAIN,keep.example.test\n', encoding='utf-8')
                        previous = {}
                        for group in ('source', 'dependent'):
                            (root / group).mkdir()
                            for name in NAMES:
                                path = root / group / name
                                path.write_bytes(b'old product\x00\xff\r\n')
                                previous[path] = path.read_bytes()
                        expected = {root / group / name: text for group, neighbor in
                                    (('source', False), ('dependent', True)) for name, text in
                                    self._expected(group, value, dns_value, purpose, neighbor=neighbor,
                                                   whitelist=whitelist and neighbor, dns_supported=dns_supported).items()}
                        skips = {name + ':DOMAIN-REGEX': 1 for name in
                                 ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt')}
                        source_skips = dict(skips)
                        dependent_skips = dict(skips)
                        if purpose != 'block':
                            dependent_skips['fin-adb.txt:DOMAIN'] = 1
                        if purpose != 'block' or not dns_supported:
                            source_skips['fin-adb.txt:DOMAIN-REGEX'] = 1
                            dependent_skips['fin-adb.txt:DOMAIN-REGEX'] = 1 + int(whitelist and purpose == 'block')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                            clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(list(outputs), list(expected))
                        self.assertEqual(outputs, expected)
                        self.assertEqual(stderr.getvalue().splitlines(), [
                            f'{group} {key}: {count}' for group, counts in
                            (('source', source_skips), ('dependent', dependent_skips)) for key, count in sorted(counts.items())])
                        self.assertEqual(parse(outputs[root / 'source' / 'fin.yaml'], purpose=purpose), ([rule], []))
                        self.assertEqual(parse(outputs[root / 'dependent' / 'fin.yaml'], purpose=purpose),
                                         ([Rule('DOMAIN', 'keep.example.test'), rule], []))
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in expected.items()})
                        published = {path: path.read_bytes() for path in outputs}
                        (root / 'input.yaml').unlink()
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                            clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name == 'dependent'})
                        self.assertEqual(stderr.getvalue().splitlines(), [f'dependent {key}: {count}' for key, count in sorted(dependent_skips.items())])
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in outputs}, published)

    def _run_deep(self, depth, **kwargs):
        code = ('from tests.test_generate import DnsDeepRegexGenerateTests; '
                f'DnsDeepRegexGenerateTests()._check_generate({depth}, **{kwargs!r})')
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_600_capture_regex_publishes_and_reimports_disk_yaml(self):
        self._run_deep(600)

    def test_1000_capture_regex_publishes_and_reimports_equivalent_dns(self):
        self._run_deep(1000)

    def test_999_capture_regex_publishes_and_reimports_equivalent_dns(self):
        self._run_deep(999)

    def test_600_nested_concat_publishes_and_reimports_equivalent_dns(self):
        self._run_deep(600, prefix='(a?', dns_prefix='(?:a?')

    def test_998_quantified_atom_publishes_and_reimports_equivalent_dns(self):
        self._run_deep(998, atom='audit.*')

    def test_500_nested_quantifiers_publishes_and_reimports_equivalent_dns(self):
        self._run_deep(500, suffix=')?')

    def test_500_nested_alternations_publishes_and_reimports_equivalent_dns(self):
        self._run_deep(500, prefix='(x|', dns_prefix='(?:x|')

    def test_deep_nonportable_regex_skips_only_dns_and_reimports_disk(self):
        self._run_deep(600, atom='a{1001}', dns_supported=False)

    def _check_mixed(self, depth, purpose, mode, *, prefix='(', atom='audit[.]example[.]test',
                     suffix=')', dns_prefix='(?:', dns_supported=True):
        from rules import Rule, parse

        value = '^' + prefix * depth + atom + suffix * depth + '$'
        dns_value = '^' + dns_prefix * depth + atom + suffix * depth + '$'
        logic = '((DOMAIN-REGEX,' + value + '),(IP-CIDR,203.0.113.0/24,no-resolve),'
        logic += '(SRC-IP-CIDR,198.51.100.0/24),(PROCESS-NAME,Foo*Bar))'
        source = 'payload:\n' + ''.join('  - ' + json.dumps(line) + '\n' for line in (
            'DOMAIN-REGEX,' + value, 'PROCESS-NAME-REGEX,' + value, 'AND,' + logic,
            'DOMAIN,keep.example.test', 'IP-CIDR,203.0.113.0/24,no-resolve',
            'SRC-IP-CIDR,198.51.100.0/24'))
        initial = [Rule('DOMAIN-REGEX', value), Rule('PROCESS-NAME-REGEX', value),
                   Rule('AND', logic, literal_process=True, native_fields=True),
                   Rule('DOMAIN', 'keep.example.test', domain_source='mihomo'),
                   Rule('IP-CIDR', '203.0.113.0/24', ('no-resolve',)),
                   Rule('SRC-IP-CIDR', '198.51.100.0/24')]
        self.assertEqual(parse(source, purpose=purpose), (initial, []))
        flag = '' if mode == 'strip' else ',no-resolve'
        options = () if mode == 'strip' else ('no-resolve',)
        target_logic = logic.replace(',no-resolve', '') if mode == 'strip' else logic
        ip = 'IP-CIDR,203.0.113.0/24' + flag
        source_ip = 'SRC-IP,198.51.100.0/24'
        yaml_lines = ['AND,' + target_logic, 'DOMAIN,keep.example.test', 'DOMAIN-REGEX,' + value,
                      'PROCESS-NAME-REGEX,' + value, ip, 'SRC-IP-CIDR,198.51.100.0/24']
        parsed_expected = [Rule('AND', target_logic, literal_process=True, native_fields=True),
                           Rule('DOMAIN', 'keep.example.test', domain_source='mihomo'), Rule('DOMAIN-REGEX', value),
                           Rule('PROCESS-NAME-REGEX', value),
                           Rule('IP-CIDR', '203.0.113.0/24', options),
                           Rule('SRC-IP-CIDR', '198.51.100.0/24')]
        bodies = {'fin.txt': ['DOMAIN,keep.example.test', ip, source_ip],
                  'fin-qx.txt': ['HOST,keep.example.test,LIST', 'IP-CIDR,203.0.113.0/24,LIST' + flag],
                  'fin.yaml': ['payload:', *[
                      '  - ' + json.dumps(line) + ' # rconvert-rule-v1 ' + json.dumps(
                          [[rule.kind, rule.value, list(rule.options), rule.allow, rule.literal_process,
                            rule.native_fields, rule.domain_source]], separators=(',', ':'))
                      for line, rule in zip(yaml_lines, parsed_expected)]],
                  'fin-surge.txt': [ip, source_ip], 'fin-surge-ds.txt': ['keep.example.test']}
        dns = (['@@/' + dns_value + '/', '0.0.0.0 keep.example.test', '/' + dns_value + '/'] if dns_supported else
               ['0.0.0.0 keep.example.test']) if purpose == 'block' else []
        expected_skips = {}
        supported = {'DOMAIN-REGEX': {'fin.yaml', *(['fin-adb.txt'] if purpose == 'block' and dns_supported else [])},
                     'PROCESS-NAME-REGEX': {'fin.yaml'}, 'AND': {'fin.yaml'},
                     'IP-CIDR': {'fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-surge.txt'},
                     'SRC-IP-CIDR': {'fin.txt', 'fin.yaml', 'fin-surge.txt'}}
        for kind, names in supported.items():
            for name in NAMES:
                if name not in names:
                    expected_skips[name + ':' + kind] = 1
        if purpose != 'block':
            expected_skips['fin-adb.txt:DOMAIN'] = 1
        elif not dns_supported:
            expected_skips['fin-adb.txt:DOMAIN-REGEX'] += 1
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                        'sources': ['input.yaml'] if group == 'source' else ['source/fin.yaml'],
                        'whitelist': ['white.yaml']} for group in ('source', 'dependent')]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'input.yaml').write_text(source, encoding='utf-8')
            (root / 'white.yaml').write_text('payload:\n  - DOMAIN-REGEX,' + value + '\n', encoding='utf-8')
            expected = {}
            previous = {}
            for group in ('source', 'dependent'):
                (root / group).mkdir()
                for name in NAMES:
                    path = root / group / name
                    path.write_bytes(b'old mixed product\x00\xff\r\n')
                    previous[path] = path.read_bytes()
                    if name == 'fin-adb.txt':
                        text = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
                                f'! Total count: {len(dns)}\n' + ''.join(line + '\n' for line in dns) +
                                ('! No AdBlock rules for non-advertising group.\n' if purpose != 'block' else ''))
                    else:
                        count = len(bodies[name]) - int(name == 'fin.yaml')
                        text = f'# {group} rules: {count}\n' + ''.join(line + '\n' for line in bodies[name])
                    expected[path] = text
            for disk_only in (False, True):
                if disk_only:
                    (root / 'input.yaml').unlink()
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    actual = generate(root, lambda url: self.fail(url))
                selected = {path: text for path, text in expected.items()
                            if not disk_only or path.parent.name == 'dependent'}
                self.assertEqual(list(actual), list(selected))
                self.assertEqual(actual, selected)
                groups = ('dependent',) if disk_only else ('source', 'dependent')
                self.assertEqual(stderr.getvalue().splitlines(), [f'{group} {key}: {count}'
                    for group in groups for key, count in sorted(expected_skips.items())])
                for group in groups:
                    self.assertEqual(parse(actual[root / group / 'fin.yaml'], purpose=purpose), (parsed_expected, []))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                publish(actual)
                previous = {path: text.encode('utf-8') for path, text in expected.items()}
                self.assertEqual({path: path.read_bytes() for path in expected}, previous)

    def test_deep_regex_mixed_neighbors_flags_and_twelve_ordered_products(self):
        cases = [(600, {}), (999, {}), (1000, {}),
                 (600, {'prefix': '(a?', 'dns_prefix': '(?:a?'}),
                 (998, {'atom': 'audit.*'}), (500, {'suffix': ')?'}),
                 (500, {'prefix': '(x|', 'dns_prefix': '(?:x|'}),
                 (600, {'atom': 'a{1001}', 'dns_supported': False})]
        for depth, kwargs in cases:
            for purpose in ('block', 'proxy', 'direct'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(depth=depth, purpose=purpose, mode=mode, kwargs=kwargs):
                        code = ('from tests.test_generate import DnsDeepRegexGenerateTests; '
                                f'DnsDeepRegexGenerateTests()._check_mixed({depth}, {purpose!r}, {mode!r}, **{kwargs!r})')
                        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                                capture_output=True, text=True, timeout=8)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class RegexValidatorGenerateTests(unittest.TestCase):
    def test_regex_six_products_publish_same_round_and_disk_for_all_modes(self):
        from rules import Rule, parse
        from tests.test_formats import RegexValidatorFormatTests
        from tests.test_rules import RegexValidatorRuleTests

        cases = (('(?x) +', True), ('(?x:^ads # note\n[.]example[.]org$)', True),
                 ('(?i)(?#note)a+', True), ('(?x)foo# note\n[', False),
                 ('(?x)(?i)# ignored\n+', False), ('(?i)(?#note)+a', False)) + RegexValidatorRuleTests.boundary_cases[:8]
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for kind in RegexValidatorRuleTests.kinds:
                    for value, valid in cases:
                        with self.subTest(purpose=purpose, mode=mode, kind=kind, value=value), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                            root = Path(directory)
                            initial = '' if mode == 'add' else ',no-resolve'
                            flag = '' if mode == 'strip' else ',no-resolve'
                            expression = f'(({kind},{value}),(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            wanted = f'(({kind},{value}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['input.yaml'] if group == 'parent' else ['parent/fin.yaml'],
                                        'whitelist': []} for group in ('parent', 'child')]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            source = ('payload:\n  - ' + json.dumps('AND,' + expression) +
                                      '\n  - DOMAIN-REGEX,*bad\n  - DOMAIN,keep.example.com\n')
                            (root / 'input.yaml').write_text(source, encoding='utf-8')
                            old = {}
                            for group in ('parent', 'child'):
                                (root / group).mkdir()
                                for name in NAMES:
                                    path = root / group / name
                                    old[path] = b'old complete\x00\xff\r\n' + name.encode('ascii')
                                    path.write_bytes(old[path])
                            matchers = (['AND,' + wanted] if valid else []) + ['DOMAIN,keep.example.com']
                            expected = {root / group / name: text for group in ('parent', 'child')
                                        for name, text in RegexValidatorFormatTests.products(group, matchers, purpose).items()}
                            skips = {name + ':AND': 1 for name in
                                     ('fin.txt', 'fin-qx.txt', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')} if valid else {}
                            if purpose != 'block':
                                skips['fin-adb.txt:DOMAIN'] = 1
                            warnings = ([] if valid else [f'{root / "input.yaml"}: line 2: invalid logical expression {expression}'])
                            warnings += [f'{root / "input.yaml"}: line 3: invalid DOMAIN-REGEX *bad']
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                                clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual(outputs, expected)
                            self.assertEqual(list(outputs), list(expected))
                            self.assertEqual(stderr.getvalue(), ''.join(message + '\n' for message in warnings +
                                             [f'{group} {key}: {count}' for group in ('parent', 'child') for key, count in sorted(skips.items())]))
                            public = ([Rule('AND', wanted, native_fields=True)] if valid else []) + [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')]
                            for group in ('parent', 'child'):
                                self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose), (public, []))
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs)
                            published = {path: text.encode('utf-8') for path, text in expected.items()}
                            self.assertEqual({path: path.read_bytes() for path in old}, published)
                            (root / 'input.yaml').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                                clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name == 'child'})
                            self.assertEqual(stderr.getvalue().splitlines(), [f'child {key}: {count}' for key, count in sorted(skips.items())])
                            self.assertEqual({path: path.read_bytes() for path in old}, published)
                            publish(disk)
                            self.assertEqual({path: path.read_bytes() for path in old}, published)

    def test_marked_local_and_remote_bytes_source_white_validate_complete_state(self):
        from rules import GeneratedRuleError, Rule, parse
        from tests.test_rules import GeneratedDeclarationValidationTests, RegexValidatorRuleTests

        cases = (('(?x) +', True), ('(?x:^ads # note\n[.]example[.]org$)', True),
                 ('(?i)(?#note)a+', True), ('(?x)^ads # note\n\\q', False),
                 ('(?x)(?i)# ignored\n+', False), ('(?i)(?#note)+a', False)) + RegexValidatorRuleTests.boundary_cases[:8]
        for value, valid in cases:
            document = GeneratedDeclarationValidationTests.document('DOMAIN-REGEX,' + value,
                         [['DOMAIN-REGEX', value, [], False, False, False, 'surge']])
            for remote in (False, True):
                for white in (False, True):
                    with self.subTest(value=value, remote=remote, white=white), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        entry = 'https://example.org/marked.yaml' if remote else 'marked.yaml'
                        (root / 'marked.yaml').write_text(document, encoding='utf-8')
                        (root / 'input.yaml').write_text('payload:\n  - DOMAIN,keep.example.com\n', encoding='utf-8')
                        configs = [{'name': 'child', 'purpose': 'block', 'no_resolve': 'keep',
                                    'sources': ['input.yaml'] if white else [entry], 'whitelist': [entry] if white else []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        (root / 'child').mkdir()
                        old = {root / 'child' / name: b'old marked\x00\xff\r\n' for name in NAMES}
                        for path, data in old.items():
                            path.write_bytes(data)
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            if valid:
                                outputs = generate(root, lambda url: document.encode('utf-8') if url == entry else self.fail(url))
                                expected = [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')] if white else [Rule('DOMAIN-REGEX', value)]
                                self.assertEqual(parse(outputs[root / 'child' / 'fin.yaml'], purpose='block'), (expected, []))
                                self.assertNotIn('invalid whitelist', stderr.getvalue())
                                self.assertNotIn('invalid generated', stderr.getvalue())
                            else:
                                with self.assertRaisesRegex(GeneratedRuleError, 'invalid generated public state'):
                                    generate(root, lambda url: document.encode('utf-8') if url == entry else self.fail(url))
                                self.assertEqual(stderr.getvalue(), '')
                        self.assertEqual({path: path.read_bytes() for path in old}, old)


class NativeKeywordGenerateTests(unittest.TestCase):
    complete_values = ('中文 #1\\', '中文 ;1\\', '中文 //1\\', '中文 #1\\\\\\',
                       '中文\\', '中文\\\\', '中文 #1\\\\', '中文 #1(', '中文 #1)',
                       '中文 ;1(', '中文 //1)', '中文(1', '中文)1', '中文(1) #2')

    def test_qx_literal_source_publishes_complete_fields_same_round_and_disk(self):
        self._check_qx_keyword_marker_dependency(False, self.complete_values)

    def test_qx_literal_whitelist_preserves_shorter_matcher_same_round_and_disk(self):
        self._check_qx_keyword_marker_dependency(True, self.complete_values)

    def _qx_marker_products(self, group, purpose, mode, value, white, version):
        import re
        from rules import Rule

        parent = group == 'parent'
        only_keyword = parent and white
        keyword = value if parent or not white else '中文'
        source = 'mihomo' if parent else 'qx'
        flag = ',no-resolve' if mode != 'strip' else ''
        public = ([] if only_keyword else [Rule('DOMAIN', 'keep.example.com', domain_source=source)])
        public.append(Rule('DOMAIN-KEYWORD', keyword, domain_source=source))
        if not only_keyword:
            public.append(Rule('IP-CIDR', '203.0.113.0/24', ('no-resolve',) if flag else ()))
        if not only_keyword and (parent or white):
            public.append(Rule('SRC-IP-CIDR', '198.51.100.0/24'))
        if (len(keyword) - len(keyword.rstrip('\\'))) % 2:
            field = json.dumps(keyword, ensure_ascii=False)
        elif any(' ' + marker in keyword for marker in ('#', ';', '//')):
            field = "'" + keyword + "'"
        else:
            field = keyword
        bodies = {'fin.txt': ([] if only_keyword else ['DOMAIN,keep.example.com']) + ['DOMAIN-KEYWORD,' + field],
                  'fin-qx.txt': ([] if only_keyword else ['HOST,keep.example.com,LIST']) + ['HOST-KEYWORD,' + keyword + ',LIST'],
                  'fin-surge.txt': ['DOMAIN-KEYWORD,' + field],
                  'fin-surge-ds.txt': [] if only_keyword else ['keep.example.com'], 'fin.yaml': []}
        if not only_keyword:
            for name in ('fin.txt', 'fin-surge.txt'):
                bodies[name].append('IP-CIDR,203.0.113.0/24' + flag)
                if parent or white:
                    bodies[name].append('SRC-IP,198.51.100.0/24')
            bodies['fin-qx.txt'].append('IP-CIDR,203.0.113.0/24,LIST' + flag)
        for rule in public:
            payload = rule.kind + ',' + rule.value + (',no-resolve' if rule.options else '')
            record = [[rule.kind, rule.value, list(rule.options), rule.allow,
                       rule.literal_process, rule.native_fields, rule.domain_source]]
            bodies['fin.yaml'].append('  - ' + json.dumps(payload, ensure_ascii=False) +
                                      ' # rconvert-rule-v1 ' + json.dumps(record, separators=(',', ':')))
        expected = {name: f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '') +
                    ''.join(line + '\n' for line in body) for name, body in bodies.items()}
        dns = []
        if purpose == 'block':
            if white and not parent and '/' not in value:
                dns.append('@@/^.*' + re.escape(value) + '.*$/')
            if '/' not in keyword:
                dns.append(('/(?s-i:\\A.*' + re.escape(keyword) + '.*\\z)/') if parent else
                           '/^.*' + re.escape(keyword) + '.*$/')
            if not only_keyword:
                dns.append('0.0.0.0 keep.example.com')
        dns.sort(key=lambda line: (not line.startswith('@@'), len(line), line))
        expected['fin-adb.txt'] = (f'[Adblock Plus 2.0]\n! Title: {group}\n'
            '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n! License: Inherits upstream licenses\n'
            '! Version: ' + version + f'\n! Total count: {len(dns)}\n' + ''.join(line + '\n' for line in dns) +
            ('! No AdBlock rules for non-advertising group.\n' if purpose != 'block' else ''))
        skipped = {'fin-surge-ds.txt:DOMAIN-KEYWORD': 1}
        if purpose != 'block' or '/' in keyword:
            skipped['fin-adb.txt:DOMAIN-KEYWORD'] = 1
        if not only_keyword:
            skipped.update({'fin-adb.txt:IP-CIDR': 1, 'fin-surge-ds.txt:IP-CIDR': 1})
            if purpose != 'block':
                skipped['fin-adb.txt:DOMAIN'] = 1
            if parent or white:
                skipped.update({name + ':SRC-IP-CIDR': 1 for name in
                                ('fin-qx.txt', 'fin-adb.txt', 'fin-surge-ds.txt')})
            if purpose == 'block' and white and not parent and '/' in value:
                skipped['fin-adb.txt:DOMAIN-KEYWORD'] = 1
        return expected, public, skipped

    def _check_qx_keyword_marker_dependency(self, white, values=('中文 #1', '中文 ;1', '中文 //1')):
        import warnings
        from rules import Rule, parse, parse_whitelist

        staging = ROOT / '.tmp'
        staging.mkdir(exist_ok=True)
        for value in values:
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'keep', 'strip'):
                    with self.subTest(value=value, purpose=purpose, mode=mode, white=white), tempfile.TemporaryDirectory(dir=staging) as directory:
                        root = Path(directory)
                        configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.yaml'], 'whitelist': []},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source.list'] if white else ['parent/fin-qx.txt'],
                                    'whitelist': ['parent/fin-qx.txt'] if white else []}]
                        matchers = ['DOMAIN-KEYWORD,' + value] if white else [
                            'DOMAIN-KEYWORD,' + value, 'DOMAIN,keep.example.com',
                            'IP-CIDR,203.0.113.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24']
                        (root / 'input.yaml').write_text('payload:\n' + ''.join('  - ' + json.dumps(matcher, ensure_ascii=False) + '\n'
                                                                                for matcher in matchers), encoding='utf-8')
                        if white:
                            (root / 'source.list').write_text('HOST-KEYWORD,中文,LIST\nHOST-KEYWORD,' + value + ',LIST\nHOST-KEYWORD,' + value +
                                '9,LIST\nHOST,keep.example.com,LIST\nIP-CIDR,203.0.113.0/24,LIST,no-resolve\nSRC-IP-CIDR,198.51.100.0/24\n', encoding='utf-8')
                        previous = {}
                        for group in ('parent', 'child'):
                            (root / group).mkdir()
                            for name in NAMES:
                                path = root / group / name
                                previous[path] = b'old\r\ncomplete\x00' + group.encode() + name.encode()
                                path.write_bytes(previous[path])
                        parent_bytes = {}
                        for phase in ('parent', 'same-round', 'disk-only'):
                            with self.subTest(value=value, purpose=purpose, mode=mode, white=white, phase=phase):
                                if phase == 'disk-only':
                                    (root / 'input.yaml').unlink()
                                    (root / 'rulesets.json').unlink()
                                selected = configs[:1] if phase == 'parent' else configs[1:] if phase == 'disk-only' else configs
                                (root / 'rulesets.json').write_text(json.dumps(selected), encoding='utf-8')
                                before = datetime.now(timezone(timedelta(hours=8))).strftime('%Y%m%d%H%M')
                                with warnings.catch_warnings(record=True) as warnings_seen, contextlib.redirect_stderr(io.StringIO()) as messages:
                                    outputs = generate(root, lambda url: self.fail(url))
                                after = datetime.now(timezone(timedelta(hours=8))).strftime('%Y%m%d%H%M')
                                groups = ('parent',) if phase == 'parent' else ('child',) if phase == 'disk-only' else ('parent', 'child')
                                expected, identities, skips = {}, {}, []
                                for group in groups:
                                    version = outputs[root / group / 'fin-adb.txt'].splitlines()[5].removeprefix('! Version: ')
                                    self.assertRegex(version, r'^[0-9]{12}$')
                                    datetime.strptime(version, '%Y%m%d%H%M')
                                    self.assertLessEqual(before, version)
                                    self.assertLessEqual(version, after)
                                    texts, identities[group], counters = self._qx_marker_products(group, purpose, mode, value, white, version)
                                    expected.update({root / group / name: text for name, text in texts.items()})
                                    skips.extend(f'{group} {key}: {count}' for key, count in sorted(counters.items()))
                                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                                publish(outputs)
                                previous |= {path: text.encode('utf-8') for path, text in outputs.items()}
                                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                                if phase in ('parent', 'same-round'):
                                    parent_bytes = {path: path.read_bytes() for path in previous if path.parent.name == 'parent'}
                                self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)
                                self.assertEqual(outputs, expected)
                                self.assertEqual(messages.getvalue().splitlines(), skips)
                                self.assertEqual(warnings_seen, [])
                                for group in groups:
                                    self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose), (identities[group], []))
                                with warnings.catch_warnings(record=True) as white_warnings:
                                    self.assertEqual(parse_whitelist((root / 'parent' / 'fin-qx.txt').read_text(encoding='utf-8')),
                                                     [Rule('DOMAIN-KEYWORD', value, domain_source='qx')] if white else
                                                     [Rule('DOMAIN', 'keep.example.com', domain_source='qx'),
                                                      Rule('DOMAIN-KEYWORD', value, domain_source='qx'), Rule('IP-CIDR', '203.0.113.0/24')])
                                self.assertEqual(white_warnings, [])
                                if phase == 'disk-only':
                                    self.assertFalse((root / 'input.yaml').exists())
                                    self.assertEqual(json.loads((root / 'rulesets.json').read_text(encoding='utf-8')), configs[1:])
                        invalid = root / 'parent' / 'fin-qx.txt'
                        invalid.write_text('HOST-KEYWORD,' + value + ',LIST,no-resolve\n', encoding='utf-8')
                        old = {path: path.read_bytes() for path in previous}
                        with contextlib.redirect_stderr(io.StringIO()) as messages, self.assertRaises(ValueError) as error_seen:
                            publish(generate(root, lambda url: self.fail(url)))
                        warning = 'line 1: unsupported no-resolve for DOMAIN-KEYWORD'
                        self.assertEqual(str(error_seen.exception), f'Invalid whitelist {invalid}: {warning}' if white else
                                         f'No adaptable rules in {invalid}')
                        self.assertEqual(messages.getvalue(), '' if white else f'{invalid}: {warning}\n')
                        self.assertEqual({path: path.read_bytes() for path in old}, old)

    def test_qx_keyword_source_preserves_markers_same_round_and_disk_without_mock(self):
        self._check_qx_keyword_marker_dependency(False)

    def test_qx_keyword_whitelist_keeps_short_keyword_same_round_and_disk_without_mock(self):
        self._check_qx_keyword_marker_dependency(True)

    def _surge_keyword_products(self, group, purpose, mode, value, dependency=None):
        import re
        from rules import Rule
        from tests.test_formats import native_keyword_expected

        flag = ',no-resolve' if mode != 'strip' else ''
        conjunction = ('((DOMAIN-KEYWORD,' + value + '),(IP-CIDR,192.0.2.0/24' + flag +
                       '),(SRC-IP-CIDR,198.51.100.0/24))')
        source = 'surge' if dependency else 'mihomo'
        public = [Rule('AND', conjunction.replace('SRC-IP-CIDR,', 'SRC-IP,') if dependency else conjunction,
                       native_fields=not dependency, domain_source=source),
                  Rule('DOMAIN', 'keep.example.com', domain_source=source),
                  Rule('DOMAIN-KEYWORD', value, domain_source=source),
                  Rule('NOT', '((DOMAIN-KEYWORD,' + value + '))', native_fields=not dependency, domain_source=source),
                  Rule('OR', '((DOMAIN-KEYWORD,' + value + '),(' + ('PROTOCOL,UDP' if dependency else 'NETWORK,udp') + '))',
                       native_fields=not dependency, domain_source=source),
                  Rule('IP-CIDR', '203.0.113.0/24', ('no-resolve',) if flag else ()),
                  Rule('SRC-IP-CIDR', '198.51.100.0/24')]
        expected = {name: text.replace('中文', re.escape(value) if name == 'fin-adb.txt' else value)
                    for name, text in native_keyword_expected(group, purpose, mode).items()}
        if dependency:
            keyword = 'DOMAIN-REGEX,' + re.escape(value)
            payloads = ['AND,' + conjunction.replace('DOMAIN-KEYWORD,' + value, keyword), keyword,
                        expected_domain('DOMAIN', 'keep.example.com'),
                        'NOT,((DOMAIN-REGEX,' + re.escape(value) + '))',
                        'OR,((DOMAIN-REGEX,' + re.escape(value) + '),(NETWORK,udp))',
                        'IP-CIDR,203.0.113.0/24' + flag, 'SRC-IP-CIDR,198.51.100.0/24']
            public[1:3] = [public[2], public[1]]
            expected['fin.yaml'] = f'# {group} rules: 7\npayload:\n' + ''.join(
                '  - ' + json.dumps(payload, ensure_ascii=False) + '\n' for payload in payloads)
            expected['fin-adb.txt'] = expected['fin-adb.txt'].replace(
                '/(?s-i:\\A.*' + re.escape(value) + '.*\\z)/', '/^.*' + re.escape(value) + '.*$/')
            if dependency == 'fin-surge.txt':
                public = [rule for rule in public if rule.kind != 'DOMAIN']
                for name, line, old_count in (('fin.txt', 'DOMAIN,keep.example.com', 7),
                                             ('fin-qx.txt', 'HOST,keep.example.com,LIST', 3),
                                             ('fin.yaml', '  - ' + json.dumps(expected_domain('DOMAIN', 'keep.example.com')), 7),
                                             ('fin-surge-ds.txt', 'keep.example.com', 1)):
                    expected[name] = expected[name].replace(line + '\n', '').replace(
                        f'# {group} rules: {old_count}\n', f'# {group} rules: {old_count - 1}\n')
                if purpose == 'block':
                    expected['fin-adb.txt'] = expected['fin-adb.txt'].replace(
                        '0.0.0.0 keep.example.com\n', '').replace('! Total count: 2\n', '! Total count: 1\n')
        lines = expected['fin.yaml'].splitlines()
        for index, rule in enumerate(public, 2):
            record = [[rule.kind, rule.value, list(rule.options), rule.allow,
                       rule.literal_process, rule.native_fields, rule.domain_source]]
            lines[index] += ' # rconvert-rule-v1 ' + json.dumps(record, separators=(',', ':'))
        expected['fin.yaml'] = '\n'.join(lines) + '\n'
        return expected, public

    def test_surge_keyword_source_publishes_six_products_and_disk_only_dependencies(self):
        from rules import parse
        from tests.test_formats import NATIVE_KEYWORD_SOURCE, native_keyword_skips

        staging = ROOT / '.tmp'
        staging.mkdir(exist_ok=True)
        for value in ('中文', '中文123', '123#1', '123'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'keep', 'strip'):
                    for dependency in ('fin.txt', 'fin-surge.txt'):
                        with self.subTest(value=value, purpose=purpose, mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=staging) as directory:
                            root = Path(directory)
                            configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['input.yaml'], 'whitelist': []},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['parent/' + dependency], 'whitelist': []}]
                            (root / 'input.yaml').write_text(NATIVE_KEYWORD_SOURCE.replace('中文', value), encoding='utf-8')
                            old = {}
                            for group in ('parent', 'child'):
                                (root / group).mkdir()
                                for name in NAMES:
                                    path = root / group / name
                                    old[path] = b'old\r\ncomplete\x00' + name.encode('ascii')
                                    path.write_bytes(old[path])
                            parent, native = self._surge_keyword_products('parent', purpose, mode, value)
                            child, ordinary = self._surge_keyword_products('child', purpose, mode, value, dependency)
                            previous = old
                            for phase in ('parent', 'same-round', 'disk-only'):
                                if phase == 'disk-only':
                                    (root / 'input.yaml').unlink()
                                    (root / 'rulesets.json').unlink()
                                selected = configs[:1] if phase == 'parent' else configs[1:] if phase == 'disk-only' else configs
                                (root / 'rulesets.json').write_text(json.dumps(selected), encoding='utf-8')
                                with contextlib.redirect_stderr(io.StringIO()) as messages, patch('formats.datetime') as clock:
                                    clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                                    outputs = generate(root, lambda url: self.fail(url))
                                groups = ('parent',) if phase == 'parent' else ('child',) if phase == 'disk-only' else ('parent', 'child')
                                expected = {root / group / name: text for group in groups
                                            for name, text in (parent if group == 'parent' else child).items()}
                                self.assertEqual(outputs, expected)
                                child_skips = native_keyword_skips(purpose)
                                if dependency == 'fin-surge.txt' and purpose != 'block':
                                    child_skips.pop('fin-adb.txt:DOMAIN')
                                self.assertEqual(messages.getvalue().splitlines(), [f'{group} {key}: {count}' for group in groups
                                                 for key, count in sorted((native_keyword_skips(purpose) if group == 'parent' else child_skips).items())])
                                for group in groups:
                                    self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                                     (native if group == 'parent' else ordinary, []))
                                self.assertEqual({path: path.read_bytes() for path in old}, previous)
                                publish(outputs)
                                previous = previous | {path: text.encode('utf-8') for path, text in expected.items()}
                                self.assertEqual({path: path.read_bytes() for path in old}, previous)
                                self.assertEqual({root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in NAMES},
                                                 {root / 'parent' / name: text.encode('utf-8') for name, text in parent.items()})
                                if phase == 'disk-only':
                                    self.assertFalse((root / 'input.yaml').exists())
                                    self.assertEqual(json.loads((root / 'rulesets.json').read_text(encoding='utf-8')), configs[1:])

    def test_surge_keyword_whitelist_removes_only_covered_rules_same_round_and_disk(self):
        import re
        import warnings
        from rules import Rule, parse, parse_whitelist

        staging = ROOT / '.tmp'
        staging.mkdir(exist_ok=True)
        for value in ('中文', '中文123', '123#1', '123'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'keep', 'strip'):
                    for dependency in ('fin.txt', 'fin-surge.txt'):
                        with self.subTest(value=value, purpose=purpose, mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=staging) as directory:
                            root = Path(directory)
                            configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['input.yaml'], 'whitelist': []},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source.list'], 'whitelist': ['parent/' + dependency]}]
                            (root / 'input.yaml').write_text('payload:\n  - DOMAIN-KEYWORD,' + value + '\n', encoding='utf-8')
                            (root / 'source.list').write_text('DOMAIN-KEYWORD,' + value + '\nDOMAIN-KEYWORD,' + value +
                                                             '9\nDOMAIN,keep.example.com\n', encoding='utf-8')
                            parent_rule = Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')
                            child_rule = Rule('DOMAIN', 'keep.example.com')
                            parent = {'fin.txt': '# parent rules: 1\nDOMAIN-KEYWORD,' + value + '\n',
                                      'fin-qx.txt': '# parent rules: 1\nHOST-KEYWORD,' + value + ',LIST\n',
                                      'fin.yaml': '# parent rules: 1\npayload:\n  - ' + json.dumps('DOMAIN-KEYWORD,' + value, ensure_ascii=False) +
                                                  ' # rconvert-rule-v1 ' + json.dumps([['DOMAIN-KEYWORD', value, [], False, False, False, 'mihomo']], separators=(',', ':')) + '\n',
                                      'fin-surge.txt': '# parent rules: 1\nDOMAIN-KEYWORD,' + value + '\n',
                                      'fin-surge-ds.txt': '# parent rules: 0\n'}
                            child = {'fin.txt': '# child rules: 1\nDOMAIN,keep.example.com\n',
                                     'fin-qx.txt': '# child rules: 1\nHOST,keep.example.com,LIST\n',
                                     'fin.yaml': '# child rules: 1\npayload:\n  - ' + json.dumps(expected_domain('DOMAIN', 'keep.example.com')) +
                                                 ' # rconvert-rule-v1 [["DOMAIN","keep.example.com",[],false,false,false,"surge"]]\n',
                                     'fin-surge.txt': '# child rules: 0\n',
                                     'fin-surge-ds.txt': '# child rules: 1\nkeep.example.com\n'}
                            for group, texts in (('parent', parent), ('child', child)):
                                texts['fin-adb.txt'] = (f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
                                    '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n' +
                                    ('! Total count: 1\n/(?s-i:\\A.*' + re.escape(value) + '.*\\z)/\n' if group == 'parent' else
                                     '! Total count: 2\n@@/^.*' + re.escape(value) + '.*$/\n0.0.0.0 keep.example.com\n') if purpose == 'block' else
                                    f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
                                    '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n'
                                    '! Total count: 0\n! No AdBlock rules for non-advertising group.\n')
                            previous = {}
                            for group in ('parent', 'child'):
                                (root / group).mkdir()
                                for name in NAMES:
                                    path = root / group / name
                                    previous[path] = b'old\r\ncomplete\x00' + name.encode('ascii')
                                    path.write_bytes(previous[path])
                            for phase in ('parent', 'same-round', 'disk-only'):
                                if phase == 'disk-only':
                                    (root / 'input.yaml').unlink()
                                    (root / 'rulesets.json').unlink()
                                selected = configs[:1] if phase == 'parent' else configs[1:] if phase == 'disk-only' else configs
                                (root / 'rulesets.json').write_text(json.dumps(selected), encoding='utf-8')
                                with warnings.catch_warnings(record=True) as warnings_seen, contextlib.redirect_stderr(io.StringIO()) as messages, patch('formats.datetime') as clock:
                                    clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                                    outputs = generate(root, lambda url: self.fail(url))
                                self.assertEqual(warnings_seen, [])
                                groups = ('parent',) if phase == 'parent' else ('child',) if phase == 'disk-only' else ('parent', 'child')
                                expected = {root / group / name: text for group in groups
                                            for name, text in (parent if group == 'parent' else child).items()}
                                self.assertEqual(outputs, expected)
                                skips = ['parent fin-surge-ds.txt:DOMAIN-KEYWORD: 1'] if 'parent' in groups else []
                                if purpose != 'block':
                                    skips = (['parent fin-adb.txt:DOMAIN-KEYWORD: 1'] if 'parent' in groups else []) + skips
                                    skips += ['child fin-adb.txt:DOMAIN: 1'] if 'child' in groups else []
                                self.assertEqual(messages.getvalue().splitlines(), skips)
                                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                                publish(outputs)
                                previous |= {path: text.encode('utf-8') for path, text in expected.items()}
                                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                                self.assertEqual(parse((root / 'parent' / 'fin.yaml').read_text(encoding='utf-8'), purpose=purpose), ([parent_rule], []))
                                if 'child' in groups:
                                    self.assertEqual(parse_whitelist((root / 'parent' / dependency).read_text(encoding='utf-8')), [Rule('DOMAIN-KEYWORD', value)])
                                    self.assertEqual(parse(outputs[root / 'child' / 'fin.yaml'], purpose=purpose), ([child_rule], []))
                                self.assertEqual({root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in NAMES},
                                                 {root / 'parent' / name: text.encode('utf-8') for name, text in parent.items()})

    def test_no_resolve_runs_once_before_normalize_and_preserves_real_products(self):
        import rules
        from dataclasses import fields
        from formats import render
        from tests.test_formats import NATIVE_KEYWORD_SOURCE, native_keyword_expected

        unmarked = "AND,((DOMAIN-KEYWORD,中文),(IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))"
        source = NATIVE_KEYWORD_SOURCE + "  - " + unmarked + "\n  - IP-CIDR,203.0.113.0/24\n"
        self.assertEqual([field.name for field in fields(rules.Rule)],
                         ["kind", "value", "options", "allow", "literal_process", "native_fields", "domain_source"])
        original = rules._normalize_logic
        operations = []

        def counted(*args, **kwargs):
            result = original(*args, **kwargs)
            # 只观察真实 add/strip 运算；parse 和 metadata 恢复的 keep 校验照常执行。
            if kwargs.get("no_resolve", "keep") != "keep":
                operations.append((kwargs["no_resolve"], args[0], args[1], result))
            return result

        for purpose in ("block", "direct", "proxy"):
            for mode in ("add", "keep", "strip"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    flag = ",no-resolve" if mode != "strip" else ""
                    conjunction = "AND,((DOMAIN-KEYWORD,中文),(IP-CIDR,192.0.2.0/24" + flag + "),(SRC-IP-CIDR,198.51.100.0/24))"
                    values = [conjunction, "DOMAIN,keep.example.com", "DOMAIN-KEYWORD,中文",
                              "NOT,((DOMAIN-KEYWORD,中文))", "OR,((DOMAIN-KEYWORD,中文),(NETWORK,udp))",
                              "IP-CIDR,203.0.113.0/24" + flag, "SRC-IP-CIDR,198.51.100.0/24"]
                    if mode == "keep":
                        values += [unmarked, "IP-CIDR,203.0.113.0/24"]
                    records = {}
                    for value in values:
                        kind, _, payload = value.partition(",")
                        options = ["no-resolve"] if kind == "IP-CIDR" and payload.endswith(",no-resolve") else []
                        if options:
                            payload = payload.removesuffix(",no-resolve")
                        records[value] = [[kind, payload, options, False, False, kind in {"AND", "NOT", "OR"},
                                           "mihomo" if kind in {"AND", "DOMAIN", "DOMAIN-KEYWORD", "NOT", "OR"} else "surge"]]
                    wanted_rules = {rules.Rule(row[0], row[1], tuple(row[2]), *row[3:])
                                    for entries in records.values() for row in entries}

                    def expected(group):
                        texts = native_keyword_expected(group, purpose, mode)
                        if mode == "keep":
                            extra = {"fin.txt": [unmarked.replace("SRC-IP-CIDR,", "SRC-IP,"), "IP-CIDR,203.0.113.0/24"],
                                     "fin-surge.txt": [unmarked.replace("SRC-IP-CIDR,", "SRC-IP,"), "IP-CIDR,203.0.113.0/24"],
                                     "fin-qx.txt": ["IP-CIDR,203.0.113.0/24,LIST"],
                                     "fin.yaml": ["  - " + json.dumps(unmarked, ensure_ascii=False), '  - "IP-CIDR,203.0.113.0/24"']}
                            for name, additions in extra.items():
                                body = texts[name].splitlines()[2 if name == "fin.yaml" else 1:] + additions
                                def order(line):
                                    kind = (json.loads(line[4:]) if name == "fin.yaml" else line).partition(",")[0]
                                    return kind.startswith(("IP-", "SRC-IP")), kind, len(line), line
                                texts[name] = f"# {group} rules: {len(body)}\n" + ("payload:\n" if name == "fin.yaml" else "") + "".join(line + "\n" for line in sorted(body, key=order))
                        texts["fin.yaml"] = "\n".join(
                            line + " # rconvert-rule-v1 " + json.dumps(records[json.loads(line[4:])], separators=(',', ':'))
                            if line.startswith("  - ") else line for line in texts["fin.yaml"].splitlines()) + "\n"
                        return texts

                    parsed, messages = rules.parse(source, purpose=purpose)
                    self.assertEqual(messages, [])
                    operations.clear()
                    with patch("rules._normalize_logic", counted), patch("formats.datetime") as clock:
                        clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                        standalone, _ = render("parent", rules.normalize(parsed), purpose=purpose, no_resolve=mode)
                    self.assertEqual(standalone, expected("parent"))
                    self.assertEqual(len(operations), 0 if mode == "keep" else 4)
                    configs = [{"name": group, "purpose": purpose, "no_resolve": mode,
                                "sources": ["input.yaml" if group == "parent" else "parent/fin.yaml"], "whitelist": []}
                               for group in ("parent", "child")]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "input.yaml").write_text(source, encoding="utf-8")
                    parent_bytes = {}
                    for phase in ("same-round", "disk-only", "repeat"):
                        if phase == "disk-only":
                            (root / "input.yaml").unlink()
                            (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        groups = ("parent", "child") if phase == "same-round" else ("child",)
                        operations.clear()
                        with patch("rules._normalize_logic", counted), contextlib.redirect_stderr(io.StringIO()), patch("formats.datetime") as clock:
                            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(outputs, {root / group / name: text for group in groups
                                                   for name, text in expected(group).items()})
                        for group in groups:
                            restored, messages = rules.parse(outputs[root / group / "fin.yaml"], purpose=purpose)
                            self.assertEqual(messages, [])
                            self.assertEqual(set(restored), wanted_rules)
                            self.assertEqual(len(restored), len(wanted_rules))
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode("utf-8") for path, text in outputs.items()})
                        if phase == "same-round":
                            parent_bytes = {path: path.read_bytes() for path in outputs if path.parent.name == "parent"}
                        else:
                            self.assertFalse((root / "input.yaml").exists())
                            self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)
                        self.assertEqual(len(operations), 0 if mode == "keep" else 7 if phase == "same-round" else 3,
                                         (purpose, mode, phase, operations))

    def test_r22_same_round_twelve_products_publish_and_disk_only_reimport(self):
        from tests.test_formats import NATIVE_KEYWORD_SOURCE, native_keyword_expected, native_keyword_skips

        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'keep', 'strip'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['input.yaml'], 'whitelist': []},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['parent/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'input.yaml').write_text(NATIVE_KEYWORD_SOURCE, encoding='utf-8')
                    old = {}
                    for group in ('parent', 'child'):
                        (root / group).mkdir()
                        for name in NAMES:
                            path = root / group / name
                            old[path] = f'old {group} {name}\n'.encode()
                            path.write_bytes(old[path])
                    for disk_only in (False, True):
                        before = {path: path.read_bytes() for path in old}
                        groups = ('child',) if disk_only else ('parent', 'child')
                        if disk_only:
                            (root / 'input.yaml').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            self.assertFalse((root / 'input.yaml').exists())
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        expected = {root / group / name: text for group in groups
                                    for name, text in native_keyword_expected(group, purpose, mode).items()}
                        self.assertEqual(generated_texts(outputs), expected)
                        self.assertEqual(stderr.getvalue().splitlines(), [f'{group} {key}: {count}'
                                         for group in groups for key, count in sorted(native_keyword_skips(purpose).items())])
                        self.assertEqual({path: path.read_bytes() for path in old}, before)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: value.encode("utf-8") for path, value in outputs.items()})
                        self.assertEqual({path: generated_text(path.read_text(encoding="utf-8")).encode("utf-8") if path.name == "fin.yaml" else path.read_bytes() for path in expected},
                                         {path: text.encode('utf-8') for path, text in expected.items()})
                        if disk_only:
                            self.assertEqual({path: path.read_bytes() for path in before if path.parent.name == 'parent'},
                                             {path: data for path, data in before.items() if path.parent.name == 'parent'})

    def test_r22_generated_whitelist_and_invalid_input_protect_old_bytes(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'keep', 'strip'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['white.yaml'], 'whitelist': []},
                               {'name': 'consumer', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source.yaml'], 'whitelist': ['white/fin.yaml']}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'white.yaml').write_text('payload:\n  - DOMAIN-KEYWORD,中文\n', encoding='utf-8')
                    (root / 'source.yaml').write_text('payload:\n  - DOMAIN-KEYWORD,中文\n  - DOMAIN-KEYWORD,中文广告\n  - DOMAIN,keep.example.com\n', encoding='utf-8')
                    def expected(group):
                        white = group == 'white'
                        bodies = {'fin.txt': ['DOMAIN-KEYWORD,中文'] if white else ['DOMAIN,keep.example.com'],
                                  'fin-qx.txt': ['HOST-KEYWORD,中文,LIST'] if white else ['HOST,keep.example.com,LIST'],
                                  'fin.yaml': ['  - "DOMAIN-KEYWORD,中文"'] if white else ['  - "DOMAIN,keep.example.com"'],
                                  'fin-surge.txt': ['DOMAIN-KEYWORD,中文'] if white else [],
                                  'fin-surge-ds.txt': [] if white else ['keep.example.com']}
                        output = {name: f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '') +
                                  ''.join(line + '\n' for line in body) for name, body in bodies.items()}
                        output['fin-adb.txt'] = (
                            f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
                            '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n' +
                            ('! Total count: 1\n/(?s-i:\\A.*中文.*\\z)/\n' if white else
                             '! Total count: 2\n@@/(?s-i:\\A.*中文.*\\z)/\n0.0.0.0 keep.example.com\n') if purpose == 'block' else
                            f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
                            '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n'
                            '! Total count: 0\n! No AdBlock rules for non-advertising group.\n')
                        return output
                    for disk_only in (False, True):
                        if disk_only:
                            (root / 'white.yaml').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        groups = ('consumer',) if disk_only else ('white', 'consumer')
                        self.assertEqual(generated_texts(outputs), {root / group / name: text for group in groups
                                                   for name, text in expected(group).items()})
                        messages = ([] if disk_only else ['white fin-adb.txt:DOMAIN-KEYWORD: 1'] if purpose != 'block' else [])
                        if not disk_only:
                            messages += ['white fin-surge-ds.txt:DOMAIN-KEYWORD: 1']
                        if purpose != 'block':
                            messages += ['consumer fin-adb.txt:DOMAIN: 1']
                        self.assertEqual(stderr.getvalue().splitlines(), messages)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in outputs.items()})
                    old = {root / group / name: (root / group / name).read_bytes()
                           for group in ('white', 'consumer') for name in NAMES}
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'white.yaml').write_text('payload:\n  - DOMAIN-KEYWORD,\n', encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaisesRegex(ValueError, 'No adaptable rules'):
                        publish(generate(root, lambda url: self.fail(url)))
                    self.assertEqual(stderr.getvalue().splitlines(), [f"{root / 'white.yaml'}: line 2: invalid DOMAIN-KEYWORD "])
                    self.assertEqual({path: path.read_bytes() for path in old}, old)

    def test_r22_600_and_1000_layers_keep_keyword_and_twelve_published_texts(self):
        code = '''
import contextlib
import io
import json
import sys
import tempfile
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist
from tests.test_formats import generated_texts
limit = sys.getrecursionlimit()
names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
assert [field.name for field in fields(Rule)] == ['kind', 'value', 'options', 'allow', 'literal_process', 'native_fields', 'domain_source']
leaf = '(AND,((DOMAIN-KEYWORD,中文),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24)))'
matcher = ('(NOT,(' * DEPTH + leaf + '))' * DEPTH)[1:-1]
source = 'payload:\\n  - DOMAIN-KEYWORD,中文\\n  - ' + json.dumps(matcher) + '\\n  - DOMAIN,keep.example.com\\n'
keyword = Rule('DOMAIN-KEYWORD', '中文', domain_source='mihomo')
logical = Rule('NOT', matcher[4:], native_fields=True, domain_source='mihomo')
neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')
assert parse(source, purpose=PURPOSE) == ([keyword, logical, neighbor], [])
assert normalize([keyword, logical, neighbor] * 2) == [neighbor, keyword, logical]
assert parse_whitelist(source) == [keyword, neighbor]
emitted = matcher.replace(',no-resolve', '') if MODE == 'strip' else matcher
def expected(group):
    bodies = {'fin.txt': ['DOMAIN,keep.example.com', 'DOMAIN-KEYWORD,中文'],
              'fin-qx.txt': ['HOST,keep.example.com,LIST', 'HOST-KEYWORD,中文,LIST'],
              'fin.yaml': ['  - "DOMAIN,keep.example.com"', '  - "DOMAIN-KEYWORD,中文"',
                           '  - ' + json.dumps(emitted, ensure_ascii=False)],
              'fin-surge.txt': ['DOMAIN-KEYWORD,中文'], 'fin-surge-ds.txt': ['keep.example.com']}
    output = {name: f'# {group} rules: {len(body)}\\n' + ('payload:\\n' if name == 'fin.yaml' else '') +
              ''.join(line + '\\n' for line in body) for name, body in bodies.items()}
    output['fin-adb.txt'] = (f'[Adblock Plus 2.0]\\n! Title: {group}\\n! Homepage: https://github.com/DoingDog/rconvert\\n'
                            '! Expires: 1 day\\n! License: Inherits upstream licenses\\n! Version: 202610061200\\n' +
                            ('! Total count: 2\\n/(?s-i:\\\\A.*中文.*\\\\z)/\\n0.0.0.0 keep.example.com\\n' if PURPOSE == 'block' else
                             '! Total count: 0\\n! No AdBlock rules for non-advertising group.\\n'))
    return output
skips = {name + ':NOT': 1 for name in names if name != 'fin.yaml'}
skips['fin-surge-ds.txt:DOMAIN-KEYWORD'] = 1
if PURPOSE != 'block':
    skips.update({'fin-adb.txt:DOMAIN': 1, 'fin-adb.txt:DOMAIN-KEYWORD': 1})
with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
    root = Path(directory)
    configs = [{'name': 'parent', 'purpose': PURPOSE, 'no_resolve': MODE, 'sources': ['input.yaml'], 'whitelist': []},
               {'name': 'child', 'purpose': PURPOSE, 'no_resolve': MODE, 'sources': ['parent/fin.yaml'], 'whitelist': []}]
    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
    (root / 'input.yaml').write_text(source, encoding='utf-8')
    old = {}
    for group in ('parent', 'child'):
        (root / group).mkdir()
        for name in names:
            path = root / group / name
            old[path] = f'old {group} {name}\\n'.encode()
            path.write_bytes(old[path])
    for disk_only in (False, True):
        groups = ('child',) if disk_only else ('parent', 'child')
        before = {path: path.read_bytes() for path in old}
        if disk_only:
            (root / 'input.yaml').unlink()
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch('formats.datetime') as clock:
            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
            outputs = generate(root, lambda url: (_ for _ in ()).throw(AssertionError(url)))
        assert generated_texts(outputs) == {root / group / name: text for group in groups for name, text in expected(group).items()}
        assert stderr.getvalue().splitlines() == [f'{group} {key}: {count}' for group in groups for key, count in sorted(skips.items())]
        assert {path: path.read_bytes() for path in old} == before
        publish(outputs)
        assert {path: path.read_bytes() for path in outputs} == {path: text.encode('utf-8') for path, text in outputs.items()}
        if disk_only:
            assert not (root / 'input.yaml').exists()
            assert {path: path.read_bytes() for path in old if path.parent.name == 'parent'} == {path: data for path, data in before.items() if path.parent.name == 'parent'}
        wanted = [neighbor, keyword, Rule('NOT', emitted[4:], native_fields=True, domain_source='mihomo')]
        for group in ('parent', 'child'):
            assert parse((root / group / 'fin.yaml').read_text(encoding='utf-8'), purpose=PURPOSE) == (wanted, [])
assert sys.getrecursionlimit() == limit
'''
        for depth in (600, 1000):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'keep', 'strip'):
                    with self.subTest(depth=depth, purpose=purpose, mode=mode):
                        settings = f'DEPTH = {depth}\nPURPOSE = {purpose!r}\nMODE = {mode!r}\n'
                        result = subprocess.run([sys.executable, '-B', '-c', settings + code], cwd=ROOT,
                                                capture_output=True, text=True, timeout=8)
                        self.assertEqual(result.returncode, 0, result.stderr[-3000:])


class ConstructorGenerateTests(unittest.TestCase):
    def test_constructor_same_round_source_and_disk_only_reimport(self):
        from tests.test_formats import CONSTRUCTOR_SOURCE, constructor_expected, constructor_skips

        for purpose in ("block", "direct", "proxy"):
            for mode in ("add", "keep", "strip"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": "parent", "purpose": purpose, "no_resolve": mode,
                                "sources": ["input.list"], "whitelist": []},
                               {"name": "child", "purpose": purpose, "no_resolve": mode,
                                "sources": ["parent/fin.yaml", "special.list"], "whitelist": []}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "input.list").write_text(CONSTRUCTOR_SOURCE, encoding="utf-8")
                    (root / "special.list").write_text("IP-ASN,UNKNOWN,no-resolve\nGEOIP,UNKNOWN\n", encoding="utf-8")
                    old = {}
                    for group in ("parent", "child"):
                        (root / group).mkdir()
                        for name in NAMES:
                            path = root / group / name
                            old[path] = f"old {group} {name}\n".encode()
                            path.write_bytes(old[path])
                    for disk_only in (False, True):
                        groups = ("child",) if disk_only else ("parent", "child")
                        if disk_only:
                            parent_bytes = {root / "parent" / name: (root / "parent" / name).read_bytes() for name in NAMES}
                            (root / "input.list").unlink()
                            (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch("formats.datetime") as clock:
                            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        expected = {root / group / name: text for group in groups
                                    for name, text in constructor_expected(group, purpose, mode).items()}
                        expected = {path: expected_ordinary_text(value) if path.name == "fin.yaml" else value for path, value in expected.items()}
                        self.assertEqual(generated_texts(outputs), expected)
                        self.assertEqual(stderr.getvalue().splitlines(), [f"{group} {key}: {count}"
                                         for group in groups for key, count in sorted(constructor_skips(purpose).items())])
                        if not disk_only:
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: value.encode("utf-8") for path, value in outputs.items()})
                        self.assertEqual({path: generated_text(path.read_text(encoding="utf-8")).encode("utf-8") if path.name == "fin.yaml" else path.read_bytes() for path in expected},
                                         {path: text.encode("utf-8") for path, text in expected.items()})
                        if disk_only:
                            self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)
                    self.assertEqual({path for path in root.rglob("fin*") if path.is_file()}, set(old))

    def test_constructor_generated_whitelist_and_disk_keep_direction_and_literal_asn(self):
        source = ("IP-ASN,AS13335\npayload:\n  - IP-CIDR6,127.0.0.1/8\n  - GEOIP,LAN\n"
                  "  - IP-ASN,0\n  - IP-SUFFIX,192.0.2.7/24\n  - SRC-IP-ASN,0\n"
                  "  - SRC-GEOIP,LAN\n  - SRC-IP-SUFFIX,192.0.2.7/24\n")
        for purpose in ("block", "direct", "proxy"):
            for mode in ("add", "keep", "strip"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": "white", "purpose": purpose, "no_resolve": mode,
                                "sources": ["white.list"], "whitelist": []},
                               {"name": "consumer", "purpose": purpose, "no_resolve": mode,
                                "sources": ["source.list"], "whitelist": ["white/fin.yaml"]}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "white.list").write_text(source, encoding="utf-8")
                    (root / "source.list").write_text(source + "DOMAIN,keep.example.com\nIP-ASN,00\n", encoding="utf-8")
                    flag = ",no-resolve" if mode == "add" else ""
                    expected = {
                        "fin.txt": "# consumer rules: 2\nDOMAIN,keep.example.com\nIP-ASN,00" + flag + "\n",
                        "fin-qx.txt": "# consumer rules: 2\nHOST,keep.example.com,LIST\nIP-ASN,00,LIST" + flag + "\n",
                        "fin.yaml": '# consumer rules: 2\npayload:\n  - "DOMAIN,keep.example.com"\n  - "IP-ASN,00' + flag + '"\n',
                        "fin-surge.txt": "# consumer rules: 1\nIP-ASN,00" + flag + "\n",
                        "fin-surge-ds.txt": "# consumer rules: 1\nkeep.example.com\n",
                        "fin-adb.txt": ("[Adblock Plus 2.0]\n! Title: consumer\n! Homepage: https://github.com/DoingDog/rconvert\n"
                                        "! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n" +
                                        ("! Total count: 1\n0.0.0.0 keep.example.com\n" if purpose == "block" else
                                         "! Total count: 0\n! No AdBlock rules for non-advertising group.\n")),
                    }
                    expected["fin.yaml"] = expected_ordinary_text(expected["fin.yaml"])
                    for disk_only in (False, True):
                        if disk_only:
                            (root / "white.list").unlink()
                            (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch("formats.datetime") as clock:
                            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual({path.name: text for path, text in generated_texts(outputs).items() if path.parent.name == "consumer"}, expected)
                        self.assertEqual([line for line in stderr.getvalue().splitlines() if line.startswith("consumer ")],
                                         ["consumer fin-adb.txt:IP-ASN: 1", "consumer fin-surge-ds.txt:IP-ASN: 1"] if purpose == "block" else
                                         ["consumer fin-adb.txt:DOMAIN: 1", "consumer fin-adb.txt:IP-ASN: 1", "consumer fin-surge-ds.txt:IP-ASN: 1"])
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: value.encode("utf-8") for path, value in outputs.items()})
                        self.assertEqual({name: generated_text((root / "consumer" / name).read_text(encoding="utf-8")).encode("utf-8") if name == "fin.yaml" else (root / "consumer" / name).read_bytes() for name in NAMES},
                                         {name: text.encode("utf-8") for name, text in expected.items()})

    def test_invalid_constructor_source_warns_and_generated_whitelist_aborts_before_publish(self):
        for matcher, reason in (("IN-NAME,A//B", "invalid value A//B"),
                                ("REMATCH-NAME,/A", "invalid value /A"),
                                ("IP-SUFFIX,192.0.2.7/255.255.255.0", "invalid IP-SUFFIX 192.0.2.7/255.255.255.0"),
                                ("IN-TYPE,MIXED", "invalid IN-TYPE MIXED")):
            with self.subTest(matcher=matcher), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                config = [{"name": "parent", "purpose": "proxy", "no_resolve": "keep",
                           "sources": ["input.list"], "whitelist": []}]
                (root / "rulesets.json").write_text(json.dumps(config), encoding="utf-8")
                (root / "input.list").write_text("payload:\n  - " + matcher + "\n  - DOMAIN,keep.example.com", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(stderr.getvalue().splitlines(), [f"{root / 'input.list'}: line 2: {reason}", "parent fin-adb.txt:DOMAIN: 1"])
                self.assertEqual(generated_text(outputs[root / "parent" / "fin.yaml"]), '# parent rules: 1\npayload:\n  - "DOMAIN,keep.example.com"\n')
                (root / "input.list").write_text("payload:\n  - IN-USER,alice bob", encoding="utf-8")
                config.append({"name": "consumer", "purpose": "proxy", "no_resolve": "keep",
                               "sources": ["good.list"], "whitelist": ["parent/fin.yaml"]})
                (root / "rulesets.json").write_text(json.dumps(config), encoding="utf-8")
                (root / "good.list").write_text("DOMAIN,keep.example.com", encoding="utf-8")
                old = {}
                for group in ("parent", "consumer"):
                    (root / group).mkdir()
                    for name in NAMES:
                        path = root / group / name
                        old[path] = b"old complete product\n"
                        path.write_bytes(old[path])
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, r"parent.*fin.yaml.*line 3"):
                    publish(generate(root, lambda url: self.fail(url)))
                self.assertEqual({path: path.read_bytes() for path in old}, old)

    def test_constructor_deep_twelve_products_publish_and_disk_only_reimport(self):
        code = '''
import contextlib
import io
import json
import sys
import tempfile
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests.test_formats import generated_texts
import re
limit = sys.getrecursionlimit()
names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
assert [field.name for field in fields(Rule)] == ['kind', 'value', 'options', 'allow', 'literal_process', 'native_fields', 'domain_source']
def nest(leaf):
    return '(NOT,(' * DEPTH + leaf + '))' * DEPTH
native = [
    ('(IN-USER,alice bob / <Alice>)', '(IN-USER,alice bob / <Alice>)', False, None),
    ('(IN-NAME,Foo(,ignored))', '(IN-NAME,Foo(,ignored))', False, None),
    ('(REMATCH-NAME,Foo(,ignored))', '(REMATCH-NAME,Foo(,ignored))', False, None),
    ('(PROCESS-NAME,<Foo>)', '(PROCESS-NAME,<Foo>)', True, None),
    ('(PROCESS-PATH,/tmp/<Foo>)', '(PROCESS-PATH,/tmp/<Foo>)', False, None),
    ('(PROCESS-NAME-WILDCARD,*<Foo>*)', '(PROCESS-NAME-WILDCARD,*<Foo>*)', False, None),
    ('(PROCESS-PATH-WILDCARD,/tmp/*<Foo>*)', '(PROCESS-PATH-WILDCARD,/tmp/*<Foo>*)', False, None),
    ('(IN-TYPE,HTTP / SOCKS)', '(IN-TYPE,HTTP / SOCKS)', False, None),
    ('(DSCP,256-319/0//1)', '(DSCP,256-319/0//1)', False, None),
    ('(UID,4294967296-4294967298)', '(UID,4294967296-4294967298)', False, None),
    ('(DST-PORT,0-65535)', '(DST-PORT,0-65535)', False, None),
    ('(SRC-PORT,0-80)', '(SRC-PORT,0-80)', False, None),
    ('(IN-PORT,0-65535)', '(IN-PORT,0-65535)', False, None),
    ('(GEOSITE,geolocation-!cn)', '(GEOSITE,geolocation-!cn)', False, None),
    ('(GEOIP,LAN,no-resolve)', '(GEOIP,LAN,no-resolve)', False, None),
    ('(IP-ASN,00,no-resolve)', '(IP-ASN,00,no-resolve)', False, None),
    ('(IP-SUFFIX,192.0.2.7/24,no-resolve)', '(IP-SUFFIX,192.0.2.7/24,no-resolve)', False, None),
    ('(IP-CIDR6,127.0.0.1/8,no-resolve)', '(IP-CIDR,127.0.0.0/8,no-resolve)', False, None),
    ('(IP-CIDR6,127.0.0.1/8)', '(IP-CIDR,127.0.0.0/8)', False, None),
    ('(IP-ASN,0)', '(IP-ASN,0)', False, None),
    ('(GEOIP,LAN,src,no-resolve)', '(SRC-GEOIP,LAN)', False, 'SRC-GEOIP'),
    ('(IP-ASN,0,src,no-resolve)', '(SRC-IP-ASN,0)', False, 'SRC-IP-ASN'),
    ('(IP-SUFFIX,192.0.2.7/24,src,no-resolve)', '(SRC-IP-SUFFIX,192.0.2.7/24)', False, 'SRC-IP-SUFFIX'),
    ('(IP-CIDR6,127.0.0.1/8,src,no-resolve)', '(SRC-IP-CIDR,127.0.0.0/8)', False, 'SRC-IP-CIDR'),
]
ordinary = [('(IP-ASN,AS13335,no-resolve)', '(IP-ASN,13335,no-resolve)'),
            ('(IP-ASN,UNKNOWN)', '(IP-ASN,UNKNOWN)'), ('(GEOIP,UNKNOWN)', '(GEOIP,UNKNOWN)')]
source = ''.join(nest(leaf)[1:-1] + '\\n' for leaf, _ in ordinary)
source += 'payload:\\n' + ''.join('  - ' + json.dumps(nest(leaf)[1:-1]) + '\\n' for leaf, _, _, _ in native)
source += '  - DOMAIN,neighbor.example.com\\n'
expected_rules = [Rule('NOT', nest(canonical)[5:-1]) for _, canonical in ordinary]
expected_rules += [Rule('NOT', nest(canonical)[5:-1], literal_process=literal, native_fields=True)
                   for _, canonical, literal, _ in native]
expected_rules += [Rule('DOMAIN', 'neighbor.example.com', domain_source='mihomo')]
parsed, warnings = parse(source, purpose=PURPOSE)
assert parsed == expected_rules, (DEPTH, PURPOSE, MODE)
expected_warnings = [f'line {index + 5}: unsupported no-resolve for {warning}'
                     for index, (_, _, _, warning) in enumerate(native) if warning]
assert warnings == expected_warnings, warnings
assert parse_whitelist(source) == [Rule('DOMAIN', 'neighbor.example.com', domain_source='mihomo')]
assert exclude_covered(parsed, parse_whitelist(source)) == expected_rules[:-1]
ordered = sorted(expected_rules, key=lambda rule: (rule.kind, rule.value, rule.options, rule.allow,
                 rule.literal_process, rule.native_fields, rule.domain_source))
assert normalize(parsed * 2) == ordered
assert [Rule(rule.kind, rule.value, rule.options, rule.allow, rule.literal_process,
             rule.native_fields, rule.domain_source) for rule in parsed] == parsed
canonical_leaves = [ordinary[0][1]] + [canonical for _, canonical, _, _ in native]
def emitted(leaf):
    if MODE == 'strip':
        return leaf.replace(',no-resolve', '')
    if MODE == 'add':
        return re.sub(r'\\((GEOIP|IP-ASN|IP-CIDR|IP-SUFFIX),([^()]*)\\)',
                      lambda match: '(' + match[1] + ',' + match[2].replace(',no-resolve', '') + ',no-resolve)', leaf)
    return leaf
effective = {Rule(rule.kind, emitted(rule.value), rule.options, rule.allow, rule.literal_process,
                  rule.native_fields, rule.domain_source) for rule in expected_rules}
restorable = {rule for rule in effective if 'UNKNOWN' not in rule.value}
yaml_matchers = sorted({nest(emitted(leaf))[1:-1] for leaf in canonical_leaves}, key=lambda value: (len(value), value))
def expected(group):
    parent = group == 'parent'
    bodies = {'fin.txt': ['DOMAIN,neighbor.example.com'],
              'fin-qx.txt': ['HOST,neighbor.example.com,LIST'],
              'fin.yaml': ['  - "DOMAIN,neighbor.example.com"'] +
                          ['  - ' + json.dumps(matcher) for matcher in yaml_matchers],
              'fin-surge.txt': [], 'fin-surge-ds.txt': ['neighbor.example.com']}
    result = {name: f'# {group} rules: {len(body)}\\n' + ('payload:\\n' if name == 'fin.yaml' else '') +
                    ''.join(line + '\\n' for line in body) for name, body in bodies.items()}
    result['fin-adb.txt'] = ('[Adblock Plus 2.0]\\n! Title: ' + group + '\\n! Homepage: https://github.com/DoingDog/rconvert\\n'
                            '! Expires: 1 day\\n! License: Inherits upstream licenses\\n! Version: 202610061200\\n' +
                            (('! Total count: 1\\n0.0.0.0 neighbor.example.com\\n' if parent else
                              '! Total count: 2\\n@@|neighbor.example.com|\\n0.0.0.0 neighbor.example.com\\n')
                             if PURPOSE == 'block' else '! Total count: 0\\n! No AdBlock rules for non-advertising group.\\n'))
    return result
def skip_lines(group):
    count = len(effective) - 1 if group == 'parent' else len(restorable) - 1
    skipped = {name + ':NOT': count for name in names if name != 'fin.yaml'}
    if group == 'parent':
        skipped['fin.yaml:NOT'] = 2
    if PURPOSE != 'block':
        skipped['fin-adb.txt:DOMAIN'] = 1
    return [f'{group} {key}: {value}' for key, value in sorted(skipped.items())]
with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
    root = Path(directory)
    configs = [{'name': 'parent', 'purpose': PURPOSE, 'no_resolve': MODE, 'sources': ['input.list'], 'whitelist': []},
               {'name': 'child', 'purpose': PURPOSE, 'no_resolve': MODE, 'sources': ['parent/fin.yaml'],
                'whitelist': ['parent/fin-surge-ds.txt']}]
    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
    (root / 'input.list').write_text(source, encoding='utf-8')
    old = {}
    for group in ('parent', 'child'):
        (root / group).mkdir()
        for name in names:
            path = root / group / name
            old[path] = f'old {group} {name}\\n'.encode()
            path.write_bytes(old[path])
    for disk_only in (False, True):
        groups = ('child',) if disk_only else ('parent', 'child')
        before = {path: path.read_bytes() for path in old}
        if disk_only:
            (root / 'input.list').unlink()
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
            assert not (root / 'input.list').exists()
        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch('formats.datetime') as clock:
            clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
            outputs = generate(root, lambda url: (_ for _ in ()).throw(AssertionError(url)))
        expected_outputs = {root / group / name: text for group in groups for name, text in expected(group).items()}
        assert generated_texts(outputs) == expected_outputs, (DEPTH, PURPOSE, MODE, disk_only)
        messages = ([] if disk_only else [str(root / 'input.list') + ': ' + warning for warning in expected_warnings])
        messages += [line for group in groups for line in skip_lines(group)]
        assert stderr.getvalue().splitlines() == messages, stderr.getvalue()
        assert {path: path.read_bytes() for path in old} == before
        publish(outputs)
        assert {path: path.read_bytes() for path in outputs} == {path: text.encode('utf-8') for path, text in outputs.items()}
        assert {path: text.encode('utf-8') for path, text in generated_texts(outputs).items()} == {path: text.encode('utf-8') for path, text in expected_outputs.items()}
        parent_before = {path: data for path, data in before.items() if path.parent.name == 'parent'}
        if disk_only:
            assert {path: path.read_bytes() for path in parent_before} == parent_before
        reparsed, messages = parse((root / 'parent' / 'fin.yaml').read_text(encoding='utf-8'), purpose=PURPOSE)
        assert set(reparsed) == restorable and len(reparsed) == len(restorable) and messages == [], (messages, DEPTH, PURPOSE, MODE)
        child, messages = parse((root / 'child' / 'fin.yaml').read_text(encoding='utf-8'), purpose=PURPOSE)
        wanted = restorable
        assert set(child) == wanted and len(child) == len(wanted) and messages == []
    assert {path for path in root.rglob('fin*') if path.is_file()} == set(old)
assert sys.getrecursionlimit() == limit
'''
        for depth in (600, 1000):
            for purpose in ("block", "direct", "proxy"):
                for mode in ("add", "keep", "strip"):
                    with self.subTest(depth=depth, purpose=purpose, mode=mode):
                        settings = f"DEPTH = {depth}\nPURPOSE = {purpose!r}\nMODE = {mode!r}\n"
                        result = subprocess.run([sys.executable, "-B", "-c", settings + code], cwd=ROOT,
                                                capture_output=True, text=True, timeout=8)
                        self.assertEqual(result.returncode, 0, result.stderr[-3000:])


class DnsExactHostsGenerateTests(unittest.TestCase):
    def assert_exact_products(self, outputs, root, group, purpose, bodies):
        self.assertEqual({path for path in outputs if path.parent.name == group}, {root / group / name for name in NAMES})
        for name in NAMES:
            lines = outputs[root / group / name].splitlines()
            expected = {expected_ordinary_payload(entry) for entry in bodies[name]} if name == "fin.yaml" else bodies[name]
            if name == "fin-adb.txt":
                self.assertEqual(lines[:5], ["[Adblock Plus 2.0]", f"! Title: {group}",
                                            "! Homepage: https://github.com/DoingDog/rconvert",
                                            "! Expires: 1 day", "! License: Inherits upstream licenses"])
                self.assertRegex(lines[5], r"^! Version: [0-9]{12}$")
                self.assertEqual(lines[6], f"! Total count: {len(expected) if purpose == 'block' else 0}")
                actual = lines[7:]
                if purpose != "block":
                    expected = {"! No AdBlock rules for non-advertising group."}
            else:
                self.assertEqual(lines[0], f"# {group} rules: {len(expected)}")
                if name == "fin.yaml":
                    self.assertEqual(lines[1], "payload:")
                actual = [generated_payload(line[4:]) for line in lines[2:]] if name == "fin.yaml" else lines[1:]
            self.assertEqual(set(actual), expected, (group, name))
            self.assertEqual(len(actual), len(expected), (group, name))

    def test_exact_generated_dns_and_disk_dependencies_cover_all_purposes_and_modes(self):
        from rules import Rule, parse
        from tests.test_rules import DNS_EXACT_DOMAINS

        bodies = {"fin.txt": {f"DOMAIN,{value}" for value in DNS_EXACT_DOMAINS},
                  "fin-qx.txt": {f"HOST,{value},LIST" for value in DNS_EXACT_DOMAINS},
                  "fin.yaml": {f"DOMAIN,{value}" for value in DNS_EXACT_DOMAINS},
                  "fin-adb.txt": {f"0.0.0.0 {value}" for value in DNS_EXACT_DOMAINS},
                  "fin-surge.txt": set(), "fin-surge-ds.txt": set(DNS_EXACT_DOMAINS)}
        for purpose in ("block", "direct", "proxy"):
            for mode in ("keep", "add", "strip"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    action = "REJECT" if purpose == "block" else purpose.upper()
                    source = root / "input.list"
                    source.write_text("".join(f"DOMAIN,{value.upper()}.,{action}\n" for value in DNS_EXACT_DOMAINS), encoding="utf-8")
                    self.assertEqual(parse(source.read_text(encoding="utf-8"), purpose=purpose),
                                     ([Rule("DOMAIN", value) for value in DNS_EXACT_DOMAINS], []))
                    dependency = "fin-adb.txt" if purpose == "block" else "fin.txt"
                    configs = [{"name": "parent", "purpose": purpose, "no_resolve": mode,
                                "sources": ["input.list"], "whitelist": []},
                               {"name": "dependent", "purpose": purpose, "no_resolve": mode,
                                "sources": [f"parent/{dependency}"], "whitelist": []}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    previous = {}
                    for group in ("parent", "dependent", "disk"):
                        (root / group).mkdir()
                        for name in NAMES:
                            path = root / group / name
                            previous[path] = f"old {group} {name}\n".encode()
                            path.write_bytes(previous[path])
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / group / name for group in ("parent", "dependent") for name in NAMES})
                    for group in ("parent", "dependent"):
                        self.assert_exact_products(outputs, root, group, purpose, bodies)
                    header_warnings = [f"{root / 'parent/fin-adb.txt'}: line {line}: invalid rule" for line in range(1, 6)]
                    header_warnings.append(f"{root / 'parent/fin-adb.txt'}: 7 skipped lines; first five shown")
                    expected_stderr = header_warnings if purpose == "block" else [
                        f"{group} fin-adb.txt:DOMAIN: {len(DNS_EXACT_DOMAINS)}" for group in ("parent", "dependent")]
                    self.assertEqual(stderr.getvalue().splitlines(), expected_stderr)
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    publish(outputs)
                    self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in outputs.items()))
                    published = {path: path.read_bytes() for path in outputs}
                    source.unlink()
                    (root / "rulesets.json").write_text(json.dumps([{"name": "disk", "purpose": purpose,
                        "no_resolve": mode, "sources": [f"parent/{dependency}"], "whitelist": []}]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        disk = generate(root, lambda url: self.fail(url))
                    self.assert_exact_products(disk, root, "disk", purpose, bodies)
                    self.assertEqual(stderr.getvalue().splitlines(), header_warnings if purpose == "block" else [
                        f"disk fin-adb.txt:DOMAIN: {len(DNS_EXACT_DOMAINS)}"])
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    self.assertEqual({path: path.read_bytes() for path in previous if path.parent.name == "disk"},
                                     {path: data for path, data in previous.items() if path.parent.name == "disk"})
                    publish(disk)
                    self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in disk.items()))
                    self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_exact_generated_hosts_whitelist_preserves_suffix_and_ip_flags_on_disk(self):
        import warnings
        from tests.test_rules import DNS_EXACT_DOMAINS

        for purpose in ("block", "direct", "proxy"):
            for mode in ("keep", "add", "strip"):
                for hosts in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, hosts=hosts), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        allow = "".join((f"0.0.0.0 {value.upper()}.\n" if hosts else f"DOMAIN,{value.upper()}.,REJECT\n")
                                        for value in DNS_EXACT_DOMAINS)
                        (root / "allow.list").write_text(allow, encoding="utf-8")
                        action = "REJECT" if purpose == "block" else purpose.upper()
                        routes = "".join(f"DOMAIN,{value},{action}\n" for value in DNS_EXACT_DOMAINS)
                        routes += (f"DOMAIN-SUFFIX,localhost,{action}\nDOMAIN-SUFFIX,com,{action}\n"
                                   f"DOMAIN,retained.example.net,{action}\nIP-CIDR,192.0.2.0/24,{action},no-resolve\n"
                                   f"IP-CIDR,198.51.100.0/24,{action}\nSRC-IP-CIDR,127.0.0.0/8,{action}\n"
                                   f"AND,((DOMAIN,logic.example.net),(IP-CIDR,203.0.113.0/24,no-resolve)),{action}\n")
                        (root / "routes.list").write_text(routes, encoding="utf-8")
                        configs = [{"name": "allow", "purpose": "block", "no_resolve": mode,
                                    "sources": ["allow.list"], "whitelist": []},
                                   {"name": "filtered", "purpose": purpose, "no_resolve": mode,
                                    "sources": ["routes.list"], "whitelist": ["allow/fin-adb.txt"]}]
                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                        previous = {}
                        for group in ("allow", "filtered"):
                            (root / group).mkdir()
                            for name in NAMES:
                                path = root / group / name
                                previous[path] = f"old {group} {name}\n".encode()
                                path.write_bytes(previous[path])
                        flag = "" if mode == "strip" else ",no-resolve"
                        unflagged = ",no-resolve" if mode == "add" else ""
                        domains = {"DOMAIN,retained.example.net", "DOMAIN-SUFFIX,localhost", "DOMAIN-SUFFIX,com"}
                        ips = {"IP-CIDR,192.0.2.0/24" + flag, "IP-CIDR,198.51.100.0/24" + unflagged}
                        logic = f"AND,((DOMAIN,logic.example.net),(IP-CIDR,203.0.113.0/24{flag}))"
                        bodies = {"fin.txt": domains | ips | {"SRC-IP,127.0.0.0/8", logic},
                                  "fin.yaml": domains | ips | {"SRC-IP-CIDR,127.0.0.0/8", logic},
                                  "fin-surge.txt": ips | {"SRC-IP,127.0.0.0/8", logic},
                                  "fin-qx.txt": {"HOST,retained.example.net,LIST", "HOST-SUFFIX,localhost,LIST", "HOST-SUFFIX,com,LIST",
                                                 "IP-CIDR,192.0.2.0/24,LIST" + flag, "IP-CIDR,198.51.100.0/24,LIST" + unflagged},
                                  "fin-surge-ds.txt": {"retained.example.net", ".localhost", ".com"},
                                  "fin-adb.txt": {f"@@|{value}|" for value in DNS_EXACT_DOMAINS} |
                                                 {"||localhost^", "||com^", "0.0.0.0 retained.example.net"}}
                        skips = {"fin-adb.txt:AND": 1, "fin-adb.txt:IP-CIDR": 2, "fin-adb.txt:SRC-IP-CIDR": 1,
                                 "fin-qx.txt:AND": 1, "fin-qx.txt:SRC-IP-CIDR": 1, "fin-surge-ds.txt:AND": 1,
                                 "fin-surge-ds.txt:IP-CIDR": 2, "fin-surge-ds.txt:SRC-IP-CIDR": 1}
                        if purpose != "block":
                            skips.update({"fin-adb.txt:DOMAIN": 1, "fin-adb.txt:DOMAIN-SUFFIX": 2})
                        expected_stderr = [f"filtered {key}: {count}" for key, count in sorted(skips.items())]
                        for disk_only in (False, True):
                            if disk_only:
                                (root / "allow.list").unlink()
                                (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                            with warnings.catch_warnings(record=True) as caught, contextlib.redirect_stderr(io.StringIO()) as stderr:
                                warnings.simplefilter("always")
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual([str(warning.message) for warning in caught], [f"line {line}: invalid rule" for line in range(1, 8)])
                            self.assertEqual(stderr.getvalue().splitlines(), expected_stderr)
                            self.assert_exact_products(outputs, root, "filtered", purpose, bodies)
                            self.assertEqual(set(outputs), {root / group / name for group in (("filtered",) if disk_only else ("allow", "filtered")) for name in NAMES})
                            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                            publish(outputs)
                            self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in outputs.items()))
                            previous = {path: path.read_bytes() for path in previous}


class ProcessRendererDependencyGenerateTests(unittest.TestCase):
    def assert_products(self, outputs, root, group, expected):
        from rules import parse

        for name in NAMES:
            text = outputs[root / group / name]
            lines = text.splitlines()
            header = 7 if name == "fin-adb.txt" else 2 if name == "fin.yaml" else 1
            body = {generated_payload(line[4:]) if name == "fin.yaml" else line for line in lines[header:]}
            self.assertEqual(body, expected[name], (group, name))
            self.assertEqual(lines[6] if name == "fin-adb.txt" else lines[0],
                             f"! Total count: {len(body)}" if name == "fin-adb.txt" else
                             f"# {group} rules: {len(body)}")
            self.assertEqual(parse("\n".join(lines[header:]) if name == "fin-adb.txt" else text,
                                   purpose="block")[1], [], (group, name))

    def dependency_matrix(self, source, mode, parent, dependent, expected_skips, whitelist_source=None):
        for dependency in NAMES:
            with self.subTest(mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                configs = [{"name": "source", "purpose": "block", "no_resolve": mode,
                            "sources": ["input.list"], "whitelist": []},
                           {"name": "dependent", "purpose": "block", "no_resolve": mode,
                            "sources": [f"source/{dependency}"], "whitelist": []}]
                if whitelist_source is not None:
                    configs[0]["whitelist"] = ["whitelist.yaml"]
                    (root / "whitelist.yaml").write_text(whitelist_source, encoding="utf-8")
                (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                (root / "input.list").write_text(source, encoding="utf-8")
                previous = {}
                for group in ("source", "dependent"):
                    (root / group).mkdir()
                    for name in NAMES:
                        path = root / group / name
                        path.write_bytes(b"old complete product\n")
                        previous[path] = path.read_bytes()
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(set(outputs), set(previous))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                self.assertEqual([line for line in stderr.getvalue().splitlines() if line.startswith("source ")],
                                 [f"source {key}: {count}" for key, count in sorted(expected_skips.items())])
                if dependency != "fin-adb.txt":
                    self.assertNotIn(": line ", stderr.getvalue())
                self.assertNotIn("frozen", stderr.getvalue())
                self.assert_products(outputs, root, "source", parent)
                self.assert_products(outputs, root, "dependent", dependent[dependency])
                publish(outputs)
                self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in outputs.items()))
                published = {path: path.read_bytes() for path in outputs}
                (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                    disk = generate(root, lambda url: self.fail(url))
                self.assertEqual(set(disk), {root / "dependent" / name for name in NAMES})
                if dependency != "fin-adb.txt":
                    self.assertNotIn(": line ", disk_stderr.getvalue())
                self.assert_products(disk, root, "dependent", dependent[dependency])
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                publish(disk)
                self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in disk.items()))

    def basic_products(self, flag, *, domain=True, ip=True, source_ip=True, domain_source="surge"):
        dest = "IP-CIDR,203.0.113.0/24" + flag
        plain = ({"DOMAIN,keep.example.com"} if domain else set()) | ({dest} if ip else set())
        surge = plain | ({"SRC-IP,127.0.0.0/8"} if source_ip else set())
        return {"fin.txt": surge, "fin-surge.txt": surge - {"DOMAIN,keep.example.com"},
                "fin.yaml": ({expected_domain("DOMAIN", "keep.example.com") if domain_source == "surge" else
                              "DOMAIN,keep.example.com"} if domain else set()) | ({dest} if ip else set()) | ({"SRC-IP-CIDR,127.0.0.0/8"} if source_ip else set()),
                "fin-qx.txt": ({"HOST,keep.example.com,LIST"} if domain else set()) |
                              ({"IP-CIDR,203.0.113.0/24,LIST" + flag} if ip else set()),
                "fin-adb.txt": {"0.0.0.0 keep.example.com"} if domain else set(),
                "fin-surge-ds.txt": {"keep.example.com"} if domain else set()}

    def test_surge_process_and_quoted_regex_preserve_six_generated_dependencies(self):
        from tests.test_formats import expected_process

        values = ("FooApp", "/Applications/Widget.app/", "Game #1", "Game ;1", "Game //1")
        source = "\n".join(f"PROCESS-NAME,'{value}',REJECT" for value in (*values, "Foo*"))
        source += ('\nAND,((DOMAIN-REGEX,"^f{1,2}oo[.]example[.]org$"),(NETWORK,tcp)),REJECT'
                   '\nAND,((PROCESS-NAME-REGEX,"^Game,Inc$"),(NETWORK,tcp)),REJECT'
                   '\nAND,((IP-CIDR,203.0.113.0/24,no-resolve),(SRC-IP-CIDR,127.0.0.0/8)),REJECT'
                   '\nDOMAIN,keep.example.com,REJECT\nIP-CIDR,203.0.113.0/24,REJECT,no-resolve'
                   '\nSRC-IP-CIDR,127.0.0.0/8,REJECT\n')
        names = {"PROCESS-NAME," + (f"'{value}'" if " " in value else value) for value in (*values, "Foo*")}
        regexes = {'AND,((DOMAIN-REGEX,^f{1,2}oo[.]example[.]org$),(NETWORK,tcp))',
                   'AND,((PROCESS-NAME-REGEX,^Game,Inc$),(NETWORK,tcp))'}
        for mode in ("add", "keep", "strip"):
            flag = "" if mode == "strip" else ",no-resolve"
            logic = f"AND,((IP-CIDR,203.0.113.0/24{flag}),(SRC-IP-CIDR,127.0.0.0/8))"
            parent = self.basic_products(flag, domain_source="surge")
            for name in ("fin.txt", "fin-surge.txt"):
                parent[name] |= names | {logic.replace("SRC-IP-CIDR,", "SRC-IP,")}
            parent["fin.yaml"] |= {expected_process(value) for value in values} | regexes | {logic}
            dependent = {}
            for name in NAMES:
                full = name in ("fin.txt", "fin-surge.txt", "fin.yaml")
                body = self.basic_products(flag, domain=name != "fin-surge.txt",
                                           ip=full or name == "fin-qx.txt", source_ip=full, domain_source="qx" if name == "fin-qx.txt" else "surge")
                if name in ("fin.txt", "fin-surge.txt"):
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target] |= names | {logic.replace("SRC-IP-CIDR,", "SRC-IP,")}
                    body["fin.yaml"] |= {expected_process(value) for value in values} | {logic}
                elif name == "fin.yaml":
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target] |= names - {"PROCESS-NAME,Foo*"} | {logic.replace("SRC-IP-CIDR,", "SRC-IP,")}
                    body["fin.yaml"] |= {expected_process(value) for value in values} | regexes | {logic}
                dependent[name] = body
            skips = {"fin.txt:AND": 2, "fin-surge.txt:AND": 2, "fin.yaml:PROCESS-NAME": 1}
            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                skips.update({f"{name}:AND": 3, f"{name}:PROCESS-NAME": 6, f"{name}:SRC-IP-CIDR": 1})
                if name != "fin-qx.txt":
                    skips[f"{name}:IP-CIDR"] = 1
            self.dependency_matrix(source, mode, parent, dependent, skips)

    def test_native_controls_and_ignored_tails_preserve_six_generated_dependencies(self):
        controls = ("\0", "\r", "\n", "\x85", " ", " ", "\x7f", "\x9f", "￾", "￿", "\U0001f642")
        values = {f"{kind},A{char}B" for kind in ("PROCESS-NAME", "PROCESS-PATH",
                  "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX") for char in controls}
        values |= {f"AND,(({kind},A{char}B),(NETWORK,tcp))" for kind in ("PROCESS-NAME", "PROCESS-PATH",
                   "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "DOMAIN-REGEX") for char in controls}
        values |= {f"{operator},(({kind},Foo(,ignored))" + (")" if operator == "NOT" else ",(NETWORK,tcp))")
                   for operator in ("NOT", "AND", "OR") for kind in ("PROCESS-NAME", "PROCESS-PATH", "IN-NAME")}
        source = "payload:\n" + "".join("  - " + json.dumps(value, ensure_ascii=False).translate(
                 {ord(char): "\\u" + format(ord(char), "04x") for char in controls if ord(char) <= 0xffff}) + "\n"
                 for value in sorted(values))
        source += ("  - DOMAIN,keep.example.com\n  - IP-CIDR,203.0.113.0/24,no-resolve\n"
                   "  - SRC-IP-CIDR,127.0.0.0/8\n")
        for mode in ("add", "keep", "strip"):
            flag = "" if mode == "strip" else ",no-resolve"
            parent = self.basic_products(flag, domain_source="mihomo")
            parent["fin.yaml"] |= values
            dependent = {name: self.basic_products(flag, domain=name != "fin-surge.txt",
                         ip=name in ("fin.txt", "fin-surge.txt", "fin.yaml", "fin-qx.txt"),
                         source_ip=name in ("fin.txt", "fin-surge.txt", "fin.yaml"), domain_source="qx" if name == "fin-qx.txt" else "mihomo" if name == "fin.yaml" else "surge") for name in NAMES}
            dependent["fin.yaml"]["fin.yaml"] |= values
            skips = {f"{name}:{kind}": count for name in NAMES if name != "fin.yaml"
                     for kind, count in (("AND", 58), ("OR", 3), ("NOT", 3), ("PROCESS-NAME", 11),
                                         ("PROCESS-PATH", 11), ("PROCESS-NAME-WILDCARD", 11), ("PROCESS-NAME-REGEX", 11))}
            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                skips[f"{name}:SRC-IP-CIDR"] = 1
                if name != "fin-qx.txt":
                    skips[f"{name}:IP-CIDR"] = 1
            self.dependency_matrix(source, mode, parent, dependent, skips)

    def test_native_deep_and_long_matchers_preserve_generated_dependencies(self):
        tails = set()
        for depth, kind, inner in ((1, "PROCESS-NAME", None), (600, "PROCESS-NAME", None),
                                   (1000, "PROCESS-NAME", None), (601, "PROCESS-PATH", None),
                                   (1001, "IN-NAME", None), (600, "PROCESS-NAME", "AND"),
                                   (1000, "PROCESS-NAME", "OR")):
            leaf = f"({kind},Foo(,ignored))"
            if inner:
                leaf = f"({inner},({leaf},(NETWORK,tcp)))"
            tails.add(("(NOT,(" * depth + leaf + "))" * depth)[1:-1])
        matcher = "^(" + "|".join(f"host{index}.example.com" for index in range(1024)) + ")$"
        self.assertEqual(len(matcher), 20397)
        cases = []
        for depth in (600, 1000):
            for long in (False, True):
                for flagged in (False, True):
                    leaf = ("(AND,((IP-CIDR,203.0.113.0/24" + (",no-resolve" if flagged else "") +
                            "),(SRC-IP-CIDR,127.0.0.0/8)," +
                            (f"(PROCESS-NAME-REGEX,{matcher})" if long else "(DOMAIN,x.example.com)") + "))")
                    cases.append((("(NOT,(" * depth + leaf + "))" * depth)[1:-1], long, flagged))
        source = "payload:\n" + "".join("  - " + json.dumps(value) + "\n"
                 for value in sorted(tails | {value for value, _, _ in cases}))
        source += "  - DOMAIN,keep.example.com\n  - DST-PORT,443\n"
        for mode in ("add", "keep", "strip"):
            parent = self.basic_products("", ip=False, source_ip=False, domain_source="mihomo")
            yaml_rules = set(tails) | {"DST-PORT,443"}
            for value, long, flagged in cases:
                expected = value.replace(",no-resolve", "")
                if mode == "add" or mode == "keep" and flagged:
                    expected = expected.replace("IP-CIDR,203.0.113.0/24)", "IP-CIDR,203.0.113.0/24,no-resolve)")
                yaml_rules.add(expected)
                self.assertEqual(expected.count("no-resolve"), int(mode == "add" or mode == "keep" and flagged))
            parent["fin.yaml"] |= yaml_rules
            for name in ("fin.txt", "fin-surge.txt"):
                parent[name].add("DEST-PORT,443")
            dependent = {}
            for name in NAMES:
                body = self.basic_products("", domain=name != "fin-surge.txt", ip=False, source_ip=False, domain_source="qx" if name == "fin-qx.txt" else "mihomo" if name == "fin.yaml" else "surge")
                if name in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target].add("DEST-PORT,443")
                    body["fin.yaml"] |= yaml_rules if name == "fin.yaml" else {"DST-PORT,443"}
                dependent[name] = body
            self.assertEqual(len(yaml_rules) - 1, 15 if mode == "keep" else 11)
            skips = {f"{name}:NOT": len(yaml_rules) - 1 for name in NAMES if name != "fin.yaml"}
            skips.update({f"{name}:DST-PORT": 1 for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")})
            self.dependency_matrix(source, mode, parent, dependent, skips)


class ProcessReviewDependencyGenerateTests(unittest.TestCase):
    assert_products = ProcessRendererDependencyGenerateTests.assert_products
    dependency_matrix = ProcessRendererDependencyGenerateTests.dependency_matrix
    basic_products = ProcessRendererDependencyGenerateTests.basic_products

    def test_parenthesis_backslash_and_regex_complete_dependencies(self):
        field = r'"Game(1)\\"'
        surge_fields = set()
        process_fields = set()
        source = []
        strict = r"PROCESS-NAME-REGEX,(?-i:\A\x{47}\x{61}\x{6D}\x{65}\x{28}\x{31}\x{29}\x{5C}\z)"
        for kind in ("PROCESS-NAME", "USER-AGENT", "DEVICE-NAME"):
            for operator in ("AND", "OR", "NOT"):
                expression = f"(({kind},{field}))" if operator == "NOT" else f"(({kind},{field}),(DOMAIN,x.example.com))"
                surge_fields.add(operator + "," + expression)
                source.append(operator + "," + expression + ",REJECT")
                if kind == "PROCESS-NAME":
                    process_fields.add(f"NOT,(({strict}))" if operator == "NOT" else
                                       f"{operator},(({strict}),({expected_domain('DOMAIN', 'x.example.com')}))")
        regexes = {f"AND,(({kind},^foo[.\\x{{29}}]bar$),(NETWORK,tcp))" for kind in
                   ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX")}
        source.extend(f'AND,(({kind},"^foo[.)]bar$"),(NETWORK,tcp)),REJECT' for kind in
                      ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"))
        source.extend(("DOMAIN,keep.example.com,REJECT", "DST-PORT,443,REJECT"))
        for mode in ("add", "keep", "strip"):
            parent = self.basic_products("", ip=False, source_ip=False, domain_source="surge")
            for target in ("fin.txt", "fin-surge.txt"):
                parent[target] |= surge_fields | {"DEST-PORT,443"}
            parent["fin.yaml"] |= process_fields | regexes | {"DST-PORT,443"}
            dependent = {}
            for name in NAMES:
                body = self.basic_products("", domain=name != "fin-surge.txt", ip=False, source_ip=False, domain_source="qx" if name == "fin-qx.txt" else "surge")
                if name in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target] |= {"DEST-PORT,443"} | (surge_fields if name != "fin.yaml" else {entry for entry in surge_fields if "PROCESS-NAME," in entry})
                    body["fin.yaml"] |= {"DST-PORT,443"} | process_fields | (regexes if name == "fin.yaml" else set())
                dependent[name] = body
            skips = {f"{name}:AND": 3 for name in ("fin.txt", "fin-surge.txt")}
            skips.update({f"fin.yaml:{kind}": 2 for kind in ("AND", "OR", "NOT")})
            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                skips.update({f"{name}:{kind}": count for kind, count in (("AND", 6), ("OR", 3), ("NOT", 3), ("DST-PORT", 1))})
            self.dependency_matrix("\n".join(source), mode, parent, dependent, skips)

    def test_native_user_tail_and_unicode_complete_dependencies(self):
        users = {"NOT,((IN-USER,Foo(,ignored)))", "AND,((IN-USER,Foo(,ignored)),(NETWORK,tcp))",
                 "OR,((IN-USER,Foo(,ignored)),(NETWORK,tcp))"}
        processes = {"PROCESS-NAME,123🙂", "PROCESS-NAME-WILDCARD,123🙂",
                     "PROCESS-PATH,/123/🙂", "PROCESS-PATH-WILDCARD,/123/🙂"}
        source = "payload:\n" + "".join("  - " + json.dumps(value, ensure_ascii=False) + "\n" for value in sorted(users | processes))
        source += "  - DOMAIN,keep.example.com\n  - DST-PORT,443\n"
        surge_processes = {"PROCESS-NAME,123🙂", "PROCESS-NAME,/123/🙂"}
        strict_processes = {
            r"PROCESS-NAME-REGEX,(?-i:\A\x{31}\x{32}\x{33}\x{1F642}\z)",
            r"PROCESS-PATH-REGEX,(?-i:\A\x{2F}\x{31}\x{32}\x{33}\x{2F}\x{1F642}\z)"}
        for mode in ("add", "keep", "strip"):
            parent = self.basic_products("", ip=False, source_ip=False, domain_source="mihomo")
            for target in ("fin.txt", "fin-surge.txt"):
                parent[target] |= surge_processes | {"DEST-PORT,443"}
            parent["fin.yaml"] |= users | processes | {"DST-PORT,443"}
            dependent = {}
            for name in NAMES:
                body = self.basic_products("", domain=name != "fin-surge.txt", ip=False, source_ip=False, domain_source="qx" if name == "fin-qx.txt" else "mihomo" if name == "fin.yaml" else "surge")
                if name in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target] |= {"DEST-PORT,443"} | surge_processes
                    body["fin.yaml"] |= {"DST-PORT,443"} | (users | processes if name == "fin.yaml" else strict_processes)
                dependent[name] = body
            skips = {f"{name}:{kind}": 1 for name in NAMES if name != "fin.yaml" for kind in ("AND", "OR", "NOT")}
            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                skips.update({f"{name}:{kind}": 1 for kind in ("DST-PORT", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD")})
            self.dependency_matrix(source, mode, parent, dependent, skips)

    def test_unsafe_yaml_whitelist_preserves_all_dependencies_without_split_lines(self):
        whitelist = "payload:\n" + "".join("  - " + json.dumps("DOMAIN-REGEX,^A" + char + "B$") + "\n"
                     for char in ("\0", "\r", "\n", "\x85", "\u2028", "\u2029", "\x7f", "\x9f", "\ufffe", "\uffff"))
        source = "DOMAIN,keep.example.com,REJECT\nDST-PORT,443,REJECT\n"
        for mode in ("add", "keep", "strip"):
            parent = self.basic_products("", ip=False, source_ip=False, domain_source="surge")
            for target in ("fin.txt", "fin-surge.txt"):
                parent[target].add("DEST-PORT,443")
            parent["fin.yaml"].add("DST-PORT,443")
            dependent = {}
            for name in NAMES:
                body = self.basic_products("", domain=name != "fin-surge.txt", ip=False, source_ip=False, domain_source="qx" if name == "fin-qx.txt" else "surge")
                if name in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target].add("DEST-PORT,443")
                    body["fin.yaml"].add("DST-PORT,443")
                dependent[name] = body
            skips = {f"{name}:DST-PORT": 1 for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")}
            skips["fin-adb.txt:DOMAIN-REGEX"] = 10
            self.dependency_matrix(source, mode, parent, dependent, skips, whitelist_source=whitelist)


class ProcessRendererRound2DependencyGenerateTests(unittest.TestCase):
    assert_products = ProcessRendererDependencyGenerateTests.assert_products
    dependency_matrix = ProcessRendererDependencyGenerateTests.dependency_matrix
    basic_products = ProcessRendererDependencyGenerateTests.basic_products

    def process_dependencies(self, selected, omitted=()):
        from collections import Counter
        from tests.test_formats import expected_process

        values, surge, strict = set(), set(), set()
        counts, surge_skips = Counter(), Counter()
        for kind, value, operator in selected:
            leaf = f"{kind},{value}"
            matcher = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))"
            values.add(matcher)
            counts[operator or kind] += 1
            if (kind, value, operator) in omitted:
                surge_skips[operator or kind] += 1
                continue
            field = f"'{value}'" if value != value.strip() else value
            leaf = f"PROCESS-NAME,{field}"
            surge.add(leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(PROTOCOL,TCP))")
            leaf = expected_process(value)
            strict.add(leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))")
        source = "payload:\n" + "".join("  - " + json.dumps(value, ensure_ascii=False) + "\n" for value in sorted(values))
        source += "  - DOMAIN,keep.example.com\n  - DST-PORT,443\n  - IP-CIDR,203.0.113.0/24,no-resolve\n  - SRC-IP-CIDR,127.0.0.0/8\n"
        for mode in ("add", "keep", "strip"):
            flag = "" if mode == "strip" else ",no-resolve"
            parent = self.basic_products(flag, domain_source="mihomo")
            for name in ("fin.txt", "fin-surge.txt"):
                parent[name] |= surge | {"DEST-PORT,443"}
            parent["fin.yaml"] |= values | {"DST-PORT,443"}
            dependent = {}
            for name in NAMES:
                full = name in ("fin.txt", "fin-surge.txt", "fin.yaml")
                body = self.basic_products(flag, domain=name != "fin-surge.txt", ip=full or name == "fin-qx.txt", source_ip=full, domain_source="qx" if name == "fin-qx.txt" else "mihomo" if name == "fin.yaml" else "surge")
                if full:
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target] |= surge | {"DEST-PORT,443"}
                    body["fin.yaml"] |= {"DST-PORT,443"} | (values if name == "fin.yaml" else strict)
                dependent[name] = body
            skips = {f"{name}:{kind}": count for name in ("fin.txt", "fin-surge.txt") for kind, count in surge_skips.items()}
            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                skips.update({f"{name}:{kind}": count for kind, count in counts.items()})
                skips.update({f"{name}:DST-PORT": 1, f"{name}:SRC-IP-CIDR": 1})
                if name != "fin-qx.txt":
                    skips[f"{name}:IP-CIDR"] = 1
            self.dependency_matrix(source, mode, parent, dependent, skips)

    def test_native_boundary_whitespace_preserves_generated_dependency_scope(self):
        selected = []
        for kind in ("PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"):
            for char in ("\t", "\xa0", " ", " ", "　"):
                values = ("123" + char, char + "123", "12" + char + "3") if "NAME" in kind else ("/123/" + char, "/12" + char + "/3")
                selected.extend((kind, value, operator) for value in values for operator in ("", "AND", "OR", "NOT"))
        self.process_dependencies(selected)

    def test_dotless_wildcard_preserves_generated_dependency_scope(self):
        selected = [(kind, ("123" if "NAME" in kind else "/123/") + scalar, operator)
                    for kind in ("PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD")
                    for scalar in ("ı", "İ") for operator in ("", "AND", "OR", "NOT")]
        omitted = [item for item in selected if item[0].endswith("-WILDCARD") and item[1].endswith("İ")]
        self.process_dependencies(selected, omitted)

    def test_regex_comma_spaces_preserve_generated_dependency_scope(self):
        from collections import Counter

        patterns = ((r"^f{1, 2}oo[.]example[.]org$", r"^f{1\x{2C} 2}oo[.]example[.]org$"),
                    (r"^[a, b][.]example$", r"^[a\x{2C} b][.]example$"),
                    (r"^a ,b$", r"^a \x{2C}b$"),
                    (r"(?x)^f{1, 2}oo$", r"(?x)^f{1\x{2C} 2}oo$"))
        source, regexes, counts = [], set(), Counter()
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for pattern, expected in (*patterns, (r"^(?<n>a ,b)\k<n>$", r"^(?<n>a \x{2C}b)\k<n>$")):
                for operator in (("",) if "?<n>" in pattern else ("AND", "OR", "NOT")):
                    field = '"' + pattern.replace("\\", "\\\\") + '"'
                    leaf = f"{kind},{field}"
                    source.append((leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))") + ",REJECT")
                    leaf = f"{kind},{expected}"
                    regexes.add(leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))")
                    counts[operator or kind] += 1
        source.extend(("DOMAIN,keep.example.com,REJECT", "DST-PORT,443,REJECT", "IP-CIDR,203.0.113.0/24,REJECT,no-resolve", "SRC-IP-CIDR,127.0.0.0/8,REJECT"))
        for mode in ("add", "keep", "strip"):
            flag = "" if mode == "strip" else ",no-resolve"
            parent = self.basic_products(flag, domain_source="surge")
            for target in ("fin.txt", "fin-surge.txt"):
                parent[target].add("DEST-PORT,443")
            parent["fin.yaml"] |= regexes | {"DST-PORT,443"}
            dependent = {}
            for name in NAMES:
                full = name in ("fin.txt", "fin-surge.txt", "fin.yaml")
                body = self.basic_products(flag, domain=name != "fin-surge.txt", ip=full or name == "fin-qx.txt", source_ip=full, domain_source="qx" if name == "fin-qx.txt" else "surge")
                if full:
                    for target in ("fin.txt", "fin-surge.txt"):
                        body[target].add("DEST-PORT,443")
                    body["fin.yaml"] |= {"DST-PORT,443"} | (regexes if name == "fin.yaml" else set())
                dependent[name] = body
            skips = {f"{name}:{kind}": count for name in NAMES if name != "fin.yaml" for kind, count in counts.items()}
            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                skips.update({f"{name}:DST-PORT": 1, f"{name}:SRC-IP-CIDR": 1})
                if name != "fin-qx.txt":
                    skips[f"{name}:IP-CIDR"] = 1
            self.dependency_matrix("\n".join(source), mode, parent, dependent, skips)


class NativeDnsByteGenerateTests(unittest.TestCase):
    def test_nine_modes_mixed_sources_publish_and_disk_only_preserve_byte_language(self):
        from rules import GeneratedRuleError, Rule, parse, parse_whitelist
        from tests.test_formats import dns_regex

        native = ('payload:\n  - DOMAIN-WILDCARD,api-?.example.org\n'
                  '  - DOMAIN-WILDCARD,same-?.mix.org\n  - DOMAIN-WILDCARD,br-[0-9].example.org\n'
                  '  - DOMAIN-KEYWORD,İΟΣ\n  - DOMAIN,keep.example.net\n'
                  '  - IP-CIDR,192.0.2.0/24,no-resolve\n  - SRC-IP-CIDR,198.51.100.0/24\n')
        routes = ('payload:\n  - DOMAIN,api-a.example.org\n  - DOMAIN,api-ı.example.org\n'
                  '  - DOMAIN,same-a.mix.org\n  - DOMAIN,same-ı.mix.org\n'
                  '  - DOMAIN,retained.example.net\n  - IP-CIDR,203.0.113.0/24,no-resolve\n')
        records = [Rule('DOMAIN-WILDCARD', value, domain_source='mihomo') for value in
                   ('api-?.example.org', 'same-?.mix.org', 'br-[0-9].example.org')]
        records += [Rule('DOMAIN-KEYWORD', 'İΟΣ', domain_source='mihomo'),
                    Rule('DOMAIN', 'keep.example.net', domain_source='mihomo')]
        records += [Rule('DOMAIN-WILDCARD', 'same-?.mix.org', domain_source=source)
                    for source in ('surge', 'qx')]
        native_patterns = {'api-?.example.org': r'/(?s-i:\Aapi\-[\x00-\x7f]\.example\.org\z)/',
                           'same-?.mix.org': r'/(?s-i:\Asame\-[\x00-\x7f]\.mix\.org\z)/'}
        ordinary = r'/^same\-.\.mix\.org$/'
        keyword = r'/(?s-i:\A.*iοσ.*\z)/'
        ordered = lambda body: sorted(set(body), key=lambda line: (line.partition(',')[0], len(line), line))

        def expected(group, purpose, mode, white=False):
            flag = ',no-resolve' if mode != 'strip' else ''
            ip = 'IP-CIDR,' + ('203.0.113.0/24' if white else '192.0.2.0/24') + flag
            exact = ('api-ı.example.org', 'same-ı.mix.org', 'retained.example.net') if white else ('keep.example.net',)
            typed = ordered(['DOMAIN,' + value for value in exact] + [ip] + ([] if white else
                            ['DOMAIN-WILDCARD,same-?.mix.org', 'SRC-IP,198.51.100.0/24']))
            qx = ordered(['HOST,' + value + ',LIST' for value in exact] + [ip.partition(',')[0] + ',' + ip.partition(',')[2].replace(flag, '') + ',LIST' + flag] + ([] if white else
                         ['HOST-WILDCARD,api-?.example.org,LIST', 'HOST-WILDCARD,same-?.mix.org,LIST', 'HOST-KEYWORD,İΟΣ,LIST']))
            identities = ([Rule('DOMAIN', value, domain_source='mihomo') for value in exact] if white else records) + [Rule('IP-CIDR', ip.split(',')[1], ('no-resolve',) if flag else ())]
            if not white:
                identities.append(Rule('SRC-IP-CIDR', '198.51.100.0/24'))
            payloads = {}
            for rule in identities:
                payload = (r'DOMAIN-REGEX,^same\-.\.mix\.org\.?$' if rule.kind == 'DOMAIN-WILDCARD' and rule.domain_source == 'surge' else
                           rule.kind + ',' + rule.value + (',' + ','.join(rule.options) if rule.options else ''))
                scalar = '  - ' + json.dumps(payload, ensure_ascii=False)
                payloads.setdefault(scalar, []).append([rule.kind, rule.value, list(rule.options), rule.allow,
                                                       rule.literal_process, rule.native_fields, rule.domain_source])
            def yaml_order(line):
                kind, _, value = json.loads(line[4:]).partition(',')
                return kind.startswith(('IP-', 'SRC-IP')), 1 if kind.startswith(('IP-', 'SRC-IP')) else 0, kind, len(line), line
            yaml = [scalar + ' # rconvert-rule-v1 ' + json.dumps(sorted(payloads[scalar]), ensure_ascii=True, separators=(',', ':'))
                    for scalar in sorted(payloads, key=yaml_order)]
            dns = (['0.0.0.0 ' + value for value in exact] +
                   (['@@' + line for line in (*native_patterns.values(), ordinary, keyword)] + ['@@|keep.example.net|'] if white else
                    [*native_patterns.values(), ordinary, keyword])) if purpose == 'block' else []
            bodies = {'fin.txt': typed, 'fin-surge.txt': [line for line in typed if not line.startswith('DOMAIN,')],
                      'fin-qx.txt': qx, 'fin.yaml': yaml, 'fin-surge-ds.txt': sorted(exact, key=lambda value: (len(value), value)),
                      'fin-adb.txt': sorted(set(dns), key=lambda line: (not line.startswith('@@'), len(line), line))}
            texts = {name: f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '') + ''.join(line + '\n' for line in body)
                     for name, body in bodies.items() if name != 'fin-adb.txt'}
            texts['fin-adb.txt'] = ('[Adblock Plus 2.0]\n! Title: ' + group + '\n! Homepage: https://github.com/DoingDog/rconvert\n'
                '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610081200\n' +
                f'! Total count: {len(bodies["fin-adb.txt"])}\n' + ''.join(line + '\n' for line in bodies['fin-adb.txt']) +
                ('! No AdBlock rules for non-advertising group.\n' if purpose != 'block' else ''))
            return texts, identities

        def expected_skips(group, purpose):
            if group == 'white':
                skipped = {'fin-adb.txt:IP-CIDR': 1, 'fin-surge-ds.txt:IP-CIDR': 1}
                skipped.update({'fin-adb.txt:DOMAIN-WILDCARD': 1} if purpose == 'block' else
                               {'fin-adb.txt:DOMAIN': 3})
            else:
                skipped = {'fin.txt:DOMAIN-KEYWORD': 1, 'fin.txt:DOMAIN-WILDCARD': 3,
                           'fin-adb.txt:IP-CIDR': 1, 'fin-adb.txt:SRC-IP-CIDR': 1,
                           'fin-adb.txt:DOMAIN-WILDCARD': 1 if purpose == 'block' else 5,
                           'fin-qx.txt:DOMAIN-WILDCARD': 1, 'fin-qx.txt:SRC-IP-CIDR': 1,
                           'fin-surge.txt:DOMAIN-KEYWORD': 1, 'fin-surge.txt:DOMAIN-WILDCARD': 3,
                           'fin-surge-ds.txt:DOMAIN-KEYWORD': 1, 'fin-surge-ds.txt:DOMAIN-WILDCARD': 5,
                           'fin-surge-ds.txt:IP-CIDR': 1, 'fin-surge-ds.txt:SRC-IP-CIDR': 1}
                if purpose != 'block':
                    skipped.update({'fin-adb.txt:DOMAIN': 1, 'fin-adb.txt:DOMAIN-KEYWORD': 1})
            return [f'{group} {key}: {count}' for key, count in sorted(skipped.items())]

        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('keep', 'add', 'strip'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['native.yaml', 'surge.list', 'qx.list'], 'whitelist': []},
                               {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['parent/fin.yaml'], 'whitelist': []},
                               {'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['routes.yaml', 'surge-routes.list', 'qx-routes.list'], 'whitelist': ['parent/fin.yaml']}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    for name, text in {'native.yaml': native, 'routes.yaml': routes,
                                       'surge.list': 'DOMAIN-WILDCARD,same-?.mix.org\n', 'qx.list': 'HOST-WILDCARD,same-?.mix.org\n',
                                       'surge-routes.list': 'DOMAIN,same-ı.mix.org\n', 'qx-routes.list': 'HOST,same-ı.mix.org\n'}.items():
                        (root / name).write_text(text, encoding='utf-8')
                    previous = DomainSetSingleLabelGenerateTests().seed(root, ('parent', 'source', 'white'))
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as stderr:
                        clock.now.return_value = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(stderr.getvalue().splitlines(), sum(
                        (expected_skips(group, purpose) for group in ('parent', 'source', 'white')), []))
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    for group in ('parent', 'source', 'white'):
                        texts, identities = expected(group, purpose, mode, group == 'white')
                        self.assertEqual({path.name: text for path, text in outputs.items() if path.parent.name == group}, texts)
                        restored, messages = parse(texts['fin.yaml'], purpose=purpose)
                        self.assertEqual(messages, [])
                        self.assertEqual(set(restored), set(identities))
                        self.assertEqual(len(restored), len(identities))
                        self.assertEqual(set(parse_whitelist(texts['fin.yaml'])), {Rule(rule.kind, rule.value, domain_source=rule.domain_source) for rule in identities})
                    if purpose == 'block':
                        matcher = dns_regex(native_patterns['api-?.example.org'])
                        self.assertIsNone(matcher.fullmatch('api-ı.example.org'))
                        self.assertIsNotNone(matcher.fullmatch('api-a.example.org'))
                    publish(outputs)
                    published = {path: path.read_bytes() for path in outputs}
                    parent = {path: data for path, data in published.items() if path.parent.name == 'parent'}
                    for name in ('native.yaml', 'surge.list', 'qx.list'):
                        (root / name).unlink()
                    (root / 'rulesets.json').unlink()
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        clock.now.return_value = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(disk_stderr.getvalue().splitlines(),
                                     expected_skips('source', purpose) + expected_skips('white', purpose))
                    self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name != 'parent'})
                    self.assertEqual({path: path.read_bytes() for path in parent}, parent)
                    publish(disk)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    adjacent = root / 'parent/fin.yaml'
                    original = adjacent.read_bytes()
                    adjacent.write_bytes(original.replace(b'api-?.example.org', b'wrong.example.org', 1))
                    with self.assertRaises(GeneratedRuleError):
                        publish(generate(root, lambda url: self.fail(url)))
                    adjacent.write_bytes(original)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    actual_replace = os.replace
                    count = 0
                    def failed_replace(source, destination):
                        nonlocal count
                        count += 1
                        if count == 2:
                            raise OSError('native DNS controlled publication failure')
                        return actual_replace(source, destination)
                    with patch('generate.os.replace', side_effect=failed_replace), self.assertRaisesRegex(OSError, 'controlled publication failure'):
                        publish({path: 'changed\n' + text for path, text in disk.items()})
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    publish(disk)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)


class DomainProvenanceGenerateTests(unittest.TestCase):
    def test_converted_yaml_whitelist_preserves_six_outputs_on_same_round_and_disk(self):
        from rules import Rule, parse_whitelist

        cases = (("DOMAIN-KEYWORD,ad", "ad"),
                 ("DOMAIN-WILDCARD,api-*.example.com", r"^api\-.*\.example\.com\.?$"),
                 ("DOMAIN-WILDCARD,api-[0-9].example.com", r"^api\-[0-9]\.example\.com\.?$"))
        for matcher, regex in cases:
            for mode in ("keep", "add", "strip"):
                for disk_only in (False, True):
                    with self.subTest(matcher=matcher, mode=mode, disk=disk_only), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        configs = [{"name": "allow", "purpose": "block", "no_resolve": mode,
                                    "sources": ["allow.list"], "whitelist": []},
                                   {"name": "filtered", "purpose": "block", "no_resolve": mode,
                                    "sources": ["block.list"], "whitelist": ["allow/fin.yaml"]}]
                        (root / "allow.list").write_text(matcher + ",REJECT\nDOMAIN,safe.example.org,REJECT", encoding="utf-8")
                        (root / "block.list").write_text(
                            "DOMAIN,ads.example.com,REJECT\nDOMAIN,api-7.example.com,REJECT\n"
                            "DOMAIN,keep.example.net,REJECT\nDOMAIN,safe.example.org,REJECT\n"
                            "IP-CIDR,192.0.2.0/24,REJECT,no-resolve", encoding="utf-8")
                        (root / "rulesets.json").write_text(json.dumps(configs[:1] if disk_only else configs), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            outputs = generate(root, lambda url: self.fail(url))
                        expected_skips = (["allow fin-qx.txt:DOMAIN-WILDCARD: 1"] if "[0-9]" in matcher else [])
                        expected_skips.append(f"allow fin-surge-ds.txt:{matcher.split(',', 1)[0]}: 1")
                        if not disk_only:
                            expected_skips += ["filtered fin-adb.txt:IP-CIDR: 1", "filtered fin-surge-ds.txt:IP-CIDR: 1"]
                        self.assertEqual(stderr.getvalue().splitlines(), expected_skips)
                        allow_text = outputs[root / "allow/fin.yaml"]
                        self.assertEqual(set(parse_whitelist(allow_text)),
                                         {Rule("DOMAIN", "safe.example.org"), Rule(*matcher.split(",", 1))})
                        if disk_only:
                            publish(outputs)
                            (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual(stderr.getvalue(), "filtered fin-adb.txt:IP-CIDR: 1\nfiltered fin-surge-ds.txt:IP-CIDR: 1\n")
                        flag = "" if mode == "strip" else ",no-resolve"
                        domains = {"DOMAIN,ads.example.com", "DOMAIN,api-7.example.com", "DOMAIN,keep.example.net"}
                        if matcher.startswith("DOMAIN-KEYWORD,"):
                            domains.remove("DOMAIN,ads.example.com")
                        elif "*" in matcher:
                            domains.remove("DOMAIN,api-7.example.com")
                        dns_regex = "^.*ad.*$" if matcher.startswith("DOMAIN-KEYWORD,") else regex.replace(r"\.?$", "$")
                        ip = "IP-CIDR,192.0.2.0/24" + flag
                        expected = {"fin.txt": domains | {ip}, "fin.yaml": {expected_ordinary_payload(entry) for entry in domains} | {ip},
                                    "fin-qx.txt": {"HOST,ads.example.com,LIST", "HOST,api-7.example.com,LIST",
                                                   "HOST,keep.example.net,LIST", "IP-CIDR,192.0.2.0/24,LIST" + flag},
                                    "fin-surge.txt": {ip},
                                    "fin-surge-ds.txt": {"ads.example.com", "api-7.example.com", "keep.example.net"},
                                    "fin-adb.txt": {"0.0.0.0 ads.example.com", "0.0.0.0 api-7.example.com", "0.0.0.0 keep.example.net",
                                                    "@@|safe.example.org|", "@@/" + regex + "/"}}
                        expected["fin-qx.txt"] = {"HOST," + entry.split(",", 1)[1] + ",LIST" for entry in domains} | {"IP-CIDR,192.0.2.0/24,LIST" + flag}
                        expected["fin-surge-ds.txt"] = {entry.split(",", 1)[1] for entry in domains}
                        expected["fin-adb.txt"] = {"0.0.0.0 " + entry.split(",", 1)[1] for entry in domains} | {"@@|safe.example.org|", "@@/" + dns_regex + "/"}
                        self.assertEqual(set(outputs), {root / group / name for group in
                                         (("filtered",) if disk_only else ("allow", "filtered")) for name in NAMES})
                        for name, expected_body in expected.items():
                            lines = outputs[root / "filtered" / name].splitlines()
                            header = 7 if name == "fin-adb.txt" else 2 if name == "fin.yaml" else 1
                            body = {generated_payload(line[4:]) if name == "fin.yaml" else line for line in lines[header:]}
                            self.assertEqual(body, expected_body, name)
                            self.assertEqual(lines[6] if name == "fin-adb.txt" else lines[0],
                                             f"! Total count: {len(expected_body)}" if name == "fin-adb.txt"
                                             else f"# filtered rules: {len(expected_body)}", name)
                        publish(outputs)
                        self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in outputs.items()))
                        previous = {root / group / name: (root / group / name).read_bytes()
                                    for group in ("allow", "filtered") for name in NAMES}
                        (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(stderr.getvalue(), "filtered fin-adb.txt:IP-CIDR: 1\nfiltered fin-surge-ds.txt:IP-CIDR: 1\n")
                        self.assertEqual(set(disk), {root / "filtered" / name for name in NAMES})
                        for name in NAMES:
                            start = 6 if name == "fin-adb.txt" else 0
                            self.assertEqual(disk[root / "filtered" / name].splitlines()[start:],
                                             outputs[root / "filtered" / name].splitlines()[start:])
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        self.assertEqual((root / "allow/fin.yaml").read_text(encoding="utf-8"), allow_text)
                        publish(disk)
                        self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in disk.items()))

    def test_domain_sources_follow_actual_generated_file_on_same_round_and_disk(self):
        from rules import Rule, parse

        source = ("DOMAIN-KEYWORD,ads,REJECT\nDOMAIN-WILDCARD,api-*.example.com,REJECT\n"
                  "DOMAIN-WILDCARD,api-[0-9].example.com,REJECT\nDOMAIN,keep.example.org,REJECT\n"
                  "IP-CIDR,192.0.2.0/24,REJECT,no-resolve\n")
        native = ("payload:\n  - DOMAIN-KEYWORD,ads\n  - DOMAIN-WILDCARD,api-*.example.com\n"
                  "  - DOMAIN-WILDCARD,api-[0-9].example.com\n")
        for mode in ("keep", "add", "strip"):
            for dependency in ("fin.txt", "fin-surge.txt", "fin.yaml", "fin-qx.txt", "fin-surge-ds.txt"):
                with self.subTest(mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": "parent", "purpose": "block", "no_resolve": mode,
                                "sources": ["surge.list", "native.yaml", "qx.list"], "whitelist": []},
                               {"name": "dependent", "purpose": "block", "no_resolve": mode,
                                "sources": [f"parent/{dependency}"], "whitelist": []}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "surge.list").write_text(source, encoding="utf-8")
                    (root / "native.yaml").write_text(native, encoding="utf-8")
                    (root / "qx.list").write_text("HOST-KEYWORD,ads,REJECT\n", encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / group / name for group in ("parent", "dependent") for name in NAMES})
                    parent_yaml = {generated_payload(line[4:]) for line in outputs[root / "parent/fin.yaml"].splitlines()[2:]}
                    self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com", parent_yaml)
                    self.assertIn("DOMAIN-KEYWORD,ads", parent_yaml)
                    self.assertTrue(any(line.startswith("DOMAIN-REGEX,") and "ads" in line for line in parent_yaml))
                    self.assertEqual(stderr.getvalue().count("parent fin.txt:DOMAIN-WILDCARD: 2\n"), 1)
                    self.assertIn("parent fin.txt:DOMAIN-KEYWORD: 1\n", stderr.getvalue())
                    self.assertIn("parent fin-adb.txt:DOMAIN-WILDCARD: 1\n", stderr.getvalue())
                    self.assertNotIn(": line ", stderr.getvalue())
                    text = outputs[root / "parent" / dependency]
                    parsed, messages = parse(text, purpose="block")
                    self.assertEqual(messages, [])
                    flag = "" if mode == "strip" else ",no-resolve"
                    ip = "IP-CIDR,192.0.2.0/24" + flag
                    wildcard = "DOMAIN-WILDCARD,api-*.example.com"
                    digit = "DOMAIN-WILDCARD,api-[0-9].example.com"
                    regexes = {"DOMAIN-REGEX,ads", r"DOMAIN-REGEX,^api\-.*\.example\.com\.?$",
                               r"DOMAIN-REGEX,^api\-[0-9]\.example\.com\.?$"}
                    exact = {"DOMAIN,keep.example.org"} if dependency != "fin-surge.txt" else set()
                    regular = {"DOMAIN-KEYWORD,ads", wildcard}
                    expected_rules = ({ip} | regular | {digit} | exact if dependency in ("fin.txt", "fin-surge.txt")
                                      else {ip} | regular | {digit} | exact if dependency == "fin.yaml"
                                      else {ip} | regular | exact if dependency == "fin-qx.txt" else exact)
                    expected_parsed = set()
                    for line in expected_rules:
                        kind, value = line.split(",", 1)
                        options = ("no-resolve",) if kind == "IP-CIDR" and flag else ()
                        value = value.removesuffix(",no-resolve")
                        domain_source = ("mihomo" if dependency == "fin.yaml" and kind in
                                         {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"} else "qx" if
                                         dependency == "fin-qx.txt" and kind.startswith("DOMAIN") else "surge")
                        expected_parsed.add(Rule(kind, value, options, domain_source=domain_source))
                    if dependency == "fin.yaml":
                        expected_parsed = {Rule("DOMAIN", "keep.example.org"), Rule("IP-CIDR", "192.0.2.0/24", ("no-resolve",) if flag else ())}
                        expected_parsed |= {Rule(*entry.split(",", 1), domain_source=source)
                                            for source in ("surge", "mihomo") for entry in regular | {digit}}
                        expected_parsed.add(Rule("DOMAIN-KEYWORD", "ads", domain_source="qx"))
                    self.assertEqual(set(parsed), expected_parsed)
                    self.assertEqual(len(parsed), len(expected_parsed))
                    surge_body = expected_rules
                    yaml_body = ({ip} | exact | regexes if dependency in ("fin.txt", "fin-surge.txt")
                                 else {ip} | regular | {digit} | regexes | exact if dependency == "fin.yaml" else expected_rules)
                    if dependency != "fin-qx.txt":
                        yaml_body = {expected_ordinary_payload(entry) for entry in yaml_body}
                    qx_body = {"HOST,keep.example.org,LIST"} if exact else set()
                    if dependency != "fin-surge-ds.txt":
                        qx_body |= {"HOST-KEYWORD,ads,LIST", "HOST-WILDCARD,api-*.example.com,LIST",
                                    "IP-CIDR,192.0.2.0/24,LIST" + flag}
                    dns_body = {"0.0.0.0 keep.example.org"} if exact else set()
                    if dependency != "fin-surge-ds.txt":
                        dns_body |= {r"/^.*ads.*$/", r"/^api\-.*\.example\.com$/"}
                    if dependency in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                        dns_body.add(r"/^api\-[0-9]\.example\.com$/")
                    if dependency == 'fin.yaml':
                        dns_body.update({r'/(?s-i:\Aapi\-.*\.example\.com\z)/', r'/(?s-i:\A.*ads.*\z)/'})
                    bodies = {"fin.txt": surge_body, "fin-surge.txt": surge_body - exact,
                              "fin.yaml": yaml_body, "fin-qx.txt": qx_body, "fin-adb.txt": dns_body,
                              "fin-surge-ds.txt": {"keep.example.org"} if exact else set()}
                    for name, expected_body in bodies.items():
                        lines = outputs[root / "dependent" / name].splitlines()
                        header = 7 if name == "fin-adb.txt" else 2 if name == "fin.yaml" else 1
                        actual_body = {generated_payload(line[4:]) if name == "fin.yaml" else line for line in lines[header:]}
                        self.assertEqual(actual_body, expected_body, name)
                        self.assertEqual(lines[6] if name == "fin-adb.txt" else lines[0],
                                         f"! Total count: {len(expected_body)}" if name == "fin-adb.txt"
                                         else f"# dependent rules: {len(expected_body)}", name)
                    publish(outputs)
                    published = {path: path.read_bytes() for path in outputs}
                    (root / "rulesets.json").write_text(json.dumps([{
                        "name": "dependent", "purpose": "block", "no_resolve": mode,
                        "sources": [f"parent/{dependency}"], "whitelist": [],
                    }]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk), {root / "dependent" / name for name in NAMES})
                    self.assertNotIn(": line ", disk_stderr.getvalue())
                    for name in NAMES:
                        self.assertEqual(disk[root / "dependent" / name].splitlines()[6 if name == "fin-adb.txt" else 0:],
                                         outputs[root / "dependent" / name].splitlines()[6 if name == "fin-adb.txt" else 0:])
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    publish(disk)
                    self.assertTrue(all(path.read_bytes() == text.encode("utf-8") for path, text in disk.items()))

    def test_native_whitelist_does_not_erase_surge_or_unknown_qx_sources(self):
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "allow", "purpose": "block", "no_resolve": "keep",
                     "sources": ["allow.yaml"], "whitelist": []},
                    {"name": "filtered", "purpose": "block", "no_resolve": mode,
                     "sources": ["surge.list", "qx.list", "native.yaml"], "whitelist": ["allow/fin.yaml"]},
                ]), encoding="utf-8")
                (root / "allow.yaml").write_text("payload:\n  - DOMAIN-KEYWORD,ad", encoding="utf-8")
                (root / "surge.list").write_text("DOMAIN-KEYWORD,ads,REJECT\nDOMAIN,keep.example.org,REJECT", encoding="utf-8")
                (root / "qx.list").write_text("HOST-KEYWORD,ads,REJECT", encoding="utf-8")
                (root / "native.yaml").write_text("payload:\n  - DOMAIN-KEYWORD,ads", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertIn("DOMAIN-KEYWORD,ads\n", outputs[root / "filtered/fin.txt"])
                self.assertIn("HOST-KEYWORD,ads,LIST\n", outputs[root / "filtered/fin-qx.txt"])
                yaml = [generated_payload(line[4:]) for line in outputs[root / "filtered/fin.yaml"].splitlines()[2:]]
                self.assertIn("DOMAIN-KEYWORD,ads", yaml)
                self.assertTrue(any(line.startswith("DOMAIN-REGEX,") and "ads" in line for line in yaml))
                publish(outputs)
                (root / "rulesets.json").write_text(json.dumps([{
                    "name": "filtered", "purpose": "block", "no_resolve": mode,
                    "sources": ["surge.list", "qx.list", "native.yaml"], "whitelist": ["allow/fin.yaml"],
                }]), encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    disk = generate(root, lambda url: self.fail(url))
                for name in NAMES:
                    self.assertEqual(disk[root / "filtered" / name].splitlines()[6 if name == "fin-adb.txt" else 0:],
                                     outputs[root / "filtered" / name].splitlines()[6 if name == "fin-adb.txt" else 0:])


class DomainSetSuffixGenerateTests(unittest.TestCase):
    three_domains = {
        "fin.txt": ("DOMAIN,example.org", "DOMAIN-SUFFIX,com", "DOMAIN-SUFFIX,example.net"),
        "fin-qx.txt": ("HOST,example.org,LIST", "HOST-SUFFIX,com,LIST", "HOST-SUFFIX,example.net,LIST"),
        "fin.yaml": ("DOMAIN,example.org", "DOMAIN-SUFFIX,com", "DOMAIN-SUFFIX,example.net"),
        "fin-adb.txt": ("0.0.0.0 example.org", "||com^", "||example.net^"),
        "fin-surge.txt": (),
        "fin-surge-ds.txt": (".com", "example.org", ".example.net"),
    }

    def _assert_group(self, outputs, root, group, purpose, bodies):
        from rules import Rule, parse

        self.assertEqual({path for path in outputs if path.parent.name == group},
                         {root / group / name for name in NAMES})
        for name in NAMES:
            text = outputs[root / group / name]
            lines = text.splitlines()
            body = tuple(expected_ordinary_payload(entry) for entry in bodies[name]) if name == "fin.yaml" else bodies[name]
            count = len(body)
            if name == "fin.yaml":
                self.assertEqual(lines[1], "payload:")
                actual = [generated_payload(line[4:]) for line in lines[2:]]
            elif name == "fin-adb.txt":
                if purpose != "block":
                    body, count = ("! No AdBlock rules for non-advertising group.",), 0
                self.assertEqual(lines[6], f"! Total count: {count}")
                actual = lines[7:]
            else:
                actual = lines[1:]
            if name != "fin-adb.txt":
                self.assertEqual(lines[0], f"# {group} rules: {count}")
            self.assertEqual(set(actual), set(body), (group, name))
            self.assertEqual(len(actual), len(body), (group, name))
            if name in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-surge.txt", "fin-surge-ds.txt"):
                parsed, messages = parse(text, purpose=purpose)
                expected = {Rule(*line.split(",", 1), domain_source="qx" if name == "fin-qx.txt" else "surge") for line in bodies["fin.txt"]}
                self.assertEqual(set(parsed), set() if name == "fin-surge.txt" else expected)
                self.assertEqual(messages, [])

    def _seed_previous(self, root, groups):
        previous = {}
        for group in groups:
            (root / group).mkdir()
            for name in NAMES:
                path = root / group / name
                previous[path] = b"previous version\n"
                path.write_bytes(previous[path])
        return previous

    def _publish_updated(self, outputs, previous):
        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
        publish(outputs)
        for path, text in outputs.items():
            self.assertEqual(path.read_bytes(), text.encode("utf-8"))
            self.assertNotEqual(path.read_bytes(), previous[path])

    def test_single_label_suffix_survives_same_round_and_disk_domain_set_dependencies(self):
        from rules import Rule, parse

        source = ".com\nexample.org\n.example.net\n"
        expected = [Rule("DOMAIN-SUFFIX", "com"), Rule("DOMAIN", "example.org"),
                    Rule("DOMAIN-SUFFIX", "example.net")]
        for purpose in ("direct", "block", "proxy"):
            for mode in ("keep", "add", "strip"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": group, "purpose": purpose, "no_resolve": mode,
                                "sources": entries, "whitelist": []}
                               for group, entries in (("parent", ["domains.list"]),
                                                      ("dependent", ["parent/fin-surge-ds.txt"]))]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "domains.list").write_text(source, encoding="utf-8")
                    self.assertEqual(parse(source, purpose=purpose), (expected, []))
                    previous = self._seed_previous(root, ("parent", "dependent"))
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), set(previous))
                    for group in ("parent", "dependent"):
                        self._assert_group(outputs, root, group, purpose, self.three_domains)
                    skips = [] if purpose == "block" else [
                        f"{group} fin-adb.txt:{kind}: {count}"
                        for group in ("parent", "dependent")
                        for kind, count in (("DOMAIN", 1), ("DOMAIN-SUFFIX", 2))]
                    self.assertEqual(stderr.getvalue().splitlines(), skips)
                    self._publish_updated(outputs, previous)
                    published = {path: path.read_bytes() for path in outputs}
                    disk_previous = self._seed_previous(root, ("disk",))
                    (root / "rulesets.json").write_text(json.dumps([{
                        "name": "disk", "purpose": purpose, "no_resolve": mode,
                        "sources": ["parent/fin-surge-ds.txt"], "whitelist": [],
                    }]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk_outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk_outputs), set(disk_previous))
                    self._assert_group(disk_outputs, root, "disk", purpose, self.three_domains)
                    self.assertEqual(disk_stderr.getvalue().splitlines(), [] if purpose == "block" else [
                        "disk fin-adb.txt:DOMAIN: 1", "disk fin-adb.txt:DOMAIN-SUFFIX: 2"])
                    self._publish_updated(disk_outputs, disk_previous)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    self.assertEqual({path for path in root.rglob("fin*") if path.is_file()},
                                     set(published) | set(disk_outputs))

    def test_invalid_domain_set_entries_warn_without_freezing_legal_neighbors(self):
        for purpose in ("direct", "block", "proxy"):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                configs = [{"name": group, "purpose": purpose, "no_resolve": "keep",
                            "sources": entries, "whitelist": []}
                           for group, entries in (("parent", ["domains.list"]),
                                                  ("dependent", ["parent/fin-surge-ds.txt"]))]
                (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                source = root / "domains.list"
                source.write_text(".com\ncom\n.-bad\nexample.org\n.com,REJECT\n..net\n.example.net\n",
                                  encoding="utf-8")
                previous = self._seed_previous(root, ("parent", "dependent"))
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(set(outputs), set(previous))
                for group in ("parent", "dependent"):
                    self._assert_group(outputs, root, group, purpose, self.three_domains)
                messages = [f"{source}: line {line}: {reason}" for line, reason in (
                    (2, "invalid rule"), (3, "invalid rule"), (5, "unknown type .COM"), (6, "invalid rule"))]
                if purpose != "block":
                    messages += [f"{group} fin-adb.txt:{kind}: {count}"
                                 for group in ("parent", "dependent")
                                 for kind, count in (("DOMAIN", 1), ("DOMAIN-SUFFIX", 2))]
                self.assertEqual(stderr.getvalue().splitlines(), messages)
                self._publish_updated(outputs, previous)

    def test_domain_set_whitelist_keeps_suffix_direction_and_updates_fully_covered_groups(self):
        for purpose in ("direct", "block", "proxy"):
            for coverage in ("suffix", "exact", "all"):
                with self.subTest(purpose=purpose, coverage=coverage), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    exact = coverage == "exact"
                    allow = "ads.example.com" if exact else ".com"
                    routes = (".com\nads.example.com\n.child.com\n" if coverage == "all" else
                              "DOMAIN-SUFFIX,com\nDOMAIN,ads.example.com\nDOMAIN-SUFFIX,child.com\n"
                              "DOMAIN,notcom.org\nDOMAIN,example.org\n")
                    bodies = {
                        "fin.txt": () if coverage == "all" else
                                   (("DOMAIN-SUFFIX,com",) if exact else ()) + ("DOMAIN,notcom.org", "DOMAIN,example.org"),
                        "fin-qx.txt": () if coverage == "all" else
                                      (("HOST-SUFFIX,com,LIST",) if exact else ()) + ("HOST,notcom.org,LIST", "HOST,example.org,LIST"),
                        "fin.yaml": () if coverage == "all" else
                                    (("DOMAIN-SUFFIX,com",) if exact else ()) + ("DOMAIN,notcom.org", "DOMAIN,example.org"),
                        "fin-adb.txt": (("@@|ads.example.com|", "||com^", "0.0.0.0 notcom.org", "0.0.0.0 example.org") if exact else
                                        ("@@||com^",) if coverage == "all" else ("@@||com^", "0.0.0.0 notcom.org", "0.0.0.0 example.org")),
                        "fin-surge.txt": (),
                        "fin-surge-ds.txt": () if coverage == "all" else
                                            ((".com",) if exact else ()) + ("notcom.org", "example.org"),
                    }
                    configs = [
                        {"name": "allow", "purpose": purpose, "no_resolve": "keep",
                         "sources": ["allow.list"], "whitelist": []},
                        {"name": "filtered", "purpose": purpose, "no_resolve": "keep",
                         "sources": ["routes.list"], "whitelist": ["allow/fin-surge-ds.txt"]},
                        {"name": "dependent", "purpose": purpose, "no_resolve": "keep",
                         "sources": ["filtered/fin-surge-ds.txt"], "whitelist": []},
                    ]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "allow.list").write_text(allow + "\n", encoding="utf-8")
                    (root / "routes.list").write_text(routes, encoding="utf-8")
                    previous = self._seed_previous(root, ("allow", "filtered", "dependent"))
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), set(previous))
                    self.assertEqual(outputs[root / "allow" / "fin-surge-ds.txt"], f"# allow rules: 1\n{allow}\n")
                    self._assert_group(outputs, root, "filtered", purpose, bodies)
                    dependent = dict(bodies)
                    dependent["fin-adb.txt"] = () if coverage == "all" else (
                        (("||com^",) if exact else ()) + ("0.0.0.0 notcom.org", "0.0.0.0 example.org"))
                    self._assert_group(outputs, root, "dependent", purpose, dependent)
                    counts = (("allow", (("DOMAIN", 1),) if exact else (("DOMAIN-SUFFIX", 1),)),
                              ("filtered", () if coverage == "all" else
                               (("DOMAIN", 2), ("DOMAIN-SUFFIX", 1)) if exact else (("DOMAIN", 2),)),
                              ("dependent", () if coverage == "all" else
                               (("DOMAIN", 2), ("DOMAIN-SUFFIX", 1)) if exact else (("DOMAIN", 2),)))
                    self.assertEqual(stderr.getvalue().splitlines(), [] if purpose == "block" else [
                        f"{group} fin-adb.txt:{kind}: {count}" for group, entries in counts for kind, count in entries])
                    self._publish_updated(outputs, previous)
                    disk_previous = self._seed_previous(root, ("disk",))
                    (root / "rulesets.json").write_text(json.dumps([{
                        "name": "disk", "purpose": purpose, "no_resolve": "keep",
                        "sources": ["routes.list"], "whitelist": ["allow/fin-surge-ds.txt"],
                    }]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk_outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk_outputs), set(disk_previous))
                    self._assert_group(disk_outputs, root, "disk", purpose, bodies)
                    self.assertEqual(disk_stderr.getvalue().splitlines(), [] if purpose == "block" else [
                        f"disk fin-adb.txt:{kind}: {count}" for kind, count in counts[1][1]])
                    self._publish_updated(disk_outputs, disk_previous)


class SurgeEscapedFieldDependencyGenerateTests(unittest.TestCase):
    def test_encoded_fields_survive_generation_publish_and_disk_reimport(self):
        from rules import parse

        values = ("Game\\", "Game\\\\", "Game\\\\\\", "'Game\\\\", '"Game\'Inc"', "'Game\"Inc'", '"Game\\', "'Game\\")
        expressions = []
        for leaf in ("PROCESS-NAME", "PROCESS-PATH"):
            for value in values:
                payload = "/Applications/" + value if leaf == "PROCESS-PATH" else value
                expressions.extend((operator, f"(({leaf},{payload}),(IP-CIDR,192.0.2.0/24,no-resolve),"
                                    "(SRC-IP-CIDR,198.51.100.0/24))") for operator in ("AND", "OR"))
                expressions.append(("NOT", f"((NOT,(({leaf},{payload}))))"))
        native_lines = [f"{kind},{value}" for kind, value in expressions]
        document = "payload:\n" + "".join("  - " + json.dumps(line) + "\n" for line in native_lines)
        document += "  - DOMAIN-KEYWORD,keep\n  - NETWORK,tcp\n"
        original, messages = parse(document, purpose="proxy")
        self.assertEqual(messages, [])
        self.assertEqual(len(original), len(expressions) + 2)
        for mode in ("keep", "add", "strip"):
            expected = {line.replace(",no-resolve", "") if mode == "strip" else line for line in native_lines}
            expected.add("NETWORK,tcp")
            for dependency in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                with self.subTest(mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{"name": "source", "purpose": "proxy", "no_resolve": mode,
                                "sources": ["native.yaml"], "whitelist": []},
                               {"name": "dependent", "purpose": "proxy", "no_resolve": mode,
                                "sources": [f"source/{dependency}"], "whitelist": []}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    (root / "native.yaml").write_text(document, encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / group / name
                                                   for group in ("source", "dependent") for name in NAMES})
                    publish(outputs)
                    for group in ("source", "dependent"):
                        yaml = (root / group / "fin.yaml").read_text(encoding="utf-8")
                        neighbors = {"DOMAIN-KEYWORD,keep"} if group == "source" or dependency == "fin.yaml" else set()
                        visible = expected if group == "source" or dependency == "fin.yaml" else {"NETWORK,tcp"}
                        self.assertEqual({generated_payload(line[4:]) for line in yaml.splitlines()[2:]}, visible | neighbors)
                        parsed, warnings = parse(yaml, purpose="proxy")
                        self.assertEqual(warnings, [])
                        self.assertTrue(all(rule.native_fields for rule in parsed if rule.kind in {"AND", "OR", "NOT"}))
                        for name in ("fin.txt", "fin-surge.txt"):
                            text = (root / group / name).read_text(encoding="utf-8")
                            self.assertEqual(text.splitlines()[0], f"# {group} rules: 1")
                            self.assertNotIn("DOMAIN-KEYWORD,keep", text)
                            if group == "source" or dependency == "fin.yaml":
                                for kind in ("AND", "OR", "NOT"):
                                    self.assertIn(f"{group} {name}:{kind}:", stderr.getvalue())
                        for name in NAMES:
                            self.assertEqual((root / group / name).read_bytes(), outputs[root / group / name].encode("utf-8"))
                    self.assertNotIn(": line ", stderr.getvalue())
                    (root / "rulesets.json").write_text(json.dumps([
                        {"name": "disk", "purpose": "proxy", "no_resolve": mode,
                         "sources": [f"source/{dependency}"], "whitelist": []},
                    ]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk_outputs = generate(root, lambda url: self.fail(url))
                    publish(disk_outputs)
                    self.assertEqual(set(disk_outputs), {root / "disk" / name for name in NAMES})
                    self.assertEqual({generated_payload(line[4:]) for line in
                                      (root / "disk" / "fin.yaml").read_text(encoding="utf-8").splitlines()[2:]},
                                     (expected | {"DOMAIN-KEYWORD,keep"}) if dependency == "fin.yaml" else {"NETWORK,tcp"})
                    self.assertNotIn(": line ", disk_stderr.getvalue())


class LiteralQuoteDependencyGenerateTests(unittest.TestCase):
    def test_native_literal_quotes_survive_surge_and_yaml_dependencies_for_all_modes(self):
        from rules import Rule, parse

        expressions = (
            ('AND', '((PROCESS-NAME,"Game"),(DOMAIN,x.example.com))'),
            ('OR', "((PROCESS-NAME,'Game'),(IP-CIDR,198.51.100.0/24,no-resolve),"
                   "(SRC-IP-CIDR,192.0.2.0/24))"),
            ('NOT', r'((PROCESS-NAME,"Game\Inc"))'),
            ('AND', '((OR,((PROCESS-NAME,"Game"),(DOMAIN,other.example.com))),'
                    '(NOT,((IP-CIDR,203.0.113.0/24))))'),
        )
        for mode, suffix, added in (("keep", ",no-resolve", ""),
                                    ("add", ",no-resolve", ",no-resolve"), ("strip", "", "")):
            expected = (
                expressions[0],
                ('OR', "((PROCESS-NAME,'Game'),(IP-CIDR,198.51.100.0/24" + suffix + "),"
                       "(SRC-IP-CIDR,192.0.2.0/24))"),
                expressions[2],
                ('AND', '((OR,((PROCESS-NAME,"Game"),(DOMAIN,other.example.com))),'
                        '(NOT,((IP-CIDR,203.0.113.0/24' + added + '))))'),
            )
            for dependency in ("fin.txt", "fin-surge.txt", "fin.yaml"):
                with self.subTest(mode=mode, dependency=dependency), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    (root / "rulesets.json").write_text(json.dumps([
                        {"name": "source", "purpose": "proxy", "no_resolve": mode,
                         "sources": ["native.yaml"], "whitelist": []},
                        {"name": "dependent", "purpose": "proxy", "no_resolve": mode,
                         "sources": [f"source/{dependency}"], "whitelist": []},
                    ]), encoding="utf-8")
                    native = "payload:\n  - 'AND,((PROCESS-NAME,\"Game\"),(DOMAIN,x.example.com))'\n"
                    native += "".join(
                        "  - " + json.dumps(f"{kind},{value}") + "\n" for kind, value in expressions[1:]
                    ) + '  - "DOMAIN-KEYWORD,keep"\n  - "NETWORK,tcp"\n'
                    (root / "native.yaml").write_text(native, encoding="utf-8")
                    self.assertEqual(parse(native, purpose="proxy"), (
                        [Rule(kind, value, literal_process=True, native_fields=True,
                                  domain_source="mihomo" if "(DOMAIN," in value else "surge") for kind, value in expressions]
                        + [Rule("DOMAIN-KEYWORD", "keep", domain_source="mihomo"), Rule("NETWORK", "tcp")], [],
                    ))
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(outputs), {root / group / name
                                                   for group in ("source", "dependent") for name in NAMES})
                    publish(outputs)
                    self.assertTrue(all(path.is_file() and path.read_text(encoding="utf-8") == text
                                        for path, text in outputs.items()))
                    for group, values in (("dependent", expected), ("source", expected)):
                        neighbors = {"DOMAIN-KEYWORD,keep"} if group == "source" or dependency == "fin.yaml" else set()
                        values = values if group == "source" or dependency == "fin.yaml" else ()
                        yaml = (root / group / "fin.yaml").read_text(encoding="utf-8")
                        self.assertEqual({generated_payload(line[4:]) for line in yaml.splitlines()[2:]},
                                         {f"{kind},{value}" for kind, value in values}
                                         | {"NETWORK,tcp"} | neighbors)
                        parsed, messages = parse(yaml, purpose="proxy")
                        self.assertEqual(messages, [])
                        self.assertEqual(set(parsed), {
                            Rule(kind, value, literal_process=True, native_fields=True,
                                  domain_source="mihomo" if "(DOMAIN," in value else "surge") for kind, value in values
                        } | {Rule("NETWORK", "tcp") if group == "source" or dependency == "fin.yaml" else Rule("PROTOCOL", "TCP")} |
                            ({Rule("DOMAIN-KEYWORD", "keep", domain_source="mihomo")} if neighbors else set()))
                        for name in ("fin.txt", "fin-surge.txt"):
                            surge = (root / group / name).read_text(encoding="utf-8")
                            self.assertEqual(surge, f"# {group} rules: 1\nPROTOCOL,TCP\n")
                            self.assertNotIn("DOMAIN-KEYWORD,keep", surge)
                            if values:
                                for kind in ("AND", "OR", "NOT"):
                                    self.assertIn(f"{group} {name}:{kind}:", stderr.getvalue())
                        for kind, count in ((("AND", 2), ("OR", 1), ("NOT", 1)) if values else ()):
                            for name in ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                                self.assertIn(f"{group} {name}:{kind}: {count}\n", stderr.getvalue())
                    self.assertNotIn(": line ", stderr.getvalue())
                    self.assertNotIn("no routable rules", stderr.getvalue())
                    (root / "rulesets.json").write_text(json.dumps([
                        {"name": "disk", "purpose": "proxy", "no_resolve": mode,
                         "sources": [f"source/{dependency}"], "whitelist": []},
                    ]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                        disk_outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(set(disk_outputs), {root / "disk" / name for name in NAMES})
                    publish(disk_outputs)
                    self.assertTrue(all(path.is_file() and path.read_text(encoding="utf-8") == text
                                        for path, text in disk_outputs.items()))
                    self.assertEqual((root / "disk" / "fin.yaml").read_text(encoding="utf-8").splitlines()[2:],
                                     (root / "dependent" / "fin.yaml").read_text(encoding="utf-8").splitlines()[2:])
                    self.assertNotIn(": line ", disk_stderr.getvalue())
                    self.assertNotIn("no routable rules", disk_stderr.getvalue())

    def test_unrepresentable_native_quotes_skip_surge_logic_without_losing_yaml_dependency(self):
        from rules import Rule, parse

        invalid = []
        # 用原生字面 * 验证整个逻辑规则的目标 skip，不把可转义的引号判为不可表达。
        for value in ('"Game\'Inc*"', '"Game*\\'):
            invalid.extend((kind, f"((PROCESS-NAME,{value}),(DOMAIN,x.example.com))")
                           for kind in ("AND", "OR"))
            invalid.append(("NOT", f"((PROCESS-NAME,{value}))"))
        invalid.append(("AND", '((OR,((PROCESS-NAME,"Game*\\),(DOMAIN,x.example.com))),'
                               '(DOMAIN,other.example.com))'))
        safe = "OR,((DOMAIN,a.example.com),(DOMAIN,b.example.com))"
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                configs = [{"name": "source", "purpose": "proxy", "no_resolve": mode,
                            "sources": ["native.yaml"], "whitelist": []}] + [
                    {"name": group, "purpose": "proxy", "no_resolve": mode,
                     "sources": [f"source/{name}"], "whitelist": []}
                    for group, name in (("txt", "fin.txt"), ("surge", "fin-surge.txt"), ("yaml", "fin.yaml"))
                ]
                (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                document = "payload:\n" + "".join(
                    "  - " + json.dumps(f"{kind},{value}") + "\n" for kind, value in invalid
                ) + "  - " + json.dumps(safe) + '\n  - "DOMAIN-KEYWORD,keep"\n  - "NETWORK,tcp"\n'
                (root / "native.yaml").write_text(document, encoding="utf-8")
                original = [Rule(kind, value, literal_process=True, native_fields=True,
                                  domain_source="mihomo" if "(DOMAIN," in value else "surge")
                            for kind, value in invalid]
                self.assertEqual(parse(document, purpose="proxy"), (
                    original + [Rule("OR", safe[3:], native_fields=True, domain_source="mihomo"),
                                Rule("DOMAIN-KEYWORD", "keep", domain_source="mihomo"), Rule("NETWORK", "tcp")], [],
                ))
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(set(outputs), {root / group / name
                                               for group in ("source", "txt", "surge", "yaml") for name in NAMES})
                publish(outputs)
                self.assertTrue(all(path.is_file() and path.read_text(encoding="utf-8") == text
                                    for path, text in outputs.items()))
                for group in ("source", "txt", "surge", "yaml"):
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual((root / group / name).read_text(encoding="utf-8"),
                                         f"# {group} rules: 2\n{safe}\nPROTOCOL,TCP\n")
                        for kind, count in (("AND", 3), ("OR", 2), ("NOT", 2)):
                            diagnostic = f"{group} {name}:{kind}:"
                            if group in ("source", "yaml"):
                                self.assertIn(f"{diagnostic} {count}\n", stderr.getvalue())
                            else:
                                self.assertNotIn(diagnostic, stderr.getvalue())
                    yaml = (root / group / "fin.yaml").read_text(encoding="utf-8")
                    expected = {safe if group in ("source", "yaml") else expected_ordinary_payload(safe), "NETWORK,tcp"}
                    if group in ("source", "yaml"):
                        expected |= {f"{kind},{value}" for kind, value in invalid} | {"DOMAIN-KEYWORD,keep"}
                    self.assertEqual({generated_payload(line[4:]) for line in yaml.splitlines()[2:]}, expected)
                    parsed, messages = parse(yaml, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(set(parsed), {
                        Rule("OR", safe[3:], native_fields=group in ("source", "yaml"),
                             domain_source="mihomo" if group in ("source", "yaml") else "surge"),
                        Rule("NETWORK", "tcp") if group in ("source", "yaml") else Rule("PROTOCOL", "TCP"),
                    } | (set(original) | {Rule("DOMAIN-KEYWORD", "keep", domain_source="mihomo")}
                         if group in ("source", "yaml") else set()))
                self.assertNotIn(": line ", stderr.getvalue())
                self.assertNotIn("no routable rules", stderr.getvalue())


class BoundedRegexTailGenerateTests(unittest.TestCase):
    def test_six_products_preserve_bounded_tails_same_round_publish_and_only_disk(self):
        from rules import Rule, parse
        from tests.test_formats import BoundedRegexTailFormatTests
        from tests.test_rules import _quote_matcher

        staging = ROOT / '.tmp'
        staging.mkdir(exist_ok=True)
        for purpose, action in (('block', 'REJECT'), ('proxy', 'PROXY'), ('direct', 'DIRECT')):
            for mode in ('add', 'strip', 'keep'):
                for source in ('ordinary', 'quoted', 'payload', 'rules'):
                    native = source in ('payload', 'rules')
                    cases, inputs = [], []
                    for kind, matcher in (('PROCESS-NAME-REGEX', '^Foo,no-resolve'),
                                          ('PROCESS-PATH-REGEX', '^/tmp/Foo,no-resolve'),
                                          ('DOMAIN-REGEX', '^ads,no-resolve')):
                        field = _quote_matcher(matcher) if source == 'quoted' else matcher
                        for operator in ('AND', 'OR', 'NOT'):
                            raw = (f'(({kind},{field}),(IP-CIDR,192.0.2.0/24,no-resolve,no-resolve),'
                                   '(IP-CIDR,198.51.100.0/24),(SRC-IP-CIDR,203.0.113.0/24))')
                            marked = '' if mode == 'strip' else ',no-resolve'
                            unmarked = ',no-resolve' if mode == 'add' else ''
                            wanted = (f'(({kind},{field}),(IP-CIDR,192.0.2.0/24{marked}),'
                                      f'(IP-CIDR,198.51.100.0/24{unmarked}),(SRC-IP-CIDR,203.0.113.0/24))')
                            if operator == 'NOT':
                                raw, wanted = '((AND,' + raw + '))', '((AND,' + wanted + '))'
                            rule = Rule(operator, wanted, native_fields=native)
                            projected = wanted.replace(field, matcher) if source == 'quoted' else wanted
                            cases.append((rule, operator + ',' + projected))
                            inputs.append(operator + ',' + raw)
                    neighbor_source = 'mihomo' if native else 'surge'
                    document = (source + ':\n' + ''.join('  - ' + json.dumps(item) + '\n' for item in inputs) +
                                '  - DOMAIN,keep.example.com\n' if native else
                                ''.join(item + ',' + action + '\n' for item in inputs) + 'DOMAIN,keep.example.com,' + action + '\n')
                    with self.subTest(purpose=purpose, mode=mode, source=source), tempfile.TemporaryDirectory(dir=staging) as directory:
                        root = Path(directory)
                        configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.list'], 'whitelist': []},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['parent/fin.yaml'], 'whitelist': []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        (root / 'input.list').write_text(document, encoding='utf-8')
                        previous = r25_old_files(root, ('parent', 'child'))
                        expected, diagnostics = {}, []
                        for group in ('parent', 'child'):
                            texts, skipped = BoundedRegexTailFormatTests.products(group, cases, purpose, neighbor_source)
                            expected.update({root / group / name: text for name, text in texts.items()})
                            diagnostics.extend(f'{group} {key}: {count}\n' for key, count in sorted(skipped.items()))
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as messages:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(outputs, expected)
                        self.assertEqual(messages.getvalue(), ''.join(diagnostics))
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        for group in ('parent', 'child'):
                            restored, warnings = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                            self.assertEqual(warnings, [])
                            self.assertEqual(set(restored), {rule for rule, _ in cases} |
                                             {Rule('DOMAIN', 'keep.example.com', domain_source=neighbor_source)})
                            self.assertEqual(len(restored), 10)
                        publish(outputs)
                        published = {path: text.encode('utf-8') for path, text in outputs.items()}
                        self.assertEqual({path: path.read_bytes() for path in outputs}, published)
                        (root / 'input.list').unlink()
                        (root / 'rulesets.json').unlink()
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as disk_messages:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name == 'child'})
                        self.assertEqual(disk_messages.getvalue(), ''.join(line for line in diagnostics if line.startswith('child ')))
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_generated_logical_whitelist_rejection_keeps_all_previous_bytes(self):
        from rules import GeneratedRuleError, Rule
        from tests.test_formats import BoundedRegexTailFormatTests

        staging = ROOT / '.tmp'
        staging.mkdir(exist_ok=True)
        for disk_only in (False, True):
            with self.subTest(disk_only=disk_only), tempfile.TemporaryDirectory(dir=staging) as directory:
                root = Path(directory)
                configs = [{'name': 'parent', 'purpose': 'proxy', 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': []},
                           {'name': 'child', 'purpose': 'proxy', 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': ['parent/fin.yaml']}]
                expression = '((PROCESS-NAME-REGEX,^Foo,no-resolve),(NETWORK,tcp))'
                (root / 'input.list').write_text('AND,' + expression + ',PROXY\nDOMAIN,keep.example.com,PROXY\n', encoding='utf-8')
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                previous = r25_old_files(root, ('parent', 'child'))
                if disk_only:
                    texts, _ = BoundedRegexTailFormatTests.products('parent', [(Rule('AND', expression), 'AND,' + expression)], 'proxy')
                    publish({root / 'parent' / name: text for name, text in texts.items()})
                    (root / 'rulesets.json').unlink()
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    previous.update({root / 'parent' / name: text.encode('utf-8') for name, text in texts.items()})
                with contextlib.redirect_stderr(io.StringIO()) as messages:
                    with self.assertRaisesRegex(GeneratedRuleError, r'Invalid whitelist .*fin.yaml: line 3: unsupported whitelist rule AND'):
                        generate(root, lambda url: self.fail(url))
                self.assertNotIn(': line ', messages.getvalue())
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)


class NativeFieldFix8GenerateTests(unittest.TestCase):
    def test_generated_yaml_dependency_keeps_native_logic_provenance_for_all_modes(self):
        from rules import parse

        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "source", "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["native.yaml"], "whitelist": []},
                    {"name": "dependent", "purpose": "proxy", "no_resolve": mode,
                     "sources": ["source/fin.yaml"], "whitelist": []},
                ]), encoding="utf-8")
                expression = '((DOMAIN-REGEX,"*ads"),(PROCESS-NAME-REGEX,^Game,Inc$))'
                (root / "native.yaml").write_text("rules:\n  - 'AND," + expression + "'\n", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    outputs = generate(root, lambda url: self.fail(url))
                for group in ("source", "dependent"):
                    text = outputs[root / group / "fin.yaml"]
                    self.assertEqual([generated_payload(line[4:]) for line in text.splitlines()[2:]], ["AND," + expression])
                    parsed, messages = parse(text, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertTrue(parsed[0].native_fields)
                    self.assertEqual({path.name for path in outputs if path.parent.name == group}, set(NAMES))
                self.assertNotIn("invalid", stderr.getvalue())


class SourceFieldContinuationGenerateTests(unittest.TestCase):
    _seed_previous = DomainSetSuffixGenerateTests._seed_previous
    _publish_updated = DomainSetSuffixGenerateTests._publish_updated

    def test_literal_user_agent_and_url_regex_survive_six_products_and_disk_dependency(self):
        from rules import Rule, parse

        source = ('USER-AGENT,"Client #1",LIST\n'
                  'USER-AGENT,"Client ;1",LIST\n'
                  'USER-AGENT,"Client //1",LIST\n'
                  'URL-REGEX,"^https://media.example.org/item #1$",PROXY\n')
        expected_rules = [Rule("USER-AGENT", value) for value in
                          ("Client #1", "Client ;1", "Client //1")]
        expected_rules.append(Rule("URL-REGEX", "^https://media.example.org/item #1$"))
        self.assertEqual(parse(source, purpose="proxy"), (expected_rules, []))
        surge = ("URL-REGEX,'^https://media.example.org/item #1$'\n"
                 "USER-AGENT,'Client #1'\nUSER-AGENT,'Client ;1'\nUSER-AGENT,'Client //1'\n")
        bodies = {"fin.txt": surge, "fin-surge.txt": surge,
                  "fin-qx.txt": "USER-AGENT,Client #1,LIST\nUSER-AGENT,Client ;1,LIST\nUSER-AGENT,Client //1,LIST\n",
                  "fin.yaml": "payload:\n", "fin-surge-ds.txt": ""}
        skips = {"fin-adb.txt:URL-REGEX": 1, "fin-adb.txt:USER-AGENT": 3,
                 "fin-qx.txt:URL-REGEX": 1, "fin-surge-ds.txt:URL-REGEX": 1,
                 "fin-surge-ds.txt:USER-AGENT": 3, "fin.yaml:URL-REGEX": 1,
                 "fin.yaml:USER-AGENT": 3}
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                configs = [{"name": group, "purpose": "proxy", "no_resolve": mode,
                            "sources": entries, "whitelist": []}
                           for group, entries in (("cdn", ["input.list"]), ("big-data", ["cdn/fin.txt"]))]
                (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                (root / "input.list").write_text(source, encoding="utf-8")
                previous = self._seed_previous(root, ("cdn", "big-data"))
                for disk_only in (False, True):
                    with self.subTest(disk_only=disk_only):
                        groups = ("big-data",) if disk_only else ("cdn", "big-data")
                        if disk_only:
                            (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                            previous = {root / "big-data" / name: b"stale disk consumer\n" for name in NAMES}
                            for path, content in previous.items():
                                path.write_bytes(content)
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(set(outputs), set(previous))
                        self.assertEqual(stderr.getvalue().splitlines(), [
                            f"{group} {key}: {count}" for group in groups for key, count in sorted(skips.items())])
                        for group in groups:
                            for name, body in bodies.items():
                                count = 4 if name in ("fin.txt", "fin-surge.txt") else 3 if name == "fin-qx.txt" else 0
                                self.assertEqual(outputs[root / group / name], f"# {group} rules: {count}\n" + body)
                            for name in ("fin.txt", "fin-surge.txt"):
                                parsed, messages = parse(outputs[root / group / name], purpose="proxy")
                                self.assertEqual(messages, [])
                                self.assertEqual(set(parsed), set(expected_rules))
                                self.assertEqual(len(parsed), 4)
                            for name in ("fin.yaml", "fin-surge-ds.txt"):
                                self.assertEqual(parse(outputs[root / group / name], purpose="proxy"), ([], []))
                            adb = outputs[root / group / "fin-adb.txt"].splitlines()
                            self.assertEqual(adb[:5], ["[Adblock Plus 2.0]", f"! Title: {group}",
                                             "! Homepage: https://github.com/DoingDog/rconvert", "! Expires: 1 day",
                                             "! License: Inherits upstream licenses"])
                            self.assertRegex(adb[5], r"^! Version: [0-9]{12}$")
                            self.assertEqual(adb[6:], ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                        self._publish_updated(outputs, previous)
                        if disk_only:
                            self.assertEqual({path: path.read_bytes() for path in published_source}, published_source)
                        else:
                            published_source = {root / "cdn" / name: (root / "cdn" / name).read_bytes() for name in NAMES}
                self.assertEqual({path for path in root.rglob("fin*") if path.is_file()},
                                 {root / group / name for group in ("cdn", "big-data") for name in NAMES})

    def test_quoted_url_regex_markers_survive_surge_generated_dependency(self):
        from rules import Rule, parse

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "source", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "dependent", "purpose": "proxy", "no_resolve": "strip",
                 "sources": ["source/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            values = ["^foo #bar$", "^foo ;bar$", "^foo //bar$"]
            (root / "source.list").write_text("".join(f"URL-REGEX,'{value}',PROXY\n" for value in values), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda url: self.fail(url))
            for group in ("source", "dependent"):
                self.assertEqual({path.name for path in outputs if path.parent.name == group}, set(NAMES))
                parsed, messages = parse(outputs[root / group / "fin.txt"], purpose="proxy")
                self.assertEqual(set(parsed), {Rule("URL-REGEX", value) for value in values})
                self.assertEqual(messages, [])


class GenerateTests(unittest.TestCase):
    def test_http_source_is_rejected_before_network(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            fetch_https("http://example.org/list.txt")

    def test_https_download_returns_rule_bytes(self):
        url = "https://example.org/list.txt"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), b"DOMAIN,ads.example.org\n")

    def test_https_redirect_to_http_is_rejected(self):
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: "http://example.org/list.txt"
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                fetch_https("https://example.org/list.txt")

    def test_insecure_redirect_is_blocked_before_request(self):
        url = "https://example.org/list.txt"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url
        visited_http = []

        class RedirectingOpener:
            def __init__(self, handler):
                self.handler = handler

            def open(self, source, timeout):
                self.handler.redirect_request(
                    request.Request(source), None, 302, "Found", {}, "http://example.org/list.txt"
                )
                visited_http.append(True)
                return response

        with patch("urllib.request.build_opener", side_effect=lambda handler: RedirectingOpener(handler)):
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    fetch_https(url)
        self.assertFalse(visited_http)

    def test_download_larger_than_limit_is_rejected(self):
        response = BytesIO(b"12345")
        response.geturl = lambda: "https://example.org/list.txt"
        with patch("generate.MAX_BYTES", 4, create=True), patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "size"):
                fetch_https("https://example.org/list.txt")

    def test_partial_http_response_is_rejected_before_parsing(self):
        url = "https://example.org/partial.txt"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url
        response.status = 206
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "206"):
                fetch_https(url)

    def test_html_response_is_passed_to_parser(self):
        url = "https://example.org/list.txt"
        body = b"<html>DOMAIN,ads.example.org</html>"
        response = BytesIO(body)
        response.geturl = lambda: url
        response.headers = {"Content-Type": "text/html"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), body)

    def test_empty_download_is_rejected(self):
        url = "https://example.org/empty.txt"
        response = BytesIO(b"")
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, "empty"):
                fetch_https(url)

    def test_html_body_with_wrong_media_type_is_passed_to_parser(self):
        url = "https://example.org/list.txt"
        body = b"<!DOCTYPE html><html>DOMAIN,ads.example.org</html>"
        response = BytesIO(body)
        response.geturl = lambda: url
        response.headers = {"Content-Type": "text/plain"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), body)

    def test_download_uses_accepted_user_agent_for_sukka_source(self):
        url = "https://ruleset.skk.moe/List/non_ip/my_reject.conf"
        response = BytesIO(b"DOMAIN,ads.example.org\n")
        response.geturl = lambda: url

        class AgentSensitiveOpener:
            addheaders = []

            def open(self, source, timeout):
                if not any(name.lower() == "user-agent" and "Mozilla" in value
                           for name, value in self.addheaders):
                    raise error.HTTPError(url, 403, "Forbidden", {}, None)
                return response

        with patch("urllib.request.build_opener", return_value=AgentSensitiveOpener()):
            self.assertEqual(fetch_https(url), b"DOMAIN,ads.example.org\n")

    def test_http_failure_identifies_source_url(self):
        url = "https://example.org/broken.txt"
        failure = error.HTTPError(url, 404, "Not Found", {}, None)
        with patch("urllib.request.OpenerDirector.open", side_effect=failure):
            with self.assertRaisesRegex(Exception, url):
                fetch_https(url)

    def test_timeout_identifies_source_url(self):
        url = "https://example.org/slow.txt"
        with patch("urllib.request.OpenerDirector.open", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(Exception, url):
                fetch_https(url)

    def test_timeout_while_reading_identifies_source_url(self):
        url = "https://example.org/slow.txt"

        class SlowResponse(BytesIO):
            def read(self, size=-1):
                raise TimeoutError("timed out")

        response = SlowResponse()
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(Exception, url):
                fetch_https(url)

    def test_short_response_with_content_length_is_rejected(self):
        url = "https://example.org/truncated.txt"
        data = b"DOMAIN,ads.example.org\n"
        response = BytesIO(data)
        response.geturl = lambda: url
        response.headers = {"Content-Length": str(len(data) + 50)}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(ValueError, url):
                fetch_https(url)

    def test_incomplete_download_identifies_source_url(self):
        url = "https://example.org/truncated.txt"

        class TruncatedResponse(BytesIO):
            def read(self, size=-1):
                raise IncompleteRead(b"DOMAIN,partial.example.org", 50)

        response = TruncatedResponse()
        response.geturl = lambda: url
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(RuntimeError, url):
                fetch_https(url)

    def test_gzip_download_is_decompressed_for_rules(self):
        url = "https://example.org/list.txt"
        data = b"DOMAIN,ads.example.org\n"
        compressed = gzip.compress(data)
        response = BytesIO(compressed)
        response.geturl = lambda: url
        response.headers = {"Content-Encoding": "gzip", "Content-Length": str(len(compressed))}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            self.assertEqual(fetch_https(url), data)

    def test_gzip_checks_compressed_and_decompressed_size_limits(self):
        url = "https://example.org/huge.txt"
        compressed = gzip.compress(b"DOMAIN," + b"a" * 1000)
        for maximum, label in ((len(compressed) - 1, "size"), (len(compressed), "Decompressed")):
            with self.subTest(label=label):
                response = BytesIO(compressed)
                response.geturl = lambda: url
                response.headers = {"Content-Encoding": "gzip", "Content-Length": str(len(compressed))}
                with patch("generate.MAX_BYTES", maximum), patch("urllib.request.OpenerDirector.open", return_value=response):
                    with self.assertRaisesRegex(ValueError, label):
                        fetch_https(url)

    def test_truncated_gzip_download_aborts_instead_of_skipping(self):
        url = "https://example.org/broken.txt"
        response = BytesIO(gzip.compress(b"DOMAIN,ads.example.org\n")[:-5])
        response.geturl = lambda: url
        response.headers = {"Content-Encoding": "gzip"}
        with patch("urllib.request.OpenerDirector.open", return_value=response):
            with self.assertRaisesRegex(RuntimeError, url):
                fetch_https(url)

    def test_publish_writes_a_complete_utf8_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "a3" / "fin.txt"
            output.parent.mkdir()
            publish({output: "DOMAIN,例子.example\n"})
            self.assertEqual(output.read_bytes(), "DOMAIN,例子.example\n".encode("utf-8"))

    def test_publish_creates_a_new_group_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "new-group" / "fin.txt"
            publish({output: "DOMAIN,new.example.org\n"})
            self.assertEqual(output.read_text(encoding="utf-8"), "DOMAIN,new.example.org\n")

    def test_second_replacement_failure_restores_all_old_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            first, second = root / "cdn" / "fin.txt", root / "a3" / "fin.txt"
            for path in (first, second):
                path.parent.mkdir()
                path.write_bytes(b"old data\n")
            original_replace = os.replace
            calls = 0

            def fail_second(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("replacement failed")
                return original_replace(source, target)

            with patch("os.replace", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "replacement failed"):
                    publish({first: "new first\n", second: "new second\n"})
            self.assertEqual(first.read_bytes(), b"old data\n")
            self.assertEqual(second.read_bytes(), b"old data\n")

    def test_publish_failure_removes_new_group_and_keeps_prior_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            new = root / "new-group" / "fin.txt"
            old = root / "cdn" / "fin.txt"
            old.parent.mkdir()
            old.write_bytes(b"previous version\n")
            original_replace = os.replace
            calls = 0

            def fail_second(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("replacement failed")
                return original_replace(source, target)

            with patch("os.replace", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "replacement failed"):
                    publish({new: "new content\n", old: "new old\n"})
            self.assertFalse(new.parent.exists())
            self.assertEqual(old.read_bytes(), b"previous version\n")

    def test_publish_rejects_paths_outside_worktree(self):
        outside = ROOT.parent / "outside-fin.txt"
        with patch("os.replace", side_effect=RuntimeError("would write outside")):
            with self.assertRaisesRegex(ValueError, "worktree"):
                publish({outside: "DOMAIN,ads.example.org\n"})
        self.assertFalse(outside.exists())

    def test_publish_rejects_static_paths_before_replacement(self):
        target = ROOT / "static/main/Direct.list"
        original = target.read_bytes()
        with patch("os.replace", side_effect=AssertionError("static write attempted")):
            with self.assertRaisesRegex(ValueError, "static"):
                publish({target: "DOMAIN,evil.example\n"})
        self.assertEqual(target.read_bytes(), original)

    def test_generate_rejects_root_outside_worktree_before_reading(self):
        with self.assertRaisesRegex(ValueError, "worktree"):
            generate(ROOT.parent, lambda _: self.fail("network must not be used"))

    def test_json_config_builds_a_new_group_without_hardcoded_names(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "custom", "title": "Custom Ads", "purpose": "block", "no_resolve": "keep",
                "sources": ["input.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "input.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / "custom" / name for name in NAMES})
            self.assertIn("DOMAIN,ads.example.org\n", outputs[root / "custom" / "fin.txt"])
            self.assertIn("! Title: Custom Ads\n", outputs[root / "custom" / "fin-adb.txt"])

    def _assert_output_collision_rejected(self, root, first, second):
        from formats import render
        from rules import parse, parse_whitelist

        previous = {path: path.read_bytes() for path in root.rglob("fin*") if path.is_file()}
        hashes = {path: hashlib.sha256(data).hexdigest() for path, data in previous.items()}
        resolved = first.resolve()
        calls = []

        def fetch(url):
            calls.append(url)
            if url == "https://example.org/missing.txt":
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)
            return b"DOMAIN,current.example.org\n"

        outputs, failure = {}, None
        with contextlib.redirect_stderr(io.StringIO()), patch("rules.parse", wraps=parse) as parsed, \
                patch("rules.parse_whitelist", wraps=parse_whitelist) as allowed, \
                patch("formats.render", wraps=render) as rendered, \
                patch("generate.publish", wraps=publish) as published:
            try:
                outputs = generate(root, fetch)
                published(outputs)
            except ValueError as exc:
                failure = exc
        with self.subTest(check="error"):
            self.assertIsInstance(failure, ValueError)
            self.assertIn("Output path collision", str(failure))
            for path in (first, second, resolved):
                self.assertIn(str(path), str(failure))
        with self.subTest(check="fetch"):
            self.assertEqual(calls, [])
        with self.subTest(check="processing"):
            parsed.assert_not_called()
            allowed.assert_not_called()
            rendered.assert_not_called()
        with self.subTest(check="outputs"):
            self.assertEqual(outputs, {})
        with self.subTest(check="dependency"):
            self.assertFalse(any(path.parent.name == "big-data" for path in outputs))
        with self.subTest(check="publication"):
            published.assert_not_called()
        with self.subTest(check="old bytes"):
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
        with self.subTest(check="old hashes"):
            self.assertEqual({path: hashlib.sha256(path.read_bytes()).hexdigest() for path in previous}, hashes)
        with self.subTest(check="complete file set"):
            self.assertEqual({path for path in root.rglob("fin*") if path.is_file()}, set(previous))

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive output paths")
    def test_windows_case_collision_rejects_before_freezing_fetching_or_publishing(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configs = [
                {"name": group, "purpose": "proxy", "no_resolve": "keep",
                 "sources": sources, "whitelist": ["allow.list"] if group == "healthy" else []}
                for group, sources in (
                    ("healthy", ["https://example.org/healthy.txt"]),
                    ("cdn", ["https://example.org/missing.txt"]),
                    ("CDN", ["current.list"]),
                    ("big-data", ["CDN/fin.txt"]),
                )
            ]
            (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
            (root / "current.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("DOMAIN,safe.example.org,DIRECT\n", encoding="utf-8")
            for group in ("healthy", "CDN", "big-data"):
                (root / group).mkdir()
                for name in NAMES:
                    (root / group / name).write_bytes(f"DOMAIN,stale-{group}.example.org\n".encode())
            for name in NAMES:
                self.assertTrue((root / "cdn" / name).samefile(root / "CDN" / name))
            self._assert_output_collision_rejected(root, root / "cdn" / NAMES[0], root / "CDN" / NAMES[0])

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive output paths")
    def test_windows_case_collision_rejects_nonexistent_group_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": group, "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["current.list"], "whitelist": []}
                for group in ("cdn", "CDN")
            ]), encoding="utf-8")
            (root / "current.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            self.assertFalse((root / "cdn").exists())
            self.assertFalse((root / "CDN").exists())
            self._assert_output_collision_rejected(root, root / "cdn" / NAMES[0], root / "CDN" / NAMES[0])
            self.assertFalse((root / "cdn").exists())
            self.assertFalse((root / "CDN").exists())

    @unittest.skipUnless(os.name == "nt", "Requires real Windows file symlinks")
    def test_windows_file_alias_collision_checks_each_of_the_six_output_paths(self):
        for filename in NAMES:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": group, "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["mirror/fin.txt"] if group == "big-data" else ["current.list"],
                     "whitelist": []}
                    for group in ("cdn", "mirror", "big-data")
                ]), encoding="utf-8")
                (root / "current.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for group in ("cdn", "mirror", "big-data"):
                    (root / group).mkdir()
                    for name in NAMES:
                        (root / group / name).write_bytes(f"DOMAIN,stale-{group}.example.org\n".encode())
                first, second = root / "cdn" / filename, root / "mirror" / filename
                second.unlink()
                try:
                    second.symlink_to(first)
                except OSError as exc:
                    if exc.winerror != 1314:
                        raise
                    self.skipTest("Windows file symlinks require a privilege unavailable on this host")
                self.assertTrue(second.is_symlink())
                self.assertTrue(first.samefile(second))
                self._assert_output_collision_rejected(root, first, second)
                self.assertTrue(second.is_symlink())

    @unittest.skipUnless(os.name == "nt", "Requires real Windows directory junctions")
    def test_windows_directory_junction_collision_rejects_shared_old_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": group, "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["current.list"], "whitelist": []}
                for group in ("cdn", "mirror")
            ]), encoding="utf-8")
            (root / "current.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            (root / "cdn").mkdir()
            for name in NAMES:
                (root / "cdn" / name).write_bytes(b"DOMAIN,stale.example.org\n")
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(root / "mirror"), str(root / "cdn")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "mirror").is_junction())
            for name in NAMES:
                self.assertTrue((root / "cdn" / name).samefile(root / "mirror" / name))
            self._assert_output_collision_rejected(root, root / "cdn" / NAMES[0], root / "mirror" / NAMES[0])
            self.assertTrue((root / "mirror").is_junction())

    @unittest.skipIf(os.name == "nt", "Case-distinct groups require a case-sensitive platform")
    def test_case_distinct_groups_generate_separate_outputs_on_case_sensitive_platform(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "cdn").mkdir()
            if (root / "CDN").exists():
                self.skipTest("This filesystem does not support case-distinct directories")
            (root / "CDN").mkdir()
            (root / "rulesets.json").write_text(json.dumps([
                {"name": group, "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["current.list"], "whitelist": []}
                for group in ("cdn", "CDN")
            ]), encoding="utf-8")
            (root / "current.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name for group in ("cdn", "CDN") for name in NAMES})
            publish(outputs)
            self.assertTrue(all(path.is_file() for path in outputs))
            self.assertFalse((root / "cdn" / NAMES[0]).samefile(root / "CDN" / NAMES[0]))

    def test_generate_keeps_literal_and_glob_process_sources_separate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "proxy", "purpose": "proxy", "no_resolve": "strip",
                "sources": ["literal.yaml", "surge.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "literal.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Foo*Bar"\n'
                '  - "AND,((PROCESS-NAME,Foo*Bar),(DOMAIN,a.example.com))"\n',
                encoding="utf-8",
            )
            (root / "surge.list").write_text(
                "PROCESS-NAME,Foo*Bar,PROXY\n"
                "HOST-SUFFIX,googleapis.com,PROXY,force-cellular\n", encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                out = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(generated_text(out[root / "proxy" / "fin.yaml"]),
                             '# proxy rules: 3\npayload:\n'
                             '  - "AND,((PROCESS-NAME,Foo*Bar),(DOMAIN,a.example.com))"\n'
                             '  - "DOMAIN-SUFFIX,googleapis.com"\n'
                             '  - "PROCESS-NAME,Foo*Bar"\n')
            self.assertEqual(out[root / "proxy" / "fin.txt"],
                             '# proxy rules: 2\nDOMAIN-SUFFIX,googleapis.com\nPROCESS-NAME,Foo*Bar\n')
            self.assertEqual(out[root / "proxy" / "fin-qx.txt"],
                             '# proxy rules: 1\nHOST-SUFFIX,googleapis.com,LIST\n')
            self.assertIn("proxy fin.txt:AND: 1", stderr.getvalue())
            self.assertIn("proxy fin.txt:PROCESS-NAME: 1", stderr.getvalue())
            self.assertIn("proxy fin.yaml:PROCESS-NAME: 1", stderr.getvalue())
            self.assertIn("proxy fin-qx.txt:DOMAIN-SUFFIX:interface-option: 1", stderr.getvalue())

    def test_no_resolve_policy_add_strip_and_keep_is_configured_per_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "tagged.list").write_text("IP-CIDR,192.0.2.0/24,no-resolve\n", encoding="utf-8")
            (root / "untagged.list").write_text("IP-CIDR,198.51.100.0/24\n", encoding="utf-8")
            groups = [
                {"name": name, "purpose": "direct", "no_resolve": policy,
                 "sources": [source], "whitelist": []}
                for name, policy, source in (
                    ("dirt", "strip", "tagged.list"),
                    ("preserved", "keep", "tagged.list"),
                    ("untagged", "keep", "untagged.list"),
                    ("forced", "add", "untagged.list"),
                )
            ]
            (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            for name in ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin.yaml"):
                self.assertNotIn("no-resolve", outputs[root / "dirt" / name], name)
                self.assertIn("no-resolve", outputs[root / "preserved" / name], name)
                self.assertNotIn("no-resolve", outputs[root / "untagged" / name], name)
                self.assertIn("no-resolve", outputs[root / "forced" / name], name)

    def test_local_source_ip_direction_and_ip_suffix_are_target_specific(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "proxy", "purpose": "proxy", "no_resolve": "add",
                "sources": ["source.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "source.list").write_text(
                "DOMAIN,baseline.example.org,PROXY\n"
                "IP-CIDR,192.0.2.0/24,PROXY,src\n"
                "IP-SUFFIX,8.8.8.8/24,PROXY,no-resolve\n", encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            for name in ("fin.txt", "fin-surge.txt"):
                self.assertIn("SRC-IP,192.0.2.0/24\n", outputs[root / "proxy" / name])
                self.assertNotIn("IP-CIDR,192.0.2.0/24", outputs[root / "proxy" / name])
                self.assertNotIn("8.8.8.8/24", outputs[root / "proxy" / name])
            self.assertIn('  - "SRC-IP-CIDR,192.0.2.0/24"\n', generated_text(outputs[root / "proxy" / "fin.yaml"]))
            self.assertIn('  - "IP-SUFFIX,8.8.8.8/24,no-resolve"\n', generated_text(outputs[root / "proxy" / "fin.yaml"]))
            self.assertNotIn("192.0.2.0/24", outputs[root / "proxy" / "fin-qx.txt"])
            self.assertNotIn("8.8.8.8/24", outputs[root / "proxy" / "fin-qx.txt"])
            self.assertIn("proxy fin-qx.txt:SRC-IP-CIDR: 1", stderr.getvalue())
            self.assertIn("proxy fin-surge.txt:IP-SUFFIX: 1", stderr.getvalue())

    def test_local_sources_preserve_matchers_across_six_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "add",
                 "sources": ["block.list", "literal.yaml"], "whitelist": ["allow.list"]},
                {"name": "dirt", "purpose": "direct", "no_resolve": "strip",
                 "sources": ["direct.list"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "block.list").write_text(
                "DOMAIN-SUFFIX,ads.example.org,REJECT\n"
                "DOMAIN,safe.ads.example.org,REJECT\n"
                "DOMAIN-WILDCARD,api-[0-9].example.org,REJECT\n"
                "IP-CIDR,192.0.2.0/24,REJECT,src\n"
                "AND,((IP-CIDR,198.51.100.0/24),(DOMAIN,track.example.net)),REJECT\n",
                encoding="utf-8",
            )
            (root / "literal.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Foo*Bar"\n', encoding="utf-8",
            )
            (root / "allow.list").write_text(
                "DOMAIN,safe.ads.example.org,DIRECT\n", encoding="utf-8",
            )
            (root / "direct.list").write_text(
                "OR,((IP-CIDR,203.0.113.0/24,no-resolve),(DOMAIN,direct.example.net)),DIRECT\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stderr(io.StringIO()) as warnings:
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "dirt") for name in NAMES})
            publish(outputs)
            self.assertTrue(all(path.is_file() for path in outputs))

            block = {
                "fin.txt": "# a3 rules: 4\n"
                           "AND,((IP-CIDR,198.51.100.0/24,no-resolve),(DOMAIN,track.example.net))\n"
                           "DOMAIN-SUFFIX,ads.example.org\n"
                           "DOMAIN-WILDCARD,api-[0-9].example.org\n"
                           "SRC-IP,192.0.2.0/24\n",
                "fin-qx.txt": "# a3 rules: 1\nHOST-SUFFIX,ads.example.org,LIST\n",
                "fin.yaml": '# a3 rules: 5\npayload:\n'
                            '  - "AND,((IP-CIDR,198.51.100.0/24,no-resolve),(DOMAIN,track.example.net))"\n'
                            '  - "DOMAIN-REGEX,^api\\\\-[0-9]\\\\.example\\\\.org\\\\.?$"\n'
                            '  - "DOMAIN-SUFFIX,ads.example.org"\n'
                            '  - "PROCESS-NAME,Foo*Bar"\n'
                            '  - "SRC-IP-CIDR,192.0.2.0/24"\n',
                "fin-surge.txt": "# a3 rules: 3\n"
                                 "AND,((IP-CIDR,198.51.100.0/24,no-resolve),(DOMAIN,track.example.net))\n"
                                 "DOMAIN-WILDCARD,api-[0-9].example.org\n"
                                 "SRC-IP,192.0.2.0/24\n",
                "fin-surge-ds.txt": "# a3 rules: 1\n.ads.example.org\n",
            }
            for name, expected in block.items():
                with self.subTest(group="a3", name=name):
                    self.assertEqual(generated_text((root / "a3" / name).read_text(encoding="utf-8")) if name == "fin.yaml" else
                                     (root / "a3" / name).read_text(encoding="utf-8"),
                                     expected_ordinary_text(expected) if name == "fin.yaml" else expected)
            self.assertEqual((root / "a3" / "fin-adb.txt").read_text(encoding="utf-8").splitlines()[6:], [
                "! Total count: 3", "@@|safe.ads.example.org|", "||ads.example.org^",
                r"/^api\-[0-9]\.example\.org$/",
            ])
            self.assertIn("a3 fin-qx.txt:SRC-IP-CIDR: 1", warnings.getvalue())
            self.assertIn("a3 fin-qx.txt:DOMAIN-WILDCARD: 1", warnings.getvalue())
            self.assertIn("a3 fin-surge.txt:PROCESS-NAME: 1", warnings.getvalue())

            direct = "OR,((IP-CIDR,203.0.113.0/24),(DOMAIN,direct.example.net))"
            self.assertEqual((root / "dirt" / "fin.txt").read_text(encoding="utf-8"),
                             f"# dirt rules: 1\n{direct}\n")
            self.assertEqual((root / "dirt" / "fin-surge.txt").read_text(encoding="utf-8"),
                             f"# dirt rules: 1\n{direct}\n")
            self.assertEqual(generated_text((root / "dirt" / "fin.yaml").read_text(encoding="utf-8")),
                             expected_ordinary_text(f'# dirt rules: 1\npayload:\n  - "{direct}"\n'))
            for name in ("fin-qx.txt", "fin-surge-ds.txt"):
                self.assertEqual((root / "dirt" / name).read_text(encoding="utf-8"),
                                 "# dirt rules: 0\n")
            self.assertEqual((root / "dirt" / "fin-adb.txt").read_text(encoding="utf-8").splitlines()[6:], [
                "! Total count: 0", "! No AdBlock rules for non-advertising group.",
            ])
            self.assertTrue(all("no-resolve" not in outputs[root / "dirt" / name] for name in NAMES))

    def test_json_whitelist_removes_only_covered_rules_and_adds_dns_exceptions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["block.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "block.list").write_text(
                "DOMAIN-SUFFIX,a.com\nDOMAIN,remove.example.com\n"
                "DOMAIN-KEYWORD,ad.track\n@@||safe.org^\n", encoding="utf-8",
            )
            (root / "allow.list").write_text(
                "DOMAIN,safe.a.com,DIRECT\nDOMAIN-SUFFIX,remove.example.com,DIRECT\n"
                "USER-AGENT,*bot*,DIRECT\n", encoding="utf-8",
            )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            surge = outputs[root / "a3" / "fin.txt"]
            dns = outputs[root / "a3" / "fin-adb.txt"]
            self.assertIn("DOMAIN-SUFFIX,a.com\n", surge)
            self.assertIn("DOMAIN-KEYWORD,ad.track\n", surge)
            self.assertNotIn("remove.example.com", surge)
            self.assertIn("||a.com^\n", dns)
            self.assertIn("/^.*ad\\.track.*$/\n", dns)
            self.assertIn("@@|safe.a.com|\n", dns)
            self.assertIn("@@||safe.org^\n", dns)
            self.assertNotIn("\nremove.example.com\n", dns)
            self.assertNotIn("USER-AGENT", dns)

    def test_dirt_whitelist_removes_requested_routes_and_keeps_unrelated_domain(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            whitelist = root / "static/main/NoDirect.list"
            whitelist.parent.mkdir(parents=True)
            whitelist.write_bytes((ROOT / "static/main/NoDirect.list").read_bytes())
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "dirt", "purpose": "direct", "no_resolve": "strip",
                "sources": ["direct.list"], "whitelist": ["static/main/NoDirect.list"],
            }]), encoding="utf-8")
            (root / "direct.list").write_text(
                "DOMAIN-KEYWORD,microsoft\nDOMAIN-WILDCARD,windows-*.net\n"
                "DOMAIN-SUFFIX,ms\nDOMAIN-SUFFIX,sm.ms\nDOMAIN-SUFFIX,loli.net\n"
                "DOMAIN,office.ms\nDOMAIN,cdn.loli.net\nDOMAIN,keep.example.org\n",
                encoding="utf-8",
            )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(outputs[root / "dirt" / "fin.txt"].splitlines()[1:],
                             ["DOMAIN,keep.example.org"])
            for name in ("fin-qx.txt", "fin.yaml", "fin-surge.txt", "fin-surge-ds.txt"):
                with self.subTest(name=name):
                    self.assertNotIn("microsoft", outputs[root / "dirt" / name])
                    self.assertNotIn("windows-*.net", outputs[root / "dirt" / name])
                    self.assertNotIn("loli.net", outputs[root / "dirt" / name])
                    self.assertNotIn("sm.ms", outputs[root / "dirt" / name])

    def test_html_whitelist_aborts_instead_of_silently_disabling_exclusions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["rules.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "rules.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("<html><body>login</body></html>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"allow\.list.*HTML"):
                generate(root, lambda _: self.fail("local input must not fetch"))

    def test_non_html_invalid_whitelist_aborts_but_unsupported_types_are_ignored(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["rules.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "rules.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("Login required\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"allow\.list.*invalid rule"):
                generate(root, lambda _: self.fail("local input must not fetch"))
            (root / "allow.list").write_text("USER-AGENT,*bot*,DIRECT\n", encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,ads.example.org\n", outputs[root / "a3" / "fin.txt"])

    def test_missing_or_invalid_utf8_local_whitelist_aborts_entire_round(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            with self.assertRaises(FileNotFoundError):
                publish(generate(root, lambda _: self.fail("local input must not fetch")))
            (root / "allow.list").write_bytes(b"DOMAIN,good.example.org\n\xff\n")
            with self.assertRaisesRegex(UnicodeError, "allow.list"):
                publish(generate(root, lambda _: self.fail("local input must not fetch")))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_configured_empty_whitelist_aborts_instead_of_disabling_exclusions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["rules.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "rules.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            for content in ("", "# only comments\n"):
                with self.subTest(content=content):
                    (root / "allow.list").write_text(content, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, r"allow\.list.*no rules"):
                        generate(root, lambda _: self.fail("local input must not fetch"))

    def test_cli_builds_fixture_with_local_sources_only(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "generate.py"), "--root", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                {root / group / name for group in GROUPS for name in NAMES},
                {path for group in GROUPS for path in (root / group).glob("fin*")},
            )

    def test_cli_publishes_allow_only_group_and_updates_healthy_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "@@||safe.example.org^\n" if group == "a3" else "DOMAIN,current.example.org\n",
                    encoding="utf-8",
                )
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            result = subprocess.run(
                [sys.executable, str(ROOT / "generate.py"), "--root", str(root)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(all((root / "a3" / name).read_bytes() != b"previous version\n" for name in NAMES))
            self.assertEqual((root / "a3" / "fin-adb.txt").read_text(encoding="utf-8").splitlines()[6:],
                             ["! Total count: 1", "@@||safe.example.org^"])
            self.assertIn("DOMAIN,current.example.org", (root / "cdn" / "fin.txt").read_text(encoding="utf-8"))

    def test_adblock_keeps_wide_block_with_narrow_allow_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\n@@||safe.example.com^\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a3" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn("@@||safe.example.com^", outputs[root / "a3" / "fin-adb.txt"])

    def test_whitelist_keeps_broad_route_and_adds_dns_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN-SUFFIX,safe.example.com,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\nDOMAIN,ads.example.com\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a3" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn("@@||safe.example.com^", outputs[root / "a3" / "fin-adb.txt"])

    def test_exact_whitelist_keeps_broad_block_with_anchored_dns_exception(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN,safe.example.com,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\n" if group == "a3"
                    else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN-SUFFIX,example.com", outputs[root / "a3" / "fin.txt"])
            self.assertIn("||example.com^", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn("@@|safe.example.com|", outputs[root / "a3" / "fin-adb.txt"])

    def test_empty_required_source_aborts_with_its_path(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "# no rules\n" if group == "a3" else "DOMAIN,ads.example.org\n",
                    encoding="utf-8",
                )
            with self.assertRaisesRegex(ValueError, "a3.*rules.txt"):
                generate(root, lambda _: self.fail("local input must not fetch"))

    def test_wholly_bad_utf8_remote_source_freezes_its_group_without_stopping_others(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/broken.txt"
            configure_groups(root, sources={"a3": [url]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"\xff\xfe")
            self.assertIn(url, stderr.getvalue())
            self.assertIn("UTF-8", stderr.getvalue())
            self.assertNotIn(root / "a3" / "fin.txt", outputs)
            publish(outputs)
            self.assertTrue(all((root / "a3" / name).read_bytes() == b"previous version\n" for name in NAMES))
            self.assertIn("DOMAIN,current.example.org", (root / "cdn" / "fin.txt").read_text(encoding="utf-8"))

    def test_last_source_failure_keeps_all_previous_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"dirt": ["https://example.org/final.txt"]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            with self.assertRaisesRegex(RuntimeError, "final.txt"):
                publish(generate(root, lambda _: (_ for _ in ()).throw(RuntimeError("final.txt unavailable"))))
            self.assertTrue(all(
                (root / group / name).read_bytes() == b"previous version\n"
                for group in GROUPS for name in NAMES
            ))

    def test_non404_http_errors_and_timeout_stop_all_publication(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/final.txt"
            configure_groups(root, sources={"dirt": [url]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            for failure in (
                error.HTTPError(url, 410, "Gone", {}, None),
                error.HTTPError(url, 429, "Too Many Requests", {}, None),
                error.HTTPError(url, 503, "Service Unavailable", {}, None),
                TimeoutError("timed out"),
                IncompleteRead(b"DOMAIN,partial.example.org", 50),
            ):
                with self.subTest(failure=str(failure)):
                    with patch("urllib.request.OpenerDirector.open", side_effect=failure):
                        with self.assertRaisesRegex(RuntimeError, url):
                            publish(generate(root, fetch_https))
                    self.assertTrue(all(
                        (root / group / name).read_bytes() == b"previous version\n"
                        for group in GROUPS for name in NAMES
                    ))

    def test_short_http_200_response_stops_all_publication(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/final.txt"
            configure_groups(root, sources={"dirt": [url]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")
            response = BytesIO(b"DOMAIN,partial.example.org\n")
            response.geturl = lambda: url
            response.headers = {"Content-Length": "999"}
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with self.assertRaisesRegex(ValueError, "Incomplete source"):
                    publish(generate(root, fetch_https))
            self.assertTrue(all(
                (root / group / name).read_bytes() == b"previous version\n"
                for group in GROUPS for name in NAMES
            ))

    def test_unsupported_source_rule_reports_url_and_line(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"a3": ["https://example.org/mixed.txt"]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                generate(root, lambda _: b"DOMAIN,ads.example.org\nUNKNOWN-TYPE,foo\n")
            self.assertIn("https://example.org/mixed.txt", stderr.getvalue())
            self.assertIn("line 2", stderr.getvalue())
            self.assertIn("UNKNOWN-TYPE", stderr.getvalue())

    def test_incompatible_target_type_reports_count(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "PROCESS-NAME,Game.exe,REJECT\n" if group == "a3"
                    else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("a3 fin-qx.txt:PROCESS-NAME: 1", stderr.getvalue())

    def test_generated_process_name_hash_is_preserved_before_replacing_six_old_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.yaml"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Game #1"\n', encoding="utf-8",
            )
            previous = {}
            for name in NAMES:
                path = root / "cdn" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = b"previous version\n"
                path.write_bytes(previous[path])
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(outputs[root / "a3" / "fin.txt"],
                             "# a3 rules: 0\n")
            self.assertEqual(outputs[root / "cdn" / "fin.txt"],
                             "# cdn rules: 0\n")
            self.assertEqual(outputs[root / "cdn" / "fin.yaml"], "# cdn rules: 0\npayload:\n")
            self.assertIn('"PROCESS-NAME,Game #1"', outputs[root / "a3" / "fin.yaml"])
            self.assertNotIn("a3/fin.txt: line 2", stderr.getvalue())
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            publish(outputs)
            self.assertEqual((root / "cdn" / "fin.txt").read_text(encoding="utf-8"),
                             outputs[root / "cdn" / "fin.txt"])

    def test_generated_process_comment_markers_survive_six_output_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.yaml"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.yaml").write_text(
                'payload:\n  - "PROCESS-NAME,Game ;1"\n'
                '  - "PROCESS-NAME,Game //1"\n', encoding="utf-8",
            )
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "cdn") for name in NAMES})
            for group in ("a3", "cdn"):
                self.assertEqual(outputs[root / group / "fin.txt"],
                                 f"# {group} rules: 0\n")
                self.assertEqual('"PROCESS-NAME,Game //1"' in outputs[root / group / "fin.yaml"], group == "a3")
                self.assertEqual('"PROCESS-NAME,Game ;1"' in outputs[root / group / "fin.yaml"], group == "a3")
            self.assertNotIn("a3/fin.txt: line", stderr.getvalue())
            publish(outputs)
            self.assertTrue(all(path.read_text(encoding="utf-8") == text
                                for path, text in outputs.items()))

    def test_process_regex_policy_token_is_not_truncated_in_six_output_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "direct", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "cdn", "purpose": "direct", "no_resolve": "keep",
                 "sources": ["a3/fin.yaml"], "whitelist": []},
            ]), encoding="utf-8")
            values = [f"^Game,DIRECT {marker}1$" for marker in (";", "#", "//")]
            values.append("^Game,'s$")
            (root / "source.list").write_text(
                "".join(f'PROCESS-NAME-REGEX,"{value}",DIRECT # note\n' for value in values),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "cdn") for name in NAMES})
            for group in ("a3", "cdn"):
                text = outputs[root / group / "fin.yaml"]
                self.assertEqual(sorted(generated_payload(line.removeprefix("  - "))
                                        for line in text.splitlines()[2:]),
                                 sorted(f"PROCESS-NAME-REGEX,{value}" for value in values))
            self.assertNotIn("source.list: line", stderr.getvalue())
            self.assertNotIn("a3/fin.yaml: line", stderr.getvalue())

    def test_domain_regex_comment_group_and_tail_survive_yaml_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "cdn", "purpose": "block", "no_resolve": "keep",
                 "sources": ["a3/fin.yaml"], "whitelist": []},
            ]), encoding="utf-8")
            scoped = r"^(?x:(?#note)a)\.example\.com$"
            (root / "source.list").write_text(
                "DOMAIN-REGEX,^foo$,REJECT # note,REJECT\n"
                f"DOMAIN-REGEX,{scoped},REJECT\n"
                "AND,((DOMAIN-REGEX,^ads$,no-resolve),(DOMAIN,x.example.com)),REJECT\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            expected = {"DOMAIN-REGEX,^foo$", f"DOMAIN-REGEX,{scoped}",
                        f"AND,((DOMAIN-REGEX,^ads$,no-resolve),({expected_domain('DOMAIN', 'x.example.com')}))"}
            for group in ("a3", "cdn"):
                yaml = outputs[root / group / "fin.yaml"]
                self.assertEqual({generated_payload(line.removeprefix("  - "))
                                  for line in yaml.splitlines()[2:]}, expected)
            self.assertNotIn("source.list: line 3:", stderr.getvalue())
            self.assertNotIn("source.list: line 1:", stderr.getvalue())
            self.assertNotIn("source.list: line 2:", stderr.getvalue())
            self.assertNotIn("a3/fin.yaml: line", stderr.getvalue())

    def test_unquoted_yaml_process_markers_survive_six_output_dependency(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["source.yaml"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.yaml").write_text(
                "# upstream\npayload:\n  - PROCESS-NAME,Game ;1\n"
                "  - PROCESS-NAME,Game //1\n# end\n", encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name
                                            for group in ("a3", "cdn") for name in NAMES})
            for group in ("a3", "cdn"):
                self.assertEqual(outputs[root / group / "fin.txt"],
                                 f"# {group} rules: 0\n")
                self.assertEqual('"PROCESS-NAME,Game ;1"' in outputs[root / group / "fin.yaml"], group == "a3")
                self.assertEqual('"PROCESS-NAME,Game //1"' in outputs[root / group / "fin.yaml"], group == "a3")
                self.assertEqual(outputs[root / group / "fin-surge.txt"],
                                 outputs[root / group / "fin.txt"])
                for name in ("fin-qx.txt", "fin-surge-ds.txt"):
                    self.assertEqual(outputs[root / group / name], f"# {group} rules: 0\n")
                self.assertIn("! Total count: 0", outputs[root / group / "fin-adb.txt"])
            self.assertNotIn("source.yaml: line", stderr.getvalue())
            self.assertNotIn("a3/fin.txt: line", stderr.getvalue())

    def test_dependent_group_uses_current_in_memory_cdn_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"big-data": ["cdn/fin.txt"]})
            for group in GROUPS:
                if group != "big-data":
                    (root / group / "rules.txt").write_text(
                        f"DOMAIN,from-{group}.example.org\n", encoding="utf-8",
                    )
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,from-cdn.example.org", outputs[root / "big-data" / "fin.txt"])
            self.assertFalse((root / "cdn" / "fin.txt").exists())

    def test_header_only_generated_dependency_replaces_stale_derived_routes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": ["allow.list"]},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
            previous = {}
            for group in ("a3", "cdn"):
                for name in NAMES:
                    path = root / group / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = "DOMAIN,stale.example.org\n"
                    path.write_text(previous[path], encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), set(previous))
            self.assertEqual(outputs[root / "a3" / "fin.txt"], "# a3 rules: 0\n")
            self.assertEqual(outputs[root / "cdn" / "fin.txt"], "# cdn rules: 0\n")
            publish(outputs)
            for path in previous:
                self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                self.assertNotIn("stale.example.org", outputs[path])

    def test_header_only_yaml_and_adblock_dependencies_remain_empty(self):
        for filename in ("fin.yaml", "fin-adb.txt"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": ["allow.list"]},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": [f"a3/{filename}"], "whitelist": []},
                ]), encoding="utf-8")
                (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
                (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda _: self.fail("local input must not fetch"))
                self.assertEqual(outputs[root / "cdn" / "fin.txt"], "# cdn rules: 0\n")
                self.assertEqual({root / "cdn" / name for name in NAMES},
                                 {path for path in outputs if path.parent.name == "cdn"})

    def test_header_only_generated_whitelist_allows_downstream_publication(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": ["allow.list"]},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["cdn.list"], "whitelist": ["a3/fin.txt"]},
            ]), encoding="utf-8")
            (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
            (root / "cdn.list").write_text("DOMAIN,keep.example.org\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "cdn" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = b"DOMAIN,stale.example.org\n"
                path.write_bytes(previous[path])
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(outputs[root / "a3" / "fin.txt"], "# a3 rules: 0\n")
            self.assertEqual(outputs[root / "cdn" / "fin.txt"],
                             "# cdn rules: 1\nDOMAIN,keep.example.org\n")
            publish(outputs)
            self.assertTrue(all(path.read_bytes() != previous[path] for path in previous))

    def test_nonempty_unadaptable_generated_whitelist_aborts_before_publish(self):
        for source_rule, line in (
            ("PROCESS-NAME,Game.exe,REJECT\n", 3),
            ("DOMAIN,exclude.example.org,REJECT\nPROCESS-NAME,Game.exe,REJECT\n", 4),
        ):
            with self.subTest(line=line), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": []},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["cdn.list"], "whitelist": ["a3/fin.yaml"]},
                ]), encoding="utf-8")
                (root / "source.list").write_text(source_rule, encoding="utf-8")
                (root / "cdn.list").write_text("DOMAIN,exclude.example.org\n", encoding="utf-8")
                previous = {}
                for name in NAMES:
                    path = root / "cdn" / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = b"previous version\n"
                    path.write_bytes(previous[path])
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, rf"a3.*fin\.yaml.*line {line}"):
                        publish(generate(root, lambda _: self.fail("local input must not fetch")))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    @unittest.skipUnless(os.name == "nt", "WindowsPath case-insensitive dependency")
    def test_case_variant_header_only_generated_dependencies_stay_empty(self):
        for filename in ("FIN.YAML", "FIN-ADB.TXT"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": ["allow.list"]},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": [f"a3/{filename}"], "whitelist": []},
                ]), encoding="utf-8")
                (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
                (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, lambda _: self.fail("local input must not fetch"))
                self.assertEqual(outputs[root / "cdn" / "fin.txt"], "# cdn rules: 0\n")
                self.assertFalse((root / "a3" / filename).exists())

    def test_mixed_generated_adblock_rules_abort_without_publishing_partial_result(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": []},
                {"name": "a4", "purpose": "block", "no_resolve": "keep",
                 "sources": ["a3/fin-adb.txt"], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.list").write_text(
                "DOMAIN-SUFFIX,plain.example.org\n"
                r"DOMAIN-REGEX,^ads[0-9]+\.example\.org$" "\n", encoding="utf-8",
            )
            previous = {}
            for group in ("a3", "a4"):
                for name in NAMES:
                    path = root / group / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = f"previous {group} {name}\n".encode()
                    path.write_bytes(previous[path])
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, r"a3.*fin-adb\.txt.*line 9"):
                    publish(generate(root, lambda _: self.fail("local input must not fetch")))
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_unadaptable_generated_adblock_rules_cannot_clear_old_downstream_files(self):
        for source_rule in ("DOMAIN-SUFFIX,ads.example.org\n",
                            r"DOMAIN-REGEX,^ads[0-9]+\.example\.org$" + "\n"):
            with self.subTest(source_rule=source_rule), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([
                    {"name": "a3", "purpose": "block", "no_resolve": "keep",
                     "sources": ["source.list"], "whitelist": []},
                    {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                     "sources": ["a3/fin-adb.txt"], "whitelist": []},
                ]), encoding="utf-8")
                (root / "source.list").write_text(source_rule, encoding="utf-8")
                previous = {}
                for name in NAMES:
                    path = root / "cdn" / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = b"previous version\n"
                    path.write_bytes(previous[path])
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, r"a3.*fin-adb\.txt"):
                        publish(generate(root, lambda _: self.fail("local input must not fetch")))
                self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_missing_remote_source_with_empty_generated_dependency_freezes_downstream(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "a3", "purpose": "block", "no_resolve": "keep",
                 "sources": ["source.list"], "whitelist": ["allow.list"]},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["a3/fin.txt", missing], "whitelist": []},
            ]), encoding="utf-8")
            (root / "source.list").write_text("IP-CIDR,203.0.113.0/24,REJECT\n", encoding="utf-8")
            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "cdn" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = "DOMAIN,stale.example.org\n"
                path.write_text(previous[path], encoding="utf-8")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(set(outputs), {root / "a3" / name for name in NAMES})
            publish(outputs)
            self.assertEqual({path: path.read_text(encoding="utf-8") for path in previous}, previous)

    def test_forward_generated_dependency_rejects_stale_disk_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "cdn").mkdir()
            (root / "cdn" / "fin.txt").write_text("DOMAIN,stale.example.org\n", encoding="utf-8")
            (root / "new.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            (root / "rulesets.json").write_text(json.dumps([
                {"name": "big-data", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["cdn/fin.txt"], "whitelist": []},
                {"name": "cdn", "purpose": "proxy", "no_resolve": "keep",
                 "sources": ["new.list"], "whitelist": []},
            ]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not yet generated"):
                generate(root, lambda _: self.fail("local input must not fetch"))

    def test_changed_dependency_changes_the_same_round_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={"big-data": ["cdn/fin.txt"]})
            for group in GROUPS:
                if group != "big-data":
                    (root / group / "rules.txt").write_text(
                        f"DOMAIN,original-{group}.example.org\n", encoding="utf-8",
                    )
            first = generate(root, lambda _: self.fail("local input must not fetch"))
            (root / "cdn" / "rules.txt").write_text(
                "DOMAIN,replaced-cdn.example.org\n", encoding="utf-8",
            )
            second = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertIn("DOMAIN,replaced-cdn.example.org", second[root / "big-data" / "fin.txt"])
            self.assertNotEqual(first[root / "big-data" / "fin.txt"], second[root / "big-data" / "fin.txt"])

    def test_same_remote_url_is_fetched_once_for_rules_and_whitelist(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            shared = "https://example.org/shared.txt"
            configure_groups(root, sources={"cdn": [shared], "a3": [shared, "a3/rules.txt"]},
                             whitelist={"a3": [shared]})
            for group in GROUPS:
                if group != "cdn":
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            calls = []

            def fetch(url):
                calls.append(url)
                return b"DOMAIN,shared.example.org\n"

            generate(root, fetch)
            self.assertEqual(calls, [shared])

    def test_missing_remote_source_and_whitelist_share_cached_404_and_keep_good_rules(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            good = "https://example.org/good.txt"
            configure_groups(root, sources={"a3": [missing, good]}, whitelist={"a3": [missing]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            calls = []

            def fetch(url):
                calls.append(url)
                if url == missing:
                    raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)
                return b"DOMAIN,good.example.org\n"

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, fetch)
            self.assertEqual(calls, [missing, good])
            self.assertIn("404", stderr.getvalue())
            self.assertIn(missing, stderr.getvalue())
            self.assertIn("DOMAIN,good.example.org", outputs[root / "a3" / "fin.txt"])

    def test_fetch_https_wrapped_real_http_404_freezes_existing_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/missing.txt"
            configure_groups(root, sources={"a3": [url]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            failure = error.HTTPError(url, 404, "Not Found", {}, None)
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", side_effect=failure):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            self.assertIn(f"{url}: HTTP 404", stderr.getvalue())
            self.assertNotIn(root / "a3" / "fin.txt", outputs)
            self.assertIn(root / "cdn" / "fin.txt", outputs)

    def test_all_404_freezes_group_six_files_while_healthy_groups_publish(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"a3": [missing]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "a3" / name
                previous[path] = f"previous {name}\n".encode()
                path.write_bytes(previous[path])

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertFalse(any(path.parent.name == "a3" for path in outputs))
            self.assertEqual(len(outputs), 18)
            publish(outputs)
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
            self.assertIn("DOMAIN,current.example.org", (root / "cdn" / "fin.txt").read_text(encoding="utf-8"))

    def test_frozen_cdn_also_freezes_big_data_without_reading_stale_cdn_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing-cdn.txt"
            configure_groups(root, sources={"cdn": [missing],
                                            "big-data": ["cdn/fin.txt", "https://example.org/extra.txt"]})
            for group in ("a3", "dirt"):
                (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            previous = {}
            for group in ("cdn", "big-data"):
                for name in NAMES:
                    path = root / group / name
                    previous[path] = f"DOMAIN,stale-{group}.example.org\n".encode()
                    path.write_bytes(previous[path])
            calls = []

            def fetch(url):
                calls.append(url)
                if url == missing:
                    raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)
                return b"DOMAIN,extra.example.org\n"

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(calls, [missing])
            self.assertEqual(set(outputs), {root / group / name for group in ("a3", "dirt") for name in NAMES})
            publish(outputs)
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_freeze_propagates_through_multiple_generated_dependency_levels(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing-cdn.txt"
            configure_groups(root, sources={"cdn": [missing], "big-data": ["cdn/fin.txt"]})
            configs = json.loads((root / "rulesets.json").read_text(encoding="utf-8"))
            configs.append({"name": "archive", "purpose": "proxy", "no_resolve": "keep",
                            "sources": ["big-data/fin.txt"], "whitelist": []})
            (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
            for group in ("a3", "dirt"):
                (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for group in ("cdn", "big-data", "archive"):
                (root / group).mkdir(exist_ok=True)
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(set(outputs), {root / group / name for group in ("a3", "dirt") for name in NAMES})
            self.assertTrue(all(
                (root / group / name).read_bytes() == b"previous version\n"
                for group in ("cdn", "big-data", "archive") for name in NAMES
            ))

    def _assert_r25_publication(self, root, outputs, previous, groups, purpose, mode, before, after):
        expected = {}
        for group, empty in groups:
            version = outputs[root / group / "fin-adb.txt"].splitlines()[5]
            self.assertRegex(version, r"^! Version: [0-9]{12}$")
            stamp = datetime.strptime(version.removeprefix("! Version: "), "%Y%m%d%H%M").replace(
                tzinfo=timezone(timedelta(hours=8)))
            self.assertLessEqual(before.replace(second=0, microsecond=0), stamp)
            self.assertLessEqual(stamp, after.replace(second=0, microsecond=0))
            expected.update({root / group / name: text for name, text in
                             r25_expected(group, purpose, mode, version, empty).items()})
        self.assertEqual(list(outputs), list(expected))
        self.assertEqual(outputs, expected)
        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
        publish(outputs)
        self.assertEqual({path: path.read_bytes() for path in previous},
                         {path: expected[path].encode("utf-8") if path in expected else old
                          for path, old in previous.items()})
        self.assertEqual({path: path.read_bytes() for path in expected},
                         {path: text.encode("utf-8") for path, text in expected.items()})

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive group aliases")
    def test_windows_frozen_group_aliases_propagate_through_source_and_whitelist_dependencies(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        missing = "https://example.org/missing-cdn.txt"
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                for configured, physical in (("CDN", "cdn"), ("cdn", "CDN"), ("cdn", "cdn")):
                    for reason in ("404", "no-rules", "no-routable"):
                        for dependency in ("sources", "whitelist"):
                            for filename in NAMES:
                                for healthy_first in (False, True):
                                    with self.subTest(purpose=purpose, mode=mode, configured=configured,
                                                      physical=physical, reason=reason, dependency=dependency,
                                                      filename=filename, healthy_first=healthy_first), \
                                            tempfile.TemporaryDirectory(dir=staging) as directory:
                                        root = Path(directory)
                                        configs = [
                                            {"name": configured, "purpose": purpose, "no_resolve": mode,
                                             "sources": ["bad.list" if reason == "no-routable" else missing], "whitelist": []},
                                            {"name": "DEPENDENT", "purpose": purpose, "no_resolve": mode,
                                             "sources": ["healthy.list"], "whitelist": []},
                                            {"name": "archive", "purpose": purpose, "no_resolve": mode,
                                             "sources": ["healthy.list"], "whitelist": ["dependent/FIN.TXT"]},
                                        ]
                                        configs[1][dependency] = [f"{configured.upper()}/{filename.upper()}"]
                                        healthy = {"name": "healthy", "purpose": purpose, "no_resolve": mode,
                                                   "sources": ["healthy.list"], "whitelist": []}
                                        configs.insert(0 if healthy_first else len(configs), healthy)
                                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                                        (root / "healthy.list").write_text(R25_SOURCE, encoding="utf-8")
                                        fixture = "payload:\n  - " + json.dumps("USER-AGENT,A\x00B") + "\n"
                                        (root / "bad.list").write_text(fixture, encoding="utf-8")
                                        dependent = "DEPENDENT" if configured == physical == "cdn" else "dependent"
                                        previous = r25_old_files(root, (physical, dependent, "archive", "healthy"))
                                        self.assertTrue((root / configured).samefile(root / physical))
                                        self.assertEqual((root / configured).resolve().name, physical)

                                        def fetch(url):
                                            self.assertEqual(url, missing)
                                            if reason == "404":
                                                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(
                                                    url, 404, "Not Found", {}, None)
                                            self.assertEqual(reason, "no-rules")
                                            return b"# no rules\n"

                                        before = datetime.now().astimezone()
                                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                                            outputs = generate(root, fetch)
                                        after = datetime.now().astimezone()
                                        cause = (f"{missing}: HTTP 404; skipped\n" if reason == "404" else
                                                 f"{missing}: no adaptable rules; skipped\n" if reason == "no-rules" else
                                                 f"{configured}: no routable rules; frozen\n")
                                        skips = (("healthy fin-adb.txt:DOMAIN: 1\n" if purpose != "block" else "") +
                                                 "healthy fin-adb.txt:IP-CIDR: 2\nhealthy fin-surge-ds.txt:IP-CIDR: 2\n")
                                        self.assertEqual(stderr.getvalue(), skips + cause if healthy_first else cause + skips)
                                        self._assert_r25_publication(root, outputs, previous, [("healthy", False)],
                                                                     purpose, mode, before, after)

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive group aliases")
    def test_windows_frozen_alias_incomplete_old_products_abort_publication(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        missing = "https://example.org/missing-cdn.txt"
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                for dependency in ("sources", "whitelist"):
                    for broken in ("cdn", "dependent", "archive"):
                        for filename in NAMES:
                            for defect in ("missing", "empty"):
                                with self.subTest(purpose=purpose, mode=mode, dependency=dependency,
                                                  broken=broken, filename=filename, defect=defect), \
                                        tempfile.TemporaryDirectory(dir=staging) as directory:
                                    root = Path(directory)
                                    configs = [{"name": group, "purpose": purpose, "no_resolve": mode,
                                                "sources": [missing if group == "CDN" else "healthy.list"],
                                                "whitelist": ["dependent/FIN.TXT"] if group == "archive" else []}
                                               for group in ("healthy", "CDN", "DEPENDENT", "archive")]
                                    configs[2][dependency] = ["cdn/FIN.TXT"]
                                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                                    (root / "healthy.list").write_text(R25_SOURCE, encoding="utf-8")
                                    previous = r25_old_files(root, ("healthy", "cdn", "dependent", "archive"))
                                    damaged = root / broken / filename
                                    if defect == "missing":
                                        damaged.unlink()
                                        previous.pop(damaged)
                                    else:
                                        damaged.write_bytes(b"")
                                        previous[damaged] = b""

                                    def fetch(url):
                                        raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(
                                            url, 404, "Not Found", {}, None)

                                    group = {"cdn": "CDN", "dependent": "DEPENDENT", "archive": "archive"}[broken]
                                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                                        with self.assertRaises(ValueError) as failure:
                                            publish(generate(root, fetch))
                                    self.assertEqual(str(failure.exception),
                                                     f"Cannot freeze {group}: missing complete old file {root / group / filename}")
                                    self.assertEqual(stderr.getvalue(),
                                                     ("healthy fin-adb.txt:DOMAIN: 1\n" if purpose != "block" else "") +
                                                     "healthy fin-adb.txt:IP-CIDR: 2\nhealthy fin-surge-ds.txt:IP-CIDR: 2\n" +
                                                     f"{missing}: HTTP 404; skipped\n")
                                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                                    self.assertEqual({path for group in ("healthy", "cdn", "dependent", "archive")
                                                      for path in (root / group).iterdir()}, set(previous))

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive group aliases")
    def test_windows_frozen_alias_does_not_hide_missing_local_whitelist(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=staging) as directory:
                    root = Path(directory)
                    configs = [{"name": "CDN", "purpose": purpose, "no_resolve": mode,
                                "sources": ["https://example.org/missing-cdn.txt"], "whitelist": []},
                               {"name": "dependent", "purpose": purpose, "no_resolve": mode,
                                "sources": ["cdn/FIN.TXT"], "whitelist": ["absent.list"]}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    previous = r25_old_files(root, ("cdn", "dependent"))
                    with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(FileNotFoundError) as failure:
                        publish(generate(root, lambda url: self.fail("whitelist validation must precede fetch: " + url)))
                    self.assertEqual(Path(failure.exception.filename), root / "absent.list")
                    self.assertEqual(stderr.getvalue(), "")
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive group aliases")
    def test_windows_case_alias_header_only_dependencies_publish_complete_products(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                for dependency in ("sources", "whitelist"):
                    for filename in NAMES:
                        with self.subTest(purpose=purpose, mode=mode, dependency=dependency, filename=filename), \
                                tempfile.TemporaryDirectory(dir=staging) as directory:
                            root = Path(directory)
                            configs = [{"name": "CDN", "purpose": purpose, "no_resolve": mode,
                                        "sources": ["source.list"], "whitelist": ["allow.list"]},
                                       {"name": "DEPENDENT", "purpose": purpose, "no_resolve": mode,
                                        "sources": ["healthy.list"], "whitelist": []}]
                            configs[1][dependency] = [f"cdn/{filename.upper()}"]
                            (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                            (root / "source.list").write_text("IP-CIDR,192.0.2.0/24,no-resolve\n", encoding="utf-8")
                            (root / "allow.list").write_text("IP-CIDR,192.0.2.0/24,DIRECT\n", encoding="utf-8")
                            (root / "healthy.list").write_text(R25_SOURCE, encoding="utf-8")
                            previous = r25_old_files(root, ("cdn", "dependent"))
                            before = datetime.now().astimezone()
                            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                                outputs = generate(root, lambda url: self.fail(url))
                            after = datetime.now().astimezone()
                            skips = "" if dependency == "sources" else (
                                ("DEPENDENT fin-adb.txt:DOMAIN: 1\n" if purpose != "block" else "") +
                                "DEPENDENT fin-adb.txt:IP-CIDR: 2\nDEPENDENT fin-surge-ds.txt:IP-CIDR: 2\n")
                            if dependency == "sources" and filename == "fin-adb.txt":
                                source = (root / "cdn" / filename).resolve()
                                skips = "".join(f"{source}: line {number}: invalid rule\n" for number in range(1, 6))
                                skips += f"{source}: {7 if purpose == 'block' else 8} skipped lines; first five shown\n"
                            self.assertEqual(stderr.getvalue(), skips)
                            self._assert_r25_publication(root, outputs, previous,
                                                         [("CDN", True), ("DEPENDENT", dependency == "sources")],
                                                         purpose, mode, before, after)

    @unittest.skipUnless(os.name == "nt", "Requires real Windows case-insensitive group aliases")
    def test_windows_case_alias_forward_dependencies_reject_stale_products(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                for dependency in ("sources", "whitelist"):
                    for filename in NAMES:
                        with self.subTest(purpose=purpose, mode=mode, dependency=dependency, filename=filename), \
                                tempfile.TemporaryDirectory(dir=staging) as directory:
                            root = Path(directory)
                            configs = [{"name": "dependent", "purpose": purpose, "no_resolve": mode,
                                        "sources": ["healthy.list"], "whitelist": []},
                                       {"name": "CDN", "purpose": purpose, "no_resolve": mode,
                                        "sources": ["https://example.org/missing-cdn.txt"], "whitelist": []}]
                            configs[0][dependency] = [f"cdn/{filename.upper()}"]
                            (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                            (root / "healthy.list").write_text(R25_SOURCE, encoding="utf-8")
                            previous = r25_old_files(root, ("cdn", "dependent"))
                            with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(ValueError) as failure:
                                publish(generate(root, lambda url: self.fail("forward dependency must precede fetch: " + url)))
                            self.assertEqual(str(failure.exception),
                                             f"Dependent output not yet generated: {(root / 'cdn' / filename).resolve()}")
                            self.assertEqual(stderr.getvalue(), "")
                            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    @unittest.skipIf(os.name == "nt", "Case-distinct freeze identities require a case-sensitive platform")
    def test_case_distinct_freeze_does_not_freeze_healthy_group_on_case_sensitive_platform(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=staging) as directory:
            root = Path(directory)
            (root / "cdn").mkdir()
            if (root / "CDN").exists():
                self.skipTest("This filesystem does not support case-distinct directories")
            (root / "CDN").mkdir()
            (root / "dependent").mkdir()
            for purpose in ("block", "proxy", "direct"):
                for mode in ("add", "strip", "keep"):
                    with self.subTest(purpose=purpose, mode=mode):
                        configs = [{"name": group, "purpose": purpose, "no_resolve": mode,
                                    "sources": ["https://example.org/missing.txt" if group == "CDN" else
                                                "healthy.list" if group == "cdn" else "cdn/fin.yaml"], "whitelist": []}
                                   for group in ("CDN", "cdn", "dependent")]
                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                        (root / "healthy.list").write_text(R25_SOURCE, encoding="utf-8")
                        previous = {}
                        for group in ("CDN", "cdn", "dependent"):
                            for name in NAMES:
                                path = root / group / name
                                previous[path] = f"OLD::{group}::{name}\r\n".encode() + b"\x00\x80\xff"
                                path.write_bytes(previous[path])

                        def fetch(url):
                            raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

                        before = datetime.now().astimezone()
                        with contextlib.redirect_stderr(io.StringIO()):
                            outputs = generate(root, fetch)
                        after = datetime.now().astimezone()
                        self._assert_r25_publication(root, outputs, previous, [("cdn", False), ("dependent", False)],
                                                     purpose, mode, before, after)

    def test_missing_local_whitelist_still_aborts_when_source_is_404(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"a3": [missing]}, whitelist={"a3": ["allow.list"]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(FileNotFoundError):
                    publish(generate(root, fetch))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_frozen_dependency_does_not_hide_missing_local_whitelist(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"cdn": [missing], "big-data": ["cdn/fin.txt"]},
                             whitelist={"big-data": ["allow.list"]})
            for group in ("a3", "dirt"):
                (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
            for group in ("cdn", "big-data"):
                for name in NAMES:
                    (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(FileNotFoundError):
                    publish(generate(root, fetch))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_missing_old_file_in_frozen_group_aborts_entire_round(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            missing = "https://example.org/missing.txt"
            configure_groups(root, sources={"dirt": [missing]})
            for group in GROUPS:
                if group != "dirt":
                    (root / group / "rules.txt").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    if group != "dirt" or name != "fin.yaml":
                        (root / group / name).write_bytes(b"previous version\n")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with self.assertRaisesRegex(ValueError, r"dirt.*fin.yaml"):
                publish(generate(root, fetch))
            self.assertEqual((root / "cdn" / "fin.txt").read_bytes(), b"previous version\n")

    def test_html_labeled_mixed_source_keeps_rules_around_markup(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/mixed.txt"
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": [url], "whitelist": [],
            }]), encoding="utf-8")
            (root / "a3").mkdir()
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            response = BytesIO(b"DOMAIN,one.example\n<html>noise</html>\nDOMAIN,two.example\n")
            response.geturl = lambda: url
            response.headers = {"Content-Type": "text/html"}
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            text = outputs[root / "a3" / "fin.txt"]
            self.assertIn("DOMAIN,one.example\n", text)
            self.assertIn("DOMAIN,two.example\n", text)
            self.assertIn(f"{url}: line 2: HTML", stderr.getvalue())

    def test_http_200_html_remote_source_is_skipped_with_warning(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/login.txt"
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": [url, "good.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "good.list").write_text("DOMAIN,good.example\n", encoding="utf-8")
            response = BytesIO(b"<html><body>DOMAIN,evil.example</body></html>")
            response.geturl = lambda: url
            response.headers = {"Content-Type": "text/html"}
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            self.assertIn("DOMAIN,good.example\n", outputs[root / "a3" / "fin.txt"])
            self.assertNotIn("evil.example", outputs[root / "a3" / "fin.txt"])
            self.assertIn(f"{url}: line 1: HTML", stderr.getvalue())

    def test_remote_whitelist_html_200_is_skipped_with_warning(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"<html><body>login</body></html>")
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("HTML", stderr.getvalue())

    def test_bad_utf8_remote_line_keeps_other_complete_rules_and_line_number(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/mixed.txt"
            configure_groups(root, sources={"a3": [url]})
            for group in GROUPS:
                if group != "a3":
                    (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"DOMAIN,first.example.org\nDOMAIN,\xffbad.example.org\nDOMAIN,last.example.org\n")
            text = outputs[root / "a3" / "fin.txt"]
            self.assertIn("DOMAIN,first.example.org", text)
            self.assertIn("DOMAIN,last.example.org", text)
            self.assertNotIn("bad.example.org", text)
            self.assertIn(f"{url}: line 2", stderr.getvalue())
            self.assertIn("UTF-8", stderr.getvalue())

    def test_whitelist_covering_every_block_replaces_stale_dns_and_six_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["block.list"], "whitelist": ["allow.list"],
            }]), encoding="utf-8")
            (root / "block.list").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            (root / "allow.list").write_text("DOMAIN,ads.example.org,DIRECT\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "a3" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = "||ads.example.org^\n" if name == "fin-adb.txt" else "previous version\n"
                path.write_text(previous[path], encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), set(previous))
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@|ads.example.org|"])
            publish(outputs)
            for path in previous:
                self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                self.assertNotEqual(outputs[path], previous[path])

    def test_whitelist_covering_ip_source_replaces_old_six_files_without_dns_exception(self):
        for group, purpose, action in (("a3", "block", "REJECT"),
                                       ("cdn", "proxy", "PROXY"),
                                       ("dirt", "direct", "DIRECT")):
            with self.subTest(group=group), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                (root / "rulesets.json").write_text(json.dumps([{
                    "name": group, "purpose": purpose, "no_resolve": "keep",
                    "sources": ["source.list"], "whitelist": ["allow.list"],
                }]), encoding="utf-8")
                (root / "source.list").write_text(
                    f"IP-CIDR,203.0.113.0/24,{action}\n", encoding="utf-8",
                )
                (root / "allow.list").write_text(
                    "IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8",
                )
                previous = {}
                for name in NAMES:
                    path = root / group / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = "IP-CIDR,203.0.113.0/24\n"
                    path.write_text(previous[path], encoding="utf-8")
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
                self.assertEqual(set(outputs), set(previous))
                self.assertEqual(outputs[root / group / "fin.txt"], f"# {group} rules: 0\n")
                self.assertEqual(outputs[root / group / "fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 0"] if purpose == "block" else
                                 ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                publish(outputs)
                for path in previous:
                    self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                    self.assertNotEqual(outputs[path], previous[path])

    def test_allow_only_source_replaces_stale_dns_and_six_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "rulesets.json").write_text(json.dumps([{
                "name": "a3", "purpose": "block", "no_resolve": "keep",
                "sources": ["allow.list"], "whitelist": [],
            }]), encoding="utf-8")
            (root / "allow.list").write_text("@@||safe.example.org^\n", encoding="utf-8")
            previous = {}
            for name in NAMES:
                path = root / "a3" / name
                path.parent.mkdir(exist_ok=True)
                previous[path] = "||safe.example.org^\n" if name == "fin-adb.txt" else "previous version\n"
                path.write_text(previous[path], encoding="utf-8")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), set(previous))
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@||safe.example.org^"])
            publish(outputs)
            for path in previous:
                self.assertEqual(path.read_text(encoding="utf-8"), outputs[path])
                self.assertNotEqual(outputs[path], previous[path])

    def test_unavailable_or_unadaptable_source_with_unrelated_whitelist_stays_frozen(self):
        for source in ("missing", "unadaptable"):
            with self.subTest(source=source), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                url = "https://example.org/missing.txt"
                (root / "rulesets.json").write_text(json.dumps([{
                    "name": "a3", "purpose": "block", "no_resolve": "keep",
                    "sources": [url], "whitelist": ["allow.list"],
                }]), encoding="utf-8")
                (root / "allow.list").write_text("DOMAIN,unrelated.example.org,DIRECT\n", encoding="utf-8")
                previous = {}
                for name in NAMES:
                    path = root / "a3" / name
                    path.parent.mkdir(exist_ok=True)
                    previous[path] = "previous version\n"
                    path.write_text(previous[path], encoding="utf-8")

                def fetch(_):
                    if source == "missing":
                        raise RuntimeError("source unavailable") from error.HTTPError(url, 404, "Not Found", {}, None)
                    return b"UNKNOWN-TYPE,ads.example.org\n"

                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, fetch)
                self.assertEqual(outputs, {})
                publish(outputs)
                self.assertEqual({path: path.read_text(encoding="utf-8") for path in previous}, previous)

    def test_only_dns_allow_without_routable_rules_publishes_group(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "@@||safe.example.org^\n" if group == "a3" else "DOMAIN,current.example.org\n",
                    encoding="utf-8",
                )
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual({root / "a3" / name for name in NAMES}, {path for path in outputs if path.parent.name == "a3"})
            self.assertEqual(len(outputs), 24)
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@||safe.example.org^"])

    def test_wholly_bad_utf8_remote_whitelist_is_skipped(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"\xff\xfe")
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("skipped", stderr.getvalue())

    def test_whitelist_removing_all_routes_publishes_dns_exceptions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, whitelist={"a3": ["allow.list"]})
            (root / "allow.list").write_text("DOMAIN,ads.example.org,DIRECT\n", encoding="utf-8")
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            for name in NAMES:
                (root / "a3" / name).write_bytes(b"previous version\n")
            outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(set(outputs), {root / group / name for group in GROUPS for name in NAMES})
            self.assertEqual(outputs[root / "a3" / "fin-adb.txt"].splitlines()[6:],
                             ["! Total count: 1", "@@|ads.example.org|"])

    def test_remote_whitelist_unsupported_only_warns_and_skips(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"USER-AGENT,*bot*,DIRECT\n")
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("skipped", stderr.getvalue())

    def test_http_200_html_remote_whitelist_is_skipped_by_generate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text("DOMAIN,ads.example.org\n", encoding="utf-8")
            response = BytesIO(b"<html>login</html>")
            response.geturl = lambda: url
            response.headers = {"Content-Type": "text/html"}
            stderr = io.StringIO()
            with patch("urllib.request.OpenerDirector.open", return_value=response):
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, fetch_https)
            self.assertIn("DOMAIN,ads.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn(url, stderr.getvalue())
            self.assertIn("HTML", stderr.getvalue())

    def test_remote_whitelist_keeps_recognized_lines_around_bad_utf8_and_unsupported(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            url = "https://example.org/allow.txt"
            configure_groups(root, whitelist={"a3": [url]})
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN,remove.example.org\nDOMAIN,keep.example.org\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outputs = generate(root, lambda _: b"DOMAIN,\xffbad.example.org\nUSER-AGENT,*bot*,DIRECT\nDOMAIN,remove.example.org,DIRECT\n")
            self.assertNotIn("DOMAIN,remove.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn("DOMAIN,keep.example.org", outputs[root / "a3" / "fin.txt"])
            self.assertIn("@@|remove.example.org|", outputs[root / "a3" / "fin-adb.txt"])
            self.assertIn(f"{url}: line 1", stderr.getvalue())

    def test_a3_and_a4_freeze_independently_when_configured(self):
        for frozen in ("a3", "a4"):
            with self.subTest(frozen=frozen), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                missing = f"https://example.org/{frozen}.txt"
                groups = [
                    {"name": name, "purpose": "block", "no_resolve": "keep",
                     "sources": [missing if name == frozen else f"{name}.list"], "whitelist": []}
                    for name in ("a3", "a4")
                ]
                (root / "rulesets.json").write_text(json.dumps(groups), encoding="utf-8")
                healthy = "a4" if frozen == "a3" else "a3"
                (root / f"{healthy}.list").write_text("DOMAIN,current.example.org\n", encoding="utf-8")
                for name in NAMES:
                    path = root / frozen / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(b"previous version\n")

                def fetch(url):
                    raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

                with contextlib.redirect_stderr(io.StringIO()):
                    outputs = generate(root, fetch)
                self.assertEqual(set(outputs), {root / healthy / name for name in NAMES})
                publish(outputs)
                self.assertTrue(all((root / frozen / name).read_bytes() == b"previous version\n" for name in NAMES))
                self.assertIn("DOMAIN,current.example.org", (root / healthy / "fin.txt").read_text(encoding="utf-8"))

    def test_remote_html_or_unsupported_only_200_source_skips_but_keeps_good_source(self):
        for body in (b"<html><body>login</body></html>", b"UNKNOWN-TYPE,ads.example.org\n"):
            with self.subTest(body=body), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root = Path(directory)
                bad = "https://example.org/bad.txt"
                good = "https://example.org/good.txt"
                configure_groups(root, sources={"a3": [bad, good]})
                for group in GROUPS:
                    if group != "a3":
                        (root / group / "rules.txt").write_text("DOMAIN,baseline.example.org\n", encoding="utf-8")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    outputs = generate(root, lambda url: body if url == bad else b"DOMAIN,good.example.org\n")
                self.assertIn("DOMAIN,good.example.org", outputs[root / "a3" / "fin.txt"])
                self.assertIn(bad, stderr.getvalue())
                self.assertIn("skipped", stderr.getvalue())

    def test_automatic_no_resolve_allows_cidr_coalescing_across_source_options(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25,no-resolve\n"
                    if group == "a3" else "DOMAIN,baseline.example.org\n", encoding="utf-8",
                )
            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, lambda _: self.fail("local input must not fetch"))
            rules = outputs[root / "a3" / "fin.txt"].splitlines()[1:]
            self.assertEqual(rules, ["IP-CIDR,192.0.2.0/24,no-resolve"])

    def test_repeat_build_has_identical_utf8_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root)
            for group in GROUPS:
                (root / group / "rules.txt").write_text(
                    "DOMAIN-SUFFIX,example.com\nIP-CIDR,203.0.113.0/24\n", encoding="utf-8",
                )
            with contextlib.redirect_stderr(io.StringIO()), patch("formats.datetime") as clock:
                clock.now.side_effect = lambda tz: datetime(2026, 9, 29, tzinfo=timezone.utc).astimezone(tz)
                first = generate(root, lambda _: self.fail("local input must not fetch"))
                second = generate(root, lambda _: self.fail("local input must not fetch"))
            self.assertEqual(
                {path: text.encode("utf-8") for path, text in first.items()},
                {path: text.encode("utf-8") for path, text in second.items()},
            )

    def test_offline_build_produces_six_files_per_group_without_writing_them(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configure_groups(root, sources={group: [f"https://example.org/{group}.txt"] for group in GROUPS})
            contents = {
                f"https://example.org/{group}.txt": b"DOMAIN,ads.example.org\n"
                for group in GROUPS
            }
            outputs = generate(root, contents.__getitem__)
            self.assertEqual(len(outputs), 24)
            self.assertEqual(set(outputs), {root / group / name for group in GROUPS for name in NAMES})
            self.assertFalse(any(path.exists() for path in outputs))

    def _resolved_directory_alias(self, root):
        alias = root / "parent"
        try:
            alias.symlink_to(root / "physical", target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and exc.winerror == 1314:
                self.skipTest(f"Directory symlink unavailable: {exc}")
            raise
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve(), root / "physical")
        self.assertTrue(alias.resolve().is_relative_to(root))

    def _resolved_alias_products(self, group, kind, value, *, domain_source="surge", whitelist=()):
        keyword = kind == "DOMAIN-KEYWORD"
        payload = (value if keyword else expected_domain(kind, value).partition(",")[2])
        yaml_kind = "DOMAIN-REGEX" if domain_source == "surge" else kind
        if domain_source != "surge":
            payload = value
        record = [[kind, value, [], False, False, False, domain_source]]
        yaml = "  - " + json.dumps(yaml_kind + "," + payload) + " # rconvert-rule-v1 " + \
            json.dumps(record, separators=(",", ":")) + "\n"
        dns = ["@@" + (f"/^.*{item}.*$/" if keyword else f"|{item}|") for item in whitelist]
        dns.append(f"/^.*{value}.*$/" if keyword else f"0.0.0.0 {value}")
        return {
            "fin.txt": f"# {group} rules: 1\n{kind},{value}\n",
            "fin-qx.txt": f"# {group} rules: 1\nHOST{'-KEYWORD' if keyword else ''},{value},LIST\n",
            "fin.yaml": f"# {group} rules: 1\npayload:\n" + yaml,
            "fin-adb.txt": (f"[Adblock Plus 2.0]\n! Title: {group}\n"
                            "! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n"
                            "! License: Inherits upstream licenses\n! Version: 202601021104\n"
                            f"! Total count: {len(dns)}\n" + "".join(item + "\n" for item in dns)),
            "fin-surge.txt": f"# {group} rules: {1 if keyword else 0}\n" +
                             (f"{kind},{value}\n" if keyword else ""),
            "fin-surge-ds.txt": f"# {group} rules: {0 if keyword else 1}\n" +
                                ("" if keyword else value + "\n"),
        }

    def test_resolved_directory_alias_sources_publish_and_reimport_all_six_formats(self):
        from rules import Rule, parse

        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        with patch("formats.datetime") as clock:
            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
            for alias in (True, False):
                for filename in NAMES:
                    with self.subTest(alias=alias, filename=filename), tempfile.TemporaryDirectory(dir=staging) as directory:
                        root = Path(directory)
                        previous = r25_old_files(root, ("physical" if alias else "parent", "child"))
                        if alias:
                            self._resolved_directory_alias(root)
                        kind, new, stale = (("DOMAIN-KEYWORD", "new", "stale") if filename == "fin-surge.txt" else
                                            ("DOMAIN", "new.example.org", "stale.example.org"))
                        selected = (root / "parent" / filename).resolve()
                        previous[selected] = f"# stale\n{kind},{stale}\n".encode()
                        selected.write_bytes(previous[selected])
                        (root / "input.list").write_text(f"{kind},{new}\n", encoding="utf-8")
                        configs = [{"name": group, "purpose": "block", "no_resolve": "keep",
                                    "sources": ["input.list" if group == "parent" else f"parent/./{filename}"],
                                    "whitelist": []} for group in ("parent", "child")]
                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                        expected = {(root / "parent" / name).resolve(): text for name, text in
                                    self._resolved_alias_products("parent", kind, new).items()}
                        source = "qx" if filename == "fin-qx.txt" else "surge"
                        expected.update({root / "child" / name: text for name, text in
                                         self._resolved_alias_products("child", kind, new, domain_source=source).items()})
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(outputs[root / "child" / "fin.txt"], expected[root / "child" / "fin.txt"])
                        self.assertEqual(outputs, expected)
                        self.assertEqual(list(outputs), list(expected))
                        warnings = (f"parent fin-surge-ds.txt:{kind}: 1\n" if kind == "DOMAIN-KEYWORD" else "")
                        if filename == "fin-adb.txt":
                            warnings += "".join(f"{selected}: line {number}: invalid rule\n" for number in range(1, 6))
                            warnings += f"{selected}: 7 skipped lines; first five shown\n"
                        if kind == "DOMAIN-KEYWORD":
                            warnings += f"child fin-surge-ds.txt:{kind}: 1\n"
                        self.assertEqual(stderr.getvalue(), warnings)
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        self.assertEqual(parse(outputs[root / "child" / "fin.yaml"], purpose="block"),
                                         ([Rule(kind, new, domain_source=source)], []))
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode("utf-8") for path, text in expected.items()})
                        parent_bytes = {path: path.read_bytes() for path in expected if path.parent != root / "child"}
                        (root / "input.list").unlink()
                        (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as disk_stderr:
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent == root / "child"})
                        self.assertEqual(disk_stderr.getvalue(), warnings.removeprefix(
                            f"parent fin-surge-ds.txt:{kind}: 1\n") if kind == "DOMAIN-KEYWORD" else warnings)
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in disk},
                                         {path: text.encode("utf-8") for path, text in disk.items()})
                        self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)

    def test_resolved_directory_alias_whitelists_remove_new_and_keep_stale_in_all_six_formats(self):
        import warnings

        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        with patch("formats.datetime") as clock:
            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
            for alias in (True, False):
                for filename in NAMES:
                    with self.subTest(alias=alias, filename=filename), tempfile.TemporaryDirectory(dir=staging) as directory:
                        root = Path(directory)
                        previous = r25_old_files(root, ("physical" if alias else "parent", "child"))
                        if alias:
                            self._resolved_directory_alias(root)
                        kind, new, stale = (("DOMAIN-KEYWORD", "new", "stale") if filename == "fin-surge.txt" else
                                            ("DOMAIN", "new.example.org", "stale.example.org"))
                        selected = (root / "parent" / filename).resolve()
                        previous[selected] = f"# stale\n{kind},{stale}\n".encode()
                        selected.write_bytes(previous[selected])
                        (root / "input.list").write_text(f"{kind},{new}\n", encoding="utf-8")
                        source = "qx" if filename == "fin-qx.txt" else "surge"
                        child_kind = "HOST" if source == "qx" else kind
                        (root / "child.list").write_text(f"{child_kind},{new}\n{child_kind},{stale}\n", encoding="utf-8")
                        configs = [{"name": "parent", "purpose": "block", "no_resolve": "keep",
                                    "sources": ["input.list"], "whitelist": []},
                                   {"name": "child", "purpose": "block", "no_resolve": "keep",
                                    "sources": ["child.list"], "whitelist": [f"parent/{filename}"]}]
                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                        expected = {(root / "parent" / name).resolve(): text for name, text in
                                    self._resolved_alias_products("parent", kind, new).items()}
                        expected.update({root / "child" / name: text for name, text in
                                         self._resolved_alias_products("child", kind, stale, domain_source=source,
                                                                       whitelist=(new,)).items()})
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, warnings.catch_warnings(record=True) as notices:
                            warnings.simplefilter("always")
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(outputs[root / "child" / "fin.txt"], expected[root / "child" / "fin.txt"])
                        self.assertEqual(outputs, expected)
                        expected_warnings = (f"parent fin-surge-ds.txt:{kind}: 1\nchild fin-surge-ds.txt:{kind}: 1\n"
                                             if kind == "DOMAIN-KEYWORD" else "")
                        self.assertEqual(stderr.getvalue(), expected_warnings)
                        header_warnings = [f"line {number}: invalid rule" for number in range(1, 8)] if filename == "fin-adb.txt" else []
                        self.assertEqual([str(notice.message) for notice in notices], header_warnings)
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode("utf-8") for path, text in expected.items()})
                        parent_bytes = {path: path.read_bytes() for path in expected if path.parent != root / "child"}
                        (root / "input.list").unlink()
                        (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as disk_stderr, warnings.catch_warnings(record=True) as notices:
                            warnings.simplefilter("always")
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent == root / "child"})
                        self.assertEqual(disk_stderr.getvalue(), f"child fin-surge-ds.txt:{kind}: 1\n"
                                         if kind == "DOMAIN-KEYWORD" else "")
                        self.assertEqual([str(notice.message) for notice in notices], header_warnings)
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in disk},
                                         {path: text.encode("utf-8") for path, text in disk.items()})
                        self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)

    def test_resolved_directory_alias_forward_source_and_whitelist_reject_stale_files(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for dependency in ("sources", "whitelist"):
            for filename in NAMES:
                with self.subTest(dependency=dependency, filename=filename), tempfile.TemporaryDirectory(dir=staging) as directory:
                    root = Path(directory)
                    previous = r25_old_files(root, ("physical", "child"))
                    self._resolved_directory_alias(root)
                    selected = (root / "parent" / filename).resolve()
                    previous[selected] = b"# stale\nDOMAIN,stale.example.org\n"
                    selected.write_bytes(previous[selected])
                    (root / "input.list").write_text("DOMAIN,new.example.org\n", encoding="utf-8")
                    configs = [{"name": group, "purpose": "block", "no_resolve": "keep",
                                "sources": ["input.list"], "whitelist": []} for group in ("child", "parent")]
                    configs[0][dependency] = [f"parent/{filename}"]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(ValueError) as failure:
                        publish(generate(root, lambda url: self.fail(url)))
                    self.assertEqual(str(failure.exception), f"Dependent output not yet generated: {selected}")
                    self.assertEqual(stderr.getvalue(), "")
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_resolved_directory_alias_freeze_keeps_all_old_bytes_and_updates_healthy_group(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        missing = "https://example.org/missing-parent.txt"
        for reason in ("404", "no-rules", "no-routable"):
            for dependency in ("sources", "whitelist"):
                for filename in NAMES:
                    with self.subTest(reason=reason, dependency=dependency, filename=filename), \
                            tempfile.TemporaryDirectory(dir=staging) as directory, patch("formats.datetime") as clock:
                        clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                        root = Path(directory)
                        previous = r25_old_files(root, ("physical", "child", "archive", "healthy"))
                        self._resolved_directory_alias(root)
                        selected = (root / "parent" / filename).resolve()
                        previous[selected] = b"# stale\r\nDOMAIN,stale.example.org\r\n# \x00\r\n"
                        selected.write_bytes(previous[selected])
                        (root / "input.list").write_text("DOMAIN,new.example.org\n", encoding="utf-8")
                        (root / "bad.yaml").write_text('payload:\n  - "USER-AGENT,A\\0B"\n', encoding="utf-8")
                        configs = [{"name": group, "purpose": "block", "no_resolve": "keep",
                                    "sources": ["input.list"], "whitelist": []}
                                   for group in ("parent", "child", "archive", "healthy")]
                        configs[0]["sources"] = ["bad.yaml" if reason == "no-routable" else missing]
                        configs[1][dependency] = [f"physical/{filename}"]
                        configs[2]["whitelist"] = ["child/fin.txt"]
                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")

                        def fetch(url):
                            self.assertEqual(url, missing)
                            if reason == "404":
                                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)
                            return b"# no rules\n"

                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            outputs = generate(root, fetch)
                        expected = {root / "healthy" / name: text for name, text in
                                    self._resolved_alias_products("healthy", "DOMAIN", "new.example.org").items()}
                        self.assertEqual(outputs, expected)
                        self.assertEqual(list(outputs), list(expected))
                        cause = (f"{missing}: HTTP 404; skipped\n" if reason == "404" else
                                 f"{missing}: no adaptable rules; skipped\n" if reason == "no-rules" else
                                 "parent: no routable rules; frozen\n")
                        self.assertEqual(stderr.getvalue(), cause)
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in previous},
                                         {path: expected[path].encode("utf-8") if path in expected else old
                                          for path, old in previous.items()})

    def test_resolved_file_alias_freeze_tracks_the_exact_output_paths(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=staging) as directory:
            root = Path(directory)
            previous = r25_old_files(root, ("parent", "storage", "child"))
            selected = root / "parent" / "fin.txt"
            selected.unlink()
            previous.pop(selected)
            try:
                selected.symlink_to(root / "storage" / "fin.txt")
            except OSError as exc:
                if os.name == "nt" and exc.winerror == 1314:
                    self.skipTest(f"File symlink unavailable: {exc}")
                raise
            target = selected.resolve()
            previous[target] = b"# stale\r\nDOMAIN,stale.example.org\r\n# \x00\r\n"
            target.write_bytes(previous[target])
            self.assertTrue(selected.is_symlink())
            self.assertTrue(target.is_relative_to(root))
            (root / "rulesets.json").write_text(json.dumps([
                {"name": group, "purpose": "block", "no_resolve": "keep",
                 "sources": ["https://example.org/missing.txt" if group == "parent" else "parent/fin.txt"],
                 "whitelist": []} for group in ("parent", "child")]), encoding="utf-8")

            def fetch(url):
                raise RuntimeError(f"Failed to fetch {url}") from error.HTTPError(url, 404, "Not Found", {}, None)

            with contextlib.redirect_stderr(io.StringIO()):
                outputs = generate(root, fetch)
            self.assertEqual(outputs, {})
            publish(outputs)
            self.assertTrue(selected.is_symlink())
            self.assertEqual({path: path.read_bytes() for path in previous}, previous)

    def test_resolved_directory_alias_collision_reuses_existing_rejection(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=staging) as directory:
            root = Path(directory)
            r25_old_files(root, ("physical",))
            self._resolved_directory_alias(root)
            (root / "rulesets.json").write_text(json.dumps([
                {"name": group, "purpose": "block", "no_resolve": "keep",
                 "sources": ["https://example.org/missing.txt"], "whitelist": []}
                for group in ("parent", "physical")]), encoding="utf-8")
            self._assert_output_collision_rejected(root, root / "parent" / "fin.txt", root / "physical" / "fin.txt")

    def test_resolved_directory_alias_yaml_preserves_nine_purpose_and_no_resolve_modes(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=staging) as directory, \
                        patch("formats.datetime") as clock:
                    clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                    root = Path(directory)
                    previous = r25_old_files(root, ("physical", "child"))
                    self._resolved_directory_alias(root)
                    selected = root / "physical" / "fin.yaml"
                    previous[selected] = b'payload:\n  - DOMAIN,stale.example.org\n'
                    selected.write_bytes(previous[selected])
                    (root / "input.list").write_text(R25_SOURCE, encoding="utf-8")
                    configs = [{"name": group, "purpose": purpose, "no_resolve": mode,
                                "sources": ["input.list" if group == "parent" else "physical/../physical/fin.yaml"],
                                "whitelist": []} for group in ("parent", "child")]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    expected = {(root / group / name).resolve(): text
                                for group in ("parent", "child")
                                for name, text in r25_expected(group, purpose, mode, "! Version: 202601021104").items()}
                    with contextlib.redirect_stderr(io.StringIO()):
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual(outputs, expected)
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    publish(outputs)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode("utf-8") for path, text in expected.items()})
                    parent_bytes = {path: path.read_bytes() for path in expected if path.parent != root / "child"}
                    (root / "input.list").unlink()
                    (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent == root / "child"})
                    publish(disk)
                    self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)

    def _resolved_file_alias(self, root, filename, destination, previous):
        alias = root / "parent" / filename
        alias.unlink()
        previous.pop(alias)
        target = root / "storage" / destination
        target.write_bytes(b"# stale\r\nDOMAIN,stale.example.org\r\n# \x00\r\n")
        previous[target] = target.read_bytes()
        try:
            alias.symlink_to(target)
        except OSError as exc:
            if os.name == "nt" and exc.winerror == 1314:
                self.skipTest(f"File symlink unavailable: {exc}")
            raise
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve(), target)
        self.assertTrue(target.is_relative_to(root))
        return target

    def test_resolved_file_alias_product_format_sources_and_whitelists(self):
        import warnings
        from rules import Rule, parse

        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for dependency in ("sources", "whitelist"):
            for filename in NAMES:
                other = "fin-adb.txt" if filename == "fin.yaml" else "fin.yaml"
                for destination in (filename, other):
                    with self.subTest(dependency=dependency, filename=filename, destination=destination), \
                            tempfile.TemporaryDirectory(dir=staging) as directory, patch("formats.datetime") as clock:
                        clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                        root = Path(directory)
                        previous = r25_old_files(root, ("parent", "child", "storage"))
                        selected = self._resolved_file_alias(root, filename, destination, previous)
                        kind, new, stale = (("DOMAIN-KEYWORD", "new", "stale") if filename == "fin-surge.txt" else
                                            ("DOMAIN", "new.example.org", "stale.example.org"))
                        source = "qx" if filename == "fin-qx.txt" else "surge"
                        child_kind = "HOST" if source == "qx" else kind
                        (root / "input.list").write_text(f"{kind},{new}\n", encoding="utf-8")
                        (root / "child.list").write_text(f"{child_kind},{new}\n{child_kind},{stale}\n", encoding="utf-8")
                        configs = [{"name": group, "purpose": "block", "no_resolve": "keep",
                                    "sources": ["input.list" if group == "parent" else "child.list"],
                                    "whitelist": []} for group in ("parent", "child")]
                        configs[1][dependency] = [f"parent/{filename}"]
                        (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                        expected = {(root / "parent" / name).resolve(): text for name, text in
                                    self._resolved_alias_products("parent", kind, new).items()}
                        expected.update({root / "child" / name: text for name, text in
                                         self._resolved_alias_products("child", kind, stale if dependency == "whitelist" else new,
                                                                       domain_source=source,
                                                                       whitelist=(new,) if dependency == "whitelist" else ()).items()})
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, warnings.catch_warnings(record=True) as notices:
                            warnings.simplefilter("always")
                            outputs = generate(root, lambda url: self.fail(url))
                        self.assertEqual(outputs, expected)
                        self.assertEqual(list(outputs), list(expected))
                        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                        messages = ("parent fin-surge-ds.txt:DOMAIN-KEYWORD: 1\n" if kind == "DOMAIN-KEYWORD" else "")
                        if filename == "fin-adb.txt" and dependency == "sources":
                            messages += "".join(f"{selected}: line {number}: invalid rule\n" for number in range(1, 6))
                            messages += f"{selected}: 7 skipped lines; first five shown\n"
                        if kind == "DOMAIN-KEYWORD":
                            messages += "child fin-surge-ds.txt:DOMAIN-KEYWORD: 1\n"
                        self.assertEqual(stderr.getvalue(), messages)
                        header_warnings = [f"line {number}: invalid rule" for number in range(1, 8)] \
                            if filename == "fin-adb.txt" and dependency == "whitelist" else []
                        self.assertEqual([str(notice.message) for notice in notices], header_warnings)
                        self.assertEqual(parse(outputs[root / "child" / "fin.yaml"], purpose="block"),
                                         ([Rule(kind, stale if dependency == "whitelist" else new, domain_source=source)], []))
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode("utf-8") for path, text in expected.items()})
                        parent_bytes = {path: path.read_bytes() for path in outputs if path.parent != root / "child"}
                        (root / "input.list").unlink()
                        (root / "rulesets.json").unlink()
                        (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                        with contextlib.redirect_stderr(io.StringIO()) as disk_stderr, warnings.catch_warnings(record=True) as disk_notices:
                            warnings.simplefilter("always")
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent == root / "child"})
                        self.assertEqual(disk_stderr.getvalue(), messages.removeprefix(
                            "parent fin-surge-ds.txt:DOMAIN-KEYWORD: 1\n") if kind == "DOMAIN-KEYWORD" else messages)
                        self.assertEqual([str(notice.message) for notice in disk_notices], header_warnings)
                        publish(disk)
                        self.assertEqual({path: path.read_bytes() for path in disk},
                                         {path: text.encode("utf-8") for path, text in disk.items()})
                        self.assertEqual({path: path.read_bytes() for path in parent_bytes}, parent_bytes)
                        self.assertTrue((root / "parent" / filename).is_symlink())

    def test_resolved_file_alias_empty_products_preserve_nine_purpose_and_no_resolve_modes(self):
        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for purpose in ("block", "proxy", "direct"):
            for mode in ("add", "strip", "keep"):
                for filename in ("fin.yaml", "fin-adb.txt"):
                    for dependency in ("sources", "whitelist"):
                        with self.subTest(purpose=purpose, mode=mode, filename=filename, dependency=dependency), \
                                tempfile.TemporaryDirectory(dir=staging) as directory, patch("formats.datetime") as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            previous = r25_old_files(root, ("parent", "child", "storage"))
                            selected = self._resolved_file_alias(root, filename, "saved-output.list", previous)
                            nonblock = filename == "fin-adb.txt" and purpose != "block"
                            (root / "input.list").write_text(R25_SOURCE if nonblock else "IP-CIDR,203.0.113.0/24\n", encoding="utf-8")
                            (root / "allow.list").write_text("IP-CIDR,203.0.113.0/24,DIRECT\n", encoding="utf-8")
                            (root / "child.list").write_text(R25_SOURCE, encoding="utf-8")
                            configs = [{"name": "parent", "purpose": purpose, "no_resolve": mode,
                                        "sources": ["input.list"], "whitelist": [] if nonblock else ["allow.list"]},
                                       {"name": "child", "purpose": purpose, "no_resolve": mode,
                                        "sources": ["child.list"], "whitelist": []}]
                            configs[1][dependency] = [f"parent/{filename}"]
                            (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                            expected = {(root / group / name).resolve(): text for group in ("parent", "child")
                                        for name, text in r25_expected(group, purpose, mode, "! Version: 202601021104",
                                                                      empty=not nonblock if group == "parent" else dependency == "sources").items()}
                            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual(outputs, expected)
                            self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                            skips = {"fin-adb.txt:IP-CIDR": 2, "fin-surge-ds.txt:IP-CIDR": 2}
                            if purpose != "block":
                                skips["fin-adb.txt:DOMAIN"] = 1
                            expected_messages = "".join(f"parent {key}: {count}\n" for key, count in sorted(skips.items())) if nonblock else ""
                            if filename == "fin-adb.txt" and dependency == "sources":
                                expected_messages += "".join(f"{selected}: line {number}: invalid rule\n" for number in range(1, 6))
                                expected_messages += f"{selected}: {8 if nonblock else 7} skipped lines; first five shown\n"
                            if dependency == "whitelist":
                                expected_messages += "".join(f"child {key}: {count}\n" for key, count in sorted(skips.items()))
                            self.assertEqual(stderr.getvalue(), expected_messages)
                            publish(outputs)
                            self.assertEqual({path: path.read_bytes() for path in outputs},
                                             {path: text.encode("utf-8") for path, text in expected.items()})
                            published = {path: path.read_bytes() for path in outputs}
                            (root / "input.list").unlink()
                            (root / "allow.list").unlink()
                            (root / "rulesets.json").write_text(json.dumps(configs[1:]), encoding="utf-8")
                            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ValueError) as failure:
                                generate(root, lambda url: self.fail(url))
                            self.assertIn("No adaptable rules" if dependency == "sources" else "Invalid whitelist", str(failure.exception))
                            self.assertIn(str(selected), str(failure.exception))
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_resolved_file_alias_unsupported_generated_whitelist_rejects_complete_body(self):
        from rules import GeneratedRuleError

        staging = ROOT / ".tmp"
        staging.mkdir(exist_ok=True)
        for filename in ("fin.txt", "fin.yaml"):
            for destination in (filename, "fin.yaml" if filename == "fin.txt" else "fin-adb.txt"):
                with self.subTest(filename=filename, destination=destination), tempfile.TemporaryDirectory(dir=staging) as directory:
                    root = Path(directory)
                    previous = r25_old_files(root, ("parent", "child", "storage"))
                    selected = self._resolved_file_alias(root, filename, destination, previous)
                    (root / "input.list").write_text("PROCESS-NAME,Game.exe,REJECT\n", encoding="utf-8")
                    (root / "child.list").write_text("DOMAIN,keep.example.org\n", encoding="utf-8")
                    configs = [{"name": "parent", "purpose": "block", "no_resolve": "keep",
                                "sources": ["input.list"], "whitelist": []},
                               {"name": "child", "purpose": "block", "no_resolve": "keep",
                                "sources": ["child.list"], "whitelist": [f"parent/{filename}"]}]
                    (root / "rulesets.json").write_text(json.dumps(configs), encoding="utf-8")
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ValueError) as failure:
                        publish(generate(root, lambda url: self.fail(url)))
                    self.assertEqual(type(failure.exception), GeneratedRuleError if filename == "fin.yaml" else ValueError)
                    self.assertEqual(str(failure.exception), f"Invalid whitelist {selected}: " +
                                     ("line 3: unsupported whitelist rule PROCESS-NAME" if filename == "fin.yaml" else
                                      "line 2: unsupported rule"))
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)


class PublicGeneratedPipelineTests(unittest.TestCase):
    @staticmethod
    def expected(group, purpose, mode, *, child=False):
        from rules import Rule

        flag = '' if mode == 'strip' else ',no-resolve'
        logic = '((DOMAIN,logic.example.net),(IP-CIDR,198.51.100.0/24' + flag + '),(SRC-IP-CIDR,203.0.113.1/32))'
        surge_logic = 'AND,' + logic.replace('SRC-IP-CIDR,', 'SRC-IP,')
        target_logic = 'AND,((' + expected_domain('DOMAIN', 'logic.example.net') + '),(IP-CIDR,198.51.100.0/24' + flag + '),(SRC-IP-CIDR,203.0.113.1/32))'
        keyword = Rule('DOMAIN-KEYWORD', 'ΟΣ', domain_source='mihomo')
        native = Rule('DOMAIN', 'NATIVE.EXAMPLE.ORG.', domain_source='mihomo')
        exact = Rule('DOMAIN', 'keep.example.org')
        suffix = Rule('DOMAIN-SUFFIX', 'broad.example.net')
        ip = Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ())
        source = Rule('SRC-IP', '127.0.0.1')
        logical = Rule('AND', logic)
        pairs = [(target_logic, logical), ('DOMAIN,NATIVE.EXAMPLE.ORG.', native),
                 ('DOMAIN-KEYWORD,ΟΣ', keyword)]
        if not child:
            pairs.append((expected_domain('DOMAIN', exact.value), exact))
        pairs += [(expected_domain('DOMAIN-SUFFIX', suffix.value), suffix),
                  ('IP-CIDR,192.0.2.0/24' + flag, ip), ('SRC-IP-CIDR,127.0.0.1/32', source)]
        yaml_lines = []
        for payload, rule in pairs:
            record = [rule.kind, rule.value, list(rule.options), False, False, False, rule.domain_source]
            yaml_lines.append('  - ' + json.dumps(payload, ensure_ascii=False) + ' # rconvert-rule-v1 ' +
                              json.dumps([record], ensure_ascii=True, separators=(',', ':')))
        domains = ([] if child else ['DOMAIN,keep.example.org']) + ['DOMAIN,NATIVE.EXAMPLE.ORG.']
        hosts = ([] if child else ['HOST,keep.example.org,LIST']) + ['HOST,NATIVE.EXAMPLE.ORG.,LIST']
        ds = ([] if child else ['keep.example.org']) + ['.broad.example.net', 'NATIVE.EXAMPLE.ORG.']
        dns = (['@@|keep.example.org|'] if child else []) + [r'/(?s-i:\A.*οσ.*\z)/', '||broad.example.net^'] + (
            [] if child else ['0.0.0.0 keep.example.org']) + ['0.0.0.0 NATIVE.EXAMPLE.ORG.']
        bodies = {'fin.txt': [surge_logic, *domains, 'DOMAIN-KEYWORD,ΟΣ', 'DOMAIN-SUFFIX,broad.example.net',
                              'IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,127.0.0.1'],
                  'fin-qx.txt': [*hosts, 'HOST-KEYWORD,ΟΣ,LIST', 'HOST-SUFFIX,broad.example.net,LIST',
                                 'IP-CIDR,192.0.2.0/24,LIST' + flag],
                  'fin.yaml': yaml_lines,
                  'fin-surge.txt': [surge_logic, 'DOMAIN-KEYWORD,ΟΣ', 'IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,127.0.0.1'],
                  'fin-surge-ds.txt': ds}
        expected = {name: f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '') +
                    ''.join(line + '\n' for line in body) for name, body in bodies.items()}
        expected['fin-adb.txt'] = (
            f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
            '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610071200\n' +
            (f'! Total count: {len(dns)}\n' + ''.join(line + '\n' for line in dns) if purpose == 'block' else
             '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))
        skipped = {'fin-adb.txt:AND': 1, 'fin-adb.txt:IP-CIDR': 1, 'fin-adb.txt:SRC-IP': 1,
                   'fin-qx.txt:AND': 1, 'fin-qx.txt:SRC-IP': 1, 'fin-surge-ds.txt:AND': 1,
                   'fin-surge-ds.txt:DOMAIN-KEYWORD': 1, 'fin-surge-ds.txt:IP-CIDR': 1, 'fin-surge-ds.txt:SRC-IP': 1}
        if purpose != 'block':
            skipped.update({'fin-adb.txt:DOMAIN': 1 if child else 2, 'fin-adb.txt:DOMAIN-SUFFIX': 1,
                            'fin-adb.txt:DOMAIN-KEYWORD': 1})
        return expected, [rule for _, rule in pairs], skipped

    def test_nine_modes_full_six_texts_metadata_same_round_whitelist_and_disk_publish(self):
        from rules import parse

        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode, 'sources': sources, 'whitelist': white}
                               for group, sources, white in (
                                   ('parent', ['ordinary.list', 'native.yaml'], []), ('white', ['white.list'], []),
                                   ('child', ['parent/fin.yaml'], ['white/fin.yaml']))]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'ordinary.list').write_text(
                        'DOMAIN,keep.example.org\nDOMAIN-SUFFIX,broad.example.net\nIP-CIDR,192.0.2.0/24,no-resolve\n'
                        'SRC-IP,127.0.0.1\nAND,((DOMAIN,logic.example.net),(IP-CIDR,198.51.100.0/24,no-resolve),'
                        '(SRC-IP-CIDR,203.0.113.1/32))\n', encoding='utf-8')
                    (root / 'native.yaml').write_text('payload:\n  - DOMAIN,NATIVE.EXAMPLE.ORG.\n  - DOMAIN-KEYWORD,ΟΣ\n', encoding='utf-8')
                    (root / 'white.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
                    old = {}
                    for group in ('parent', 'white', 'child'):
                        (root / group).mkdir()
                        for name in NAMES:
                            path = root / group / name
                            old[path] = bytes(range(256))
                            path.write_bytes(old[path])
                    for disk in (False, True):
                        if disk:
                            for name in ('ordinary.list', 'native.yaml', 'white.list'):
                                (root / name).unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                        before = {path: path.read_bytes() for path in old}
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
                            outputs = generate(root, lambda url: self.fail(url))
                        groups = ('child',) if disk else ('parent', 'white', 'child')
                        self.assertEqual(set(outputs), {root / group / name for group in groups for name in NAMES})
                        wanted_messages = []
                        for group in ('parent', 'child') if not disk else ('child',):
                            expected, identities, skipped = self.expected(group, purpose, mode, child=group == 'child')
                            self.assertEqual({path.name: text for path, text in outputs.items() if path.parent.name == group}, expected)
                            self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose), (identities, []))
                            wanted_messages.extend(f'{group} {key}: {count}' for key, count in sorted(skipped.items()))
                        if not disk and purpose != 'block':
                            position = next(index for index, line in enumerate(wanted_messages) if line.startswith('child '))
                            wanted_messages.insert(position, 'white fin-adb.txt:DOMAIN: 1')
                        self.assertEqual(stderr.getvalue().splitlines(), wanted_messages)
                        self.assertEqual({path: path.read_bytes() for path in old}, before)
                        publish(outputs)
                        self.assertEqual({path: path.read_bytes() for path in outputs},
                                         {path: text.encode('utf-8') for path, text in outputs.items()})
                        if disk:
                            self.assertEqual({path: path.read_bytes() for path in old if path.parent.name != 'child'},
                                             {path: data for path, data in before.items() if path.parent.name != 'child'})
                            self.assertFalse((root / 'ordinary.list').exists())
                            self.assertFalse((root / 'native.yaml').exists())
                            self.assertFalse((root / 'white.list').exists())

    def test_generated_unsupported_whitelist_is_terminal_and_preserves_all_old_binary_files(self):
        from rules import GeneratedRuleError

        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    config = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['white.list'], 'whitelist': []},
                              {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['source.list'], 'whitelist': ['white/fin.yaml']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'white.list').write_text('DOMAIN,keep.example.org\nDEST-PORT,443\nDST-PORT,443\n', encoding='utf-8')
                    (root / 'source.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
                    old = {}
                    for group in ('white', 'child'):
                        (root / group).mkdir()
                        for name in NAMES:
                            old[root / group / name] = bytes(range(256))
                            (root / group / name).write_bytes(old[root / group / name])
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(GeneratedRuleError, r'white.*fin.yaml.*line 4:'):
                        publish(generate(root, lambda url: self.fail(url)))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)


class PublicGeneratedDeepAndFailureTests(unittest.TestCase):
    def test_flat_metadata_binding_and_publish_disk_at_600_and_1000_layers(self):
        code = r'''
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch
from generate import generate, publish
from rules import Rule, parse
from tests.test_formats import expected_domain
limit = sys.getrecursionlimit()
assert limit == 1000
names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
def matcher(flag):
    leaf = '(AND,((IP-CIDR,192.0.2.0/24' + flag + '),(SRC-IP-CIDR,198.51.100.0/24),(NETWORK,tcp)))'
    return ('(NOT,(' * DEPTH + leaf + '))' * DEPTH)[1:-1]
plain = matcher('') + '\n' + matcher(',no-resolve') + '\nDOMAIN,keep.example.org\n'
native = 'payload:\n' + ''.join('  - ' + json.dumps(matcher(flag)) + '\n' for flag in ('', ',no-resolve'))
neighbor = Rule('DOMAIN', 'keep.example.org')
initial = [Rule('NOT', matcher(flag)[4:], native_fields=native_fields)
           for native_fields in (False, True) for flag in ('', ',no-resolve')]
assert parse(plain, purpose=PURPOSE) == (initial[:2] + [neighbor], [])
assert parse(native, purpose=PURPOSE) == (initial[2:], [])
flags = ('', ',no-resolve') if MODE == 'keep' else (',no-resolve',) if MODE == 'add' else ('',)
expected_rules = [neighbor]
yaml_lines = ['  - ' + json.dumps(expected_domain('DOMAIN', neighbor.value)) + ' # rconvert-rule-v1 ' +
              json.dumps([['DOMAIN', neighbor.value, [], False, False, False, 'surge']], separators=(',', ':'))]
for flag in flags:
    payload = matcher(flag)
    records = [['NOT', payload[4:], [], False, False, native_fields, 'surge'] for native_fields in (False, True)]
    yaml_lines.append('  - ' + json.dumps(payload) + ' # rconvert-rule-v1 ' + json.dumps(records, separators=(',', ':')))
    expected_rules.extend(Rule('NOT', payload[4:], native_fields=native_fields) for native_fields in (False, True))
with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
    root = Path(directory)
    configs = [{'name': 'parent', 'purpose': PURPOSE, 'no_resolve': MODE,
                'sources': ['ordinary.list', 'native.yaml'], 'whitelist': []},
               {'name': 'child', 'purpose': PURPOSE, 'no_resolve': MODE,
                'sources': ['parent/fin.yaml'], 'whitelist': []}]
    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
    (root / 'ordinary.list').write_text(plain, encoding='utf-8')
    (root / 'native.yaml').write_text(native, encoding='utf-8')
    for disk in (False, True):
        if disk:
            parent_bytes = {root / 'parent' / name: (root / 'parent' / name).read_bytes() for name in names}
            (root / 'ordinary.list').unlink()
            (root / 'native.yaml').unlink()
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
        with contextlib.redirect_stderr(io.StringIO()) as stderr, patch('formats.datetime') as clock:
            clock.now.return_value = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
            outputs = generate(root, lambda url: (_ for _ in ()).throw(AssertionError(url)))
        groups = ('child',) if disk else ('parent', 'child')
        count = 2 * len(flags)
        skips = {name + ':NOT': count for name in names if name != 'fin.yaml'}
        if PURPOSE != 'block':
            skips['fin-adb.txt:DOMAIN'] = 1
        assert stderr.getvalue().splitlines() == [f'{group} {key}: {value}' for group in groups for key, value in sorted(skips.items())]
        for group in groups:
            wanted = f'# {group} rules: {len(yaml_lines)}\npayload:\n' + ''.join(line + '\n' for line in yaml_lines)
            assert outputs[root / group / 'fin.yaml'] == wanted
            assert parse(wanted, purpose=PURPOSE) == (expected_rules, [])
            for scalar in yaml_lines:
                records = json.loads(scalar.partition(' # rconvert-rule-v1 ')[2])
                assert all(len(record) == 7 and isinstance(record[1], str) for record in records)
            for name, body in (('fin.txt', 'DOMAIN,keep.example.org\n'), ('fin-qx.txt', 'HOST,keep.example.org,LIST\n'),
                               ('fin-surge.txt', ''), ('fin-surge-ds.txt', 'keep.example.org\n')):
                assert outputs[root / group / name] == f'# {group} rules: {int(bool(body))}\n' + body
            dns = (f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
                   '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610071200\n' +
                   ('! Total count: 1\n0.0.0.0 keep.example.org\n' if PURPOSE == 'block' else
                    '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))
            assert outputs[root / group / 'fin-adb.txt'] == dns
        publish(outputs)
        assert {path: path.read_bytes() for path in outputs} == {path: text.encode('utf-8') for path, text in outputs.items()}
        if disk:
            assert {path: path.read_bytes() for path in parent_bytes} == parent_bytes
            assert not (root / 'ordinary.list').exists() and not (root / 'native.yaml').exists()
        for group in ('parent', 'child'):
            assert parse((root / group / 'fin.yaml').read_text(encoding='utf-8'), purpose=PURPOSE) == (expected_rules, [])
assert sys.getrecursionlimit() == limit
'''
        for depth in (600, 1000):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(depth=depth, purpose=purpose, mode=mode):
                        settings = f'DEPTH={depth}\nPURPOSE={purpose!r}\nMODE={mode!r}\n'
                        result = subprocess.run([sys.executable, '-B', '-c', settings + code], cwd=ROOT,
                                                capture_output=True, text=True, timeout=8)
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_remote_marked_failures_before_decode_html_skip_and_publish(self):
        from rules import GeneratedRuleError

        prefix = b'\xef\xbb\xbf<html>\r\n</html>\r\npayload:\r\n  - '
        declarations = (b'"DOMAIN,keep.example.org" # rconvert-rule-v2 []',
                        b'"DOMAIN,keep.example.org" # rconvert-rule-v1 null',
                        b'"DOMAIN,keep.example.org" # rconvert-rule-v1 \xff',
                        b'"DOMAIN,keep.example.org\\q" # rconvert-rule-v1 []',
                        b'"DOMAIN,keep.example.org" junk # rconvert-rule-v1 []',
                        b'"DOMAIN,keep.example.org\x00" # rconvert-rule-v1 []',
                        b'"DOMAIN,keep.example.org\xff" # rconvert-rule-v1 []',
                        b'"DOMAIN,keep.example.org" # rconvert-rule-v1 [["DOMAIN","other.example.org",[],false,false,false,"mihomo"]]')
        for remote in (False, True):
            for white in (False, True):
                for declaration in declarations:
                    with self.subTest(remote=remote, white=white, declaration=declaration), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                        root = Path(directory)
                        endpoint = 'https://example.org/marked.yaml' if remote else 'marked.yaml'
                        config = [{'name': 'consumer', 'purpose': 'block', 'no_resolve': 'keep',
                                   'sources': ['good.list'] if white else [endpoint],
                                   'whitelist': [endpoint] if white else []}]
                        (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                        (root / 'good.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
                        data = prefix + declaration + b'\r\n'
                        (root / 'marked.yaml').write_bytes(data)
                        (root / 'consumer').mkdir()
                        old = {root / 'consumer' / name: bytes(range(256)) for name in NAMES}
                        for path, value in old.items():
                            path.write_bytes(value)
                        with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaisesRegex(GeneratedRuleError, r'line 4:'):
                            publish(generate(root, lambda url: data))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        self.assertNotIn('invalid UTF-8; skipped', stderr.getvalue())
                        self.assertNotIn('invalid whitelist', stderr.getvalue())

    def test_real_generated_publish_failure_restores_binary_bytes_and_removes_new_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            configs = [{'name': group, 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': ['input.list'], 'whitelist': []} for group in ('old', 'new')]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'input.list').write_text('DOMAIN,keep.example.org\n', encoding='utf-8')
            (root / 'old').mkdir()
            old = {root / 'old' / name: bytes(range(256)) for name in NAMES}
            for path, value in old.items():
                path.write_bytes(value)
            with contextlib.redirect_stderr(io.StringIO()):
                output = generate(root, lambda url: self.fail(url))
            ordered = {path: text for group in ('new', 'old') for path, text in output.items() if path.parent.name == group}
            actual_replace = os.replace
            calls = 0
            def fail_second_existing(source, destination):
                nonlocal calls
                calls += 1
                if calls == 8:
                    raise OSError('public generated replacement failure')
                return actual_replace(source, destination)
            with patch('generate.os.replace', side_effect=fail_second_existing), self.assertRaisesRegex(OSError, 'public generated replacement failure'):
                publish(ordered)
            self.assertGreater(calls, 8)
            self.assertEqual({path: path.read_bytes() for path in old}, old)
            self.assertFalse((root / 'new').exists())
