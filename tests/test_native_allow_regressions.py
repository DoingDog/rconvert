import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


ROOT = Path(__file__).resolve().parents[1]


def expected_outputs(group, purpose, *, ip=False, mode='keep'):
    flag = ',no-resolve' if ip and mode == 'add' else ''
    matcher = 'IP-CIDR,198.51.100.0/24' + flag if ip else 'DOMAIN,safe.example.org'
    dns = [] if ip or purpose != 'block' else ['0.0.0.0 safe.example.org']
    return {'fin.txt': f'# {group} rules: 1\n{matcher}\n',
            'fin-surge.txt': f'# {group} rules: {int(ip)}\n' + (matcher + '\n' if ip else ''),
            'fin-surge-ds.txt': f'# {group} rules: {int(not ip)}\n' + ('' if ip else 'safe.example.org\n'),
            'fin-qx.txt': f'# {group} rules: 1\n' + ('IP-CIDR,198.51.100.0/24,LIST' + flag if ip else 'HOST,safe.example.org,LIST') + '\n',
            'fin.yaml': f'# {group} rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n',
            'fin-adb.txt': ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                '! License: Inherits upstream licenses\n! Version: 202610240000\n' +
                f'! Total count: {len(dns)}\n' + ''.join(line + '\n' for line in dns) +
                ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n'))}


class NativeAllowRegressionTests(unittest.TestCase):
    def test_decoded_native_abp_allow_is_rejected_at_its_physical_line(self):
        parsed, messages = parse('payload:\n  - "@@||safe.example.org^"\n', purpose='block')
        self.assertEqual(parsed, [])
        self.assertEqual(messages, ['line 2: invalid native rule'])

    def test_headers_quoted_escapes_and_plain_restrictions_reject_only_decoded_item_start(self):
        items = ('"@@||safe.example.org^"', "'@@||safe.example.org^'",
                 '"\\x40\\u0040||safe.example.org^"', '"\\U00000040@||safe.example.org^"',
                 '"@@DOMAIN,safe.example.org"', '"@@||safe.example.org^$important"',
                 '@@||safe.example.org^')
        for header in ('payload', 'rules'):
            for item in items:
                for purpose in ('block', 'direct', 'proxy'):
                    text = '﻿# input\r\n' + header + ':\r\n\r\n  - ' + item + '\r\n  - DOMAIN,neighbor.test\r\n'
                    with self.subTest(header=header, item=item, purpose=purpose):
                        parsed, messages = parse(text, purpose=purpose)
                        self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.test', domain_source='mihomo')])
                        self.assertEqual(messages, ['line 4: ' + ('invalid YAML payload' if item.startswith('@') else 'invalid native rule')])
                        self.assertFalse(any(rule.allow for rule in parsed))
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            self.assertEqual(parse_whitelist(text), parsed)
                        self.assertEqual([str(item.message) for item in caught], messages)
                        only = header + ':\n  - ' + item + '\n'
                        with self.assertRaisesRegex(ValueError, '^line 2: invalid '):
                            parse_whitelist(only)
        for literal in ('DOMAIN-KEYWORD,@@tag', 'PROCESS-NAME,@@tool', 'DOMAIN-REGEX,^@@tag$'):
            expected = Rule(*literal.split(',', 1), literal_process=literal.startswith('PROCESS-NAME'),
                            domain_source='mihomo' if literal.startswith('DOMAIN-KEYWORD') else 'surge')
            self.assertEqual(parse('payload:\n  - ' + json.dumps(literal), purpose='block'), ([expected], []))

    def test_native_mixed_shortcuts_and_top_level_allow_keep_their_existing_behavior(self):
        cases = (('safe.example.org', Rule('DOMAIN', 'safe.example.org')),
                 ('192.0.2.0/24', Rule('IP-CIDR', '192.0.2.0/24')),
                 ('HOST,safe.example.org', Rule('DOMAIN', 'safe.example.org', domain_source='qx')),
                 ('0.0.0.0 safe.example.org', Rule('DOMAIN', 'safe.example.org')),
                 ('||safe.example.org^', Rule('DOMAIN-SUFFIX', 'safe.example.org')))
        for header in ('payload', 'rules'):
            for source, expected in cases:
                for item in (source, "'" + source + "'", json.dumps(source)):
                    with self.subTest(header=header, item=item):
                        result = parse(header + ':\n  - ' + item, purpose='block')
                        self.assertEqual(result, ([], ['line 2: invalid YAML payload']) if item.startswith('|')
                                         else ([expected], []))
        allowed = Rule('DOMAIN-SUFFIX', 'safe.example.org', allow=True)
        self.assertEqual(parse('@@||safe.example.org^', purpose='block'), ([allowed], []))
        self.assertEqual(parse_whitelist('@@||safe.example.org^'), [Rule('DOMAIN-SUFFIX', 'safe.example.org')])
        source = [Rule('DOMAIN', 'safe.example.org'), Rule('DOMAIN', 'neighbor.test'), allowed]
        self.assertEqual(exclude_covered(iter(source), iter([allowed])), source[1:])
        self.assertEqual(normalize(iter(reversed(source + source))), normalize(source))
        for allow_fixture in ([allowed], parse('@@||safe.example.org^', purpose='block')[0]):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    outputs, _ = render('allow', source[:2] + allow_fixture, purpose=purpose, no_resolve=mode)
                    self.assertEqual(outputs['fin.txt'], '# allow rules: 1\nDOMAIN,neighbor.test\n')
                    self.assertEqual([line for line in outputs['fin-adb.txt'].splitlines()[7:] if line.startswith('@@')],
                                     ['@@||safe.example.org^'] if purpose == 'block' else [])
        for invalid, reason in (('||safe.example.org^$important', 'conditional ABP rule'), ('||safe.example.org^junk', 'invalid rule')):
            self.assertEqual(parse(invalid, purpose='block'), ([], ['line 1: ' + reason]))

    def test_real_source_and_white_do_not_delete_safe_routes_or_emit_dns_exceptions(self):
        for header in ('payload', 'rules'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(header=header, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/source.yaml').write_bytes(('﻿' + header + ':\r\n  - "@@||safe.example.org^"\r\n'
                                                                  '  - safe.example.org\r\n').encode())
                        (root / 'static/white.yaml').write_bytes(('﻿' + header + ':\r\n  - "\\x40@||safe.example.org^"\r\n'
                                                                 '  - IP-CIDR,198.51.100.0/24\r\n').encode())
                        (root / 'static/healthy.list').write_bytes(b'DOMAIN,safe.example.org\r\n')
                        (root / 'static/marker').write_bytes(b'static\x00\xff\r\n')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [dict(name=group, purpose=purpose, no_resolve=mode, sources=sources, whitelist=white)
                                   for group, sources, white in
                                   (('parent', ['static/source.yaml'], ['static/white.yaml']),
                                    ('whiteparent', ['static/white.yaml'], []),
                                    ('sourcechild', ['parent/fin.txt'], ['static/white.yaml']),
                                    ('whitechild', ['static/healthy.list'], ['whiteparent/fin.yaml']))]
                        config = root / 'rulesets.json'
                        config.write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for item in configs:
                            (root / item['name']).mkdir()
                            for name in FILES:
                                path = root / item['name'] / name
                                old[path] = b'old complete product\x00\xff\r\n'
                                path.write_bytes(old[path])
                        expected = {root / item['name'] / name: text for item in configs
                                    for name, text in expected_outputs(item['name'], purpose,
                                        ip=item['name'] == 'whiteparent', mode=mode).items()}
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as logs, warnings.catch_warnings(record=True) as caught:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            warnings.simplefilter('always')
                            outputs = generate(root, self.fail)
                        self.assertEqual(outputs, expected)
                        self.assertEqual([str(item.message) for item in caught], ['line 2: invalid native rule'])
                        self.assertNotIn('frozen', logs.getvalue())
                        self.assertIn('line 2: invalid native rule', logs.getvalue())
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode() for path, text in expected.items()})
                        config.write_text(json.dumps(configs[2:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()), warnings.catch_warnings():
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            warnings.simplefilter('ignore', UserWarning)
                            disk = generate(root, self.fail)
                        self.assertEqual(disk, {path: text for path, text in expected.items()
                                               if path.parent.name in ('sourcechild', 'whitechild')})
                        publish(disk, root=root)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                        for role, message in (('sources', 'No adaptable rules in'), ('whitelist', 'Invalid whitelist')):
                            (root / 'bad.yaml').write_bytes((header + ':\r\n  - "@@||safe.example.org^"\r\n').encode())
                            invalid = dict(configs[2], sources=['static/healthy.list'], whitelist=[])
                            invalid[role] = ['bad.yaml']
                            config.write_text(json.dumps([invalid]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, message):
                                publish(generate(root, self.fail), root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_valid_single_native_source_publishes_without_neighbor_masking(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'input.yaml').write_bytes(b'payload:\n  - safe.example.org\n')
                    (root / 'rulesets.json').write_text(json.dumps([dict(name='single', purpose=purpose,
                        no_resolve=mode, sources=['input.yaml'], whitelist=[])]), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                        clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                        outputs = generate(root, self.fail)
                    self.assertEqual(outputs, {root / 'single' / name: text
                                               for name, text in expected_outputs('single', purpose).items()})
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode() for path, text in outputs.items()})

    def test_invalid_remote_only_source_freezes_complete_old_group_and_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            (root / 'static/healthy.list').write_bytes(b'DOMAIN,safe.example.org\n')
            (root / 'static/marker').write_bytes(b'static\x00\xff')
            inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
            configs = [dict(name=group, purpose='block', no_resolve='keep', sources=sources, whitelist=white)
                       for group, sources, white in (('parent', ['https://example.test/source'], []),
                           ('child', ['parent/fin.yaml'], []),
                           ('whitechild', ['static/healthy.list'], ['parent/fin.yaml']),
                           ('healthy', ['static/healthy.list'], []))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            old = {}
            for group in ('parent', 'child', 'whitechild'):
                (root / group).mkdir()
                for name in FILES:
                    path = root / group / name
                    old[path] = b'old complete product\x00\xff\r\n'
                    path.write_bytes(old[path])
            with contextlib.redirect_stderr(io.StringIO()) as logs:
                outputs = generate(root, lambda url: b'payload:\n  - "@@||safe.example.org^"\n')
            self.assertEqual(set(outputs), {root / 'healthy' / name for name in FILES})
            self.assertIn('line 2: invalid native rule', logs.getvalue())
            self.assertIn('https://example.test/source: no adaptable rules; skipped', logs.getvalue())
            publish(outputs, root=root)
            self.assertEqual({path: path.read_bytes() for path in old}, old)
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_cli_rejects_invalid_local_source_and_white_without_touching_products(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input.list').write_bytes(b'DOMAIN,safe.example.org\n')
            (root / 'bad.yaml').write_bytes(b'\xef\xbb\xbfpayload:\r\n  - "@@||safe.example.org^"\r\n')
            (root / 'static').mkdir()
            marker = root / 'static/marker'
            marker.write_bytes(b'static\x00\xff')
            (root / 'group').mkdir()
            old = {root / 'group' / name: b'old complete product\x00\xff' for name in FILES}
            for path, data in old.items():
                path.write_bytes(data)
            command = [sys.executable, '-I', '-B', '-c',
                "import runpy,sys; root=sys.argv.pop(1); sys.path.insert(0,root); runpy.run_path(root+'/generate.py',run_name='__main__')",
                str(ROOT), '--root', str(root)]
            for role, message in (('sources', 'No adaptable rules in'), ('whitelist', 'Invalid whitelist')):
                config = dict(name='group', purpose='block', no_resolve='keep', sources=['input.list'], whitelist=[])
                config[role] = ['bad.yaml']
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=8)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                self.assertEqual(marker.read_bytes(), b'static\x00\xff')
