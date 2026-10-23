import contextlib
from datetime import datetime, timezone
import io
import ipaddress
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


def expected_products(group, purpose, bodies):
    products = {}
    for name in FILES:
        rows = bodies.get(name, [])
        if name == 'fin-adb.txt':
            header = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n'
                      '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                      '! License: Inherits upstream licenses\n! Version: 202610230000\n' +
                      f'! Total count: {len(rows)}\n')
            if purpose != 'block':
                rows = ['! No AdBlock rules for non-advertising group.']
        else:
            header = f'# {group} rules: {len(rows)}\n'
            if name == 'fin.yaml':
                header += 'payload:\n'
                rows = ['  - ' + json.dumps(row) for row in rows]
        products[name] = header + ''.join(row + '\n' for row in rows)
    return products


class CidrWhitelistUnionTests(unittest.TestCase):
    def test_two_ipv4_halves_cover_parsed_parent(self):
        source, messages = parse('IP-CIDR,192.0.2.0/24', purpose='block')
        white = parse_whitelist('IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25')
        self.assertEqual(messages, [])
        self.assertEqual({address for entry in white for address in ipaddress.ip_network(entry.value)},
                         set(ipaddress.ip_network('192.0.2.0/24')))
        self.assertEqual(exclude_covered(iter(source), iter(white)), [])

    def test_parsed_ipv6_aliases_and_source_directions_share_complete_union(self):
        for source_kind in ('IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR'):
            for white_kind in ('IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR'):
                for native in (False, True):
                    source_text = source_kind + ',2001:db8::/32'
                    white_text = white_kind + ',2001:db8::/33\n' + white_kind + ',2001:db8:8000::/33'
                    if native:
                        source_text = 'payload:\n  - ' + source_text
                        white_text = 'rules:\n  - ' + white_text.replace('\n', '\n  - ')
                    with self.subTest(source=source_kind, white=white_kind, native=native):
                        source, messages = parse(source_text, purpose='block')
                        white = parse_whitelist(white_text)
                        self.assertEqual(messages, [])
                        self.assertEqual(len(source), 1)
                        self.assertEqual(len(white), 2)
                        self.assertEqual(exclude_covered(iter(source), iter(white)),
                                         [] if source_kind.startswith('SRC-') == white_kind.startswith('SRC-') else source)
        for native, tail in ((False, ',DIRECT,src'), (True, ',src')):
            source = 'IP-CIDR,192.0.2.0/24' + tail
            white = '\n'.join('IP-CIDR,' + value + tail for value in ('192.0.2.0/25', '192.0.2.128/25'))
            if native:
                source = 'payload:\n  - ' + source
                white = 'payload:\n  - ' + white.replace('\n', '\n  - ')
            parsed, messages = parse(source, purpose='direct')
            self.assertEqual((parsed, messages), ([Rule('SRC-IP-CIDR', '192.0.2.0/24')], []))
            self.assertEqual(exclude_covered(parsed, parse_whitelist(white)), [])

    def test_hosts_extreme_prefixes_and_multilevel_unions(self):
        cases = (
            ('SRC-IP-CIDR,192.0.2.0/31', 'SRC-IP,192.0.2.0\nSRC-IP,192.0.2.1'),
            ('SRC-IP-CIDR,2001:db8::/127', 'SRC-IP,2001:db8::\nSRC-IP,2001:db8::1'),
            ('SRC-IP-CIDR,2001:db8::/127', 'SRC-IP,2001:db8::\nSRC-IP-CIDR,2001:db8::1/128'),
            ('IP-CIDR,0.0.0.0/0', 'IP-CIDR,0.0.0.0/1\nIP-CIDR,128.0.0.0/1'),
            ('IP-CIDR6,::/0', 'IP-CIDR,::/1\nIP-CIDR6,8000::/1'),
            ('SRC-IP-CIDR,0.0.0.0/0', 'SRC-IP-CIDR,0.0.0.0/1\nSRC-IP-CIDR,128.0.0.0/1'),
            ('SRC-IP-CIDR,::/0', 'SRC-IP-CIDR,::/1\nSRC-IP-CIDR,8000::/1'),
            ('IP-CIDR,192.0.2.1/32', 'IP-CIDR,192.0.2.1/32'),
            ('IP-CIDR6,2001:db8::1/128', 'IP-CIDR,2001:db8::1/128'),
            ('SRC-IP,192.0.2.1', 'SRC-IP,192.0.2.1'),
            ('SRC-IP,2001:db8::1', 'SRC-IP-CIDR,2001:db8::1/128'),
            ('IP-CIDR,192.0.2.0/24', 'IP-CIDR,192.0.2.0/26\nIP-CIDR,192.0.2.64/27\n'
             'IP-CIDR,192.0.2.96/27\nIP-CIDR,192.0.2.128/25\nIP-CIDR,192.0.2.160/27'),
            ('SRC-IP-CIDR,2001:db8::/124', 'SRC-IP-CIDR,2001:db8::/126\n'
             'SRC-IP-CIDR,2001:db8::4/127\nSRC-IP-CIDR,2001:db8::6/127\n'
             'SRC-IP-CIDR,2001:db8::8/125\nSRC-IP,2001:db8::f'),
        )
        for source_text, white_text in cases:
            with self.subTest(source=source_text):
                source, messages = parse(source_text, purpose='proxy')
                self.assertEqual(messages, [])
                white = parse_whitelist(white_text)
                for entries in (white, list(reversed(white)), white + white):
                    self.assertEqual(exclude_covered(iter(source), iter(entries)), [])

    def test_partial_union_never_splits_source_or_mixes_direction_and_family(self):
        for kind, parent, halves, gap, elsewhere in (
            ('IP-CIDR', '192.0.2.0/30', ('192.0.2.0/31', '192.0.2.2/31'),
             '192.0.2.2/32', '192.0.2.4/31'),
            ('IP-CIDR6', '2001:db8::/126', ('2001:db8::/127', '2001:db8::2/127'),
             '2001:db8::2/128', '2001:db8::4/127'),
        ):
            for direction in (kind, 'SRC-IP-CIDR'):
                source = Rule(direction, parent)
                other = kind if direction == 'SRC-IP-CIDR' else 'SRC-IP-CIDR'
                whites = ([Rule(direction, halves[0])],
                          [Rule(direction, halves[0]), Rule(direction, elsewhere)],
                          [Rule(direction, halves[0]), Rule(direction, gap)],
                          [Rule(direction, halves[0]), Rule(other, halves[1])])
                for white in whites:
                    with self.subTest(source=source, white=white):
                        kept = exclude_covered(iter([source]), iter(white))
                        self.assertEqual(kept, [source])
                        self.assertIs(kept[0], source)
        for kind, parent, white in (
            ('IP-CIDR', '192.0.2.0/23', ('192.0.2.0/25', '192.0.2.128/25')),
            ('IP-CIDR6', '2001:db8::/31', ('2001:db8::/33', '2001:db8:8000::/33')),
            ('IP-CIDR', '0.0.0.0/31', ('0.0.0.0/32', '::1/128')),
            ('IP-CIDR6', '::/127', ('::/128', '0.0.0.1/32')),
        ):
            source = Rule(kind, parent)
            entries = [Rule('IP-CIDR', value) for value in white]
            with self.subTest(source=source):
                self.assertEqual(exclude_covered([source], entries), [source])

    def test_preserves_objects_order_allow_and_non_network_coverage(self):
        covered = Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',))
        allowed = Rule('IP-CIDR', covered.value, allow=True)
        source, messages = parse('DOMAIN,keep.example\nDOMAIN-REGEX,^keep$\nIP-ASN,64512\n'
                                 'GEOIP,CN\nIP-SUFFIX,192.0.2.1/24\nSRC-IP-SUFFIX,192.0.2.1/24\n'
                                 'AND,((IP-CIDR,192.0.2.0/24),(NETWORK,tcp))\n'
                                 'OR,((SRC-IP-CIDR,192.0.2.0/24),(DOMAIN,keep.example))\n'
                                 'NOT,((IP-CIDR,192.0.2.0/24))', purpose='block')
        self.assertEqual(messages, [])
        original = [source[0], covered, allowed, *source[1:], covered]
        white = parse_whitelist('IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\n'
                                'SRC-IP-CIDR,192.0.2.0/25\nSRC-IP-CIDR,192.0.2.128/25')
        kept = exclude_covered(iter(original), iter(white))
        expected = [source[0], allowed, *source[1:]]
        self.assertEqual(kept, expected)
        self.assertTrue(all(actual is wanted for actual, wanted in zip(kept, expected)))
        self.assertEqual(exclude_covered(iter(original), iter(())), original)
        self.assertEqual(normalize(white), [Rule('IP-CIDR', '192.0.2.0/24'),
                                           Rule('SRC-IP-CIDR', '192.0.2.0/24')])
        self.assertEqual(exclude_covered(source, white + parse_whitelist(
            'DOMAIN,keep.example\nDOMAIN-REGEX,^keep$\nIP-ASN,64512\nGEOIP,CN\n'
            'IP-SUFFIX,192.0.2.1/24\nSRC-IP-SUFFIX,192.0.2.1/24')), source[-3:])

    def test_scope_is_rejected_before_coverage_even_for_allow(self):
        white = parse_whitelist('IP-CIDR6,fe80::/65\nIP-CIDR6,fe80:0:0:0:8000::/65')
        for allow in (False, True):
            scoped = Rule('IP-CIDR6', 'fe80::1%eth0/64', allow=allow)
            for source, entries in (([scoped], white), ([], [*white, scoped])):
                with self.subTest(allow=allow, white=bool(source)), self.assertRaisesRegex(ValueError, 'scope'):
                    exclude_covered(iter(source), iter(entries))
        self.assertEqual(parse('IP-CIDR6,fe80::1%eth0/64\nDOMAIN,keep.example', purpose='block'),
                         ([Rule('DOMAIN', 'keep.example')], ['line 1: invalid CIDR fe80::1%eth0/64']))


class CidrWhitelistUnionRenderTests(unittest.TestCase):
    def setUp(self):
        clock = patch('formats.datetime')
        self.addCleanup(clock.stop)
        clock.start().now.return_value = datetime(2026, 10, 23, tzinfo=timezone.utc)

    def test_six_products_and_coverage_counts_preserve_all_purposes_flags_and_directions(self):
        for kind, parent, halves in (
            ('IP-CIDR', '192.0.2.0/24', ('192.0.2.0/25', '192.0.2.128/25')),
            ('IP-CIDR6', '2001:db8::/32', ('2001:db8::/33', '2001:db8:8000::/33')),
            ('SRC-IP-CIDR', '192.0.2.0/24', ('192.0.2.0/25', '192.0.2.128/25')),
            ('SRC-IP-CIDR', '2001:db8::/32', ('2001:db8::/33', '2001:db8:8000::/33')),
        ):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    for flagged in (False, True) if not kind.startswith('SRC-') else (False,):
                        for complete in (False, True):
                            with self.subTest(kind=kind, parent=parent, purpose=purpose, mode=mode,
                                              flagged=flagged, complete=complete):
                                source = Rule(kind, parent, ('no-resolve',) if flagged else ())
                                white = [Rule(kind, value) for value in halves[:2 if complete else 1]]
                                out, diagnostic = render('union', iter([source]), purpose=purpose,
                                                         no_resolve=mode, whitelist=iter(white))
                                flag = ',no-resolve' if not kind.startswith('SRC-') and (
                                    mode == 'add' or mode == 'keep' and flagged) else ''
                                surge_kind = 'SRC-IP' if kind == 'SRC-IP-CIDR' else kind
                                routes = {'fin.txt', 'fin-surge.txt', 'fin.yaml'}
                                bodies = {'fin.txt': [surge_kind + ',' + parent + flag],
                                          'fin-surge.txt': [surge_kind + ',' + parent + flag],
                                          'fin.yaml': [kind + ',' + parent + flag]}
                                if not kind.startswith('SRC-'):
                                    routes.add('fin-qx.txt')
                                    qx_kind = 'IP6-CIDR' if kind == 'IP-CIDR6' else kind
                                    bodies['fin-qx.txt'] = [qx_kind + ',' + parent + ',LIST' + flag]
                                self.assertEqual(out, expected_products('union', purpose, {} if complete else bodies))
                                expected = {name + ':' + kind: 1 for name in FILES if name not in routes}
                                if complete:
                                    expected.update({name + ':' + kind + ':whitelist-covered': 1 for name in routes})
                                    expected['whitelist-covered:' + kind] = 1
                                self.assertEqual(diagnostic, expected)

    def test_external_white_options_are_filtered_before_union_but_direct_api_ignores_them(self):
        source = [Rule('IP-CIDR', '192.0.2.0/24')]
        for options, complete in ((('unsupported',), False), (('force-cellular',), False),
                                  (('via-interface=en1',), False), (('no-resolve',), True)):
            white = [Rule('IP-CIDR', '192.0.2.0/25'), Rule('IP-CIDR', '192.0.2.128/25', options)]
            with self.subTest(options=options):
                self.assertEqual(exclude_covered(iter(source), iter(white)), [])
                out, diagnostic = render('options', source, purpose='block', no_resolve='keep', whitelist=white)
                bodies = {'fin.txt': ['IP-CIDR,192.0.2.0/24'], 'fin-surge.txt': ['IP-CIDR,192.0.2.0/24'],
                          'fin-qx.txt': ['IP-CIDR,192.0.2.0/24,LIST'], 'fin.yaml': ['IP-CIDR,192.0.2.0/24']}
                self.assertEqual(out, expected_products('options', 'block', {} if complete else bodies))
                self.assertEqual(diagnostic.get('whitelist-covered:IP-CIDR'), 1 if complete else None)
        white = parse_whitelist('IP-CIDR,192.0.2.0/25,PROXY,force-cellular\n'
                                'IP-CIDR,192.0.2.128/25,DIRECT,no-resolve,via-interface=en1')
        self.assertEqual(white, [Rule('IP-CIDR', '192.0.2.0/25'), Rule('IP-CIDR', '192.0.2.128/25')])
        self.assertEqual(render('options', source, purpose='block', no_resolve='keep', whitelist=white)[0],
                         expected_products('options', 'block', {}))

    def test_allow_rules_use_existing_interface_cleanup_without_new_option_support(self):
        for options, complete in (((), True), (('force-cellular',), True),
                                  (('via-interface=en1', 'no-resolve'), True), (('unsupported',), False)):
            for mode in ('add', 'strip', 'keep'):
                source = [Rule('IP-CIDR', '192.0.2.0/24'),
                          Rule('IP-CIDR', '192.0.2.0/25', allow=True),
                          Rule('IP-CIDR', '192.0.2.128/25', options, allow=True)]
                with self.subTest(options=options, mode=mode):
                    out, diagnostic = render('allow', iter(source), purpose='block', no_resolve=mode)
                    flag = ',no-resolve' if mode == 'add' else ''
                    bodies = {'fin.txt': ['IP-CIDR,192.0.2.0/24' + flag],
                              'fin-surge.txt': ['IP-CIDR,192.0.2.0/24' + flag],
                              'fin-qx.txt': ['IP-CIDR,192.0.2.0/24,LIST' + flag],
                              'fin.yaml': ['IP-CIDR,192.0.2.0/24' + flag]}
                    self.assertEqual(out, expected_products('allow', 'block', {} if complete else bodies))
                    self.assertEqual(diagnostic.get('whitelist-covered:IP-CIDR'), 1 if complete else None)
                    self.assertTrue(source[1].allow and source[2].allow)
                    self.assertEqual(source[2].options, tuple(sorted(options)))

    def test_qx_native_ip_white_stays_identical_only_and_parsed_white_keeps_original_path(self):
        source = [Rule('IP-CIDR', '192.0.2.0/24')]
        native = [Rule('IP-CIDR', value, domain_source='mihomo')
                  for value in ('192.0.2.0/25', '192.0.2.128/25')]
        out, diagnostic = render('native', source, purpose='block', no_resolve='keep', whitelist=native)
        self.assertEqual(out, expected_products('native', 'block',
                                               {'fin-qx.txt': ['IP-CIDR,192.0.2.0/24,LIST']}))
        self.assertNotIn('whitelist-covered:IP-CIDR', diagnostic)
        self.assertNotIn('fin-qx.txt:IP-CIDR:whitelist-covered', diagnostic)
        identical = [Rule('IP-CIDR', '192.0.2.0/24', domain_source='mihomo')]
        out, diagnostic = render('native', source, purpose='block', no_resolve='keep', whitelist=identical)
        self.assertEqual(out, expected_products('native', 'block', {}))
        self.assertEqual(diagnostic['whitelist-covered:IP-CIDR'], 1)
        parsed = parse_whitelist('payload:\n  - IP-CIDR,192.0.2.0/25\n  - IP-CIDR,192.0.2.128/25')
        self.assertTrue(all(entry.domain_source == 'surge' for entry in parsed))
        self.assertEqual(render('native', source, purpose='block', no_resolve='keep', whitelist=parsed)[0],
                         expected_products('native', 'block', {}))

    def test_render_never_rewrites_logical_leaves_using_network_union(self):
        white = parse_whitelist('IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25')
        for operator, value in (('AND', '((IP-CIDR,192.0.2.0/24),(NETWORK,tcp))'),
                                ('OR', '((IP-CIDR,192.0.2.0/24),(NETWORK,tcp))'),
                                ('NOT', '((IP-CIDR,192.0.2.0/24))')):
            source, messages = parse(operator + ',' + value, purpose='block')
            self.assertEqual(messages, [])
            out, diagnostic = render('logical', source, purpose='block', no_resolve='keep', whitelist=white)
            control, control_diagnostic = render('logical', source, purpose='block', no_resolve='keep')
            self.assertEqual((out, diagnostic), (control, control_diagnostic))
            self.assertEqual(out['fin.yaml'], '# logical rules: 1\npayload:\n  - ' +
                             json.dumps(operator + ',' + value) + '\n')
            self.assertNotIn('whitelist-covered:' + operator, diagnostic)


class CidrWhitelistUnionGenerateTests(unittest.TestCase):
    def setUp(self):
        clock = patch('formats.datetime')
        self.addCleanup(clock.stop)
        clock.start().now.return_value = datetime(2026, 10, 23, tzinfo=timezone.utc)

    def seed_old(self, root, groups):
        old = {}
        for group in groups:
            (root / group).mkdir()
            for name in FILES:
                path = root / group / name
                old[path] = b'old complete artifact\x00\xff\r\n'
                path.write_bytes(old[path])
        return old

    def run_cli(self, root):
        product = Path(__file__).resolve().parents[1]
        code = ('import runpy, sys; from pathlib import Path; '
                'product = Path(sys.argv[1]).resolve(); fixture = sys.argv[2]; '
                'sys.path.insert(0, str(product)); '
                'sys.argv = [str(product / "generate.py"), "--root", fixture]; '
                'runpy.run_path(sys.argv[0], run_name="__main__")')
        return subprocess.run([sys.executable, '-I', '-B', '-c', code, str(product), str(root)],
                              cwd=product, capture_output=True, text=True, timeout=8)

    def test_raw_generated_disk_and_copied_white_publish_identical_complete_products(self):
        for kind, parent, halves in (
            ('IP-CIDR', '192.0.2.0/24', ('192.0.2.0/25', '192.0.2.128/25')),
            ('IP-CIDR6', '2001:db8::/32', ('2001:db8::/33', '2001:db8:8000::/33')),
            ('SRC-IP-CIDR', '192.0.2.0/24', ('192.0.2.0/25', '192.0.2.128/25')),
            ('SRC-IP-CIDR', '2001:db8::/32', ('2001:db8::/33', '2001:db8:8000::/33')),
        ):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    for filename in ('fin.txt', 'fin.yaml'):
                        with self.subTest(kind=kind, parent=parent, purpose=purpose, mode=mode,
                                          filename=filename), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'static').mkdir()
                            inputs = {
                                root / 'static/source.list': (kind + ',' + parent +
                                    '\nIP-CIDR,203.0.113.0/24,no-resolve\n').encode(),
                                root / 'static/white.list': b'\xef\xbb\xbf' + '\r\n'.join(
                                    kind + ',' + value for value in reversed(halves)).encode() + b'\r\n',
                            }
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            configs = [dict(name=group, purpose=purpose, no_resolve=mode,
                                            sources=sources, whitelist=white) for group, sources, white in (
                                ('white', ['static/white.list'], []),
                                ('raw', ['static/source.list'], ['static/white.list']),
                                ('filtered', ['static/source.list'], ['white/' + filename]),
                                ('child', ['raw/' + filename], []))]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = self.seed_old(root, [config['name'] for config in configs])
                            flag = '' if mode == 'strip' else ',no-resolve'
                            neighbor = {'fin.txt': ['IP-CIDR,203.0.113.0/24' + flag],
                                        'fin-surge.txt': ['IP-CIDR,203.0.113.0/24' + flag],
                                        'fin-qx.txt': ['IP-CIDR,203.0.113.0/24,LIST' + flag],
                                        'fin.yaml': ['IP-CIDR,203.0.113.0/24' + flag]}
                            white_flag = ',no-resolve' if mode == 'add' and not kind.startswith('SRC-') else ''
                            surge_kind = 'SRC-IP' if kind.startswith('SRC-') else kind
                            white_bodies = {'fin.txt': [surge_kind + ',' + parent + white_flag],
                                            'fin-surge.txt': [surge_kind + ',' + parent + white_flag],
                                            'fin.yaml': [kind + ',' + parent + white_flag]}
                            if not kind.startswith('SRC-'):
                                qx_kind = 'IP6-CIDR' if kind == 'IP-CIDR6' else kind
                                white_bodies['fin-qx.txt'] = [qx_kind + ',' + parent + ',LIST' + white_flag]
                            expected = {root / group / name: text for group in ('white', 'raw', 'filtered', 'child')
                                        for name, text in expected_products(
                                            group, purpose, white_bodies if group == 'white' else neighbor).items()}
                            with contextlib.redirect_stderr(io.StringIO()) as messages:
                                outputs = generate(root, lambda url: self.fail(url))
                            self.assertEqual(outputs, expected)
                            white_skips = {name + ':' + kind: 1 for name in FILES if name not in white_bodies}
                            neighbor_skips = {'fin-adb.txt:IP-CIDR': 1, 'fin-surge-ds.txt:IP-CIDR': 1}
                            self.assertEqual(messages.getvalue().splitlines(),
                                [f'{group} {key}: {count}' for group in ('white', 'raw', 'filtered', 'child')
                                 for key, count in sorted((white_skips if group == 'white' else neighbor_skips).items())])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: text.encode() for path, text in expected.items()}
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            for copied in (False, True):
                                children = configs[2:]
                                if copied:
                                    for group in ('white', 'raw'):
                                        path = root / 'static' / ('copied-' + group + '.list')
                                        inputs[path] = published[root / group / filename]
                                        path.write_bytes(inputs[path])
                                    children = [dict(configs[2], whitelist=['static/copied-white.list']),
                                                dict(configs[3], sources=['static/copied-raw.list'])]
                                (root / 'rulesets.json').write_text(json.dumps(children), encoding='utf-8')
                                with contextlib.redirect_stderr(io.StringIO()) as messages:
                                    disk = generate(root, lambda url: self.fail(url))
                                self.assertEqual(disk, {path: text for path, text in expected.items()
                                                       if path.parent.name in {'filtered', 'child'}})
                                publish(disk, root=root)
                                self.assertEqual({path: path.read_bytes() for path in published}, published)
                                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_union_replaces_old_six_files_empty_dependencies_cli_and_disk_strictness(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    inputs = {root / 'static/source.list': b'IP-CIDR,192.0.2.0/24,no-resolve\n',
                              root / 'static/white.list': b'IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\n',
                              root / 'static/neighbor.list': b'IP-CIDR,203.0.113.0/24\n'}
                    for path, data in inputs.items():
                        path.write_bytes(data)
                    configs = [dict(name=group, purpose=purpose, no_resolve=mode, sources=sources,
                                    whitelist=white) for group, sources, white in (
                        ('parent', ['static/source.list'], ['static/white.list']),
                        ('source-child', ['parent/fin.txt'], []),
                        ('white-child', ['static/neighbor.list'], ['parent/fin.txt']))]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = self.seed_old(root, [config['name'] for config in configs])
                    with contextlib.redirect_stderr(io.StringIO()) as messages:
                        outputs = generate(root, lambda url: self.fail(url))
                    flag = ',no-resolve' if mode == 'add' else ''
                    neighbor = {'fin.txt': ['IP-CIDR,203.0.113.0/24' + flag],
                                'fin-surge.txt': ['IP-CIDR,203.0.113.0/24' + flag],
                                'fin-qx.txt': ['IP-CIDR,203.0.113.0/24,LIST' + flag],
                                'fin.yaml': ['IP-CIDR,203.0.113.0/24' + flag]}
                    expected = {root / group / name: text for group in ('parent', 'source-child', 'white-child')
                                for name, text in expected_products(
                                    group, purpose, neighbor if group == 'white-child' else {}).items()}
                    self.assertEqual(outputs, expected)
                    self.assertEqual(messages.getvalue().splitlines(),
                                     ['white-child fin-adb.txt:IP-CIDR: 1', 'white-child fin-surge-ds.txt:IP-CIDR: 1'])
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    publish(outputs, root=root)
                    published = {path: text.encode() for path, text in expected.items()}
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                    if purpose == 'block' and mode == 'keep':
                        cli = self.run_cli(root)
                        self.assertEqual(cli.returncode, 0, cli.stderr)
                        self.assertEqual(cli.stdout, '')
                        self.assertEqual(cli.stderr, messages.getvalue())
                        for path, text in expected.items():
                            actual = path.read_text(encoding='utf-8')
                            if path.name == 'fin-adb.txt':
                                version = actual.splitlines()[5]
                                self.assertRegex(version, r'^! Version: [0-9]{12}$')
                                datetime.strptime(version[11:], '%Y%m%d%H%M')
                                text = text.replace('! Version: 202610230000', version)
                            self.assertEqual(path.read_bytes(), text.encode())
                        published = {path: path.read_bytes() for path in published}
                    for config, message in ((configs[1], 'No adaptable rules in .*parent.*fin.txt'),
                                            (configs[2], 'Invalid whitelist .*parent.*fin.txt.*no rules')):
                        (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                        with self.assertRaisesRegex(ValueError, message):
                            publish(generate(root, lambda url: self.fail(url)), root=root)
                        if purpose == 'block' and mode == 'keep':
                            cli = self.run_cli(root)
                            self.assertEqual(cli.returncode, 1)
                            self.assertRegex(cli.stderr, message)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_union_does_not_hide_unsupported_or_unavailable_sources_or_frozen_dependencies(self):
        for failure in ('unsupported', 'missing'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                source = 'payload:\n  - IP-CIDR,192.0.2.0/24\n'
                if failure == 'unsupported':
                    source += '  - ' + json.dumps('DEVICE-NAME,a\x00b') + '\n'
                inputs = {root / 'static/source.yaml': source.encode(),
                          root / 'static/white.list': b'IP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\n',
                          root / 'static/healthy.list': b'IP-CIDR,203.0.113.0/24\n'}
                for path, data in inputs.items():
                    path.write_bytes(data)
                configs = [dict(name=group, purpose='block', no_resolve='keep', sources=sources,
                                whitelist=white) for group, sources, white in (
                    ('parent', ['static/source.yaml'] + (['https://example.org/missing'] if failure == 'missing' else []),
                     ['static/white.list']),
                    ('source-child', ['parent/fin.txt'], []),
                    ('white-child', ['static/healthy.list'], ['parent/fin.yaml']),
                    ('healthy', ['static/healthy.list'], []))]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                old = self.seed_old(root, [config['name'] for config in configs])

                def unavailable(url):
                    self.assertEqual(url, 'https://example.org/missing')
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as messages:
                    outputs = generate(root, unavailable)
                neighbor = {'fin.txt': ['IP-CIDR,203.0.113.0/24'], 'fin-surge.txt': ['IP-CIDR,203.0.113.0/24'],
                            'fin-qx.txt': ['IP-CIDR,203.0.113.0/24,LIST'], 'fin.yaml': ['IP-CIDR,203.0.113.0/24']}
                expected = {root / 'healthy' / name: text
                            for name, text in expected_products('healthy', 'block', neighbor).items()}
                self.assertEqual(outputs, expected)
                self.assertEqual(messages.getvalue().splitlines(),
                    (['https://example.org/missing: HTTP 404; skipped'] if failure == 'missing' else []) +
                    ['parent: no routable rules; frozen', 'healthy fin-adb.txt:IP-CIDR: 1',
                     'healthy fin-surge-ds.txt:IP-CIDR: 1'])
                publish(outputs, root=root)
                frozen = {path: data for path, data in old.items() if path.parent.name != 'healthy'}
                self.assertEqual({path: path.read_bytes() for path in frozen}, frozen)
                self.assertEqual({path: path.read_bytes() for path in expected},
                                 {path: text.encode() for path, text in expected.items()})
                for name in FILES:
                    missing = root / 'parent' / name
                    missing.unlink()
                    before = {path: path.read_bytes() for path in old if path != missing}
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(
                            ValueError, 'Cannot freeze parent: missing complete old file'):
                        publish(generate(root, unavailable), root=root)
                    self.assertEqual({path: path.read_bytes() for path in before}, before)
                    missing.write_bytes(old[missing])
                for invalid in (b'', b'IP-CIDR,not-a-network\n', b'IP-CIDR6,fe80::1%eth0/64\n'):
                    (root / 'static/white.list').write_bytes(invalid)
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                        publish(generate(root, unavailable), root=root)
                    self.assertEqual({path: path.read_bytes() for path in frozen}, frozen)
                (root / 'static/white.list').write_bytes(inputs[root / 'static/white.list'])
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
