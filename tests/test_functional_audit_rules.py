import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch
from urllib.error import HTTPError

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


def native_text(*matchers):
    return 'payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)


class UnderscoreDomainAuditTests(unittest.TestCase):
    suffixes = ('ad-cdn_core.cctv.com', 'ad_core.cctv.com', 'ad_m.cctv.com',
                'piano_log.kingsoft.jp', 'imp_track.zmaticoo.com', 'fb_servpub-a.akamaihd.net',
                'at_w_atexxpressdata-c3a3188a23.exxpress.at')
    upstream = ('host-suffix, ad-cdn_core.cctv.com, reject\n'
                'host-suffix, ad_core.cctv.com, reject\n'
                'host-suffix, ad_m.cctv.com, reject\n'
                '.piano_log.kingsoft.jp\n.imp_track.zmaticoo.com\n'
                '.fb_servpub-a.akamaihd.net\n.at_w_atexxpressdata-c3a3188a23.exxpress.at')

    def test_real_native_suffix_preserves_underscore_and_neighbor(self):
        self.assertEqual(parse(native_text('DOMAIN-SUFFIX,piano_log.kingsoft.jp',
                                           'DOMAIN,neighbor.example.org'), purpose='block'),
                         ([Rule('DOMAIN-SUFFIX', 'piano_log.kingsoft.jp', domain_source='mihomo'),
                           Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')], []))

    def test_seven_fixed_upstream_formats_and_shared_entries_keep_source_identity(self):
        expected = [Rule('DOMAIN-SUFFIX', value, domain_source='qx' if index < 3 else 'surge')
                    for index, value in enumerate(self.suffixes)]
        self.assertEqual(parse(self.upstream, purpose='block'), (expected, []))
        self.assertEqual(parse_whitelist(self.upstream), expected)
        for purpose, policy in (('block', 'REJECT'), ('direct', 'DIRECT'), ('proxy', 'PROXY')):
            for value in self.suffixes:
                for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                    cases = ((f'{kind},"{value.upper()}.",{policy}', 'surge', value),
                             (f'{"HOST" if kind == "DOMAIN" else "HOST-SUFFIX"},{value},{policy}', 'qx', value),
                             (native_text(kind + ',' + value.upper() + '.'), 'mihomo', value.upper() + '.'))
                    for text, source, raw in cases:
                        with self.subTest(purpose=purpose, value=value, kind=kind, source=source):
                            wanted = [Rule(kind, raw, domain_source=source)]
                            self.assertEqual(parse(text, purpose=purpose), (wanted, []))
                            self.assertEqual(parse_whitelist(text), wanted)
                            self.assertEqual(normalize(wanted * 2), wanted)
                for text, kind, allow in ((value, 'DOMAIN', False), ('.' + value, 'DOMAIN-SUFFIX', False),
                                          ('||' + value + '^', 'DOMAIN-SUFFIX', False),
                                          ('@@||' + value + '^', 'DOMAIN-SUFFIX', True)):
                    with self.subTest(purpose=purpose, value=value, text=text):
                        self.assertEqual(parse(text, purpose=purpose, domain_set=True),
                                         ([], ['line 1: incompatible action REJECT']) if text.startswith('||') and purpose != 'block' else
                                         ([Rule(kind, value, allow=allow)], []))
            for address in ('0.0.0.0', '127.0.0.1', '::', '::1'):
                text = address + ' ' + ' '.join(self.suffixes) + ' # tail\n'
                with self.subTest(purpose=purpose, address=address):
                    self.assertEqual(parse(text, purpose=purpose),
                                     ([Rule('DOMAIN', value) for value in self.suffixes], []) if purpose == 'block' else
                                     ([], ['line 1: hosts entry is block-only']))

    def test_underscore_label_edges_lengths_and_invalid_neighbors_keep_boundaries(self):
        longest = '.'.join(['_' * 63] * 3 + ['_' * 61])
        valid = ('_', '_a', 'a_', '__', '_a-b_', '_' * 63, longest, 'ad_core.cctv.com.')
        invalid = ('', '-_a.example', '_a-.example', 'ad_..example', '.ad_.example', 'ad_.example..',
                   'ad_+x.example', 'ad_/x.example', 'ad_\\x.example', 'ad_ x.example', 'ad_\tx.example',
                   'ad_\x7fx.example', 'ad_\x00x.example', 'ad_\rx.example', 'ad_ x.example',
                   '_' * 64 + '.example', longest + '_', '192.0.2.1', '2001:db8::1')
        for native in (False, True):
            neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')
            for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                for value in valid + invalid:
                    with self.subTest(native=native, kind=kind, value=value):
                        matcher = kind + ',' + value
                        text = native_text(matcher, 'DOMAIN,neighbor.example.org') if native else matcher + '\nDOMAIN,neighbor.example.org'
                        parsed, messages = parse(text, purpose='proxy')
                        wanted = ([Rule(kind, value, domain_source='mihomo' if native else 'surge')] if value in valid else []) + [neighbor]
                        self.assertEqual(parsed, wanted)
                        self.assertEqual(len(messages), int(value in invalid))
                        if messages:
                            self.assertTrue(messages[0].startswith(f'line {2 if native else 1}:'))
        self.assertEqual(parse('a_b', purpose='block'), ([], ['line 1: invalid rule']))
        self.assertEqual(parse('a_b', purpose='block', domain_set=True), ([Rule('DOMAIN', 'a_b')], []))
        self.assertEqual(parse('.a_b', purpose='proxy'), ([Rule('DOMAIN-SUFFIX', 'a_b')], []))
        for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
            for quote in ('\'', '"'):
                text = native_text(kind + ',' + quote + 'ad_core.cctv.com' + quote)
                self.assertEqual(parse(text, purpose='block')[0], [])
                with self.assertRaises(ValueError):
                    parse_whitelist(text)

    def test_logical_quotes_order_and_no_resolve_preserve_underscore_leaves(self):
        for native in (False, True):
            for quote in ('', '\'', '"'):
                field = quote + 'ad_core.cctv.com' + quote
                expressions = (('AND', f'((DOMAIN-SUFFIX,{field}),(IP-CIDR,192.0.2.7/24,no-resolve),(SRC-IP-CIDR,198.51.100.7/24))'),
                               ('OR', f'((DOMAIN,{field}),(DOMAIN-SUFFIX,imp_track.zmaticoo.com))'),
                               ('NOT', f'((DOMAIN,{field}))'),
                               ('AND', f'((NOT,((DOMAIN,{field}))),(OR,((DOMAIN-SUFFIX,piano_log.kingsoft.jp),(NETWORK,tcp))))'))
                for operator, expression in expressions:
                    for purpose in ('block', 'direct', 'proxy'):
                        with self.subTest(native=native, quote=quote, operator=operator, purpose=purpose):
                            matcher = operator + ',' + expression
                            text = native_text(matcher, 'DOMAIN,neighbor.example.org') if native else matcher + '\nDOMAIN,neighbor.example.org'
                            neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')
                            parsed, messages = parse(text, purpose=purpose)
                            if native and quote:
                                self.assertEqual(parsed, [neighbor])
                                self.assertEqual(messages, ['line 2: invalid logical expression ' + expression])
                                continue
                            wanted = expression.replace('192.0.2.7/24', '192.0.2.0/24').replace('198.51.100.7/24', '198.51.100.0/24')
                            self.assertEqual((parsed, messages), ([Rule(operator, wanted, native_fields=native,
                                                                     domain_source='mihomo' if native else 'surge'), neighbor], []))
                            for mode in ('add', 'strip', 'keep'):
                                outputs, _ = render('underscore', parsed, purpose=purpose, no_resolve=mode)
                                emitted = wanted.replace(field, 'ad_core.cctv.com')
                                if mode == 'strip':
                                    emitted = emitted.replace(',no-resolve', '')
                                self.assertIn(json.dumps(operator + ',' + emitted), outputs['fin.yaml'])
                                self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose),
                                                 ([neighbor if native else Rule('DOMAIN', neighbor.value, domain_source='mihomo'),
                                                   Rule(operator, emitted, native_fields=True, domain_source='mihomo')]
                                                  if operator in ('NOT', 'OR') else
                                                  [Rule(operator, emitted, native_fields=True, domain_source='mihomo'),
                                                   Rule('DOMAIN', neighbor.value, domain_source='mihomo')], []))

    def test_mihomo_render_reimport_preserves_seven_suffixes_and_wildcard_literals(self):
        for source in ('surge', 'qx', 'mihomo'):
            rules = [Rule('DOMAIN-SUFFIX', value, domain_source=source) for value in self.suffixes]
            rules += [Rule('DOMAIN', 'ad_core.cctv.com', domain_source=source),
                      Rule('DOMAIN-WILDCARD', 'ad_core-*.example.org', domain_source=source)]
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(source=source, purpose=purpose, mode=mode):
                        outputs, skipped = render('underscore', iter(rules), purpose=purpose, no_resolve=mode)
                        self.assertFalse(any(key.startswith('fin.yaml:') for key in skipped))
                        for value in self.suffixes:
                            self.assertIn(json.dumps('DOMAIN-SUFFIX,' + value), outputs['fin.yaml'])
                        wildcard = (Rule('DOMAIN-REGEX', r'^ad_core\-.*\.example\.org\.?$') if source == 'surge' else
                                    Rule('DOMAIN-WILDCARD', 'ad_core-*.example.org', domain_source='mihomo'))
                        wanted = {*(Rule('DOMAIN-SUFFIX', value, domain_source='mihomo') for value in self.suffixes),
                                  Rule('DOMAIN', 'ad_core.cctv.com', domain_source='mihomo'), wildcard}
                        parsed, messages = parse(outputs['fin.yaml'], purpose=purpose)
                        self.assertEqual((set(parsed), messages), (wanted, []))

    def test_generate_local_remote_inputs_and_yaml_dependencies_preserve_underscore(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            flag = '' if mode == 'strip' else ',no-resolve'
                            logic = '((NOT,((DOMAIN,ad_core.cctv.com))),(DOMAIN-SUFFIX,piano_log.kingsoft.jp),'
                            logic += '(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = [*('DOMAIN-SUFFIX,' + value for value in self.suffixes),
                                        'DOMAIN,ad_core.cctv.com', 'AND,' + logic, 'DOMAIN,covered_core.example.com',
                                        'DOMAIN,neighbor.example.org', 'IP-CIDR,192.0.2.0/24,no-resolve',
                                        'SRC-IP-CIDR,198.51.100.0/24']
                            source = native_text(*matchers) if native else '\n'.join(matchers)
                            source += '\n@@||allow_core.example.com^\n'
                            white = 'DOMAIN-SUFFIX,covered_core.example.com\n'
                            (root / 'input.list').write_text(source, encoding='utf-8')
                            (root / 'static').mkdir()
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'input.list', root / 'static/white.list')}
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'input.list'],
                                        'whitelist': ['https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            self.assertNotIn('invalid ', diagnostic.getvalue())
                            self.assertEqual(list(outputs), [root / group / name for group in ('source', 'child') for name in FILES])
                            wanted_logic = logic.replace(',no-resolve', '') if mode == 'strip' else logic
                            wanted = {*(Rule('DOMAIN-SUFFIX', value, domain_source='mihomo') for value in self.suffixes),
                                      Rule('AND', wanted_logic, native_fields=True, domain_source='mihomo'),
                                      Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'),
                                      Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                      Rule('SRC-IP-CIDR', '198.51.100.0/24')}
                            for group in ('source', 'child'):
                                parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual((set(parsed), messages), (wanted, []))
                                self.assertNotIn('covered_core.example.com', outputs[root / group / 'fin.yaml'])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'input.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_generated_underscore_white_empty_routes_and_disk_freeze_boundaries(self):
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                white = native_text('DOMAIN-SUFFIX,ad_core.cctv.com')
                source = native_text('DOMAIN,ad_core.cctv.com', 'DOMAIN,sub.ad_core.cctv.com')
                (root / 'white.list').write_text(white, encoding='utf-8')
                (root / 'input.list').write_text(source, encoding='utf-8')
                configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': 'keep', 'sources': ['white.list'], 'whitelist': []},
                           {'name': 'source', 'purpose': purpose, 'no_resolve': 'keep', 'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep', 'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                                 [Rule('DOMAIN-SUFFIX', 'ad_core.cctv.com', domain_source='mihomo')])
                for group in ('source', 'child'):
                    self.assertEqual(outputs[root / group / 'fin.yaml'], f'# {group} rules: 0\npayload:\n')
                publish(outputs, root=root)
                published = {path: path.read_bytes() for path in outputs}
                configs[1]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'No adaptable rules in '):
                    generate(root, lambda url: self.fail(url))
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({root / 'static/white.list': white}, root=root)
                with self.assertRaisesRegex(ValueError, 'Output path escapes root'):
                    publish({root / '../escape.list': white}, root=root)
                for remote in (False, True):
                    configs[1]['sources'] = ['input.list']
                    configs[1]['whitelist'] = ['https://example.com/bad-white' if remote else 'white.list']
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:2]), encoding='utf-8')
                    (root / 'white.list').write_text('DOMAIN-SUFFIX,bad_..example\n', encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        if remote:
                            actual = generate(root, lambda url: b'DOMAIN-SUFFIX,bad_..example\n')
                            self.assertIn('invalid whitelist', diagnostic.getvalue())
                            self.assertIn('DOMAIN,ad_core.cctv.com', actual[root / 'source/fin.yaml'])
                        else:
                            with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                                generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in published}, published)


class QuantifierAuditTests(unittest.TestCase):
    kinds = ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX')
    cases = (
        ('a{' + '9' * 5000 + '}', False),
        ('a{' + '0' * 5000 + '1}', True),
        ('a{2147483648}', False), ('a{1,2147483648}', False),
        ('a{2147483648,}', False), ('a{2147483648,2147483648}', False),
        ('a{2,1}', False), ('a{0}', True), ('a{0,}', True),
        ('a{2147483647}', True), ('a{0001,0002}', True),
        ('a{xyz}', True), ('a{,4294967295}', True),
        ('a{,' + '9' * 5000 + '}', True),
        ('a{,' + '0' * 5000 + '1}', True),
    )

    def test_regexp2_quantifiers_preserve_raw_matchers_and_line_warnings(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            for value, valid in self.cases:
                for native in (False, True):
                    for logical in (False, True):
                        expression = f'(({kind},{value}),(NETWORK,tcp))'
                        matcher = f'AND,{expression}' if logical else f'{kind},{value}'
                        source = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                  (matcher if logical else f'{kind},\'{value}\'') + '\nDOMAIN,keep.example.com')
                        neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                        expected = Rule('AND', expression, native_fields=native) if logical else Rule(kind, value)
                        with self.subTest(kind=kind, length=len(value), native=native, logical=logical):
                            parsed, messages = parse(source, purpose='block')
                            self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                            if valid:
                                self.assertEqual(parsed[0].value, expression if logical else value)
                            self.assertEqual(len(messages), int(not valid))
                            if messages:
                                self.assertTrue(messages[0].startswith(f'line {2 if native else 1}: invalid '))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_domain_white_and_url_regex_numeric_failures_do_not_stop_neighbors(self):
        for value, valid in self.cases[:6] + self.cases[-3:]:
            for native in (False, True):
                text = (native_text('DOMAIN-REGEX,' + value, 'DOMAIN,keep.example.com') if native else
                        f"DOMAIN-REGEX,'{value}'\nDOMAIN,keep.example.com")
                with self.subTest(length=len(value), valid=valid, native=native), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    white = parse_whitelist(text)
                    self.assertEqual([rule.value for rule in white], ([value] if valid else []) + ['keep.example.com'])
                    self.assertEqual(len(caught), int(not valid))
        for value in ('a{' + '9' * 5000 + '}', 'a{' + '0' * 5000 + '1}'):
            with self.subTest(url_length=len(value)):
                parsed, messages = parse(f"URL-REGEX,'{value}'\nDOMAIN,keep.example.com", purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.com')])
                self.assertEqual(messages, ['line 1: invalid URL-REGEX ' + value])
        self.assertEqual(parse("URL-REGEX,'a{2147483648}'", purpose='proxy'),
                         ([Rule('URL-REGEX', 'a{2147483648}')], []))

    def test_unexpected_compiler_value_error_propagates_from_public_parse(self):
        for kind in (*self.kinds, 'URL-REGEX'):
            failure = ValueError('unexpected regex compiler failure')
            with self.subTest(kind=kind), patch('rules.re.compile', side_effect=failure):
                with self.assertRaises(ValueError) as caught:
                    parse(f"{kind},'^ok$'\nDOMAIN,keep.example.com", purpose='proxy')
                self.assertIs(caught.exception, failure)

    def test_generate_local_remote_white_and_yaml_dependencies_keep_legal_long_zero(self):
        legal = 'a{' + '0' * 5000 + '1}'
        invalid = 'a{' + '9' * 5000 + '}'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['input.yaml'], 'whitelist': ['https://example.com/white' if remote else 'white.txt']},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['source/fin.yaml'], 'whitelist': []}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        source = native_text(*(kind + ',' + legal for kind in self.kinds), 'DOMAIN-REGEX,' + invalid, 'DOMAIN,keep.example.com')
                        (root / 'input.yaml').write_text(source, encoding='utf-8')
                        white = f"DOMAIN-REGEX,'{legal}'\nDOMAIN-REGEX,'{invalid}'\nDOMAIN,other.example.com\n"
                        (root / 'white.txt').write_text(white, encoding='utf-8')
                        with warnings.catch_warnings(record=True), contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            warnings.simplefilter('always')
                            outputs = generate(root, lambda url: white.encode('utf-8'))
                        self.assertIn('invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                        expected = {*(Rule(kind, legal) for kind in self.kinds), Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')}
                        for group in ('source', 'child'):
                            for kind in self.kinds:
                                self.assertIn(json.dumps(kind + ',' + legal), outputs[root / group / 'fin.yaml'])
                            parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                            self.assertEqual(set(parsed), expected)
                            self.assertEqual(messages, [])
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()):
                            disk = generate(root, lambda url: self.fail(url))
                        self.assertEqual(disk[root / 'child' / 'fin.yaml'], outputs[root / 'child' / 'fin.yaml'])
                        self.assertEqual({path: path.read_bytes() for path in published}, published)


class InlineOptionsAuditTests(unittest.TestCase):
    kinds = QuantifierAuditTests.kinds
    cases = (
        (r'^(?n)ads\.example\.com$', True), (r'^(?-n)ads\.example\.com$', True),
        (r'^(?in:ads)\.example\.com$', True), (r'^(?I)ads\.example\.com$', True),
        (r'^(?x+i)ads\.example\.com$', True),
        (r'^(?IMNSXDU:ads)\.example\.com$', True),
        (r'^(?imnsxdu)ads\.example\.com$', True),
        (r'^(?+-N++X--x+n-n+i:ads)\.example\.com$', True),
        (r'^(?+)ads$', True), (r'^(?---:)ads$', True),
        (r'^(?D-U)(?u-d:ads)+$', True), (r'^(?m-s:i)+$', True),
        (r'^(?n)(a)\k<1>$', False), (r'^(?N)(a)\1$', False),
        (r'^(?-n)(a)\k<1>$', True), (r'^(?n)(?-n:(a))\k<1>$', True),
        (r'^(?n:(a))(b)\k<1>$', True), (r'^(?n:(a))(b)\k<2>$', False),
        (r'^((?N)(a))(b)\k<2>$', True),
        (r'^(?N)((?-n)(a))(b)\k<1>$', True),
        (r'^(?<name>c)(?n:(a))(?-n:(b))\k<2>$', True),
        (r'^(?n)(?<7>a)(?-n:(b))(?<name>c)\k<1>\k<2>\k<7>$', True),
        (r'^(?N)(?-n:(a))(b)\k<2>$', False),
        (r'^(?n:(?<name>a))\k<name>\k<1>$', True),
        (r"^(?N:(?'name'a))\k'name'$", True),
        (r'^(?n)(?<name>a)(?<name>b)\k<1>$', True),
        (r'^(?n)(?<7>a)\k<7>$', True), (r'^(?n)(?<7>a)\k<1>$', False),
        (r'^(?n)(?<2147483647>a)\k<2147483647>$', True),
        (r'^(?n)(?<2147483648>a)$', False), (r'^(?n)(?<0>a)$', False),
        (r'^(?n)(?<name>a)(b)\k<2>$', False),
        (r'^(?n)(?-n:(a))(?<name>b)\k<1>\k<2>$', True),
        (r'^(?n)(a)(?(1)b|c)$', False),
        (r'^(?n)(?<name>a)(?(name)b|c)$', True),
        (r'^(?n)(?<7>a)(?(7)b|c)$', True),
        (r'^(?n)(?<7>a)(?(8)b|c)$', False),
        (r'^(?n)(?<name>a)(?(name)b|c|d)$', False),
        (r'^(?n)(?<name>a)(?<out-name>b)\k<out>$', True),
        (r'^(?n)(?<name>a)(?<out-missing>b)$', False),
        (r'^(?X:a[ # ])(?-X:b#c)$', True),
        (r'^(?X:a)(b)# [c]$', True), (r'^(?X:a)(b)# [', False),
        (r'^(?X)(?-x: +a) # ignored,PROXY [ #', True),
        (r'^(?X)(?#ignored,#) a+$', True),
        (r'^(?X)a(?-X) # [b]$', True), (r'^(?X)a(?-X) # [', False),
        (r'^(?X) +a$', False), (r'^(?n)+a$', False),
        (r'^a(?D){2}$', False), (r'^a(?+x-n)(?#note)+$', False),
        (r'^(?n:a)+$', True), (r'^(?d:)+a$', True),
        (r'^(?r)a$', False), (r'^(?e:a)$', False),
        (r'^(?R)a$', False), (r'^(?E:a)$', False),
        (r'^(?a:a)$', False), (r'^(?ia:a)$', False), (r'^(?ai:a)$', False),
        (r'^(?L)a$', False), (r'^(?c:a)$', False),
        (r'^(?inZ:a)$', False), (r'^(?n a)$', False), (r'^(?n:a$', False),
        (r'^(?n)(?(?i:a)b|c)$', False),
        (r'^(?n)\u{61}$', False),
        (r'^[(?n)]+(a)\k<1>$', True), (r'^\(\?n\)(a)\k<1>$', True),
    )

    def test_public_parse_keeps_regexp2_inline_options_raw(self):
        for value, valid in self.cases[:5]:
            with self.subTest(value=value):
                self.assertEqual(parse('DOMAIN-REGEX,' + value + '\nDOMAIN,keep.example.com', purpose='block'),
                                 ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'keep.example.com')], []))

    def test_options_capture_and_scope_follow_fixed_regexp2_at_public_parse(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            for value, valid in self.cases:
                for native in (False, True):
                    for quoted in (False, True):
                        field = ('"' + value + '"' if native else json.dumps(value)) if quoted else value
                        checked = field if native else value
                        expression = f'(({kind},{field}),(NETWORK,tcp))'
                        for operator in ('top', 'AND', 'OR', 'NOT'):
                            if not native and not quoted and operator == 'top' and ' #' in value:
                                continue
                            logic = f'(({kind},{field}))' if operator == 'NOT' else expression
                            matcher = kind + ',' + field if operator == 'top' else operator + ',' + logic
                            text = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                    matcher + '\nDOMAIN,keep.example.com')
                            expected = Rule(kind, checked) if operator == 'top' else Rule(operator, logic, native_fields=native)
                            neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                            with self.subTest(kind=kind, value=value, native=native, quoted=quoted, operator=operator):
                                parsed, messages = parse(text, purpose='proxy')
                                self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                                self.assertEqual(len(messages), int(not valid))
                                if messages:
                                    self.assertTrue(messages[0].startswith(f'line {2 if native else 1}:'))
                                self.assertEqual(set(normalize(parsed)), set(parsed))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_native_newline_comments_restore_x_and_n_state(self):
        for value, valid in (
                ('^(?XN:ads # ignored,(#)\n)(a)\\k<1>$', True),
                ('^(?XN:ads # ignored,(#)\n)(a)\\k<2>$', False),
                ('^(?XN)(?-x-n: +a)(b)\\k<1>$', False),
                ('^(?XN)(?-x-n:(a))(b)\\k<1>$', True),
                ('^(?X)(?-x: +a) # ignored\n+$', True),
                ('^(?X)(?n) # ignored\n+$', False)):
            for kind in self.kinds:
                with self.subTest(value=value, kind=kind):
                    parsed, messages = parse(native_text(kind + ',' + value, 'DOMAIN,keep.example.com'), purpose='block')
                    self.assertEqual(parsed, ([Rule(kind, value)] if valid else []) +
                                     [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')])
                    self.assertEqual(messages, [] if valid else [f'line 2: invalid {kind} {value}'])

    def test_x_comments_keep_logical_siblings_and_source_policy_boundaries(self):
        value = r'^(?X+N)ads # ignored,PROXY [ #'
        for operator in ('AND', 'OR', 'NOT'):
            expression = f'((DOMAIN-REGEX,{value}))' if operator == 'NOT' else f'((DOMAIN-REGEX,{value}),(NETWORK,tcp))'
            for policy, purpose in (('REJECT', 'block'), ('DIRECT', 'direct'), ('PROXY', 'proxy')):
                with self.subTest(operator=operator, purpose=purpose):
                    self.assertEqual(parse(f'{operator},{expression},{policy} # tail (\nDOMAIN,keep.example.com,{policy}',
                                           purpose=purpose),
                                     ([Rule(operator, expression), Rule('DOMAIN', 'keep.example.com')], []))
        self.assertEqual(parse('DOMAIN-REGEX,' + value + '\nDOMAIN,keep.example.com', purpose='proxy'),
                         ([Rule('DOMAIN', 'keep.example.com')], ['line 1: ambiguous unquoted regex comment']))
        value = r'^(?X+N)(?#note(,)ads$'
        expression = f'((DOMAIN-REGEX,{value}),(NETWORK,tcp))'
        parsed, messages = parse('AND,' + expression, purpose='proxy')
        self.assertEqual((parsed, messages), ([Rule('AND', expression)], []))
        outputs, _ = render('options', parsed, purpose='proxy', no_resolve='keep')
        wanted = r'((DOMAIN-REGEX,^(?X+N)(?#note\x{28},)ads$),(NETWORK,tcp))'
        self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'), ([Rule('AND', wanted, native_fields=True)], []))

    def test_whitelist_and_long_options_keep_raw_capture_identity(self):
        values = [(value, valid) for value, valid in self.cases]
        values += [(r'^(?' + '+N-x+i-' * 1000 + r'n)(a)\k<1>$', True),
                   (r'^(?N)(?<name>a)\k<' + '0' * 5000 + '1>$', True),
                   (r'^(?N)(a)\k<' + '0' * 5000 + '1>$', False)]
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for value, valid in values:
            for native in (False, True):
                text = (native_text('DOMAIN-REGEX,' + value, 'DOMAIN,keep.example.com') if native else
                        'DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,keep.example.com')
                with self.subTest(value=value[:80], length=len(value), native=native), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    selected = parse_whitelist(text)
                    self.assertEqual(selected, ([Rule('DOMAIN-REGEX', value)] if valid else []) +
                                     [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')])
                    self.assertEqual([str(item.message) for item in caught],
                                     [] if valid else [f'line {2 if native else 1}: invalid DOMAIN-REGEX {value}'])
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_url_regex_keeps_independent_python_options_and_capture_rules(self):
        for value, valid in ((r'(?i)^ads$', True), (r'^(?i:ads)$', True),
                             (r'^(?u:ads)$', True), (r'^(?a:ads)$', True),
                             (r'^(?P<name>ads)(?P=name)$', True),
                             (r'^(?n)ads$', False), (r'^(?-n)ads$', False),
                             (r'^(?I)ads$', False), (r'^(?x+i)ads$', False),
                             (r'^(?d:ads)$', False), (r'^(?N:(a))\k<1>$', False)):
            with self.subTest(value=value):
                self.assertEqual(parse('URL-REGEX,' + json.dumps(value) + '\nDOMAIN,keep.example.com', purpose='proxy'),
                                 (([Rule('URL-REGEX', value)] if valid else []) + [Rule('DOMAIN', 'keep.example.com')],
                                  [] if valid else ['line 1: invalid URL-REGEX ' + value]))

    def test_render_preserves_options_allow_white_and_source_identity(self):
        value = r'^(?IN-D+u)(?<ad>ads)(?-n:(a))\k<1>\k<2>$'
        blocker = Rule('DOMAIN-REGEX', value)
        allowed = Rule('DOMAIN-REGEX', value, allow=True)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    outputs, skipped = render('options', iter([blocker, allowed]), purpose=purpose, no_resolve=mode,
                                              whitelist=iter([Rule('DOMAIN-REGEX', r'^(?N)other$')]))
                    self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([blocker], []))
                    self.assertIn(json.dumps('DOMAIN-REGEX,' + value), outputs['fin.yaml'])
                    self.assertEqual(normalize([allowed, blocker]), [blocker, allowed])
                    self.assertEqual(allowed.value, value)
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 3 if purpose == 'block' else 2)

    def test_generate_options_white_publish_and_same_round_disk_dependencies(self):
        value = r'^(?IN-D+u)(?<ad>ads)(?-n:(a))\k<1>\k<2>(?X:(?#note,#)[ #]+)$'
        invalid = r'^(?N)(ads)\k<1>$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            flag = '' if mode == 'strip' else ',no-resolve'
                            initial = '' if mode == 'add' else ',no-resolve'
                            field = value if native else json.dumps(value)
                            logic = f'((NOT,((DOMAIN-REGEX,{field}))),(OR,((PROCESS-NAME-REGEX,{field}),(NETWORK,tcp))),'
                            logic += f'(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            wanted = f'((NOT,((DOMAIN-REGEX,{value}))),(OR,((PROCESS-NAME-REGEX,{value}),(NETWORK,tcp))),'
                            wanted += f'(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = [*(kind + ',' + field for kind in self.kinds), 'AND,' + logic,
                                        'IP-CIDR,192.0.2.0/24' + initial, 'SRC-IP-CIDR,198.51.100.0/24',
                                        'DOMAIN-REGEX,' + invalid, 'DOMAIN,covered.example.com', 'DOMAIN,keep.example.com']
                            source = (native_text(*matchers) if native else '\n'.join(matchers)) + '\n@@||allow.example.com^\n'
                            white = (native_text('DOMAIN-REGEX,^(?N)other$', 'DOMAIN,covered.example.com') if native else
                                     "DOMAIN-REGEX,'^(?N)other$'\nDOMAIN,covered.example.com\n")
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'input.list'],
                                        'whitelist': ['https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            (root / 'input.list').write_text(source, encoding='utf-8')
                            (root / 'static').mkdir()
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'input.list', root / 'static/white.list')}
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            self.assertIn('invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            expected = {*(Rule(kind, value) for kind in self.kinds), Rule('AND', wanted, native_fields=True),
                                        Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                        Rule('SRC-IP-CIDR', '198.51.100.0/24'),
                                        Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')}
                            self.assertEqual(list(outputs), [root / group / name for group in ('source', 'child') for name in FILES])
                            for group in ('source', 'child'):
                                self.assertEqual(set(parse(outputs[root / group / 'fin.yaml'], purpose=purpose)[0]), expected)
                                self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose)[1], [])
                                for kind in self.kinds:
                                    self.assertIn(json.dumps(kind + ',' + value), outputs[root / group / 'fin.yaml'])
                                self.assertNotIn('covered.example.com', outputs[root / group / 'fin.yaml'])
                                self.assertEqual(outputs[root / group / 'fin.txt'].splitlines()[1:],
                                                 ['DOMAIN,keep.example.com', 'IP-CIDR,192.0.2.0/24' + flag,
                                                  'SRC-IP,198.51.100.0/24'])
                                self.assertEqual(outputs[root / group / 'fin-surge-ds.txt'].splitlines()[1:], ['keep.example.com'])
                            if purpose == 'block':
                                self.assertIn('@@||allow.example.com^\n', outputs[root / 'source/fin-adb.txt'])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'input.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_options_in_generated_white_use_same_round_and_disk_bytes(self):
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['white.list'], 'whitelist': []},
                           {'name': 'source', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                value, white_value = r'^(?N)(?<ad>ads)\k<1>$', r'^(?XN:other)$'
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                (root / 'white.list').write_text(native_text('DOMAIN-REGEX,' + white_value,
                                                            'DOMAIN,covered.example.com'), encoding='utf-8')
                (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value,
                                                            'DOMAIN,covered.example.com', 'DOMAIN,keep.example.com'), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                                 [Rule('DOMAIN', 'covered.example.com', domain_source='mihomo'), Rule('DOMAIN-REGEX', white_value)])
                for group in ('source', 'child'):
                    self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                     ([Rule('DOMAIN', 'keep.example.com', domain_source='mihomo'), Rule('DOMAIN-REGEX', value)], []))
                publish(outputs, root=root)
                published = {path: path.read_bytes() for path in outputs}
                (root / 'input.list').unlink()
                (root / 'white.list').unlink()
                (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    disk = generate(root, lambda url: self.fail(url))
                self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({root / 'static/white.list': outputs[root / 'white/fin.yaml']}, root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                configs[1]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_invalid_options_white_keeps_local_error_and_remote_skip(self):
        for invalid in (r'^(?R)ads$', r'^(?N)(ads)\k<1>$'):
            for remote in (False, True):
                with self.subTest(invalid=invalid, remote=remote), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = [{'name': 'source', 'purpose': 'block', 'no_resolve': 'keep',
                               'sources': ['input.list'],
                               'whitelist': ['https://example.com/white' if remote else 'white.list']}]
                    value = r'^(?N)ads$'
                    white = native_text('DOMAIN-REGEX,' + invalid)
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value), encoding='utf-8')
                    (root / 'white.list').write_text(white, encoding='utf-8')
                    (root / 'source').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'source' / name
                        path.write_bytes(b'old product\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        if remote:
                            outputs = generate(root, lambda url: white.encode('utf-8'))
                            self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose='block'), ([Rule('DOMAIN-REGEX', value)], []))
                            self.assertIn('invalid whitelist (line 2: invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                        else:
                            with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                                generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)


class DeepRegexAuditTests(unittest.TestCase):
    kinds = QuantifierAuditTests.kinds

    def test_600_noncapture_groups_preserve_complete_raw_matcher(self):
        value = '^' + '(?:' * 600 + 'ads' + ')' * 600 + '$'
        self.assertEqual(parse('DOMAIN-REGEX,' + value + '\nDOMAIN,keep.example.com', purpose='block'),
                         ([Rule('DOMAIN-REGEX', value), Rule('DOMAIN', 'keep.example.com')], []))

    def test_expression_condition_has_no_first_branch_quantifier_operand(self):
        value = '^' + '(?:' * 600 + '(?(?=a)+b)' + ')' * 600 + '$'
        source = 'DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example.org'
        self.assertEqual(parse(source, purpose='block'),
                         ([Rule('DOMAIN', 'neighbor.example.org')], ['line 1: invalid DOMAIN-REGEX ' + value]))

    def test_expression_condition_boundaries_keep_only_valid_branches_at_all_depths(self):
        cases = (
            ('(?(?=a)+b)', False), ('(?(?!a)*b)', False),
            ('(?(?<!a)?b)', False), ('(?(?<=a){2}b)', False),
            ('(?(?=a){0}b)', False), ('(?(?=a){1,2}b)', False),
            ('(?(?=a){2,}b)', False), ('(?(?=a)(?#note)+b)', False),
            ('(?(?=a)(?#note)*b)', False), ('(?(?=a)(?#note)?b)', False),
            ('(?(?=a)(?#note){2}b)', False),
            ('(?x:(?(?=a) \t (?#note) +b))', False),
            ('(?x:(?(?=a) \t (?#note) {2}b))', False),
            ('(?(?=(a(?=b)))(?#note)?b)', False),
            ('(?(a|b)(?#note){2}b)', False), ('(?(missing)+b)', False),
            ('(a)(?(1)+b)', False), ('(?<ad>a)(?(ad){2}b)', False),
            ('(?(?=a)(?(?=b)+c)|d)', False),
            ('(?(?=a)b|c)', True), ('(?(?=a)b*?|c{2})', True),
            ('(?(?=a)(?#note)b(?#after)+|c)', True),
            ('(?(?<=a)(?:)+b|c)', True), ('(?(?=a)|c)', True),
            ('(?(?!a))', True), (r'(?(?=(a+))b|c)\k<1>', True),
            ('(a)(?(1)b+|c{2})', True), ('(?<ad>a)(?(ad)b|c)', True),
            (r'(?(?=a)\+{2}b|c)', True), ('(?(?=a)[+*?]{2}b|c)', True),
            ('(?(?=a){x}b|c)', True), ('(?(?=a){,2}b|c)', True),
            ('(?(?=a)(?:b?)+|c)', True), ('(?(?=a)(?(?=b)c+|d{2})|e)', True),
            ('(?x:(?(?=a) (?#note) b (?#after) +|c))', True),
            ('(?(?=a) +b|c)', True),
        )
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for depth in (0, 600, 1000):
            for atom, valid in cases:
                value = '^' + '(?:' * depth + atom + ')' * depth + '$'
                for kind in self.kinds:
                    for native in (False, True):
                        for quoted in (False, True):
                            escaped = value if native else value.replace('\\', '\\\\').replace('"', '\\"')
                            field = '"' + escaped + '"' if quoted else value
                            for operator in ('top', 'AND', 'OR', 'NOT'):
                                logic = f'(({kind},{field}))' if operator == 'NOT' else f'(({kind},{field}),(NETWORK,tcp))'
                                matcher = kind + ',' + field if operator == 'top' else operator + ',' + logic
                                source = (native_text(matcher, 'DOMAIN,neighbor.example.org') if native else
                                          matcher + '\nDOMAIN,neighbor.example.org')
                                expected = (Rule(kind, field if native else value) if operator == 'top' else
                                            Rule(operator, logic, native_fields=native))
                                neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')
                                message = f'invalid {kind} {field if native else value}' if operator == 'top' else f'invalid logical expression {logic}'
                                with self.subTest(depth=depth, atom=atom, kind=kind, native=native, quoted=quoted, operator=operator):
                                    parsed, messages = parse(source, purpose='proxy')
                                    self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                                    self.assertEqual(messages, [] if valid else [f'line {2 if native else 1}: {message}'])
                                    self.assertEqual(set(normalize(parsed)), set(parsed))
                                    if kind == 'DOMAIN-REGEX' and operator == 'top':
                                        with warnings.catch_warnings(record=True) as caught:
                                            warnings.simplefilter('always')
                                            self.assertEqual(parse_whitelist(source), ([expected] if valid else []) + [neighbor])
                                        self.assertEqual([str(item.message) for item in caught], messages)
                                        if not valid:
                                            with self.assertRaisesRegex(ValueError, 'invalid DOMAIN-REGEX'):
                                                parse_whitelist(native_text(matcher) if native else matcher)
                                    if not valid:
                                        outputs, _ = render('condition', parsed, purpose='proxy', no_resolve='keep')
                                        self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                                                         ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')], []))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_native_expression_condition_x_comments_do_not_create_branch_operands(self):
        for depth in (0, 600, 1000):
            for atom, valid in (
                    ('(?x:(?(?=a)# ignored\n+b|c))', False),
                    ('(?x:(?(?=a) # ignored\n*b|c))', False),
                    ('(?x:(?(?=a) # ignored\n?b|c))', False),
                    ('(?x:(?(?=(a+)) # ignored\n{0}b|c))', False),
                    ('(?x:(?(?=a) # ignored\nb+|c))', True),
                    ('(?x:(?(?=a) # ignored\nb|c))(?-x: +a)', True)):
                value = '^' + '(?:' * depth + atom + ')' * depth + '$'
                for kind in self.kinds:
                    for operator in ('top', 'AND', 'OR', 'NOT'):
                        logic = f'(({kind},{value}))' if operator == 'NOT' else f'(({kind},{value}),(NETWORK,tcp))'
                        matcher = kind + ',' + value if operator == 'top' else operator + ',' + logic
                        expected = Rule(kind, value) if operator == 'top' else Rule(operator, logic, native_fields=True)
                        message = f'invalid {kind} {value}' if operator == 'top' else f'invalid logical expression {logic}'
                        with self.subTest(depth=depth, atom=atom, kind=kind, operator=operator):
                            self.assertEqual(parse(native_text(matcher, 'DOMAIN,neighbor.example.org'), purpose='block'),
                                             (([expected] if valid else []) + [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')],
                                              [] if valid else ['line 2: ' + message]))

    def _check_group_headers(self, depth):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for opening in ('(', '(?:', '(?i:', '(?n:', '(?x:', '(?<ad>', "(?'ad'", '(?<7>',
                        '(?=', '(?!', '(?<=', '(?<!', '(?>', '(?(?=a)', '(?(?<=a)', '(?(missing)'):
            value = '^' + opening * depth + 'a|b' + ')' * depth + '{2}?$'
            for kind in self.kinds:
                for native in (False, True):
                    source = (native_text(kind + ',' + value, 'DOMAIN,keep.example.com') if native else
                              kind + ',' + json.dumps(value) + '\nDOMAIN,keep.example.com')
                    with self.subTest(depth=depth, opening=opening, kind=kind, native=native):
                        self.assertEqual(parse(source, purpose='proxy'),
                                         ([Rule(kind, value), Rule('DOMAIN', 'keep.example.com',
                                          domain_source='mihomo' if native else 'surge')], []))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_600_and_1000_group_headers_keep_all_regexp2_kinds_within_eight_seconds(self):
        for depth in (600, 1000):
            with self.subTest(depth=depth):
                code = ('from tests.test_functional_audit_rules import DeepRegexAuditTests; '
                        f'DeepRegexAuditTests()._check_group_headers({depth})')
                result = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                                        timeout=8, cwd=Path(__file__).resolve().parents[1])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_deep_mixed_groups_restore_options_captures_quotes_and_logical_order(self):
        for depth in (600, 1000):
            for atom, valid in ((r'(?N:(a))(?-n:(b))\k<1>', True),
                                (r'(?N:(a))(?-n:(b))\k<2>', False),
                                (r'(?<ad>a)(?(ad)b|c)\k<ad>', True),
                                (r'(?<ad>a)(?(7)b|c)', False),
                                (r'(?<7>a)(?(7)b|c)\k<7>', True),
                                (r'(?<ad>a)(?<out-ad>b)\k<out>', True),
                                (r'(?<ad>a)(?<out-missing>b)', False),
                                (r'(?>ab|c)(?=a)(?!b)(?<=a+)(?<!b+)', True),
                                (r'(?X:a[ # ])(?-x:b#c)', True),
                                (r'[\]\(\)]a(?#note)*?', True)):
                value = '^' + '(?i:(?:' * (depth // 2) + atom + '))' * (depth // 2) + '$'
                for native in (False, True):
                    for quoted in (False, True):
                        field = ('"' + value + '"' if native else json.dumps(value)) if quoted else value
                        for kind in self.kinds:
                            for operator in ('top', 'AND', 'OR', 'NOT'):
                                logic = f'(({kind},{field}))' if operator == 'NOT' else f'(({kind},{field}),(NETWORK,tcp))'
                                matcher = kind + ',' + field if operator == 'top' else operator + ',' + logic
                                source = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                          matcher + '\nDOMAIN,keep.example.com')
                                expected = (Rule(kind, field if native else value) if operator == 'top' else
                                            Rule(operator, logic, native_fields=native))
                                neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                                with self.subTest(depth=depth, atom=atom, native=native, quoted=quoted, kind=kind, operator=operator):
                                    parsed, messages = parse(source, purpose='proxy')
                                    self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                                    self.assertEqual(len(messages), int(not valid))
                                    if messages:
                                        self.assertTrue(messages[0].startswith(f'line {2 if native else 1}:'))
                                    self.assertEqual(set(normalize(parsed)), set(parsed))

    def test_deep_invalid_bodies_headers_and_delimiters_warn_and_keep_neighbors(self):
        for depth in (600, 1000):
            for atom in ('*a', 'a**', 'a{3,2}', r'\u{61}', r'\x(?#note)41',
                         '[z-a]', '[abc', '(?q:a)', '(?P<ad>a)', '(?=*)', '(?>*)',
                         '(?:*a)', '(?<ad name>a)', '(?(1)a|b)', '(?(?=a)b|c|d)',
                         r'a\k<missing>', r'a\k<2147483648>', '(?n)+a'):
                value = '^' + '(?:' * depth + atom + ')' * depth + '$'
                for kind in self.kinds:
                    for native in (False, True):
                        source = (native_text(kind + ',' + value, 'DOMAIN,keep.example.com') if native else
                                  kind + ',' + json.dumps(value) + '\nDOMAIN,keep.example.com')
                        with self.subTest(depth=depth, atom=atom, kind=kind, native=native):
                            parsed, messages = parse(source, purpose='proxy')
                            self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.com',
                                                          domain_source='mihomo' if native else 'surge')])
                            self.assertEqual(messages, [f'line {2 if native else 1}: invalid {kind} {value}'])
            for closers in (depth - 1, depth + 1):
                value = '^' + '(?:' * depth + 'a' + ')' * closers + '$'
                source = native_text('DOMAIN-REGEX,' + value, 'DOMAIN,keep.example.com')
                parsed, messages = parse(source, purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')])
                self.assertEqual(len(messages), 1)

    def test_deep_native_x_comments_and_scope_restore_after_newline(self):
        for depth in (600, 1000):
            for atom, valid in (('a # ignored,( [ *\n b', True), ('a # ignored )', False),
                                ('a # ignored\n**', False), ('a # ignored\n*?', True)):
                value = '^' + '(?XN:' * depth + atom + ')' * depth + '(b)\\k<1>$'
                for kind in self.kinds:
                    with self.subTest(depth=depth, atom=atom, kind=kind):
                        parsed, messages = parse(native_text(kind + ',' + value, 'DOMAIN,keep.example.com'), purpose='block')
                        self.assertEqual(parsed, ([Rule(kind, value)] if valid else []) +
                                         [Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')])
                        self.assertEqual(len(messages), int(not valid))

    def test_deep_domain_whitelist_and_url_regex_keep_distinct_validation(self):
        for depth in (600, 1000):
            value = '^' + '(?n:' * depth + r'(?<ad>a)\k<ad>' + ')' * depth + '$'
            invalid = '^' + '(?:' * depth + '(?(?<=a)(?#note){2}b)' + ')' * depth + '$'
            for native in (False, True):
                text = (native_text('DOMAIN-REGEX,' + value, 'DOMAIN-REGEX,' + invalid, 'DOMAIN,keep.example.com') if native else
                        'DOMAIN-REGEX,' + json.dumps(value) + '\nDOMAIN-REGEX,' + json.dumps(invalid) + '\nDOMAIN,keep.example.com')
                with self.subTest(depth=depth, native=native), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    self.assertEqual(parse_whitelist(text), [Rule('DOMAIN-REGEX', value),
                                     Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')])
                    self.assertEqual([str(item.message) for item in caught],
                                     [f'line {3 if native else 2}: invalid DOMAIN-REGEX {invalid}'])
            url_value = '^' + '(?:' * depth + 'ads' + ')' * depth + '$'
            self.assertEqual(parse('URL-REGEX,' + json.dumps(url_value) + '\nDOMAIN,keep.example.com', purpose='proxy'),
                             ([Rule('DOMAIN', 'keep.example.com')], ['line 1: invalid URL-REGEX ' + url_value]))
            with self.assertRaisesRegex(ValueError, 'invalid DOMAIN-REGEX'):
                parse_whitelist(native_text('DOMAIN-REGEX,' + invalid))
            blocker, allowed = Rule('DOMAIN-REGEX', value), Rule('DOMAIN-REGEX', value, allow=True)
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    outputs, skipped = render('deep', iter([blocker, allowed]), purpose=purpose, no_resolve=mode,
                                              whitelist=iter([Rule('DOMAIN-REGEX', value.replace('a)', 'b)'))]))
                    self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([blocker], []))
                    self.assertEqual(normalize([allowed, blocker]), [blocker, allowed])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 3 if purpose == 'block' else 2)
        for value, valid in (('(a)(?(1)b+|c{2})', True), ('(?(?=a)b|c)', False),
                             ('(a)(?(1)+b)', False), ('(?n:(a))(?(1)b|c)', False)):
            self.assertEqual(parse('URL-REGEX,' + json.dumps(value) + '\nDOMAIN,neighbor.example.org', purpose='proxy'),
                             (([Rule('URL-REGEX', value)] if valid else []) + [Rule('DOMAIN', 'neighbor.example.org')],
                              [] if valid else ['line 1: invalid URL-REGEX ' + value]))

    def test_deep_generate_local_remote_white_publish_and_yaml_dependencies(self):
        value = '^' + '(?n:' * 1000 + r'(?<ad>a)\k<ad>' + ')' * 1000 + '$'
        invalid = '^' + '(?:' * 600 + '(?(?=a)(?#note)+b)' + ')' * 600 + '$'
        white_value = '^' + '(?n:' * 600 + r'(?<other>b)\k<other>' + ')' * 600 + '$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            flag = '' if mode == 'strip' else ',no-resolve'
                            initial = '' if mode == 'add' else ',no-resolve'
                            field = value if native else json.dumps(value)
                            logic = f'((NOT,((DOMAIN-REGEX,{field}))),(OR,((PROCESS-PATH-REGEX,{field}),(NETWORK,tcp))),'
                            logic += f'(DOMAIN,leaf.example.com),(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            wanted = f'((NOT,((DOMAIN-REGEX,{value}))),(OR,((PROCESS-PATH-REGEX,{value}),(NETWORK,tcp))),'
                            wanted += f'(DOMAIN,leaf.example.com),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            bad_field = invalid if native else json.dumps(invalid)
                            matchers = [*(kind + ',' + field for kind in self.kinds), 'AND,' + logic,
                                        *(kind + ',' + bad_field for kind in self.kinds),
                                        'AND,' + f'((DOMAIN-REGEX,{bad_field}),(NETWORK,tcp))',
                                        'OR,' + f'((PROCESS-NAME-REGEX,{bad_field}),(NETWORK,tcp))',
                                        'NOT,' + f'((PROCESS-PATH-REGEX,{bad_field}))',
                                        'DOMAIN,covered.example.com', 'DOMAIN,keep.example.com',
                                        'IP-CIDR,192.0.2.0/24' + initial, 'SRC-IP-CIDR,198.51.100.0/24']
                            source = (native_text(*matchers) if native else '\n'.join(matchers)) + '\n@@||allow.example.com^\n'
                            white = (native_text('DOMAIN-REGEX,' + white_value, 'DOMAIN,covered.example.com') if native else
                                     'DOMAIN-REGEX,' + json.dumps(white_value) + '\nDOMAIN,covered.example.com')
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'input.list'],
                                        'whitelist': ['https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            (root / 'input.list').write_text(source, encoding='utf-8')
                            (root / 'static').mkdir()
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'input.list', root / 'static/white.list')}
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            for kind in self.kinds:
                                self.assertIn('invalid ' + kind + ' ' + invalid, diagnostic.getvalue())
                            self.assertIn('invalid logical expression', diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            expected = {*(Rule(kind, value) for kind in self.kinds),
                                        Rule('AND', wanted, native_fields=True, domain_source='mihomo'),
                                        Rule('DOMAIN', 'keep.example.com', domain_source='mihomo'),
                                        Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                        Rule('SRC-IP-CIDR', '198.51.100.0/24')}
                            self.assertEqual(list(outputs), [root / group / name for group in ('source', 'child') for name in FILES])
                            for group in ('source', 'child'):
                                parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(set(parsed), expected)
                                self.assertEqual(messages, [])
                                self.assertNotIn('covered.example.com', outputs[root / group / 'fin.yaml'])
                                for kind in self.kinds:
                                    self.assertIn(json.dumps(kind + ',' + value), outputs[root / group / 'fin.yaml'])
                                self.assertEqual(outputs[root / group / 'fin.txt'].splitlines()[1:],
                                                 ['DOMAIN,keep.example.com', 'IP-CIDR,192.0.2.0/24' + flag,
                                                  'SRC-IP,198.51.100.0/24'])
                                self.assertEqual(outputs[root / group / 'fin-surge-ds.txt'].splitlines()[1:], ['keep.example.com'])
                            if purpose == 'block':
                                self.assertIn('@@||allow.example.com^\n', outputs[root / 'source/fin-adb.txt'])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'input.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_illegal_expression_conditions_in_disk_yaml_do_not_reach_published_dependency(self):
        invalid = '^' + '(?:' * 1000 + '(?(?<=a)(?#note){2}b)' + ')' * 1000 + '$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'source').mkdir()
                    source = root / 'source/fin.yaml'
                    source.write_text(native_text(*(kind + ',' + invalid for kind in self.kinds),
                                                  'DOMAIN,neighbor.example.org'), encoding='utf-8')
                    original = source.read_bytes()
                    config = [{'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                               'sources': ['source/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'child').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'child' / name
                        path.write_bytes(b'old product\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        outputs = generate(root, lambda url: self.fail(url))
                    for kind in self.kinds:
                        self.assertIn('invalid ' + kind + ' ' + invalid, diagnostic.getvalue())
                    self.assertEqual(parse(outputs[root / 'child/fin.yaml'], purpose=purpose),
                                     ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')], []))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    self.assertEqual(source.read_bytes(), original)

    def test_deep_generated_white_disk_freeze_and_strict_white_boundaries(self):
        value = '^' + '(?n:' * 600 + r'(?<ad>a)\k<ad>' + ')' * 600 + '$'
        white_value = '^' + '(?n:' * 600 + r'(?<other>b)\k<other>' + ')' * 600 + '$'
        invalid = '^' + '(?:' * 600 + '(?(?=a)(?#note)+b)' + ')' * 600 + '$'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = [{'name': 'white', 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': ['white.list'], 'whitelist': []},
                       {'name': 'source', 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                       {'name': 'child', 'purpose': 'proxy', 'no_resolve': 'keep',
                        'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'white.list').write_text(native_text('DOMAIN-REGEX,' + white_value, 'DOMAIN-REGEX,' + invalid,
                                                        'DOMAIN,covered.example.com'), encoding='utf-8')
            (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value, 'DOMAIN-REGEX,' + invalid,
                                                        'DOMAIN,covered.example.com', 'DOMAIN,keep.example.com'), encoding='utf-8')
            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                outputs = generate(root, lambda url: self.fail(url))
            self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                             [Rule('DOMAIN', 'covered.example.com', domain_source='mihomo'), Rule('DOMAIN-REGEX', white_value)])
            for group in ('source', 'child'):
                self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose='proxy'),
                                 ([Rule('DOMAIN', 'keep.example.com', domain_source='mihomo'), Rule('DOMAIN-REGEX', value)], []))
            publish(outputs, root=root)
            published = {path: path.read_bytes() for path in outputs}
            (root / 'input.list').unlink()
            (root / 'white.list').unlink()
            (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                disk = generate(root, lambda url: self.fail(url))
            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
            with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                publish({root / 'static/white.list': outputs[root / 'white/fin.yaml']}, root=root)
            configs[1]['sources'] = ['https://example.com/missing']
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

            def unavailable(url):
                raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                self.assertEqual(generate(root, unavailable), {})
            self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
            self.assertEqual({path: path.read_bytes() for path in published}, published)
            (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value), encoding='utf-8')
            (root / 'white.list').write_text(native_text('DOMAIN-REGEX,' + invalid), encoding='utf-8')
            for remote in (False, True):
                config = {'name': 'source', 'purpose': 'proxy', 'no_resolve': 'keep', 'sources': ['input.list'],
                          'whitelist': ['https://example.com/white' if remote else 'white.list']}
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    if remote:
                        actual = generate(root, lambda url: native_text('DOMAIN-REGEX,' + invalid).encode('utf-8'))
                        self.assertEqual(parse(actual[root / 'source/fin.yaml'], purpose='proxy'), ([Rule('DOMAIN-REGEX', value)], []))
                        self.assertIn('invalid whitelist', diagnostic.getvalue())
                    else:
                        with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                            generate(root, lambda url: self.fail(url))
                self.assertEqual({path: path.read_bytes() for path in published}, published)


class BracedHexAuditTests(unittest.TestCase):
    kinds = QuantifierAuditTests.kinds
    cases = (
        (r'^\x{000061}$', True), (r'^\x{0000061}$', True),
        (r'^\x{' + '0' * 5000 + '61}$', True),
        (r'^\x{' + '0' * 5000 + '}$', True),
        (r'^\x{' + '0' * 5000 + '10fFFF}$', True),
        (r'^\x{10FFFF}$', True), (r'^\x{D800}$', True),
        (r'^\x{000002E}+$', True), (r'^\x{0000061}{1,2}$', True),
        (r'^[\x{0000061}-\x{0000063}]$', True),
        (r'^[\x{0000028}-\x{0000029}]$', True),
        (r'^[\x{000005C}\x{000005D}\x{000005E}\x{000002D}]$', True),
        (r'^\\x{0000061}$', True), (r'^\\x{110000}$', True),
        (r'^\\x{' + 'F' * 5000 + '}$', True),
        (r'^[\x{0000063}-\x{0000061}]$', False),
        (r'^[\x{0000061}-\d]$', False),
        (r'^\x{110000}$', False),
        (r'^\x{' + '0' * 5000 + '110000}$', False),
        (r'^\x{' + 'F' * 5000 + '}$', False),
        (r'^\x{}$', False), (r'^\x{0_61}$', False),
        (r'^\x{+61}$', False), (r'^\x{-61}$', False),
        (r'^\x{0x61}$', False), (r'^\x{６１}$', False),
        (r'^\x{' + '0' * 5000 + 'g}$', False),
        (r'^\x{ 61}$', False), (r'^\x{61$', False),
    )

    def test_public_parse_and_normalize_preserve_raw_hex_with_quoted_and_logical_fields(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            for value, valid in self.cases:
                for native in (False, True):
                    for quoted in (False, True):
                        for logical in (False, True):
                            field = f"'{value}'" if quoted else value
                            checked = field if native else value
                            expression = f'(({kind},{field}),(NETWORK,tcp))'
                            matcher = f'AND,{expression}' if logical else f'{kind},{field}'
                            source = (native_text(matcher, 'DOMAIN,keep.example.com') if native else
                                      matcher + '\nDOMAIN,keep.example.com')
                            neighbor = Rule('DOMAIN', 'keep.example.com', domain_source='mihomo' if native else 'surge')
                            expected = Rule('AND', expression, native_fields=native) if logical else Rule(kind, checked)
                            with self.subTest(kind=kind, length=len(value), native=native, quoted=quoted, logical=logical):
                                parsed, messages = parse(source, purpose='proxy')
                                self.assertEqual(parsed, ([expected] if valid else []) + [neighbor])
                                self.assertEqual(set(normalize(parsed)), set(parsed))
                                if valid:
                                    self.assertEqual(parsed[0].value, expression if logical else checked)
                                self.assertEqual(len(messages), int(not valid))
                                if messages:
                                    self.assertTrue(messages[0].startswith(f'line {2 if native else 1}: invalid '))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_domain_whitelist_preserves_legal_hex_and_warns_only_for_invalid_lines(self):
        for value, valid in self.cases:
            for native in (False, True):
                for quoted in (False, True):
                    field = f"'{value}'" if quoted else value
                    text = (native_text('DOMAIN-REGEX,' + field, 'DOMAIN,keep.example.com') if native else
                            f'DOMAIN-REGEX,{field}\nDOMAIN,keep.example.com')
                    with self.subTest(length=len(value), native=native, quoted=quoted), warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        white = parse_whitelist(text)
                        checked = field if native else value
                        self.assertEqual([rule.value for rule in white], ([checked] if valid else []) + ['keep.example.com'])
                        self.assertEqual(len(caught), int(not valid))

    def test_generated_hex_white_uses_same_round_and_disk_bytes(self):
        value = r'^\x{' + '0' * 5000 + '61}$'
        white_value = r'^\x{' + '0' * 5000 + '62}$'
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['white.list'], 'whitelist': []},
                           {'name': 'source', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['input.list'], 'whitelist': ['white/fin.yaml']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                (root / 'white.list').write_text(native_text('DOMAIN-REGEX,' + white_value,
                                                            'DOMAIN,covered.example.com'), encoding='utf-8')
                (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value, 'DOMAIN,covered.example.com',
                                                            'DOMAIN,keep.example.com'), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    outputs = generate(root, lambda url: self.fail(url))
                self.assertEqual(parse_whitelist(outputs[root / 'white/fin.yaml']),
                                 [Rule('DOMAIN', 'covered.example.com', domain_source='mihomo'),
                                  Rule('DOMAIN-REGEX', white_value)])
                for group in ('source', 'child'):
                    self.assertEqual(parse(outputs[root / group / 'fin.yaml'], purpose=purpose),
                                     ([Rule('DOMAIN', 'keep.example.com', domain_source='mihomo'),
                                       Rule('DOMAIN-REGEX', value)], []))
                publish(outputs, root=root)
                published = {path: path.read_bytes() for path in outputs}
                (root / 'input.list').unlink()
                (root / 'white.list').unlink()
                (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                    disk = generate(root, lambda url: self.fail(url))
                self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({root / 'static/white.list': outputs[root / 'white/fin.yaml']}, root=root)
                self.assertFalse((root / 'static').exists())
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                configs[1]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_invalid_hex_white_keeps_local_error_and_remote_skip_boundaries(self):
        value = r'^\x{' + '0' * 5000 + '61}$'
        for invalid in (r'^\x{}$', r'^\x{110000}$', r'^\x{' + '0' * 5000 + 'g}$'):
            for remote in (False, True):
                with self.subTest(length=len(invalid), remote=remote), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = [{'name': 'source', 'purpose': 'block', 'no_resolve': 'keep',
                               'sources': ['input.list'],
                               'whitelist': ['https://example.com/white' if remote else 'white.list']}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    (root / 'input.list').write_text(native_text('DOMAIN-REGEX,' + value), encoding='utf-8')
                    white = native_text('DOMAIN-REGEX,' + invalid)
                    (root / 'white.list').write_text(white, encoding='utf-8')
                    (root / 'source').mkdir()
                    old = {}
                    for name in FILES:
                        path = root / 'source' / name
                        path.write_bytes(b'old product\x00\xff\r\n')
                        old[path] = path.read_bytes()
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        if remote:
                            outputs = generate(root, lambda url: white.encode('utf-8'))
                            self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose='block'),
                                             ([Rule('DOMAIN-REGEX', value)], []))
                            self.assertIn('invalid whitelist (line 2: invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                        else:
                            with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                                generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)

    def test_double_quoted_fields_decode_only_ordinary_source(self):
        for kind in self.kinds:
            for value in (r'^\x{000061}$', r'^\x{' + '0' * 5000 + '61}$'):
                for native in (False, True):
                    field = '"' + value + '"' if native else json.dumps(value)
                    expression = f'(({kind},{field}),(NETWORK,tcp))'
                    for matcher in (kind + ',' + field, 'AND,' + expression):
                        document = native_text(matcher) if native else matcher
                        expected = (Rule('AND', expression, native_fields=native) if matcher.startswith('AND,') else
                                    Rule(kind, field if native else value))
                        with self.subTest(kind=kind, length=len(value), native=native, logical=matcher.startswith('AND,')):
                            self.assertEqual(parse(document, purpose='proxy'), ([expected], []))
                            if kind == 'DOMAIN-REGEX' and not matcher.startswith('AND,'):
                                self.assertEqual(parse_whitelist(document), [expected])

    def test_direct_render_preserves_hex_matcher_and_allow_identity(self):
        value = r'^\x{' + '0' * 5000 + '61}$'
        blocker = Rule('DOMAIN-REGEX', value)
        allowed = Rule('DOMAIN-REGEX', value, allow=True)
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    outputs, _ = render('hex', [blocker, allowed], purpose=purpose, no_resolve=mode,
                                        whitelist=[Rule('DOMAIN-REGEX', r'^\x{0000062}$')])
                    self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([blocker], []))
                    self.assertEqual(normalize([allowed, blocker]), [blocker, allowed])
                    self.assertEqual(allowed.value, value)

    def test_url_regex_keeps_python_hex_semantics(self):
        for value in (r'^\x{0000061}$', r'^\x{' + '0' * 5000 + '61}$'):
            with self.subTest(length=len(value)):
                parsed, messages = parse(f"URL-REGEX,'{value}'\nDOMAIN,keep.example.com", purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'keep.example.com')])
                self.assertEqual(messages, ['line 1: invalid URL-REGEX ' + value])
        value = r'^\x61$'
        self.assertEqual(parse(f"URL-REGEX,'{value}'", purpose='proxy'), ([Rule('URL-REGEX', value)], []))

    def test_generate_local_remote_white_publish_and_yaml_dependencies_preserve_raw_hex(self):
        legal = r'^\x{' + '0' * 5000 + '61}$'
        legal_white = r'^\x{' + '0' * 5000 + '62}$'
        invalid = r'^\x{110000}$'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            flag = '' if mode == 'strip' else ',no-resolve'
                            initial = '' if mode == 'add' else ',no-resolve'
                            leaf = legal if native else f"'{legal}'"
                            logic = f'((NOT,((DOMAIN-REGEX,{leaf}))),(OR,((PROCESS-NAME-REGEX,{leaf}),(NETWORK,tcp))),'
                            logic += f'(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            wanted = f'((NOT,((DOMAIN-REGEX,{legal}))),(OR,((PROCESS-NAME-REGEX,{legal}),(NETWORK,tcp))),'
                            wanted += f'(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = [*(kind + ',' + leaf for kind in self.kinds), 'AND,' + logic,
                                        'IP-CIDR,192.0.2.0/24' + initial, 'SRC-IP-CIDR,198.51.100.0/24',
                                        'DOMAIN-REGEX,' + invalid, 'DOMAIN,keep.example.com']
                            source = (native_text(*matchers) if native else '\n'.join(matchers)) + '\n@@||allow.example.com^\n'
                            white = (native_text('DOMAIN-REGEX,' + legal_white, 'DOMAIN,other.example.com') if native else
                                     f"DOMAIN-REGEX,'{legal_white}'\nDOMAIN,other.example.com\n")
                            configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'input.list'],
                                        'whitelist': ['https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            (root / 'input.list').write_text(source, encoding='utf-8')
                            (root / 'static').mkdir()
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'input.list', root / 'static/white.list')}
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            old = {}
                            for group in ('source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, lambda url: responses[url])
                            self.assertIn('invalid DOMAIN-REGEX ' + invalid, diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            expected = {*(Rule(kind, legal) for kind in self.kinds),
                                        Rule('AND', wanted, native_fields=True),
                                        Rule('IP-CIDR', '192.0.2.0/24', ('no-resolve',) if flag else ()),
                                        Rule('SRC-IP-CIDR', '198.51.100.0/24'),
                                        Rule('DOMAIN', 'keep.example.com', domain_source='mihomo')}
                            self.assertEqual(list(outputs), [root / group / name for group in ('source', 'child') for name in FILES])
                            for group in ('source', 'child'):
                                parsed, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(set(parsed), expected)
                                self.assertEqual(messages, [])
                                for kind in self.kinds:
                                    self.assertIn(json.dumps(kind + ',' + legal), outputs[root / group / 'fin.yaml'])
                            if purpose == 'block':
                                self.assertIn('@@||allow.example.com^\n', outputs[root / 'source/fin-adb.txt'])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'input.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)


class QuotedLogicalPortAuditTests(unittest.TestCase):
    kinds = ('DEST-PORT', 'DST-PORT', 'SRC-PORT', 'IN-PORT')
    cases = (('443', '443'), ('0', '0'), ('65535', '65535'), ('000443', '000443'),
             ('80-90', '80-90'), ('0-65535', '0-65535'), ('80/443', None),
             ('80/443-445', None), ('>80', '81-65535'), ('>=80', '80-65535'),
             ('<80', '1-79'), ('<=80', '1-80'), ('>65534', '65535'), ('<2', '1'),
             ('>=65535', '65535'), ('<=1', '1'))

    def test_ordinary_quoted_logical_port_uses_decoded_value_and_keeps_neighbor(self):
        source = 'AND,((DEST-PORT,"443"),(NETWORK,tcp)),PROXY\nDOMAIN,neighbor.example.org,PROXY'
        self.assertEqual(parse(source, purpose='proxy'),
                         ([Rule('AND', '((DEST-PORT,443),(NETWORK,tcp))'),
                           Rule('DOMAIN', 'neighbor.example.org')], []))

    def test_ordinary_top_and_logical_quotes_share_port_values_and_preserve_child_order(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for kind in self.kinds:
            port_kind = 'DST-PORT' if kind == 'DEST-PORT' else kind
            for raw, canonical in self.cases:
                canonical_leaf = (f'({kind},{canonical})' if canonical is not None else
                                  f'(OR,(({port_kind},80),({port_kind},{"443" if raw == "80/443" else "443-445"})))')
                for quote in ('', '\'', '"'):
                    field = quote + raw + quote
                    leaf = f'({kind},{field})'
                    for purpose, policy in (('block', 'REJECT'), ('direct', 'DIRECT'), ('proxy', 'PROXY')):
                        with self.subTest(kind=kind, raw=raw, quote=quote, purpose=purpose):
                            top = Rule(kind, canonical) if canonical is not None else Rule('OR', canonical_leaf[4:-1])
                            self.assertEqual(parse(f'{kind},{field},{policy}', purpose=purpose), ([top], []))
                            pairs = ((f'AND,({leaf},(NETWORK,tcp))', Rule('AND', f'({canonical_leaf},(NETWORK,tcp))')),
                                     (f'OR,((NETWORK,tcp),{leaf})', Rule('OR', f'((NETWORK,tcp),{canonical_leaf})')),
                                     (f'NOT,({leaf})', Rule('NOT', f'({canonical_leaf})')),
                                     (f'NOT,{leaf}', Rule('NOT', canonical_leaf)),
                                     (f'AND,((NOT,({leaf})),(OR,((NETWORK,tcp),{leaf})))',
                                      Rule('AND', f'((NOT,({canonical_leaf})),(OR,((NETWORK,tcp),{canonical_leaf})))')))
                            for matcher, wanted in pairs:
                                source = matcher + ',' + policy + '\nDOMAIN,neighbor.example.org,' + policy
                                self.assertEqual(parse(source, purpose=purpose),
                                                 ([wanted, Rule('DOMAIN', 'neighbor.example.org')], []))
                                self.assertEqual(set(normalize([wanted, wanted])), {wanted})
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_native_outer_yaml_quotes_decode_while_inner_port_quotes_remain_literal(self):
        for header in ('payload', 'rules'):
            for scalar in ('plain', 'single', 'double'):
                for kind in ('DST-PORT', 'SRC-PORT', 'IN-PORT'):
                    for operator in ('top', 'AND', 'OR', 'NOT'):
                        for quote in ('', '\'', '"'):
                            field = quote + '443' + quote
                            expression = f'(({kind},{field}))' if operator == 'NOT' else f'(({kind},{field}),(NETWORK,tcp))'
                            matcher = kind + ',' + field if operator == 'top' else operator + ',' + expression
                            scalar_value = (matcher if scalar == 'plain' else json.dumps(matcher) if scalar == 'double' else
                                            "'" + matcher.replace("'", "''") + "'")
                            source = header + ':\n  - ' + scalar_value + '\n  - DOMAIN,neighbor.example.org'
                            neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')
                            wanted = Rule(kind, '443') if operator == 'top' else Rule(operator, expression, native_fields=True)
                            with self.subTest(header=header, scalar=scalar, kind=kind, operator=operator, quote=quote):
                                self.assertEqual(parse(source, purpose='proxy'),
                                                 (([] if quote else [wanted]) + [neighbor],
                                                  [f'line 2: invalid port {field}' if operator == 'top' else
                                                   f'line 2: invalid logical expression {expression}'] if quote else []))
        self.assertEqual(parse('payload:\n  - "NOT,((DST-PORT,\\x34\\x34\\x33))"', purpose='proxy'),
                         ([Rule('NOT', '((DST-PORT,443))', native_fields=True)], []))
        expression = '((DST-PORT,443),(DOMAIN,ADS.EXAMPLE.ORG.),(DOMAIN-WILDCARD,[ab]),(IP-ASN,00),(PROCESS-NAME,"Game"))'
        wanted = Rule('AND', expression, literal_process=True, native_fields=True, domain_source='mihomo')
        self.assertEqual(parse(native_text('AND,' + expression), purpose='proxy'), ([wanted], []))
        for mode in ('add', 'strip', 'keep'):
            outputs, _ = render('native', [wanted], purpose='proxy', no_resolve=mode)
            emitted = expression.replace('(IP-ASN,00)', '(IP-ASN,00,no-resolve)') if mode == 'add' else expression
            self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                             ([Rule('AND', emitted, literal_process=True, native_fields=True, domain_source='mihomo')], []))

    def test_invalid_quoted_ports_warn_without_accepting_a_partial_logical_rule(self):
        invalid = ('', ' ', '65536', '-1', '+443', '443-80', '80-', '80/65536', '/80', '80/',
                   '80//443', '80,443', '*', '>65535', '<=0', '>=65536', '<0', '>80/443',
                   '44a', '４４３', '80 -90', ' 443 ', '\t443', '0x1bb', '"443"', "'443'", '9' * 5000)
        for native in (False, True):
            for kind in self.kinds:
                for raw in invalid:
                    for quote in ('\'', '"'):
                        field = quote + raw + quote
                        for operator in ('top', 'AND', 'OR', 'NOT'):
                            expression = f'(({kind},{field}))' if operator == 'NOT' else f'(({kind},{field}),(NETWORK,tcp))'
                            matcher = kind + ',' + field if operator == 'top' else operator + ',' + expression
                            source = native_text(matcher, 'DOMAIN,neighbor.example.org') if native else matcher + '\nDOMAIN,neighbor.example.org'
                            with self.subTest(native=native, kind=kind, raw=raw[:40], quote=quote, operator=operator):
                                parsed, messages = parse(source, purpose='block')
                                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org',
                                                              domain_source='mihomo' if native else 'surge')])
                                self.assertEqual(len(messages), 1)
                                self.assertTrue(messages[0].startswith(f'line {2 if native else 1}:'))
        for source in ('AND,((DST-PORT,"443),(NETWORK,tcp))', "NOT,((SRC-PORT,'443))"):
            parsed, messages = parse(source + '\nDOMAIN,neighbor.example.org', purpose='proxy')
            self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
            self.assertEqual(messages, ['line 1: unbalanced delimiters'])

    def test_quoted_ports_do_not_receive_ip_options_and_no_resolve_only_changes_destination_ip(self):
        expression = ('((SRC-PORT,"443"),(NOT,((IN-PORT,\'80-90\'))),'
                      '(OR,((DST-PORT,"80/443"),(DEST-PORT,\'>80\'))),'
                      '(IP-CIDR,192.0.2.7/24),(IP-CIDR,198.51.100.7/24,no-resolve),'
                      '(IP-CIDR,203.0.113.7/24,src,no-resolve),(SRC-IP-CIDR,203.0.114.7/24,no-resolve))')
        canonical = ('((SRC-PORT,443),(NOT,((IN-PORT,80-90))),'
                     '(OR,((OR,((DST-PORT,80),(DST-PORT,443))),(DEST-PORT,81-65535))),'
                     '(IP-CIDR,192.0.2.0/24),(IP-CIDR,198.51.100.0/24,no-resolve),'
                     '(SRC-IP-CIDR,203.0.113.0/24),(SRC-IP-CIDR,203.0.114.0/24))')
        for purpose in ('block', 'direct', 'proxy'):
            parsed, messages = parse('AND,' + expression, purpose=purpose)
            self.assertEqual((parsed, messages), ([Rule('AND', canonical)],
                             ['line 1: unsupported no-resolve for SRC-IP-CIDR'] * 2))
            for mode in ('add', 'strip', 'keep'):
                emitted = canonical.replace('DEST-PORT,', 'DST-PORT,')
                if mode == 'add':
                    emitted = emitted.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)')
                elif mode == 'strip':
                    emitted = emitted.replace(',no-resolve', '')
                outputs, skipped = render('ports', parsed, purpose=purpose, no_resolve=mode)
                self.assertEqual(outputs['fin.yaml'], '# ports rules: 1\npayload:\n  - ' + json.dumps('AND,' + emitted) + '\n')
                self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), ([Rule('AND', emitted, native_fields=True)], []))
                self.assertEqual(outputs['fin.txt'], '# ports rules: 1\nAND,' + emitted.replace('DST-PORT,', 'DEST-PORT,').replace('SRC-IP-CIDR,', 'SRC-IP,') + '\n')
                self.assertEqual(skipped, {f'{name}:AND': 1 for name in ('fin-qx.txt', 'fin-adb.txt', 'fin-surge-ds.txt')})
        for kind in self.kinds:
            for option in ('no-resolve', 'src', 'force-cellular', 'REJECT'):
                parsed, messages = parse(f'AND,(({kind},"443",{option}),(NETWORK,tcp))\nDOMAIN,neighbor.example.org', purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                self.assertEqual(len(messages), 1)

    def test_white_allow_and_quoted_regex_siblings_keep_existing_roles(self):
        expression = '((SRC-PORT,"443"),(DOMAIN-REGEX,"^a{2,3}\\.example\\.org$"),(PROCESS-NAME,"Game,Inc"))'
        canonical = expression.replace('(SRC-PORT,"443")', '(SRC-PORT,443)')
        for purpose in ('block', 'direct', 'proxy'):
            self.assertEqual(parse('AND,' + expression, purpose=purpose), ([Rule('AND', canonical)], []))
        for native in (False, True):
            source = (native_text('NOT,((DST-PORT,"443"))', 'DOMAIN,neighbor.example.org') if native else
                      'NOT,((DST-PORT,"443"))\nDOMAIN,neighbor.example.org')
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                self.assertEqual(parse_whitelist(source), [Rule('DOMAIN', 'neighbor.example.org',
                                                               domain_source='mihomo' if native else 'surge')])
            self.assertEqual([str(item.message) for item in caught],
                             ['line 2: invalid logical expression ((DST-PORT,"443"))'] if native else [])
        self.assertEqual(parse_whitelist('DST-PORT,"443"\nNOT,((SRC-PORT,\'443\'))'), [])
        with self.assertRaisesRegex(ValueError, 'invalid logical expression'):
            parse_whitelist(native_text('NOT,((SRC-PORT,"443"))'))
        allowed = Rule('AND', '((SRC-PORT,443),(NETWORK,tcp))', allow=True)
        for mode in ('add', 'strip', 'keep'):
            outputs, skipped = render('allow', [allowed], purpose='block', no_resolve=mode)
            self.assertEqual(outputs['fin.yaml'], '# allow rules: 0\npayload:\n')
            self.assertEqual(skipped, {f'{name}:AND': 1 for name in FILES})
            self.assertEqual(normalize([allowed]), [allowed])

    def test_deep_quoted_port_logic_keeps_eight_second_timeout_and_original_global_limits(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
for depth in (600, 1000):
    matcher, canonical = 'SRC-PORT,"443"', 'SRC-PORT,443'
    for _ in range(depth):
        matcher, canonical = 'NOT,((' + matcher + '))', 'NOT,((' + canonical + '))'
    parsed, messages = parse(matcher, purpose='proxy')
    assert (parsed, messages) == ([Rule('NOT', canonical[4:])], [])
    outputs, skips = render('deep-port', parsed, purpose='proxy', no_resolve='add')
    assert 'fin.yaml:NOT' not in skips
    assert parse(outputs['fin.yaml'], purpose='proxy') == ([Rule('NOT', canonical[4:], native_fields=True)], [])
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generate_quoted_ports_publish_six_outputs_and_same_round_disk_dependencies(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            initial = '' if mode == 'add' else ',no-resolve'
                            flag = '' if mode == 'strip' else ',no-resolve'
                            destination = 'DST-PORT' if native else 'DEST-PORT'
                            single = '443' if native else '"443"'
                            multi = '80/443' if native else "'80/443'"
                            port_range = '80-90' if native else '"80-90"'
                            zero = '0' if native else "'0'"
                            conjunction = f'((SRC-PORT,{single}),(NOT,((IN-PORT,{zero}))),'
                            conjunction += f'(IP-CIDR,192.0.2.0/24{initial}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = [f'{destination},{single}', 'SRC-PORT,' + ('123' if native else "'123'"),
                                        'IN-PORT,' + port_range, 'AND,' + conjunction,
                                        f'OR,(({destination},{multi}),(NETWORK,tcp))', f'NOT,((IN-PORT,{single}))',
                                        'IP-CIDR,192.0.2.0/24' + initial, 'SRC-IP-CIDR,198.51.100.0/24',
                                        'DOMAIN,covered.example.org', 'DOMAIN,neighbor.example.org',
                                        'NOT,((DST-PORT,"443"))' if native else 'NOT,((DST-PORT,"65536"))']
                            source = (native_text(*matchers) if native else '\n'.join(matchers)) + '\n@@||allow.example.org^\n'
                            white = 'DOMAIN,covered.example.org\n'
                            (root / 'static').mkdir()
                            (root / 'static/source.list').write_text(source, encoding='utf-8')
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/white' if remote else 'static/white.list'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'static/source.list'],
                                        'whitelist': ['white/fin.txt']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.txt']}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': white.encode('utf-8')}
                            calls = []

                            def fetch(url):
                                calls.append(url)
                                return responses[url]

                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, fetch)
                            self.assertEqual(calls, ['https://example.com/white', 'https://example.com/source'] if remote else [])
                            self.assertIn('invalid logical expression ((DST-PORT,"443"))' if native else
                                          'invalid logical expression ((DST-PORT,"65536"))', diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertEqual(list(outputs), [root / group / name for group in ('white', 'source', 'child') for name in FILES])
                            conjunction = ('((SRC-PORT,443),(NOT,((IN-PORT,0))),'
                                           f'(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))')
                            disjunction = '((OR,((DST-PORT,80),(DST-PORT,443))),(NETWORK,tcp))'
                            yaml_body = ['AND,' + conjunction, 'DOMAIN,neighbor.example.org', 'DST-PORT,443',
                                         'IN-PORT,80-90', 'NOT,((IN-PORT,443))', 'OR,' + disjunction, 'SRC-PORT,123',
                                         'IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP-CIDR,198.51.100.0/24']
                            surge_body = ['AND,' + conjunction.replace('SRC-IP-CIDR,', 'SRC-IP,'), 'DEST-PORT,443',
                                          'DOMAIN,neighbor.example.org', 'IN-PORT,80-90', 'NOT,((IN-PORT,443))',
                                          'OR,((OR,((DEST-PORT,80),(DEST-PORT,443))),(PROTOCOL,TCP))', 'SRC-PORT,123',
                                          'IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,198.51.100.0/24']
                            qx_body = ['HOST,neighbor.example.org,LIST', 'IP-CIDR,192.0.2.0/24,LIST' + flag]
                            for group in ('source', 'child'):
                                dns_body = (['@@||allow.example.org^'] if group == 'source' else []) + ['@@|covered.example.org|', '0.0.0.0 neighbor.example.org']
                                if purpose != 'block':
                                    dns_body = []
                                expected = {'fin.yaml': f'# {group} rules: 9\npayload:\n' + ''.join('  - ' + json.dumps(line) + '\n' for line in yaml_body),
                                            'fin.txt': f'# {group} rules: 9\n' + '\n'.join(surge_body) + '\n',
                                            'fin-qx.txt': f'# {group} rules: 2\n' + '\n'.join(qx_body) + '\n',
                                            'fin-surge.txt': f'# {group} rules: 8\n' + '\n'.join(line for line in surge_body if not line.startswith('DOMAIN,')) + '\n',
                                            'fin-surge-ds.txt': f'# {group} rules: 1\nneighbor.example.org\n',
                                            'fin-adb.txt': '[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                                           '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n' +
                                                           '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
                                                           f'! Total count: {len(dns_body)}\n' +
                                                           (''.join(line + '\n' for line in dns_body) if purpose == 'block' else
                                                            '! No AdBlock rules for non-advertising group.\n')}
                                self.assertEqual({name: outputs[root / group / name] for name in FILES}, expected)
                                restored, messages = parse(expected['fin.yaml'], purpose=purpose)
                                self.assertEqual(messages, [])
                                self.assertEqual([rule.kind + ',' + rule.value + (',no-resolve' if rule.options else '') for rule in restored], yaml_body)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertTrue(all(b'\r' not in data and data.endswith(b'\n') for data in published.values()))
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'static/source.list').unlink()
                            (root / 'static/white.list').unlink()
                            (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)

    def test_invalid_port_white_and_unavailable_sources_keep_freeze_and_path_boundaries(self):
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                source = 'NOT,((SRC-PORT,"443"))\nDOMAIN,neighbor.example.org\n'
                white = native_text('NOT,((DST-PORT,"443"))')
                (root / 'input.list').write_text(source, encoding='utf-8')
                (root / 'static/white.list').write_text(white, encoding='utf-8')
                configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': 'add',
                            'sources': ['input.list'], 'whitelist': ['static/white.list']},
                           {'name': 'child', 'purpose': purpose, 'no_resolve': 'keep',
                            'sources': ['source/fin.yaml'], 'whitelist': []}]
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                old = {}
                for group in ('source', 'child'):
                    (root / group).mkdir()
                    for name in FILES:
                        path = root / group / name
                        path.write_bytes(b'old product\x00\xff\r\n')
                        old[path] = path.read_bytes()
                with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                    generate(root, lambda url: self.fail(url))
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                configs[0]['whitelist'] = ['https://example.com/invalid-white']
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    outputs = generate(root, lambda url: white.encode('utf-8'))
                self.assertIn('invalid whitelist', diagnostic.getvalue())
                self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose=purpose),
                                 ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'),
                                   Rule('NOT', '((SRC-PORT,443))', native_fields=True)], []))
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                for path, message in ((root / 'static/white.list', 'Output path targets static'),
                                      (root / '../escape.list', 'Output path escapes root')):
                    with self.assertRaisesRegex(ValueError, message):
                        publish({path: outputs[root / 'source/fin.yaml']}, root=root)
                self.assertEqual((root / 'static/white.list').read_text(encoding='utf-8'), white)
                configs[0]['sources'], configs[0]['whitelist'] = ['https://example.com/missing'], []
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                configs[0]['sources'] = ['https://example.com/invalid-source']
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, lambda url: white.encode('utf-8')), {})
                self.assertIn('no adaptable rules; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in old}, old)

    def test_long_zero_padded_quoted_ports_preserve_raw_numbers_and_bounded_comparisons(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for quote in ('\'', '"'):
            for kind in self.kinds:
                for raw, canonical in (('0' * 5000 + '443', '0' * 5000 + '443'),
                                       ('>' + '0' * 5000 + '80', '81-65535'),
                                       ('<=' + '0' * 5000 + '1', '1')):
                    field = quote + raw + quote
                    with self.subTest(quote=quote, kind=kind, suffix=raw[-5:]):
                        self.assertEqual(parse(kind + ',' + field, purpose='proxy'), ([Rule(kind, canonical)], []))
                        self.assertEqual(parse(f'NOT,(({kind},{field}))', purpose='proxy'),
                                         ([Rule('NOT', f'(({kind},{canonical}))')], []))
                        outputs, _ = render('zero-port', [Rule('NOT', f'(({kind},{canonical}))')],
                                            purpose='proxy', no_resolve='add')
                        native_kind = 'DST-PORT' if kind == 'DEST-PORT' else kind
                        self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]),
                                         f'NOT,(({native_kind},{canonical}))')
                        restored, messages = parse(outputs['fin.yaml'], purpose='proxy')
                        self.assertEqual(messages, [])
                        self.assertEqual(len(restored), 1)
                        self.assertEqual((restored[0].kind, restored[0].native_fields), ('NOT', True))
                        self.assertTrue(restored[0].value.startswith(f'(({native_kind},'))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_generate_quoted_comparisons_keep_source_destination_and_inbound_ports(self):
        source = 'AND,((SRC-PORT,">80"),(DEST-PORT,\'<=443\'),(IN-PORT,"0-80"))\n'
        surge = 'AND,((SRC-PORT,81-65535),(DEST-PORT,1-443),(IN-PORT,0-80))'
        native = 'AND,((SRC-PORT,81-65535),(DST-PORT,1-443),(IN-PORT,0-80))'
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'source.list').write_text(source, encoding='utf-8')
                    configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source.list'], 'whitelist': []},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertNotIn('invalid ', diagnostic.getvalue())
                    for group in ('source', 'child'):
                        self.assertEqual(outputs[root / group / 'fin.txt'], f'# {group} rules: 1\n' + surge + '\n')
                        self.assertEqual(outputs[root / group / 'fin.yaml'],
                                         f'# {group} rules: 1\npayload:\n  - ' + json.dumps(native) + '\n')
                        self.assertEqual(outputs[root / group / 'fin-qx.txt'], f'# {group} rules: 0\n')
                        self.assertEqual(outputs[root / group / 'fin-surge-ds.txt'], f'# {group} rules: 0\n')
                    publish(outputs, root=root)
                    published = {path: path.read_bytes() for path in outputs}
                    self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                    self.assertEqual((root / 'source.list').read_text(encoding='utf-8'), source)
                    (root / 'source.list').unlink()
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                        clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                        disk = generate(root, lambda url: self.fail(url))
                    self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
