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
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


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


class NativeUnsignedPortAuditTests(unittest.TestCase):
    kinds = ('DEST-PORT', 'DST-PORT', 'SRC-PORT', 'IN-PORT')
    cases = (('443-80', '80-443'), ('[80-90]', '80-90'), ('/80//443/', '80/443'),
             ('80/ /443', '80/0/443'), ('65536', '0'), ('65537-65536', '0-1'),
             ('18446744073709551615', '65535'), ('000443', '443'), ('0000-80', '0-80'),
             ('80-80', '80'), ('0-65536', '0'), ('80-0', '0-80'), ('80 - 90', '80-90'),
             ('[ 80 ]-[ 90 ]', '80-90'), ('[[80]', '80'), ('80]]', '80'),
             ('65535-65537', '1-65535'), ('/ /', '0'), ('80/\t/443', '80/0/443'),
             ('80/ /443', '80/0/443'), ('80/ /443', '80/0/443'))

    @staticmethod
    def port_leaf(kind, canonical):
        if '/' not in canonical:
            return f'({kind},{canonical})'
        port_kind = 'DST-PORT' if kind == 'DEST-PORT' else kind
        return f"(OR,({','.join(f'({port_kind},{part})' for part in canonical.split('/'))}))"

    def test_native_reversed_range_keeps_neighbor_and_sorts_converted_endpoints(self):
        self.assertEqual(parse(native_text('DST-PORT,443-80', 'DOMAIN,neighbor.example.org'), purpose='proxy'),
                         ([Rule('DST-PORT', '80-443'),
                           Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')], []))

    def test_constructor_ranges_top_logical_quotes_and_order_use_the_same_unsigned_values(self):
        for kind in self.kinds:
            for raw, canonical in self.cases:
                leaf = self.port_leaf(kind, canonical)
                top = Rule(kind, canonical) if '/' not in canonical else Rule('OR', leaf[4:-1], native_fields=True)
                pairs = ((kind + ',' + raw, top),
                         (f'AND,(({kind},{raw}),(NETWORK,tcp))', Rule('AND', f'({leaf},(NETWORK,tcp))', native_fields=True)),
                         (f'OR,((NETWORK,tcp),({kind},{raw}))', Rule('OR', f'((NETWORK,tcp),{leaf})', native_fields=True)),
                         (f'NOT,(({kind},{raw}))', Rule('NOT', f'({leaf})', native_fields=True)),
                         (f'AND,((NOT,(({kind},{raw}))),(OR,((NETWORK,tcp),({kind},{raw}))))',
                          Rule('AND', f'((NOT,({leaf})),(OR,((NETWORK,tcp),{leaf})))', native_fields=True)))
                for matcher, wanted in pairs:
                    for purpose in ('block', 'direct', 'proxy'):
                        with self.subTest(kind=kind, raw=raw, matcher=matcher[:50], purpose=purpose):
                            self.assertEqual(parse(native_text(matcher, 'DOMAIN,neighbor.example.org'), purpose=purpose),
                                             ([wanted, Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')], []))
        for header in ('payload', 'rules'):
            for matcher, wanted in (('DST-PORT,[80-90]', Rule('DST-PORT', '80-90')),
                                    ('NOT,((SRC-PORT,65537-65536))', Rule('NOT', '((SRC-PORT,0-1))', native_fields=True))):
                for scalar in (matcher, "'" + matcher + "'", json.dumps(matcher)):
                    self.assertEqual(parse(header + ':\n  - ' + scalar, purpose='proxy'), ([wanted], []))

    def test_uint64_and_raw_segment_boundaries_keep_global_limits_and_empty_segments(self):
        limits = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        cases = (('0' * 5000 + '65537', '1'), ('0' * 5000 + '18446744073709551615', '65535'),
                 ('/' * 27 + '80', '80'), ('80' + '/' * 27, '80'),
                 ('/' * 13 + '80' + '/' * 14, '80'), ('/'.join(['80'] * 28), '/'.join(['80'] * 28)))
        for raw, canonical in cases:
            for kind in self.kinds:
                leaf = self.port_leaf(kind, canonical)
                wanted = Rule(kind, canonical) if '/' not in canonical else Rule('OR', leaf[4:-1], native_fields=True)
                self.assertEqual(parse(native_text(kind + ',' + raw), purpose='block'), ([wanted], []))
                self.assertEqual(parse(native_text(f'NOT,(({kind},{raw}))'), purpose='block'),
                                 ([Rule('NOT', f'({leaf})', native_fields=True)], []))
        for raw in ('/' * 28 + '80', '80' + '/' * 28, '/'.join(['80'] * 29),
                    '18446744073709551616', '9' * 5000, '0' * 5000 + '18446744073709551616'):
            parsed, messages = parse(native_text('DST-PORT,' + raw, 'DOMAIN,neighbor.example.org'), purpose='block')
            self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')])
            self.assertEqual(messages, ['line 2: invalid port ' + raw])
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_invalid_native_values_warn_and_never_keep_partial_logical_rules(self):
        invalid = ('', '*', '/', '//', '>80', '>=80', '<80', '<=80', '80/>90', '-1', '+443',
                   '1-2-3', '80-', '-80', '[ ]', '80\t-90', '80-\t90', '80 -90',
                   '80- 90', '0x50', '４４３', '\x1c80\x1c', '​80', '"443"', "'443'")
        for kind in self.kinds:
            for raw in invalid:
                for operator in ('top', 'AND', 'OR', 'NOT'):
                    expression = f'(({kind},{raw}))' if operator == 'NOT' else f'(({kind},{raw}),(NETWORK,tcp))'
                    matcher = kind + ',' + raw if operator == 'top' else operator + ',' + expression
                    with self.subTest(kind=kind, raw=raw, operator=operator):
                        self.assertEqual(parse(native_text(matcher, 'DOMAIN,neighbor.example.org'), purpose='proxy'),
                                         ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')],
                                          ['line 2: invalid port ' + raw if operator == 'top' else
                                           'line 2: invalid logical expression ' + expression]))
        self.assertEqual(parse(native_text('DST-PORT,\t443 '), purpose='proxy'), ([Rule('DST-PORT', '443')], []))

    def test_native_params_are_not_ports_and_ordinary_ranges_remain_strict(self):
        for kind in self.kinds:
            for params in ('443', '443,src,no-resolve,anything', 'src', 'no-resolve'):
                self.assertEqual(parse(native_text(f'{kind},80,{params}'), purpose='proxy'), ([Rule(kind, '80')], []))
                self.assertEqual(parse(native_text(f'AND,(({kind},80,{params}),(NETWORK,tcp))'), purpose='proxy'),
                                 ([Rule('AND', f'(({kind},80),(NETWORK,tcp))', native_fields=True)], []))
            for raw in ('65536', '65537-65536', '443-80', '[80-90]', '/80//443/', '80/ /443', '80-0'):
                parsed, messages = parse(f'{kind},"{raw}"\nDOMAIN,neighbor.example.org', purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                self.assertEqual(messages, ['line 1: invalid port ' + raw])
            for raw, canonical in (('>80', '81-65535'), ('<=443', '1-443'), ('000443', '000443')):
                self.assertEqual(parse(f'NOT,(({kind},"{raw}"))', purpose='proxy'),
                                 ([Rule('NOT', f'(({kind},{canonical}))')], []))
            ordinary = 'DST-PORT' if kind == 'DEST-PORT' else kind
            self.assertEqual(parse(f'{kind},80,443,PROXY', purpose='proxy'),
                             ([Rule('OR', f'(({ordinary},80),({ordinary},443))')], []))
        for kind, raw in (('UID', '4294967296-4294967298'), ('UID', '18446744073709551615'),
                          ('DSCP', '256-319'), ('DSCP', '/'), ('DSCP', '*'), ('DSCP', '80/ /443')):
            if raw == '80/ /443':
                self.assertEqual(parse(native_text(kind + ',' + raw), purpose='proxy'),
                                 ([], ['line 2: invalid DSCP ' + raw]))
            else:
                self.assertEqual(parse(native_text(kind + ',' + raw), purpose='proxy'), ([Rule(kind, raw)], []))
        for kind in ('UID', 'DSCP'):
            self.assertEqual(parse(native_text(kind + ',0/1/8-1'), purpose='proxy'), ([Rule(kind, '0/1/8-1')], []))
            self.assertEqual(parse(native_text(kind + ',' + '/'.join(['0'] * 29)), purpose='proxy')[0], [])

    def test_native_ports_preserve_sibling_source_identity_no_resolve_and_white_roles(self):
        raw = ('((DST-PORT,65536),(SRC-PORT,443-80),(IN-PORT,80/ /443),'
               '(DOMAIN,ADS.EXAMPLE.ORG.),(DOMAIN-WILDCARD,[ab]),(IP-ASN,00),'
               '(PROCESS-NAME,"Game"),(IP-CIDR,192.0.2.7/24),(IP-CIDR,198.51.100.7/24,no-resolve),'
               '(IP-CIDR,203.0.113.7/24,src,no-resolve))')
        canonical = ('((DST-PORT,0),(SRC-PORT,80-443),(OR,((IN-PORT,80),(IN-PORT,0),(IN-PORT,443))),'
                     '(DOMAIN,ADS.EXAMPLE.ORG.),(DOMAIN-WILDCARD,[ab]),(IP-ASN,00),'
                     '(PROCESS-NAME,"Game"),(IP-CIDR,192.0.2.0/24),(IP-CIDR,198.51.100.0/24,no-resolve),'
                     '(SRC-IP-CIDR,203.0.113.0/24))')
        wanted = Rule('AND', canonical, literal_process=True, native_fields=True, domain_source='mihomo')
        parsed, messages = parse(native_text('AND,' + raw), purpose='proxy')
        self.assertEqual((parsed, messages), ([wanted], ['line 2: unsupported no-resolve for SRC-IP-CIDR']))
        self.assertEqual(normalize(parsed * 2), [wanted])
        self.assertEqual(exclude_covered(iter(parsed), iter([Rule('DOMAIN', 'ADS.EXAMPLE.ORG.', domain_source='mihomo')])), parsed)
        for mode in ('add', 'strip', 'keep'):
            emitted = canonical
            if mode == 'add':
                emitted = emitted.replace('(IP-ASN,00)', '(IP-ASN,00,no-resolve)').replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)')
            elif mode == 'strip':
                emitted = emitted.replace(',no-resolve', '')
            outputs, _ = render('native-ports', iter(parsed), purpose='proxy', no_resolve=mode)
            self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                             ([Rule('AND', emitted, literal_process=True, native_fields=True, domain_source='mihomo')], []))
        self.assertEqual(parse_whitelist(native_text('DST-PORT,65536', 'NOT,((SRC-PORT,443-80))')), [])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertEqual(parse_whitelist(native_text('DST-PORT,>80', 'DOMAIN,neighbor.example.org')),
                             [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')])
        self.assertEqual([str(item.message) for item in caught], ['line 2: invalid port >80'])
        allowed = Rule('OR', '((DST-PORT,0),(DST-PORT,443))', allow=True, native_fields=True)
        for mode in ('add', 'strip', 'keep'):
            outputs, skipped = render('allow', [allowed], purpose='block', no_resolve=mode)
            self.assertEqual(outputs['fin.yaml'], '# allow rules: 0\npayload:\n')
            self.assertEqual(skipped, {name + ':OR': 1 for name in FILES})

    def test_deep_native_port_logic_keeps_eight_second_timeout_and_global_limits(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
for depth in (600, 1000):
    matcher, canonical = 'SRC-PORT,65537-65536', 'SRC-PORT,0-1'
    for _ in range(depth):
        matcher, canonical = 'NOT,((' + matcher + '))', 'NOT,((' + canonical + '))'
    source = 'payload:\\n  - ' + json.dumps(matcher)
    parsed, messages = parse(source, purpose='proxy')
    assert (parsed, messages) == ([Rule('NOT', canonical[4:], native_fields=True)], [])
    outputs, skips = render('deep-port', parsed, purpose='proxy', no_resolve='add')
    assert 'fin.yaml:NOT' not in skips
    assert parse(outputs['fin.yaml'], purpose='proxy') == (parsed, [])
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generate_native_ports_six_outputs_same_round_disk_and_generated_white(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for remote in (False, True):
                    with self.subTest(purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        initial = '' if mode == 'add' else ',no-resolve'
                        flag = '' if mode == 'strip' else ',no-resolve'
                        source = native_text('DST-PORT,65536', 'SRC-PORT,443-80', 'IN-PORT,[80-90]',
                                             'DST-PORT,/80//443/', 'NOT,((DST-PORT,65537-65536))',
                                             'AND,((SRC-PORT,80/ /443),(NETWORK,tcp),'
                                             f'(IP-CIDR,192.0.2.7/24{initial}),(SRC-IP-CIDR,198.51.100.7/24))',
                                             'OR,((IN-PORT,18446744073709551615),(DST-PORT,80,443))',
                                             'DOMAIN,covered.example.org', 'DOMAIN,neighbor.example.org',
                                             'DST-PORT,>80') + '@@||allow.example.org^\n'
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
                        responses = {'https://example.com/white': white.encode('utf-8'),
                                     'https://example.com/source': source.encode('utf-8')}
                        calls = []

                        def fetch(url):
                            calls.append(url)
                            return responses[url]

                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                            outputs = generate(root, fetch)
                        self.assertEqual(calls, ['https://example.com/white', 'https://example.com/source'] if remote else [])
                        self.assertIn('invalid port >80', diagnostic.getvalue())
                        self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                        self.assertNotIn('frozen', diagnostic.getvalue())
                        self.assertEqual(list(outputs), [root / group / name for group in ('white', 'source', 'child') for name in FILES])
                        conjunction = ('((OR,((SRC-PORT,80),(SRC-PORT,0),(SRC-PORT,443))),(NETWORK,tcp),'
                                       f'(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))')
                        yaml_body = ['AND,' + conjunction, 'DOMAIN,neighbor.example.org', 'DST-PORT,0', 'IN-PORT,80-90',
                                     'NOT,((DST-PORT,0-1))', 'OR,((DST-PORT,80),(DST-PORT,443))',
                                     'OR,((IN-PORT,65535),(DST-PORT,80))', 'SRC-PORT,80-443']
                        surge_body = ['AND,' + conjunction.replace('NETWORK,tcp', 'PROTOCOL,TCP').replace('SRC-IP-CIDR,', 'SRC-IP,'),
                                      'DEST-PORT,0', 'DOMAIN,neighbor.example.org', 'IN-PORT,80-90',
                                      'NOT,((DEST-PORT,0-1))', 'OR,((DEST-PORT,80),(DEST-PORT,443))',
                                      'OR,((IN-PORT,65535),(DEST-PORT,80))', 'SRC-PORT,80-443']
                        for group in ('source', 'child'):
                            dns_body = ((['@@||allow.example.org^'] if group == 'source' else []) +
                                        ['@@|covered.example.org|', '0.0.0.0 neighbor.example.org']) if purpose == 'block' else []
                            expected = {'fin.yaml': f'# {group} rules: 8\npayload:\n' + ''.join('  - ' + json.dumps(line) + '\n' for line in yaml_body),
                                        'fin.txt': f'# {group} rules: 8\n' + '\n'.join(surge_body) + '\n',
                                        'fin-qx.txt': f'# {group} rules: 1\nHOST,neighbor.example.org,LIST\n',
                                        'fin-surge.txt': f'# {group} rules: 7\n' + '\n'.join(line for line in surge_body if not line.startswith('DOMAIN,')) + '\n',
                                        'fin-surge-ds.txt': f'# {group} rules: 1\nneighbor.example.org\n',
                                        'fin-adb.txt': '[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                                       '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n' +
                                                       '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
                                                       f'! Total count: {len(dns_body)}\n' +
                                                       (''.join(line + '\n' for line in dns_body) if purpose == 'block' else
                                                        '! No AdBlock rules for non-advertising group.\n')}
                            self.assertEqual({name: outputs[root / group / name] for name in FILES}, expected)
                            restored, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                            self.assertEqual(messages, [])
                            self.assertEqual([rule.kind + ',' + rule.value for rule in restored], yaml_body)
                            self.assertEqual([line for line in diagnostic.getvalue().splitlines() if line.startswith(group + ' fin.yaml:')],
                                             ['source fin.yaml:DOMAIN-SUFFIX: 1'] if group == 'source' else [])
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

    def test_invalid_native_port_sources_and_white_preserve_freeze_and_path_boundaries(self):
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = native_text('DST-PORT,65536', 'DOMAIN,neighbor.example.org')
                invalid = native_text('NOT,((SRC-PORT,>80))')
                (root / 'static').mkdir()
                (root / 'input.list').write_text(source, encoding='utf-8')
                (root / 'static/white.list').write_text(invalid, encoding='utf-8')
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
                    outputs = generate(root, lambda url: invalid.encode('utf-8'))
                self.assertIn('invalid whitelist', diagnostic.getvalue())
                self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose=purpose),
                                 ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'), Rule('DST-PORT', '0')], []))
                for path, message in ((root / 'static/white.list', 'Output path targets static'),
                                      (root / '../escape.list', 'Output path escapes root')):
                    with self.assertRaisesRegex(ValueError, message):
                        publish({path: outputs[root / 'source/fin.yaml']}, root=root)
                self.assertEqual((root / 'static/white.list').read_text(encoding='utf-8'), invalid)
                configs[0]['sources'], configs[0]['whitelist'] = ['https://example.com/invalid-source'], []
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, lambda url: invalid.encode('utf-8')), {})
                self.assertIn('no adaptable rules; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                configs[0]['sources'] = ['https://example.com/missing']
                (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')

                def unavailable(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, unavailable), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                with self.assertRaisesRegex(RuntimeError, 'unexpected fetch failure'):
                    generate(root, lambda url: (_ for _ in ()).throw(RuntimeError('unexpected fetch failure')))
                self.assertEqual({path: path.read_bytes() for path in old}, old)


class IPv6ScopeAuditTests(unittest.TestCase):
    def test_direct_scope_checks_reach_leaves_after_invalid_siblings(self):
        for native in (False, True):
            for sibling in ('(DST-PORT,invalid)', '(DOMAIN,bad..example)', '(DOMAIN,valid.example.org,no-resolve)'):
                for kind in ('IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP', 'IP-SUFFIX', 'SRC-IP-SUFFIX'):
                    value = 'fe80::1%eth0' if kind == 'SRC-IP' else 'fe80::1%eth0/64'
                    for allow in (False, True):
                        rule = Rule('AND', f'({sibling},({kind},{value}))', allow=allow, native_fields=native)
                        for operation in (lambda: normalize([rule]), lambda: exclude_covered([rule], []),
                                          lambda: exclude_covered([], [rule])):
                            with self.subTest(native=native, sibling=sibling, kind=kind, allow=allow), self.assertRaisesRegex(ValueError, 'scope'):
                                operation()
            for expression in ('((DST-PORT,invalid),(DOMAIN-KEYWORD,%eth0),(IP-CIDR6,fe80::/64))',
                               '((DOMAIN,bad..example),(IP-CIDR6,fe80::/64,ignored%literal))'):
                rule = Rule('AND', expression, native_fields=native)
                self.assertEqual(normalize([rule]), [rule])
                self.assertEqual(exclude_covered([rule], []), [rule])

    def test_scoped_local_white_errors_and_unavailable_scoped_sources_preserve_old_products(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    source = 'IP-CIDR6,fe80::/64\nDOMAIN,neighbor.example.org\n'
                    invalid = native_text('IP-CIDR6,fe80::1%eth0/64', 'NOT,((SRC-IP,fe80::1%eth1))')
                    (root / 'static/source.list').write_text(source, encoding='utf-8')
                    (root / 'static/white.list').write_text(invalid, encoding='utf-8')
                    inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                    configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['static/source.list'], 'whitelist': ['static/white.list']},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('source', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            path.write_bytes(b'old product\x00\xff\r\n')
                            old[path] = path.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist .*line 2: invalid CIDR'):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    configs[0]['whitelist'] = ['https://example.com/invalid-white']
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        outputs = generate(root, lambda url: invalid.encode('utf-8'))
                    self.assertIn('invalid whitelist', diagnostic.getvalue())
                    expected = [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'),
                                Rule('IP-CIDR6', 'fe80::/64', () if mode != 'add' else ('no-resolve',))]
                    self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose=purpose), (expected, []))
                    for path, message in ((root / 'static/white.list', 'Output path targets static'),
                                          (root / '../escape.list', 'Output path escapes root')):
                        with self.assertRaisesRegex(ValueError, message):
                            publish({path: outputs[root / 'source/fin.yaml']}, root=root)
                    configs[0]['sources'], configs[0]['whitelist'] = ['https://example.com/invalid-source'], []
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, lambda url: invalid.encode('utf-8')), {})
                    self.assertIn('no adaptable rules; skipped', diagnostic.getvalue())
                    configs[0]['sources'] = ['https://example.com/missing']
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')

                    def unavailable(url):
                        raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, unavailable), {})
                    self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                    with self.assertRaisesRegex(RuntimeError, 'unexpected fetch failure'):
                        generate(root, lambda url: (_ for _ in ()).throw(RuntimeError('unexpected fetch failure')))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_cidr_scope_is_rejected_before_host_bits_remove_zone(self):
        self.assertEqual(parse('# source\nIP-CIDR6,fe80::1%eth0/64\nDOMAIN,neighbor.example.org',
                               purpose='block'),
                         ([Rule('DOMAIN', 'neighbor.example.org')],
                          ['line 2: invalid CIDR fe80::1%eth0/64']))

    def test_bare_source_and_logical_scope_inputs_warn_without_removing_neighbors(self):
        cases = (('fe80::1%eth0/64', 'invalid rule'),
                 ('fe80::%eth0/64', 'invalid rule'),
                 ('SRC-IP,fe80::1%eth0', 'invalid IP address fe80::1%eth0'),
                 ('NOT,((SRC-IP,fe80::1%eth0))', 'invalid logical expression ((SRC-IP,fe80::1%eth0))'),
                 ('AND,((IP-CIDR6,fe80::1%eth0/64),(NETWORK,tcp))',
                  'invalid logical expression ((IP-CIDR6,fe80::1%eth0/64),(NETWORK,tcp))'))
        for matcher, warning in cases:
            with self.subTest(matcher=matcher):
                self.assertEqual(parse('# source\n' + matcher + '\nDOMAIN,neighbor.example.org', purpose='proxy'),
                                 ([Rule('DOMAIN', 'neighbor.example.org')], ['line 2: ' + warning]))

    def test_direct_normalize_rejects_scoped_rules_before_collapse(self):
        for kind in ('IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP', 'IP-SUFFIX', 'SRC-IP-SUFFIX'):
            for value in ('fe80::%eth0/64', 'fe80::1%eth0/64', 'fe80::1%eth0'):
                for allow in (False, True):
                    with self.subTest(kind=kind, value=value, allow=allow), self.assertRaisesRegex(ValueError, 'scope'):
                        normalize(iter([Rule(kind, value, allow=allow)]))
        for kind, values in (('SRC-IP-CIDR', ('fe80::%eth0/64', 'fe80::%eth1/64')),
                             ('IP-CIDR6', ('2001:db8::%eth0/32', '2001:db8::%eth1/32'))):
            with self.subTest(kind=kind, pair=True), self.assertRaisesRegex(ValueError, 'scope'):
                normalize(Rule(kind, value) for value in values)

    def test_direct_exclude_rejects_scoped_white_and_rules_even_without_matching_networks(self):
        for kind, value in (('IP-CIDR', 'fe80::1%eth0/64'), ('IP-CIDR6', 'fe80::%eth0/64'),
                            ('SRC-IP-CIDR', 'fe80::1%eth0/64'), ('SRC-IP', 'fe80::1%eth0'),
                            ('IP-SUFFIX', 'fe80::1%eth0/64'), ('SRC-IP-SUFFIX', 'fe80::1%eth0/64')):
            ordinary = Rule(kind, value.replace('%eth0', ''))
            for allow in (False, True):
                scoped = Rule(kind, value, allow=allow)
                for source, white in (([ordinary], [scoped]), ([scoped], []), ([scoped], [ordinary])):
                    with self.subTest(kind=kind, allow=allow, white=bool(white)), self.assertRaisesRegex(ValueError, 'scope'):
                        exclude_covered(iter(source), iter(white))

    def test_direct_logical_scope_inputs_raise_in_normalize_and_exclude(self):
        for native in (False, True):
            for kind in ('IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP', 'IP-SUFFIX', 'SRC-IP-SUFFIX'):
                value = 'fe80::1%eth0' if kind == 'SRC-IP' else 'fe80::1%eth0/64'
                leaf = f'({kind},{value})'
                for operator, expression in (('NOT', f'({leaf})'),
                                             ('AND', f'((NETWORK,tcp),{leaf})'),
                                             ('OR', f'((NOT,({leaf})),(DOMAIN,neighbor.example.org))')):
                    scoped = Rule(operator, expression, native_fields=native,
                                  domain_source='mihomo' if native else 'surge')
                    for operation in (lambda: normalize([scoped]),
                                      lambda: exclude_covered([scoped], []),
                                      lambda: exclude_covered([Rule('DOMAIN', 'neighbor.example.org')], [scoped])):
                        with self.subTest(native=native, kind=kind, operator=operator), self.assertRaisesRegex(ValueError, 'scope'):
                            operation()

    def test_scope_rejection_covers_native_quotes_aliases_directions_suffixes_and_physical_lines(self):
        values = ('fe80::%eth0/64', 'fe80::1%eth0/64', 'fe80::%eth1/64',
                  'fe80::1%1/128', '::ffff:192.0.2.1%eth0/128', 'fe80::1%/64')
        for native in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for kind in ('IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'SRC-IP-CIDR', 'SRC-IP', 'IP-SUFFIX', 'SRC-IP-SUFFIX'):
                    for value in values:
                        for quote in ('', "'", '"'):
                            matcher = kind + ',' + quote + value + quote
                            text = native_text(matcher, 'DOMAIN,neighbor.example.org') if native else '# source\n' + matcher + '\nDOMAIN,neighbor.example.org'
                            with self.subTest(native=native, purpose=purpose, kind=kind, value=value, quote=quote):
                                parsed, messages = parse('﻿' + text.replace('\n', '\r\n'), purpose=purpose)
                                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')])
                                self.assertEqual(len(messages), 1)
                                self.assertTrue(messages[0].startswith('line 2: invalid '), messages)
                                with self.assertRaisesRegex(ValueError, 'line 2: invalid'):
                                    parse_whitelist('﻿' + text.rsplit('\n', 2 if native else 1)[0])
                for kind in ('IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX'):
                    tail = ',src' if native else ',' + purpose.upper().replace('BLOCK', 'REJECT') + ',src'
                    matcher = kind + ',fe80::1%eth0/64' + tail
                    parsed, messages = parse(native_text(matcher) if native else matcher, purpose=purpose)
                    self.assertEqual(parsed, [])
                    self.assertEqual(messages, [f'line {2 if native else 1}: invalid ' +
                                                ('CIDR' if kind != 'IP-SUFFIX' else 'SRC-IP-SUFFIX') + ' fe80::1%eth0/64'])
        for value in ('fe80::1%eth0', 'fe80::1%eth1', 'fe80::1%', 'fe80::1%eth0%eth1'):
            for matcher in (value, 'SRC-IP,' + value, 'DST-IP,' + value):
                parsed, messages = parse(matcher + '\nDOMAIN,neighbor.example.org', purpose='proxy')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                self.assertTrue(messages[0].startswith('line 1:'))
        for kind in ('SRC-IP', 'IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'SRC-IP-SUFFIX'):
            value = '192.0.2.1%eth0' + ('' if kind == 'SRC-IP' else '/24')
            self.assertEqual(parse(kind + ',' + value, purpose='block')[0], [])
        self.assertEqual(parse('DST-IP,2001:db8::1', purpose='block'), ([], ['line 1: unknown type DST-IP']))

    def test_logical_scope_rejects_whole_expression_and_keeps_native_inner_literals(self):
        for native in (False, True):
            for kind in ('IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP', 'IP-SUFFIX', 'SRC-IP-SUFFIX'):
                value = 'fe80::1%eth0' if kind == 'SRC-IP' else 'fe80::1%eth0/64'
                for quote in ('', "'", '"'):
                    leaf = f'({kind},{quote}{value}{quote})'
                    for operator, expression in (('AND', f'((NETWORK,tcp),{leaf})'),
                                                 ('OR', f'({leaf},(DOMAIN,neighbor.example.org))'),
                                                 ('NOT', f'({leaf})'),
                                                 ('AND', f'((NOT,({leaf})),(OR,((DOMAIN,neighbor.example.org),(NETWORK,tcp))))')):
                        text = native_text(operator + ',' + expression, 'DOMAIN,neighbor.example.org') if native else operator + ',' + expression + '\nDOMAIN,neighbor.example.org'
                        for purpose in ('block', 'direct', 'proxy'):
                            with self.subTest(native=native, kind=kind, quote=quote, operator=operator, purpose=purpose):
                                self.assertEqual(parse(text, purpose=purpose),
                                                 ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')],
                                                  [f'line {2 if native else 1}: invalid logical expression ' + expression]))
        for native in (False, True):
            for matcher in ('NOT,((DOMAIN-REGEX,^literal%eth0$))',
                            'AND,((PROCESS-NAME,literal%eth0),(SRC-IP,2001:db8::1),(NETWORK,tcp))'):
                parsed, messages = parse(native_text(matcher) if native else matcher, purpose='proxy')
                self.assertEqual(messages, [])
                self.assertEqual(len(parsed), 1)
                self.assertEqual(normalize(iter(parsed)), parsed)
                self.assertEqual(exclude_covered(iter(parsed), iter([])), parsed)
        self.assertEqual(parse(native_text('NOT,((SRC-IP,"2001:db8::1"))'), purpose='proxy')[0], [])
        self.assertEqual(parse('NOT,((SRC-IP,"2001:db8::1"))', purpose='proxy'),
                         ([Rule('NOT', '((SRC-IP,"2001:db8::1"))')], []))

    def test_scoped_white_warns_or_raises_and_never_deletes_unscoped_addresses(self):
        for native in (False, True):
            for kind, value in (('IP-CIDR6', 'fe80::1%eth0/64'), ('SRC-IP-CIDR', 'fe80::%eth0/64'),
                                ('SRC-IP', 'fe80::1%eth0'), ('IP-SUFFIX', 'fe80::1%eth0/64'),
                                ('SRC-IP-SUFFIX', 'fe80::1%eth0/64')):
                matcher = kind + ',' + value
                text = native_text(matcher) if native else matcher
                with self.subTest(native=native, kind=kind), self.assertRaisesRegex(ValueError, 'line '):
                    parse_whitelist(text)
                neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    white = parse_whitelist(text + ('  - "DOMAIN,neighbor.example.org"\n' if native else '\nDOMAIN,neighbor.example.org'))
                self.assertEqual(white, [neighbor])
                self.assertEqual(len(caught), 1)
                self.assertTrue(str(caught[0].message).startswith(f'line {2 if native else 1}: invalid '))
                source = [Rule('IP-CIDR6', 'fe80::/64'), Rule('SRC-IP-CIDR', 'fe80::/64'),
                          Rule('SRC-IP', 'fe80::1'), Rule('IP-SUFFIX', 'fe80::1/64'),
                          Rule('SRC-IP-SUFFIX', 'fe80::1/64'), neighbor]
                self.assertEqual(exclude_covered(iter(source), iter(white)), source[:-1])

    def test_unscoped_collapse_keeps_family_direction_options_allow_and_provenance(self):
        cases = ((('192.0.2.0/25', '192.0.2.128/25'), '192.0.2.0/24', 'IP-CIDR'),
                 (('fe80::/64', 'fe80:0:0:1::/64'), 'fe80::/63', 'IP-CIDR6'),
                 (('2001:db8::/33', '2001:db8:8000::/33'), '2001:db8::/32', 'IP-CIDR6'))
        for values, collapsed, destination in cases:
            for kind in (destination, 'SRC-IP-CIDR'):
                for source in ('surge', 'qx', 'mihomo'):
                    for options in ((), ('no-resolve',)):
                        for allow in (False, True):
                            raw = [Rule(kind, value, options, allow=allow, domain_source=source) for value in values]
                            wanted = [Rule(kind, collapsed, options, allow=allow, domain_source=source)]
                            self.assertEqual(normalize(iter(raw * 2)), wanted)
                            separated = [Rule(kind, values[0], options, allow=allow, domain_source=source),
                                         Rule(kind, values[1], options, allow=not allow, domain_source=source)]
                            self.assertEqual(set(normalize(separated)), set(separated))
                            options_split = [raw[0], Rule(kind, values[1], ('force-cellular',), allow=allow, domain_source=source)]
                            self.assertEqual(set(normalize(options_split)), set(options_split))
            directions = [Rule(destination, values[0]), Rule('SRC-IP-CIDR', values[1])]
            self.assertEqual(set(normalize(directions)), set(directions))
            provenance = [Rule(destination, values[0], domain_source='surge'), Rule(destination, values[1], domain_source='mihomo')]
            self.assertEqual(set(normalize(provenance)), set(provenance))
        values = [Rule('SRC-IP', 'fe80::1'), Rule('IP-SUFFIX', '2001:db8::7/64'), Rule('SRC-IP-SUFFIX', '192.0.2.7/24')]
        self.assertEqual(set(normalize(values)), set(values))
        self.assertEqual(exclude_covered([Rule('IP-CIDR6', 'fe80::/64'), Rule('SRC-IP-CIDR', 'fe80::/64')],
                                         parse_whitelist('SRC-IP-CIDR,fe80::/63')),
                         [Rule('IP-CIDR6', 'fe80::/64')])

    def test_deep_scope_inputs_keep_eight_second_timeout_and_global_limits(self):
        code = '''import json
import sys
from rules import Rule, exclude_covered, normalize, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
for depth in (600, 1000):
    valid, scoped = 'SRC-IP,2001:db8::1', 'SRC-IP,fe80::1%eth0'
    for _ in range(depth):
        valid, scoped = 'NOT,((' + valid + '))', 'NOT,((' + scoped + '))'
    for native in (False, True):
        text = 'payload:\\n  - ' + json.dumps(scoped) if native else scoped
        parsed, messages = parse(text, purpose='proxy')
        assert parsed == [] and len(messages) == 1 and 'invalid logical expression' in messages[0]
        raw = Rule('NOT', scoped[4:], native_fields=native)
        for operation in (lambda: normalize([raw]), lambda: exclude_covered([raw], [])):
            try:
                operation()
            except ValueError as exc:
                assert 'scope' in str(exc)
            else:
                raise AssertionError('scoped logical Rule accepted')
        text = 'payload:\\n  - ' + json.dumps(valid) if native else valid
        parsed, messages = parse(text, purpose='proxy')
        assert (parsed, messages) == ([Rule('NOT', valid[4:], native_fields=native)], [])
        assert normalize(parsed) == parsed and exclude_covered(parsed, []) == parsed
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generate_scope_rejection_six_products_publish_and_same_round_disk_dependencies(self):
        for native in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    for remote in (False, True):
                        with self.subTest(native=native, purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            initial = '' if mode == 'add' else ',no-resolve'
                            flag = '' if mode == 'strip' else ',no-resolve'
                            matchers = ('IP-CIDR6,fe80::1%eth0/64', 'IP-CIDR6,fe80::%eth1/64',
                                        'NOT,((SRC-IP,fe80::1%eth0))', 'IP-CIDR6,fe80::/64' + initial,
                                        'IP-CIDR6,fe80:0:0:1::/64' + initial, 'IP-CIDR,192.0.2.7/25' + initial,
                                        'IP-CIDR,192.0.2.129/25' + initial, 'SRC-IP-CIDR,2001:db8::7/33',
                                        'SRC-IP-CIDR,2001:db8:8000::7/33', 'IP-SUFFIX,2001:db8::7/64' + initial,
                                        'SRC-IP-SUFFIX,192.0.2.7/24',
                                        'AND,((SRC-IP,2001:db8::1),(IP-CIDR6,2001:db8:abcd::7/48' + initial + '))',
                                        'DOMAIN,covered.example.org', 'DOMAIN,neighbor.example.org')
                            source = (native_text(*matchers) if native else '\n'.join(matchers) + '\n') + '@@||allow.example.org^\n'
                            white = 'IP-CIDR6,fe80::1%eth0/64\nDOMAIN,covered.example.org\n'
                            (root / 'static').mkdir()
                            (root / 'static/source.list').write_text(source, encoding='utf-8')
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/white' if remote else 'static/white.list'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'static/source.list'],
                                        'whitelist': ['white/fin.txt', 'https://example.com/white' if remote else 'static/white.list']},
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
                            responses = {'https://example.com/white': white.encode('utf-8'),
                                         'https://example.com/source': source.encode('utf-8')}
                            calls = []

                            def fetch(url):
                                calls.append(url)
                                return responses[url]

                            with warnings.catch_warnings(record=True) as caught, patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                warnings.simplefilter('always')
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, fetch)
                            self.assertEqual(calls, ['https://example.com/white', 'https://example.com/source'] if remote else [])
                            self.assertEqual([str(item.message) for item in caught], ['line 1: invalid CIDR fe80::1%eth0/64'])
                            self.assertIn('invalid CIDR fe80::1%eth0/64', diagnostic.getvalue())
                            self.assertIn('invalid CIDR fe80::%eth1/64', diagnostic.getvalue())
                            self.assertIn('invalid logical expression ((SRC-IP,fe80::1%eth0))', diagnostic.getvalue())
                            self.assertNotIn('invalid whitelist', diagnostic.getvalue())
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertEqual(list(outputs), [root / group / name for group in ('white', 'source', 'child') for name in FILES])
                            yaml_body = [f'AND,((SRC-IP-CIDR,2001:db8::1/128),(IP-CIDR6,2001:db8:abcd::/48{flag}))',
                                         'DOMAIN,neighbor.example.org', 'IP-CIDR,192.0.2.0/24' + flag,
                                         'SRC-IP-SUFFIX,192.0.2.7/24', 'IP-CIDR6,fe80::/63' + flag,
                                         'IP-SUFFIX,2001:db8::7/64' + flag, 'SRC-IP-CIDR,2001:db8::/32']
                            surge_body = [f'AND,((SRC-IP,2001:db8::1),(IP-CIDR6,2001:db8:abcd::/48{flag}))',
                                          'DOMAIN,neighbor.example.org', 'IP-CIDR,192.0.2.0/24' + flag,
                                          'IP-CIDR6,fe80::/63' + flag, 'SRC-IP,2001:db8::/32']
                            for group in ('source', 'child'):
                                current_surge = surge_body if group == 'source' else [surge_body[0].replace('2001:db8::1)', '2001:db8::1/128)'), *surge_body[1:]]
                                dns_body = ((['@@||allow.example.org^'] if group == 'source' else []) +
                                            ['@@|covered.example.org|', '0.0.0.0 neighbor.example.org']) if purpose == 'block' else []
                                expected = {'fin.yaml': f'# {group} rules: 7\npayload:\n' + ''.join('  - ' + json.dumps(line) + '\n' for line in yaml_body),
                                            'fin.txt': f'# {group} rules: 5\n' + '\n'.join(current_surge) + '\n',
                                            'fin-qx.txt': f'# {group} rules: 3\nHOST,neighbor.example.org,LIST\n' +
                                                          'IP-CIDR,192.0.2.0/24,LIST' + flag + '\nIP6-CIDR,fe80::/63,LIST' + flag + '\n',
                                            'fin-surge.txt': f'# {group} rules: 4\n' + '\n'.join(line for line in current_surge if not line.startswith('DOMAIN,')) + '\n',
                                            'fin-surge-ds.txt': f'# {group} rules: 1\nneighbor.example.org\n',
                                            'fin-adb.txt': '[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                                           '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n' +
                                                           '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
                                                           f'! Total count: {len(dns_body)}\n' +
                                                           (''.join(line + '\n' for line in dns_body) if purpose == 'block' else
                                                            '! No AdBlock rules for non-advertising group.\n')}
                                self.assertEqual({name: outputs[root / group / name] for name in FILES}, expected)
                                restored, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(messages, [])
                                self.assertEqual([rule.kind + ',' + rule.value + (',' + ','.join(rule.options) if rule.options else '')
                                                  for rule in restored], yaml_body)
                                self.assertNotIn('%', ''.join(outputs[root / group / name] for name in FILES))
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


class IPSuffixPrefixAuditTests(unittest.TestCase):
    def test_direct_normalize_reaches_lowercase_nested_logical_suffix(self):
        raw = Rule('AND', '((not,((IP-SUFFIX,192.0.2.7/024))),(NETWORK,tcp))')
        canonical = Rule('AND', '((NOT,((IP-SUFFIX,192.0.2.7/24))),(NETWORK,tcp))')
        self.assertEqual(normalize(iter([raw, canonical])), [canonical])

    def test_nested_logical_case_suffix_normalizes_and_deduplicates_with_fields_and_literal_neighbor(self):
        for operator, body in (('NOT', '(({leaf}))'), ('AND', '(({leaf}),(NETWORK,tcp))'),
                               ('OR', '(({leaf}),(NETWORK,tcp))')):
            for spelling in (operator, operator.lower(), operator.title()):
                for kind in ('IP-SUFFIX', 'SRC-IP-SUFFIX'):
                    for raw_value, value in (('192.0.2.7/024', '192.0.2.7/24'),
                                             ('2001:DB8::7/064', '2001:db8::7/64')):
                        literal = '(PROCESS-NAME,"IP-SUFFIX 192.0.2.7/024 not and or")'
                        raw_value = f'(({spelling},{body.format(leaf=kind + "," + raw_value)}),{literal})'
                        value = f'(({operator},{body.format(leaf=kind + "," + value)}),{literal})'
                        for native in (False, True):
                            for source in ('surge', 'qx', 'mihomo'):
                                for allow in (False, True):
                                    for options in ((), ('force-cellular',)):
                                        with self.subTest(operator=spelling, kind=kind, native=native, source=source,
                                                          allow=allow, options=options):
                                            raw = Rule('AND', raw_value, options, allow, True, native, source)
                                            canonical = Rule('AND', value, options, allow, True, native, source)
                                            self.assertEqual(normalize(iter([raw, canonical])), [canonical])
                                            self.assertEqual(raw.value, raw_value)
        literal = Rule('AND', '((not,((PROCESS-NAME,"IP-SUFFIX 192.0.2.7/033"))),(NETWORK,tcp))')
        self.assertEqual(normalize([literal]), [literal])

    def test_nested_logical_case_invalid_suffix_is_rejected_by_direct_normalize_and_parse(self):
        for operator, body in (('NOT', '(({leaf}))'), ('AND', '(({leaf}),(NETWORK,tcp))'),
                               ('OR', '(({leaf}),(NETWORK,tcp))')):
            for spelling in (operator, operator.lower(), operator.title()):
                for native in (False, True):
                    for kind in ('IP-SUFFIX', 'SRC-IP-SUFFIX'):
                        for value in ('192.0.2.7/033', '2001:db8::7/0129', '192.0.2.7/255.255.255.0',
                                      '192.0.2.7/+24', '192.0.2.7/', 'fe80::7%eth0/064'):
                            expression = f'(({spelling},{body.format(leaf=kind + "," + value)}),(NETWORK,tcp))'
                            with self.subTest(operator=spelling, native=native, kind=kind, value=value):
                                with self.assertRaises(ValueError):
                                    normalize([Rule('AND', expression, native_fields=native)])
                                text = native_text('AND,' + expression) if native else 'AND,' + expression
                                self.assertEqual(parse(text, purpose='proxy'),
                                                 ([], [f'line {2 if native else 1}: invalid logical expression ' + expression]))

    def test_nested_logical_case_suffix_is_canonical_in_six_published_files_and_reimport(self):
        raw = Rule('AND', '((not,((IP-SUFFIX,192.0.2.7/024))),(oR,((SRC-IP-SUFFIX,2001:DB8::7/064),(NETWORK,tcp))))')
        canonical = 'AND,((NOT,((IP-SUFFIX,192.0.2.7/24{flag}))),(OR,((SRC-IP-SUFFIX,2001:db8::7/64),(NETWORK,tcp))))'
        neighbor = Rule('DOMAIN', 'neighbor.example.org')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    emitted = canonical.format(flag=',no-resolve' if mode == 'add' else '')
                    with patch('formats.datetime') as clock:
                        clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                        outputs, skipped = render('suffix', normalize(iter([raw, neighbor])), purpose=purpose,
                                                  no_resolve=mode)
                    dns = ['0.0.0.0 neighbor.example.org'] if purpose == 'block' else []
                    expected = {'fin.yaml': '# suffix rules: 2\npayload:\n  - ' + json.dumps(emitted) + '\n  - "DOMAIN,neighbor.example.org"\n',
                                'fin.txt': '# suffix rules: 1\nDOMAIN,neighbor.example.org\n',
                                'fin-qx.txt': '# suffix rules: 1\nHOST,neighbor.example.org,LIST\n',
                                'fin-surge.txt': '# suffix rules: 0\n',
                                'fin-surge-ds.txt': '# suffix rules: 1\nneighbor.example.org\n',
                                'fin-adb.txt': '[Adblock Plus 2.0]\n! Title: suffix\n' +
                                               '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n' +
                                               '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
                                               f'! Total count: {len(dns)}\n' +
                                               (''.join(line + '\n' for line in dns) if purpose == 'block' else
                                                '! No AdBlock rules for non-advertising group.\n')}
                    self.assertEqual(outputs, expected)
                    self.assertEqual({key: value for key, value in skipped.items() if key.endswith(':AND')},
                                     {name + ':AND': 1 for name in FILES if name != 'fin.yaml'})
                    paths = {root / 'suffix' / name: text for name, text in outputs.items()}
                    publish(paths, root=root)
                    self.assertEqual({path: path.read_bytes() for path in paths},
                                     {root / 'suffix' / name: text.encode('utf-8') for name, text in expected.items()})
                    parsed = [Rule('AND', emitted[4:], native_fields=True),
                              Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo')]
                    self.assertEqual(parse((root / 'suffix/fin.yaml').read_text(encoding='utf-8'), purpose=purpose),
                                     (parsed, []))

    def test_lowercase_deep_suffix_traversal_keeps_eight_second_timeout_and_global_limits(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, normalize, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
for depth in (600, 1000):
    raw = 'IP-SUFFIX,2001:DB8::7/064'
    canonical = 'IP-SUFFIX,2001:db8::7/64'
    invalid = 'IP-SUFFIX,192.0.2.7/033'
    for index in range(depth):
        operator = 'not' if index % 2 else 'nOt'
        raw = operator + ',((' + raw + '))'
        invalid = operator + ',((' + invalid + '))'
        canonical = 'NOT,((' + canonical + '))'
    for native in (False, True):
        wanted = Rule('NOT', canonical[4:], native_fields=native)
        assert normalize(iter([Rule('NOT', raw[4:], native_fields=native), wanted])) == [wanted]
        try:
            normalize([Rule('NOT', invalid[4:], native_fields=native)])
        except ValueError:
            pass
        else:
            raise AssertionError('invalid nested suffix accepted')
        source = 'payload:\\n  - ' + json.dumps(raw) if native else raw
        assert parse(source, purpose='proxy') == ([wanted], [])
        outputs, skipped = render('deep', [wanted], purpose='proxy', no_resolve='keep')
        assert outputs['fin.yaml'] == '# deep rules: 1\\npayload:\\n  - ' + json.dumps(canonical) + '\\n'
        assert 'fin.yaml:NOT' not in skipped
        assert parse(outputs['fin.yaml'], purpose='proxy') == ([Rule('NOT', canonical[4:], native_fields=True)], [])
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generate_suffix_white_six_outputs_and_same_round_disk_dependencies(self):
        for native in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    for remote in (False, True):
                        with self.subTest(native=native, purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            initial = '' if mode == 'add' else ',no-resolve'
                            flag = '' if mode == 'strip' else ',no-resolve'
                            logic = '((IP-SUFFIX,192.0.2.8/024' + initial + '),(SRC-IP-SUFFIX,2001:DB8::8/064),(NETWORK,tcp))'
                            matchers = ('IP-SUFFIX,192.0.2.7/24' + initial, 'SRC-IP-SUFFIX,2001:db8::7/64',
                                        'IP-SUFFIX,192.0.2.8/024' + initial, 'SRC-IP-SUFFIX,192.0.2.7/024',
                                        'IP-SUFFIX,2001:DB8::7/064' + initial, 'IP-CIDR,192.0.2.7/24' + initial,
                                        'AND,' + logic, 'DOMAIN,neighbor.example.org')
                            source = (native_text(*matchers) if native else '\n'.join(matchers) + '\n') + '@@||allow.example.org^\n'
                            white_matchers = ('IP-SUFFIX,192.0.2.7/024', 'SRC-IP-SUFFIX,2001:DB8::7/064')
                            white = native_text(*white_matchers) if native else '\n'.join(white_matchers)
                            (root / 'static').mkdir()
                            (root / 'static/source.list').write_text(source, encoding='utf-8')
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/white' if remote else 'static/white.list'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.com/source' if remote else 'static/source.list'],
                                        'whitelist': ['white/fin.yaml', 'https://example.com/white' if remote else 'static/white.list']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in FILES:
                                    path = root / group / name
                                    path.write_bytes(b'old product\x00\xff\r\n')
                                    old[path] = path.read_bytes()
                            responses = {'https://example.com/white': white.encode('utf-8'),
                                         'https://example.com/source': source.encode('utf-8')}
                            calls = []

                            def fetch(url):
                                calls.append(url)
                                return responses[url]

                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 2, tzinfo=timezone.utc)
                                outputs = generate(root, fetch)
                            self.assertEqual(calls, ['https://example.com/white', 'https://example.com/source'] if remote else [])
                            self.assertNotIn('invalid ', diagnostic.getvalue())
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertEqual(list(outputs), [root / group / name for group in ('white', 'source', 'child') for name in FILES])
                            self.assertEqual(outputs[root / 'white/fin.yaml'], '# white rules: 2\npayload:\n' +
                                             '  - "IP-SUFFIX,192.0.2.7/24' + (',no-resolve' if mode == 'add' else '') + '"\n' +
                                             '  - "SRC-IP-SUFFIX,2001:db8::7/64"\n')
                            yaml_body = ['AND,((IP-SUFFIX,192.0.2.8/24' + flag + '),(SRC-IP-SUFFIX,2001:db8::8/64),(NETWORK,tcp))',
                                         'DOMAIN,neighbor.example.org', 'IP-CIDR,192.0.2.0/24' + flag,
                                         'IP-SUFFIX,192.0.2.8/24' + flag, 'SRC-IP-SUFFIX,192.0.2.7/24',
                                         'IP-SUFFIX,2001:db8::7/64' + flag]
                            for group in ('source', 'child'):
                                dns_body = (['@@||allow.example.org^', '0.0.0.0 neighbor.example.org'] if group == 'source' else
                                            ['0.0.0.0 neighbor.example.org']) if purpose == 'block' else []
                                expected = {'fin.yaml': f'# {group} rules: 6\npayload:\n' + ''.join('  - ' + json.dumps(line) + '\n' for line in yaml_body),
                                            'fin.txt': f'# {group} rules: 2\nDOMAIN,neighbor.example.org\nIP-CIDR,192.0.2.0/24{flag}\n',
                                            'fin-qx.txt': f'# {group} rules: 2\nHOST,neighbor.example.org,LIST\nIP-CIDR,192.0.2.0/24,LIST{flag}\n',
                                            'fin-surge.txt': f'# {group} rules: 1\nIP-CIDR,192.0.2.0/24{flag}\n',
                                            'fin-surge-ds.txt': f'# {group} rules: 1\nneighbor.example.org\n',
                                            'fin-adb.txt': '[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
                                                           '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n' +
                                                           '! License: Inherits upstream licenses\n! Version: 202610020000\n' +
                                                           f'! Total count: {len(dns_body)}\n' +
                                                           (''.join(line + '\n' for line in dns_body) if purpose == 'block' else
                                                            '! No AdBlock rules for non-advertising group.\n')}
                                self.assertEqual({name: outputs[root / group / name] for name in FILES}, expected)
                                restored, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(messages, [])
                                self.assertEqual([rule.kind + ',' + rule.value + (',' + ','.join(rule.options) if rule.options else '')
                                                  for rule in restored], yaml_body)
                                self.assertEqual([line for line in diagnostic.getvalue().splitlines() if line.startswith(group + ' fin.yaml:')],
                                                 ['source fin.yaml:DOMAIN-SUFFIX: 1'] if group == 'source' else [])
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt', 'fin-adb.txt'):
                                    self.assertIn(f'{group} {name}:IP-SUFFIX: 2', diagnostic.getvalue())
                                    self.assertIn(f'{group} {name}:SRC-IP-SUFFIX: 1', diagnostic.getvalue())
                                    self.assertIn(f'{group} {name}:AND: 1', diagnostic.getvalue())
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

    def test_invalid_suffix_local_remote_white_and_unavailable_sources_keep_old_products(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = 'IP-SUFFIX,192.0.2.7/024\nDOMAIN,neighbor.example.org\n'
                    invalid = native_text('IP-SUFFIX,192.0.2.7/00033')
                    (root / 'static').mkdir()
                    (root / 'static/source.list').write_text(source, encoding='utf-8')
                    (root / 'static/white.list').write_text(invalid, encoding='utf-8')
                    inputs = {path: path.read_bytes() for path in (root / 'static/source.list', root / 'static/white.list')}
                    configs = [{'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['static/source.list'], 'whitelist': ['static/white.list']},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['source/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    old = {}
                    for group in ('source', 'child'):
                        (root / group).mkdir()
                        for name in FILES:
                            path = root / group / name
                            path.write_bytes(b'old product\x00\xff\r\n')
                            old[path] = path.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'Invalid whitelist .*line 2: invalid IP-SUFFIX'):
                        generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    configs[0]['whitelist'] = ['https://example.com/invalid-white']
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        outputs = generate(root, lambda url: invalid.encode('utf-8'))
                    self.assertIn('invalid whitelist', diagnostic.getvalue())
                    flag = ('no-resolve',) if mode == 'add' else ()
                    self.assertEqual(parse(outputs[root / 'source/fin.yaml'], purpose=purpose),
                                     ([Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo'), Rule('IP-SUFFIX', '192.0.2.7/24', flag)], []))
                    for path, message in ((root / 'static/white.list', 'Output path targets static'),
                                          (root / '../escape.list', 'Output path escapes root')):
                        with self.assertRaisesRegex(ValueError, message):
                            publish({path: outputs[root / 'source/fin.yaml']}, root=root)
                    configs[0]['sources'], configs[0]['whitelist'] = ['https://example.com/invalid-source'], []
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, lambda url: invalid.encode('utf-8')), {})
                    self.assertIn('no adaptable rules; skipped', diagnostic.getvalue())
                    configs[0]['sources'] = ['https://example.com/missing']
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')

                    def unavailable(url):
                        raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        self.assertEqual(generate(root, unavailable), {})
                    self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                    with self.assertRaisesRegex(RuntimeError, 'unexpected fetch failure'):
                        generate(root, lambda url: (_ for _ in ()).throw(RuntimeError('unexpected fetch failure')))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_ordinary_suffix_prefix_is_canonical_without_masking_host_bits(self):
        self.assertEqual(parse('IP-SUFFIX,192.0.2.7/024\nDOMAIN,neighbor.example.org', purpose='block'),
                         ([Rule('IP-SUFFIX', '192.0.2.7/24'), Rule('DOMAIN', 'neighbor.example.org')], []))

    def test_quoted_logical_suffix_uses_checked_value_and_preserves_child_order(self):
        self.assertEqual(parse('AND,((SRC-IP-SUFFIX,"192.0.2.7/00"),(IP-SUFFIX,2001:db8::7/064))',
                               purpose='proxy'),
                         ([Rule('AND', '((SRC-IP-SUFFIX,192.0.2.7/0),(IP-SUFFIX,2001:db8::7/64))')], []))

    def test_direct_normalize_canonicalizes_suffix_before_deduplication(self):
        raw = Rule('IP-SUFFIX', '192.0.2.7/024', ('no-resolve',), domain_source='qx')
        canonical = Rule('IP-SUFFIX', '192.0.2.7/24', ('no-resolve',), domain_source='qx')
        self.assertEqual(normalize(iter([raw, canonical])), [canonical])
        self.assertEqual(raw.value, '192.0.2.7/024')

    def test_direct_normalize_canonicalizes_logical_suffix_without_changing_literal_neighbor(self):
        raw = Rule('AND', '((IP-SUFFIX,2001:DB8::7/064),(PROCESS-NAME,"IP-SUFFIX 192.0.2.7/024"))',
                   ('force-cellular',), allow=True, literal_process=True, domain_source='qx')
        wanted = Rule('AND', '((IP-SUFFIX,2001:db8::7/64),(PROCESS-NAME,"IP-SUFFIX 192.0.2.7/024"))',
                      ('force-cellular',), allow=True, literal_process=True, domain_source='qx')
        self.assertEqual(normalize(iter([raw, wanted])), [wanted])
        literal = Rule('NOT', '((PROCESS-NAME,"IP-SUFFIX 192.0.2.7/024"))')
        self.assertEqual(normalize([literal]), [literal])

    def test_suffix_prefix_family_extremes_long_zeros_sources_and_quotes(self):
        cases = (('192.0.2.7/024', '192.0.2.7/24'), ('192.0.2.7/00', '192.0.2.7/0'),
                 ('192.0.2.7/032', '192.0.2.7/32'), ('2001:DB8:0:0:0:0:0:7/064', '2001:db8::7/64'),
                 ('2001:db8::7/000', '2001:db8::7/0'), ('2001:db8::7/0128', '2001:db8::7/128'),
                 ('192.0.2.7/' + '0' * 5000 + '24', '192.0.2.7/24'),
                 ('2001:db8::7/' + '0' * 5000 + '128', '2001:db8::7/128'),
                 ('192.0.2.7/' + '0' * 5000, '192.0.2.7/0'))
        before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
        for native in (False, True):
            for purpose, action in (('block', 'REJECT'), ('direct', 'DIRECT'), ('proxy', 'PROXY')):
                for kind in ('IP-SUFFIX', 'SRC-IP-SUFFIX'):
                    for raw, canonical in cases:
                        for quote in ('', "'", '"'):
                            matcher = kind + ',' + quote + raw + quote
                            text = native_text(matcher, 'DOMAIN,neighbor.example.org') if native else matcher + ',' + action + '\nDOMAIN,neighbor.example.org'
                            neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')
                            with self.subTest(native=native, purpose=purpose, kind=kind, raw=raw[:60], quote=quote):
                                parsed, messages = parse('﻿' + text.replace('\n', '\r\n'), purpose=purpose)
                                wanted = ([Rule(kind, canonical)] if not native or not quote else []) + [neighbor]
                                self.assertEqual(parsed, wanted)
                                self.assertEqual(messages, [f'line 2: invalid {kind} {quote}{raw}{quote}'] if native and quote else [])
                                self.assertEqual(normalize(iter(parsed)), sorted(wanted, key=lambda rule: (rule.kind, rule.value)))
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), before)

    def test_suffix_src_params_and_logical_fields_preserve_direction_flags_and_literals(self):
        for native in (False, True):
            for purpose, action in (('block', 'REJECT'), ('direct', 'DIRECT'), ('proxy', 'PROXY')):
                tail = ',src,no-resolve' if native else ',' + action + ',src,no-resolve'
                matcher = 'IP-SUFFIX,192.0.2.7/024' + tail
                self.assertEqual(parse(native_text(matcher) if native else matcher, purpose=purpose),
                                 ([Rule('SRC-IP-SUFFIX', '192.0.2.7/24')],
                                  [f'line {2 if native else 1}: unsupported no-resolve for SRC-IP-SUFFIX']))
                for quote in ('', "'", '"'):
                    value = quote + '192.0.2.7/024' + quote
                    expressions = (('AND', f'((IP-SUFFIX,{value},no-resolve),(SRC-IP-SUFFIX,2001:DB8::7/064),(NETWORK,tcp))',
                                    '((IP-SUFFIX,192.0.2.7/24{flag}),(SRC-IP-SUFFIX,2001:db8::7/64),(NETWORK,tcp))'),
                                   ('OR', f'((SRC-IP-SUFFIX,{value}),(IP-SUFFIX,2001:DB8::7/064))',
                                    '((SRC-IP-SUFFIX,192.0.2.7/24),(IP-SUFFIX,2001:db8::7/64{flag}))'),
                                   ('NOT', f'((IP-SUFFIX,{value},src,no-resolve))', '((SRC-IP-SUFFIX,192.0.2.7/24))'),
                                   ('AND', f'((NOT,((IP-SUFFIX,{value}))),(OR,((IP-SUFFIX,2001:DB8::7/064),(SRC-IP-SUFFIX,192.0.2.8/024))))',
                                    '((NOT,((IP-SUFFIX,192.0.2.7/24{flag}))),(OR,((IP-SUFFIX,2001:db8::7/64{flag}),(SRC-IP-SUFFIX,192.0.2.8/24))))'))
                    for operator, expression, canonical in expressions:
                        with self.subTest(native=native, purpose=purpose, quote=quote, operator=operator):
                            text = operator + ',' + expression
                            parsed, messages = parse(native_text(text) if native else text, purpose=purpose)
                            if native and quote:
                                self.assertEqual((parsed, messages), ([], ['line 2: invalid logical expression ' + expression]))
                                continue
                            initial = ',no-resolve' if operator == 'AND' and expression.startswith('((IP-SUFFIX,') else ''
                            self.assertEqual(parsed, [Rule(operator, canonical.format(flag=initial), native_fields=native)])
                            self.assertEqual(messages, [f'line {2 if native else 1}: unsupported no-resolve for SRC-IP-SUFFIX'] if operator == 'NOT' else [])
                            for mode in ('add', 'strip', 'keep'):
                                flag = ',no-resolve' if mode == 'add' or mode == 'keep' and initial else ''
                                emitted = operator + ',' + canonical.format(flag=flag)
                                outputs, skipped = render('suffix', normalize(iter(parsed)), purpose=purpose, no_resolve=mode)
                                self.assertEqual(outputs['fin.yaml'], '# suffix rules: 1\npayload:\n  - ' + json.dumps(emitted) + '\n')
                                self.assertNotIn('fin.yaml:' + operator, skipped)
                                self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose),
                                                 ([Rule(operator, canonical.format(flag=flag), native_fields=True)], []))
        self.assertEqual(parse(native_text('IP-SUFFIX,192.0.2.7/024,ignored,Src,NO-RESOLVE'), purpose='proxy'),
                         ([Rule('IP-SUFFIX', '192.0.2.7/24')], []))
        self.assertEqual(parse('IP-SUFFIX,192.0.2.7/024,src', purpose='proxy'),
                         ([], ['line 1: ambiguous src policy or option']))
        for matcher in ('DST-IP-SUFFIX,192.0.2.7/024', 'IP-SUFFIX6,2001:db8::7/064'):
            self.assertEqual(parse(matcher, purpose='block'), ([], ['line 1: unknown type ' + matcher.split(',')[0]]))

    def test_invalid_suffix_prefixes_warn_and_strict_white_rejects_without_losing_neighbor(self):
        values = ('192.0.2.7/255.255.255.0', '192.0.2.7/0.0.0.255', '192.0.2.7/',
                  '192.0.2.7/+24', '192.0.2.7/-1', '192.0.2.7/ 24', '192.0.2.7/24x',
                  '192.0.2.7/３２', '192.0.2.7/33', '192.0.2.7/00033', '2001:db8::7/129',
                  '2001:db8::7/00129', '192.0.2.7/24/0', '192.0.2.7', 'bad/24',
                  'fe80::7%eth0/064', '192.0.2.7%eth0/24', '192.0.2.7/' + '9' * 5000)
        for native in (False, True):
            for kind in ('IP-SUFFIX', 'SRC-IP-SUFFIX'):
                for value in values:
                    matcher = kind + ',' + value
                    text = native_text(matcher, 'DOMAIN,neighbor.example.org') if native else '# source\n' + matcher + '\nDOMAIN,neighbor.example.org'
                    neighbor = Rule('DOMAIN', 'neighbor.example.org', domain_source='mihomo' if native else 'surge')
                    with self.subTest(native=native, kind=kind, value=value[:60]):
                        self.assertEqual(parse(text, purpose='proxy'), ([neighbor], [f'line 2: invalid {kind} {value}']))
                        invalid_white = native_text(matcher) if native else '# source\n' + matcher
                        with self.assertRaisesRegex(ValueError, 'line 2: invalid ' + kind):
                            parse_whitelist(invalid_white)
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            self.assertEqual(parse_whitelist(text), [neighbor])
                        self.assertEqual([str(item.message) for item in caught], [f'line 2: invalid {kind} {value}'])
                        with self.assertRaises(ValueError):
                            normalize([Rule(kind, value)])
                        expression = f'((NETWORK,tcp),({kind},{value}))'
                        self.assertEqual(parse(native_text('AND,' + expression) if native else 'AND,' + expression,
                                               purpose='proxy'),
                                         ([], [f'line {2 if native else 1}: invalid logical expression ' + expression]))
                        with self.assertRaises(ValueError):
                            normalize([Rule('AND', expression, native_fields=native)])

    def test_normalize_suffix_keeps_host_bits_options_allow_sources_and_neighbor_types(self):
        for kind in ('IP-SUFFIX', 'SRC-IP-SUFFIX'):
            for source in ('surge', 'qx', 'mihomo'):
                for allow in (False, True):
                    for native in (False, True):
                        for options in ((), ('no-resolve',), ('force-cellular',)):
                            raw = Rule(kind, '2001:DB8::7/064', options, allow, True, native, source)
                            canonical = Rule(kind, '2001:db8::7/64', options, allow, True, native, source)
                            adjacent = Rule(kind, '2001:db8::8/64', options, allow, True, native, source)
                            self.assertEqual(normalize(iter([raw, canonical, adjacent])), [canonical, adjacent])
                            self.assertEqual(raw.value, '2001:DB8::7/064')
        rules = [Rule('IP-SUFFIX', '192.0.2.7/024'), Rule('SRC-IP-SUFFIX', '192.0.2.7/024'),
                 Rule('IP-CIDR', '192.0.2.7/24'), Rule('IP-ASN', '00'), Rule('UNKNOWN-TYPE', '192.0.2.7/024'),
                 Rule('DOMAIN-WILDCARD', '[ab].example.org', domain_source='mihomo')]
        self.assertEqual(set(normalize(iter(rules))),
                         {Rule('IP-SUFFIX', '192.0.2.7/24'), Rule('SRC-IP-SUFFIX', '192.0.2.7/24'),
                          Rule('IP-CIDR', '192.0.2.0/24'), *rules[3:]})
        for native in (False, True):
            rule = Rule('AND', '((src-ip-suffix,192.0.2.7/00),(IP-SUFFIX,2001:DB8::7/064),(NETWORK,tcp))',
                        native_fields=native, domain_source='mihomo')
            canonical = Rule('AND', '((SRC-IP-SUFFIX,192.0.2.7/0),(IP-SUFFIX,2001:db8::7/64),(NETWORK,tcp))',
                             native_fields=native, domain_source='mihomo')
            self.assertEqual(normalize(iter([rule, canonical])), [canonical])

    def test_suffix_normalization_preserves_native_asn_wildcard_root_dot_and_process_identity(self):
        raw = Rule('AND', '((IP-SUFFIX,192.0.2.7/024),(IP-ASN,00),(DOMAIN-WILDCARD,[ab]),'
                         '(DOMAIN,Native.Example.org.),(PROCESS-NAME,<Foo>))',
                   native_fields=True, literal_process=True, domain_source='mihomo')
        wanted = Rule('AND', '((IP-SUFFIX,192.0.2.7/24),(IP-ASN,00),(DOMAIN-WILDCARD,[ab]),'
                            '(DOMAIN,Native.Example.org.),(PROCESS-NAME,<Foo>))',
                      native_fields=True, literal_process=True, domain_source='mihomo')
        self.assertEqual(normalize(iter([raw, wanted])), [wanted])
        for mode in ('add', 'strip', 'keep'):
            emitted = (wanted.value.replace('192.0.2.7/24)', '192.0.2.7/24,no-resolve)').replace('(IP-ASN,00)', '(IP-ASN,00,no-resolve)')
                       if mode == 'add' else wanted.value)
            outputs, _ = render('suffix', normalize([raw]), purpose='proxy', no_resolve=mode)
            self.assertEqual(outputs['fin.yaml'], '# suffix rules: 1\npayload:\n  - ' + json.dumps('AND,' + emitted) + '\n')
            self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                             ([Rule('AND', emitted, native_fields=True, literal_process=True, domain_source='mihomo')], []))
        allowed = Rule('IP-SUFFIX', '192.0.2.7/024', allow=True)
        self.assertEqual(normalize([allowed]), [Rule('IP-SUFFIX', '192.0.2.7/24', allow=True)])

    def test_parsed_suffix_white_compares_canonical_identity_and_keeps_direction_host_bits(self):
        for native in (False, True):
            for white_native in (False, True):
                matchers = ('IP-SUFFIX,192.0.2.7/024,no-resolve', 'SRC-IP-SUFFIX,192.0.2.7/00',
                            'IP-SUFFIX,2001:DB8::7/064', 'IP-SUFFIX,192.0.2.8/024',
                            'SRC-IP-SUFFIX,192.0.2.7/024', 'IP-CIDR,192.0.2.7/24',
                            'AND,((IP-SUFFIX,192.0.2.7/024),(NETWORK,tcp))')
                source, messages = parse(native_text(*matchers) if native else '\n'.join(matchers), purpose='block')
                self.assertEqual(messages, [])
                white_matchers = ('IP-SUFFIX,192.0.2.7/24', 'SRC-IP-SUFFIX,192.0.2.7/000', 'IP-SUFFIX,2001:db8::7/64')
                white = parse_whitelist(native_text(*white_matchers) if white_native else '\n'.join(white_matchers))
                self.assertEqual(white, [Rule('IP-SUFFIX', '192.0.2.7/24'), Rule('SRC-IP-SUFFIX', '192.0.2.7/0'),
                                         Rule('IP-SUFFIX', '2001:db8::7/64')])
                self.assertEqual(exclude_covered(iter(source), iter(white)), source[3:])
                allowed = Rule('IP-SUFFIX', '192.0.2.7/24', allow=True)
                self.assertEqual(exclude_covered([allowed], white), [allowed])
                self.assertEqual(exclude_covered(source[:1], parse_whitelist('IP-CIDR,192.0.2.0/24')), source[:1])
                self.assertEqual(exclude_covered(source[5:6], white), source[5:6])

    def test_deep_suffix_normalize_and_reimport_keep_eight_second_timeout_and_global_limits(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, normalize, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
for depth in (600, 1000):
    raw = 'IP-SUFFIX,2001:DB8::7/064'
    canonical = 'IP-SUFFIX,2001:db8::7/64'
    for _ in range(depth):
        raw, canonical = 'NOT,((' + raw + '))', 'NOT,((' + canonical + '))'
    for native in (False, True):
        source = 'payload:\\n  - ' + json.dumps(raw) if native else raw
        parsed, messages = parse(source, purpose='proxy')
        wanted = Rule('NOT', canonical[4:], native_fields=native)
        assert (parsed, messages) == ([wanted], [])
        assert normalize([Rule('NOT', raw[4:], native_fields=native), wanted]) == [wanted]
        outputs, skipped = render('deep', parsed, purpose='proxy', no_resolve='strip')
        assert outputs['fin.yaml'] == '# deep rules: 1\\npayload:\\n  - ' + json.dumps(canonical) + '\\n'
        assert 'fin.yaml:NOT' not in skipped
        assert parse(outputs['fin.yaml'], purpose='proxy') == ([Rule('NOT', canonical[4:], native_fields=True)], [])
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
