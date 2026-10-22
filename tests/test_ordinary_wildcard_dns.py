import contextlib
import io
import json
import tempfile
import tracemalloc
import unittest
from pathlib import Path

from formats import render
from generate import generate, publish
from rules import Rule, parse, parse_whitelist
from tests.test_formats import dns_regex


class OrdinaryWildcardDnsTests(unittest.TestCase):
    def test_unproved_literals_skip_dns_in_block_allow_and_external_white(self):
        patterns = ("'123*", '"123*', '(123)*', r'123\456*', '*广告*',
                    '*123 456*', '*123\t456*', '*123@456*', '*123;456*', '*123=456*')
        for pattern in patterns:
            text = 'DOMAIN-WILDCARD,"' + pattern.replace('\\', '\\\\').replace('"', '\\"') + '"'
            parsed, messages = parse(text, purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-WILDCARD', pattern)], []))
            white = parse_whitelist(text)
            for caller in ('block', 'allow', 'whitelist'):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(pattern=pattern, caller=caller, purpose=purpose, mode=mode):
                            rules = [Rule('DOMAIN-WILDCARD', pattern, allow=True)] if caller == 'allow' else parsed
                            out, skipped = render('dns', rules if caller != 'whitelist' else [],
                                                  purpose=purpose, no_resolve=mode,
                                                  whitelist=white if caller == 'whitelist' else [])
                            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [] if purpose == 'block' else
                                             ['! No AdBlock rules for non-advertising group.'])
                            self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0),
                                             int(caller != 'whitelist' or purpose == 'block'))
                            if caller == 'block':
                                reread, messages = parse(out['fin.txt'], purpose=purpose)
                                self.assertEqual((reread, messages), (parsed, []))
                                self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
                                self.assertEqual(out['fin-surge-ds.txt'], '# dns rules: 0\n')

    def test_proved_ascii_patterns_have_literal_bodies_and_matching_witnesses(self):
        cases = (('*ads*', '/^.*ads.*$/', 'xads.example', 'ad.example'),
                 ('*', '/^.*$/', 'anything.example', None),
                 ('a?', '/^a.$/', 'ab', 'abc'), ('a??', '/^a..$/', 'abc', 'ab'),
                 ('1..2*', r'/^1\.\.2.*$/', '1..234', '1.234'),
                 ('-a_*', r'/^\-a_.*$/', '-a_test', 'a_test'),
                 ('[ab]', '/^[ab]$/', 'a', 'c'))
        for source in ('surge', 'qx'):
            for pattern, body, match, miss in cases:
                text = 'DOMAIN-WILDCARD,' + pattern if source == 'surge' else 'HOST-WILDCARD,' + pattern + ',LIST'
                parsed, messages = parse(text, purpose='block')
                self.assertEqual(messages, [])
                self.assertEqual(parsed, [Rule('DOMAIN-WILDCARD', pattern, domain_source=source)])
                white = parse_whitelist(text)
                supported = pattern != '[ab]' or source == 'surge'
                for caller in ('block', 'allow', 'whitelist'):
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(source=source, pattern=pattern, caller=caller, purpose=purpose, mode=mode):
                                rules = [Rule('DOMAIN-WILDCARD', pattern, allow=True, domain_source=source)] if caller == 'allow' else parsed
                                out, skipped = render('dns', rules if caller != 'whitelist' else [],
                                                      purpose=purpose, no_resolve=mode,
                                                      whitelist=white if caller == 'whitelist' else [])
                                expected = ('@@' if caller != 'block' else '') + body
                                self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                                 ([expected] if supported else []) if purpose == 'block' else
                                                 ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0),
                                                 int((not supported or purpose != 'block') if caller != 'whitelist' else
                                                     purpose == 'block' and not supported))
                                if supported and purpose == 'block':
                                    matcher = dns_regex(expected)
                                    self.assertIsNotNone(matcher.fullmatch(match))
                                    if miss is not None:
                                        self.assertIsNone(matcher.fullmatch(miss))

    def test_line_budget_counts_regex_expansion_wrappers_exception_and_lf(self):
        for source in ('surge', 'qx'):
            for caller in ('block', 'allow', 'whitelist'):
                prefix = '@@' if caller != 'block' else ''
                available = 65536 - len(prefix) - len('/^$/\n')
                cases = (('a' * available, 'a' * available),
                         ('*' * (available // 2) + '?' * (available % 2),
                          '.*' * (available // 2) + '.' * (available % 2)),
                         ('.' * (available // 2) + '?' * (available % 2),
                          r'\.' * (available // 2) + '.' * (available % 2)),
                         ('[ab]' * (available // 4) + '?' * (available % 4),
                          '[ab]' * (available // 4) + '.' * (available % 4)))
                for pattern, body in cases:
                    if source == 'qx' and '[' in pattern:
                        continue
                    for extra in (0, 1):
                        with self.subTest(source=source, caller=caller, first=pattern[:8], extra=extra):
                            value = pattern + 'a' * extra
                            text = ('DOMAIN-WILDCARD,' + value if source == 'surge' else
                                    'HOST-WILDCARD,' + value + ',LIST')
                            parsed, messages = parse(text, purpose='block')
                            self.assertEqual(messages, [])
                            self.assertEqual(parsed, [Rule('DOMAIN-WILDCARD', value, domain_source=source)])
                            rules = [Rule('DOMAIN-WILDCARD', value, allow=True, domain_source=source)] if caller == 'allow' else parsed
                            out, skipped = render('dns', rules if caller != 'whitelist' else [],
                                                  purpose='block', no_resolve='keep',
                                                  whitelist=parse_whitelist(text) if caller == 'whitelist' else [])
                            expected = prefix + '/^' + body + '$/'
                            self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [] if extra else [expected])
                            self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0), extra)

    def test_oversized_dns_does_not_allocate_the_expanded_regex(self):
        for caller in ('allow', 'whitelist'):
            with self.subTest(caller=caller):
                value = '*' * (1 << 20)
                rule = Rule('DOMAIN-WILDCARD', value, allow=caller == 'allow', domain_source='qx')
                tracemalloc.start()
                try:
                    out, skipped = render('dns', [rule] if caller == 'allow' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[rule] if caller == 'whitelist' else [])
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)
                # QX allow／white 不生成其他 regex；扩展一个 body 就需要两倍输入长度。
                self.assertLess(peak, len(value) * 2)

    def test_large_patterns_skip_only_dns_without_raising(self):
        for pattern in ('a' * 100000 + '*', '*' * 100000, '[ab]' * 30000):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(first=pattern[:8], caller=caller):
                    text = 'DOMAIN-WILDCARD,' + pattern
                    parsed, messages = parse(text, purpose='block')
                    self.assertEqual(messages, [])
                    rules = [Rule('DOMAIN-WILDCARD', pattern, allow=True)] if caller == 'allow' else parsed
                    out, skipped = render('dns', rules if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)
                    if caller == 'block':
                        self.assertEqual(out['fin.txt'], '# dns rules: 1\n' + text + '\n')
                        self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
                        self.assertEqual(out['fin-surge-ds.txt'], '# dns rules: 0\n')

    def test_real_generation_and_publication_keep_dns_subset_and_input_bytes(self):
        patterns = ('*123*', 'a?', "'123*", '(123)*', r'123\456*', '*广告*')
        ordinary = '\n'.join('DOMAIN-WILDCARD,"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
                             for value in patterns) + '\n'
        for caller in ('block', 'whitelist'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(caller=caller, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        pattern_file = root / 'static/pattern.list'
                        pattern_file.write_bytes(ordinary.encode('utf-8'))
                        neighbor = root / 'static/neighbor.list'
                        neighbor.write_bytes(b'DOMAIN,neighbor.example.org\nIP-CIDR,192.0.2.0/24,no-resolve\n'
                                             b'SRC-IP-CIDR,198.51.100.0/24\n')
                        inputs = {path: path.read_bytes() for path in (pattern_file, neighbor)}
                        (root / 'rulesets.json').write_text(json.dumps([{
                            'name': 'dns', 'purpose': purpose, 'no_resolve': mode,
                            'sources': ['static/neighbor.list'] + ([] if caller == 'whitelist' else ['static/pattern.list']),
                            'whitelist': ['static/pattern.list'] if caller == 'whitelist' else []}]), encoding='utf-8')
                        (root / 'dns').mkdir()
                        old = {}
                        for name in ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            path = root / 'dns' / name
                            old[path] = b'previous complete output\x00\xff\r\n'
                            path.write_bytes(old[path])
                        with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            out = generate(root, lambda url: self.fail(url))
                        self.assertEqual(set(out), set(old))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        self.assertNotIn('invalid domain', diagnostic.getvalue())
                        self.assertNotIn('frozen', diagnostic.getvalue())
                        prefix = '@@' if caller != 'block' else ''
                        expected = [prefix + '/^a.$/', prefix + '/^.*123.*$/', '0.0.0.0 neighbor.example.org']
                        if caller == 'block':
                            expected.sort(key=lambda row: (len(row), row))
                        self.assertEqual(out[root / 'dns/fin-adb.txt'].splitlines()[7:], expected if purpose == 'block' else
                                         ['! No AdBlock rules for non-advertising group.'])
                        self.assertEqual(f'dns fin-adb.txt:DOMAIN-WILDCARD: 4\n' in diagnostic.getvalue(), purpose == 'block')
                        full = out[root / 'dns/fin.txt']
                        self.assertNotIn('198.51.100.0/24,no-resolve', full)
                        self.assertEqual('192.0.2.0/24,no-resolve' in full, mode != 'strip')
                        if caller == 'block':
                            recovered, messages = parse(full, purpose=purpose)
                            self.assertEqual(messages, [])
                            self.assertEqual({rule.value for rule in recovered if rule.kind == 'DOMAIN-WILDCARD'}, set(patterns))
                        publish(out, root=root)
                        self.assertEqual({path: path.read_bytes() for path in out},
                                         {path: text.encode('utf-8') for path, text in out.items()})
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
