import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from formats import render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist
from sources import load_config
from tests.test_formats import expected_domain


class RawRegexPresentationTests(unittest.TestCase):
    def test_space_and_complement_use_fixed_isspace_in_three_consumers(self):
        from tests.test_formats import dns_regex

        for value, positive, negative in ((r'\sx', (r'\ x.abc', r'\009x.abc', r'\194\160x.abc'), ('ax.abc',)),
                                          (r'\Sx', ('ax.abc',), (r'\ x.abc', r'\009x.abc', r'\194\160x.abc'))):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
                                          if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    matcher = dns_regex(rows[0])
                    for host in positive:
                        self.assertIsNotNone(matcher.search(host), host)
                    for host in negative:
                        self.assertIsNone(matcher.search(host), host)

    def test_empty_scalar_class_never_matches_and_repeat_keeps_nullable_semantics(self):
        from tests.test_formats import dns_regex

        atom = '[^\\x{0}-\U0010ffff]'
        # 完整 scalar 前缀类的补集为空，零次重复仍可匹配空串。
        cases = ((atom + 'x', (), ('x.abc', 'ax.abc')),
                 ('(?:' + atom + '|a)x', ('ax.abc',), ('x.abc', 'bx.abc')),
                 ('(?:' + atom + ')?x', ('x.abc',), ('a.abc',)),
                 ('(?:' + atom + '){0}x', ('x.abc',), ('a.abc',)),
                 ('(?:' + atom + '){1}x', (), ('x.abc',)),
                 ('(?:' + atom + '){1,2}x', (), ('x.abc',)),
                 ('(?:' + atom + '){0,2}x', ('x.abc',), ('a.abc',)))
        for value, positive, negative in cases:
            text = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value, ensure_ascii=False)
            self.assertEqual(parse(text, purpose='block'), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    matcher = dns_regex(rows[0])
                    for host in positive:
                        self.assertIsNotNone(matcher.search(host), host)
                    for host in negative:
                        self.assertIsNone(matcher.search(host), host)

    def test_lower_preimage_union_universal_does_not_use_simplefold_as_source_oracle(self):
        from tests.test_formats import dns_regex

        value = r'(?:[k]|[^K])'
        # singleton K 被 ToLower 替换为 k；两个分支的并集覆盖所有 scalar。
        out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
        rows = out['fin-adb.txt'].splitlines()[7:]
        self.assertEqual(len(rows), 1)
        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
        for host in ('k.abc', r'\226\132\170.abc', 'x.abc'):
            self.assertIsNotNone(dns_regex(rows[0]).search(host), host)

    def test_encoded_foldcase_false_does_not_merge_kelvin_into_ascii_only_class(self):
        from tests.test_formats import dns_regex

        value = r'\A[K-L]x'
        out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
        rows = out['fin-adb.txt'].splitlines()[7:]
        self.assertEqual(len(rows), 1)
        matcher = dns_regex(rows[0])
        for host in ('kx.abc', 'lx.abc', r'\226\132\170x.abc'):
            self.assertIsNotNone(matcher.search(host), host)
        for host in ('sx.abc', r'\197\191x.abc'):
            self.assertIsNone(matcher.search(host), host)

    def test_terminal_star_certificate_requires_one_rune_set_not_a_composite_group(self):
        value = r'^a(?:b[.])*$'
        parsed, warnings = parse('DOMAIN-REGEX,' + value, purpose='block')
        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
        # raw a 命中而 a. 不命中；重复的 b. 不能吸收单独根点。
        for caller in ('block', 'allow', 'whitelist'):
            with self.subTest(caller=caller):
                rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                      whitelist=[rule] if caller == 'whitelist' else ())
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)

    def test_nullable_and_universal_reduction_checks_final_body_budget_after_source_cost(self):
        from tests.test_formats import dns_regex

        values = (r'\w?', r'\w?' * 2, r'\w?' * 3, r'\w?' * 4,
                  r'(?:\w{1000}){0}', r'(?:\w\w\w\w){0}', r'(?:\w\w\w\w|.)')
        expected = r'''/(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*)/'''
        for value in values:
            text = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
            self.assertEqual(parse(text, purpose='block'), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [('@@' if caller != 'block' else '') + expected])
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    for host in ('a.abc', r'\195\169.abc', r'\ x.abc'):
                        self.assertIsNotNone(dns_regex(expected).search(host), host)
        for value in (r'\w\w\w\wx', r'(?:\w{1000}){0,2}', r'(?:\w{1001}){0}',
                      r'(?:\w\w\w\w|(?-i:a)|.)', r'(?:\w\w\w\w|a$|.)'):
            with self.subTest(unsupported=value):
                out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)

    def test_single_rune_universal_reduction_keeps_source_limits_and_exact_anchors(self):
        from tests.test_formats import dns_regex

        accepted = ('.', '(?:.|a)', '(?:x?|.)', '(?:.){1,2}', '(?:.|a)?', r'\A(?:.|a)',
                    '(?:.){0}', '(?:.){0,1}', 'a{1000}', '(?:a{20}){50}', '(?:a{500}){0}')
        for value in accepted:
            with self.subTest(value=value):
                out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
                self.assertEqual(len(out['fin-adb.txt'].splitlines()[7:]), 1)
                self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
        for value in ('(?:a{20}){51}', '(?:(?:a{500}){0,}){3}', '(?:.){0,1001}'):
            with self.subTest(rejected=value):
                out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
        out, skipped = render('dns', [Rule('DOMAIN-REGEX', r'^(?:a\.?$)')], purpose='block', no_resolve='keep')
        rows = out['fin-adb.txt'].splitlines()[7:]
        self.assertEqual(len(rows), 1)
        matcher = dns_regex(rows[0])
        self.assertIsNotNone(matcher.search('a'))
        self.assertIsNone(matcher.search('ba'))

    def test_raw_same_bytes_and_real_external_white_reach_publish_and_disk_reload(self):
        from tests.test_formats import dns_regex

        values = ('195', '195|zz', 'é', '(?:é)', r'^a[.]test$', r'(?:^a[.]test$)')
        native = ('payload:\n' + ''.join('  - ' + json.dumps('DOMAIN-REGEX,' + value) + '\n' for value in values)).encode()
        for white in (False, True):
            with self.subTest(white=white), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                source = b'DOMAIN,neighbor.example.org\n' if white else native
                (root / 'static/source.list').write_bytes(source)
                (root / 'static/white.yaml').write_bytes(native)
                config = [{'name': 'parent', 'purpose': 'block', 'no_resolve': 'keep',
                           'sources': ['static/source.list'], 'whitelist': ['static/white.yaml'] if white else []},
                          {'name': 'child', 'purpose': 'block', 'no_resolve': 'keep',
                           'sources': ['parent/fin.yaml'], 'whitelist': ['static/white.yaml'] if white else []}]
                (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                self.assertEqual(load_config(root), config)
                self.assertEqual(len(parse_whitelist(native.decode())), len(values))
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    out = generate(root, lambda url: self.fail(url))
                self.assertEqual(len(out), 12)
                self.assertNotIn('frozen', diagnostic.getvalue())
                for group in ('parent', 'child'):
                    self.assertIn(group + ' fin-adb.txt:DOMAIN-REGEX: 2\n', diagnostic.getvalue())
                    rows = out[root / group / 'fin-adb.txt'].splitlines()[7:]
                    regex = [row for row in rows if row.startswith('@@/' if white else '/')]
                    self.assertEqual(len(regex), 3)
                    checks = [dns_regex(row) for row in regex]
                    self.assertEqual(sum(matcher.search(r'\195\169.abc') is not None for matcher in checks), 1)
                    self.assertEqual(sum(matcher.search(r'\195\137.abc') is not None for matcher in checks), 1)
                    self.assertEqual(sum(matcher.search('195.abc') is not None for matcher in checks), 2)
                    self.assertEqual(sum(matcher.search('a.test') is not None for matcher in checks), 0)
                    parsed, warnings = parse(out[root / group / 'fin.yaml'], purpose='block')
                    self.assertEqual(warnings, [])
                    reout, skipped = render(group, parsed, purpose='block', no_resolve='keep',
                                           whitelist=parse_whitelist(native.decode()) if white else ())
                    self.assertEqual(reout['fin-adb.txt'].splitlines()[7:], out[root / 'child/fin-adb.txt'].splitlines()[7:])
                publish(out, root=root)
                self.assertEqual((root / 'static/source.list').read_bytes(), source)
                self.assertEqual((root / 'static/white.yaml').read_bytes(), native)
                (root / 'rulesets.json').write_text(json.dumps(config[1:]), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()):
                    disk = generate(root, lambda url: self.fail(url))
                for path, text in disk.items():
                    offset = 7 if path.name == 'fin-adb.txt' else 2 if path.name == 'fin.yaml' else 1
                    self.assertEqual(text.splitlines()[offset:], out[path].splitlines()[offset:])
                publish(disk, root=root)
                self.assertEqual({path: path.read_bytes() for path in disk}, {path: text.encode() for path, text in disk.items()})

    def test_literal_and_empty_language_source_white_publish_and_disk_reload(self):
        from tests.test_formats import dns_regex

        empty = '[^\\x{0}-\U0010ffff]'
        cases = (('a}', 'a}.abc', 'a.abc'), ('a]', 'a].abc', 'a.abc'),
                 ('a]x', 'a]x.abc', 'ax.abc'), ('a{x', 'a{x.abc', 'ax.abc'),
                 (r'\?+x', '??x.abc', 'x.abc'), (r'\*+x', '**x.abc', 'x.abc'),
                 (r'\++x', '++x.abc', 'x.abc'), ('[?+]x', '?x.abc', 'x.abc'),
                 ('[*+]x', '*x.abc', 'x.abc'), ('[++]x', '+x.abc', 'x.abc'),
                 (empty + 'x', None, 'x.abc'), ('(?:' + empty + '){0}x', 'x.abc', 'a.abc'),
                 (r'^a[.]?x{0}$', 'a', 'ab'), (r'^a[.]?(?:){2}$', 'a', 'ab'),
                 (r'(?:replace=)?ads\.example\.com', 'replace=ads.example.com', 'ads.examplexcom'),
                 (r'(?<name>ads)\.example\.com', 'ads.example.com', 'ad.example.com'),
                 (r'(?<n>ad)(?<n>s)\.example\.com', 'ads.example.com', 'ad.example.com'),
                 (r'a{1,3}?x', 'aaax.abc', 'x.abc'),
                 ('"x', r'\"x.abc', 'x.abc'), ("'x", r"\'x.abc", 'x.abc'))
        for value, positive, negative in cases:
            payload = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value, ensure_ascii=False) + '\n').encode('utf-8')
            for white in (False, True):
                with self.subTest(value=value, white=white), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    source = b'DOMAIN,neighbor.example.org\n' if white else payload
                    inputs = {root / 'static/source.list': source, root / 'static/white.yaml': payload}
                    for path, data in inputs.items():
                        path.write_bytes(data)
                    config = [{'name': 'parent', 'purpose': 'block', 'no_resolve': 'keep',
                               'sources': ['static/source.list'], 'whitelist': ['static/white.yaml'] if white else []},
                              {'name': 'child', 'purpose': 'block', 'no_resolve': 'keep',
                               'sources': ['parent/fin.yaml'], 'whitelist': ['static/white.yaml'] if white else []}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    self.assertEqual(load_config(root), config)
                    self.assertEqual(parse_whitelist(payload.decode('utf-8')), [Rule('DOMAIN-REGEX', value)])
                    with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        output = generate(root, lambda url: self.fail(url))
                    self.assertEqual(len(output), 12)
                    self.assertNotIn('frozen', diagnostic.getvalue())
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX:', diagnostic.getvalue())
                    for group in ('parent', 'child'):
                        rows = [row for row in output[root / group / 'fin-adb.txt'].splitlines()[7:]
                                if row.startswith('@@/' if white else '/')]
                        self.assertEqual(len(rows), 1)
                        matcher = dns_regex(rows[0])
                        if positive is not None:
                            self.assertIsNotNone(matcher.search(positive), positive)
                        self.assertIsNone(matcher.search(negative), negative)
                        self.assertLessEqual(len(rows[0].encode('utf-8')) + 1, 65536)
                        native, warnings = parse(output[root / group / 'fin.yaml'], purpose='block')
                        self.assertEqual(warnings, [])
                        if not white:
                            self.assertEqual(native, [Rule('DOMAIN-REGEX', value)])
                        else:
                            self.assertEqual(len(native), 1)
                    publish(output, root=root)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                    self.assertEqual({path: path.read_bytes() for path in output},
                                     {path: text.encode('utf-8') for path, text in output.items()})
                    (root / 'rulesets.json').write_text(json.dumps(config[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, lambda url: self.fail(url))
                    for path, text in disk.items():
                        header = 7 if path.name == 'fin-adb.txt' else 2 if path.name == 'fin.yaml' else 1
                        self.assertEqual(text.splitlines()[header:], output[path].splitlines()[header:])
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                    self.assertEqual({path: path.read_bytes() for path in disk},
                                     {path: text.encode('utf-8') for path, text in disk.items()})

    def test_unknown_unicode_intervals_anchor_placement_and_quantified_matchers_fail_closed(self):
        values = ('[éê]x', '[é-ê]x', '[Α-Ω]x', r'a^b', r'a$b', r'a\Ab', r'a\zb', r'$', r'\z',
                  r'(?:^a\.?$)?', r'a.*{1,2}$', r'(?-i:a)',
                  r'(?m:a)', r'(?n:a)', r'(?s:a)', r'(?x:a)', r'(?d:a)', r'(?u:a)',
                  r'(?i:é)', r'\x{E9}', r'(?:195|a$)', r'(?:a[.]?){2}$',
                  r'a++x', r'a?+x', r'a*+x', r'a{1,2}+x')
        for value in values:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=[rule] if caller == 'whitelist' else ())
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                    self.assertEqual(rule.value, value)

    def test_literal_hex_braces_and_closed_matcher_alternatives_keep_whole_structure(self):
        from tests.test_formats import dns_regex

        cases = ((r'\x{0000061}x', ('ax.abc',), ('x.abc',)),
                 ('a{x', ('a{x.abc',), ('ax.abc',)),
                 ('a}', ('a}.abc',), ('a.abc',)),
                 ('a]', ('a].abc',), ('a.abc',)),
                 ('a}x', ('a}x.abc',), ('ax.abc',)),
                 ('a]x', ('a]x.abc',), ('ax.abc',)),
                 (r'\?+x', ('??x.abc',), ('x.abc',)),
                 (r'\*+x', ('**x.abc',), ('x.abc',)),
                 (r'\++x', ('++x.abc',), ('x.abc',)),
                 ('[?+]x', ('?x.abc', '+x.abc'), ('x.abc',)),
                 ('[*+]x', ('*x.abc', '+x.abc'), ('x.abc',)),
                 ('[++]x', ('+x.abc',), ('x.abc',)),
                 (r'(?:^a\.?$|b)', ('a', 'xb.abc'), ('c.xyz',)),
                 (r'(?:a[.]*|b)\.?$', ('a', 'b'), ('c',)))
        for value, matches, misses in cases:
            text = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    if value == r'(?:a[.]*|b)\.?$':
                        self.assertEqual(rows, [])
                        self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                        continue
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    matcher = dns_regex(rows[0])
                    for host in matches:
                        self.assertIsNotNone(matcher.search(host), host)
                    for host in misses:
                        self.assertIsNone(matcher.search(host), host)

    def test_raw_unicode_literals_keep_complete_go_lower_preimages(self):
        from tests.test_formats import dns_regex

        cases = (('é', (r'\195\169.test', r'\195\137.test'), ('e.test',)),
                 ('(?:é)', (r'\195\169.test', r'\195\137.test'), ('e.test',)),
                 ('k', ('k.test', r'\226\132\170.test'), ('x.test',)),
                 ('i', ('i.test', r'\196\176.test'), (r'\196\177.test',)),
                 ('s', ('s.abc',), (r'\197\191.abc',)),
                 ('σ', (r'\207\131.test', r'\206\163.test'), (r'\207\130.test',)),
                 ('replace=', ('replace=.test',), ('replacex.test',)))
        for value, matches, misses in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
                                          if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    self.assertNotIn('replace=', rows[0])
                    self.assertIn('(?-i:', rows[0])
                    matcher = dns_regex(rows[0])
                    for host in matches:
                        self.assertIsNotNone(matcher.search(host), host)
                    for host in misses:
                        self.assertIsNone(matcher.search(host), host)

    def test_leading_literal_quotes_share_regex_lexing_and_root_checks_in_three_consumers(self):
        from tests.test_formats import dns_regex

        # 字段解码后，引号是 regex literal；完整 anchored matcher 仍须取得根点证书。
        self.assertEqual(parse('DOMAIN-REGEX,"x"', purpose='block'), ([Rule('DOMAIN-REGEX', 'x')], []))
        cases = (('"x', True, (r'\"x.abc',), ('x.abc', r'\".abc', '"x.abc')),
                 ("'x", True, (r"\'x.abc",), ('x.abc', r"\'.abc", "'x.abc")),
                 ('a"x', True, (r'a\"x.abc',), ('ax.abc', r'a\".abc', 'a"x.abc')),
                 ("a'x", True, (r"a\'x.abc",), ('ax.abc', r"a\'.abc", "a'x.abc")),
                 ('"x"', True, (r'\"x\".abc',), ('x.abc', r'\"x.abc', '"x".abc')),
                 ("'x'", True, (r"\'x\'.abc",), ('x.abc', r"\'x.abc", "'x'.abc")),
                 (r'"x|(?-i:\A[aA]\.[tT][eE][sS][tT]\.?\z)', True,
                  (r'\"x.abc', 'a.test'), ('x.abc', 'xa.test', 'a.test.extra')),
                 ('"x$', False, (), ()), ("'x$", False, (), ()))
        for value, supported, matches, misses in cases:
            for text in ('DOMAIN-REGEX,' + json.dumps(value),
                         'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)):
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(value=value, text=text, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                        rows = out['fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(len(rows), int(supported))
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(not supported))
                        if supported:
                            matcher = dns_regex(rows[0])
                            for host in matches:
                                self.assertIsNotNone(matcher.search(host), host)
                            for host in misses:
                                self.assertIsNone(matcher.search(host), host)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                            self.assertEqual(parse(out['fin.yaml'], purpose='block'), (parsed, []))
                        reference, diagnostics = render('dns', [rule] if caller != 'whitelist' else [],
                                                        purpose='proxy', no_resolve='keep')
                        for name in out:
                            if name != 'fin-adb.txt':
                                self.assertEqual(out[name], reference[name])
                                self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                                 {key: count for key, count in diagnostics.items() if key.startswith(name + ':')})

    def test_root_stable_operator_forms_keep_independent_presentation_decisions(self):
        from tests.test_formats import dns_regex

        # 非空 FQDN profile 上的 universal 没有反例，空 misses 不代表检查任意来源 matcher。
        cases = ((r'(?:replace=)?ads\.example\.com', ('ads.example.com', 'replace=ads.example.com'),
                  ('ad.example.com', 'ads.examplexcom')),
                 (r'(?<name>ads)\.example\.com', ('ads.example.com', 'xads.example.com'), ('ad.example.com',)),
                 (r'(?<n>ad)(?<n>s)\.example\.com', ('ads.example.com',), ('ad.example.com',)),
                 (r'a+?x', ('ax.abc', 'aaax.abc'), ('x.abc',)),
                 (r'a*?x', ('x.abc', 'aaax.abc'), ('a.abc',)),
                 (r'a??x', ('x.abc', 'ax.abc'), ('a.abc',)),
                 (r'a{1,3}?x', ('ax.abc', 'aaax.abc'), ('x.abc',)),
                 (r'[ab]+?x', ('abax.abc',), ('x.abc',)),
                 (r'[ab]{3}?x', ('abax.abc',), ('abx.abc',)),
                 (r'a{0001}', ('a.xyz', 'ba.xyz'), ('bbb.xyz',)),
                 (r'(?:a{500}){0}', ('x.xyz', r'\195\169.123'), ()),
                 (r'.', ('x.xyz', r'\195\169.123'), ()),
                 (r'^ads.*$', ('ads', 'ads.example.com', r'ads\195\169.abc'), ('xads.abc', 'ad.abc')),
                 (r'^.*$', ('x.xyz', r'\195\169.123'), ()),
                 (r'ads[.]*$', ('ads', 'x.ads'), ('ads.abc', 'ad')))
        for value, matches, misses in cases:
            texts = ('DOMAIN-REGEX,' + value, 'DOMAIN-REGEX,' + json.dumps(value),
                     'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
            for text in texts:
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(value=value, text=text, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                        rows = out['fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(len(rows), 1)
                        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                        self.assertNotIn('replace=', rows[0])
                        matcher = dns_regex(rows[0])
                        for host in matches:
                            self.assertIsNotNone(matcher.search(host), host)
                        for host in misses:
                            self.assertIsNone(matcher.search(host), host)

    def test_source_classes_properties_and_high_scalar_search_use_rune_sets(self):
        from tests.test_formats import dns_regex

        cases = ((r'\p{L}', ('a.123', r'\195\169.123'), ('7.123', r'\204\133.123')),
                 (r'\d', ('7.abc', r'\217\161.abc'), ('a.abc',)),
                 (r'\w', ('_.123', r'\204\133.123', r'\226\128\140.123'), ('!.---',)),
                 (r'\s', (r'\ .abc', r'\009.abc'), ('a.abc',)),
                 (r'[K]x', ('kx.abc', r'\226\132\170x.abc'), ('sx.abc',)),
                 (r'[K]y', ('ky.abc', r'\226\132\170y.abc'), ('sy.abc',)),
                 (r'[σ]x', (r'\207\131x.abc', r'\206\163x.abc'), (r'\207\130x.abc',)),
                 (r'[^ab]x', ('cx.abc', r'\195\169x.abc'), ('ax.abc', 'bx.abc')),
                 (r'[ab]{3}x', ('abax.abc',), ('abx.abc', 'aax.abc')),
                 (r'[--0]x', ('-x.abc', '.x.abc', '0x.abc'), ('1x.abc', 'ax.abc')),
                 (r'\dx', ('7x.abc', r'\217\167x.abc', r'\217\161x.abc'), ('ax.abc',)),
                 (r'\p{Nd}x', ('7x.abc', r'\217\161x.abc'), ('ax.abc',)),
                 (r'\p{L}x', ('ax.abc', r'\195\169x.abc', r'\228\184\173x.abc'), ('7x.abc', r'\204\133x.abc')),
                 (r'[\p{L}]x', ('ax.abc', r'\228\184\173x.abc'), ('7x.abc',)),
                 (r'[\p{L}\p{L}中]y', ('ay.abc', r'\228\184\173y.abc'), ('7y.abc',)),
                 (r'\wx', ('7x.abc', '_x.abc', r'\204\133x.abc', r'\226\128\140x.abc'), ('!x.abc', '-x.abc')),
                 (r'\sx', (r'\009x.abc', r'\226\128\128x.abc', r'\194\160x.abc'), ('ax.abc',)),
                 (r'\Dx', ('ax.abc',), ('7x.abc',)),
                 (r'\Wx', ('-x.abc',), ('ax.abc',)),
                 (r'\Sx', ('ax.abc',), (r'\009x.abc',)),
                 ('é{2}', (r'\195\169\195\137.abc',), (r'\195\169.abc',)),
                 ('\U0010fffdx', (r'\244\143\191\189x.abc',), ('ax.abc',)),
                 ('[\U0010fffd-\U0010fffd]x', (r'\244\143\191\189x.abc',), ('ax.abc',)),
                 ('[\\x{0}-\U0010fffd]x', ('ax.abc', r'\244\143\191\189x.abc'), (r'\244\143\191\190x.abc',)))
        for value, matches, misses in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value, ensure_ascii=False))
                                          if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    matcher = dns_regex(rows[0])
                    for host in matches:
                        self.assertIsNotNone(matcher.search(host), host)
                    for host in misses:
                        self.assertIsNone(matcher.search(host), host)
                    self.assertLessEqual(len(rows[0].encode()) + 1, 65536)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_neutral_groups_and_edge_anchors_keep_complete_root_certificate(self):
        from tests.test_formats import dns_regex

        unsafe = (r'^a[.]test$', r'(?:^a[.]test$)', r'((?:^a[.]test$))',
                  r'(?:195|^a[.]test$)', r'(?:^a[.]test$)?', r'a$')
        safe = (r'a', r'(a)', r'(?:a|é)', r'a{0001}', r'(?:a)?',
                r'^a[.]test\.?$', r'(?:^a[.]test\.?)$', r'^ads.*$', r'^.*$', r'ads[.]*$')
        for value in (*unsafe, *safe):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('DOMAIN-REGEX,' + value) if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), int(value in safe))
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(value in unsafe))
                    if value in (r'^a[.]test\.?$', r'(?:^a[.]test\.?)$'):
                        matcher = dns_regex(rows[0])
                        self.assertIsNotNone(matcher.search('a.test'))
                        self.assertIsNone(matcher.search('xa.test'))
                        self.assertIsNone(matcher.search('a.test.extra'))

    def test_canonical_exact_suffix_and_paired_exact_keep_actual_predicates(self):
        from tests.test_formats import dns_regex

        cases = ((r'(?i:\Ak\.test\.?\z)', ('k.test', r'\226\132\170.test'), ('xk.test',)),
                 (r'(?i:(?:\A|\.)k\.test\.?\z)', ('k.test', 'x.k.test', r'x.\226\132\170.test'), ('xk.test',)),
                 (r'(?i:\Ai\.test\.?\z)', ('i.test', r'\196\176.test'), (r'\196\177.test',)),
                 (r'(?i:(?:\A|\.)i\.test\.?\z)', ('i.test', r'x.\196\176.test'), (r'\196\177.test', r'x.\196\177.test')),
                 (r'(?i:\As\.test\.?\z)', ('s.test',), (r'\197\191.test',)),
                 (r'(?-i:\A[kK]\.[tT][eE][sS][tT]\.?\z)', ('k.test',), (r'\226\132\170.test',)),
                 (r'(?-i:\A[iI]\.[tT][eE][sS][tT]\.?\z)', ('i.test',), (r'\196\176.test', r'\196\177.test')))
        cases = tuple((wrapped, matches, misses) for value, matches, misses in cases
                      for wrapped in (value, '(?:' + value + ')', '(' + value + ')',
                                      '(?:' + value + '|^q[.]?$(?:))'))
        cases += ((r'(?:(?-i:\A[kK]\.[tT][eE][sS][tT]\.?\z)|k)',
                   ('k.test', r'\226\132\170.abc'), ('x.abc',)),
                  (r'(?-i:\A[aA]\.[tT][eE][sS][tT]\.?\z)|z',
                   ('a.test', 'z.abc', 'xzy.abc'), ('xa.test', 'a.test.extra')))
        for value, matches, misses in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
                                          if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                    matcher = dns_regex(rows[0])
                    for host in matches:
                        self.assertIsNotNone(matcher.search(host), host)
                    for host in misses:
                        self.assertIsNone(matcher.search(host), host)
        partial = (r'(?-i:(?:\A|\.)test\z|\A(?=[A-Za-z0-9_.-]{1,253}\.?\z)'
                   r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*'
                   r'[tT][eE][sS][tT]\.?\z)')
        for value in (partial, r'(?-i:a)', r'(?i:k\.test\z)'):
            out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
            self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)

    def test_complete_anchor_branches_and_single_rune_tail_proofs_compose(self):
        from tests.test_formats import dns_regex

        cases = ((r'(?:^a\.?$)', True, ('a',), ('ba', 'ab')),
                 (r'((?:^a\.?$))', True, ('a',), ('ba',)),
                 (r'(?:^a\.?$|é)', True, ('a', r'\195\169.abc'), ('ba',)),
                 (r'(?:^a\.?$|^b\.?$)', True, ('a', 'b'), ('ab',)),
                 (r'(?:a|[^a])', True, ('x.abc',), ()),
                 (r'^x(?:a.)*$', False, (), ()),
                 (r'^x(?:[.])*$', True, ('x', 'x..'), ('xa',)),
                 (r'^a(?:[.]?$)', True, ('a',), ('ab', 'ba')),
                 (r'^a[.]?(?:)$', True, ('a',), ('ab', 'ba')),
                 (r'^a[.](?:b[.]?$)', True, ('a.b',), ('xa.b', 'a.bc')),
                 (r'^a[.](?:b[.]*$)', True, ('a.b', 'a.b..'), ('xa.b', 'a.bc')),
                 (r'^a[.]*(?:)$', True, ('a', 'a..'), ('ab',)),
                 (r'^a[.]?()$', True, ('a',), ('ab',)),
                 (r'^a[.]?x{0}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:x){0}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:x|y){0}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:x{0})$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:x?){0}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:){2}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:|){1}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:){0,}$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:|)*$', True, ('a',), ('ab',)),
                 (r'^a[.]?(?:)+$', True, ('a',), ('ab',)),
                 (r'(?:^a\.?$)x', False, (), ()),
                 (r'(?:^a\.?$){0}x', False, (), ()),
                 (r'^a[.]?(?:a{1001}){0}$', False, (), ()),
                 (r'^a[.]?(?:(?:a{0}){1000}){2}$', False, (), ()),
                 (r'(?:^a\.?$)*', False, (), ()),
                 (r'a^b', False, (), ()), (r'a$b', False, (), ()))
        for value, supported, matches, misses in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
                                          if caller == 'whitelist' else ())
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), int(supported))
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(not supported))
                    if supported:
                        matcher = dns_regex(rows[0])
                        for host in matches:
                            self.assertIsNotNone(matcher.search(host), host)
                        for host in misses:
                            self.assertIsNone(matcher.search(host), host)

    # 固定 regexp2 源码给出 source 真值；re 只检查独立 engine presentation 字面值。
    def test_raw_numeric_search_starts_at_complete_presentation_token_in_three_consumers(self):
        from dataclasses import replace
        from tests.test_formats import dns_regex

        for value in ('195', '195|zz'):
            texts = ('DOMAIN-REGEX,' + value, 'DOMAIN-REGEX,' + json.dumps(value),
                     'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
            for text in texts:
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(value=value, text=text, caller=caller):
                        selected = parsed if caller == 'block' else [replace(parsed[0], allow=True)] if caller == 'allow' else []
                        out, skipped = render('dns', selected, purpose='block', no_resolve='keep',
                                              whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                        rows = out['fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(len(rows), 1)
                        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', skipped)
                        matcher = dns_regex(rows[0])
                        for host in ('195.test', 'x195.test', 'zz.test') if '|' in value else ('195.test', 'x195.test'):
                            self.assertIsNotNone(matcher.search(host), host)
                        for host in (r'\195\169.test', r'\195\137.test', '19.test'):
                            self.assertIsNone(matcher.search(host), host)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)


class NativeDnsProfileTests(unittest.TestCase):
    # 来源真值来自固定源码与规格；Python re 只核有限的 engine presentation 字面见证。
    def test_native_exact_and_suffix_share_case_root_guard_in_three_consumers(self):
        from dataclasses import replace

        # raw Host 的 A.test/a.test、a.test/a.test. 经 D(h) 后相同，native 决定仍不同。
        for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
            for value in ('A.test', 'a.test', 'a.test.'):
                text = 'payload:\n  - ' + json.dumps(kind + ',' + value)
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule(kind, value, domain_source='mihomo')], []))
                self.assertFalse(parsed[0].native_fields)
                white = parse_whitelist(text)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(kind=kind, value=value, caller=caller):
                        selected = parsed if caller == 'block' else [replace(parsed[0], allow=True)] if caller == 'allow' else []
                        out, skipped = render('dns', normalize(selected), purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else ())
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped['fin-adb.txt:' + kind], 1)
                        self.assertEqual(parsed[0].value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), kind + ',' + value)
                ordinary, warnings = parse(kind + ',a.test', purpose='block')
                self.assertEqual(warnings, [])
                out, skipped = render('dns', ordinary, purpose='block', no_resolve='keep', whitelist=white)
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                 ['0.0.0.0 a.test'] if kind == 'DOMAIN' else ['||a.test^'])
                self.assertEqual(skipped['fin-adb.txt:' + kind], 1)

    def test_native_keyword_constructor_cannot_restore_ascii_case_or_root(self):
        for value in ('a.test', 'A.test', '123.', 'İ', 'K'):
            text = 'payload:\n  - ' + json.dumps('DOMAIN-KEYWORD,' + value)
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual(warnings, [])
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-KEYWORD', value, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-KEYWORD'], 1)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-KEYWORD,' + value)

    def test_native_wildcard_requires_case_and_root_invariance_before_builder(self):
        from dataclasses import replace

        # *.*.* 在 x.test 与 x.test. 上决定不同；? 是必要 byte，不能按 literal 证明根点不变。
        for value in ('a.example', 'ad*.example', '*.*.*', '*.*', '*.123.*', '*123?', '*123?*', '[12]*'):
            text = 'payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + value)
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual(warnings, [])
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    selected = parsed if caller == 'block' else [replace(parsed[0], allow=True)] if caller == 'allow' else []
                    out, skipped = render('dns', selected, purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-WILDCARD,' + value)
        for value in ('*', '*?*', '*.*123*', '*?123*', '123*'):
            with self.subTest(supported=value):
                out, skipped = render('dns', [Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')],
                                      purpose='block', no_resolve='keep')
                self.assertEqual(len(out['fin-adb.txt'].splitlines()[7:]), 1)
                self.assertNotIn('fin-adb.txt:DOMAIN-WILDCARD', skipped)

    def test_native_keyword_matches_complete_presentation_bytes_after_constructor_lower(self):
        from tests.test_formats import dns_regex

        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        cases = (('é', r'\\195\\169', (r'\195\169.example',), (r'\195\137.example', 'e.example')),
                 ('É', r'\\195\\169', (r'\195\169.example',), (r'\195\137.example',)),
                 ('195', '195', ('195.example', 'x195.example'), (r'\195\169.example', r'\195\137.example')),
                 ('123', '123', ('123.example', 'x123.example'), (r'\123.example', '12.example')),
                 ('ſ', r'\\197\\191', (r'\197\191.example',), ('s.example',)),
                 ('=', r'\x{3D}', ('=.example',), ('3d.example',)),
                 ('123.456', r'123\.456', ('123.456',), ('123x456',)))
        for value, literal, matches, misses in cases:
            text = 'payload:\n  - ' + json.dumps('DOMAIN-KEYWORD,' + value)
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual(warnings, [])
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-KEYWORD', value, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else ())
                    expected = ('@@' if caller != 'block' else '') + r'/(?s-i:\A' + token + '*' + literal + token + r'*\z)/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [expected])
                    self.assertNotIn('fin-adb.txt:DOMAIN-KEYWORD', skipped)
                    matcher = dns_regex(expected)
                    for host in matches:
                        self.assertIsNotNone(matcher.fullmatch(host), host)
                    for host in misses:
                        self.assertIsNone(matcher.fullmatch(host), host)
                    self.assertEqual(parsed[0].value, value)

    def test_native_wildcard_consumes_presentation_byte_tokens_and_keeps_safe_large_spans(self):
        from tests.test_formats import dns_regex

        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        cases = (('??123*', token * 2 + '123' + token + '*',
                  (r'\195\169123.test', 'ab123.test'), (r'\228\184\173123.test', 'a123.test')),
                 ('*?123*', token + '*' + token + '123' + token + '*',
                  (r'\195\169123.test', 'a123.test'), ('123.test',)),
                 ('*.*123*', token + r'*\.' + token + '*123' + token + '*',
                  ('x.123.test',), ('x123.test',)),
                 ('é*', r'\\195\\169' + token + '*',
                  (r'\195\169.test',), (r'\195\137.test',)),
                 ('*?*', token + '*' + token + token + '*',
                  ('x.test', r'\195\169.test'), ()))
        for value, body, matches, misses in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-WILDCARD', value, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + value))
                                          if caller == 'whitelist' else ())
                    expected = ('@@' if caller != 'block' else '') + r'/(?s-i:\A' + body + r'\z)/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [expected])
                    self.assertNotIn('fin-adb.txt:DOMAIN-WILDCARD', skipped)
                    matcher = dns_regex(expected)
                    for host in matches:
                        self.assertIsNotNone(matcher.fullmatch(host), host)
                    for host in misses:
                        self.assertIsNone(matcher.fullmatch(host), host)
        for count in (17, 18, 20, 32):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(count=count, caller=caller):
                    value = '?' * count + '123*'
                    rule = Rule('DOMAIN-WILDCARD', value, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=[rule] if caller == 'whitelist' else ())
                    expected = ('@@' if caller != 'block' else '') + r'/(?s-i:\A' + token * count + '123' + token + r'*\z)/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [expected])
                    matcher = dns_regex(expected)
                    for prefix in ('1' * count, r'\195\169' + '1' * (count - 2)):
                        self.assertIsNotNone(matcher.fullmatch(prefix + '123.test'))
                    for prefix in ('1' * (count - 1), r'\195\169' + '1' * (count - 1)):
                        self.assertIsNone(matcher.fullmatch(prefix + '123.test'))
                    self.assertNotIn('fin-adb.txt:DOMAIN-WILDCARD', skipped)

    def test_native_presentation_escapes_label_specials_and_preserves_printable_bytes(self):
        from tests.test_formats import dns_regex

        cases = ((' ', '\\\\' + r'\ ', r'\ '), ("'", r"\\'", r"\'"),
                 ('@', r'\\@', r'\@'), (';', r'\\;', r'\;'),
                 ('(', r'\\\(', r'\('), (')', r'\\\)', r'\)'),
                 ('"', r'\\"', r'\"'), ('\\', r'\\\\', r'\\'),
                 ('\t', r'\\009', r'\009'), ('\x7f', r'\\127', r'\127'),
                 ('0', '0', '0'), ('<', '<', '<'), ('=', r'\x{3D}', '='))
        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        for char, literal, host in cases:
            with self.subTest(char=repr(char)):
                value = '123' + char + '456*'
                out, skipped = render('dns', [Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')],
                                      purpose='block', no_resolve='keep')
                if char == '\x7f':
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)
                    continue
                expected = r'/(?s-i:\A123' + literal + '456' + token + r'*\z)/'
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [expected])
                self.assertNotIn('fin-adb.txt:DOMAIN-WILDCARD', skipped)
                self.assertIsNotNone(dns_regex(expected).fullmatch('123' + host + '456.test'))

    def test_safe_native_presentation_budgets_keep_exact_limit_and_reject_one_byte_more(self):
        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        for caller in ('block', 'allow', 'whitelist'):
            exception = caller != 'block'
            keyword_budget = 65448 if exception else 65450
            wildcard_budget = 65484 if exception else 65486
            cases = (('DOMAIN-KEYWORD', '1' * keyword_budget, '1' * keyword_budget),
                     ('DOMAIN-KEYWORD', 'é' * (keyword_budget // 10) + '1' * (keyword_budget % 10),
                      r'\\195\\169' * (keyword_budget // 10) + '1' * (keyword_budget % 10)),
                     ('DOMAIN-KEYWORD', '=' * (keyword_budget // 6) + '1' * (keyword_budget % 6),
                      r'\x{3D}' * (keyword_budget // 6) + '1' * (keyword_budget % 6)),
                     ('DOMAIN-WILDCARD', '1' * wildcard_budget + '*', '1' * wildcard_budget),
                     ('DOMAIN-WILDCARD', 'é' * (wildcard_budget // 10) + '1' * (wildcard_budget % 10) + '*',
                      r'\\195\\169' * (wildcard_budget // 10) + '1' * (wildcard_budget % 10)),
                     ('DOMAIN-WILDCARD', '=' * (wildcard_budget // 6) + '1' * (wildcard_budget % 6) + '*',
                      r'\x{3D}' * (wildcard_budget // 6) + '1' * (wildcard_budget % 6)))
            for kind, value, literal in cases:
                for extra in (0, 1):
                    with self.subTest(caller=caller, kind=kind, literal=literal[:12], extra=extra):
                        expanded = value[:-1] + '1*' if kind == 'DOMAIN-WILDCARD' and extra else value + '1' * extra
                        rule = Rule(kind, expanded, allow=caller == 'allow', domain_source='mihomo')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                              whitelist=[rule] if caller == 'whitelist' else ())
                        expected = ('@@' if exception else '') + r'/(?s-i:\A' + (
                            token + '*' if kind == 'DOMAIN-KEYWORD' else '') + literal + token + r'*\z)/'
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [] if extra else [expected])
                        self.assertEqual(skipped.get('fin-adb.txt:' + kind, 0), extra)
                        if not extra and not exception:
                            blocked, rejected = render('dns', [], purpose='block', no_resolve='keep', whitelist=[rule])
                            self.assertEqual(blocked['fin-adb.txt'].splitlines()[7:], [])
                            self.assertEqual(rejected['fin-adb.txt:' + kind], 1)

    def test_real_native_source_and_external_white_publish_actual_dns_bytes(self):
        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        entries = ('DOMAIN,A.test', 'DOMAIN,a.test', 'DOMAIN,a.test.',
                   'DOMAIN-SUFFIX,a.test', 'DOMAIN-SUFFIX,a.test.', 'DOMAIN-KEYWORD,a.test',
                   'DOMAIN-KEYWORD,A.test', 'DOMAIN-WILDCARD,a.example', 'DOMAIN-WILDCARD,ad*.example',
                   'DOMAIN-WILDCARD,*.*.*', 'DOMAIN-KEYWORD,é', 'DOMAIN-KEYWORD,195',
                   'DOMAIN-KEYWORD,123', 'DOMAIN-WILDCARD,*', 'DOMAIN-WILDCARD,*?*')
        native = 'payload:\n' + ''.join('  - ' + json.dumps(entry) + '\n' for entry in entries)
        parsed, messages = parse(native, purpose='block')
        self.assertEqual(messages, [])
        self.assertEqual(len(parsed), len(entries))
        self.assertEqual(len(parse_whitelist(native)), len(entries))
        safe = [r'/(?s-i:\A' + token + '*' + literal + token + r'*\z)/' for literal in
                (r'\\195\\169', '195', '123')]
        safe += [r'/(?s-i:\A.*\z)/', r'/(?s-i:\A' + token + '*' + token + token + r'*\z)/']
        for caller in ('block', 'whitelist'):
            with self.subTest(caller=caller), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = native if caller == 'block' else 'DOMAIN,neighbor.example.org\n'
                config = [{'name': 'dns', 'purpose': 'block', 'no_resolve': 'keep',
                           'sources': ['https://example.test/source'],
                           'whitelist': ['https://example.test/white'] if caller == 'whitelist' else []}]
                (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                self.assertEqual(load_config(root), config)
                responses = {'https://example.test/source': source.encode(), 'https://example.test/white': native.encode()}
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    out = generate(root, responses.__getitem__)
                self.assertEqual(len(out), 6)
                self.assertNotIn('frozen', diagnostic.getvalue())
                rows = [('@@' if caller == 'whitelist' else '') + row for row in safe]
                if caller == 'whitelist':
                    rows.append('0.0.0.0 neighbor.example.org')
                rows.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                self.assertEqual(out[root / 'dns/fin-adb.txt'].splitlines()[7:], rows)
                publish(out, root=root)
                self.assertEqual((root / 'dns/fin-adb.txt').read_bytes(), out[root / 'dns/fin-adb.txt'].encode('utf-8'))
                self.assertEqual({path: path.read_bytes() for path in out}, {path: text.encode('utf-8') for path, text in out.items()})
        rejected, warnings = parse('payload:\n  - "@@DOMAIN,a.test"\n', purpose='block')
        self.assertEqual(rejected, [])
        self.assertTrue(warnings)

    def test_real_external_white_byte_budget_reaches_publish_boundary(self):
        token = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
        for kind, budget in (('DOMAIN-KEYWORD', 65448), ('DOMAIN-WILDCARD', 65484)):
            cases = (('1' * budget, '1' * budget),
                     ('é' * (budget // 10) + '1' * (budget % 10), r'\\195\\169' * (budget // 10) + '1' * (budget % 10)),
                     ('=' * (budget // 6) + '1' * (budget % 6), r'\x{3D}' * (budget // 6) + '1' * (budget % 6)))
            for value, literal in cases:
                for extra in (0, 1):
                    with self.subTest(kind=kind, first=value[:8], extra=extra), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/source.list').write_bytes(b'DOMAIN,neighbor.example.org\n')
                        payload = kind + ',' + value + '1' * extra + ('*' if kind == 'DOMAIN-WILDCARD' else '')
                        white = ('payload:\n  - ' + json.dumps(payload) + '\n').encode('utf-8')
                        (root / 'static/white.yaml').write_bytes(white)
                        (root / 'rulesets.json').write_text(json.dumps([{
                            'name': 'dns', 'purpose': 'block', 'no_resolve': 'keep',
                            'sources': ['static/source.list'], 'whitelist': ['static/white.yaml']}]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                            out = generate(root, lambda url: self.fail(url))
                        expected = r'@@/(?s-i:\A' + (token + '*' if kind == 'DOMAIN-KEYWORD' else '') + literal + token + r'*\z)/'
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                        self.assertEqual(out[root / 'dns/fin-adb.txt'].splitlines()[7:],
                                         ([] if extra else [expected]) + ['0.0.0.0 neighbor.example.org'])
                        self.assertEqual(f'dns fin-adb.txt:{kind}: 1\n' in diagnostic.getvalue(), bool(extra))
                        publish(out, root=root)
                        self.assertEqual((root / 'dns/fin-adb.txt').read_bytes(), out[root / 'dns/fin-adb.txt'].encode('utf-8'))
                        self.assertEqual((root / 'static/white.yaml').read_bytes(), white)


class DnsDomainConsumerTests(unittest.TestCase):
    def test_short_native_wildcards_and_angle_literals_use_byte_patterns(self):
        for value in ('*ads*', '*', 'a?', 'a??', '*<ads>*'):
            parsed, messages = parse('payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + value), purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-WILDCARD', value, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[rule] if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [('@@' if caller != 'block' else '') + r'/(?s-i:\A.*\z)/'] if value == '*' else [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0), int(value != '*'))
                    self.assertEqual(rule.value, value)

    def test_underscore_exact_uses_strict_regex_in_three_consumers(self):
        for source in ('surge', 'qx', 'mihomo'):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(source=source, caller=caller):
                    rule = Rule('DOMAIN', 'ad_core.cctv.com', allow=caller == 'allow', domain_source=source)
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[rule] if caller == 'whitelist' else [])
                    expected = ('@@' if caller != 'block' else '') + r'/(?s-i:\Aad_core\.cctv\.com\z)/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [expected] if source != 'mihomo' else [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN', 0), int(source == 'mihomo'))
                    self.assertEqual(rule.value, 'ad_core.cctv.com')

    def test_seven_underscore_suffixes_and_exact_keep_other_five_targets(self):
        suffixes = ('piano_log.kingsoft.jp', 'imp_track.zmaticoo.com', 'fb_servpub-a.akamaihd.net',
                    'at_w_atexxpressdata-c3a3188a23.exxpress.at', 'ad-cdn_core.cctv.com',
                    'ad_core.cctv.com', 'ad_m.cctv.com')
        for source in ('surge', 'qx', 'mihomo'):
            for value in suffixes:
                for kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                    matcher = kind + ',' + value
                    text = ('payload:\n  - ' + json.dumps(matcher) if source == 'mihomo' else
                            matcher if source == 'surge' else matcher.replace('DOMAIN', 'HOST', 1) + ',REJECT')
                    parsed, messages = parse(text, purpose='block')
                    self.assertEqual((parsed, messages), ([Rule(kind, value, domain_source=source)], []))
                    for purpose in ('block', 'direct', 'proxy'):
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(source=source, value=value, kind=kind, purpose=purpose, mode=mode):
                                out, skipped = render('dns', normalize(parsed), purpose=purpose, no_resolve=mode)
                                reference, reference_skipped = render('dns', parsed, purpose='proxy', no_resolve=mode)
                                for name in out:
                                    if name != 'fin-adb.txt':
                                        self.assertEqual(out[name], reference[name])
                                        self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                                         {key: count for key, count in reference_skipped.items() if key.startswith(name + ':')})
                                self.assertEqual(parse(out['fin.yaml'], purpose=purpose),
                                                 ([Rule(kind, value, domain_source='mihomo')], []))
                                expected = '||' + value + '^' if kind == 'DOMAIN-SUFFIX' else (
                                    r'/(?s-i:\A' + value.replace('-', r'\-').replace('.', r'\.') + r'\z)/')
                                self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                                 ([expected] if source != 'mihomo' else []) if purpose == 'block' else
                                                 ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(skipped.get('fin-adb.txt:' + kind, 0), int(purpose != 'block' or source == 'mihomo'))

    def test_underscore_exact_preserves_literal_boundaries_and_go_lowercase(self):
        for value in ('AD_CORE.CCTV.COM.', 'İ_ΟΣ.K.EXAMPLE', 'ſ_ẞ.EXAMPLE'):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN', value, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(rows, [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN'], 1)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,' + value)

    def test_single_label_and_multispan_questions_match_independent_utf8_bytes(self):
        from itertools import product
        from tests.test_formats import dns_regex

        hosts = [''.join(chars) for length in range(4) for chars in product(('a', 'b', 'é', '中', '😀'), repeat=length)]
        hosts += ['a.é', 'a.中', 'a.😀', 'xads', 'ads', 'éads中', 'aé中b😀', 'a\nb', '<ads>']
        patterns = ('*', '*ads*', '?', '??', '???', '????', 'a?', 'a??', 'a???', 'a????',
                    '?*?', '*?a*', 'a?*?b*?', '*??*a??*', 'a?.?', '*<ads>*')
        for pattern in patterns:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(pattern=pattern, caller=caller):
                    rule = Rule('DOMAIN-WILDCARD', pattern, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(rows, [('@@' if caller != 'block' else '') + r'/(?s-i:\A.*\z)/']
                                     if pattern == '*' else [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0), int(pattern != '*'))
                    if pattern == '*':
                        matcher = dns_regex(rows[0])
                        for host in hosts:
                            self.assertIsNotNone(matcher.fullmatch(host), (pattern, host, caller))

    def test_surge_classes_qx_unknown_classes_and_native_literal_brackets_stay_separate(self):
        expected = r'/^ad_core\-[ab]\.example\.org$/'
        for source in ('surge', 'qx', 'mihomo'):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(source=source, caller=caller):
                    rule = Rule('DOMAIN-WILDCARD', 'ad_core-[ab].example.org', allow=caller == 'allow', domain_source=source)
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [('@@' if caller != 'block' else '') + expected] if source == 'surge' else [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0), int(source != 'surge'))
                    self.assertEqual(rule.domain_source, source)
        for source in ('surge', 'qx'):
            for pattern in ('*ads*', '*', 'a?', 'a??', '*<ads>*'):
                with self.subTest(source=source, pattern=pattern):
                    out, skipped = render('dns', [Rule('DOMAIN-WILDCARD', pattern, domain_source=source)],
                                          purpose='block', no_resolve='keep')
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)

    def test_new_exact_regex_and_single_label_native_budgets_include_wrapper_exception_and_lf(self):
        for caller in ('block', 'allow', 'whitelist'):
            exception = caller != 'block'
            cases = (('DOMAIN', '_' + 'a' * (65519 if exception else 65521)),
                     ('DOMAIN', '_' + '中' * (21839 if exception else 21840) + ('aa' if exception else 'a')),
                     ('DOMAIN', '_' + 'İ' * (65519 if exception else 65521)),
                     ('DOMAIN-WILDCARD', 'a' * (65518 if exception else 65520) + '*'),
                     ('DOMAIN-WILDCARD', 'replace=' + 'a' * (65505 if exception else 65507) + '*'))
            for kind, value in cases:
                for extra in (0, 1):
                    with self.subTest(kind=kind, first=value[:12], caller=caller, extra=extra):
                        expanded = value + 'a' * extra
                        rule = Rule(kind, expanded, allow=caller == 'allow', domain_source='mihomo')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                              no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                        rows = out['fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(rows, [])
                        self.assertEqual(skipped['fin-adb.txt:' + kind], 1)
                        self.assertEqual(rule.value, expanded)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), kind + ',' + expanded)

    def test_single_label_question_expansion_remains_bounded_under_eight_seconds(self):
        code = '''import json
import sys
from formats import render
from rules import Rule, parse
before = (sys.get_int_max_str_digits(), sys.getrecursionlimit())
for size in (17, 18, 20, 32, 65536):
    value = '?' * size
    parsed, messages = parse('payload:\\n  - ' + json.dumps('DOMAIN-WILDCARD,' + value), purpose='block')
    assert (parsed, messages) == ([Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')], [])
    for caller in ('block', 'allow', 'whitelist'):
        source = Rule('DOMAIN-WILDCARD', value, allow=caller == 'allow', domain_source='mihomo')
        out, skips = render('dns', [source] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                            whitelist=[source] if caller == 'whitelist' else [])
        rows = out['fin-adb.txt'].splitlines()[7:]
        assert rows == [], (size, caller)
        assert skips['fin-adb.txt:DOMAIN-WILDCARD'] == 1, (size, caller)
        safe = Rule('DOMAIN-WILDCARD', value + '123*', allow=caller == 'allow', domain_source='mihomo')
        out, skips = render('dns', [safe] if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                            whitelist=[safe] if caller == 'whitelist' else [])
        rows = out['fin-adb.txt'].splitlines()[7:]
        assert len(rows) == int(size != 65536), (size, caller)
        assert skips.get('fin-adb.txt:DOMAIN-WILDCARD', 0) == int(size == 65536), (size, caller)
        assert all(len(row.encode('utf-8')) + 1 <= 65536 for row in rows)
assert (sys.get_int_max_str_digits(), sys.getrecursionlimit()) == before
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, encoding='utf-8', timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_domain_logical_children_keep_order_direction_and_whole_dns_skip(self):
        for native in (False, True):
            leaf = 'DOMAIN-WILDCARD,a??' if native else 'DOMAIN,ad_core.cctv.com'
            cases = ('AND,((' + leaf + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))',
                     'OR,((' + leaf + '),(DOMAIN,neighbor.example.org))',
                     'NOT,((' + leaf + '))',
                     'AND,((NOT,((' + leaf + '))),(NETWORK,tcp))')
            for matcher in cases:
                text = 'payload:\n  - ' + json.dumps(matcher) if native else matcher
                parsed, messages = parse(text, purpose='block')
                self.assertEqual(messages, [])
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(native=native, matcher=matcher, purpose=purpose, mode=mode):
                            out, skipped = render('dns', normalize(parsed), purpose=purpose, no_resolve=mode)
                            expected = matcher.replace(',no-resolve', '') if mode == 'strip' else matcher
                            if not native:
                                expected = expected.replace('DOMAIN,ad_core.cctv.com', expected_domain('DOMAIN', 'ad_core.cctv.com')).replace(
                                    'DOMAIN,neighbor.example.org', expected_domain('DOMAIN', 'neighbor.example.org'))
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), expected)
                            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [] if purpose == 'block' else
                                             ['! No AdBlock rules for non-advertising group.'])
                            self.assertEqual(skipped['fin-adb.txt:' + parsed[0].kind], 1)
                            self.assertEqual(parse(out['fin.yaml'], purpose=purpose)[1], [])
                            if 'SRC-IP' in matcher:
                                self.assertIn('SRC-IP-CIDR,198.51.100.0/24', expected)
                                self.assertNotIn('SRC-IP-CIDR,198.51.100.0/24,no-resolve', expected)

    def test_domain_consumers_generate_publish_and_same_round_disk_dependencies(self):
        suffixes = ('piano_log.kingsoft.jp', 'imp_track.zmaticoo.com', 'fb_servpub-a.akamaihd.net',
                    'at_w_atexxpressdata-c3a3188a23.exxpress.at', 'ad-cdn_core.cctv.com',
                    'ad_core.cctv.com', 'ad_m.cctv.com')
        native_patterns = ('*ads*', '*', 'a?', 'a??', '*<ads>*')
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for native in (False, True):
            exact = 'EXACT_CORE.EXAMPLE.ORG.' if native else 'exact_core.example.org'
            patterns = [*native_patterns, '[ab]'] if native else ['ad_core-?.example.org']
            leaf = 'DOMAIN-WILDCARD,a??' if native else 'DOMAIN,exact_core.example.org'
            logic = 'AND,((' + leaf + '),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
            matchers = ['DOMAIN,' + exact, 'DOMAIN,neighbor.example.org',
                        *('DOMAIN-SUFFIX,' + value for value in suffixes),
                        *('DOMAIN-WILDCARD,' + value for value in patterns), logic,
                        'IP-CIDR,203.0.113.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24']
            white_pattern = 'w?w' if native else 'white-?.example.org'
            white_matchers = ['DOMAIN,white_core.example.org', 'DOMAIN-WILDCARD,' + white_pattern]
            if native:
                matchers += white_matchers
            source = ('payload:\n' + ''.join('  - ' + json.dumps(row) + '\n' for row in matchers) if native else
                      '\n'.join(matchers) + '\n') + '@@||allow.example.org^\n'
            white = ('payload:\n' + ''.join('  - ' + json.dumps(row) + '\n' for row in white_matchers)
                     if native else '\n'.join(white_matchers) + '\n')
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    for remote in (False, True):
                        with self.subTest(native=native, purpose=purpose, mode=mode, remote=remote), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'static').mkdir()
                            (root / 'static/source.list').write_text(source, encoding='utf-8')
                            (root / 'static/white.list').write_text(white, encoding='utf-8')
                            inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.test/white' if remote else 'static/white.list'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['https://example.test/source' if remote else 'static/source.list'],
                                        'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml']}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0\xff\r\n' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.test/source': source.encode('utf-8'),
                                         'https://example.test/white': white.encode('utf-8')}
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                clock.now.return_value = datetime(2026, 10, 14, 12, 34, tzinfo=timezone.utc)
                                output = generate(root, lambda url: responses[url])
                            self.assertEqual(len(output), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            flag = '' if mode == 'strip' else ',no-resolve'
                            expected_logic = logic.replace(',no-resolve', flag)
                            domain_rows = sorted(['DOMAIN,' + exact, 'DOMAIN,neighbor.example.org'], key=lambda row: (len(row), row))
                            suffix_rows = sorted(['DOMAIN-SUFFIX,' + value for value in suffixes], key=lambda row: (len(row), row))
                            wildcard_rows = (['DOMAIN-WILDCARD,' + value for value in patterns] if native else
                                             [r'DOMAIN-REGEX,^ad_core\-.\.example\.org\.?$'])
                            wildcard_rows.sort(key=lambda row: (len(row), row))
                            yaml = [expected_logic, *domain_rows]
                            if not native:
                                yaml += wildcard_rows
                            yaml += suffix_rows
                            if native:
                                yaml += wildcard_rows
                            yaml += ['IP-CIDR,203.0.113.0/24' + flag, 'SRC-IP-CIDR,198.51.100.0/24']
                            white_dns = []
                            if not native and purpose == 'block':
                                white_regex = r'^white\-.\.example\.org\.?$'
                                white_output, white_skips = render('white-control', [], purpose='block', no_resolve='keep',
                                                                   whitelist=[Rule('DOMAIN-REGEX', white_regex),
                                                                              Rule('DOMAIN', 'white_core.example.org', domain_source='mihomo')])
                                self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', white_skips)
                                white_dns = white_output['fin-adb.txt'].splitlines()[7:]
                            dns = [r'/(?s-i:\A.*\z)/'] if native else [
                                *white_dns, '0.0.0.0 neighbor.example.org', *('||' + value + '^' for value in suffixes),
                                r'/(?s-i:\Aexact_core\.example\.org\z)/', r'/^ad_core\-.\.example\.org$/']
                            for group in ('source', 'child'):
                                self.assertEqual(output[root / group / 'fin.yaml'], f'# {group} rules: {len(yaml)}\npayload:\n' +
                                                 ''.join('  - ' + json.dumps(row) + '\n' for row in yaml))
                                restored, warnings = parse(output[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual([rule.kind + ',' + rule.value + (',no-resolve' if rule.options else '')
                                                  for rule in restored], yaml)
                                body = dns + (['@@||allow.example.org^'] if group == 'source' else []) if purpose == 'block' else []
                                if not native and group == 'child' and purpose == 'block':
                                    controls = [Rule('DOMAIN-REGEX', r'^ad_core\-.\.example\.org\.?$')]
                                    actual, counts = render('child-control', controls, purpose='block', no_resolve='keep')
                                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', counts)
                                    body = [*white_dns, *actual['fin-adb.txt'].splitlines()[7:]]
                                    self.assertIn('child fin-adb.txt:DOMAIN: 3\n', diagnostic.getvalue())
                                    self.assertIn('child fin-adb.txt:DOMAIN-SUFFIX: 7\n', diagnostic.getvalue())
                                body.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[7:], body if purpose == 'block' else
                                                 ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[6], f'! Total count: {len(body)}')
                                if native and purpose == 'block':
                                    self.assertIn(f'{group} fin-adb.txt:DOMAIN-WILDCARD: 6\n', diagnostic.getvalue())
                                for name in names:
                                    rows = output[root / group / name].splitlines()
                                    header = 7 if name == 'fin-adb.txt' else 2 if name == 'fin.yaml' else 1
                                    count = 0 if name == 'fin-adb.txt' and purpose != 'block' else len(rows[header:])
                                    self.assertEqual(rows[6] if name == 'fin-adb.txt' else rows[0],
                                                     f'! Total count: {count}' if name == 'fin-adb.txt' else f'# {group} rules: {count}')
                                    self.assertEqual(len(rows[header:]), len(set(rows[header:])))
                                    self.assertTrue(output[root / group / name].endswith('\n'))
                                    self.assertNotIn('\r', output[root / group / name])
                                self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536
                                                    for row in output[root / group / 'fin-adb.txt'].split('\n')[:-1]))
                            publish(output, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 14, 12, 34, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in output.items() if path.parent.name != 'white'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_domain_source_partial_404_freeze_and_strict_whitelist_preserve_old_bytes(self):
        from urllib.error import HTTPError

        source = 'payload:\n  - DOMAIN-WILDCARD,*ads*\n  - DOMAIN,ad_core.cctv.com\n'
        for purpose in ('block', 'direct', 'proxy'):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                (root / 'static/source.yaml').write_text(source, encoding='utf-8')
                (root / 'static/white.yaml').write_text('payload:\n  - DOMAIN,white_core.example.org\n', encoding='utf-8')
                config = [{'name': 'dns', 'purpose': purpose, 'no_resolve': 'keep',
                           'sources': ['static/source.yaml'], 'whitelist': ['static/white.yaml']}]
                (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()):
                    output = generate(root, lambda url: self.fail(url))
                publish(output, root=root)
                old = {path: path.read_bytes() for path in output}
                config[0]['sources'] = ['static/source.yaml', 'https://example.test/missing']
                (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')

                def missing(url):
                    raise RuntimeError('source unavailable') from HTTPError(url, 404, 'Not Found', {}, None)

                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    partial = generate(root, missing)
                self.assertEqual(set(partial), set(output))
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertNotIn('frozen', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                config[0]['sources'] = ['https://example.test/missing']
                (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(generate(root, missing), {})
                self.assertIn('HTTP 404; skipped', diagnostic.getvalue())
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                config[0]['sources'] = ['static/source.yaml']
                (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                (root / 'static/white.yaml').write_text('payload:\n  - DOMAIN-WILDCARD,\n', encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                    generate(root, missing)
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                with self.assertRaisesRegex(ValueError, 'Output path targets static'):
                    publish({root / 'static/source.yaml': 'replacement'}, root=root)
                self.assertEqual((root / 'static/source.yaml').read_text(encoding='utf-8'), source)
                self.assertEqual({path: path.read_bytes() for path in old}, old)


class DnsExactConstructorTests(unittest.TestCase):
    def test_native_uppercase_exact_hosts_lowercase_only_dns(self):
        parsed, warnings = parse('payload:\n  - DOMAIN,ADS.EXAMPLE.COM', purpose='block')
        self.assertEqual(warnings, [])
        out, skipped = render('dns', normalize(parsed), purpose='block', no_resolve='keep')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,ADS.EXAMPLE.COM')
        self.assertEqual(parsed, [Rule('DOMAIN', 'ADS.EXAMPLE.COM', domain_source='mihomo')])
        self.assertEqual(skipped['fin-adb.txt:DOMAIN'], 1)

    def test_exact_hosts_use_simple_lowercase_without_context_or_length_change(self):
        for value in ('İΟΣ.K.EXAMPLE', 'ſ.ẞ.EXAMPLE', 'Ᲊ.EXAMPLE'):
            source = Rule('DOMAIN', value, domain_source='mihomo')
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(value=value, purpose=purpose, mode=mode):
                        out, _ = render('dns', [source], purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                         [] if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN,' + value)
                        self.assertEqual(source.value, value)

    def test_exact_network_allow_and_white_preserve_original_payload(self):
        value = 'ADS.EXAMPLE.COM'
        for caller in ('allow', 'whitelist'):
            with self.subTest(caller=caller):
                source = Rule('DOMAIN', value, allow=caller == 'allow', domain_source='mihomo')
                out, _ = render('dns', [source] if caller == 'allow' else [], purpose='block',
                                no_resolve='keep', whitelist=[source] if caller == 'whitelist' else [])
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(source.value, value)

    def test_uppercase_exact_generate_publish_and_yaml_dependencies_preserve_native(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['native.yaml'], 'whitelist': []},
                               {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                'sources': ['parent/fin.yaml'], 'whitelist': []}]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    (root / 'native.yaml').write_text('payload:\n  - DOMAIN,ADS.EXAMPLE.COM\n'
                                                     '  - DOMAIN,neighbor.example.com\n', encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        out = generate(root, lambda url: self.fail(url))
                    for group in ('parent', 'child'):
                        dns = out[root / group / 'fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(set(dns), set() if purpose == 'block' else
                                         {'! No AdBlock rules for non-advertising group.'})
                        self.assertIn('DOMAIN,ADS.EXAMPLE.COM',
                                      [json.loads(line[4:]) for line in out[root / group / 'fin.yaml'].splitlines()[2:]])
                    publish(out, root=root)
                    self.assertEqual({path: path.read_bytes() for path in out},
                                     {path: text.encode('utf-8') for path, text in out.items()})
                    (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        disk = generate(root, lambda url: self.fail(url))
                    for name in ('fin.yaml', 'fin-adb.txt'):
                        header = 2 if name == 'fin.yaml' else 6
                        self.assertEqual(disk[root / 'child' / name].splitlines()[header:],
                                         out[root / 'child' / name].splitlines()[header:])


class DnsRegexLiteralTests(unittest.TestCase):
    def test_replace_literal_uses_equivalent_hex_and_preserves_native_payload(self):
        value = r'^(?:replace=)?ads\.example\.com$'
        parsed, warnings = parse('DOMAIN-REGEX,' + value + ',REJECT', purpose='block')
        self.assertEqual(warnings, [])
        out, skipped = render('dns', parsed, purpose='block', no_resolve='keep')
        # ads.example.com/ads.example.com. 的 raw source 决定不同。
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
        self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)

    def test_literal_contexts_share_block_allow_and_white_without_changing_groups(self):
        cases = ((r'^(?:replace=)?ads\.example\.com$', r'^(?:replace\x{3D})?ads\.example\.com$'),
                 (r'^[=]replace=$', r'^[\x{3D}]replace\x{3D}$'),
                 (r'^replace\x{3D}$', r'^replace\x{3D}$'),
                 (r'^\\replace=$', r'^\\replace\x{3D}$'),
                 (r'^(?i:replace=)$', r'^(?i:replace\x{3D})$'),
                 (r'^(?<name>replace=)$', r'^(?:replace\x{3D})$'))
        for value, expected in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    source = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    line = ('@@' if caller != 'block' else '') + '/' + expected + '/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertNotIn('replace=', line)
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                    self.assertEqual(source.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]),
                                         'DOMAIN-REGEX,' + value)

    def test_generated_keyword_literals_remove_sentinel_in_three_consumers(self):
        for native in (False, True):
            value = 'REPLACE=' if native else 'replace='
            text = 'payload:\n  - DOMAIN-KEYWORD,' + value if native else 'DOMAIN-KEYWORD,' + value
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual(warnings, [])
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(native=native, caller=caller):
                    source = Rule(parsed[0].kind, parsed[0].value, allow=caller == 'allow',
                                  domain_source=parsed[0].domain_source)
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    expected = r'/^.*replace\x{3D}.*$/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [] if native else [('@@' if caller != 'block' else '') + expected])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-KEYWORD', 0), int(native))
                    self.assertEqual(source.value, value)

    def test_lookaround_headers_stay_unsupported_with_original_mihomo_matcher(self):
        for value in (r'^ads(?=track)$', r'^(?<=replace=)ads$'):
            with self.subTest(value=value):
                out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)],
                                      purpose='block', no_resolve='keep')
                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_literal_regex_generate_and_publish_keep_neighbors_and_real_exceptions(self):
        value = r'^(?:replace=)?ads\.example\.com$'
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for caller in ('block', 'whitelist'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(caller=caller, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = [{'name': 'dns', 'purpose': 'block', 'no_resolve': mode,
                               'sources': ['rules.list'],
                               'whitelist': ['white.list'] if caller == 'whitelist' else []}]
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    source = 'DOMAIN,neighbor.example.com\n'
                    if caller != 'whitelist':
                        source += 'DOMAIN-REGEX,' + value + '\n'
                    else:
                        (root / 'white.list').write_text('DOMAIN-REGEX,' + value, encoding='utf-8')
                    (root / 'rules.list').write_text(source, encoding='utf-8')
                    (root / 'dns').mkdir()
                    old = {root / 'dns' / name: b'old\x00' + name.encode('ascii') for name in names}
                    for path, data in old.items():
                        path.write_bytes(data)
                    with contextlib.redirect_stderr(io.StringIO()) as stderr:
                        out = generate(root, lambda url: self.fail(url))
                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                    self.assertEqual(out[root / 'dns' / 'fin-adb.txt'].splitlines()[7:],
                                     ['0.0.0.0 neighbor.example.com'])
                    self.assertIn('fin-adb.txt:DOMAIN-REGEX: 1', stderr.getvalue())
                    native = [json.loads(line[4:]) for line in out[root / 'dns' / 'fin.yaml'].splitlines()[2:]]
                    self.assertIn(expected_domain('DOMAIN', 'neighbor.example.com'), native)
                    if caller == 'block':
                        self.assertIn('DOMAIN-REGEX,' + value, native)
                    publish(out, root=root)
                    self.assertEqual({path: path.read_bytes() for path in out},
                                     {path: text.encode('utf-8') for path, text in out.items()})


class DnsBodyBudgetTests(unittest.TestCase):
    def test_safe_rawregex_uses_exact_final_line_budget_in_three_consumers(self):
        cases = (('^a', 'a'), ('^replace=', r'replace\x{3D}'), ('^中', r'\\228\\184\\173'),
                 ('^[12]', '[12]'), ('^(replace=)', r'replace\x{3D}'),
                 ('^(?:ax|ay)', '(?:ax|ay)'),
                 (r'^\x{' + '0' * 5000 + '61}replace=', r'areplace\x{3D}'),
                 ('^a{,' + '9' * 5000 + '}replace=', 'a\\{,' + '9' * 5000 + r'\}replace\x{3D}'))
        for raw, encoded in cases:
            for caller in ('block', 'allow', 'whitelist'):
                prefix = ('@@' if caller != 'block' else '') + r'/(?-i:\A'
                for rooted in (False, True):
                    suffix = r'\z)/' if rooted else ')/'
                    padding = 65536 - len((prefix + encoded + suffix + '\n').encode('utf-8'))
                    for extra in (0, 1):
                        with self.subTest(raw=raw, caller=caller, rooted=rooted, extra=extra):
                            value = raw + 'a' * (padding + extra) + (r'\.?$' if rooted else '')
                            rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                            white = parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
                            self.assertEqual(white, [Rule('DOMAIN-REGEX', value)])
                            out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                                  no_resolve='keep', whitelist=white if caller == 'whitelist' else ())
                            expected = prefix + encoded + 'a' * padding + suffix
                            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [] if extra else [expected])
                            self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), extra)
                            self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                            self.assertEqual(rule.value, value)

    def test_eighteen_native_questions_skip_only_dns_and_keep_neighbor(self):
        value = '?' * 18 + '.example.com'
        source = Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')
        neighbor = Rule('DOMAIN', 'neighbor.example.com')
        out, skipped = render('dns', [source, neighbor], purpose='block', no_resolve='keep')
        sizes = [len(line.encode('utf-8')) + 1 for line in out['fin-adb.txt'].splitlines()[7:]]
        self.assertTrue(all(size <= 65536 for size in sizes), f'DNS line sizes including LF: {sizes}')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], ['0.0.0.0 neighbor.example.com'])
        self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)
        self.assertIn('DOMAIN-WILDCARD,' + value,
                      [json.loads(line[4:]) for line in out['fin.yaml'].splitlines()[2:]])
        reference, reference_skipped = render('dns', [source, neighbor], purpose='proxy', no_resolve='keep')
        for name in out:
            if name != 'fin-adb.txt':
                self.assertEqual(out[name], reference[name])
                self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                 {key: count for key, count in reference_skipped.items() if key.startswith(name + ':')})

    def test_native_question_budget_has_public_subprocess_timeout_for_three_consumers(self):
        code = r'''
import json
from formats import render
from rules import Rule
neighbor = Rule('DOMAIN', 'neighbor.example.com')
for size in (17, 18, 20, 32, 63):
    value = '?' * size + '.example.com'
    for caller in ('block', 'allow', 'whitelist'):
        source = Rule('DOMAIN-WILDCARD', value, allow=caller == 'allow', domain_source='mihomo')
        out, skipped = render('dns', [neighbor, source] if caller != 'whitelist' else [neighbor],
                              purpose='block', no_resolve='keep',
                              whitelist=[source] if caller == 'whitelist' else [])
        rows = out['fin-adb.txt'].splitlines()[7:]
        assert all(len(row.encode('utf-8')) + 1 <= 65536 for row in rows), (size, caller)
        assert '0.0.0.0 neighbor.example.com' in rows
        assert len(rows) == 1, (size, caller, len(rows))
        assert skipped['fin-adb.txt:DOMAIN-WILDCARD'] == 1
        if caller == 'block':
            assert 'DOMAIN-WILDCARD,' + value in [json.loads(row[4:]) for row in out['fin.yaml'].splitlines()[2:]]
        assert source.value == value
value = '?' * 63 + '.' + '?' * 63 + '.' + '?' * 60 + '.example.com'
out, skipped = render('dns', [Rule('DOMAIN-WILDCARD', value, domain_source='mihomo')],
                      purpose='block', no_resolve='keep')
assert out['fin-adb.txt'].splitlines()[7:] == []
assert skipped['fin-adb.txt:DOMAIN-WILDCARD'] == 1
print('bounded native question consumers passed')
'''
        process = subprocess.run([sys.executable, '-B', '-c', code],
                                 cwd=Path(__file__).resolve().parents[1],
                                 capture_output=True, text=True, encoding='utf-8', timeout=8, check=True)
        self.assertIn('bounded native question consumers passed', process.stdout)

    def test_native_question_regex_preserves_utf8_byte_counts_and_star_spans(self):
        cases = (('?', ('a',), ('é', '中', '😀', 'aa')),
                 ('??', ('aa', 'é'), ('a', '中', '😀')),
                 ('???', ('aaa', '中', 'aé'), ('aa', '😀')),
                 ('????', ('aaaa', '😀', 'éé'), ('aaa', '中')),
                 ('?*?', ('é', '中', '😀', 'aa'), ('a',)),
                 ('?' * 17, ('a' * 17, 'a' * 7 + 'é中😀z'),
                  ('a' * 16, 'a' * 6 + 'é中😀z', 'a' * 8 + 'é中😀z')))
        for wildcard, matches, misses in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(wildcard=wildcard, matches=matches, misses=misses, caller=caller):
                    source = Rule('DOMAIN-WILDCARD', wildcard + '.example.com',
                                  allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(rows, [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-WILDCARD'], 1)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]),
                                         'DOMAIN-WILDCARD,' + wildcard + '.example.com')

    def test_final_ascii_body_boundary_uses_real_prefix_and_lf(self):
        for caller in ('block', 'allow', 'whitelist'):
            exception = caller != 'block'
            cases = (('DOMAIN', 'a' * (65531 if exception else 65527),
                      '|', '|', 'mihomo') if exception else
                     ('DOMAIN', 'a' * 65527, '0.0.0.0 ', '', 'mihomo'),
                     ('DOMAIN-SUFFIX', 'a' * (65530 if exception else 65532), '||', '^', 'mihomo'),
                     ('DOMAIN-KEYWORD', 'a' * (65525 if exception else 65527), '/^.*', '.*$/', 'surge'),
                     ('DOMAIN-KEYWORD', 'a' * (65516 if exception else 65518),
                      r'/(?s-i:\A.*', r'.*\z)/', 'mihomo'),
                     ('DOMAIN-REGEX', '^' + 'a' * (65529 if exception else 65531) + '$', '/', '/', 'mihomo'))
            for kind, value, prefix, suffix, origin in cases:
                for mode in ('add', 'strip', 'keep'):
                    for extra in (0, 1):
                        with self.subTest(caller=caller, kind=kind, origin=origin, mode=mode, extra=extra):
                            expanded = value + 'a' * extra
                            source = Rule(kind, expanded, allow=caller == 'allow', domain_source=origin)
                            out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                                  purpose='block', no_resolve=mode,
                                                  whitelist=[source] if caller == 'whitelist' else [])
                            rows = out['fin-adb.txt'].splitlines()[7:]
                            unsupported = origin == 'mihomo'
                            self.assertEqual(len(rows), int(not extra and not unsupported))
                            self.assertEqual(skipped.get('fin-adb.txt:' + kind, 0), int(bool(extra or unsupported)))
                            self.assertEqual(source.value, expanded)
                            self.assertEqual(out['fin-adb.txt'].splitlines()[6], '! Total count: ' + str(len(rows)))
                            if not extra and not unsupported:
                                expected = ('@@' if exception else '') + prefix + value + suffix
                                self.assertTrue(rows[0] == expected, 'DNS boundary matcher or prefix changed')
                                self.assertEqual(len(rows[0].encode('utf-8')) + 1, 65536)

    def test_multibyte_and_f3_expansion_use_final_bytes_in_three_consumers(self):
        for caller in ('block', 'allow', 'whitelist'):
            exception = caller != 'block'
            cases = (('DOMAIN-KEYWORD', '中' * (21841 if exception else 21842) + 'a' * (2 if exception else 1),
                      '/^.*', '.*$/', 'surge'),
                     ('DOMAIN-KEYWORD', '=' * (10920 if exception else 10921) + 'a' * (5 if exception else 1),
                      '/^.*', '.*$/', 'surge'),
                     ('DOMAIN-REGEX', '^replace=' + 'a' * (65516 if exception else 65518) + '$',
                      '/', '/', 'mihomo'))
            for kind, value, prefix, suffix, origin in cases:
                for extra in (0, 1):
                    with self.subTest(caller=caller, kind=kind, origin=origin, extra=extra, first=value[:10]):
                        expanded = value + 'a' * extra
                        source = Rule(kind, expanded, allow=caller == 'allow', domain_source=origin)
                        out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=[source] if caller == 'whitelist' else [])
                        rows = out['fin-adb.txt'].splitlines()[7:]
                        unsupported = kind == 'DOMAIN-REGEX'
                        self.assertEqual(len(rows), int(not extra and not unsupported))
                        self.assertEqual(skipped.get('fin-adb.txt:' + kind, 0), int(bool(extra or unsupported)))
                        if not extra and not unsupported:
                            expected = ('@@' if exception else '') + prefix + value.replace('=', r'\x{3D}') + suffix
                            self.assertTrue(rows[0] == expected, 'DNS literal expansion changed')
                            self.assertEqual(len(rows[0].encode('utf-8')) + 1, 65536)
                        self.assertEqual(source.value, expanded)
        for caller in ('block', 'allow', 'whitelist'):
            source = Rule('DOMAIN-REGEX', r'\w' * 4096, allow=caller == 'allow')
            out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                  purpose='block', no_resolve='keep',
                                  whitelist=[source] if caller == 'whitelist' else [])
            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
            self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
            self.assertEqual(source.value, r'\w' * 4096)

    def test_ordinary_surge_class_boundary_preserves_other_targets(self):
        for caller in ('block', 'allow', 'whitelist'):
            count = 65515 if caller == 'block' else 65513
            for extra in (0, 1):
                with self.subTest(caller=caller, extra=extra):
                    value = '[' + 'a' * (count + extra) + '].example.com'
                    parsed, warnings = parse('DOMAIN-WILDCARD,' + value, purpose='block')
                    self.assertEqual(warnings, [])
                    self.assertEqual(len(parsed), 1)
                    source = Rule(parsed[0].kind, parsed[0].value, allow=caller == 'allow')
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), 0 if extra else 1)
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-WILDCARD', 0), extra)
                    if not extra:
                        expected = ('@@' if caller != 'block' else '') + '/^[' + 'a' * count + r']\.example\.com$/'
                        self.assertTrue(rows[0] == expected, 'Surge class matcher changed')
                        self.assertEqual(len(rows[0].encode('utf-8')) + 1, 65536)
                    reference, reference_skipped = render('dns', [source] if caller != 'whitelist' else [],
                                                          purpose='proxy', no_resolve='keep')
                    for name in out:
                        if name != 'fin-adb.txt':
                            self.assertEqual(out[name], reference[name])
                            self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                             {key: count for key, count in reference_skipped.items() if key.startswith(name + ':')})

    def test_exact_body_budget_counts_constructor_output_and_original_exception(self):
        for caller in ('block', 'allow', 'whitelist'):
            value = 'İ' * 65527 if caller == 'block' else 'İ' * 32765 + 'a'
            for extra in (0, 1):
                with self.subTest(caller=caller, extra=extra):
                    source = Rule('DOMAIN', value + 'a' * extra, allow=caller == 'allow', domain_source='mihomo')
                    out, skipped = render('dns', [source] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[source] if caller == 'whitelist' else [])
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(rows, [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN'], 1)
                    self.assertEqual(source.value, value + 'a' * extra)

    def test_body_budget_generate_publish_and_yaml_dependencies_keep_other_targets(self):
        values = ['?' * size + '.example.com' for size in (17, 18)]
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for caller in ('block', 'whitelist'):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(caller=caller, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        white = ['white.yaml'] if caller == 'whitelist' else []
                        configs = [{'name': 'parent', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['native.yaml'], 'whitelist': white},
                                   {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                    'sources': ['parent/fin.yaml'], 'whitelist': white}]
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        source = 'payload:\n  - DOMAIN,neighbor.example.com\n'
                        wildcards = ''.join('  - DOMAIN-WILDCARD,' + value + '\n' for value in values)
                        (root / 'native.yaml').write_text(source + (wildcards if caller == 'block' else ''), encoding='utf-8')
                        if white:
                            (root / 'white.yaml').write_text('payload:\n' + wildcards, encoding='utf-8')
                        old = {}
                        for group in ('parent', 'child'):
                            (root / group).mkdir()
                            for name in names:
                                path = root / group / name
                                old[path] = b'old\x00' + (group + name).encode('ascii')
                                path.write_bytes(old[path])
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            out = generate(root, lambda url: self.fail(url))
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        self.assertNotIn('frozen', stderr.getvalue())
                        for group in ('parent', 'child'):
                            rows = out[root / group / 'fin-adb.txt'].splitlines()[7:]
                            self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536 for row in rows))
                            if purpose == 'block':
                                self.assertEqual(rows, [])
                                self.assertIn(group + ' fin-adb.txt:DOMAIN-WILDCARD: 2', stderr.getvalue())
                                self.assertIn(group + ' fin-adb.txt:DOMAIN: 1', stderr.getvalue())
                            else:
                                self.assertEqual(rows, ['! No AdBlock rules for non-advertising group.'])
                            native = [json.loads(row[4:]) for row in out[root / group / 'fin.yaml'].splitlines()[2:]]
                            self.assertIn('DOMAIN,neighbor.example.com', native)
                            if caller == 'block':
                                for value in values:
                                    self.assertIn('DOMAIN-WILDCARD,' + value, native)
                        publish(out, root=root)
                        self.assertEqual({path: path.read_bytes() for path in out},
                                         {path: text.encode('utf-8') for path, text in out.items()})
                        (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()):
                            disk = generate(root, lambda url: self.fail(url))
                        for name in names:
                            header = 2 if name == 'fin.yaml' else 7 if name == 'fin-adb.txt' else 1
                            self.assertEqual(disk[root / 'child' / name].splitlines()[header:],
                                             out[root / 'child' / name].splitlines()[header:])


class DnsHeaderBudgetTests(unittest.TestCase):
    def test_title_budget_includes_utf8_prefix_and_lf_in_all_purposes(self):
        source = Rule('DOMAIN', 'neighbor.example.com')
        for char, count in (('T', 65526), ('中', 21842)):
            for fallback in (False, True):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        for extra in (0, 1):
                            with self.subTest(char=char, fallback=fallback, purpose=purpose, mode=mode, extra=extra):
                                title = char * (count + extra)
                                group = title if fallback else 'dns'
                                options = {} if fallback else {'title': title}
                                if extra:
                                    with self.assertRaisesRegex(ValueError, r'fin-adb\.txt.*title.*65536') as error:
                                        render(group, [source], purpose=purpose, no_resolve=mode, **options)
                                    self.assertIn(group, str(error.exception))
                                else:
                                    out, skipped = render(group, [source], purpose=purpose, no_resolve=mode, **options)
                                    row = out['fin-adb.txt'].split('\n')[1]
                                    self.assertTrue(row == '! Title: ' + title, 'DNS title was changed')
                                    self.assertEqual(len(row.encode('utf-8')) + 1, 65536)
                                    reference, reference_skipped = render(group, [source], purpose=purpose,
                                                                        no_resolve=mode, title='short')
                                    self.assertEqual(skipped, reference_skipped)
                                    for name in out:
                                        if name != 'fin-adb.txt':
                                            self.assertEqual(out[name], reference[name])

    def test_final_dns_comments_share_the_title_line_budget(self):
        for purpose in ('block', 'direct', 'proxy'):
            for extra in (0, 1):
                with self.subTest(purpose=purpose, extra=extra):
                    title = 'short\n! ' + 'T' * (65533 + extra)
                    if extra:
                        with self.assertRaisesRegex(ValueError, r'dns: fin-adb\.txt line 3.*65536'):
                            render('dns', [], purpose=purpose, no_resolve='keep', title=title)
                    else:
                        out, _ = render('dns', [], purpose=purpose, no_resolve='keep', title=title)
                        self.assertTrue(out['fin-adb.txt'].split('\n')[2] == '! ' + 'T' * 65533)
                        self.assertEqual(len(out['fin-adb.txt'].split('\n')[2].encode('utf-8')) + 1, 65536)

    def test_complete_dns_headers_and_non_block_comment_keep_exact_output(self):
        parsed, warnings = parse('DOMAIN,blocked.example.com\n@@||allow.example.com^\nDOMAIN-KEYWORD,replace=\n',
                                 purpose='block')
        self.assertEqual(warnings, [])
        white = parse_whitelist('DOMAIN,safe.example.com')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                    clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                    out, _ = render('dns', normalize(parsed), purpose=purpose, no_resolve=mode,
                                    whitelist=white, title='中')
                    expected = ('[Adblock Plus 2.0]\n! Title: 中\n'
                                '! Homepage: https://github.com/DoingDog/rconvert\n'
                                '! Expires: 1 day\n! License: Inherits upstream licenses\n'
                                '! Version: 202601021104\n' +
                                ('! Total count: 4\n@@|safe.example.com|\n@@||allow.example.com^\n'
                                 '/^.*replace\\x{3D}.*$/\n0.0.0.0 blocked.example.com\n' if purpose == 'block' else
                                 '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))
                    self.assertEqual(out['fin-adb.txt'], expected)
                    self.assertNotIn('\r', out['fin-adb.txt'])
                    self.assertTrue(all(len(line.encode('utf-8')) + 1 <= 65536
                                        for line in out['fin-adb.txt'].split('\n')[:-1]))

    def test_title_generate_publish_and_yaml_dependencies_preserve_inputs_and_old_files(self):
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for char, count in (('T', 65526), ('中', 21842)):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    for extra in (0, 1):
                        with self.subTest(char=char, purpose=purpose, mode=mode, extra=extra), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            inputs = {root / 'static/rules.list': b'DOMAIN,neighbor.example.com\n',
                                      root / 'static/white.list': b'DOMAIN,safe.example.com\n'}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            title = char * (count + extra)
                            configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['static/rules.list'] if group != 'child' else ['dns/fin.yaml'],
                                        'whitelist': ['static/white.list'], **({'title': title} if group == 'dns' else {})}
                                       for group in ('first', 'dns', 'child')]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            self.assertEqual(load_config(root)[1]['title'], title)
                            old = {}
                            for group in ('first', 'dns', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\x00' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            with contextlib.redirect_stderr(io.StringIO()):
                                if extra:
                                    with self.assertRaisesRegex(ValueError, r'dns: fin-adb\.txt title.*65536'):
                                        publish(generate(root, lambda url: self.fail(url)), root=root)
                                else:
                                    out = generate(root, lambda url: self.fail(url))
                                    self.assertEqual(len(out), 18)
                                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                                    dns = out[root / 'dns/fin-adb.txt']
                                    self.assertTrue(dns.split('\n')[1] == '! Title: ' + title)
                                    self.assertEqual(len(dns.split('\n')[1].encode('utf-8')) + 1, 65536)
                                    self.assertTrue(all(len(line.encode('utf-8')) + 1 <= 65536
                                                        for text in (out[root / group / 'fin-adb.txt']
                                                                     for group in ('first', 'dns', 'child'))
                                                        for line in text.split('\n')[:-1]))
                                    publish(out, root=root)
                                    self.assertEqual({path: path.read_bytes() for path in out},
                                                     {path: text.encode('utf-8') for path, text in out.items()})
                                    (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                                    disk = generate(root, lambda url: self.fail(url))
                                    self.assertEqual(disk, {path: text for path, text in out.items() if path.parent.name == 'child'})
                            if extra:
                                self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_cli_title_failure_does_not_publish_any_group_or_write_static(self):
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for char, count in (('T', 65526), ('中', 21842)):
            for purpose in ('block', 'direct', 'proxy'):
                with self.subTest(char=char, purpose=purpose), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    source = root / 'static/rules.list'
                    source.write_bytes(b'DOMAIN,neighbor.example.com\n')
                    configs = [{'name': group, 'purpose': purpose, 'no_resolve': 'keep',
                                'sources': ['static/rules.list'], 'whitelist': []}
                               for group in ('first', 'dns')]
                    old = {}
                    for group in ('first', 'dns'):
                        (root / group).mkdir()
                        for name in names:
                            path = root / group / name
                            old[path] = b'old\x00' + (group + name).encode('ascii')
                            path.write_bytes(old[path])
                    for extra in (1, 0):
                        configs[1]['title'] = char * (count + extra)
                        (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                        process = subprocess.run([sys.executable, '-B', '-X', 'utf8',
                                                  str(Path(__file__).resolve().parents[1] / 'generate.py'),
                                                  '--root', str(root)], cwd=Path(__file__).resolve().parents[1],
                                                 capture_output=True, text=True, encoding='utf-8', timeout=8)
                        if extra:
                            self.assertNotEqual(process.returncode, 0)
                            self.assertIn('ValueError: dns: fin-adb.txt title', process.stderr)
                            self.assertIn('65536', process.stderr)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                        else:
                            self.assertEqual(process.returncode, 0, process.stderr)
                            self.assertTrue(all(path.read_bytes() != data for path, data in old.items()))
                            row = (root / 'dns/fin-adb.txt').read_bytes().split(b'\n')[1]
                            self.assertTrue(row == b'! Title: ' + configs[1]['title'].encode('utf-8'))
                            self.assertEqual(len(row) + 1, 65536)
                        self.assertEqual(source.read_bytes(), b'DOMAIN,neighbor.example.com\n')


class DnsRegexConsumerTests(unittest.TestCase):
    def _check_encoded(self, output, skipped, caller, supported):
        rows = output['fin-adb.txt'].splitlines()[7:]
        self.assertEqual(len(rows), int(supported))
        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(not supported))
        if rows:
            self.assertTrue(rows[0].startswith(('@@' if caller != 'block' else '') + r'/(?-i:'))
            self.assertTrue(rows[0].isascii())
            self.assertNotIn('replace=', rows[0])
            self.assertLessEqual(len(rows[0].encode('utf-8')) + 1, 65536)
        self.assertEqual(output['fin-adb.txt'].splitlines()[6], '! Total count: ' + str(int(supported)))

    def test_unicode_and_reduced_height_keep_real_white_source_and_disk_dependencies(self):
        values, canonical = [], []
        for depth in (996, 997, 998):
            repeated = '(?:' * depth + 'z' + ')?' * depth
            value = '(?:[K]x' + repeated + '|[K]y' + repeated + ')'
            values.append(value)
            if depth < 998:
                marker = '(?:)' if depth == 997 else ''
                canonical.append('(?:' + marker + '[K]x' + repeated + '|' + marker + '[K]y' + repeated + ')')
        for depth in (997, 998):
            value = '^' + '(?:' * depth + '(?:a[bc]|a[de])' + ')?' * depth + '$'
            values.append(value)
            if depth == 997:
                canonical.append(value)
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        values.append('(?:(?:a[bc]|a[de])x' + repeated + '|a[bcde]y' + repeated + ')')
        canonical.append('(?:(?:)(?:a[bc]|a[de])x' + repeated + '|(?:)a[bcde]y' + repeated + ')')
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        values.append('replace=中(?:[σ]x' + repeated + '|[Σ]y' + repeated + ')')
        canonical.append(r'replace\x{3D}中(?:[σ]x' + repeated + '|[Σ]y' + repeated + ')')
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        canonical = [r'''(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*''' + r'(?:' + r'(?:k|\\226\\132\\170)x' + repeated + r'|(?:k|\\226\\132\\170)y' + repeated + '))',
                     r'''(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*''' + r'replace\x{3D}\\228\\184\\173(?:' + r'(?:\\206\\163|\\207\\131)x' + repeated + r'|(?:\\206\\163|\\207\\131)y' + repeated + '))']
        blockers = ['DOMAIN-REGEX,^ab$', 'DOMAIN-REGEX,^kx$']
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for native in (False, True):
            for remote in (False, True):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(native=native, remote=remote, purpose=purpose, mode=mode), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            white_text = ('payload:\n' + ''.join('  - ' + json.dumps('DOMAIN-REGEX,' + value) + '\n' for value in values)
                                          if native else ''.join("DOMAIN-REGEX,'" + value + "'\n" for value in values))
                            self.assertEqual(parse(white_text, purpose=purpose), ([Rule('DOMAIN-REGEX', value) for value in values], []))
                            self.assertEqual(parse_whitelist(white_text), [Rule('DOMAIN-REGEX', value) for value in values])
                            field = values[0] if native else "'" + values[0] + "'"
                            logic = f'((DOMAIN-REGEX,{field}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            entries = ['DOMAIN,neighbor.example.test', *blockers, 'AND,' + logic]
                            source_text = ('payload:\n' + ''.join('  - ' + json.dumps(entry) + '\n' for entry in entries)
                                           if native else '\n'.join(entries) + '\n') + '@@||allow.example.test^\n'
                            inputs = {root / 'static/white.list': white_text.encode('utf-8'),
                                      root / 'static/source.list': source_text.encode('utf-8')}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            source_entry = 'https://example.test/identity-source' if remote else 'static/source.list'
                            white_entry = 'https://example.test/identity-white' if remote else 'static/white.list'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode, 'sources': [white_entry], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode, 'sources': [source_entry], 'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode, 'sources': ['white/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.test/identity-source': source_text.encode('utf-8'),
                                         'https://example.test/identity-white': white_text.encode('utf-8')}
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                output = generate(root, lambda url: responses[url])
                            self.assertEqual(len(output), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            flag = ',no-resolve' if mode != 'strip' else ''
                            expected_logic = f'AND,((DOMAIN-REGEX,{values[0]}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = ['DOMAIN-REGEX,' + value for value in values]
                            ordered = sorted(matchers, key=lambda row: (len(json.dumps(row, ensure_ascii=False)), row))
                            for group in ('white', 'source', 'child'):
                                yaml = [expected_logic, 'DOMAIN,neighbor.example.test', *blockers] if group == 'source' else ordered
                                self.assertEqual(output[root / group / 'fin.yaml'], f'# {group} rules: {len(yaml)}\npayload:\n' +
                                                 ''.join('  - ' + json.dumps(row, ensure_ascii=False) + '\n' for row in yaml))
                                restored, warnings = parse(output[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual([rule.kind + ',' + rule.value for rule in restored], yaml)
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    body = (['DOMAIN,neighbor.example.test'] if name == 'fin.txt' else
                                            ['HOST,neighbor.example.test,LIST'] if name == 'fin-qx.txt' else
                                            ['neighbor.example.test'] if name == 'fin-surge-ds.txt' else []) if group == 'source' else []
                                    if native and name in ('fin.txt', 'fin-surge-ds.txt'):
                                        body = []
                                    self.assertEqual(output[root / group / name], f'# {group} rules: {len(body)}\n' + ''.join(row + '\n' for row in body))
                                dns = ([('@@' if group == 'source' else '') + '/' + value + '/' for value in canonical] +
                                       (['@@||allow.example.test^'] +
                                        ([] if native else ['0.0.0.0 neighbor.example.test']) if group == 'source' else [])) if purpose == 'block' else []
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[7:],
                                                 dns if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[6], f'! Total count: {len(dns)}')
                                expected_skip = (len(values) - len(canonical) + (2 if group == 'source' else 0)
                                                 if purpose == 'block' else 2 if group == 'source' else len(values))
                                self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: {expected_skip}', diagnostic.getvalue())
                                self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536
                                                    for row in output[root / group / 'fin-adb.txt'].split('\n')[:-1]))
                            publish(output, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in output.items() if path.parent.name != 'white'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_unicode_and_reduced_height_share_final_utf8_f3_exception_and_lf_budget(self):
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        raw = 'replace=中(?:[σ]x' + repeated + '|[Σ]y' + repeated + ')'
        marked = r'replace\x{3D}中(?:(?:)[σ]x' + repeated + '|(?:)[Σ]y' + repeated + ')'
        reduced = '^' + '(?:' * 997 + '(?:a[bc]|a[de])' + ')?' * 997 + 'replace=中'
        reduced_dns = '^' + '(?:' * 997 + '(?:a[bc]|a[de])' + ')?' * 997 + r'replace\x{3D}中'
        for source, canonical in ((raw, marked), (reduced, reduced_dns)):
            for caller in ('block', 'allow', 'whitelist'):
                prefix = '@@/' if caller != 'block' else '/'
                padding = 65536 - len((prefix + canonical + '$/\n').encode('utf-8'))
                for extra in (0, 1):
                    with self.subTest(caller=caller, source=source[:20], extra=extra):
                        value = source + 't' * (padding + extra) + '$'
                        text = "DOMAIN-REGEX,'" + value + "'"
                        parsed, warnings = parse(text, purpose='block')
                        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                        self.assertEqual(normalize(parsed), parsed)
                        white = parse_whitelist(text)
                        self.assertEqual(white, parsed)
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                              no_resolve='keep', whitelist=white if caller == 'whitelist' else [])
                        expected = prefix + (r'replace\x{3D}' + raw.removeprefix('replace=') if source == raw else canonical) + 't' * (padding + extra) + '$/'
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65536 + extra - (8 if source == raw else 0))
                        self.assertNotIn('replace=', expected)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_unicode_property_union_cleans_existing_letter_runes_without_widening_classes(self):
        for letter in ('a', 'Σ', '中', '\U00011f04', '\U0001df25', '\U0001e4d0', '\U00031350'):
            repeated = '(?:' * 997 + 'z' + ')?' * 997
            left, right = r'[\p{L}]', r'[\p{L}\p{L}' + letter + ']'
            value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
            text = "DOMAIN-REGEX,'" + value + "'"
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            self.assertEqual(normalize(parsed), parsed)
            white = parse_whitelist(text)
            self.assertEqual(white, parsed)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(letter=letter, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, False)
                    self.assertEqual(rule.value, value)
        value = r'(?:[\p{L}]x' + repeated + r'|[\p{L}.]y' + repeated + ')'
        parsed, warnings = parse("DOMAIN-REGEX,'" + value + "'", purpose='block')
        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
        for caller in ('block', 'allow', 'whitelist'):
            rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
            out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                  no_resolve='keep', whitelist=parsed if caller == 'whitelist' else [])
            self._check_encoded(out, skipped, caller, False)

    def test_required_unicode_markers_keep_exact_f3_exception_and_lf_budget(self):
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        head, tail = '(?:replace=中[σ]x', '|replace=中[Σ]y' + repeated + ')'
        canonical_head = r'(?:(?:)replace\x{3D}中[σ]x'
        canonical_tail = r'|(?:)replace\x{3D}中[Σ]y' + repeated + ')'
        for caller in ('block', 'allow', 'whitelist'):
            prefix = '@@/' if caller != 'block' else '/'
            padding = 65536 - len((prefix + canonical_head + repeated + canonical_tail + '/\n').encode('utf-8'))
            for extra in (0, 1):
                with self.subTest(caller=caller, extra=extra):
                    value = head + 't' * (padding + extra) + repeated + tail
                    text = "DOMAIN-REGEX,'" + value + "'"
                    parsed, warnings = parse(text, purpose='block')
                    self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                    self.assertEqual(normalize(parsed), parsed)
                    white = parse_whitelist(text)
                    self.assertEqual(white, parsed)
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    expected = prefix + canonical_head + 't' * padding + repeated + canonical_tail + '/'
                    self._check_encoded(out, skipped, caller, False)
                    self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                    self.assertNotIn('replace=', expected)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_factored_concat_uses_exact_enclosing_height_and_final_byte_boundary(self):
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        raw_unicode = '(?:[σ]x' + repeated + '|[Σ]y' + repeated + ')'
        repeated = '(?:' * 994 + 'z' + ')?' * 994
        raw_run = '(?:' + '|'.join(prefix + repeated for prefix in ('abx', 'aby', 'acz')) + ')'
        for raw in (raw_unicode, raw_run):
            canonical = r'replace\x{3D}中' + raw
            for caller in ('block', 'allow', 'whitelist'):
                prefix = '@@/' if caller != 'block' else '/'
                padding = 65536 - len((prefix + canonical + '$/\n').encode('utf-8'))
                for extra in (0, 1):
                    with self.subTest(caller=caller, raw=raw[:20], extra=extra):
                        value = 'replace=中' + raw + 't' * (padding + extra) + '$'
                        text = "DOMAIN-REGEX,'" + value + "'"
                        parsed, warnings = parse(text, purpose='block')
                        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                        self.assertEqual(normalize(parsed), parsed)
                        white = parse_whitelist(text)
                        self.assertEqual(white, parsed)
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        expected = prefix + canonical + 't' * padding + '$/'
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_reduced_concat_retains_prefix_identity_for_enclosing_alternation(self):
        pairs = (('(?:a[bc]|a[de])', 'a[bcde]'),
                 ('b(?:a[bc]|a[de])', 'ba[bcde]'),
                 ('(?:[ab]c|[ab]d)', '[ab][cd]'))
        for left, right in pairs:
            for depth in (994, 995, 996, 997, 998):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
                # 连续 literal 和 class 提取各新增一层 concat，父组仅在构建时展开一层。
                parsed, warnings = parse("DOMAIN-REGEX,'" + value + "'", purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist("DOMAIN-REGEX,'" + value + "'")
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(left=left, right=right, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self._check_encoded(out, skipped, caller, depth < 997)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_reduced_concat_flattens_before_enclosing_height_check(self):
        for atom in ('(?:a[bc]|a[de])b', 'b(?:a[bc]|a[de])', '(?:a[bc]|a[de])(?:c|d)'):
            for depth in (996, 997, 998):
                value = '^' + '(?:' * depth + atom + ')?' * depth + '$'
                text = "DOMAIN-REGEX,'" + value + "'"
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                white = parse_whitelist(text)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(atom=atom, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_factored_class_reduction_propagates_legal_height_to_outer_quantifiers(self):
        for atom in ('(?:a[bc]|a[de])', '(?:a[bc]|a[bc])', '(?:a[bc]|a[de]|a[fg])'):
            for depth in (996, 997, 998):
                value = '^' + '(?:' * depth + atom + ')?' * depth + '$'
                text = "DOMAIN-REGEX,'" + value + "'"
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(text)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(atom=atom, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        # 相同 class 的前缀提取保留 concat(class, empty)，此 atom 的 Go 高度为 3。
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(out['fin-adb.txt'].splitlines()[6], '! Total count: ' + '0')
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_unicode_class_identity_requires_markers_only_at_go_height_boundary(self):
        pairs = (('[σ]', '[Σ]'), ('[K]', '[K]'), ('[µ]', '[μ]'), ('[ᲈ]', '[Ꙋ]'),
                 ('[^σ]', '[^Σ]'), (r'[\p{L}]', r'[\p{L}\p{L}]'))
        limits = sys.get_int_max_str_digits(), sys.getrecursionlimit()
        for left, right in pairs:
            for depth in (996, 997, 998):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
                marker = '(?:)' if depth == 997 else ''
                canonical = '(?:' + marker + left + 'x' + repeated + '|' + marker + right + 'y' + repeated + ')'
                text = "DOMAIN-REGEX,'" + value + "'"
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(text)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(left=left, right=right, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self._check_encoded(out, skipped, caller, depth < 997)
                        self.assertEqual(rule.value, value)
                        self.assertLess(len(('@@/' + canonical + '/\n').encode('utf-8')), 65536)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                        reference, reference_skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                                              purpose='proxy', no_resolve='keep')
                        for name in out:
                            if name != 'fin-adb.txt':
                                self.assertEqual(out[name], reference[name])
                                self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                                 {key: count for key, count in reference_skipped.items() if key.startswith(name + ':')})
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_reviewed_prefix_and_size_rules_publish_white_and_disk_dependencies(self):
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        value = '(?:(?:a|b)x' + repeated + '|[ab]y' + repeated + ')'
        marked = '(?:(?:)(?:a|b)x' + repeated + '|(?:)[ab]y' + repeated + ')'
        repeated = '(?:' * 995 + 'z' + ')?' * 995
        branches = [prefix + repeated for prefix in ('abx', 'aby', 'acz')]
        values = [value, '(?:' + '|'.join(branches) + ')']
        canonical = [marked, '(?:' + '|'.join('(?:)' + branch for branch in branches) + ')']
        values += ['(?:' + '(?:ax|ay)' * count + '){0,1000}' for count in (1000, 1678)]
        canonical.append(values[2])
        # count=1000 的完整 search 可空；三分支 depth995 保留最终高度 marker。
        prefix = r'''(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*'''
        canonical = [prefix + ')', prefix + '(?:' + '|'.join('(?:)' + branch for branch in branches) + '))']
        blocker = '^ads[.]example[.]test$'
        self.assertIsNotNone(re.match(values[2], 'ads.example.test'))
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for native in (False, True):
            for remote in (False, True):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(native=native, remote=remote, purpose=purpose, mode=mode), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            white_text = ('payload:\n' + ''.join('  - ' + json.dumps('DOMAIN-REGEX,' + item) + '\n' for item in values)
                                          if native else ''.join("DOMAIN-REGEX,'" + item + "'\n" for item in values))
                            self.assertEqual(parse(white_text, purpose=purpose), ([Rule('DOMAIN-REGEX', item) for item in values], []))
                            self.assertEqual(parse_whitelist(white_text), [Rule('DOMAIN-REGEX', item) for item in values])
                            field = values[0] if native else "'" + values[0] + "'"
                            logical = f'((DOMAIN-REGEX,{field}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            entries = ['DOMAIN,neighbor.example.test', 'DOMAIN-REGEX,' + blocker, 'AND,' + logical]
                            source_text = ('payload:\n' + ''.join('  - ' + json.dumps(entry) + '\n' for entry in entries)
                                           if native else '\n'.join(entries) + '\n') + '@@||allow.example.test^\n'
                            inputs = {root / 'static/source.list': source_text.encode('utf-8'),
                                      root / 'static/white.list': white_text.encode('utf-8')}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            source = 'https://example.test/source' if remote else 'static/source.list'
                            white = 'https://example.test/white' if remote else 'static/white.list'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [white], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source], 'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['white/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.test/source': source_text.encode('utf-8'),
                                         'https://example.test/white': white_text.encode('utf-8')}
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                output = generate(root, lambda url: responses[url])
                            self.assertEqual(len(output), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            flag = ',no-resolve' if mode != 'strip' else ''
                            expected_logic = f'AND,((DOMAIN-REGEX,{values[0]}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            ordered = sorted(['DOMAIN-REGEX,' + item for item in values], key=lambda row: (len(row), row))
                            for group in ('white', 'source', 'child'):
                                yaml = [expected_logic, 'DOMAIN,neighbor.example.test', 'DOMAIN-REGEX,' + blocker] if group == 'source' else ordered
                                self.assertEqual(output[root / group / 'fin.yaml'], f'# {group} rules: {len(yaml)}\npayload:\n' +
                                                 ''.join('  - ' + json.dumps(row) + '\n' for row in yaml))
                                restored, warnings = parse(output[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual([rule.kind + ',' + rule.value for rule in restored], yaml)
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    body = (['DOMAIN,neighbor.example.test'] if name == 'fin.txt' else
                                            ['HOST,neighbor.example.test,LIST'] if name == 'fin-qx.txt' else
                                            ['neighbor.example.test'] if name == 'fin-surge-ds.txt' else []) if group == 'source' else []
                                    if native and name in ('fin.txt', 'fin-surge-ds.txt'):
                                        body = []
                                    self.assertEqual(output[root / group / name], f'# {group} rules: {len(body)}\n' + ''.join(row + '\n' for row in body))
                                dns = ([('@@' if group == 'source' else '') + '/' + item + '/' for item in canonical] +
                                       (['@@||allow.example.test^'] +
                                        ([] if native else ['0.0.0.0 neighbor.example.test']) if group == 'source' else [])) if purpose == 'block' else []
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[7:],
                                                 dns if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[6], f'! Total count: {len(dns)}')
                                self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: ' + (str(len(values) - len(canonical) + int(group == 'source')) if purpose == 'block' else
                                               '1' if group == 'source' else str(len(values))),
                                              diagnostic.getvalue())
                                self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536
                                                    for row in output[root / group / 'fin-adb.txt'].split('\n')[:-1]))
                            publish(output, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in output.items() if path.parent.name != 'white'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_constructed_and_multibranch_markers_use_final_utf8_f3_and_lf_budget(self):
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        raw_class = '(?:(?:a|b)x' + repeated + '|[ab]y' + repeated + ')'
        marked_class = '(?:(?:)(?:a|b)x' + repeated + '|(?:)[ab]y' + repeated + ')'
        repeated = '(?:' * 994 + 'z' + ')?' * 994
        branches = [prefix + repeated for prefix in ('abx', 'aby', 'acz')]
        raw_run = '(?:' + '|'.join(branches) + ')'
        marked_run = '(?:' + '|'.join('(?:)' + branch for branch in branches) + ')'
        for raw, marked in ((raw_class, marked_class), (raw_run, marked_run)):
            for caller in ('block', 'allow', 'whitelist'):
                prefix = '@@/' if caller != 'block' else '/'
                canonical = r'replace\x{3D}中' + marked
                padding = 65536 - len((prefix + canonical + '/\n').encode('utf-8'))
                for extra in (0, 1):
                    with self.subTest(caller=caller, raw=raw[:20], extra=extra):
                        value = 'replace=中' + raw + 't' * (padding + extra)
                        text = "DOMAIN-REGEX,'" + value + "'"
                        parsed, warnings = parse(text, purpose='block')
                        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                        white = parse_whitelist(text)
                        self.assertEqual(white, parsed)
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        expected = prefix + r'replace\x{3D}中' + raw + 't' * (padding + extra) + '/'
                        self._check_encoded(out, skipped, caller, False)
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65536 + extra - (8 if raw == raw_class else 12))
                        self.assertNotIn('replace=', expected)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_factored_literal_suffix_class_reduction_keeps_go_size_boundary(self):
        limit = (128 << 20) // 40
        self.assertLess(2 * 1677 * 1000 + 1000, limit)
        self.assertGreater(2 * 1678 * 1000 + 1000, limit)
        for count in (839, 1000, 1677, 1678):
            value = '(?:' + '(?:ax|ay)' * count + '){0,1000}'
            text = "DOMAIN-REGEX,'" + value + "'"
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            self.assertEqual(normalize(parsed), parsed)
            white = parse_whitelist(text)
            self.assertEqual(white, parsed)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(count=count, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    row = ('@@' if caller != 'block' else '') + r'/(?-i:\A' + r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})''' + '*)/'
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [row] if count < 1678 else [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(count == 1678))
                    self.assertLess(len(row.encode('utf-8')) + 1, 65536)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                    reference, reference_skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                                          purpose='proxy', no_resolve='keep')
                    for name in out:
                        if name != 'fin-adb.txt':
                            self.assertEqual(out[name], reference[name])
                            self.assertEqual({key: number for key, number in skipped.items() if key.startswith(name + ':')},
                                             {key: number for key, number in reference_skipped.items() if key.startswith(name + ':')})

    def test_complete_branch_runs_accumulate_recursive_prefix_height(self):
        for depth in (994, 995, 996, 997, 998):
            repeated = '(?:' * depth + 'z' + ')?' * depth
            branches = [prefix + repeated for prefix in ('abx', 'aby', 'acz')]
            value = '(?:' + '|'.join(branches) + ')'
            text = "DOMAIN-REGEX,'" + value + "'"
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            self.assertEqual(normalize(parsed), parsed)
            white = parse_whitelist(text)
            self.assertEqual(white, parsed)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(depth=depth, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, depth < 997)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_constructed_class_and_simplefold_prefix_identity_preserves_height(self):
        pairs = (('(?:a|b)', '[ab]'), ('[^ab]', '[^ba]'), ('K', 'K'), ('ſ', 'S'), ('σ', 'Σ'))
        for left, right in pairs:
            for depth in (996, 997):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
                text = "DOMAIN-REGEX,'" + value + "'"
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(text)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(left=left, right=right, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self._check_encoded(out, skipped, caller, depth < 997)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_simple_prefix_identity_covers_fixed_singletons_negation_and_class_union(self):
        for atom in ('a{3}', '[a]{3}', '[^ab]', r'[^\x{61}\x{62}]', '(?:a|b)', r'[\p{L}]'):
            for depth in (996, 997):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + atom + 'x' + repeated + '|' + atom + 'y' + repeated + ')'
                source = "DOMAIN-REGEX,'" + value + "'"
                parsed, warnings = parse(source, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(source)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(atom=atom, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self._check_encoded(out, skipped, caller, depth < 997)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
        for atom in ('a{3}', '[ab]{3}'):
            repeated = '(?:' * 997 + 'z' + ')?' * 997
            value = '(?:' + atom + '?x' + repeated + '|' + atom + 'y' + repeated + ')'
            self.assertEqual(parse("DOMAIN-REGEX,'" + value + "'", purpose='block'), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(lazy_atom=atom, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, False)

    def test_recursive_prefix_markers_keep_final_literal_exception_and_lf_budget(self):
        repeated = '(?:' * 995 + 'z' + ')?' * 995
        raw = 'replace=(?:a[bc]x' + repeated + '|a[bc]y' + repeated + ')'
        canonical = r'replace\x{3D}(?:(?:)a[bc]x' + repeated + '|(?:)a[bc]y' + repeated + ')'
        for caller in ('block', 'allow', 'whitelist'):
            prefix = '@@/' if caller != 'block' else '/'
            padding = 65536 - len((prefix + canonical + '/\n').encode('utf-8'))
            for extra in (0, 1):
                with self.subTest(caller=caller, extra=extra):
                    value = raw + 't' * (padding + extra)
                    text = "DOMAIN-REGEX,'" + value + "'"
                    parsed, warnings = parse(text, purpose='block')
                    self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(text) if caller == 'whitelist' else [])
                    expected = prefix + r'replace\x{3D}' + raw.removeprefix('replace=') + 't' * (padding + extra) + '/'
                    self._check_encoded(out, skipped, caller, False)
                    if not extra:
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65528)
                        self.assertNotIn('replace=', expected)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_corrected_prefix_size_and_empty_rules_publish_real_white_and_disk_dependencies(self):
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        deeper = '(?:' * 997 + 'z' + ')?' * 997
        empty = '^' + '(?:' * 998 + '(?:|)' + ')?' * 998 + r'ads\.example\.test$'
        common = '[a-z]' * 1000
        too_large = '(?:' + common + 'x' + repeated + '|' + common + 'y' + repeated + '){0,1000}'
        values = ['(?:a[bc]x' + repeated + '|a[bc]y' + repeated + ')',
                  r'(?:\dx' + deeper + r'|\dy' + deeper + ')',
                  '(?:[ab]{3}x' + deeper + '|[ab]{3}y' + deeper + ')', too_large, empty]
        canonical = ['(?:(?:)a[bc]x' + repeated + '|(?:)a[bc]y' + repeated + ')',
                     r'(?:(?:)\p{Nd}x' + deeper + r'|(?:)\p{Nd}y' + deeper + ')',
                     '(?:(?:)[ab]{3}x' + deeper + '|(?:)[ab]{3}y' + deeper + ')', empty]
        for atom in ('a{3}', '[^ab]', '(?:a|b)'):
            values.append('(?:' + atom + 'x' + deeper + '|' + atom + 'y' + deeper + ')')
            canonical.append('(?:(?:)' + atom + 'x' + deeper + '|(?:)' + atom + 'y' + deeper + ')')
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        canonical = [r'''(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*''' + '(?:(?:)a[bc]x' + repeated + '|(?:)a[bc]y' + repeated + '))']
        blocker = '^ads[.]example[.]test$'
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            white_text = ('payload:\n' + ''.join('  - ' + json.dumps('DOMAIN-REGEX,' + value) + '\n' for value in values)
                                          if native else ''.join("DOMAIN-REGEX,'" + value + "'\n" for value in values))
                            self.assertEqual(parse(white_text, purpose=purpose), ([Rule('DOMAIN-REGEX', value) for value in values], []))
                            self.assertEqual(parse_whitelist(white_text), [Rule('DOMAIN-REGEX', value) for value in values])
                            field = values[0] if native else "'" + values[0] + "'"
                            logic = f'((DOMAIN-REGEX,{field}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            entries = ['DOMAIN,neighbor.example.test', 'DOMAIN-REGEX,' + (blocker if native else "'" + blocker + "'"),
                                       'AND,' + logic]
                            source_text = (('payload:\n' + ''.join('  - ' + json.dumps(entry) + '\n' for entry in entries))
                                           if native else '\n'.join(entries) + '\n') + '@@||allow.example.test^\n'
                            source_entry = 'https://example.test/corrected-source' if remote else 'static/source.list'
                            white_entry = 'https://example.test/corrected-white' if remote else 'static/white.list'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [white_entry], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source_entry], 'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['white/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            inputs = {root / 'static/source.list': source_text.encode('utf-8'),
                                      root / 'static/white.list': white_text.encode('utf-8')}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.test/corrected-source': source_text.encode('utf-8'),
                                         'https://example.test/corrected-white': white_text.encode('utf-8')}
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                output = generate(root, lambda url: responses[url])
                            self.assertEqual(len(output), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            flag = ',no-resolve' if mode != 'strip' else ''
                            expected_logic = f'AND,((DOMAIN-REGEX,{values[0]}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            ordered = sorted(['DOMAIN-REGEX,' + value for value in values], key=lambda row: (len(row), row))
                            for group in ('white', 'source', 'child'):
                                yaml = [expected_logic, 'DOMAIN,neighbor.example.test', 'DOMAIN-REGEX,' + blocker] if group == 'source' else ordered
                                self.assertEqual(output[root / group / 'fin.yaml'], f'# {group} rules: {len(yaml)}\npayload:\n' +
                                                 ''.join('  - ' + json.dumps(row) + '\n' for row in yaml))
                                restored, warnings = parse(output[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual([rule.kind + ',' + rule.value for rule in restored], yaml)
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    body = (['DOMAIN,neighbor.example.test'] if name == 'fin.txt' else
                                            ['HOST,neighbor.example.test,LIST'] if name == 'fin-qx.txt' else
                                            ['neighbor.example.test'] if name == 'fin-surge-ds.txt' else []) if group == 'source' else []
                                    if native and name in ('fin.txt', 'fin-surge-ds.txt'):
                                        body = []
                                    self.assertEqual(output[root / group / name], f'# {group} rules: {len(body)}\n' + ''.join(row + '\n' for row in body))
                                dns = ([('@@' if group == 'source' else '') + '/' + value + '/' for value in canonical] +
                                       (['@@||allow.example.test^'] +
                                        ([] if native else ['0.0.0.0 neighbor.example.test']) if group == 'source' else [])) if purpose == 'block' else []
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[7:],
                                                 dns if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[6], f'! Total count: {len(dns)}')
                                self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: ' + (str(len(values) - len(canonical) + int(group == 'source')) if purpose == 'block' else
                                              '1' if group == 'source' else str(len(values))), diagnostic.getvalue())
                                self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536
                                                    for row in output[root / group / 'fin-adb.txt'].split('\n')[:-1]))
                            publish(output, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in output.items() if path.parent.name != 'white'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_consecutive_empty_branches_keep_legal_deep_dns_exceptions(self):
        blocker = Rule('DOMAIN-REGEX', '^ads[.]example[.]test$')
        for atom in ('(?:|)', '(?:||)', '(?:|(?:)|)', '(?:|a|)'):
            for depth in (998, 999):
                value = '^' + '(?:' * depth + atom + ')?' * depth + r'ads\.example\.test$'
                text = "DOMAIN-REGEX,'" + value + "'"
                parsed, warnings = parse(text, purpose='block')
                self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(text)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(atom=atom, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                        if caller != 'block':
                            combined, count = render('dns', [blocker, rule] if caller == 'allow' else [blocker],
                                                     purpose='block', no_resolve='keep',
                                                     whitelist=white if caller == 'whitelist' else [])
                            self.assertEqual(combined['fin-adb.txt'].splitlines()[7:],
                                             [])
                            self.assertEqual(count.get('fin-adb.txt:DOMAIN-REGEX', 0), 2)

    def test_required_markers_respect_go_compiled_size_and_exact_boundary(self):
        self.assertEqual((2 * (1000 + 1 + 997 + 1) + 1) * 1000 + 1000, 4000000)
        limit = (128 << 20) // 40
        base_size = (2 * (678 + 1 + 996 + 1) + 1) * 1000 + 1000
        self.assertEqual(base_size, 3354000)
        # 外围 literal concat 增加一层；精确大小对照为它保留一层高度。
        for depth, count, padding in (
            (996, 677, 0),
            (995, 678, limit - base_size),
            (995, 678, limit - base_size + 1),
            (996, 678, 0),
            (996, 1000, 0),
        ):
            repeated = '(?:' * depth + 'z' + ')?' * depth
            common = '[a-z]' * count
            value = '(?:' + common + 'x' + repeated + '|' + common + 'y' + repeated + '){0,1000}' + 't' * padding
            canonical = '(?:(?:)' + common + 'x' + repeated + '|(?:)' + common + 'y' + repeated + '){0,1000}' + 't' * padding
            text = "DOMAIN-REGEX,'" + value + "'"
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            self.assertEqual(normalize(parsed), parsed)
            white = parse_whitelist(text)
            self.assertEqual(white, parsed)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(count=count, padding=padding, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    # count677 的 source size3354000、height1000；归约后 target size11，扫描高度6、factoring高度7。
                    nullable_supported = count == 677 and padding == 0
                    self._check_encoded(out, skipped, caller, nullable_supported)
                    if nullable_supported:
                        expected = ('@@' if caller != 'block' else '') + r'''/(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*)/'''
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [expected])
                    self.assertEqual(rule.value, value)
                    self.assertLess(len(('@@/' + canonical + '/\n').encode('utf-8')), 65536)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                    reference, reference_skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                                          purpose='proxy', no_resolve='keep')
                    for name in out:
                        if name != 'fin-adb.txt':
                            self.assertEqual(out[name], reference[name])
                            self.assertEqual({key: number for key, number in skipped.items() if key.startswith(name + ':')},
                                             {key: number for key, number in reference_skipped.items() if key.startswith(name + ':')})

    def test_recursive_prefix_factoring_preserves_go_height_pairs_in_three_consumers(self):
        cases = (('a[bc]', 995), (r'\d', 996), ('[ab]{3}', 996), ('a[bc]g[de]', 993))
        for raw, boundary in cases:
            for depth in (boundary, boundary + 1):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + raw + 'x' + repeated + '|' + raw + 'y' + repeated + ')'
                text = "DOMAIN-REGEX,'" + value + "'"
                parsed, messages = parse(text, purpose='block')
                self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(text)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(prefix=raw, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self._check_encoded(out, skipped, caller, depth < 997)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                        reference, reference_skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                                              purpose='proxy', no_resolve='keep')
                        for name in out:
                            if name != 'fin-adb.txt':
                                self.assertEqual(out[name], reference[name])
                                self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                                 {key: count for key, count in reference_skipped.items() if key.startswith(name + ':')})

    def test_go_height_keeps_scoped_foldcase_literal_boundaries(self):
        cases = (
            (997, 'a(?i:b)'),
            (998, 'a(?i:b)'),
            (997, '(?i:a)b'),
            (998, '(?i:a)b'),
            (999, 'a(?i:b)'),
            (999, '(?i:a)b'),
            (998, '(?i:ab)'),
            (998, '(?i:a(?i:b))'),
        )
        for depth, atom in cases:
            value = '^' + '(?:' * depth + atom + ')?' * depth + '$'
            source = "DOMAIN-REGEX,'" + value + "'"
            parsed, messages = parse(source, purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(depth=depth, atom=atom, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(source) if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_go_height_reduces_singleton_classes_and_single_atom_alternation(self):
        atoms = ('[a]b', '[a-a]b', r'[\x{61}]b', '[Aa]b', '(?:a|a)b', '(?:a|.)')
        for atom in atoms + ('[ab]b', '[k]b', '[s]b'):
            for depth in (997, 998, 999):
                value = '^' + '(?:' * depth + atom + ')?' * depth + '$'
                source = "DOMAIN-REGEX,'" + value + "'"
                parsed, messages = parse(source, purpose='block')
                self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
                self.assertEqual(normalize(parsed), parsed)
                white = parse_whitelist(source)
                self.assertEqual(white, parsed)
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(atom=atom, depth=depth, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=white if caller == 'whitelist' else [])
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_prefix_factoring_keeps_large_repeat_compilable_and_shallow_output_unchanged(self):
        common = '[a-z]' * 500
        left = common + '[b-z]' * 1200 + 'd'
        right = common + '[c-z]' * 1200 + 'e'
        value = '^(?:' + left + '|' + right + '){0,1000}ads[.]example[.]test$'
        self.assertEqual((500 + 2 * 1201 + 1) * 1000 + 1000 + 16 + 2, 2904018)
        self.assertEqual((2 * (500 + 1200 + 1 + 1) + 1) * 1000 + 1000 + 16 + 2, 3406018)
        self.assertLess(2904018, (128 << 20) // 40)
        self.assertGreater(3406018, (128 << 20) // 40)
        for expression in (value, '^(?:ax|ay)$', '^(?:ads|track)$', '(?:a?b|c?)'):
            source = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + expression)
            parsed, messages = parse(source, purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', expression)], []))
            white = parse_whitelist(source)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(length=len(expression), caller=caller):
                    rule = Rule('DOMAIN-REGEX', expression, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, expression == '(?:a?b|c?)')
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + expression)
                    self.assertTrue(all(len(line.encode('utf-8')) + 1 <= 65536
                                        for line in out['fin-adb.txt'].split('\n')[:-1]))
        self.assertIsNotNone(re.fullmatch(value, 'ads.example.test'))

    def test_go_height_normalizes_literal_prefix_factoring_without_a_second_parser(self):
        for depth in (996, 997, 998):
            repeated = '(?:' * depth + 'z' + ')?' * depth
            value = '(?:ax' + repeated + '|ay' + repeated + ')'
            text = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
            parsed, messages = parse(text, purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
            white = parse_whitelist(text)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(depth=depth, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, depth < 997)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                    self.assertEqual(rule.value, value)

    def test_factoring_markers_account_for_enclosing_height_and_common_prefix(self):
        repeated = '(?:' * 600 + 'z' + ')?' * 600
        inner = '(?:ax' + repeated + '|ay' + repeated + ')'
        marked = '(?:(?:)ax' + repeated + '|(?:)ay' + repeated + ')'
        cases = [(('(?:' * outer + inner + ')?' * outer),
                  ('(?:' * outer + (marked if outer == 397 else inner) + ')?' * outer) if outer < 398 else None)
                 for outer in (396, 397, 398)]
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        cases += [('(?:a' + repeated + '|a' + repeated + ')', '(?:a' + repeated + '|a' + repeated + ')'),
                  ('(?:ax' + repeated + '|by' + repeated + ')', '(?:ax' + repeated + '|by' + repeated + ')')]
        for value, expected in cases:
            parsed, warnings = parse("DOMAIN-REGEX,'" + value + "'", purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(length=len(value), caller=caller, supported=expected is not None):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=parsed if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, expected is not None and not value.startswith('(?:ax'))
                    self.assertEqual(rule.value, value)

    def test_go_height_rejects_repeated_group_boundary_only_in_dns_consumers(self):
        limits = sys.get_int_max_str_digits(), sys.getrecursionlimit()
        for depth in (998, 999, 1000):
            for suffix in (')?', '){1}'):
                for prefix in ('(?:', '(', '(?i:'):
                    value = '^' + prefix * depth + r'ads\.example\.test' + suffix * depth + '$'
                    for native in (False, True):
                        text = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value) if native else
                                "DOMAIN-REGEX,'" + value + "'")
                        parsed, messages = parse(text, purpose='block')
                        self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
                        white = parse_whitelist(text)
                        self.assertEqual(white, parsed)
                        for caller in ('block', 'allow', 'whitelist'):
                            with self.subTest(depth=depth, suffix=suffix, prefix=prefix, native=native, caller=caller):
                                rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow',
                                            domain_source=parsed[0].domain_source)
                                out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                                      purpose='block', no_resolve='keep',
                                                      whitelist=white if caller == 'whitelist' else [])
                                self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                                self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                                self.assertEqual(rule.value, value)
                                if caller == 'block':
                                    self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                                reference, reference_skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                                                      purpose='proxy', no_resolve='keep')
                                for name in out:
                                    if name != 'fin-adb.txt':
                                        self.assertEqual(out[name], reference[name])
                                        self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                                         {key: count for key, count in reference_skipped.items() if key.startswith(name + ':')})
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_go_height_counts_operators_and_preserves_flattened_groups(self):
        cases = ((998, 'ads', ')??', '^', '$', True),
                 (999, 'ads', ')??', '^', '$', False),
                 (998, 'ads', ')*', '^', '$', True),
                 (999, 'ads', ')+', '^', '$', False),
                 (998, 'ads', '){0}', '^', '$', True),
                 (999, 'ads', '){0}', '^', '$', False),
                 (999, 'ads', ')?', '', '', True),
                 (1000, 'ads', ')?', '', '', False),
                 (996, 'ads.*', ')?', '^', '$', True),
                 (997, 'ads.*', ')?', '^', '$', False),
                 (995, '(?:a?b|c?)', ')?', '^', '$', True),
                 (996, '(?:a?b|c?)', ')?', '^', '$', False),
                 (998, r'[()\x{3D}]', ')?', r'\A', r'\z', True))
        for depth, atom, suffix, start, end, supported in cases:
            value = start + '(?:' * depth + atom + suffix * depth + end
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(depth=depth, atom=atom, suffix=suffix, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                    self._check_encoded(out, skipped, caller, not end and supported)
                    self.assertEqual(rule.value, value)
        for prefix in ('(?:a?', '(?:a|', '(?:'):
            value = '^' + prefix * 1000 + 'ads' + ')' * 1000 + '$'
            out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
            self._check_encoded(out, skipped, 'block', False)

    def test_go_height_generate_publish_and_white_dependencies_keep_six_products(self):
        values = ['^' + '(?:' * depth + r'ads\.example\.test' + suffix * depth + '$'
                  for depth in (998, 999, 1000) for suffix in (')?', '){1}')]
        whites = ['^' + '(?:' * depth + r'white\.example\.test' + suffix * depth + '$'
                  for depth in (998, 999, 1000) for suffix in (')?', '){1}')]
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        white_text = 'payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in
                                           ['DOMAIN,safe-height.example.test'] + ['DOMAIN-REGEX,' + value for value in whites])
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            regex_field = values[-1] if native else "'" + values[-1] + "'"
                            logic = f'((DOMAIN-REGEX,{regex_field}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            flag = ',no-resolve' if mode != 'strip' else ''
                            expected_logic = f'AND,((DOMAIN-REGEX,{values[-1]}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = ['DOMAIN-REGEX,' + (value if native else "'" + value + "'") for value in values]
                            matchers += ['DOMAIN,neighbor.example.test', 'AND,' + logic,
                                         'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24']
                            source_text = ('payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)
                                           if native else '\n'.join(matchers) + '\n') + '@@||allow.example.test^\n'
                            source_entry = 'https://example.test/height-source' if remote else 'static/source.list'
                            white_entry = 'https://example.test/height-white' if remote else 'static/white.yaml'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['static/white.yaml'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source_entry], 'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': [white_entry]}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            inputs = {root / 'static/source.list': source_text.encode('utf-8'),
                                      root / 'static/white.yaml': white_text.encode('utf-8')}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.test/height-source': source_text.encode('utf-8'),
                                         'https://example.test/height-white': white_text.encode('utf-8')}
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                outputs = generate(root, lambda url: responses[url])
                            self.assertEqual(len(outputs), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            for group in ('source', 'child'):
                                yaml_matchers = ([expected_logic, 'DOMAIN,neighbor.example.test'] +
                                                 sorted(['DOMAIN-REGEX,' + value for value in values],
                                                        key=lambda row: (len(json.dumps(row)), row)) +
                                                 ['IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP-CIDR,198.51.100.0/24'])
                                body = {'fin.txt': (['DOMAIN,neighbor.example.test'] if not native and group == 'source' else []) +
                                                   ['IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,198.51.100.0/24'],
                                        'fin-qx.txt': ['HOST,neighbor.example.test,LIST'] +
                                                      ['IP-CIDR,192.0.2.0/24,LIST' + flag],
                                        'fin.yaml': ['  - ' + json.dumps(matcher) for matcher in yaml_matchers],
                                        'fin-surge.txt': ['IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,198.51.100.0/24'],
                                        'fin-surge-ds.txt': ['neighbor.example.test'] if not native and group == 'source' else []}
                                for name, rows in body.items():
                                    expected = f'# {group} rules: {len(rows)}\n' + ('payload:\n' if name == 'fin.yaml' else '')
                                    self.assertEqual(outputs[root / group / name], expected + ''.join(row + '\n' for row in rows))
                                dns = ['0.0.0.0 neighbor.example.test'] if purpose == 'block' and not native and group == 'source' else []
                                if purpose == 'block' and group == 'source':
                                    dns.append('@@||allow.example.test^')
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(outputs[root / group / 'fin-adb.txt'].splitlines()[7:],
                                                 dns if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(outputs[root / group / 'fin-adb.txt'].splitlines()[6], '! Total count: ' + str(len(dns)))
                                self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: ' + str(12 if purpose == 'block' else 6), diagnostic.getvalue())
                                restored, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(messages, [])
                                self.assertEqual([rule.kind + ',' + rule.value + (',no-resolve' if rule.options else '') for rule in restored], yaml_matchers)
                            self.assertEqual(outputs[root / 'white/fin-adb.txt'].splitlines()[7:],
                                             [] if purpose == 'block' else
                                             ['! No AdBlock rules for non-advertising group.'])
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_reduced_height_and_large_factoring_generate_publish_and_disk_dependencies(self):
        atoms = ('a(?i:b)', '(?i:a)b', '[a]b', '[a-a]b', r'[\x{61}]b', '[Aa]b', '(?:a|a)b', '(?:a|.)')
        values = ['^' + '(?:' * 998 + atom + ')?' * 998 + '$' for atom in atoms]
        common = '[a-z]' * 500
        values.append('^(?:' + common + '[b-z]' * 1200 + 'd|' + common + '[c-z]' * 1200 +
                      'e){0,1000}ads[.]example[.]test$')
        matchers = ['DOMAIN-REGEX,' + value for value in values]
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            text = ('payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)
                                    if native else ''.join("DOMAIN-REGEX,'" + value + "'\n" for value in values))
                            self.assertEqual(parse(text, purpose=purpose), ([Rule('DOMAIN-REGEX', value) for value in values], []))
                            self.assertEqual(parse_whitelist(text), [Rule('DOMAIN-REGEX', value) for value in values])
                            source = 'https://example.test/reduced-height' if remote else 'static/input.list'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source, 'static/neighbor.list'], 'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['white/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            inputs = {root / 'static/input.list': text.encode('utf-8'),
                                      root / 'static/neighbor.list': b'DOMAIN,neighbor.example.test\n'}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            def fetch(url):
                                self.assertEqual(url, 'https://example.test/reduced-height')
                                return text.encode('utf-8')
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                output = generate(root, fetch)
                            self.assertEqual(len(output), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            ordered = sorted(matchers, key=lambda row: (len(row), row))
                            for group in ('white', 'source', 'child'):
                                yaml = [expected_domain('DOMAIN', 'neighbor.example.test')] if group == 'source' else ordered
                                expected_yaml = f'# {group} rules: {len(yaml)}\npayload:\n' + ''.join(
                                    '  - ' + json.dumps(matcher) + '\n' for matcher in yaml)
                                self.assertEqual(output[root / group / 'fin.yaml'], expected_yaml)
                                self.assertEqual(parse(output[root / group / 'fin.yaml'], purpose=purpose),
                                                 ([Rule('DOMAIN', 'neighbor.example.test', domain_source='mihomo')]
                                                  if group == 'source' else [Rule('DOMAIN-REGEX', row.partition(',')[2]) for row in ordered], []))
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    body = (['DOMAIN,neighbor.example.test'] if name == 'fin.txt' else
                                            ['HOST,neighbor.example.test,LIST'] if name == 'fin-qx.txt' else
                                            ['neighbor.example.test'] if name == 'fin-surge-ds.txt' else []) if group == 'source' else []
                                    self.assertEqual(output[root / group / name], f'# {group} rules: {len(body)}\n' +
                                                     ''.join(row + '\n' for row in body))
                                dns = ((['0.0.0.0 neighbor.example.test'] if group == 'source' else [])) if purpose == 'block' else []
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[7:],
                                                 dns if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[6], f'! Total count: {len(dns)}')
                                if purpose == 'block':
                                    self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: {len(values)}', diagnostic.getvalue())
                            publish(output, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, fetch)
                            self.assertEqual(disk, {path: text for path, text in output.items() if path.parent.name != 'white'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_complete_regex_generate_publish_and_white_dependencies_keep_six_products(self):
        zeroes = '0' * 5000
        values = ('a{' + zeroes + '1}', r'^\x{' + zeroes + '61}$',
                  '^a{,' + '9' * 5000 + '}$', '^' + '(?:' * 1000 + 'ads' + ')' * 1000 + '$')
        dns_values = (r'''(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*''' + '(?:a){1})',)
        white_value = r'^\x{' + zeroes + '62}$'
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                for native in (False, True):
                    for remote in (False, True):
                        with self.subTest(purpose=purpose, mode=mode, native=native, remote=remote), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            flag = ',no-resolve' if mode != 'strip' else ''
                            field = values[1] if native else "'" + values[1] + "'"
                            logic = f'((DOMAIN-REGEX,{field}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            expected_logic = f'AND,((DOMAIN-REGEX,{values[1]}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            matchers = ['DOMAIN-REGEX,' + (value if native else "'" + value + "'") for value in values]
                            matchers += ['PROCESS-NAME-REGEX,' + (values[0] if native else "'" + values[0] + "'"),
                                         'PROCESS-PATH-REGEX,' + (values[1] if native else "'" + values[1] + "'"),
                                         'AND,' + logic, 'DOMAIN,neighbor.example.com', 'DOMAIN,covered.example.com',
                                         'IP-CIDR,192.0.2.0/24,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24']
                            source = ('payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in matchers)
                                      if native else '\n'.join(matchers) + '\n') + '@@||allow.example.net^\n'
                            white_source = 'payload:\n' + ''.join('  - ' + json.dumps(matcher) + '\n' for matcher in
                                                                  ('DOMAIN-REGEX,' + white_value, 'DOMAIN,covered.example.com'))
                            external_value = '^other{,' + '9' * 5000 + '}$'
                            external = "DOMAIN-REGEX,'" + external_value + "'\n"
                            source_entry = 'https://example.com/source' if remote else 'static/source.list'
                            white_entry = 'https://example.com/white' if remote else 'static/extra-white.list'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['static/white.yaml'], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source_entry], 'whitelist': ['white/fin.yaml', white_entry]},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['source/fin.yaml'], 'whitelist': ['white/fin.yaml', white_entry]}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            inputs = {root / 'static/source.list': source.encode('utf-8'),
                                      root / 'static/white.yaml': white_source.encode('utf-8'),
                                      root / 'static/extra-white.list': external.encode('utf-8')}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.com/source': source.encode('utf-8'),
                                         'https://example.com/white': external.encode('utf-8')}
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                outputs = generate(root, lambda url: responses[url])
                            self.assertEqual(list(outputs), [root / group / name for group in ('white', 'source', 'child') for name in names])
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            raw_regex = ['DOMAIN-REGEX,' + value for value in values]
                            for group in ('source', 'child'):
                                domains = (['covered.example.com'] if not native else []) + ['neighbor.example.com']
                                yaml_matchers = ([expected_logic, 'DOMAIN,neighbor.example.com'] +
                                                 sorted(raw_regex, key=lambda matcher: (len(json.dumps(matcher)), matcher)) +
                                                 ['PROCESS-NAME-REGEX,' + values[0], 'PROCESS-PATH-REGEX,' + values[1],
                                                  'IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP-CIDR,198.51.100.0/24'])
                                body = {'fin.txt': (['DOMAIN,' + domain for domain in domains] if not native and group == 'source' else []) +
                                                  ['IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,198.51.100.0/24'],
                                        'fin-qx.txt': ['HOST,' + domain + ',LIST' for domain in
                                                       (domains if group == 'source' else ['neighbor.example.com'])] +
                                                     ['IP-CIDR,192.0.2.0/24,LIST' + flag],
                                        'fin.yaml': ['  - ' + json.dumps(matcher) for matcher in yaml_matchers],
                                        'fin-surge.txt': ['IP-CIDR,192.0.2.0/24' + flag, 'SRC-IP,198.51.100.0/24'],
                                        'fin-surge-ds.txt': domains if not native and group == 'source' else []}
                                for name, rows in body.items():
                                    expected = f'# {group} rules: {len(rows)}\n' + ('payload:\n' if name == 'fin.yaml' else '')
                                    self.assertEqual(outputs[root / group / name], expected + ''.join(row + '\n' for row in rows))
                                dns = (['/' + value + '/' for value in dns_values] +
                                       (['0.0.0.0 ' + domain for domain in domains] if not native and group == 'source' else [])
                                       if purpose == 'block' else [])
                                if purpose == 'block' and group == 'source':
                                    dns.append('@@||allow.example.net^')
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                expected_dns = (f'[Adblock Plus 2.0]\n! Title: {group}\n'
                                                '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
                                                '! License: Inherits upstream licenses\n! Version: 202601021104\n'
                                                f'! Total count: {len(dns)}\n' + ''.join(row + '\n' for row in dns) +
                                                ('! No AdBlock rules for non-advertising group.\n' if purpose != 'block' else ''))
                                self.assertEqual(outputs[root / group / 'fin-adb.txt'], expected_dns)
                                self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536 for row in expected_dns.split('\n')[:-1]))
                                restored, messages = parse(outputs[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(messages, [])
                                self.assertEqual([rule.kind + ',' + rule.value + (',no-resolve' if rule.options else '') for rule in restored],
                                                 yaml_matchers)
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    self.assertIn(f'{group} {name}:DOMAIN-REGEX: {4}', diagnostic.getvalue())
                                raw_skip = 5 if purpose == 'block' else 4
                                if raw_skip:
                                    self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: {raw_skip}', diagnostic.getvalue())
                                else:
                                    self.assertNotIn(f'{group} fin-adb.txt:DOMAIN-REGEX:', diagnostic.getvalue())
                            publish(outputs, root=root)
                            published = {path: path.read_bytes() for path in outputs}
                            self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name == 'child'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in published}, published)
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_numeric_quantifiers_keep_distinct_source_and_go_repeat_limits(self):
        prefix = r'(?-i:\A' + r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})''' + '*'
        cases = (('a{' + '0' * 5000 + '1}', '(?:a){1}'),
                 ('a{' + '0' * 5000 + '1,' + '0' * 5000 + '2}', '(?:a){1,2}'),
                 ('a{1000}', '(?:a){1000}'), ('a{1001}', None),
                 ('a{2147483647}', None), ('(?:a{20}){50}', '(?:(?:a){20}){50}'),
                 ('(?:a{20}){51}', None), ('(?:a{0500}){00}', ''),
                 ('(?:(?:a{500}){0,}){3}', None),
                 ('(?:a{0}){1000}', ''),
                 ('(?:(?:a{0}){1000}){2}', None),
                 ('(?:(?:a{500}){0}){3}', ''),
                 ('(?:(?:(?:a{500}){0}){1000}){2}', None))
        limits = sys.get_int_max_str_digits(), sys.getrecursionlimit()
        for value, expected in cases:
            expected = prefix + expected + ')' if expected is not None else None
            parsed, messages = parse("DOMAIN-REGEX,'" + value + "'", purpose='block')
            self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(length=len(value), tail=value[-20:], caller=caller):
                    out, skipped = render('dns', [Rule('DOMAIN-REGEX', value, allow=caller == 'allow')]
                                          if caller != 'whitelist' else [], purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist("DOMAIN-REGEX,'" + value + "'")
                                          if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [] if expected is None else
                                     [('@@' if caller != 'block' else '') + '/' + expected + '/'])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(expected is None))
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
        for value in ('a{2147483648}', 'a{1,2147483648}', 'a{' + '9' * 5000 + '}', 'a{2,1}'):
            with self.subTest(tail=value[-20:]):
                parsed, messages = parse("DOMAIN-REGEX,'" + value + "'\nDOMAIN,neighbor.example.com", purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.com')])
                self.assertEqual(messages, ['line 1: invalid DOMAIN-REGEX ' + value])
        self.assertEqual((sys.get_int_max_str_digits(), sys.getrecursionlimit()), limits)

    def test_leading_zero_hex_uses_canonical_dns_escape_in_three_consumers(self):
        for zeroes in (7, 5000):
            value = r'^\x{' + '0' * zeroes + r'61}ds\.example\.test$'
            source = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
            parsed, messages = parse(source, purpose='block')
            self.assertEqual(messages, [])
            self.assertEqual(parsed, [Rule('DOMAIN-REGEX', value)])
            white = parse_whitelist(source)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(zeroes=zeroes, caller=caller):
                    selected = [Rule('DOMAIN-REGEX', value, allow=caller == 'allow')]
                    out, skipped = render('dns', selected if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                    self.assertEqual(parsed[0].value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]),
                                         'DOMAIN-REGEX,' + value)

    def test_literal_brace_with_long_digits_preserves_block_allow_and_white(self):
        for digit in ('0', '9'):
            value = '^a{,' + digit * 5000 + r'}\.example\.test$'
            source = "DOMAIN-REGEX,'" + value + "'"
            parsed, messages = parse(source, purpose='block')
            self.assertEqual(messages, [])
            self.assertEqual(parsed, [Rule('DOMAIN-REGEX', value)])
            white = parse_whitelist(source)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(digit=digit, caller=caller):
                    selected = [Rule('DOMAIN-REGEX', value, allow=caller == 'allow')]
                    out, skipped = render('dns', selected if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=white if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:],
                                     [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                    self.assertEqual(parsed[0].value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]),
                                         'DOMAIN-REGEX,' + value)

    def test_literal_brace_white_generate_publish_and_yaml_dependency(self):
        value = '^a{,' + '9' * 5000 + r'}\.example\.test$'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = [{'name': group, 'purpose': 'block', 'no_resolve': 'keep',
                        'sources': ['rules.list'] if group == 'parent' else ['parent/fin.yaml'],
                        'whitelist': ['white.list']} for group in ('parent', 'child')]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            (root / 'rules.list').write_bytes(b'DOMAIN,neighbor.example.com\n')
            (root / 'white.list').write_text("DOMAIN-REGEX,'" + value + "'", encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                out = generate(root, lambda url: self.fail(url))
            self.assertIn('parent fin-adb.txt:DOMAIN-REGEX: 1\n', stderr.getvalue())
            self.assertIn('child fin-adb.txt:DOMAIN-REGEX: 1\n', stderr.getvalue())
            for group in ('parent', 'child'):
                rows = out[root / group / 'fin-adb.txt'].splitlines()[7:]
                self.assertEqual(rows, ['0.0.0.0 neighbor.example.com'] if group == 'parent' else [])
                if group == 'child':
                    self.assertIn('child fin-adb.txt:DOMAIN: 1\n', stderr.getvalue())
            publish(out, root=root)
            self.assertEqual({path: path.read_bytes() for path in out},
                             {path: text.encode('utf-8') for path, text in out.items()})
            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                disk = generate(root, lambda url: self.fail(url))
            for name in out:
                if name.parent.name == 'child':
                    header = 7 if name.name == 'fin-adb.txt' else 2 if name.name == 'fin.yaml' else 1
                    self.assertEqual(disk[name].splitlines()[header:], out[name].splitlines()[header:])

    def test_hex_class_escape_and_invalid_boundaries_remain_target_local(self):
        zeroes = '0' * 5000
        cases = (
            r'^[' + r'\x{' + zeroes + r'61}-\x{' + zeroes + r'63}]$',
            r'^[' + r'\x{' + zeroes + r'28}\x{' + zeroes + r'29}]$',
            r'^\x{' + zeroes + r'5C}\x{' + zeroes + r'3d}$',
            r'^\x{' + zeroes + '}$',
            r'^\x{' + zeroes + '7f}$',
            r'^\x{' + zeroes + '80}$',
            r'^\x{' + zeroes + '10ffff}$',
            r'^\x{}$',
            r'^\x{g}$',
            r'^\x{61$',
            r'^\x{' + zeroes + '110000}$',
            r'^\\x{' + zeroes + '61}$',
        )
        for value in cases:
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(tail=value[-20:], caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=[rule] if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
        for value in (r'^\x{}$', r'^\x{g}$', r'^\x{61$', r'^\x{' + zeroes + '110000}$'):
            with self.subTest(invalid=value[-20:]):
                parsed, messages = parse("DOMAIN-REGEX,'" + value + "'\nDOMAIN,neighbor.example.com", purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.com')])
                self.assertEqual(len(messages), 1)

    def test_portable_deep_groups_share_public_parser_and_dns_timeout(self):
        from tests.test_formats import DnsDeepRegexFormatTests

        for depth in (600, 1000):
            for prefix, dns_prefix in (('(', '(?:'), ('(?:', '(?:'), ('(?i:', '(?i:')):
                with self.subTest(depth=depth, prefix=prefix):
                    DnsDeepRegexFormatTests()._run_deep(depth, prefix=prefix, dns_prefix=dns_prefix)

    def test_deep_regexp2_only_groups_and_repeats_skip_only_dns(self):
        atoms = (r'(?=ads)ads', r'(?<=a)ds', r'(ads)\1', r'(?<ad>ads)\k<ad>',
                 r'(?>ads)', r'(a)(?(1)ds|bc)', r'(?n:ads)', r'(?x:ads)',
                 r'(?:a{500}){3}', r'a{1001}')
        for depth in (600, 1000):
            for atom in atoms:
                value = '^' + '(?:' * depth + atom + ')' * depth + '$'
                parsed, messages = parse('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value), purpose='block')
                self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
                for caller in ('block', 'allow', 'whitelist'):
                    with self.subTest(depth=depth, atom=atom, caller=caller):
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value))
                                              if caller == 'whitelist' else [])
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
        value = '^' + '(?:' * 1000 + '(?:a{20}){50}' + ')' * 1000 + '$'
        out, skipped = render('dns', [Rule('DOMAIN-REGEX', value)], purpose='block', no_resolve='keep')
        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
        self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)

    def test_canonical_groups_and_branches_use_final_utf8_budget_in_three_consumers(self):
        cases = (('^(replace=)', r'^(?:replace\x{3D})'),
                 ('^(?:ax|ay)', '^(?:ax|ay)'))
        for caller in ('block', 'allow', 'whitelist'):
            prefix = '@@/' if caller != 'block' else '/'
            for raw, canonical in cases:
                padding = 65536 - len((prefix + canonical + '$/\n').encode('utf-8'))
                for extra in (0, 1):
                    with self.subTest(caller=caller, raw=raw, extra=extra):
                        value = raw + 'a' * (padding + extra) + '$'
                        source = "DOMAIN-REGEX,'" + value + "'"
                        parsed, messages = parse(source, purpose='block')
                        self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=parse_whitelist(source) if caller == 'whitelist' else [])
                        expected = prefix + canonical + 'a' * padding + '$/'
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        if not extra:
                            self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_required_factoring_markers_share_final_f3_exception_and_lf_budget(self):
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        raw = 'replace=(?:ax' + repeated + '|ay' + repeated + ')'
        canonical = r'replace\x{3D}(?:(?:)ax' + repeated + '|(?:)ay' + repeated + ')'
        for caller in ('block', 'allow', 'whitelist'):
            prefix = '@@/' if caller != 'block' else '/'
            padding = 65536 - len((prefix + canonical + '/\n').encode('utf-8'))
            for extra in (0, 1):
                with self.subTest(caller=caller, extra=extra):
                    value = raw + 'a' * (padding + extra)
                    source = "DOMAIN-REGEX,'" + value + "'"
                    parsed, warnings = parse(source, purpose='block')
                    self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                          purpose='block', no_resolve='keep',
                                          whitelist=parse_whitelist(source) if caller == 'whitelist' else [])
                    expected = prefix + r'replace\x{3D}' + raw.removeprefix('replace=') + 'a' * (padding + extra) + '/'
                    self._check_encoded(out, skipped, caller, False)
                    if not extra:
                        self.assertEqual(len(expected.encode('utf-8')) + 1, 65528)
                        self.assertNotIn('replace=', expected)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_literal_and_canonical_hex_budgets_include_f3_wrapper_exception_and_lf(self):
        zeroes = '0' * 5000
        cases = (('^a{,' + '9' * 5000 + '}replace=', '^a{,' + '9' * 5000 + r'}replace\x{3D}'),
                 (r'^\x{' + zeroes + '61}replace=', r'^\x{61}replace\x{3D}'))
        for caller in ('block', 'allow', 'whitelist'):
            prefix = '@@/' if caller != 'block' else '/'
            for raw, canonical in cases:
                padding = 65536 - len((prefix + canonical + '$/\n').encode('utf-8'))
                for extra in (0, 1):
                    with self.subTest(caller=caller, raw=raw[:10], extra=extra):
                        value = raw + 'a' * (padding + extra) + '$'
                        parsed, messages = parse("DOMAIN-REGEX,'" + value + "'", purpose='block')
                        self.assertEqual((parsed, messages), ([Rule('DOMAIN-REGEX', value)], []))
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [],
                                              purpose='block', no_resolve='keep',
                                              whitelist=[rule] if caller == 'whitelist' else [])
                        expected = prefix + canonical + 'a' * padding + '$/'
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        if not extra:
                            self.assertEqual(len(expected.encode('utf-8')) + 1, 65536)
                            self.assertNotIn('replace=', expected)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)


class DnsClassReductionAuditTests(unittest.TestCase):
    def _check_consumers(self, value, canonical, matches=(), misses=('q.123',)):
        from tests.test_formats import dns_regex

        # 此 helper 的深层 search 值只有末尾 z?；target 外层将高度边界推进一层。
        depth = value.count(')?') // 2
        supported = canonical is not None and not value.startswith('^') and depth < 997 and '[Σ-' not in value
        if supported:
            self.assertGreater(depth, 0)
            repeated = '(?:' * depth + 'z' + ')?' * depth
            self.assertEqual(value.count(repeated), 2)
            control = value.replace(repeated, '(?:z)?')
            self.assertEqual(control.count('(?:z)?'), 2)
        for native in (False, True):
            text = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value) if native else
                    "DOMAIN-REGEX,'" + value + "'")
            parsed, warnings = parse(text, purpose='block')
            self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
            self.assertEqual(normalize(parsed), parsed)
            white = parse_whitelist(text)
            self.assertEqual(white, parsed)
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(native=native, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=white if caller == 'whitelist' else [])
                    rows = out['fin-adb.txt'].splitlines()[7:]
                    self.assertEqual(len(rows), int(supported))
                    self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), int(not supported))
                    self.assertEqual(out['fin-adb.txt'].splitlines()[6], '! Total count: ' + str(int(supported)))
                    if supported:
                        self.assertTrue(rows[0].startswith(('@@' if caller != 'block' else '') + r'/(?-i:'))
                        self.assertLessEqual(len(rows[0].encode('utf-8')) + 1, 65536)
                        control_text = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + control) if native else
                                        "DOMAIN-REGEX,'" + control + "'")
                        control_parsed, control_warnings = parse(control_text, purpose='block')
                        self.assertEqual((control_parsed, control_warnings), ([Rule('DOMAIN-REGEX', control)], []))
                        self.assertEqual(normalize(control_parsed), control_parsed)
                        control_white = parse_whitelist(control_text)
                        self.assertEqual(control_white, control_parsed)
                        control_rule = Rule('DOMAIN-REGEX', control, allow=caller == 'allow')
                        control_out, control_skipped = render('dns', [control_rule] if caller != 'whitelist' else [],
                                                              purpose='block', no_resolve='keep',
                                                              whitelist=control_white if caller == 'whitelist' else [])
                        control_rows = control_out['fin-adb.txt'].splitlines()[7:]
                        self.assertEqual(len(control_rows), 1)
                        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', control_skipped)
                        self.assertEqual(control_rows[0].count('(?:z)?'), 2)
                        # Z(d+1)=(?:Z(d))?，d>0 时均匹配空串或 z；完整深层输出逐字节核对。
                        self.assertEqual(control_rows[0].replace('(?:z)?', repeated), rows[0])
                        # 成熟 re 仅匹配实际公开生成的浅层控制，不编译删减后的 deep target。
                        matcher = dns_regex(control_rows[0])
                        for host in matches:
                            self.assertIsNotNone(matcher.search(host), host)
                        for host in misses:
                            self.assertIsNone(matcher.search(host), host)
                    self.assertEqual(rule.value, value)
                    if caller == 'block':
                        self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)
                    reference, diagnostics = render('dns', [rule] if caller != 'whitelist' else [],
                                                    purpose='proxy', no_resolve='keep')
                    for name in out:
                        if name != 'fin-adb.txt':
                            self.assertEqual(out[name], reference[name])
                            self.assertEqual({key: count for key, count in skipped.items() if key.startswith(name + ':')},
                                             {key: count for key, count in diagnostics.items() if key.startswith(name + ':')})

    def test_leading_hyphen_range_keeps_required_height_markers(self):
        for depth in (996, 997):
            repeated = '(?:' * depth + 'z' + ')?' * depth
            value = '(?:[--0]x' + repeated + r'|[\x{2D}-0]y' + repeated + ')'
            marker = '(?:)' if depth == 997 else ''
            expected = '(?:' + marker + '[--0]x' + repeated + '|' + marker + r'[\x{2D}-0]y' + repeated + ')'
            with self.subTest(depth=depth):
                self._check_consumers(value, expected, matches=('-x.123', '.x.123', '0x.123', '0y.123'),
                                      misses=('1x.123', 'ax.123', 'q.123'))

    def test_singleton_class_union_preserves_exact_dns_line_boundary(self):
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        head = '(?:(?:[1]|[2])x'
        tail = repeated + '|[12]y' + repeated + ')'
        for native in (False, True):
            for caller in ('block', 'allow', 'whitelist'):
                prefix = '@@/' if caller != 'block' else '/'
                padding = 65536 - len((prefix + head + tail + '/\n').encode('utf-8'))
                for extra in (0, 1):
                    value = head + 't' * (padding + extra) + tail
                    with self.subTest(native=native, caller=caller, extra=extra):
                        text = ('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value) if native else
                                "DOMAIN-REGEX,'" + value + "'")
                        parsed, warnings = parse(text, purpose='block')
                        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
                        self.assertEqual(normalize(parsed), parsed)
                        white = parse_whitelist(text)
                        self.assertEqual(white, parsed)
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                              no_resolve='keep', whitelist=white if caller == 'whitelist' else [])
                        expected = []
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], expected)
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(out['fin-adb.txt'].splitlines()[6], '! Total count: ' + str(len(expected)))
                        self.assertEqual(len((prefix + value + '/\n').encode('utf-8')), 65536 + extra)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_class_union_preserves_go_merge_target_foldcase(self):
        cases = (('(?:1|2)', '[12]', True), ('(?:1|[2])', '[12]', True),
                 ('(?:[1]|2)', '[12]', False), ('(?:[1]|[23])', '[123]', True),
                 ('(?:(?:[1]|[2])|[34])', '[1234]', False),
                 ('[---]', r'[\x{2D}]', True), ('[0-]', r'[\x{30}\x{2D}]', True))
        for left, right, same in cases:
            for depth in (996, 997):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
                marker = '(?:)' if same and depth == 997 else ''
                expected = '(?:' + marker + left + 'x' + repeated + '|' + marker + right + 'y' + repeated + ')'
                with self.subTest(left=left, right=right, depth=depth):
                    if left in ('[---]', '[0-]'):
                        matches, misses = ('-x.123', '-y.123'), ('1x.123', 'ax.123')
                    else:
                        matches, misses = ('1x.456', '2y.456'), ('5x.456', '5y.456')
                    self._check_consumers(value, expected, matches, misses)

    def test_dot_and_complement_class_union_keep_required_height_markers(self):
        pairs = (('(?:a|.)', '(?:b|.)'), ('(?:a|[^a])', '(?:b|[^b])'),
                 ('(?:[ab]|[^ab])', '(?:[bc]|[^bc])'),
                 ('(?:a|[^ab])', '(?:c|[^bc])'), ('(?:a|.)', r'[^\x{A}]'))
        for left, right in pairs:
            for depth in (996, 997, 998):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
                marker = '(?:)' if depth == 997 else ''
                canonical = ('(?:' + marker + left + 'x' + repeated + '|' + marker + right + 'y' + repeated + ')'
                             if depth < 998 else None)
                with self.subTest(left=left, right=right, depth=depth):
                    self._check_consumers(value, canonical, matches=('dx.123', 'dy.123', r'\195\169x.123'),
                                          misses=('x', 'q.123'))

    def test_class_union_reduces_singletons_and_simplefold_before_parent_concat(self):
        atoms = ('(?:1|[1])[2]', '(?:1|[1])(?:2|[2])', '(?:a|[a])b',
                 '(?:Δ|[δ])b', '(?:İ|[İ])[2]')
        for atom in atoms + ('(?:k|[k])b', '(?:s|[s])b'):
            for depth in (997, 998, 999):
                value = '^' + '(?:' * depth + atom + ')?' * depth + '$'
                supported = depth < (999 if atom in atoms else 998)
                with self.subTest(atom=atom, depth=depth):
                    self._check_consumers(value, value if supported else None)

    def test_high_rune_singletons_and_ranges_finish_with_original_eight_second_timeout(self):
        code = r'''
import json
from formats import render
from rules import Rule, normalize, parse, parse_whitelist
from tests.test_formats import dns_regex
high = chr(0x10FFFD)
for atom in ('[' + high + ']', '[' + high + '-' + high + ']', r'[\x{0}-' + high + ']'):
    value = '^' + atom * 64 + '$'
    text = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value, ensure_ascii=False)
    parsed, warnings = parse(text, purpose='block')
    assert (parsed, warnings) == ([Rule('DOMAIN-REGEX', value)], [])
    assert normalize(parsed) == parsed
    white = parse_whitelist(text)
    assert white == parsed
    for caller in ('block', 'allow', 'whitelist'):
        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
        out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                              no_resolve='keep', whitelist=white if caller == 'whitelist' else [])
        assert out['fin-adb.txt'].splitlines()[7:] == []
        assert skipped.get('fin-adb.txt:DOMAIN-REGEX', 0) == 1
        safe_value = '^' + atom * 64 + 'x'
        safe_white = parse_whitelist('payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + safe_value, ensure_ascii=False))
        safe = Rule('DOMAIN-REGEX', safe_value, allow=caller == 'allow')
        encoded, diagnostics = render('dns', [safe] if caller != 'whitelist' else [], purpose='block',
                                      no_resolve='keep', whitelist=safe_white if caller == 'whitelist' else [])
        rows = encoded['fin-adb.txt'].splitlines()[7:]
        assert len(rows) == 1
        assert diagnostics.get('fin-adb.txt:DOMAIN-REGEX', 0) == 0
        matcher = dns_regex(rows[0])
        assert matcher.search(r'\244\143\191\189' * 64 + 'x.abc') is not None
        assert matcher.search(r'\244\143\191\189' * 63 + 'x.abc') is None
        assert matcher.search(r'\244\143\191\190' * 64 + 'x.abc') is None
        assert rule.value == value
        if caller == 'block':
            assert json.loads(out['fin.yaml'].splitlines()[2][4:]) == 'DOMAIN-REGEX,' + value
print('bounded high rune lexical consumers passed')
'''
        process = subprocess.run([sys.executable, '-B', '-c', code],
                                 cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                 text=True, encoding='utf-8', timeout=8, check=True)
        self.assertIn('bounded high rune lexical consumers passed', process.stdout)

    def test_lexical_ranges_and_properties_keep_go_foldcase_prefix_identity(self):
        pairs = ((r'[a-\x{63}]', '[abc]'), ('[Σ-σ]', '[Σ-ςσ]'), ('[µ-µ]', '[μ]'),
                 (r'[\p{L}a-z]', r'[\p{L}A-Z]'),
                 ('(?:a|.)', r'[^\x{A}]'), (r'(?:.|\x{A})', '(?:a|[^a])'))
        for left, right in pairs:
            for depth in (996, 997):
                repeated = '(?:' * depth + 'z' + ')?' * depth
                value = '(?:' + left + 'x' + repeated + '|' + right + 'y' + repeated + ')'
                marker = '(?:)' if depth == 997 else ''
                canonical = '(?:' + marker + left + 'x' + repeated + '|' + marker + right + 'y' + repeated + ')'
                with self.subTest(left=left, right=right, depth=depth):
                    if '[Σ-' in left:
                        matches, misses = (), ()
                    elif left == '[µ-µ]':
                        matches, misses = (r'\194\181x.123', r'\206\188y.123'), ('ax.123', 'ay.123')
                    elif left.startswith(r'[\p'):
                        matches, misses = ('ax.123', r'\228\184\173y.123'), ('7x.123', '7y.123')
                    elif left == r'[a-\x{63}]':
                        matches, misses = ('ax.123', 'cy.123'), ('dx.123', 'dy.123')
                    else:
                        matches, misses = ('dx.123', r'\195\169y.123'), ('x', 'q.123')
                    self._check_consumers(value, canonical, matches, misses)

    def test_class_reductions_use_final_marker_utf8_f3_exception_and_lf_budget(self):
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        left, right = 'replace=中(?:a|.)x', 'replace=中(?:b|.)y'
        canonical_left, canonical_right = r'replace\x{3D}中(?:a|.)x', r'replace\x{3D}中(?:b|.)y'
        singleton = '^' + '(?:' * 998 + '(?:1|[1])[2]' + ')?' * 998 + 'replace=中'
        canonical_singleton = '^' + '(?:' * 998 + '(?:1|[1])[2]' + ')?' * 998 + r'replace\x{3D}中'
        cases = (('marker', '(?:' + left, repeated + '|' + right + repeated + ')',
                  '(?:(?:)' + canonical_left, repeated + '|(?:)' + canonical_right + repeated + ')'),
                 ('singleton', singleton, '$', canonical_singleton, '$'))
        for caller in ('block', 'allow', 'whitelist'):
            prefix = '@@/' if caller != 'block' else '/'
            for kind, head, tail, canonical_head, canonical_tail in cases:
                padding = 65536 - len((prefix + canonical_head + canonical_tail + '/\n').encode('utf-8'))
                for extra in (0, 1):
                    value = head + 't' * (padding + extra) + tail
                    expected = canonical_head + 't' * padding + canonical_tail
                    with self.subTest(caller=caller, kind=kind, extra=extra):
                        self.assertEqual(len((prefix + expected + '/\n').encode('utf-8')), 65536)
                        text = "DOMAIN-REGEX,'" + value + "'"
                        self.assertEqual(parse(text, purpose='block'), ([Rule('DOMAIN-REGEX', value)], []))
                        white = parse_whitelist(text)
                        rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                        out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                              no_resolve='keep', whitelist=white if caller == 'whitelist' else [])
                        self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                        self.assertEqual(skipped.get('fin-adb.txt:DOMAIN-REGEX', 0), 1)
                        self.assertEqual(rule.value, value)
                        if caller == 'block':
                            self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), 'DOMAIN-REGEX,' + value)

    def test_unclosed_class_remains_target_local_unsupported(self):
        for value in ('a|[b', 'a|[^b', '[a\\'):
            for caller in ('block', 'allow', 'whitelist'):
                with self.subTest(value=value, caller=caller):
                    rule = Rule('DOMAIN-REGEX', value, allow=caller == 'allow')
                    out, skipped = render('dns', [rule] if caller != 'whitelist' else [], purpose='block',
                                          no_resolve='keep', whitelist=[rule] if caller == 'whitelist' else [])
                    self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
                    self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
                    self.assertEqual(rule.value, value)
                    self.assertEqual(out['fin.yaml'].splitlines()[2:], [])

    def test_class_reductions_publish_real_white_and_same_round_and_disk_dependencies(self):
        repeated = '(?:' * 996 + 'z' + ')?' * 996
        values = ['^(?:(?:a|.)x' + repeated + '|(?:b|.)y' + repeated + ')[.]example[.]test$',
                  '^(?:(?:a|[^a])x' + repeated + '|(?:b|[^b])y' + repeated + ')[.]example[.]test$',
                  '^' + '(?:' * 998 + '(?:1|[1])[2]' + ')?' * 998 + '[.]example[.]test$']
        canonical = list(values)
        repeated = '(?:' * 997 + 'z' + ')?' * 997
        values += ['(?:(?:a|.)x' + repeated + '|(?:b|.)y' + repeated + ')',
                   '(?:(?:a|[^a])x' + repeated + '|(?:b|[^b])y' + repeated + ')']
        canonical += ['(?:(?:)(?:a|.)x' + repeated + '|(?:)(?:b|.)y' + repeated + ')',
                      '(?:(?:)(?:a|[^a])x' + repeated + '|(?:)(?:b|[^b])y' + repeated + ')']
        values.append('(?:[--0]x' + repeated + r'|[\x{2D}-0]y' + repeated + ')')
        canonical.append('(?:(?:)[--0]x' + repeated + r'|(?:)[\x{2D}-0]y' + repeated + ')')
        head, tail = '(?:(?:[1]|[2])x', repeated + '|[12]y' + repeated + ')'
        padding = 65536 - len(('/' + head + tail + '/\n').encode('utf-8'))
        block_boundary = head + 't' * padding + tail
        exception_boundary = head + 't' * (padding - 2) + tail
        values.extend((block_boundary, exception_boundary))
        canonical.extend((block_boundary, exception_boundary))
        domains = ['12.example.test', 'ax.example.test', 'neighbor.example.test']
        names = ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt')
        for native in (False, True):
            for remote in (False, True):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(native=native, remote=remote, purpose=purpose, mode=mode), \
                                tempfile.TemporaryDirectory() as directory, patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 1, 2, 11, 4, tzinfo=timezone.utc)
                            root = Path(directory)
                            (root / 'static').mkdir()
                            white_text = ('payload:\n' + ''.join('  - ' + json.dumps('DOMAIN-REGEX,' + value) + '\n' for value in values)
                                          if native else ''.join("DOMAIN-REGEX,'" + value + "'\n" for value in values))
                            self.assertEqual(parse(white_text, purpose=purpose), ([Rule('DOMAIN-REGEX', value) for value in values], []))
                            self.assertEqual(parse_whitelist(white_text), [Rule('DOMAIN-REGEX', value) for value in values])
                            field = values[0] if native else "'" + values[0] + "'"
                            logic = f'((DOMAIN-REGEX,{field}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))'
                            entries = ['DOMAIN,' + domain for domain in domains] + ['AND,' + logic]
                            source_text = ('payload:\n' + ''.join('  - ' + json.dumps(entry) + '\n' for entry in entries)
                                           if native else '\n'.join(entries) + '\n') + '@@||allow.example.test^\n'
                            inputs = {root / 'static/source.list': source_text.encode('utf-8'),
                                      root / 'static/white.list': white_text.encode('utf-8')}
                            for path, data in inputs.items():
                                path.write_bytes(data)
                            source_entry = 'https://example.test/class-source' if remote else 'static/source.list'
                            white_entry = 'https://example.test/class-white' if remote else 'static/white.list'
                            configs = [{'name': 'white', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [white_entry], 'whitelist': []},
                                       {'name': 'source', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': [source_entry], 'whitelist': ['white/fin.yaml']},
                                       {'name': 'child', 'purpose': purpose, 'no_resolve': mode,
                                        'sources': ['white/fin.yaml'], 'whitelist': []}]
                            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                            old = {}
                            for group in ('white', 'source', 'child'):
                                (root / group).mkdir()
                                for name in names:
                                    path = root / group / name
                                    old[path] = b'old\0' + (group + name).encode('ascii')
                                    path.write_bytes(old[path])
                            responses = {'https://example.test/class-source': source_text.encode('utf-8'),
                                         'https://example.test/class-white': white_text.encode('utf-8')}
                            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                                output = generate(root, lambda url: responses[url])
                            self.assertEqual(len(output), 18)
                            self.assertEqual({path: path.read_bytes() for path in old}, old)
                            self.assertNotIn('frozen', diagnostic.getvalue())
                            self.assertNotIn('invalid', diagnostic.getvalue())
                            flag = ',no-resolve' if mode != 'strip' else ''
                            expected_logic = f'AND,((DOMAIN-REGEX,{values[0]}),(IP-CIDR,192.0.2.0/24{flag}),(SRC-IP-CIDR,198.51.100.0/24))'
                            ordered = sorted(['DOMAIN-REGEX,' + value for value in values], key=lambda row: (len(row), row))
                            for group in ('white', 'source', 'child'):
                                yaml = ([expected_logic] + (['DOMAIN,' + domain for domain in domains] if native else
                                        sorted([expected_domain('DOMAIN', domain) for domain in domains], key=lambda row: (len(json.dumps(row)), row)))
                                        if group == 'source' else ordered)
                                self.assertEqual(output[root / group / 'fin.yaml'], f'# {group} rules: {len(yaml)}\npayload:\n' +
                                                 ''.join('  - ' + json.dumps(row) + '\n' for row in yaml))
                                restored, warnings = parse(output[root / group / 'fin.yaml'], purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual([rule.kind + ',' + rule.value for rule in restored], yaml)
                                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                    body = (['DOMAIN,' + domain for domain in domains] if name == 'fin.txt' else
                                            ['HOST,' + domain + ',LIST' for domain in domains] if name == 'fin-qx.txt' else
                                            domains if name == 'fin-surge-ds.txt' else []) if group == 'source' else []
                                    if native and name in ('fin.txt', 'fin-surge-ds.txt'):
                                        body = []
                                    self.assertEqual(output[root / group / name], f'# {group} rules: {len(body)}\n' + ''.join(row + '\n' for row in body))
                                # strict 前三条缺 root 证书；其余原深层值超最终 target 高度/行预算。
                                dns = (([] if native else ['0.0.0.0 ' + domain for domain in domains]) + ['@@||allow.example.test^']
                                       if purpose == 'block' and group == 'source' else [])
                                dns.sort(key=lambda row: (not row.startswith('@@'), len(row), row))
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[7:],
                                                 dns if purpose == 'block' else ['! No AdBlock rules for non-advertising group.'])
                                self.assertEqual(output[root / group / 'fin-adb.txt'].splitlines()[6], f'! Total count: {len(dns)}')
                                if purpose == 'block':
                                    self.assertIn(f'{group} fin-adb.txt:DOMAIN-REGEX: {len(values)}\n', diagnostic.getvalue())
                                self.assertTrue(all(len(row.encode('utf-8')) + 1 <= 65536
                                                    for row in output[root / group / 'fin-adb.txt'].split('\n')[:-1]))
                            publish(output, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                            (root / 'rulesets.json').write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()):
                                disk = generate(root, lambda url: responses[url])
                            self.assertEqual(disk, {path: text for path, text in output.items() if path.parent.name != 'white'})
                            publish(disk, root=root)
                            self.assertEqual({path: path.read_bytes() for path in output},
                                             {path: text.encode('utf-8') for path, text in output.items()})
                            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
