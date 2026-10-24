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

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


ROOT = Path(__file__).resolve().parents[1]


def expected_outputs(group, matcher, purpose, surge=None):
    outputs = {name: f'# {group} rules: 0\n' for name in FILES}
    outputs['fin.yaml'] = f'# {group} rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n'
    if surge is not None:
        outputs['fin.txt'] = outputs['fin-surge.txt'] = f'# {group} rules: 1\n' + surge + '\n'
    outputs['fin-adb.txt'] = ('[Adblock Plus 2.0]\n' + f'! Title: {group}\n' +
        '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n'
        '! License: Inherits upstream licenses\n! Version: 202610240000\n! Total count: 0\n' +
        ('' if purpose == 'block' else '! No AdBlock rules for non-advertising group.\n'))
    return outputs


class NativeNotSpaceRegressionTests(unittest.TestCase):
    def test_native_not_accepts_structural_spaces_and_preserves_list_wrapper(self):
        expected = Rule('NOT', '((DOMAIN,a.test))', native_fields=True, domain_source='mihomo')
        self.assertEqual(parse('payload:\n  - "NOT,( (DOMAIN,a.test) )"\n', purpose='proxy'),
                         ([expected], []))
        outputs, diagnostics = render('native', [expected], purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.yaml'], '# native rules: 1\npayload:\n  - "NOT,((DOMAIN,a.test))"\n')
        self.assertNotIn('fin.yaml:NOT', diagnostics)

    def test_headers_scalar_encodings_and_nested_spaces_keep_all_public_fields(self):
        for left, right in ((' ', ' '), (' ', ''), ('', ' '), ('   ', '  ')):
            for template in ('{not_rule}', 'AND,(({not_rule}),(NETWORK,tcp))',
                             'OR,((NETWORK,udp),({not_rule}))', 'NOT,(( {not_rule} ))'):
                raw = template.format(not_rule='NOT,(' + left + '(DOMAIN,a.test)' + right + ')')
                canonical = template.format(not_rule='NOT,((DOMAIN,a.test))').replace('(( ', '((').replace(' ))', '))')
                for header in ('payload', 'rules'):
                    for item in (raw, "'" + raw + "'", json.dumps(raw)):
                        for purpose in ('block', 'direct', 'proxy'):
                            with self.subTest(left=left, right=right, template=template, header=header, item=item, purpose=purpose):
                                text = '﻿# input\r\n' + header + ':\r\n  - ' + item + '\r\n'
                                parsed, messages = parse(text, purpose=purpose)
                                expected = Rule(*canonical.split(',', 1), native_fields=True, domain_source='mihomo')
                                self.assertEqual((parsed, messages), ([expected], []))
                                self.assertEqual(normalize(iter(parsed + parsed)), parsed)
                                self.assertEqual(normalize(iter(reversed(parsed + parsed))), parsed)
                                self.assertEqual(exclude_covered(iter(parsed), iter([Rule('DOMAIN', 'a.test')])), parsed)
                                self.assertEqual(parse_whitelist(text), [])
                                for mode in ('add', 'strip', 'keep'):
                                    outputs, diagnostics = render('native', parsed, purpose=purpose, no_resolve=mode)
                                    self.assertEqual(outputs['fin.yaml'], '# native rules: 1\npayload:\n  - ' + json.dumps(canonical) + '\n')
                                    self.assertNotIn('fin.yaml:' + expected.kind, diagnostics)
                                    self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose), (parsed, []))

    def test_direct_native_rule_render_uses_structural_ranges_without_extra_wrapper(self):
        templates = (('{}', '{}', '{}'),
                     ('AND,(({}),(NETWORK,udp))', 'AND,(({}),(NETWORK,udp))', 'AND,(({}),(PROTOCOL,UDP))'),
                     ('OR,((NETWORK,udp),({}))', 'OR,((NETWORK,udp),({}))', 'OR,((PROTOCOL,UDP),({}))'),
                     ('NOT,( ({}) )', 'NOT,(({}))', 'NOT,(({}))'))
        for left, right in ((' ', ' '), (' ', ''), ('', ' '), ('   ', '  ')):
            raw_not = 'NOT,(' + left + '(NETWORK,tcp)' + right + ')'
            for raw_template, canonical_template, surge_template in templates:
                raw = raw_template.format(raw_not)
                canonical = canonical_template.format('NOT,((NETWORK,tcp))')
                surge = surge_template.format('NOT,((PROTOCOL,TCP))')
                rule = Rule(*raw.split(',', 1), native_fields=True)
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(raw=raw, purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            outputs, diagnostics = render('native', [rule], purpose=purpose, no_resolve=mode)
                            for name in ('fin.txt', 'fin-surge.txt'):
                                self.assertEqual(outputs[name], '# native rules: 1\n' + surge + '\n')
                                self.assertEqual(parse(outputs[name], purpose=purpose),
                                                 ([Rule(*surge.split(',', 1))], []))
                                self.assertNotIn(name + ':' + rule.kind, diagnostics)
                            yaml = raw if mode == 'keep' else canonical
                            self.assertEqual(outputs, expected_outputs('native', yaml, purpose, surge))
                            self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose),
                                             ([Rule(*canonical.split(',', 1), native_fields=True)], []))
                            self.assertEqual(diagnostics, {name + ':' + rule.kind: 1 for name in
                                                          ('fin-qx.txt', 'fin-surge-ds.txt', 'fin-adb.txt')})
        for value in ('( (DOMAIN,a.test) )', '( (DOMAIN,a.test))', '((DOMAIN,a.test) )'):
            rule = Rule('NOT', value, native_fields=True, domain_source='mihomo')
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(value=value, mode=mode):
                    outputs, diagnostics = render('native', [rule], purpose='proxy', no_resolve=mode)
                    expected_value = value if mode == 'keep' else '((DOMAIN,a.test))'
                    self.assertEqual(outputs['fin.yaml'], '# native rules: 1\npayload:\n  - ' + json.dumps('NOT,' + expected_value) + '\n')
                    self.assertNotIn('fin.yaml:NOT', diagnostics)
                    self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'),
                        ([Rule('NOT', '((DOMAIN,a.test))', native_fields=True, domain_source='mihomo')], []))
                    for name in ('fin.txt', 'fin-surge.txt'):
                        self.assertEqual(outputs[name], '# native rules: 0\n')
                        self.assertEqual(diagnostics[name + ':NOT'], 1)

    def test_invalid_native_wrappers_and_non_ascii_structure_keep_neighbor_and_warning_line(self):
        invalid = ('NOT,(DOMAIN,a.test)', 'NOT,()', 'NOT,( )', 'NOT,(())',
                   'NOT,((DOMAIN,a.test),(DOMAIN,b.test))', 'NOT,(((DOMAIN,a.test)))',
                   'NOT,((DOMAIN,a.test),)', 'NOT,((DOMAIN,))', 'NOT,((UNKNOWN,a.test))',
                   'NOT,((DOMAIN,a.test)),tail', 'NOT,(\t(DOMAIN,a.test)\t)',
                   'NOT,(\xa0(DOMAIN,a.test)\xa0)')
        for raw in invalid:
            with self.subTest(raw=raw):
                parsed, messages = parse('﻿payload:\r\n  - ' + json.dumps(raw) +
                                         '\r\n  - DOMAIN,neighbor.test\r\n', purpose='block')
                self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.test', domain_source='mihomo')])
                self.assertEqual(len(messages), 1)
                self.assertTrue(messages[0].startswith('line 2: invalid logical expression '), messages)
        for raw in ('AND,()', 'OR,()', 'AND,((DOMAIN,a.test))', 'OR,((DOMAIN,a.test))'):
            self.assertEqual(parse(raw, purpose='proxy')[0], [])
            self.assertEqual(parse('payload:\n  - ' + raw, purpose='proxy')[1], [])
        ordinary, messages = parse('NOT,(DOMAIN,a.test)', purpose='proxy')
        self.assertEqual((ordinary, messages), ([Rule('NOT', '(DOMAIN,a.test)')], []))
        outputs, _ = render('ordinary', ordinary, purpose='proxy', no_resolve='keep')
        self.assertEqual(outputs['fin.txt'], '# ordinary rules: 1\nNOT,((DOMAIN,a.test))\n')

    def test_literal_parentheses_regex_ignored_tail_and_ip_direction_roundtrip(self):
        cases = (('PROCESS-NAME,tool(,ignored)', 'PROCESS-NAME,tool(,ignored)', True),
                 ('PROCESS-PATH,/123/(456)', 'PROCESS-PATH,/123/(456)', False),
                 ('IN-USER,123(,ignored)', 'IN-USER,123(,ignored)', False),
                 ('DOMAIN-REGEX,^(a|b)\\.test$', 'DOMAIN-REGEX,^(a|b)\\.test$', False),
                 ('PROCESS-NAME,\t', 'PROCESS-NAME,\t', True),
                 ('PROCESS-NAME,\xa0', 'PROCESS-NAME,\xa0', True),
                 ('IP-CIDR,192.0.2.1/24,no-resolve', 'IP-CIDR,192.0.2.0/24,no-resolve', False),
                 ('IP-CIDR,198.51.100.1/24,src,no-resolve', 'SRC-IP-CIDR,198.51.100.0/24', False))
        for leaf, canonical, literal in cases:
            for purpose in ('block', 'direct', 'proxy'):
                raw = 'NOT,( (' + leaf + ') )'
                with self.subTest(leaf=leaf, purpose=purpose):
                    parsed, messages = parse('payload:\n  - ' + json.dumps(raw), purpose=purpose)
                    expected = Rule('NOT', '((' + canonical + '))', literal_process=literal, native_fields=True)
                    self.assertEqual(parsed, [expected])
                    self.assertEqual(messages, ['line 2: unsupported no-resolve for SRC-IP-CIDR'] if ',src,' in leaf else [])
                    for mode in ('add', 'strip', 'keep'):
                        target = canonical.removesuffix(',no-resolve') if mode == 'strip' else canonical
                        if mode == 'add' and target.startswith('IP-CIDR,') and not target.endswith(',no-resolve'):
                            target += ',no-resolve'
                        outputs, diagnostic = render('native', parsed, purpose=purpose, no_resolve=mode)
                        self.assertEqual(outputs['fin.yaml'], '# native rules: 1\npayload:\n  - ' + json.dumps('NOT,((' + target + '))', ensure_ascii=False) + '\n')
                        self.assertNotIn('fin.yaml:NOT', diagnostic)
                        reread, warnings = parse(outputs['fin.yaml'], purpose=purpose)
                        self.assertEqual(warnings, [])
                        self.assertEqual(render('native', reread, purpose=purpose, no_resolve=mode)[0]['fin.yaml'], outputs['fin.yaml'])
        for leaf, surge in (('PROCESS-NAME,123(456)', "PROCESS-NAME,'123(456)'"),
                            ('DOMAIN-REGEX,^(a|b)\\.test$', None),
                            ('IP-CIDR,192.0.2.0/24,no-resolve', 'IP-CIDR,192.0.2.0/24,no-resolve'),
                            ('SRC-IP-CIDR,198.51.100.0/24', 'SRC-IP,198.51.100.0/24')):
            raw = 'NOT,( (' + leaf + ') )'
            rule = Rule('NOT', raw[4:], native_fields=True, literal_process=leaf.startswith('PROCESS-'))
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(leaf=leaf, purpose=purpose, mode=mode):
                        outputs, diagnostics = render('native', [rule], purpose=purpose, no_resolve=mode)
                        flag_leaf = leaf.removesuffix(',no-resolve') if mode == 'strip' else leaf
                        yaml = raw if mode == 'keep' else 'NOT,((' + flag_leaf + '))'
                        self.assertEqual(outputs['fin.yaml'], '# native rules: 1\npayload:\n  - ' + json.dumps(yaml) + '\n')
                        self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose),
                                         ([Rule('NOT', '((' + flag_leaf + '))', native_fields=True,
                                                literal_process=rule.literal_process)], []))
                        for name in ('fin.txt', 'fin-surge.txt'):
                            if surge is None:
                                self.assertEqual(outputs[name], '# native rules: 0\n')
                                self.assertEqual(diagnostics[name + ':NOT'], 1)
                            else:
                                target = surge.removesuffix(',no-resolve') if mode == 'strip' else surge
                                text = '# native rules: 1\nNOT,((' + target + '))\n'
                                self.assertEqual(outputs[name], text)
                                parsed, warnings = parse(text, purpose=purpose)
                                self.assertEqual(warnings, [])
                                self.assertEqual(render('native', parsed, purpose=purpose, no_resolve=mode)[0][name], text)
                                self.assertNotIn(name + ':NOT', diagnostics)

    def test_real_single_not_publish_same_round_and_nonempty_disk_dependencies(self):
        cases = (('NOT,( (DOMAIN,a.test) )', 'NOT,((DOMAIN,a.test))', None),
                 ('NOT,( (NETWORK,tcp) )', 'NOT,((NETWORK,tcp))', 'NOT,((PROTOCOL,TCP))'))
        for raw, canonical, surge in cases:
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(raw=raw, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / 'static').mkdir()
                        (root / 'static/input.yaml').write_bytes(('﻿rules:\r\n  - ' + json.dumps(raw) + '\r\n').encode())
                        (root / 'static/white.list').write_bytes(b'IP-CIDR,198.51.100.0/24\r\n')
                        (root / 'static/marker').write_bytes(b'static\x00\xff')
                        inputs = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                        configs = [dict(name=group, purpose=purpose, no_resolve=mode, sources=sources,
                                        whitelist=['static/white.list']) for group, sources in
                                   (('parent', ['static/input.yaml']), ('child', ['parent/fin.yaml']))]
                        config = root / 'rulesets.json'
                        config.write_text(json.dumps(configs), encoding='utf-8')
                        old = {}
                        for group in ('parent', 'child'):
                            (root / group).mkdir()
                            for name in FILES:
                                path = root / group / name
                                old[path] = b'old complete product\x00\xff\r\n'
                                path.write_bytes(old[path])
                        expected = {root / group / name: text for group in ('parent', 'child')
                                    for name, text in expected_outputs(group, canonical, purpose, surge).items()}
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as logs:
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            outputs = generate(root, self.fail)
                        self.assertEqual(outputs, expected)
                        self.assertNotIn('frozen', logs.getvalue())
                        self.assertEqual({path: path.read_bytes() for path in old}, old)
                        for path, text in outputs.items():
                            if path.name in ('fin.txt', 'fin-surge.txt', 'fin.yaml'):
                                self.assertEqual(parse(text, purpose=purpose)[1], [])
                        publish(outputs, root=root)
                        published = {path: path.read_bytes() for path in outputs}
                        self.assertEqual(published, {path: text.encode() for path, text in expected.items()})
                        config.write_text(json.dumps(configs[1:]), encoding='utf-8')
                        with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                            clock.now.return_value = datetime(2026, 10, 24, tzinfo=timezone.utc)
                            disk = generate(root, self.fail)
                        self.assertEqual(disk, {path: text for path, text in expected.items() if path.parent.name == 'child'})
                        publish(disk, root=root)
                        config.write_text(json.dumps([configs[0], dict(configs[1], whitelist=['parent/fin.yaml'])]), encoding='utf-8')
                        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'unsupported rule'):
                            generate(root, self.fail)
                        self.assertEqual({path: path.read_bytes() for path in published}, published)
                        self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_deep_spaced_not_is_iterative_and_skips_unsupported_targets_whole(self):
        for depth in (600, 1000):
            code = '''
import json
import sys
from formats import render
from rules import Rule, normalize, parse
limit = sys.getrecursionlimit()
for leaf, literal, source in (('(DOMAIN,a.test)', False, 'mihomo'),
                              ('(PROCESS-NAME,123(,ignored))', True, 'surge')):
    raw = ('(NOT,( ' * DEPTH + leaf + ' ))' * DEPTH)[1:-1]
    canonical = ('(NOT,(' * DEPTH + leaf + '))' * DEPTH)[1:-1]
    expected = Rule('NOT', canonical[4:], literal_process=literal, native_fields=True, domain_source=source)
    for purpose in ('block', 'direct', 'proxy'):
        parsed, warnings = parse('payload:\\n  - ' + json.dumps(raw), purpose=purpose)
        assert (parsed, warnings) == ([expected], []), (len(parsed), warnings)
        assert normalize(iter(parsed + parsed)) == parsed
        for mode in ('add', 'strip', 'keep'):
            outputs, diagnostic = render('deep', parsed, purpose=purpose, no_resolve=mode)
            assert outputs['fin.yaml'] == '# deep rules: 1\\npayload:\\n  - ' + json.dumps(canonical) + '\\n'
            assert parse(outputs['fin.yaml'], purpose=purpose) == (parsed, [])
            for name in ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt', 'fin-qx.txt'):
                assert outputs[name] == '# deep rules: 0\\n'
                assert diagnostic[name + ':NOT'] == 1
            assert not outputs['fin-adb.txt'].splitlines()[7:] or purpose != 'block'
assert sys.getrecursionlimit() == limit
'''.replace('DEPTH', str(depth))
            with self.subTest(depth=depth):
                result = subprocess.run([sys.executable, '-I', '-B', '-c',
                    "import sys; sys.path.insert(0, sys.argv.pop(1)); " + code, str(ROOT)],
                    cwd=ROOT, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
