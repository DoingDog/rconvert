import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist
from tests.test_formats import expected_domain


KINDS = ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX')
ANCHORS = ('^', '$', r'\A', r'\Z', r'\z', r'\G', r'\b', r'\B')
QUANTIFIERS = ('*', '+', '?', '{0}', '{1}', '{1,2}', '{1,}')


class Regexp2AnchorTests(unittest.TestCase):
    def test_bare_anchor_quantifier_preserves_matcher_and_neighbor(self):
        self.assertEqual(parse('DOMAIN-REGEX,^+ads\nDOMAIN,keep.example.org', purpose='block'),
                         ([Rule('DOMAIN-REGEX', '^+ads'), Rule('DOMAIN', 'keep.example.org')], []))

    def test_escaped_anchor_quantifier_preserves_original_matcher(self):
        for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX'):
            with self.subTest(kind=kind):
                self.assertEqual(parse(kind + r',\A?ads', purpose='proxy'),
                                 ([Rule(kind, r'\A?ads')], []))

    def test_all_eight_anchors_keep_greedy_lazy_and_bounded_quantifiers(self):
        for kind in KINDS:
            for anchor in ANCHORS:
                for quantifier in QUANTIFIERS:
                    for lazy in ('', '?'):
                        value = anchor + quantifier + lazy + 'ads'
                        for quote in ('', "'", '"'):
                            with self.subTest(kind=kind, value=value, quote=quote):
                                self.assertEqual(parse(f'{kind},{quote}{value}{quote},PROXY', purpose='proxy'),
                                                 ([Rule(kind, value)], []))
                                if kind == 'DOMAIN-REGEX':
                                    outputs, skipped = render('anchor', [Rule(kind, value)],
                                                              purpose='block', no_resolve='keep')
                                    self.assertEqual(outputs['fin.yaml'], '# anchor rules: 1\npayload:\n  - ' +
                                                     json.dumps(kind + ',' + value) + '\n')
                                    self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [])
                                    self.assertEqual(skipped, {name + ':' + kind: 1 for name in FILES
                                                               if name != 'fin.yaml'})

    def test_native_headers_and_three_scalar_forms_keep_matcher_and_physical_lines(self):
        for header in ('payload', 'rules'):
            for kind in KINDS:
                for value in ('^+ads', r'\A?ads', r'\b{1,2}?ads', 'a$*'):
                    matcher = kind + ',' + value
                    for scalar in (matcher, "'" + matcher + "'", json.dumps(matcher)):
                        with self.subTest(header=header, kind=kind, scalar=scalar):
                            document = '\ufeff' + header + ':\r\n  - ' + scalar + '\r\n  - DOMAIN,keep.example.org\r\n'
                            self.assertEqual(parse(document, purpose='proxy'),
                                             ([Rule(kind, value), Rule('DOMAIN', 'keep.example.org',
                                                                       domain_source='mihomo')], []))

    def test_comments_x_mode_flags_and_captures_preserve_original_text(self):
        values = (r'(?im)^+(?#note)?ads$*?', r'(?x) ^ (?#note)+ (?#lazy)? ads',
                  r'(?x:\b (?#note){1,2} (?#lazy)? ads)', r'(?x)^+(?-x: +)ads',
                  r'(?<named>a)^+\k<named>(b)\1\2', r'(a)\b+\1',
                  r'(?<7>a)\A?\k<7>', r'(?n)(a)^+(?<named>b)\1',
                  r'\^+\$?', r'\\A+ads', r'[$^\b]+ads', r'[^$\b]+ads')
        for kind in KINDS:
            for value in values:
                with self.subTest(kind=kind, value=value):
                    self.assertEqual(parse(f'{kind},{json.dumps(value)},PROXY', purpose='proxy'),
                                     ([Rule(kind, value)], []))
                    document = 'payload:\n  - ' + json.dumps(kind + ',' + value) + '\n'
                    self.assertEqual(parse(document, purpose='proxy'), ([Rule(kind, value)], []))
                    outputs, _ = render('anchor', [Rule(kind, value)], purpose='proxy', no_resolve='keep')
                    self.assertEqual(json.loads(outputs['fin.yaml'].splitlines()[2][4:]), kind + ',' + value)
                    self.assertEqual(parse(outputs['fin.yaml'], purpose='proxy'), ([Rule(kind, value)], []))
            for space in ' \t\n\r\v\f':
                value = '(?x)^' + space + '+' + space + '?' + 'ads'
                document = 'payload:\n  - ' + json.dumps(kind + ',' + value) + '\n'
                with self.subTest(kind=kind, space=repr(space)):
                    self.assertEqual(parse(document, purpose='proxy'), ([Rule(kind, value)], []))
            value = '(?x)^# before quantifier\n+# before lazy\n?ads'
            document = 'payload:\n  - ' + json.dumps(kind + ',' + value) + '\n'
            self.assertEqual(parse(document, purpose='proxy'), ([Rule(kind, value)], []))

    def test_invalid_quantifiers_and_other_invalid_syntax_keep_neighbor_and_line_numbers(self):
        values = ('^++ads', '^+*ads', r'\b+?+ads', 'a$**', '^+??ads', '^+{1}ads',
                  '*ads', '+ads', '?ads', '{1}ads', r'^+\q', r'^+[z-a]',
                  r'^+\p{Invalid}', r'^+(?a:ads)', r'^+\1', r'^+(a)\2',
                  r'(?<name>a)^+\k<missing>', '^+a{2,1}', '^+a{2147483648}',
                  r'^+\x{110000}', r'^+\b{2,1}', r'(?x)^+(?#note)*ads',
                  r'(?x)^+(?i)?ads', r'(?x)^+(?#note)??ads')
        neighbor = Rule('DOMAIN', 'keep.example.org')
        for kind in KINDS:
            for value in values:
                with self.subTest(kind=kind, value=value):
                    source = f'{kind},"{value}",PROXY\nDOMAIN,keep.example.org,PROXY'
                    self.assertEqual(parse(source, purpose='proxy'),
                                     ([neighbor], [f'line 1: invalid {kind} {value}']))
                    document = 'payload:\n  - ' + json.dumps(kind + ',' + value) + '\n  - DOMAIN,keep.example.org\n'
                    self.assertEqual(parse(document, purpose='proxy'),
                                     ([Rule('DOMAIN', 'keep.example.org', domain_source='mihomo')],
                                      [f'line 2: invalid {kind} {value}']))

    def test_url_regex_retains_independent_python_validation(self):
        for anchor in ANCHORS:
            for quantifier in QUANTIFIERS:
                value = anchor + quantifier + 'ads'
                with self.subTest(value=value):
                    self.assertEqual(parse(f'URL-REGEX,"{value}",PROXY\nDOMAIN,keep.example.org', purpose='proxy'),
                                     ([Rule('DOMAIN', 'keep.example.org')],
                                      [f'line 1: invalid URL-REGEX {value}']))
        for value in (r'(?:^)+ads', r'\^+ads', r'[$^\b]+ads'):
            self.assertEqual(parse('URL-REGEX,' + value, purpose='proxy'),
                             ([Rule('URL-REGEX', value)], []))

    def test_logical_all_operators_modes_and_purposes_keep_complete_matcher(self):
        for kind in KINDS:
            for value in ('^+ads', r'\A?ads', r'\b{1,2}?ads', 'a$*'):
                leaf = f'({kind},{value})'
                for operator, expression in (('AND', f'({leaf},(IP-CIDR,203.0.113.0/24,no-resolve))'),
                                             ('OR', f'({leaf},(IP-CIDR,203.0.113.0/24,no-resolve))'),
                                             ('NOT', f'({leaf})'),
                                             ('AND', f'((OR,({leaf},(NETWORK,tcp))),(IP-CIDR,203.0.113.0/24,no-resolve))')):
                    for native in (False, True):
                        for purpose in ('block', 'direct', 'proxy'):
                            policy = {'block': 'REJECT', 'direct': 'DIRECT', 'proxy': 'PROXY'}[purpose]
                            source = (('payload:\n  - ' + json.dumps(operator + ',' + expression) + '\n  - DOMAIN,keep.example.org\n')
                                      if native else f'{operator},{expression},{policy}\nDOMAIN,keep.example.org,{policy}')
                            rules, messages = parse(source, purpose=purpose)
                            self.assertEqual(messages, [])
                            self.assertEqual(rules, [Rule(operator, expression, native_fields=native),
                                                     Rule('DOMAIN', 'keep.example.org', domain_source='mihomo' if native else 'surge')])
                            ordered = rules if operator == 'AND' else list(reversed(rules))
                            self.assertEqual(normalize(iter(rules + rules)), ordered)
                            for mode in ('keep', 'add', 'strip'):
                                with self.subTest(kind=kind, value=value, operator=operator, native=native,
                                                  purpose=purpose, mode=mode, expression=expression):
                                    outputs, skipped = render('anchor', iter(rules), purpose=purpose, no_resolve=mode)
                                    wanted = expression.replace(',no-resolve', '') if mode == 'strip' else expression
                                    neighbor = 'DOMAIN,keep.example.org' if native else expected_domain('DOMAIN', 'keep.example.org')
                                    records = [json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]]
                                    self.assertEqual(set(records), {operator + ',' + wanted, neighbor})
                                    restored, warnings = parse(outputs['fin.yaml'], purpose=purpose)
                                    self.assertEqual(warnings, [])
                                    self.assertIn(Rule(operator, wanted, native_fields=True), restored)
                                    self.assertEqual(outputs['fin.txt'], '# anchor rules: 0\n' if native else
                                                     '# anchor rules: 1\nDOMAIN,keep.example.org\n')
                                    for name in ('fin.txt', 'fin-qx.txt', 'fin-adb.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                                        self.assertEqual(skipped[name + ':' + operator], 1)

    def test_invalid_logical_anchor_leaf_skips_the_complete_expression(self):
        for kind in KINDS:
            for value in ('^++ads', r'\b+?+ads', 'a$**', r'(?<name>a)^+\k<missing>'):
                for operator in ('AND', 'OR', 'NOT'):
                    leaf = f'({kind},{value})'
                    expression = f'({leaf})' if operator == 'NOT' else f'({leaf},(NETWORK,tcp))'
                    for native in (False, True):
                        source = ('payload:\n  - ' + json.dumps(operator + ',' + expression) + '\n  - DOMAIN,keep.example.org\n'
                                  if native else f'{operator},{expression},PROXY\nDOMAIN,keep.example.org')
                        with self.subTest(kind=kind, value=value, operator=operator, native=native):
                            self.assertEqual(parse(source, purpose='proxy'),
                                             ([Rule('DOMAIN', 'keep.example.org', domain_source='mihomo' if native else 'surge')],
                                              [f'line {2 if native else 1}: invalid logical expression {expression}']))

    def test_domain_white_identity_does_not_infer_arbitrary_regex_equivalence(self):
        source = 'DOMAIN-REGEX,^+ads\nDOMAIN-REGEX,(?:^)+ads\nDOMAIN-REGEX,^++ads\nDOMAIN,keep.example.org'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            white = parse_whitelist(source)
        self.assertEqual(white, [Rule('DOMAIN-REGEX', '^+ads'), Rule('DOMAIN-REGEX', '(?:^)+ads'),
                                 Rule('DOMAIN', 'keep.example.org')])
        self.assertEqual([str(item.message) for item in caught], ['line 3: invalid DOMAIN-REGEX ^++ads'])
        self.assertEqual(exclude_covered(iter(white), iter(white[:1])), white[1:])
        self.assertEqual(normalize(iter(reversed(white + white))),
                         [Rule('DOMAIN', 'keep.example.org'), Rule('DOMAIN-REGEX', '(?:^)+ads'),
                          Rule('DOMAIN-REGEX', '^+ads')])
        self.assertEqual(parse_whitelist('PROCESS-NAME-REGEX,^+ads\nPROCESS-PATH-REGEX,^+ads'), [])
        for consumer in ('block', 'allow', 'white'):
            rules = [Rule('DOMAIN-REGEX', '^+ads', allow=consumer == 'allow')] if consumer != 'white' else []
            outputs, skipped = render('anchor', rules, purpose='block', no_resolve='keep',
                                      whitelist=white[:1] if consumer == 'white' else [])
            self.assertEqual(outputs['fin-adb.txt'].splitlines()[7:], [])
            self.assertEqual(skipped['fin-adb.txt:DOMAIN-REGEX'], 1)
            self.assertFalse(any('whitelist-covered' in key for key in skipped))

    def test_deep_anchor_quantifiers_preserve_capture_slots_and_iterative_validation(self):
        script = r'''
import json
import sys
sys.path.insert(0, sys.argv[1])
from formats import render
from rules import Rule, parse
assert sys.getrecursionlimit() == 1000
for depth in (600, 1000):
    for kind in ('DOMAIN-REGEX', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX'):
        for header in ('(', '(?:', '(?i:', '(?n:', '(?x:'):
            atom = r'(?<named>a)^+\k<named>\A?\Z{0}\z{1}\G{1,2}?\b{1,}?\B??$*'
            value = header * depth + atom + ')' * depth
            expression = f'(({kind},{value}),(IP-CIDR,203.0.113.0/24,no-resolve))'
            for logical in (False, True):
                matcher = 'AND,' + expression if logical else kind + ',' + value
                source = 'payload:\n  - ' + json.dumps(matcher) + '\n'
                parsed, warnings = parse(source, purpose='proxy')
                expected = Rule('AND', expression, native_fields=True) if logical else Rule(kind, value)
                assert parsed == [expected] and warnings == [], (depth, kind, header, logical, warnings)
                for mode in ('keep', 'add', 'strip'):
                    outputs, skipped = render('anchor', parsed, purpose='proxy', no_resolve=mode)
                    wanted = matcher.replace(',no-resolve', '') if mode == 'strip' else matcher
                    assert json.loads(outputs['fin.yaml'].splitlines()[2][4:]) == wanted
                    restored, warnings = parse(outputs['fin.yaml'], purpose='proxy')
                    assert len(restored) == 1 and warnings == [], (depth, kind, header, logical, mode)
            invalid = value.replace('^+', '^++', 1)
            assert parse('payload:\n  - ' + json.dumps(kind + ',' + invalid), purpose='proxy') == ([], [f'line 2: invalid {kind} {invalid}'])
assert sys.getrecursionlimit() == 1000
'''
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root)],
                                cwd=root, capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generate_publish_same_round_and_disk_source_white_read_actual_yaml_bytes(self):
        matchers = ('DOMAIN-REGEX,^+ads', r'PROCESS-NAME-REGEX,\A?ads',
                    r'PROCESS-PATH-REGEX,\b{1,2}?ads',
                    r'AND,((DOMAIN-REGEX,a$*),(IP-CIDR,203.0.113.0/24,no-resolve))')
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('keep', 'add', 'strip'):
                with self.subTest(purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'static').mkdir()
                    (root / 'static/input.yaml').write_bytes((chr(0xfeff) + 'payload:\r\n' + ''.join(
                        '  - ' + json.dumps(matcher) + '\r\n' for matcher in matchers)).encode('utf-8'))
                    (root / 'static/white.list').write_bytes(b'DOMAIN-REGEX,^+ads\r\n')
                    (root / 'static/block.list').write_bytes(b'DOMAIN-REGEX,^+ads\r\nDOMAIN-REGEX,other$*\r\n')
                    static = {path: path.read_bytes() for path in (root / 'static').iterdir()}
                    configs = [{'name': group, 'purpose': purpose, 'no_resolve': mode,
                                'sources': sources, 'whitelist': white} for group, sources, white in (
                        ('parent', ['static/input.yaml'], []),
                        ('whiteparent', ['static/white.list'], []),
                        ('sourcechild', ['parent/fin.yaml'], []),
                        ('whitechild', ['static/block.list'], ['whiteparent/fin.yaml']),
                        ('cleared', ['static/white.list'], ['whiteparent/fin.yaml']))]
                    (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
                    previous = {}
                    for config in configs:
                        (root / config['name']).mkdir()
                        for name in FILES:
                            path = root / config['name'] / name
                            previous[path] = b'old complete\r\n\x00' + name.encode('ascii')
                            path.write_bytes(previous[path])
                    with contextlib.redirect_stderr(io.StringIO()) as logs:
                        outputs = generate(root, self.fail)
                    self.assertEqual(len(outputs), 30)
                    self.assertNotIn(': line ', logs.getvalue())
                    self.assertNotIn('frozen', logs.getvalue())
                    self.assertEqual({path: path.read_bytes() for path in previous}, previous)
                    wanted = [matcher.replace(',no-resolve', '') if mode == 'strip' else matcher
                              for matcher in matchers]
                    expected_rows = {'parent': set(wanted), 'sourcechild': set(wanted),
                                     'whiteparent': {'DOMAIN-REGEX,^+ads'},
                                     'whitechild': {'DOMAIN-REGEX,other$*'}, 'cleared': set()}
                    for group, rows in expected_rows.items():
                        yaml = outputs[root / group / 'fin.yaml']
                        self.assertEqual(yaml.splitlines()[:2], [f'# {group} rules: {len(rows)}', 'payload:'])
                        self.assertEqual({json.loads(row[4:]) for row in yaml.splitlines()[2:]}, rows)
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(outputs[root / group / name], f'# {group} rules: 0\n')
                        self.assertEqual(outputs[root / group / 'fin-adb.txt'].splitlines()[6:],
                                         ['! Total count: 0'] + ([] if purpose == 'block' else
                                          ['! No AdBlock rules for non-advertising group.']))
                    counts = {group: {name + ':' + kind: 1 for name in FILES if name != 'fin.yaml'
                                      for kind in ('AND', *KINDS)} for group in ('parent', 'sourcechild')}
                    counts.update({group: {name + ':DOMAIN-REGEX': 1 for name in FILES if name != 'fin.yaml'}
                                   for group in ('whiteparent', 'whitechild')})
                    counts['cleared'] = {}
                    if purpose == 'block':
                        counts['whitechild']['fin-adb.txt:DOMAIN-REGEX'] = 2
                        counts['cleared']['fin-adb.txt:DOMAIN-REGEX'] = 1
                    expected_logs = ''.join(f'{config["name"]} {key}: {count}\n' for config in configs
                                            for key, count in sorted(counts[config['name']].items()))
                    self.assertEqual(logs.getvalue(), expected_logs)
                    publish(outputs, root=root)
                    self.assertEqual({path: path.read_bytes() for path in outputs},
                                     {path: text.encode('utf-8') for path, text in outputs.items()})
                    parents = {root / group / name: (root / group / name).read_bytes()
                               for group in ('parent', 'whiteparent') for name in FILES}
                    for group, count in (('parent', 4), ('whiteparent', 1)):
                        actual = (root / group / 'fin.yaml').read_bytes().decode('utf-8')
                        restored, warnings = parse(actual, purpose=purpose)
                        self.assertEqual(warnings, [])
                        self.assertEqual(len(restored), count)
                    self.assertEqual(parse_whitelist((root / 'whiteparent/fin.yaml').read_text(encoding='utf-8')),
                                     [Rule('DOMAIN-REGEX', '^+ads')])
                    (root / 'rulesets.json').write_text(json.dumps(configs[2:]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as disk_logs:
                        disk = generate(root, self.fail)
                    self.assertEqual(len(disk), 18)
                    self.assertNotIn(': line ', disk_logs.getvalue())
                    self.assertNotIn('frozen', disk_logs.getvalue())
                    self.assertEqual(disk_logs.getvalue(), ''.join(f'{config["name"]} {key}: {count}\n'
                                     for config in configs[2:] for key, count in sorted(counts[config['name']].items())))
                    for path, text in disk.items():
                        if path.name == 'fin-adb.txt':
                            self.assertEqual(text.splitlines()[6:], outputs[path].splitlines()[6:])
                        else:
                            self.assertEqual(text, outputs[path])
                    publish(disk, root=root)
                    self.assertEqual({path: path.read_bytes() for path in disk},
                                     {path: text.encode('utf-8') for path, text in disk.items()})
                    self.assertEqual({path: path.read_bytes() for path in parents}, parents)
                    self.assertEqual({path: path.read_bytes() for path in static}, static)
