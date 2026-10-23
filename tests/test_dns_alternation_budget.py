import contextlib
from datetime import datetime, timezone
import gc
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from dataclasses import replace
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, normalize, parse, parse_whitelist


FAMILIES = {'word': (r'\w',), 'letter': (r'\p{L}',),
            'double-word': (r'\w\w',), 'mixed': (r'\w', r'\p{L}')}
CONSUMERS = ('block', 'allow', 'white')


class DnsAlternationBudgetTests(unittest.TestCase):
    def test_repeated_word_keeps_single_branch_dns_bytes(self):
        bodies = []
        for value in (r'\w', r'\w|\w|\w|\w'):
            source = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
            rules, warnings = parse(source, purpose='block')
            self.assertEqual(warnings, [])
            self.assertEqual([rule.value for rule in rules], [value])
            outputs, diagnostics = render('dns', rules, purpose='block', no_resolve='keep')
            bodies.append(''.join(outputs['fin-adb.txt'].splitlines(keepends=True)[7:]).encode())
            if value == r'\w':
                self.assertEqual(len(bodies[-1]), 32390)
                self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)
        self.assertEqual(bodies[1], bodies[0])

    def convert(self, value, consumer, presentation='payload', *, purpose='block', neighbor=True):
        if presentation in ('payload', 'rules'):
            source = presentation + ':\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
        elif presentation == 'typed':
            source = 'DOMAIN-REGEX,' + value
        else:
            source = "DOMAIN-REGEX,'" + value + "'"
        parsed, warnings = parse(source, purpose=purpose)
        self.assertEqual((parsed, warnings), ([Rule('DOMAIN-REGEX', value)], []))
        self.assertEqual(normalize(parsed), parsed)
        white = parse_whitelist(source) if consumer == 'white' else []
        if consumer == 'white':
            self.assertEqual(white, parsed)
        selected = [] if consumer == 'white' else [replace(parsed[0], allow=consumer == 'allow')]
        if neighbor:
            selected.append(Rule('DOMAIN', 'ads.test'))
        outputs, diagnostics = render('dns', selected, purpose=purpose, no_resolve='keep', whitelist=white)
        self.assertEqual(parsed, [Rule('DOMAIN-REGEX', value)])
        return outputs, diagnostics

    def regex_bytes(self, outputs):
        rows = outputs['fin-adb.txt'].splitlines(keepends=True)[7:]
        self.assertTrue(all(row.endswith('\n') and len(row.encode()) <= 65536 for row in rows))
        return ''.join(row for row in rows if row.startswith(('/', '@@/'))).encode()

    def test_repeated_word_allow_and_real_white_keep_exact_exception_bytes(self):
        for consumer in ('allow', 'white'):
            with self.subTest(consumer=consumer):
                control, control_diagnostics = self.convert(r'\w', consumer)
                outputs, diagnostics = self.convert(r'\w|\w|\w|\w', consumer)
                expected = self.regex_bytes(control)
                self.assertEqual(len(expected), 32392)
                self.assertTrue(expected.startswith(b'@@/'))
                self.assertEqual(self.regex_bytes(outputs), expected)
                self.assertEqual(diagnostics, control_diagnostics)
                self.assertIn('0.0.0.0 ads.test\n', outputs['fin-adb.txt'])

    def test_four_families_and_all_presentations_preserve_other_targets(self):
        for family, atoms in FAMILIES.items():
            single, repeated = '|'.join(atoms), '|'.join(atoms * 4)
            for consumer in CONSUMERS:
                control, control_diagnostics = self.convert(single, consumer)
                expected = self.regex_bytes(control)
                self.assertTrue(expected)
                for presentation in ('payload', 'rules', 'typed', 'quoted'):
                    with self.subTest(family=family, consumer=consumer, presentation=presentation):
                        outputs, diagnostics = self.convert(repeated, consumer, presentation)
                        self.assertEqual(self.regex_bytes(outputs), expected)
                        self.assertEqual(diagnostics, control_diagnostics)
                        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)
                        self.assertIn('0.0.0.0 ads.test\n', outputs['fin-adb.txt'])
                        for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                            self.assertEqual(outputs[name], control[name])
                        payload = [json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]]
                        self.assertEqual(payload, ['DOMAIN,ads.test'] +
                                         (['DOMAIN-REGEX,' + repeated] if consumer == 'block' else []))
                        self.assertEqual(outputs['fin.yaml'].splitlines()[0], f'# dns rules: {len(payload)}')

    def test_nested_and_quantified_repetitions_keep_one_round_bytes(self):
        for atoms in FAMILIES.values():
            for suffix in ('', '{1}'):
                single = '(?:' + '|'.join(atoms) + ')' + suffix
                repeated = '(?:' + '|'.join(atoms * 4) + ')' + suffix
                for consumer in CONSUMERS:
                    with self.subTest(atoms=atoms, suffix=suffix, consumer=consumer):
                        control, _ = self.convert(single, consumer)
                        outputs, diagnostics = self.convert(repeated, consumer)
                        self.assertEqual(self.regex_bytes(outputs), self.regex_bytes(control))
                        self.assertTrue(self.regex_bytes(outputs))
                        self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)

    def test_direct_and_proxy_keep_the_existing_dns_comment(self):
        for purpose in ('direct', 'proxy'):
            for consumer in CONSUMERS:
                with self.subTest(purpose=purpose, consumer=consumer):
                    outputs, _ = self.convert('|'.join(FAMILIES['mixed'] * 4), consumer, purpose=purpose)
                    self.assertEqual(outputs['fin-adb.txt'].splitlines()[6:],
                                     ['! Total count: 0', '! No AdBlock rules for non-advertising group.'])

    def test_exact_final_line_budget_includes_exception_slashes_and_lf(self):
        for consumer in CONSUMERS:
            for atom in ('a', r'\w'):
                control, _ = self.convert('^' + atom, consumer)
                single = self.regex_bytes(control)
                padding = 65536 - len(single)
                expected = single[:-3] + b'a' * padding + b')/\n'
                self.assertEqual(len(expected), 65536)
                for extra in (0, 1):
                    branch = '^' + atom + 'a' * (padding + extra)
                    for count in (1, 4):
                        with self.subTest(consumer=consumer, atom=atom, extra=extra, count=count):
                            value = '|'.join([branch] * count)
                            outputs, diagnostics = self.convert(value, consumer)
                            self.assertEqual(self.regex_bytes(outputs), b'' if extra else expected)
                            self.assertEqual(diagnostics.get('fin-adb.txt:DOMAIN-REGEX', 0), extra)
                            self.assertIn('0.0.0.0 ads.test\n', outputs['fin-adb.txt'])
                            self.assertEqual(outputs['fin-adb.txt'].splitlines()[6],
                                             '! Total count: ' + str(1 if extra else 2))
                            if consumer == 'block':
                                payload = [json.loads(row[4:]) for row in outputs['fin.yaml'].splitlines()[2:]]
                                self.assertIn('DOMAIN-REGEX,' + value, payload)

    def test_distinct_branches_use_encoded_bytes_without_a_branch_count_limit(self):
        cases = (('large', 2, 64748), ('large', 3, 0),
                 ('small', 4096, 41010), ('small', 8192, 0))
        for family, count, line_bytes in cases:
            value = '|'.join((r'\w' + f'{index:04}x' if family == 'large' else f'123{index:05}x')
                             for index in range(count))
            for consumer in CONSUMERS:
                with self.subTest(family=family, count=count, consumer=consumer):
                    outputs, diagnostics = self.convert(value, consumer)
                    regex = self.regex_bytes(outputs)
                    expected_bytes = line_bytes + (2 if consumer != 'block' else 0) if line_bytes else 0
                    self.assertEqual(len(regex), expected_bytes)
                    self.assertEqual(len(regex.splitlines()), int(bool(line_bytes)))
                    self.assertEqual(diagnostics.get('fin-adb.txt:DOMAIN-REGEX', 0), int(not line_bytes))
                    self.assertIn('0.0.0.0 ads.test\n', outputs['fin-adb.txt'])
                    if consumer == 'block':
                        self.assertIn(json.dumps('DOMAIN-REGEX,' + value), outputs['fin.yaml'])

    def test_late_unknown_syntax_and_repeat_limits_are_not_hidden_by_reuse(self):
        prefix = '|'.join([r'\w'] * 512)
        tails = (r'(?-i:a)', r'(?=a)a', r'(?>a)', r'\p{M}', r'[é-ê]', r'\x{80}',
                 'a$', 'a{1001}', '(?:a{20}){51}', '(?:a{1001}){0}')
        for tail in tails:
            for wrapper in ('plain', 'universal', 'zero'):
                value = prefix + '|' + tail
                if wrapper == 'universal':
                    value = '(?:' + value + '|.)'
                elif wrapper == 'zero':
                    value = '(?:' + value + '){0}'
                for consumer in CONSUMERS:
                    with self.subTest(tail=tail, wrapper=wrapper, consumer=consumer):
                        outputs, diagnostics = self.convert(value, consumer)
                        self.assertEqual(self.regex_bytes(outputs), b'')
                        self.assertEqual(diagnostics['fin-adb.txt:DOMAIN-REGEX'], 1)
                        self.assertIn('0.0.0.0 ads.test\n', outputs['fin-adb.txt'])
        for tail in ('[a', 'a{2147483648}', 'a{2,1}'):
            source = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + prefix + '|' + tail)
            parsed, warnings = parse(source + '\n  - DOMAIN,ads.test', purpose='block')
            self.assertEqual(parsed, [Rule('DOMAIN', 'ads.test', domain_source='mihomo')])
            self.assertEqual(len(warnings), 1)
            self.assertTrue(warnings[0].startswith('line 2:'))

    def test_nullable_empty_universal_and_deep_repetitions_keep_their_certificates(self):
        prefix = '|'.join([r'\w'] * 512)
        universal = rb'''/(?-i:\A(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})*)/''' + b'\n'
        for consumer in CONSUMERS:
            expected = (b'@@' if consumer != 'block' else b'') + universal
            for value in ('(?:' + prefix + '){0}', prefix + '|', '(?:' + prefix + '|.)'):
                with self.subTest(consumer=consumer, value=value[:24]):
                    outputs, diagnostics = self.convert(value, consumer)
                    self.assertEqual(self.regex_bytes(outputs), expected)
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)
            control, _ = self.convert(r'\w', consumer)
            for depth in (600, 1000):
                with self.subTest(consumer=consumer, depth=depth):
                    value = '(?:' * depth + r'\w|\w|\w|\w' + ')' * depth
                    outputs, diagnostics = self.convert(value, consumer)
                    self.assertEqual(self.regex_bytes(outputs), self.regex_bytes(control))
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)

    def test_512_rounds_complete_three_consumers_within_eight_seconds(self):
        root = Path(__file__).resolve().parents[1]
        code = r'''
import hashlib
import json
from pathlib import Path
import sys
import time
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from tests.test_dns_alternation_budget import CONSUMERS, FAMILIES, DnsAlternationBudgetTests
assert (sys.getrecursionlimit(), sys.get_int_max_str_digits()) == (1000, 4300)
case = DnsAlternationBudgetTests()
atoms = FAMILIES[sys.argv[2]]
value = '|'.join(atoms * 512)
records = []
for consumer in CONSUMERS:
    control, _ = case.convert('|'.join(atoms), consumer)
    expected = case.regex_bytes(control)
    assert expected
    started = time.monotonic()
    outputs, diagnostics = case.convert(value, consumer)
    actual = case.regex_bytes(outputs)
    assert actual == expected and 'fin-adb.txt:DOMAIN-REGEX' not in diagnostics
    records.append({'consumer': consumer, 'seconds': time.monotonic() - started,
                    'line_bytes': len(actual), 'line_sha256': hashlib.sha256(actual).hexdigest()})
print(json.dumps({'family': sys.argv[2], 'rounds': 512, 'branches': 512 * len(atoms),
                  'value_sha256': hashlib.sha256(value.encode()).hexdigest(), 'records': records,
                  'source_sha256': hashlib.sha256((root / 'formats.py').read_bytes()).hexdigest()}))
'''
        for family, atoms in FAMILIES.items():
            with self.subTest(family=family):
                started = time.monotonic()
                result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(root), family],
                                        cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(result.stdout)
                record['process_seconds'] = time.monotonic() - started
                self.assertEqual(record['branches'], 512 * len(atoms))
                self.assertEqual(record['source_sha256'], hashlib.sha256((root / 'formats.py').read_bytes()).hexdigest())
                self.assertEqual([row['consumer'] for row in record['records']], list(CONSUMERS))
                print('dns-bounded ' + json.dumps(record), flush=True)

    def test_repeated_branch_allocation_growth_is_less_than_one_full_line_per_round(self):
        source_hash = hashlib.sha256((Path(__file__).resolve().parents[1] / 'formats.py').read_bytes()).hexdigest()
        for family, atoms in FAMILIES.items():
            for consumer in CONSUMERS:
                control, _ = self.convert('|'.join(atoms), consumer)
                expected = self.regex_bytes(control)
                self.assertTrue(expected)
                peaks, inputs = {}, {}
                for count in (64, 256, 512):
                    value = '|'.join(atoms * count)
                    source = 'payload:\n  - ' + json.dumps('DOMAIN-REGEX,' + value)
                    inputs[count] = hashlib.sha256(source.encode()).hexdigest()
                    re.purge()
                    gc.collect()
                    tracemalloc.start()
                    try:
                        outputs, diagnostics = self.convert(value, consumer)
                        actual = self.regex_bytes(outputs)
                        _, peaks[count] = tracemalloc.get_traced_memory()
                    finally:
                        tracemalloc.stop()
                    self.assertEqual(actual, expected, (family, consumer, count))
                    self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)
                intervals = []
                for left, right in ((64, 256), (256, 512), (64, 512)):
                    growth, threshold = peaks[right] - peaks[left], (right - left) * len(expected)
                    intervals.append({'left': left, 'right': right, 'growth': growth, 'threshold': threshold})
                    self.assertLess(growth, threshold, (family, consumer, peaks))
                print('dns-memory ' + json.dumps({'family': family, 'consumer': consumer,
                      'source_sha256': source_hash, 'input_sha256': inputs, 'python_peak_bytes': peaks,
                      'line_bytes': len(expected), 'intervals': intervals}), flush=True)

    def test_generate_publish_raw_and_yaml_dependencies_preserve_bytes_and_cli(self):
        from tests.test_functional_audit_projection import SurgeRootDotProjectionTests

        for family, atoms in FAMILIES.items():
            with self.subTest(family=family), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                single, repeated = '|'.join(atoms), '|'.join(atoms * 4)
                inputs = {root / 'static/control.list': ('DOMAIN-REGEX,' + single + '\n').encode(),
                          root / 'static/source.list': ('DOMAIN-REGEX,' + repeated + '\n').encode(),
                          root / 'static/neighbor.list': b'DOMAIN,ads.test\n',
                          root / 'static/untouched.bin': b'\x00\xffkeep static bytes\r\n'}
                for path, data in inputs.items():
                    path.write_bytes(data)

                def configs(source):
                    return [dict(name=name, purpose='block', no_resolve='keep', sources=sources, whitelist=white)
                            for name, sources, white in (
                                ('parent', [source], []),
                                ('raw-source', [source, 'static/neighbor.list'], []),
                                ('raw-white', ['static/neighbor.list'], [source]),
                                ('source-child', ['parent/fin.yaml', 'static/neighbor.list'], []),
                                ('white-child', ['static/neighbor.list'], ['parent/fin.yaml']))]

                old = {}
                for config in configs('static/source.list'):
                    (root / config['name']).mkdir()
                    for name in FILES:
                        path = root / config['name'] / name
                        old[path] = b'old output\x00\xff\r\n'
                        path.write_bytes(old[path])

                def run(config):
                    (root / 'rulesets.json').write_text(json.dumps(config), encoding='utf-8')
                    config_bytes = (root / 'rulesets.json').read_bytes()
                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                        clock.now.return_value = datetime(2026, 10, 23, 12, 34, tzinfo=timezone.utc)
                        outputs = generate(root, lambda url: self.fail(url))
                    self.assertEqual((root / 'rulesets.json').read_bytes(), config_bytes)
                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
                    return outputs, diagnostic.getvalue()

                control, control_diagnostics = run(configs('static/control.list'))
                outputs, diagnostics = run(configs('static/source.list'))
                self.assertEqual(len(outputs), 5 * len(FILES))
                self.assertEqual(diagnostics, control_diagnostics)
                self.assertNotIn('fin-adb.txt:DOMAIN-REGEX', diagnostics)
                self.assertNotIn('frozen', diagnostics)
                for config in configs('static/source.list'):
                    group = config['name']
                    products = {name: outputs[root / group / name] for name in FILES}
                    SurgeRootDotProjectionTests.assert_counts_and_split(self, products, 'block', group)
                    for name in FILES:
                        path = root / group / name
                        if name == 'fin.yaml':
                            self.assertEqual(outputs[path], control[path].replace(json.dumps('DOMAIN-REGEX,' + single),
                                                                                 json.dumps('DOMAIN-REGEX,' + repeated)))
                        else:
                            self.assertEqual(outputs[path], control[path])
                    expected, _ = self.convert(single, 'white' if 'white' in group else 'block', neighbor=False)
                    wanted = self.regex_bytes(expected)
                    self.assertTrue(wanted)
                    self.assertIn(wanted, products['fin-adb.txt'].encode())
                    if group != 'parent':
                        self.assertIn('0.0.0.0 ads.test\n', products['fin-adb.txt'])
                self.assertEqual({path: path.read_bytes() for path in old}, old)
                publish(outputs, root=root)
                published = {path: text.encode() for path, text in outputs.items()}
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                parent_yaml = (root / 'parent/fin.yaml').read_bytes()
                disk_config = configs('static/source.list')[1:]
                disk, disk_diagnostics = run(disk_config)
                self.assertEqual(disk, {path: text for path, text in outputs.items() if path.parent.name != 'parent'})
                self.assertEqual(disk_diagnostics, ''.join(line + '\n' for line in diagnostics.splitlines()
                                                         if not line.startswith('parent ')))
                publish(disk, root=root)
                self.assertEqual((root / 'parent/fin.yaml').read_bytes(), parent_yaml)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                if family == 'mixed':
                    product = Path(__file__).resolve().parents[1]
                    code = '''import runpy, sys
from datetime import datetime, timezone
from unittest.mock import patch
root = sys.argv.pop(1)
sys.path.insert(0, root)
with patch('formats.datetime') as clock:
    clock.now.return_value = datetime(2026, 10, 23, 12, 34, tzinfo=timezone.utc)
    runpy.run_path(root + '/generate.py', run_name='__main__')
'''
                    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(product), '--root', str(root)],
                                            cwd=product, capture_output=True, text=True, encoding='utf-8', timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, disk_diagnostics)
                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_public_allow_seam_publishes_exact_exception_bytes(self):
        for family, atoms in FAMILIES.items():
            with self.subTest(family=family), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'static').mkdir()
                marker = root / 'static/keep.bin'
                marker.write_bytes(b'\xff\x00original\r\n')
                with patch('formats.datetime') as clock:
                    clock.now.return_value = datetime(2026, 10, 23, 12, 34, tzinfo=timezone.utc)
                    control, control_diagnostics = self.convert('|'.join(atoms), 'allow')
                    outputs, diagnostics = self.convert('|'.join(atoms * 4), 'allow')
                self.assertEqual(outputs, control)
                self.assertEqual(diagnostics, control_diagnostics)
                self.assertTrue(self.regex_bytes(outputs).startswith(b'@@/'))
                paths = {root / 'dns' / name: text for name, text in outputs.items()}
                publish(paths, root=root)
                self.assertEqual({path: path.read_bytes() for path in paths},
                                 {path: text.encode() for path, text in paths.items()})
                self.assertEqual(marker.read_bytes(), b'\xff\x00original\r\n')

    def test_same_round_empty_yaml_is_legal_and_disk_only_empty_inputs_remain_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            value = r'\w|\w|\w|\w'
            inputs = {root / 'static/source.list': ('DOMAIN-REGEX,' + value + '\n').encode(),
                      root / 'static/neighbor.list': b'DOMAIN,ads.test\n'}
            for path, data in inputs.items():
                path.write_bytes(data)
            configs = [dict(name=name, purpose='block', no_resolve='keep', sources=sources, whitelist=white)
                       for name, sources, white in (
                           ('empty', ['static/source.list'], ['static/source.list']),
                           ('source-child', ['empty/fin.yaml'], []),
                           ('white-child', ['static/neighbor.list'], ['empty/fin.yaml']))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                outputs = generate(root, lambda url: self.fail(url))
            self.assertEqual(len(outputs), 3 * len(FILES))
            self.assertEqual(diagnostic.getvalue(), '')
            expected, _ = self.convert(r'\w', 'white', neighbor=False)
            self.assertEqual(self.regex_bytes({'fin-adb.txt': outputs[root / 'empty/fin-adb.txt']}),
                             self.regex_bytes(expected))
            for group in ('empty', 'source-child'):
                self.assertEqual(outputs[root / group / 'fin.yaml'], f'# {group} rules: 0\npayload:\n')
                for name in ('fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin-surge-ds.txt'):
                    self.assertEqual(outputs[root / group / name], f'# {group} rules: 0\n')
            self.assertEqual(outputs[root / 'source-child/fin-adb.txt'].splitlines()[7:], [])
            self.assertEqual(outputs[root / 'white-child/fin-adb.txt'].splitlines()[7:], ['0.0.0.0 ads.test'])
            publish(outputs, root=root)
            published = {path: text.encode() for path, text in outputs.items()}
            self.assertEqual({path: path.read_bytes() for path in published}, published)
            for config, message in ((configs[1], 'No adaptable rules'), (configs[2], 'Invalid whitelist')):
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, message), contextlib.redirect_stderr(io.StringIO()):
                    publish(generate(root, lambda url: self.fail(url)), root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
                self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_unknown_dns_is_local_and_existing_freeze_and_strict_input_boundaries_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            repeated = r'\w|\w|\w|\w'
            unknown = '|'.join([r'\w'] * 512) + r'|\p{M}'
            oversized = '|'.join(r'\w' + f'{index:04}x' for index in range(3))
            inputs = {root / 'static/source.list': ('DOMAIN-REGEX,' + repeated + '\n').encode(),
                      root / 'static/neighbor.list': b'DOMAIN,ads.test\n',
                      root / 'static/invalid.list': b'DOMAIN-REGEX,[a\n',
                      root / 'static/unsupported.yaml': ('payload:\n' + ''.join(
                          '  - ' + json.dumps('DOMAIN-REGEX,' + value) + '\n' for value in (unknown, oversized))).encode()}
            for path, data in inputs.items():
                path.write_bytes(data)
            remote = 'https://example.org/broken.list'
            configs = [dict(name=name, purpose='block', no_resolve='keep', sources=sources, whitelist=white)
                       for name, sources, white in (
                           ('frozen', [remote], []),
                           ('source-child', ['frozen/fin.yaml'], []),
                           ('white-child', ['static/neighbor.list'], ['frozen/fin.yaml']),
                           ('healthy', ['static/source.list', 'static/neighbor.list'], []),
                           ('unsupported', ['static/unsupported.yaml', 'static/neighbor.list'], []))]
            (root / 'rulesets.json').write_text(json.dumps(configs), encoding='utf-8')
            old = {}
            for config in configs:
                (root / config['name']).mkdir()
                for name in FILES:
                    path = root / config['name'] / name
                    old[path] = b'old frozen artifact\x00\xff\r\n'
                    path.write_bytes(old[path])

            def fetch(url):
                self.assertEqual(url, remote)
                return b'DOMAIN-REGEX,[a\n'

            with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                outputs = generate(root, fetch)
            self.assertEqual(set(outputs), {root / group / name for group in ('healthy', 'unsupported') for name in FILES})
            self.assertIn('unsupported fin-adb.txt:DOMAIN-REGEX: 2\n', diagnostic.getvalue())
            self.assertNotIn('healthy fin-adb.txt:DOMAIN-REGEX', diagnostic.getvalue())
            expected, _ = self.convert(r'\w', 'block')
            self.assertEqual(self.regex_bytes({'fin-adb.txt': outputs[root / 'healthy/fin-adb.txt']}),
                             self.regex_bytes(expected))
            self.assertEqual(outputs[root / 'unsupported/fin-adb.txt'].splitlines()[7:], ['0.0.0.0 ads.test'])
            for value in (unknown, oversized):
                self.assertIn(json.dumps('DOMAIN-REGEX,' + value), outputs[root / 'unsupported/fin.yaml'])
            self.assertEqual({path: path.read_bytes() for path in old}, old)
            publish(outputs, root=root)
            published = {path: outputs[path].encode() if path in outputs else data for path, data in old.items()}
            self.assertEqual({path: path.read_bytes() for path in published}, published)
            victim = root / 'frozen/fin.txt'
            victim.unlink()
            with self.assertRaisesRegex(ValueError, 'Cannot freeze frozen: missing complete old file'), \
                    contextlib.redirect_stderr(io.StringIO()):
                publish(generate(root, fetch), root=root)
            self.assertEqual({path: path.read_bytes() for path in published if path != victim},
                             {path: data for path, data in published.items() if path != victim})
            victim.write_bytes(published[victim])
            for white in (False, True):
                config = dict(configs[3], sources=['static/neighbor.list'] if white else ['static/invalid.list'],
                              whitelist=['static/invalid.list'] if white else [])
                (root / 'rulesets.json').write_text(json.dumps([config]), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'Invalid whitelist' if white else 'No adaptable rules'), \
                        contextlib.redirect_stderr(io.StringIO()):
                    publish(generate(root, fetch), root=root)
                self.assertEqual({path: path.read_bytes() for path in published}, published)
            product = Path(__file__).resolve().parents[1]
            code = "import runpy, sys; root=sys.argv.pop(1); sys.path.insert(0, root); runpy.run_path(root+'/generate.py', run_name='__main__')"
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(product), '--root', str(root)],
                                    cwd=product, capture_output=True, text=True, encoding='utf-8', timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Invalid whitelist', result.stderr)
            self.assertEqual({path: path.read_bytes() for path in published}, published)
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)
