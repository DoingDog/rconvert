import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class KeywordNormalizationPerformanceTests(unittest.TestCase):
    def run_bounded(self, code, *arguments):
        script = 'import sys; sys.path.insert(0, sys.argv[1])\n' + textwrap.dedent(code)
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), *arguments],
                                cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_long_keyword_normalize_and_generate_finish_within_existing_bound(self):
        for entry in ('normalize', 'generate'):
            with self.subTest(entry=entry):
                self.run_bounded(r'''
                    import contextlib
                    import io
                    import json
                    import tempfile
                    from pathlib import Path
                    from formats import render
                    from generate import generate, publish
                    from rules import Rule, normalize, parse

                    value = '1' * 65450
                    source = 'payload:\n  - DOMAIN-KEYWORD,' + value + '\n'
                    expected = [Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')]
                    def no_fetch(url):
                        raise AssertionError(url)
                    parsed, warnings = parse(source, purpose='block')
                    assert (parsed, warnings) == (expected, [])
                    direct, diagnostics = render('long', parsed, purpose='block', no_resolve='keep')
                    assert direct['fin.txt'] == '# long rules: 1\nDOMAIN-KEYWORD,' + value + '\n'
                    assert len(direct['fin-adb.txt'].splitlines()[7].encode('utf-8')) + 1 == 65536
                    assert diagnostics == {'fin-surge-ds.txt:DOMAIN-KEYWORD': 1}
                    if sys.argv[2] == 'normalize':
                        assert normalize(iter(parsed)) == expected
                    else:
                        with tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'input.yaml').write_text(source, encoding='utf-8')
                            (root / 'rulesets.json').write_text(json.dumps([
                                dict(name='long', purpose='block', no_resolve='keep',
                                     sources=['input.yaml'], whitelist=[])]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()) as log:
                                outputs = generate(root, no_fetch)
                            assert outputs[root / 'long/fin.txt'] == direct['fin.txt']
                            assert parse(outputs[root / 'long/fin.yaml'], purpose='block') == (expected, [])
                            assert len(outputs[root / 'long/fin-adb.txt'].splitlines()[7].encode('utf-8')) + 1 == 65536
                            assert log.getvalue().splitlines() == ['long fin-surge-ds.txt:DOMAIN-KEYWORD: 1']
                            publish(outputs, root=root)
                            assert all(path.read_bytes() == text.encode('utf-8') for path, text in outputs.items())
                ''', entry)

    def test_long_pairs_empty_keys_and_actual_shorter_keywords_keep_containment(self):
        self.run_bounded(r'''
            from formats import render
            from rules import Rule, normalize, parse

            first, second = '1' * 65450, '2' * 65450
            parsed, warnings = parse('payload:\n  - DOMAIN-KEYWORD,' + first +
                                     '\n  - DOMAIN-KEYWORD,' + second + '\n', purpose='block')
            assert warnings == [] and len(parsed) == 2
            empty = Rule('DOMAIN-KEYWORD', '', domain_source='mihomo')
            for order in (parsed, parsed[::-1], parsed[::-1] + parsed):
                assert normalize(iter(order)) == parsed
                assert normalize(iter([empty, *order])) == [empty, *parsed]
            short = Rule('DOMAIN-KEYWORD', '1', domain_source='mihomo')
            assert normalize(iter([*parsed, short])) == [short, parsed[1]]
            outputs, diagnostics = render('pair', normalize(parsed), purpose='block', no_resolve='keep')
            assert outputs['fin.txt'] == '# pair rules: 2\nDOMAIN-KEYWORD,' + first + '\nDOMAIN-KEYWORD,' + second + '\n'
            assert len(outputs['fin-adb.txt'].splitlines()[7:]) == 2
            assert all(len(row.encode('utf-8')) + 1 == 65536 for row in outputs['fin-adb.txt'].splitlines()[7:])
            assert diagnostics == {'fin-surge-ds.txt:DOMAIN-KEYWORD': 2}
            beyond = Rule('DOMAIN-KEYWORD', '1' * 65451, domain_source='mihomo')
            assert normalize(iter([beyond])) == [beyond]
            outputs, diagnostics = render('beyond', [beyond], purpose='block', no_resolve='keep')
            assert outputs['fin.txt'] == '# beyond rules: 1\nDOMAIN-KEYWORD,' + beyond.value + '\n'
            assert outputs['fin-adb.txt'].splitlines()[7:] == []
            assert diagnostics == {'fin-adb.txt:DOMAIN-KEYWORD': 1, 'fin-surge-ds.txt:DOMAIN-KEYWORD': 1}
        ''')

    def test_many_short_keywords_and_long_mixture_finish_within_existing_bound(self):
        for mixed in ('short-only', 'mixed'):
            with self.subTest(mixed=mixed):
                self.run_bounded(r'''
                    from rules import Rule, normalize, parse

                    values = [f'k{number:05d}x' for number in range(30000)]
                    source = 'payload:\n' + ''.join('  - DOMAIN-KEYWORD,' + value + '\n' for value in values)
                    parsed, warnings = parse(source, purpose='block')
                    expected = [Rule('DOMAIN-KEYWORD', value, domain_source='mihomo') for value in values]
                    assert (parsed, warnings) == (expected, [])
                    if sys.argv[2] == 'mixed':
                        long = Rule('DOMAIN-KEYWORD', '1' * 65450, domain_source='mihomo')
                        parsed.append(long)
                        expected.insert(0, long)
                    assert normalize(iter(parsed[::-1] + parsed)) == expected
                ''', mixed)

    def test_comparison_key_lengths_original_values_and_identity_groups_are_preserved(self):
        self.run_bounded(r'''
            from dataclasses import replace
            from formats import render
            from rules import Rule, normalize

            for source in ('surge', 'qx', 'mihomo'):
                values = ('İ', 'xİ') if source != 'mihomo' else ('İ', 'I9')
                pair = [Rule('DOMAIN-KEYWORD', value, domain_source=source) for value in values]
                for order in (pair, pair[::-1], pair + pair):
                    assert normalize(iter(order)) == pair[:1]
                guarded = [Rule('DOMAIN-KEYWORD', value, domain_source=source) for value in ('<İ>', '(?<İ>)')]
                assert set(normalize(iter(guarded[::-1] + guarded))) == set(guarded)
                outputs, diagnostics = render('unicode', normalize(guarded), purpose='proxy', no_resolve='keep')
                assert outputs['fin-qx.txt'] == '# unicode rules: 1\nHOST-KEYWORD,(?<İ>),LIST\n'
                assert diagnostics['fin-qx.txt:DOMAIN-KEYWORD'] == 1

            short = Rule('DOMAIN-KEYWORD', '1', domain_source='mihomo')
            long = Rule('DOMAIN-KEYWORD', '1' * 65450, domain_source='mihomo')
            attributes = ({'allow': True}, {'options': ('special',)}, {'literal_process': True},
                          {'native_fields': True}, {'domain_source': 'surge'}, {'domain_source': 'qx'})
            for attribute in attributes:
                changed = replace(long, **attribute)
                assert set(normalize(iter([changed, short, changed]))) == {short, changed}
                paired_short = replace(short, **attribute)
                assert normalize(iter([changed, paired_short, changed])) == [paired_short]
        ''')

    def test_long_keyword_source_and_white_dependencies_publish_and_read_actual_bytes(self):
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'strip', 'keep'):
                with self.subTest(purpose=purpose, mode=mode):
                    self.run_bounded(r'''
                        import contextlib
                        import io
                        import json
                        import tempfile
                        from pathlib import Path
                        from formats import FILES
                        from generate import generate, publish
                        from rules import Rule, exclude_covered, parse, parse_whitelist
                        from tests.test_formats import DNS_BYTE_TOKEN

                        purpose, mode = sys.argv[2:]
                        value = '1' * 65450
                        long = Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')
                        other = Rule('DOMAIN-KEYWORD', '9', domain_source='mihomo')
                        def no_fetch(url):
                            raise AssertionError(url)
                        def assert_products(outputs, root, group, keyword):
                            texts = {name: outputs[root / group / name] for name in FILES}
                            assert texts['fin.txt'] == '# ' + group + ' rules: 1\nDOMAIN-KEYWORD,' + keyword + '\n'
                            assert texts['fin-surge.txt'] == texts['fin.txt']
                            assert texts['fin-qx.txt'] == '# ' + group + ' rules: 1\nHOST-KEYWORD,' + keyword + ',LIST\n'
                            assert texts['fin.yaml'] == '# ' + group + ' rules: 1\npayload:\n  - ' + json.dumps('DOMAIN-KEYWORD,' + keyword) + '\n'
                            assert texts['fin-surge-ds.txt'] == '# ' + group + ' rules: 0\n'
                            dns = r'/(?s-i:\A' + DNS_BYTE_TOKEN + '*' + keyword + DNS_BYTE_TOKEN + r'*\z)/'
                            assert texts['fin-adb.txt'].splitlines()[6:] == (['! Total count: 1', dns] if purpose == 'block' else
                                                                                  ['! Total count: 0', '! No AdBlock rules for non-advertising group.'])
                            if purpose == 'block':
                                assert len(dns.encode('utf-8')) + 1 == (65536 if keyword == value else 87)

                        with tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'static').mkdir()
                            source = root / 'static/source.yaml'
                            source.write_bytes(b'\xef\xbb\xbfpayload:\r\n  - DOMAIN-KEYWORD,' + value.encode() + b'\r\n')
                            blocker = root / 'static/blocker.yaml'
                            blocker.write_bytes(b'payload:\n  - DOMAIN-KEYWORD,9\n')
                            inputs = {path: path.read_bytes() for path in (source, blocker)}
                            white = parse_whitelist(source.read_text(encoding='utf-8-sig'))
                            assert white == [long]
                            assert exclude_covered(iter([long, other]), iter(white)) == [other]
                            configs = [dict(name='parent', sources=['static/source.yaml'], whitelist=[]),
                                       dict(name='child', sources=['parent/fin.yaml'], whitelist=[]),
                                       dict(name='consumer', sources=['static/blocker.yaml'], whitelist=['parent/fin.yaml']),
                                       dict(name='external', sources=['static/blocker.yaml'], whitelist=['static/source.yaml'])]
                            for config in configs:
                                config.update(purpose=purpose, no_resolve=mode)
                            config_path = root / 'rulesets.json'
                            config_path.write_text(json.dumps(configs), encoding='utf-8')
                            old = {root / config['name'] / name: b'old\x00\xff' for config in configs for name in FILES}
                            for path, data in old.items():
                                path.parent.mkdir(exist_ok=True)
                                path.write_bytes(data)
                            with contextlib.redirect_stderr(io.StringIO()) as log:
                                outputs = generate(root, no_fetch)
                            assert set(outputs) == set(old)
                            assert all(path.read_bytes() == data for path, data in old.items())
                            for group in ('parent', 'child', 'consumer', 'external'):
                                assert_products(outputs, root, group, value if group in ('parent', 'child') else '9')
                            expected_log = []
                            for config in configs:
                                skips = {'fin-surge-ds.txt:DOMAIN-KEYWORD': 1}
                                if config['name'] in ('consumer', 'external') or purpose != 'block':
                                    skips['fin-adb.txt:DOMAIN-KEYWORD'] = 1
                                expected_log.extend(config['name'] + ' ' + key + ': ' + str(count) for key, count in sorted(skips.items()))
                            assert log.getvalue().splitlines() == expected_log
                            publish(outputs, root=root)
                            assert all(path.read_bytes() == text.encode('utf-8') for path, text in outputs.items())
                            assert parse((root / 'child/fin.yaml').read_text(encoding='utf-8'), purpose=purpose) == ([long], [])
                            assert parse_whitelist((root / 'parent/fin.yaml').read_text(encoding='utf-8')) == [long]
                            config_path.write_text(json.dumps(configs[1:]), encoding='utf-8')
                            with contextlib.redirect_stderr(io.StringIO()) as disk_log:
                                disk = generate(root, no_fetch)
                            assert set(disk) == {root / config['name'] / name for config in configs[1:] for name in FILES}
                            assert disk_log.getvalue().splitlines() == [line for line in expected_log if not line.startswith('parent ')]
                            for group in ('child', 'consumer', 'external'):
                                assert_products(disk, root, group, value if group == 'child' else '9')
                            for path, text in disk.items():
                                if path.name == 'fin-adb.txt':
                                    assert text.splitlines()[:5] + text.splitlines()[6:] == outputs[path].splitlines()[:5] + outputs[path].splitlines()[6:]
                                else:
                                    assert text == outputs[path]
                            publish(disk, root=root)
                            assert all(path.read_bytes() == text.encode('utf-8') for path, text in disk.items())
                            assert all(path.read_bytes() == data for path, data in inputs.items())
                    ''', purpose, mode)
