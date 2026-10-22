import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from formats import FILES, render
from generate import generate, publish
from rules import Rule, exclude_covered, normalize, parse, parse_whitelist


class WildcardReadbackTests(unittest.TestCase):
    def test_native_universal_wildcard_reads_back_from_actual_text_and_yaml(self):
        parsed, messages = parse('payload:\n  - DOMAIN-WILDCARD,*\n', purpose='proxy')
        self.assertEqual((parsed, messages), ([Rule('DOMAIN-WILDCARD', '*', domain_source='mihomo')], []))
        outputs, _ = render('parent', normalize(parsed), purpose='proxy', no_resolve='keep')
        for name, source in (('fin.txt', 'surge'), ('fin-surge.txt', 'surge'),
                             ('fin-qx.txt', 'qx'), ('fin.yaml', 'mihomo')):
            with self.subTest(name=name):
                text = outputs[name].encode('utf-8').decode('utf-8')
                wanted = [Rule('DOMAIN-WILDCARD', '*', domain_source=source)]
                self.assertEqual(parse(text, purpose='proxy'), (wanted, []))
                self.assertEqual(parse_whitelist(text), wanted)
        self.assertEqual(outputs['fin.txt'], '# parent rules: 1\nDOMAIN-WILDCARD,*\n')
        self.assertEqual(outputs['fin-surge.txt'], outputs['fin.txt'])
        self.assertEqual(outputs['fin-qx.txt'], '# parent rules: 1\nHOST-WILDCARD,*,LIST\n')
        self.assertEqual(outputs['fin-surge-ds.txt'], '# parent rules: 0\n')

    def test_safe_patterns_read_back_as_sources_and_scalar_whitelists_in_nine_modes(self):
        patterns = ('*123*', '*?123*', '**123**', '*.*123*', '1..2*', '1' * 254 + '*')
        for pattern in patterns:
            for purpose in ('block', 'direct', 'proxy'):
                parsed, messages = parse('payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + pattern), purpose=purpose)
                self.assertEqual(messages, [])
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(pattern=pattern, purpose=purpose, mode=mode):
                        out, _ = render('parent', normalize(parsed), purpose=purpose, no_resolve=mode)
                        self.assertEqual(out['fin.txt'], '# parent rules: 1\nDOMAIN-WILDCARD,' + pattern + '\n')
                        self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
                        self.assertEqual(out['fin-surge-ds.txt'], '# parent rules: 0\n')
                        for name, source in (('fin.txt', 'surge'), ('fin-surge.txt', 'surge'),
                                             ('fin-qx.txt', 'qx'), ('fin.yaml', 'mihomo')):
                            text = out[name].encode('utf-8').decode('utf-8')
                            wanted = [Rule('DOMAIN-WILDCARD', pattern, domain_source=source)]
                            self.assertEqual(parse(text, purpose=purpose), (wanted, []))
                            self.assertEqual(parse_whitelist(text), wanted)
                        ordinary, messages = parse(out['fin.txt'], purpose=purpose)
                        again, skipped = render('child', ordinary, purpose=purpose, no_resolve=mode)
                        self.assertEqual(messages, [])
                        self.assertNotIn('fin.yaml:DOMAIN-WILDCARD', skipped)
                        reread, messages = parse(again['fin.yaml'], purpose=purpose)
                        self.assertEqual(messages, [])
                        self.assertEqual(reread[0].kind, 'DOMAIN-REGEX')
                        self.assertTrue(reread[0].value.startswith('^'))
                        if purpose == 'block':
                            self.assertEqual(len(again['fin-adb.txt'].splitlines()[7:]), 1)
                            self.assertNotIn('fin-adb.txt:DOMAIN-WILDCARD', skipped)

    def test_surge_quotes_protect_literal_wildcards_in_scalar_and_logical_readback(self):
        for pattern in ("'123*", "'123.456*", '(123)*', '*广告*'):
            matchers = ('DOMAIN-WILDCARD,' + pattern,
                        'AND,((DOMAIN-WILDCARD,' + pattern + '),(IP-CIDR,192.0.2.0/24))',
                        'OR,((DOMAIN-WILDCARD,' + pattern + '),(IP-CIDR,192.0.2.0/24))',
                        'NOT,((DOMAIN-WILDCARD,' + pattern + '))')
            for matcher in matchers:
                with self.subTest(pattern=pattern, matcher=matcher):
                    native, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose='proxy')
                    self.assertEqual(messages, [])
                    out, _ = render('quoted', native, purpose='proxy', no_resolve='keep')
                    expected = matcher.replace('DOMAIN-WILDCARD,' + pattern, 'DOMAIN-WILDCARD,' +
                                               ('"' + pattern + '"' if pattern.startswith("'") else
                                                "'" + pattern + "'" if '(' in pattern and native[0].kind != 'DOMAIN-WILDCARD' else pattern))
                    self.assertEqual(out['fin.txt'], '# quoted rules: 1\n' + expected + '\n')
                    self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
                    ordinary, messages = parse(out['fin.txt'], purpose='proxy')
                    self.assertEqual(messages, [])
                    self.assertEqual(len(ordinary), 1)
                    self.assertEqual(ordinary[0].domain_source, 'surge')
                    repeated, _ = render('quoted', ordinary, purpose='proxy', no_resolve='keep')
                    self.assertEqual(repeated['fin.txt'], out['fin.txt'])
                    self.assertEqual(repeated['fin-surge.txt'], out['fin-surge.txt'])
                    self.assertEqual(parse_whitelist(out['fin.txt']), ordinary if native[0].kind == 'DOMAIN-WILDCARD' else [])

    def test_logical_readback_keeps_destination_options_and_source_direction(self):
        for pattern in ('*', '*123*', '*?123*', '**123**'):
            for marked in (False, True):
                destination = '(IP-CIDR,192.0.2.0/24' + (',no-resolve)' if marked else ')')
                source = '(SRC-IP-CIDR,198.51.100.0/24)'
                leaf = '(DOMAIN-WILDCARD,' + pattern + ')'
                matchers = ('AND,(' + ','.join((leaf, destination, source)) + ')',
                            'OR,(' + ','.join((leaf, destination, source)) + ')',
                            'NOT,(' + leaf + ')',
                            'AND,((NOT,(' + leaf + ')),(OR,(' + destination + ',' + source + ')))')
                for matcher in matchers:
                    for purpose in ('block', 'direct', 'proxy'):
                        parsed, messages = parse('payload:\n  - ' + json.dumps(matcher), purpose=purpose)
                        self.assertEqual(messages, [])
                        for mode in ('add', 'strip', 'keep'):
                            with self.subTest(pattern=pattern, marked=marked, matcher=matcher, purpose=purpose, mode=mode):
                                out, skipped = render('logical', parsed, purpose=purpose, no_resolve=mode)
                                expected = matcher.replace(',no-resolve', '')
                                if mode == 'add' or mode == 'keep' and marked:
                                    expected = expected.replace('192.0.2.0/24)', '192.0.2.0/24,no-resolve)')
                                surge = expected.replace('SRC-IP-CIDR,', 'SRC-IP,')
                                self.assertEqual(out['fin.txt'], '# logical rules: 1\n' + surge + '\n')
                                self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
                                self.assertEqual(json.loads(out['fin.yaml'].splitlines()[2][4:]), expected)
                                for name in ('fin.txt', 'fin-surge.txt', 'fin.yaml'):
                                    ordinary, messages = parse(out[name], purpose=purpose)
                                    self.assertEqual(messages, [])
                                    self.assertEqual(len(ordinary), 1)
                                    self.assertNotIn('198.51.100.0/24,no-resolve', ordinary[0].value)
                                    again, _ = render('logical', ordinary, purpose=purpose, no_resolve='keep')
                                    self.assertEqual(again[name], out[name])
                                    self.assertEqual(parse_whitelist(out[name]), [])
                                self.assertEqual(skipped, {name + ':' + parsed[0].kind: 1 for name in
                                                           ('fin-qx.txt', 'fin-adb.txt', 'fin-surge-ds.txt')})

    def test_scalar_and_class_guards_leave_hostname_rules_unchanged(self):
        unsafe = ('', '.', '[', ']', '[]', '[!a]', '[^a]', '[a_b]', '[é]', '[a/b]',
                  '\x00', '\x08', '\x0b', '\x0c', '\x1f', '\x7f', '\x85', ' ', ' ', '\ud800', '￾', '￿')
        for prefix in ('DOMAIN-WILDCARD,', 'HOST-WILDCARD,'):
            for pattern in unsafe:
                with self.subTest(prefix=prefix, pattern=repr(pattern)):
                    text = prefix + '"' + pattern + '"'
                    parsed, messages = parse(text + '\nDOMAIN,neighbor.example.org', purpose='block')
                    self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                    self.assertTrue(messages)
                    with self.assertRaises(ValueError):
                        parse_whitelist(text)
        for pattern in ('*', '*123*', '1..2', '-123.example', '123-.example', '1' * 254):
            for prefix in ('DOMAIN,', 'DOMAIN-SUFFIX,', 'HOST,', 'HOST-SUFFIX,', '0.0.0.0 ', ''):
                with self.subTest(prefix=prefix, pattern=pattern):
                    parsed, messages = parse(prefix + pattern + '\nDOMAIN,neighbor.example.org', purpose='block')
                    self.assertEqual(parsed, [Rule('DOMAIN', 'neighbor.example.org')])
                    self.assertTrue(messages)

    def test_native_brackets_and_byte_root_case_guards_remain_target_local(self):
        for value in ('[12]*', 'api-[0-9].example.org'):
            ordinary, messages = parse('DOMAIN-WILDCARD,' + value, purpose='block')
            self.assertEqual(messages, [])
            out, skipped = render('class', ordinary, purpose='block', no_resolve='keep')
            self.assertNotIn('fin.yaml:DOMAIN-WILDCARD', skipped)
            self.assertNotIn('fin-adb.txt:DOMAIN-WILDCARD', skipped)
            self.assertEqual(skipped['fin-qx.txt:DOMAIN-WILDCARD'], 1)
        for value in ('*??123*', '*.*', '*.123', '*[12]*', '*ads*'):
            native, messages = parse('payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + value), purpose='block')
            self.assertEqual(messages, [])
            out, skipped = render('guard', native, purpose='block', no_resolve='keep')
            self.assertEqual(out['fin.txt'], '# guard rules: 0\n')
            self.assertEqual(out['fin-surge.txt'], out['fin.txt'])
            self.assertEqual(skipped['fin.txt:DOMAIN-WILDCARD'], 1)
            self.assertEqual(parse(out['fin.yaml'], purpose='block'), (native, []))
        for value in ('[z-a]*', '[a--b]*'):
            ordinary, messages = parse('DOMAIN-WILDCARD,' + value, purpose='block')
            self.assertEqual(messages, [])
            out, skipped = render('range', ordinary, purpose='block', no_resolve='keep')
            self.assertEqual(out['fin.yaml'], '# range rules: 0\npayload:\n')
            self.assertEqual(skipped['fin.yaml:DOMAIN-WILDCARD'], 1)
            self.assertEqual(out['fin-adb.txt'].splitlines()[7:], [])
        native, _ = parse('payload:\n  - "DOMAIN-WILDCARD,*[12]*"', purpose='block')
        ordinary = parse_whitelist('DOMAIN-WILDCARD,*[12]*')
        self.assertEqual(exclude_covered(native, ordinary), native)
        for value in ('K*', 'é*'):
            native, _ = parse('payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + value), purpose='block')
            white = parse_whitelist('HOST-WILDCARD,' + value)
            self.assertEqual(exclude_covered(native, white), native)

    def test_dotless_white_and_allow_filter_only_proved_coverage(self):
        blockers, messages = parse('DOMAIN,protected123.example.org\nDOMAIN,keep.example.org\n'
                                   'DOMAIN-SUFFIX,example.org', purpose='block')
        self.assertEqual(messages, [])
        white = parse_whitelist('DOMAIN-WILDCARD,*123*')
        allowed = Rule('DOMAIN-WILDCARD', '*123*', allow=True)
        self.assertEqual(exclude_covered([*blockers, allowed], white), [*blockers[1:], allowed])
        for input_allow in (False, True):
            for purpose in ('block', 'direct', 'proxy'):
                for mode in ('add', 'strip', 'keep'):
                    with self.subTest(input_allow=input_allow, purpose=purpose, mode=mode):
                        out, skipped = render('white', [*blockers, *([allowed] if input_allow else [])],
                                              whitelist=[] if input_allow else white, purpose=purpose, no_resolve=mode)
                        self.assertNotIn('DOMAIN,protected123.example.org\n', out['fin.txt'])
                        self.assertIn('DOMAIN,keep.example.org\n', out['fin.txt'])
                        self.assertIn('DOMAIN-SUFFIX,example.org\n', out['fin.txt'])
                        self.assertEqual(skipped['fin.txt:DOMAIN:whitelist-covered'], 1)
                        if purpose == 'block':
                            self.assertIn('@@/^.*123.*$/', out['fin-adb.txt'].splitlines()[7:])


class WildcardGeneratedDependencyTests(unittest.TestCase):
    def test_same_round_and_disk_source_white_bytes_publish_without_wildcard_loss(self):
        for pattern in ('*', '*123*'):
            for filename in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt', 'fin.yaml'):
                for role in ('source', 'white'):
                    for mixed in (False, True):
                        for purpose in ('block', 'direct', 'proxy'):
                            for mode in ('add', 'strip', 'keep'):
                                with self.subTest(pattern=pattern, filename=filename, role=role, mixed=mixed,
                                                  purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                                    root = Path(directory)
                                    (root / 'static').mkdir()
                                    native = root / 'static/pattern.yaml'
                                    native.write_text('payload:\n  - ' + json.dumps('DOMAIN-WILDCARD,' + pattern), encoding='utf-8')
                                    neighbor = root / 'static/neighbor.list'
                                    neighbor.write_text('DOMAIN,neighbor.example.org\nIP-CIDR,192.0.2.0/24,no-resolve\n'
                                                        'SRC-IP-CIDR,198.51.100.0/24\n', encoding='utf-8')
                                    blockers = ('DOMAIN,protected123.example.org', 'DOMAIN,keep.example.org',
                                                'DOMAIN,neighbor.example.org')
                                    consumer = root / 'static/consumer.list'
                                    if filename == 'fin.yaml':
                                        text = 'payload:\n' + ''.join('  - ' + json.dumps(row) + '\n' for row in blockers)
                                    elif filename == 'fin-qx.txt':
                                        text = '\n'.join(row.replace('DOMAIN,', 'HOST,') + ',LIST' for row in blockers)
                                    else:
                                        text = '\n'.join(blockers)
                                    consumer.write_text(text, encoding='utf-8')
                                    inputs = {path: path.read_bytes() for path in (native, neighbor, consumer)}
                                    parent = dict(name='parent', purpose=purpose, no_resolve=mode,
                                                  sources=['static/pattern.yaml'] + (['static/neighbor.list'] if mixed else []), whitelist=[])
                                    child = dict(name='child', purpose=purpose, no_resolve=mode,
                                                 sources=['parent/' + filename] if role == 'source' else ['static/consumer.list'],
                                                 whitelist=['parent/' + filename] if role == 'white' else [])
                                    config = root / 'rulesets.json'
                                    config.write_text(json.dumps([parent, child]), encoding='utf-8')
                                    old = {}
                                    for group in ('parent', 'child'):
                                        (root / group).mkdir()
                                        for name in FILES:
                                            path = root / group / name
                                            old[path] = b'previous complete output\x00\xff\r\n'
                                            path.write_bytes(old[path])
                                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as log:
                                        clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                                        outputs = generate(root, lambda url: self.fail(url))
                                    self.assertEqual(set(outputs), set(old))
                                    self.assertNotIn('invalid domain', log.getvalue())
                                    self.assertNotIn('frozen', log.getvalue())
                                    self.assertEqual({path: path.read_bytes() for path in old}, old)
                                    for group in ('parent', 'child'):
                                        full = set(outputs[root / group / 'fin.txt'].splitlines()[1:])
                                        split = set(outputs[root / group / 'fin-surge.txt'].splitlines()[1:])
                                        domainset = {('DOMAIN-SUFFIX,' + row[1:] if row.startswith('.') else 'DOMAIN,' + row)
                                                     for row in outputs[root / group / 'fin-surge-ds.txt'].splitlines()[1:]}
                                        self.assertEqual(full, split | domainset)
                                        self.assertFalse(split & domainset)
                                    if role == 'source':
                                        parsed, messages = parse(outputs[root / 'child' / filename], purpose=purpose)
                                        self.assertEqual(messages, [])
                                        self.assertIn(pattern, [rule.value for rule in parsed if rule.kind == 'DOMAIN-WILDCARD'])
                                    else:
                                        parsed, messages = parse(outputs[root / 'child/fin.yaml'], purpose=purpose)
                                        self.assertEqual(messages, [])
                                        domains = {rule.value for rule in parsed if rule.kind == 'DOMAIN'}
                                        self.assertNotIn('protected123.example.org', domains)
                                        self.assertEqual('keep.example.org' in domains, pattern != '*')
                                        self.assertEqual('neighbor.example.org' in domains,
                                                         pattern != '*' and (not mixed or filename == 'fin-surge.txt'))
                                    publish(outputs, root=root)
                                    published = {path: path.read_bytes() for path in outputs}
                                    self.assertEqual(published, {path: text.encode('utf-8') for path, text in outputs.items()})
                                    expected = {path: text for path, text in outputs.items() if path.parent.name == 'child'}
                                    expected_log = [line for line in log.getvalue().splitlines() if line.startswith('child ')]
                                    config.write_text(json.dumps([child]), encoding='utf-8')
                                    with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()) as log:
                                        clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                                        disk = generate(root, lambda url: self.fail(url))
                                    self.assertEqual(disk, expected)
                                    self.assertEqual(log.getvalue().splitlines(), expected_log)
                                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                                    publish(disk, root=root)
                                    self.assertEqual({path: path.read_bytes() for path in published}, published)
                                    self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_disk_only_mixed_source_and_white_do_not_warn_and_drop_wildcard(self):
        for name in ('fin.txt', 'fin-surge.txt', 'fin-qx.txt'):
            for role in ('source', 'white'):
                with self.subTest(name=name, role=role), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'native.yaml').write_text('payload:\n  - DOMAIN-WILDCARD,*123*\n'
                                                     '  - DOMAIN-KEYWORD,456\n', encoding='utf-8')
                    parent = dict(name='parent', purpose='block', no_resolve='keep', sources=['native.yaml'], whitelist=[])
                    config = root / 'rulesets.json'
                    config.write_text(json.dumps([parent]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()):
                        publish(generate(root, lambda url: self.fail(url)), root=root)
                    path = root / 'parent' / name
                    before = path.read_bytes()
                    source = 'HOST,protected123.example.org,LIST' if name == 'fin-qx.txt' else 'DOMAIN,protected123.example.org'
                    (root / 'source.list').write_text(source, encoding='utf-8')
                    child = dict(name='child', purpose='block', no_resolve='keep',
                                 sources=['parent/' + name] if role == 'source' else ['source.list'],
                                 whitelist=['parent/' + name] if role == 'white' else [])
                    config.write_text(json.dumps([child]), encoding='utf-8')
                    with contextlib.redirect_stderr(io.StringIO()) as log:
                        out = generate(root, lambda url: self.fail(url))
                    self.assertNotIn('invalid domain', log.getvalue())
                    if role == 'source':
                        self.assertIn('DOMAIN-WILDCARD,*123*\n', out[root / 'child/fin.txt'])
                    else:
                        self.assertEqual(out[root / 'child/fin.yaml'], '# child rules: 0\npayload:\n')
                    self.assertEqual(path.read_bytes(), before)

    def test_logical_generated_sources_read_actual_surge_and_yaml_bytes(self):
        for matcher in ('AND,((DOMAIN-WILDCARD,*?123*),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))',
                        'OR,((DOMAIN-WILDCARD,*123*),(DOMAIN-KEYWORD,456))',
                        'NOT,((DOMAIN-WILDCARD,*))',
                        'AND,((NOT,((DOMAIN-WILDCARD,**123**))),(OR,((IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))))'):
            for name in ('fin.txt', 'fin-surge.txt', 'fin.yaml'):
                for purpose in ('block', 'direct', 'proxy'):
                    for mode in ('add', 'strip', 'keep'):
                        with self.subTest(matcher=matcher, name=name, purpose=purpose, mode=mode), tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / 'native.yaml').write_text('payload:\n  - ' + json.dumps(matcher), encoding='utf-8')
                            parent = dict(name='parent', purpose=purpose, no_resolve=mode, sources=['native.yaml'], whitelist=[])
                            child = dict(name='child', purpose=purpose, no_resolve=mode, sources=['parent/' + name], whitelist=[])
                            config = root / 'rulesets.json'
                            config.write_text(json.dumps([parent, child]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                                out = generate(root, lambda url: self.fail(url))
                            self.assertEqual(len(out), 12)
                            for group in ('parent', 'child'):
                                parsed, messages = parse(out[root / group / name], purpose=purpose)
                                self.assertEqual(messages, [])
                                self.assertEqual(len(parsed), 1)
                                self.assertEqual(parsed[0].kind, matcher.partition(',')[0])
                                self.assertNotIn('198.51.100.0/24,no-resolve', parsed[0].value)
                            publish(out, root=root)
                            expected = {path: text for path, text in out.items() if path.parent.name == 'child'}
                            config.write_text(json.dumps([child]), encoding='utf-8')
                            with patch('formats.datetime') as clock, contextlib.redirect_stderr(io.StringIO()):
                                clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                                disk = generate(root, lambda url: self.fail(url))
                            self.assertEqual(disk, expected)

    def test_invalid_scalar_white_and_generated_logical_white_stop_before_publication(self):
        for invalid in (False, True):
            with self.subTest(invalid_scalar=invalid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'source.list').write_text('DOMAIN,protected.example.org', encoding='utf-8')
                (root / 'white.list').write_text('DOMAIN-WILDCARD,[', encoding='utf-8')
                (root / 'native.yaml').write_text('payload:\n  - "NOT,((DOMAIN-WILDCARD,*))"', encoding='utf-8')
                parent = dict(name='parent', purpose='block', no_resolve='keep', sources=['native.yaml'], whitelist=[])
                child = dict(name='child', purpose='block', no_resolve='keep', sources=['source.list'],
                             whitelist=['white.list' if invalid else 'parent/fin.txt'])
                (root / 'rulesets.json').write_text(json.dumps([parent, child]), encoding='utf-8')
                old = {}
                for group in ('parent', 'child'):
                    (root / group).mkdir()
                    for name in FILES:
                        path = root / group / name
                        old[path] = b'complete old bytes\r\n'
                        path.write_bytes(old[path])
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'Invalid whitelist'):
                    publish(generate(root, lambda url: self.fail(url)), root=root)
                self.assertEqual({path: path.read_bytes() for path in old}, old)
