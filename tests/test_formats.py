import json
import re
import unittest
from datetime import datetime, timezone
from functools import partial
from unittest.mock import patch

from rules import Rule
from formats import render as render_configured


render = partial(render_configured, purpose="block", no_resolve="add")


def generated_payload(scalar, expected_records=None):
    from rules import _yaml_scalar

    payload, comment = _yaml_scalar(scalar, with_comment=True)
    prefix = '# rconvert-rule-v1 '
    assert comment.startswith(prefix), comment
    records = json.loads(comment[len(prefix):])
    assert type(records) is list and records
    assert all(type(record) is list and len(record) == 7 and
               all(type(record[index]) is str for index in (0, 1, 6)) and
               type(record[2]) is list and all(type(option) is str for option in record[2]) and
               all(type(record[index]) is bool for index in (3, 4, 5)) and
               record[6] in {'surge', 'mihomo', 'qx'} for record in records), records
    identities = [json.dumps(record, ensure_ascii=True, separators=(',', ':')) for record in records]
    assert len(set(identities)) == len(identities), records
    assert comment == prefix + json.dumps(records, ensure_ascii=True, separators=(',', ':')), comment
    if expected_records is not None:
        assert records == expected_records, (records, expected_records)
    return payload


def generated_text(text):
    from rules import _yaml_quoted

    lines = text.split('\n')
    for index, line in enumerate(lines):
        if line.startswith('  - '):
            generated_payload(line[4:])
            _, end = _yaml_quoted(line[4:])
            lines[index] = line[:4 + end]
    return '\n'.join(lines)


def generated_texts(outputs):
    return {name: generated_text(text) if str(name).endswith('fin.yaml') else text
            for name, text in outputs.items()}


def expected_domain(kind, value):
    # 独立的 ASCII 字面预期；固定大小写集合和两个锚点由本类字面回归另行检查。
    alphabet = dict(zip('abcdefghijklmnopqrstuvwxyz',
                        ('[' + char + char.upper() + ']' for char in 'abcdefghijklmnopqrstuvwxyz')))
    literal = ''.join(alphabet.get(char, '\\' + char if char in '.-' else char) for char in value)
    anchor = r'\A' if kind == 'DOMAIN' else r'(?:\A|\.)'
    return 'DOMAIN-REGEX,(?-i:' + anchor + literal + r'\.?\z)'


def expected_ordinary_payload(payload):
    return re.sub(r'(^|\()DOMAIN(-SUFFIX)?,([a-z0-9.-]+)(?=\)|$)',
                  lambda match: match[1] + expected_domain('DOMAIN' + (match[2] or ''), match[3]), payload)


def expected_ordinary_text(text):
    lines = text.split('\n')
    entries = []
    for index, line in enumerate(lines):
        if line.startswith('  - '):
            entries.append((index, '  - ' + json.dumps(expected_ordinary_payload(json.loads(line[4:])))))
        elif line.startswith('"'):
            lines[index] = json.dumps(expected_ordinary_payload(json.loads(line)))
    if entries:
        def order(line):
            kind, _, value = json.loads(line[4:]).partition(',')
            ip = kind.startswith(('IP-', 'IP6-', 'SRC-IP')) or kind in {'GEOIP', 'SRC-GEOIP'}
            family = 0 if kind in {'GEOIP', 'IP-ASN', 'SRC-GEOIP', 'SRC-IP-ASN'} else 2 if ':' in value else 1
            return ip, family if ip else 0, kind, len(line), line
        for (index, _), line in zip(entries, sorted((line for _, line in entries), key=order)):
            lines[index] = line
    return '\n'.join(lines)


def expected_process(value):
    kind = "PROCESS-PATH-REGEX" if value.startswith("/") else "PROCESS-NAME-REGEX"
    escaped = "".join("\\x{" + format(ord(char), "X") + "}" for char in value)
    end = "" if value.startswith("/") and value.endswith("/") else "\\z"
    return kind + ",(?-i:\\A" + escaped + end + ")"


NATIVE_KEYWORD_SOURCE = '''payload:
  - DOMAIN-KEYWORD,中文
  - AND,((DOMAIN-KEYWORD,中文),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))
  - OR,((DOMAIN-KEYWORD,中文),(NETWORK,udp))
  - NOT,((DOMAIN-KEYWORD,中文))
  - DOMAIN,keep.example.com
  - IP-CIDR,203.0.113.0/24,no-resolve
  - SRC-IP-CIDR,198.51.100.0/24
'''


def native_keyword_expected(group, purpose, mode):
    flag = ',no-resolve' if mode != 'strip' else ''
    conjunction = ('AND,((DOMAIN-KEYWORD,中文),(IP-CIDR,192.0.2.0/24' + flag +
                   '),(SRC-IP-CIDR,198.51.100.0/24))')
    negative = 'NOT,((DOMAIN-KEYWORD,中文))'
    alternative = 'OR,((DOMAIN-KEYWORD,中文),(NETWORK,udp))'
    ip = 'IP-CIDR,203.0.113.0/24' + flag
    surge_conjunction = conjunction.replace('SRC-IP-CIDR,', 'SRC-IP,')
    surge = [surge_conjunction, 'DOMAIN,keep.example.com', 'DOMAIN-KEYWORD,中文', negative,
             'OR,((DOMAIN-KEYWORD,中文),(PROTOCOL,UDP))', ip, 'SRC-IP,198.51.100.0/24']
    bodies = {'fin.txt': surge,
              'fin-qx.txt': ['HOST,keep.example.com,LIST', 'HOST-KEYWORD,中文,LIST',
                            'IP-CIDR,203.0.113.0/24,LIST' + flag],
              'fin.yaml': ['  - "' + line + '"' for line in
                           [conjunction, 'DOMAIN,keep.example.com', 'DOMAIN-KEYWORD,中文', negative,
                            alternative, ip, 'SRC-IP-CIDR,198.51.100.0/24']],
              'fin-surge.txt': [surge[0], *surge[2:]], 'fin-surge-ds.txt': ['keep.example.com']}
    expected = {name: f'# {group} rules: {len(body)}\n' + ('payload:\n' if name == 'fin.yaml' else '') +
                ''.join(line + '\n' for line in body) for name, body in bodies.items()}
    expected['fin-adb.txt'] = (
        f'[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n'
        '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n' +
        ('! Total count: 2\n/^.*中文.*$/\n0.0.0.0 keep.example.com\n' if purpose == 'block' else
         '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))
    return expected


def native_keyword_skips(purpose):
    skipped = {f'{name}:{kind}': 1 for name in ('fin-qx.txt', 'fin-adb.txt', 'fin-surge-ds.txt')
               for kind in ('AND', 'NOT', 'OR', 'SRC-IP-CIDR')}
    skipped.update({'fin-adb.txt:IP-CIDR': 1, 'fin-surge-ds.txt:IP-CIDR': 1,
                    'fin-surge-ds.txt:DOMAIN-KEYWORD': 1})
    if purpose != 'block':
        skipped.update({'fin-adb.txt:DOMAIN': 1, 'fin-adb.txt:DOMAIN-KEYWORD': 1})
    return skipped


class DomainSetSingleLabelFormatTests(unittest.TestCase):
    def test_exact_output_and_context_roundtrip_have_no_domain_set_skip(self):
        from rules import normalize, parse, parse_whitelist
        from tests.test_rules import DOMAIN_SET_LABELS

        for purpose in ("block", "direct", "proxy"):
            for mode in ("keep", "add", "strip"):
                for label in DOMAIN_SET_LABELS:
                    with self.subTest(purpose=purpose, mode=mode, label=label):
                        source, messages = parse(f"DOMAIN,{label}", purpose=purpose)
                        self.assertEqual(messages, [])
                        out, skipped = render_configured("parent", normalize(source), purpose=purpose, no_resolve=mode)
                        self.assertEqual(out["fin-surge-ds.txt"], f"# parent rules: 1\n{label}\n")
                        self.assertEqual(out["fin-surge.txt"], "# parent rules: 0\n")
                        self.assertEqual(skipped, {} if purpose == "block" else {"fin-adb.txt:DOMAIN": 1})
                        self.assertEqual(parse(out["fin-surge-ds.txt"], purpose=purpose, domain_set=True), (source, []))
                        self.assertEqual(parse_whitelist(out["fin-surge-ds.txt"], domain_set=True), source)
                        self.assertEqual(out["fin.txt"], f"# parent rules: 1\nDOMAIN,{label}\n")
                        self.assertEqual(out["fin-qx.txt"], f"# parent rules: 1\nHOST,{label},LIST\n")
                        record = [["DOMAIN", label, [], False, False, False, "surge"]]
                        self.assertEqual(out["fin.yaml"], '# parent rules: 1\npayload:\n  - ' +
                                         json.dumps(expected_domain("DOMAIN", label)) + ' # rconvert-rule-v1 ' +
                                         json.dumps(record, separators=(',', ':')) + '\n')
                        self.assertEqual(parse(out["fin.yaml"], purpose=purpose), (source, []))
                        dns = out["fin-adb.txt"].splitlines()
                        self.assertRegex(dns[5], r"^! Version: [0-9]{12}$")
                        datetime.strptime(dns[5].removeprefix("! Version: "), "%Y%m%d%H%M")
                        self.assertEqual(out["fin-adb.txt"],
                                         '[Adblock Plus 2.0]\n! Title: parent\n' +
                                         '! Homepage: https://github.com/DoingDog/rconvert\n! Expires: 1 day\n' +
                                         '! License: Inherits upstream licenses\n' + dns[5] + '\n' +
                                         (f'! Total count: 1\n0.0.0.0 {label}\n' if purpose == 'block' else
                                          '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))


class PublicStateRestorationFormatTests(unittest.TestCase):
    def test_ordinary_ascii_exact_suffix_projection_retains_public_kind(self):
        from rules import _yaml_scalar, parse

        expected = {'DOMAIN': r'DOMAIN-REGEX,(?-i:\A[kK][eE][eE][pP]\.[eE][xX][aA][mM][pP][lL][eE]\.[oO][rR][gG]\.?\z)',
                    'DOMAIN-SUFFIX': r'DOMAIN-REGEX,(?-i:(?:\A|\.)[kK][eE][eE][pP]\.[eE][xX][aA][mM][pP][lL][eE]\.[oO][rR][gG]\.?\z)'}
        for kind, payload in expected.items():
            original = Rule(kind, 'keep.example.org')
            output, _ = render_configured('public', [original], purpose='proxy', no_resolve='keep')
            self.assertEqual(_yaml_scalar(output['fin.yaml'].splitlines()[2][4:]), payload)
            self.assertEqual(parse(output['fin.yaml'], purpose='proxy'), ([original], []))

    def test_every_scalar_keeps_all_unique_seven_field_collisions(self):
        from rules import parse

        originals = [Rule('DOMAIN', 'keep.example.org', domain_source=source)
                     for source in ('mihomo', 'qx')]
        originals += [Rule('DST-PORT', '443'), Rule('DEST-PORT', '443'),
                      Rule('NETWORK', 'tcp'), Rule('PROTOCOL', 'TCP')]
        output, _ = render_configured('public', originals + originals, purpose='proxy', no_resolve='keep')
        lines = output['fin.yaml'].splitlines()
        self.assertEqual(lines[0], '# public rules: 3')
        expected = {
            'DOMAIN,keep.example.org': [['DOMAIN', 'keep.example.org', [], False, False, False, source]
                                        for source in ('mihomo', 'qx')],
            'DST-PORT,443': [[kind, '443', [], False, False, False, 'surge']
                            for kind in ('DEST-PORT', 'DST-PORT')],
            'NETWORK,tcp': [['NETWORK', 'tcp', [], False, False, False, 'surge'],
                            ['PROTOCOL', 'TCP', [], False, False, False, 'surge']],
        }
        for line in lines[2:]:
            payload = generated_payload(line[4:])
            generated_payload(line[4:], expected[payload])
        restored, messages = parse(output['fin.yaml'], purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(set(restored), set(originals))
        repeat, _ = render_configured('public', restored, purpose='proxy', no_resolve='keep')
        self.assertEqual(repeat, output)

    def test_effective_leaf_options_survive_strip_then_keep_reimport(self):
        from rules import parse

        original = Rule('AND', '((IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))')
        output, _ = render_configured('public', [original], purpose='proxy', no_resolve='strip')
        restored, messages = parse(output['fin.yaml'], purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(restored, [Rule('AND', '((IP-CIDR,192.0.2.0/24),(SRC-IP-CIDR,198.51.100.0/24))')])
        repeated, _ = render_configured('public', restored, purpose='proxy', no_resolve='keep')
        self.assertEqual(repeated, output)


class NativeKeywordFormatTests(unittest.TestCase):
    def test_r22_nine_modes_preserve_ordered_six_texts_and_leaf_flags(self):
        from rules import normalize, parse

        for purpose in ('block', 'direct', 'proxy'):
            parsed, messages = parse(NATIVE_KEYWORD_SOURCE, purpose=purpose)
            self.assertEqual(messages, [])
            for mode in ('add', 'keep', 'strip'):
                with self.subTest(purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                    clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                    outputs, skipped = render_configured('keyword', normalize(parsed), purpose=purpose, no_resolve=mode)
                self.assertEqual(generated_texts(outputs), native_keyword_expected('keyword', purpose, mode))
                self.assertEqual(skipped, native_keyword_skips(purpose))
                self.assertEqual(parse(outputs['fin.yaml'], purpose=purpose)[1], [])

    def test_r22_dns_allow_and_whitelist_keep_full_text(self):
        from rules import parse_whitelist

        keyword = Rule('DOMAIN-KEYWORD', '中文', allow=True, domain_source='mihomo')
        white = parse_whitelist('payload:\n  - DOMAIN-KEYWORD,中文')
        self.assertEqual(white, [Rule('DOMAIN-KEYWORD', '中文', domain_source='mihomo')])
        for purpose in ('block', 'direct', 'proxy'):
            for mode in ('add', 'keep', 'strip'):
                with self.subTest(purpose=purpose, mode=mode), patch('formats.datetime') as clock:
                    clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                    allowed, skipped = render_configured('keyword', [keyword], purpose=purpose, no_resolve=mode)
                    whitelisted, white_skips = render_configured('keyword', [], purpose=purpose, no_resolve=mode, whitelist=white)
                expected = {name: '# keyword rules: 0\n' + ('payload:\n' if name == 'fin.yaml' else '')
                            for name in ('fin.txt', 'fin-qx.txt', 'fin.yaml', 'fin-surge.txt', 'fin-surge-ds.txt')}
                expected['fin-adb.txt'] = (
                    '[Adblock Plus 2.0]\n! Title: keyword\n! Homepage: https://github.com/DoingDog/rconvert\n'
                    '! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n' +
                    ('! Total count: 1\n@@/^.*中文.*$/\n' if purpose == 'block' else
                     '! Total count: 0\n! No AdBlock rules for non-advertising group.\n'))
                self.assertEqual(allowed, expected)
                self.assertEqual(whitelisted, expected)
                self.assertEqual(skipped, {name + ':DOMAIN-KEYWORD': 1 for name in expected
                                          if name != 'fin-adb.txt' or purpose != 'block'})
                self.assertEqual(white_skips, {})


CONSTRUCTOR_SOURCE = '''payload:
  - DSCP,0-63
  - GEOSITE,geolocation-!cn
  - GEOIP,LAN,no-resolve
  - IN-NAME,<Foo>/A
  - IN-PORT,0-65535
  - IN-TYPE,HTTP / SOCKS
  - IN-USER,alice bob / <Alice>
  - IP-ASN,0,no-resolve
  - IP-CIDR6,127.0.0.1/8
  - IP-SUFFIX,192.0.2.7/24,no-resolve
  - PROCESS-NAME,<Foo>
  - PROCESS-PATH,/tmp/<Foo>
  - PROCESS-NAME-WILDCARD,*<Foo>*
  - PROCESS-PATH-WILDCARD,/tmp/*<Foo>*
  - REMATCH-NAME,<Foo>/B
  - SRC-GEOIP,LAN
  - SRC-IP-ASN,0
  - SRC-IP-SUFFIX,192.0.2.7/24
  - SRC-PORT,0-80
  - UID,1000-1002/2000
  - AND,((IN-TYPE,HTTP / SOCKS),(DSCP,0-63))
  - NOT,((IP-CIDR6,127.0.0.1/8))
DOMAIN,neighbor.example.com
IP-ASN,AS13335
IP-ASN,UNKNOWN,no-resolve
GEOIP,UNKNOWN
'''


def constructor_expected(group, purpose, mode):
    flag = ",no-resolve" if mode == "add" else ""
    kept = ",no-resolve" if mode != "strip" else ""
    geo = (["GEOIP,UNKNOWN", "GEOIP,LAN,no-resolve"] if mode == "keep" else
           ["GEOIP,LAN" + kept, "GEOIP,UNKNOWN" + flag])
    asn = (["IP-ASN,13335", "IP-ASN,0,no-resolve", "IP-ASN,UNKNOWN,no-resolve"] if mode == "keep" else
           ["IP-ASN,0" + kept, "IP-ASN,13335" + flag, "IP-ASN,UNKNOWN" + kept])
    cidr = "IP-CIDR,127.0.0.0/8" + flag
    negative = "NOT,((" + cidr + "))"
    surge = ["DOMAIN,neighbor.example.com", "IN-PORT,0-65535", negative, "SRC-PORT,0-80", *geo, *asn, cidr]
    qx = ["HOST,neighbor.example.com,LIST", *[line.replace(",no-resolve", "") + ",LIST" +
          (",no-resolve" if line.endswith(",no-resolve") else "") for line in geo + asn + [cidr]]]
    yaml = ["AND,((IN-TYPE,HTTP / SOCKS),(DSCP,0-63))", "DOMAIN,neighbor.example.com", "DSCP,0-63",
            "GEOSITE,geolocation-!cn", "IN-NAME,<Foo>/A", "IN-PORT,0-65535", "IN-TYPE,HTTP / SOCKS",
            "IN-USER,alice bob / <Alice>", negative, "PROCESS-NAME,<Foo>", "PROCESS-NAME-WILDCARD,*<Foo>*",
            "PROCESS-PATH,/tmp/<Foo>", "PROCESS-PATH-WILDCARD,/tmp/*<Foo>*", "REMATCH-NAME,<Foo>/B",
            "SRC-PORT,0-80", "UID,1000-1002/2000", "GEOIP,LAN" + kept,
            *(["IP-ASN,13335", "IP-ASN,0,no-resolve"] if mode == "keep" else
              ["IP-ASN,0" + kept, "IP-ASN,13335" + flag]),
            "SRC-GEOIP,LAN", "SRC-IP-ASN,0", cidr, "IP-SUFFIX,192.0.2.7/24" + kept,
            "SRC-IP-SUFFIX,192.0.2.7/24"]
    bodies = {"fin.txt": surge, "fin-qx.txt": qx, "fin.yaml": ["  - " + json.dumps(line) for line in yaml],
              "fin-surge.txt": surge[1:], "fin-surge-ds.txt": ["neighbor.example.com"]}
    expected = {name: f"# {group} rules: {len(body)}\n" + ("payload:\n" if name == "fin.yaml" else "") +
                "".join(line + "\n" for line in body) for name, body in bodies.items()}
    expected["fin-adb.txt"] = (
        f"[Adblock Plus 2.0]\n! Title: {group}\n! Homepage: https://github.com/DoingDog/rconvert\n"
        "! Expires: 1 day\n! License: Inherits upstream licenses\n! Version: 202610061200\n" +
        ("! Total count: 1\n0.0.0.0 neighbor.example.com\n" if purpose == "block" else
         "! Total count: 0\n! No AdBlock rules for non-advertising group.\n"))
    return expected


def constructor_skips(purpose):
    kinds = {"AND": 1, "DOMAIN": 1, "DSCP": 1, "GEOSITE": 1, "GEOIP": 2, "IN-NAME": 1,
             "IN-PORT": 1, "IN-TYPE": 1, "IN-USER": 1, "IP-ASN": 3, "IP-CIDR": 1, "IP-SUFFIX": 1,
             "NOT": 1, "PROCESS-NAME": 1, "PROCESS-NAME-WILDCARD": 1, "PROCESS-PATH": 1,
             "PROCESS-PATH-WILDCARD": 1, "REMATCH-NAME": 1, "SRC-GEOIP": 1, "SRC-IP-ASN": 1,
             "SRC-IP-SUFFIX": 1, "SRC-PORT": 1, "UID": 1}
    represented = {
        "fin.txt": {"DOMAIN", "GEOIP", "IN-PORT", "IP-ASN", "IP-CIDR", "NOT", "SRC-PORT"},
        "fin-surge.txt": {"DOMAIN", "GEOIP", "IN-PORT", "IP-ASN", "IP-CIDR", "NOT", "SRC-PORT"},
        "fin-qx.txt": {"DOMAIN", "GEOIP", "IP-ASN", "IP-CIDR"},
        "fin-adb.txt": {"DOMAIN"} if purpose == "block" else set(), "fin-surge-ds.txt": {"DOMAIN"},
    }
    skips = {f"{name}:{kind}": count for name, included in represented.items()
             for kind, count in kinds.items() if kind not in included}
    skips.update({"fin.yaml:GEOIP": 1, "fin.yaml:IP-ASN": 1})
    return skips


class ConstructorRendererTests(unittest.TestCase):
    def test_constructor_nine_modes_have_independent_ordered_six_texts(self):
        from rules import normalize, parse

        for purpose in ("block", "direct", "proxy"):
            parsed, messages = parse(CONSTRUCTOR_SOURCE, purpose=purpose)
            self.assertEqual(messages, [])
            for mode in ("add", "keep", "strip"):
                with self.subTest(purpose=purpose, mode=mode), patch("formats.datetime") as clock:
                    clock.now.return_value = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
                    outputs, skipped = render_configured("constructors", normalize(parsed), purpose=purpose, no_resolve=mode)
                expected = constructor_expected("constructors", purpose, mode)
                expected["fin.yaml"] = expected_ordinary_text(expected["fin.yaml"])
                self.assertEqual(generated_texts(outputs), expected)
                self.assertEqual(skipped, constructor_skips(purpose))
                self.assertEqual({name: text.encode("utf-8") for name, text in generated_texts(outputs).items()},
                                 {name: text.encode("utf-8") for name, text in expected.items()})

    def test_surge_unknown_mihomo_skip_covers_options_and_whole_logic(self):
        for kind in ("GEOIP", "IP-ASN"):
            for options in ((), ("no-resolve",)):
                for operator in (None, "AND", "OR", "NOT"):
                    expression = f"(({kind},unknown))" if operator == "NOT" else f"(({kind},unknown),(NETWORK,tcp))"
                    rule = Rule(operator, expression) if operator else Rule(kind, "unknown", options)
                    for mode in ("keep", "add", "strip"):
                        output, skips = render_configured("unknown", [rule], purpose="proxy", no_resolve=mode)
                        self.assertEqual(generated_text(output["fin.yaml"]), "# unknown rules: 0\npayload:\n")
                        self.assertEqual(skips[f"fin.yaml:{operator or kind}"], 1)
                        self.assertIn("unknown", output["fin.txt"])

    def test_unsigned_range_payloads_keep_mihomo_predicates(self):
        from rules import parse

        for source, matcher in (
            ("payload:\n  - DSCP,*", "DSCP,*"),
            ("payload:\n  - AND,((DSCP,/),(NETWORK,tcp))", "AND,((DSCP,/),(NETWORK,tcp))"),
            ("payload:\n  - NOT,((DSCP,//))", "NOT,((DSCP,//))"),
            ("payload:\n  - " + json.dumps("AND,((DSCP,\t),(NETWORK,tcp))"), "AND,((DSCP,\t),(NETWORK,tcp))"),
            ("AND,((DSCP,'\t'),(NETWORK,tcp)),PROXY", "AND,((DSCP,\t),(NETWORK,tcp))"),
            ("DSCP,'0,1',PROXY", "DSCP,0/1"),
            ("AND,((DSCP,'0,1'),(NETWORK,tcp)),PROXY", "AND,((DSCP,0/1),(NETWORK,tcp))"),
            ("UID,'1000,2000',PROXY", "UID,1000/2000"),
        ):
            for purpose in ("block", "direct", "proxy"):
                parsed, messages = parse(source, purpose=purpose, ignore_policy=True)
                self.assertEqual(messages, [])
                for mode in ("add", "keep", "strip"):
                    with self.subTest(source=source, purpose=purpose, mode=mode):
                        outputs, _ = render_configured("ranges", parsed, purpose=purpose, no_resolve=mode)
                        expected = '# ranges rules: 1\npayload:\n  - ' + json.dumps(matcher) + '\n'
                        self.assertEqual(generated_text(outputs["fin.yaml"]), expected)
                        self.assertEqual(parse(expected, purpose=purpose)[1], [])
        outputs, _ = render_configured("ranges", [Rule("DSCP", "0,1")], purpose="proxy", no_resolve="keep")
        self.assertEqual(generated_text(outputs["fin.yaml"]), '# ranges rules: 1\npayload:\n  - "DSCP,0/1"\n')
        for native in (False, True):
            for kind, value in (("AND", "((DSCP,),(NETWORK,tcp))"), ("NOT", "((DSCP,))")):
                with self.subTest(kind=kind, native=native):
                    outputs, skipped = render_configured("ranges", [Rule(kind, value, native_fields=native)],
                                                         purpose="proxy", no_resolve="keep")
                    self.assertEqual(generated_text(outputs["fin.yaml"]), '# ranges rules: 0\npayload:\n')
                    self.assertEqual(skipped["fin.yaml:" + kind], 1)

    def test_new_constructor_fields_allow_whitelist_normalize_and_rebuild(self):
        from dataclasses import fields
        from rules import exclude_covered, normalize, parse, parse_whitelist

        self.assertEqual([field.name for field in fields(Rule)],
                         ["kind", "value", "options", "allow", "literal_process", "native_fields", "domain_source"])
        source = "payload:\n  - IP-CIDR6,127.0.0.1/8\n  - IP-ASN,0\n  - IP-ASN,00\n  - SRC-IP-ASN,0"
        parsed, warnings = parse(source, purpose="proxy")
        self.assertEqual(warnings, [])
        allowed = parse_whitelist("payload:\n  - IP-CIDR6,127.0.0.0/8\n  - IP-ASN,0")
        self.assertEqual(exclude_covered(parsed, allowed), [Rule("IP-ASN", "00"), Rule("SRC-IP-ASN", "0")])
        self.assertEqual(exclude_covered([Rule("IP-ASN", "13335")], parse_whitelist("IP-ASN,AS13335")), [])
        self.assertEqual(exclude_covered(parse("IP-ASN,AS13335", purpose="proxy")[0], [Rule("IP-ASN", "13335")]), [])
        native, warnings = parse("payload:\n  - IN-TYPE,HTTP / SOCKS\n  - IN-NAME,A/ B\n  - IN-USER,alice bob\n  - GEOSITE,geolocation-!cn", purpose="proxy")
        self.assertEqual(warnings, [])
        self.assertEqual(parse_whitelist("payload:\n  - IN-TYPE,HTTP\n  - IN-USER,alice\n  - GEOSITE,youtube"), [])
        for original in native:
            allowed_rule = Rule(original.kind, original.value, allow=True)
            outputs, skipped = render_configured("constructors", [allowed_rule], purpose="block", no_resolve="add")
            self.assertEqual(skipped, {f"{name}:{original.kind}": 1 for name in outputs})
        for mode in ("add", "strip", "keep"):
            output, _ = render_configured("constructors", normalize(parsed), purpose="proxy", no_resolve=mode)
            reparsed, messages = parse(output["fin.yaml"], purpose="proxy")
            self.assertEqual(messages, [])
            self.assertTrue(all(not rule.native_fields and rule.domain_source == "surge" for rule in reparsed))
            self.assertEqual([rule.value for rule in reparsed if rule.kind == "IP-ASN"], ["0", "00"])


class DnsExactHostsFormatTests(unittest.TestCase):
    def test_all_exact_values_preserve_six_texts_purposes_and_modes(self):
        from tests.test_rules import DNS_EXACT_DOMAINS

        for purpose in ("block", "direct", "proxy"):
            for mode in ("keep", "add", "strip"):
                with self.subTest(purpose=purpose, mode=mode):
                    source = [Rule("DOMAIN", value) for value in DNS_EXACT_DOMAINS]
                    out, skipped = render_configured("exact", source, purpose=purpose, no_resolve=mode)
                    count = len(DNS_EXACT_DOMAINS)
                    ordered = sorted(DNS_EXACT_DOMAINS, key=lambda value: (len(value), value))
                    header = f"# exact rules: {count}\n"
                    self.assertEqual(out["fin.txt"], header + "".join(f"DOMAIN,{value}\n" for value in ordered))
                    self.assertEqual(out["fin-qx.txt"], header + "".join(f"HOST,{value},LIST\n" for value in ordered))
                    self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text(header + "payload:\n" + "".join(f'  - "DOMAIN,{value}"\n' for value in ordered)))
                    self.assertEqual(out["fin-surge-ds.txt"], header + "".join(value + "\n" for value in ordered))
                    self.assertEqual(out["fin-surge.txt"], "# exact rules: 0\n")
                    dns = out["fin-adb.txt"].splitlines()
                    self.assertEqual(dns[:5], ["[Adblock Plus 2.0]", "! Title: exact",
                                              "! Homepage: https://github.com/DoingDog/rconvert",
                                              "! Expires: 1 day", "! License: Inherits upstream licenses"])
                    self.assertRegex(dns[5], r"^! Version: [0-9]{12}$")
                    self.assertEqual(dns[6:], ([f"! Total count: {count}"] + [f"0.0.0.0 {value}" for value in ordered])
                                     if purpose == "block" else ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                    self.assertEqual(skipped, {} if purpose == "block" else {"fin-adb.txt:DOMAIN": count})
                    self.assertEqual(source, [Rule("DOMAIN", value) for value in DNS_EXACT_DOMAINS])

    def test_exact_allow_and_whitelist_stay_anchored_with_other_dns_kinds(self):
        from tests.test_rules import DNS_EXACT_DOMAINS

        for value in DNS_EXACT_DOMAINS:
            for mode in ("keep", "add", "strip"):
                for allow in (False, True):
                    with self.subTest(value=value, mode=mode, allow=allow):
                        selected = [Rule("DOMAIN", value), Rule("DOMAIN-SUFFIX", "broad.example.org"),
                                    Rule("DOMAIN-KEYWORD", "track"), Rule("DOMAIN-WILDCARD", "api-*.example.org"),
                                    Rule("DOMAIN-REGEX", "^ads[.]example[.]org$")]
                        whitelist = []
                        if allow:
                            selected.append(Rule("DOMAIN", value, allow=True))
                        else:
                            whitelist.append(Rule("DOMAIN", value))
                        out, skipped = render_configured("exact", selected, purpose="block", no_resolve=mode,
                                                         whitelist=whitelist)
                        expected = [f"@@|{value}|", f"0.0.0.0 {value}", "||broad.example.org^", "/^.*track.*$/",
                                    r"/^api\-.*\.example\.org$/", "/^ads[.]example[.]org$/"]
                        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                         ["! Total count: 6"] + sorted(expected, key=lambda line: (not line.startswith("@@"), len(line), line)))
                        self.assertNotIn("fin-adb.txt:DOMAIN", skipped)
                        self.assertEqual(skipped.get("fin-surge-ds.txt:DOMAIN-REGEX"), 1)
                        if allow:
                            for name in ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-surge.txt", "fin-surge-ds.txt"):
                                self.assertEqual(skipped[name + ":DOMAIN"], 1)
                        for text in out.values():
                            self.assertTrue(text.endswith("\n"))


class ProcessRendererCompletionTests(unittest.TestCase):
    def outputs(self, source, mode="keep"):
        from rules import normalize, parse

        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(messages, [])
        return render_configured("group", normalize(parsed), purpose="proxy", no_resolve=mode)

    def yaml_body(self, out):
        return [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]]

    def test_surge_literal_name_and_app_prefix_use_strict_case_sensitive_regex(self):
        cases = (("Foo", r"PROCESS-NAME-REGEX,(?-i:\A\x{46}\x{6F}\x{6F}\z)"),
                 ("/1", r"PROCESS-PATH-REGEX,(?-i:\A\x{2F}\x{31}\z)"),
                 ("/1/", r"PROCESS-PATH-REGEX,(?-i:\A\x{2F}\x{31}\x{2F})"))
        for value, expected in cases:
            for logical in (False, True):
                with self.subTest(value=value, logical=logical):
                    source = (f"AND,((PROCESS-NAME,{value}),(DOMAIN,x.example.com)),PROXY"
                              if logical else f"PROCESS-NAME,{value},PROXY")
                    out, skipped = self.outputs(source)
                    self.assertEqual(self.yaml_body(out), [f"AND,(({expected}),({expected_domain('DOMAIN', 'x.example.com')}))"
                                                          if logical else expected])
                    kind = "AND" if logical else "PROCESS-NAME"
                    self.assertEqual(skipped, {f"{name}:{kind}": 1 for name in
                                              ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")})
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertIn(f"PROCESS-NAME,{value}", out[name])

    def test_native_casefold_and_trailing_slash_do_not_change_surge_scope(self):
        for kind, value in (("PROCESS-NAME", "FooApp"), ("PROCESS-NAME", "S"),
                            ("PROCESS-NAME", "I"), ("PROCESS-PATH", "/123/"),
                            ("PROCESS-PATH", "/usr/bin/ssh"),
                            ("PROCESS-NAME-WILDCARD", "*telegram*"),
                            ("PROCESS-PATH-WILDCARD", "/usr/*/ssh")):
            for logical in (False, True):
                matcher = f"AND,(({kind},{value}),(DOMAIN,x.example.com))" if logical else f"{kind},{value}"
                with self.subTest(matcher=matcher):
                    out, skipped = self.outputs("payload:\n  - " + json.dumps(matcher))
                    self.assertEqual(self.yaml_body(out), [matcher])
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], "# group rules: 0\n")
                        self.assertEqual(skipped[f"{name}:{'AND' if logical else kind}"], 1)
        for kind, value in (("PROCESS-NAME", "123-_."), ("PROCESS-PATH", "/123/456"),
                            ("PROCESS-NAME-WILDCARD", "123")):
            out, skipped = self.outputs("payload:\n  - " + json.dumps(f"{kind},{value}"))
            for name in ("fin.txt", "fin-surge.txt"):
                self.assertEqual(out[name], f"# group rules: 1\nPROCESS-NAME,{value}\n")
                self.assertNotIn(f"{name}:{kind}", skipped)

    def test_surge_glob_keeps_source_and_counts_only_unproved_targets(self):
        for value in ("Foo*", "/usr/*/ssh", "?", "*", "123?", "[ab]*"):
            for logical in (False, True):
                source = f"AND,((PROCESS-NAME,{value}),(DOMAIN,x.example.com)),PROXY" if logical else f"PROCESS-NAME,{value},PROXY"
                with self.subTest(source=source):
                    out, skipped = self.outputs(source)
                    self.assertEqual(self.yaml_body(out), [])
                    self.assertEqual(skipped[f"fin.yaml:{'AND' if logical else 'PROCESS-NAME'}"], 1)
                    self.assertIn(f"PROCESS-NAME,{value}", out["fin.txt"])
                    self.assertEqual(out["fin.txt"], out["fin-surge.txt"])

    def test_logical_quoted_quantifier_and_literal_comma_regex_are_unquoted_for_mihomo(self):
        cases = (("DOMAIN-REGEX", '"^f{1,2}oo[.]example[.]org$"', "^f{1,2}oo[.]example[.]org$"),
                 ("PROCESS-NAME-REGEX", '"^Game,Inc$"', "^Game,Inc$"),
                 ("PROCESS-NAME-REGEX", "^Game,Inc$", "^Game,Inc$"),
                 ("PROCESS-PATH-REGEX", '"^/Game,Inc$"', "^/Game,Inc$"))
        for kind, field, value in cases:
            with self.subTest(kind=kind, field=field):
                out, skipped = self.outputs(f"AND,(({kind},{field}),(DOMAIN,x.example.com)),PROXY")
                self.assertEqual(self.yaml_body(out), [f"AND,(({kind},{value}),({expected_domain('DOMAIN', 'x.example.com')}))"])
                self.assertNotIn("fin.yaml:AND", skipped)

    def test_comment_markers_are_quoted_for_each_shared_surge_value(self):
        from rules import parse

        for marker in ("#", ";", "//"):
            for kind, value in (("PROCESS-NAME", f"Game {marker}1"),
                                ("USER-AGENT", f"Client {marker}1"),
                                ("URL-REGEX", f"^https://media.example.org/item {marker}1$")):
                for logical in (False, True):
                    field = f"'{value}'"
                    source = f"AND,(({kind},{field}),(DOMAIN,x.example.com)),PROXY" if logical else f"{kind},{field},PROXY"
                    with self.subTest(source=source):
                        out, _ = self.outputs(source)
                        for name in ("fin.txt", "fin-surge.txt"):
                            self.assertIn(f"{kind},{field}", out[name])
                            parsed, messages = parse(out[name], purpose="proxy")
                            self.assertEqual(messages, [])
                            again, _ = render_configured("group", parsed, purpose="proxy", no_resolve="keep")
                            self.assertEqual(again[name], out[name])

    def test_decoded_controls_use_safe_yaml_without_surrogate_pairs(self):
        from rules import parse

        for char in ("\0", "\r", "\n", "\x85", "\u2028", "\u2029", "\x7f", "\x9f", "\ufffe", "\uffff", "🙂"):
            for kind in ("PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "DOMAIN-REGEX"):
                value = "A" + char + "B"
                for logical in (False, True):
                    matcher = f"AND,(({kind},{value}),(DOMAIN,x.example.com))" if logical else f"{kind},{value}"
                    with self.subTest(char=repr(char), kind=kind, logical=logical):
                        out, skipped = self.outputs("payload:\n  - " + json.dumps(matcher, ensure_ascii=False).replace(char, f"\\u{ord(char):04x}") if ord(char) <= 0xffff else "payload:\n  - " + json.dumps(matcher, ensure_ascii=False))
                        self.assertEqual(self.yaml_body(out), [matcher])
                        reparsed, messages = parse(out["fin.yaml"], purpose="proxy")
                        self.assertEqual(messages, [])
                        repeated, _ = render_configured("group", reparsed, purpose="proxy", no_resolve="keep")
                        self.assertEqual(self.yaml_body(repeated), [matcher])
                        if char != "🙂":
                            for name in ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt"):
                                self.assertEqual(skipped.get(f"{name}:{'AND' if logical else kind}"), 1)
                                self.assertFalse(any(line and not line.startswith(("#", "!", "[Adblock"))
                                                     for line in out[name].splitlines()), name)
                            self.assertEqual(len(generated_text(out["fin.yaml"]).splitlines()), 3)
                            self.assertNotIn(char, generated_text(out["fin.yaml"]).splitlines()[2])
                        else:
                            self.assertIn("🙂", generated_text(out["fin.yaml"]))
                            self.assertNotIn("\\ud83d", generated_text(out["fin.yaml"]).lower())
                        self.assertNotIn(f"fin.yaml:{'AND' if logical else kind}", skipped)

    def test_native_ignored_tail_keeps_complete_rendered_logical_rule(self):
        from rules import parse

        for kind in ("PROCESS-NAME", "PROCESS-PATH", "IN-NAME"):
            for operator, expression in (("NOT", f"(({kind},Foo(,ignored)))"),
                                         ("AND", f"(({kind},Foo(,ignored)),(NETWORK,tcp))"),
                                         ("OR", f"(({kind},Foo(,ignored)),(NETWORK,tcp))")):
                source = "payload:\n  - " + json.dumps(operator + "," + expression)
                with self.subTest(source=source):
                    out, skipped = self.outputs(source)
                    self.assertEqual(self.yaml_body(out), [operator + "," + expression])
                    parsed, messages = parse(out["fin.yaml"], purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(len(parsed), 1)
                    self.assertNotIn(f"fin.yaml:{operator}", skipped)

    def test_deep_complete_render_and_no_resolve_have_bounded_subprocess_time(self):
        import subprocess
        import sys
        from pathlib import Path

        code = r'''
from tests.test_formats import generated_payload, expected_ordinary_payload

import json, sys, time
from rules import parse, normalize
from formats import render
limit = sys.getrecursionlimit()
for depth in (600, 1000):
    for long in (False, True):
        matcher = '^(' + '|'.join(f'host{index}.example.com' for index in range(1024)) + ')$'
        if long:
            assert len(matcher) == 20397
        for flagged in (False, True):
            leaf = '(AND,((IP-CIDR,203.0.113.0/24' + (',no-resolve' if flagged else '') + '),(SRC-IP-CIDR,127.0.0.0/8)' + (',(PROCESS-NAME-REGEX,' + matcher + ')' if long else ',(DOMAIN,x.example.com)') + '))'
            for native in (False, True):
                expression = '(NOT,(' * depth + leaf + '))' * depth
                source = 'payload:\n  - ' + json.dumps(expression[1:-1]) if native else expression[1:-1] + ',PROXY'
                parsed, warnings = parse(source, purpose='proxy')
                assert not warnings and len(parsed) == 1, warnings
                for mode in ('add', 'keep', 'strip'):
                    start = time.perf_counter()
                    out, skipped = render('group', normalize(parsed), purpose='proxy', no_resolve=mode)
                    flag = mode == 'add' or mode == 'keep' and flagged
                    expected = expression[1:-1].replace(',no-resolve', '')
                    if flag:
                        expected = expected.replace('IP-CIDR,203.0.113.0/24)', 'IP-CIDR,203.0.113.0/24,no-resolve)')
                    if not native:
                        expected = expected_ordinary_payload(expected)
                    actual = generated_payload(out['fin.yaml'].splitlines()[2][4:])
                    assert actual == expected and actual.count('no-resolve') == int(flag)
                    for target in ('fin.txt', 'fin-surge.txt'):
                        assert out[target] == '# group rules: 0\n' and skipped[target + ':NOT'] == 1
                    if long:
                        assert matcher in actual
                    assert sys.getrecursionlimit() == limit
print('complete')
'''
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertEqual(result.stdout.strip(), "complete")


class ProcessRendererReviewFixTests(unittest.TestCase):
    outputs = ProcessRendererCompletionTests.outputs
    yaml_body = ProcessRendererCompletionTests.yaml_body

    def test_logical_parentheses_and_trailing_backslashes_roundtrip_shared_fields(self):
        from rules import parse

        for kind in ("PROCESS-NAME", "USER-AGENT", "DEVICE-NAME"):
            for value in ("Game(1)\\", "Game(1)\\\\", "Game(1)\\\\\\", 'Game(\'1")\\'):
                field = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
                for operator in ("AND", "OR", "NOT"):
                    expression = f"(({kind},{field}))" if operator == "NOT" else f"(({kind},{field}),(DOMAIN,x.example.com))"
                    source = f"{operator},{expression},PROXY"
                    with self.subTest(source=source):
                        out, skipped = self.outputs(source)
                        for name in ("fin.txt", "fin-surge.txt"):
                            reparsed, messages = parse(out[name], purpose="proxy")
                            self.assertEqual(messages, [])
                            self.assertEqual(len(reparsed), 1)
                            self.assertNotIn(f"{name}:{operator}", skipped)
                            repeated, _ = render_configured("group", reparsed, purpose="proxy", no_resolve="keep")
                            self.assertEqual(repeated[name], out[name])
                            if kind == "PROCESS-NAME":
                                self.assertEqual(self.yaml_body(repeated), self.yaml_body(out))

    def test_native_in_user_ignored_tail_preserves_whole_logic(self):
        from rules import normalize, parse

        for operator in ("NOT", "AND", "OR"):
            expression = "((IN-USER,Foo(,ignored)))" if operator == "NOT" else "((IN-USER,Foo(,ignored)),(NETWORK,tcp))"
            matcher = operator + "," + expression
            source = "payload:\n  - " + json.dumps(matcher) + "\n  - DOMAIN,keep.example.com\n"
            with self.subTest(operator=operator):
                out, skipped = self.outputs(source)
                self.assertEqual(set(self.yaml_body(out)), {matcher, "DOMAIN,keep.example.com"})
                self.assertNotIn(f"fin.yaml:{operator}", skipped)
                parsed, messages = parse(out["fin.yaml"], purpose="proxy")
                self.assertEqual(messages, [])
                self.assertEqual(normalize(parsed), self.outputs_rules(source))

    def outputs_rules(self, source):
        from rules import normalize, parse

        parsed, messages = parse(source, purpose="proxy")
        self.assertEqual(messages, [])
        return normalize(parsed)

    def test_logical_regex_literal_parentheses_are_encoded_without_changing_groups(self):
        cases = ((r"^Game[(]Inc$", r"^Game[\x{28}]Inc$"),
                 (r"^foo[.)]example[.]org$", r"^foo[.\x{29}]example[.]org$"),
                 (r"^foo\(bar$", r"^foo\x{28}bar$"),
                 (r"^[a)b]\.example$", r"^[a\x{29}b]\.example$"),
                 (r"^foo\)bar$", r"^foo\x{29}bar$"),
                 (r"^(?<n>foo)[()]\k<n>$", r"^(?<n>foo)[\x{28}\x{29}]\k<n>$"),
                 (r"^[(-)]$", r"^[\x{28}-\x{29}]$"),
                 (r"^[]()]$", r"^[]\x{28}\x{29}]$"))
        for kind in ("PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "DOMAIN-REGEX"):
            for pattern, expected in cases:
                for quoted in (False, True):
                    field = '"' + pattern.replace("\\", "\\\\") + '"' if quoted else pattern
                    source = f"AND,(({kind},{field}),(NETWORK,tcp)),PROXY"
                    with self.subTest(source=source):
                        out, skipped = self.outputs(source)
                        self.assertEqual(self.yaml_body(out), [f"AND,(({kind},{expected}),(NETWORK,tcp))"])
                        self.assertNotIn("fin.yaml:AND", skipped)
                        self.assertEqual(len(self.outputs_rules(out["fin.yaml"])), 1)
        for pattern, expected in ((r"(?#left()^foo$", r"(?#left\x{28})^foo$"),
                                  (r"(?x)^foo$#left(right)", r"(?x)^foo$#left\x{28}right\x{29}"),
                                  (r"'foo[(]", r"'foo[\x{28}]"),
                                  (r"^[()-[)]]$", r"^[\x{28}\x{29}-[\x{29}]]$")):
            for kind in ("PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "DOMAIN-REGEX"):
                with self.subTest(kind=kind, pattern=pattern):
                    out, skipped = self.outputs(f'AND,(({kind},"{pattern}"),(NETWORK,tcp)),PROXY')
                    self.assertEqual(self.yaml_body(out), [f"AND,(({kind},{expected}),(NETWORK,tcp))"])
                    self.assertNotIn("fin.yaml:AND", skipped)
                    self.assertEqual(len(self.outputs_rules(out["fin.yaml"])), 1)
        for pattern in (r"^(foo|bar)$", r"(?-i:\Afoo\z)", r"(?#note)^foo$"):
            out, _ = self.outputs(f'AND,((DOMAIN-REGEX,"{pattern}"),(NETWORK,tcp)),PROXY')
            self.assertEqual(self.yaml_body(out), [f"AND,((DOMAIN-REGEX,{pattern}),(NETWORK,tcp))"])

    def test_case_invariant_unicode_native_literals_keep_surge_range(self):
        for scalar in ("中", "🙂", "₀", "؜", "\U000e0001"):
            for kind in ("PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"):
                value = "123" + scalar if "NAME" in kind else "/123/" + scalar
                for logical in (False, True):
                    matcher = f"AND,(({kind},{value}),(NETWORK,tcp))" if logical else f"{kind},{value}"
                    with self.subTest(matcher=matcher):
                        out, skipped = self.outputs("payload:\n  - " + json.dumps(matcher, ensure_ascii=False))
                        expected = f"AND,((PROCESS-NAME,{value}),(PROTOCOL,TCP))" if logical else f"PROCESS-NAME,{value}"
                        for name in ("fin.txt", "fin-surge.txt"):
                            self.assertEqual(out[name], "# group rules: 1\n" + expected + "\n")
                            self.assertNotIn(f"{name}:{'AND' if logical else kind}", skipped)
                        self.assertEqual(self.yaml_body(out), [matcher])
        for scalar in ("Σ", "ς", "ſ", "K", "Ⅳ", "\u0345", "\U00010400"):
            out, skipped = self.outputs("payload:\n  - " + json.dumps("PROCESS-NAME,123" + scalar, ensure_ascii=False))
            self.assertEqual(out["fin.txt"], "# group rules: 0\n")
            self.assertEqual(skipped["fin.txt:PROCESS-NAME"], 1)

    def test_native_simplefold_singleton_i_keeps_exact_literal_scope(self):
        for scalar in ("İ", "ı"):
            for kind in ("PROCESS-NAME", "PROCESS-PATH"):
                value = "123" + scalar if kind == "PROCESS-NAME" else "/123/" + scalar
                out, skipped = self.outputs("payload:\n  - " + json.dumps(kind + "," + value, ensure_ascii=False))
                self.assertEqual(out["fin.txt"], "# group rules: 1\nPROCESS-NAME," + value + "\n")
                self.assertNotIn("fin.txt:" + kind, skipped)
        out, skipped = self.outputs('payload:\n  - "PROCESS-NAME-WILDCARD,123İ"')
        self.assertEqual(out["fin.txt"], "# group rules: 0\n")
        self.assertEqual(skipped["fin.txt:PROCESS-NAME-WILDCARD"], 1)

    def test_allow_and_whitelist_share_line_unsafe_skip_counts(self):
        from rules import parse, parse_whitelist

        for char in ("\0", "\r", "\n", "\x85", "\u2028", "\u2029", "\x7f", "\x9f", "\ufffe", "\uffff"):
            value = "^A" + char + "B$"
            source = "payload:\n  - " + json.dumps("DOMAIN-REGEX," + value)
            parsed, messages = parse(source, purpose="block")
            self.assertEqual(messages, [])
            for allow in (False, True):
                with self.subTest(char=repr(char), allow=allow):
                    selected = [Rule("DOMAIN-REGEX", value, allow=True)] if allow else []
                    out, skipped = render_configured("group", [Rule("DOMAIN", "keep.example.com"), *selected],
                                                     purpose="block", no_resolve="keep",
                                                     whitelist=() if allow else parse_whitelist(source))
                    self.assertEqual(out["fin-adb.txt"].splitlines()[7:], ["0.0.0.0 keep.example.com"])
                    self.assertEqual(out["fin-adb.txt"].splitlines()[6], "! Total count: 1")
                    self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 1)

    def test_surge_logical_depth_limit_is_target_local(self):
        for native in (False, True):
            for depth in (1, 10, 11, 12, 600, 1000):
                matcher = ("(NOT,(" * depth + "(DOMAIN,deep.example.com)" + "))" * depth)[1:-1]
                source = ("payload:\n  - " + json.dumps(matcher) + "\n  - DOMAIN,keep.example.com" if native else
                          matcher + ",PROXY\nDOMAIN,keep.example.com,PROXY")
                with self.subTest(native=native, depth=depth):
                    out, skipped = self.outputs(source)
                    self.assertEqual(set(self.yaml_body(out)), {matcher, "DOMAIN,keep.example.com"} if native else {expected_ordinary_payload(matcher), expected_domain("DOMAIN", "keep.example.com")})
                    allowed = depth <= 10
                    self.assertEqual(set(out["fin.txt"].splitlines()[1:]), {"DOMAIN,keep.example.com"} | ({matcher} if allowed else set()))
                    self.assertEqual(out["fin-surge.txt"], f"# group rules: {int(allowed)}\n" + (matcher + "\n" if allowed else ""))
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(skipped.get(f"{name}:NOT", 0), int(not allowed))


class ProcessRendererRound2FixTests(unittest.TestCase):
    outputs = ProcessRendererCompletionTests.outputs
    yaml_body = ProcessRendererCompletionTests.yaml_body

    def test_shared_surge_fields_preserve_boundary_whitespace(self):
        from rules import parse

        for char in ("\t", "\xa0", " ", " ", "　"):
            for position in ("leading", "trailing", "middle"):
                for kind in ("PROCESS-NAME", "USER-AGENT", "DEVICE-NAME", "URL-REGEX"):
                    value = char + "123" if position == "leading" else "123" + char if position == "trailing" else "12" + char + "3"
                    for operator in ("", "AND", "OR", "NOT"):
                        leaf = f"{kind},'{value}'"
                        source = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(PROTOCOL,TCP))"
                        for mode in ("add", "keep", "strip"):
                            with self.subTest(kind=kind, char=repr(char), position=position, operator=operator, mode=mode):
                                out, skipped = self.outputs(source + ",PROXY", mode)
                                field = f"'{value}'" if position != "middle" else value
                                expected_leaf = f"{kind},{field}"
                                expected = expected_leaf if not operator else f"NOT,(({expected_leaf}))" if operator == "NOT" else f"{operator},(({expected_leaf}),(PROTOCOL,TCP))"
                                for name in ("fin.txt", "fin-surge.txt"):
                                    self.assertEqual(out[name], "# group rules: 1\n" + expected + "\n")
                                    self.assertNotIn(f"{name}:{operator or kind}", skipped)
                                    parsed, messages = parse(out[name], purpose="proxy")
                                    self.assertEqual(messages, [])
                                    repeated, _ = render_configured("group", parsed, purpose="proxy", no_resolve=mode)
                                    self.assertEqual(repeated[name], out[name])

    def test_native_process_boundary_whitespace_does_not_become_bundle_prefix(self):
        from rules import parse

        for kind in ("PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"):
            for char in ("\t", "\xa0", " ", " ", "　"):
                for position in ("leading", "trailing", "middle"):
                    base = "123" if "NAME" in kind else "/123/456"
                    value = char + base if position == "leading" else base + char if position == "trailing" else base[:2] + char + base[2:]
                    for operator in ("", "AND", "OR", "NOT"):
                        leaf = f"{kind},{value}"
                        matcher = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))"
                        for mode in ("add", "keep", "strip"):
                            with self.subTest(matcher=matcher, mode=mode):
                                out, skipped = self.outputs("payload:\n  - " + json.dumps(matcher, ensure_ascii=False), mode)
                                self.assertEqual(self.yaml_body(out), [matcher])
                                for name in ("fin.txt", "fin-surge.txt"):
                                    if "PATH" in kind and position == "leading":
                                        self.assertEqual(out[name], "# group rules: 0\n")
                                        self.assertEqual(skipped[f"{name}:{operator or kind}"], 1)
                                        continue
                                    parsed, messages = parse(out[name], purpose="proxy")
                                    self.assertEqual(messages, [])
                                    self.assertEqual(len(parsed), 1)
                                    again, _ = render_configured("group", parsed, purpose="proxy", no_resolve=mode)
                                    self.assertEqual(again[name], out[name])
                                    expected = expected_process(value)
                                    strict = expected if not operator else f"NOT,(({expected}))" if operator == "NOT" else f"{operator},(({expected}),(NETWORK,tcp))"
                                    self.assertEqual(self.yaml_body(again), [strict])
        for operator in ("", "AND", "OR", "NOT"):
            leaf = "PROCESS-PATH,/123/\xa0"
            matcher = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))"
            out, _ = self.outputs("payload:\n  - " + json.dumps(matcher))
            parsed, messages = parse(out["fin.txt"], purpose="proxy")
            self.assertEqual(messages, [])
            again, _ = render_configured("group", parsed, purpose="proxy", no_resolve="keep")
            self.assertIn(r"\x{A0}\z", self.yaml_body(again)[0])

    def test_ordinary_regex_comma_spaces_preserve_lexical_meaning(self):
        cases = ((r"^f{1, 2}oo[.]example[.]org$", r"^f{1\x{2C} 2}oo[.]example[.]org$"),
                 (r"^[a, b][.]example$", r"^[a\x{2C} b][.]example$"),
                 (r"^a ,b$", r"^a \x{2C}b$"),
                 (r"(?x)^f{1, 2}oo$", r"(?x)^f{1\x{2C} 2}oo$"),
                 (r"(?x)^a , b$", r"(?x)^a \x{2C} b$"),
                 (r"(?x)^[a, b]$", r"(?x)^[a\x{2C} b]$"),
                 (r"(?x)^a\ ,b$", r"(?x)^a\ \x{2C}b$"),
                 (r"^a\, b$", r"^a\x{2C} b$"),
                 (r"^[ ,-a]$", r"^[ \x{2C}-a]$"),
                 (r"^[] ,]$", r"^[] \x{2C}]$"),
                 (r"^(?<n>a ,b)\k<n>$", r"^(?<n>a \x{2C}b)\k<n>$"),
                 (r"(?#a , b)^foo$", r"(?#a \x{2C} b)^foo$"),
                 (r"(?x)^foo$#a , b", r"(?x)^foo$#a \x{2C} b"),
                 (r"^a{1,2} ,b$", r"^a{1,2} \x{2C}b$"),
                 (r"(?x:^(?-x:a , b))$", r"(?x:^(?-x:a \x{2C} b))$"),
                 (r"^a, ", r"^a\x{2C} (?:)"),
                 (r" ,a$", r"(?:) \x{2C}a$"),
                 (r"(?x)^a, ", r"(?x)^a\x{2C} (?:)"),
                 (r"(?x)^a$#a, ", r"(?x)^a$#a\x{2C} (?:)"))
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for pattern, encoded in cases:
                field = '"' + pattern.replace("\\", "\\\\") + '"'
                for operator in ("", "AND", "OR", "NOT"):
                    leaf = f"{kind},{field}"
                    source = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))"
                    for mode in ("add", "keep", "strip"):
                        with self.subTest(kind=kind, pattern=pattern, operator=operator, mode=mode):
                            out, skipped = self.outputs(source + ",PROXY", mode)
                            expected = f"{kind},{encoded}"
                            expected = expected if not operator else f"NOT,(({expected}))" if operator == "NOT" else f"{operator},(({expected}),(NETWORK,tcp))"
                            self.assertEqual(self.yaml_body(out), [expected])
                            self.assertNotIn(f"fin.yaml:{operator or kind}", skipped)
                            repeated, _ = self.outputs(out["fin.yaml"], mode)
                            self.assertEqual(self.yaml_body(repeated), [expected])
                            consumed = ",".join(part.strip(" ") for part in expected.split(","))
                            self.assertEqual(consumed, expected)
                            native = f"{kind}," + ",".join(part.strip(" ") for part in pattern.split(","))
                            native = native if not operator else f"NOT,(({native}))" if operator == "NOT" else f"{operator},(({native}),(NETWORK,tcp))"
                            native_out, _ = self.outputs("payload:\n  - " + json.dumps(native), mode)
                            self.assertEqual(self.yaml_body(native_out), [native])

    def test_dotless_native_wildcard_keeps_tolower_singleton_scope(self):
        for scalar in ("ı", "İ", "I", "i", "ſ", "Σ"):
            for kind in ("PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"):
                value = ("123" if "NAME" in kind else "/123/") + scalar
                for operator in ("", "AND", "OR", "NOT"):
                    leaf = f"{kind},{value}"
                    matcher = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(NETWORK,tcp))"
                    for mode in ("add", "keep", "strip"):
                        with self.subTest(matcher=matcher, mode=mode):
                            out, skipped = self.outputs("payload:\n  - " + json.dumps(matcher, ensure_ascii=False), mode)
                            self.assertEqual(self.yaml_body(out), [matcher])
                            allowed = scalar == "ı" or scalar == "İ" and not kind.endswith("-WILDCARD")
                            leaf = f"PROCESS-NAME,{value}"
                            expected = leaf if not operator else f"NOT,(({leaf}))" if operator == "NOT" else f"{operator},(({leaf}),(PROTOCOL,TCP))"
                            for name in ("fin.txt", "fin-surge.txt"):
                                self.assertEqual(out[name], "# group rules: 1\n" + expected + "\n" if allowed else "# group rules: 0\n")
                                self.assertEqual(skipped.get(f"{name}:{operator or kind}", 0), int(not allowed))


class DomainProvenanceFormatTests(unittest.TestCase):
    def outputs(self, source, **kwargs):
        from rules import normalize, parse

        parsed, messages = parse(source, purpose="block")
        self.assertEqual(messages, [])
        return render_configured("group", normalize(parsed), purpose="block",
                                 no_resolve=kwargs.pop("no_resolve", "keep"), **kwargs)

    def assert_counts(self, out):
        from formats import FILES

        self.assertEqual(set(out), set(FILES))
        for name, text in out.items():
            lines = text.splitlines()
            header = 7 if name == "fin-adb.txt" else 2 if name == "fin.yaml" else 1
            count_line = lines[6] if name == "fin-adb.txt" else lines[0]
            self.assertEqual(count_line, f"! Total count: {len(lines[header:])}" if name == "fin-adb.txt"
                             else f"# group rules: {len(lines[header:])}", name)

    def test_native_brackets_stay_literal_and_surge_class_matches_only_digits(self):
        value = "api-[0-9].example.com"
        native, skipped = self.outputs("payload:\n  - DOMAIN-WILDCARD," + value)
        self.assertEqual([generated_payload(line[4:]) for line in native["fin.yaml"].splitlines()[2:]],
                         ["DOMAIN-WILDCARD," + value])
        self.assertEqual(skipped, {f"{name}:DOMAIN-WILDCARD": 1 for name in
                                  ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")})
        self.assert_counts(native)
        surge, skipped = self.outputs("DOMAIN-WILDCARD," + value + ",REJECT")
        matcher = generated_payload(surge["fin.yaml"].splitlines()[2][4:])
        self.assertTrue(matcher.startswith("DOMAIN-REGEX,"))
        expression = re.compile(matcher.split(",", 1)[1], re.I)
        for host in ("api-7.example.com", "API-7.EXAMPLE.COM", "api-7.example.com."):
            self.assertIsNotNone(expression.fullmatch(host), host)
        for host in ("api-a.example.com", value, "api-7.example.com.evil", "api-7.exampleXcom"):
            self.assertIsNone(expression.fullmatch(host), host)
        self.assertEqual(skipped, {"fin-qx.txt:DOMAIN-WILDCARD": 1,
                                   "fin-surge-ds.txt:DOMAIN-WILDCARD": 1})
        self.assert_counts(surge)

    def test_surge_keyword_and_wildcard_preserve_case_with_native_target_skips(self):
        for kind, value, positive, negative in (
            ("DOMAIN-KEYWORD", "ads", "CDN.ADS.EXAMPLE.COM", "CDN.EXAMPLE.COM"),
            ("DOMAIN-WILDCARD", "api-*.example.com", "API-7.EXAMPLE.COM", "OTHER-7.EXAMPLE.COM"),
        ):
            for mode in ("keep", "add", "strip"):
                with self.subTest(kind=kind, mode=mode):
                    out, skipped = self.outputs(f"{kind},{value},REJECT", no_resolve=mode)
                    converted = generated_payload(out["fin.yaml"].splitlines()[2][4:])
                    self.assertTrue(converted.startswith("DOMAIN-REGEX,"))
                    regex = re.compile(converted.split(",", 1)[1], re.I)
                    self.assertIsNotNone(regex.search(positive))
                    self.assertIsNotNone(regex.search(positive.lower()))
                    self.assertIsNone(regex.search(negative))
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertIn(f"{kind},{value}\n", out[name])
                    self.assertIn(f"HOST-{kind.removeprefix('DOMAIN-')},{value},LIST\n", out["fin-qx.txt"])
                    self.assertEqual(skipped, {f"fin-surge-ds.txt:{kind}": 1})
                    self.assert_counts(out)
                    native, native_skipped = self.outputs(f"payload:\n  - {kind},{value}", no_resolve=mode)
                    self.assertEqual([generated_payload(line[4:]) for line in native["fin.yaml"].splitlines()[2:]],
                                     [f"{kind},{value}"])
                    self.assertEqual(native_skipped, {f"{name}:{kind}": 1 for name in
                                                      ("fin.txt", "fin-surge.txt", "fin-surge-ds.txt")})
                    self.assert_counts(native)

    def test_dns_native_literal_class_skips_block_allow_and_whitelist(self):
        from rules import parse, parse_whitelist

        source = "payload:\n  - DOMAIN-WILDCARD,api-[0-9].example.com"
        native, _ = parse(source, purpose="block")
        for allowed in (False, True):
            with self.subTest(allowed=allowed):
                from dataclasses import replace
                out, skipped = render_configured("group", [replace(native[0], allow=allowed)],
                                                 purpose="block", no_resolve="keep")
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
                self.assertEqual(skipped["fin-adb.txt:DOMAIN-WILDCARD"], 1)
                self.assert_counts(out)
        out, skipped = self.outputs("DOMAIN,keep.example.org,REJECT", whitelist=parse_whitelist(source))
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 1", "0.0.0.0 keep.example.org"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-WILDCARD"], 1)
        for source in ("DOMAIN-WILDCARD,api-[0-9].example.com,REJECT",
                       "payload:\n  - DOMAIN-WILDCARD,api-*.example.com",
                       "payload:\n  - DOMAIN-KEYWORD,ads"):
            out, skipped = self.outputs(source)
            expression = re.compile(out["fin-adb.txt"].splitlines()[7][1:-1])
            self.assertIsNotNone(expression.search("API-7.EXAMPLE.COM".lower()) if "ads" not in source
                                 else expression.search("CDN.ADS.EXAMPLE.COM".lower()))
            self.assertIsNone(expression.search("outside.example.org"))
            self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

    def test_logical_domain_provenance_skips_whole_target_with_flags_intact(self):
        for operator in ("AND", "OR", "NOT"):
            for leaf in ("DOMAIN-KEYWORD,ads", "DOMAIN-WILDCARD,api-*.example.com",
                         "DOMAIN-WILDCARD,api-[0-9].example.com"):
                expression = (f"(({leaf}))" if operator == "NOT" else
                              f"(({leaf}),(IP-CIDR,192.0.2.0/24,no-resolve),(SRC-IP-CIDR,198.51.100.0/24))")
                for mode in ("keep", "add", "strip"):
                    with self.subTest(operator=operator, leaf=leaf, mode=mode):
                        native, native_skipped = self.outputs("payload:\n  - " + json.dumps(operator + "," + expression),
                                                               no_resolve=mode)
                        expected = expression.replace(",no-resolve", "") if mode == "strip" else expression
                        self.assertEqual([generated_payload(line[4:]) for line in native["fin.yaml"].splitlines()[2:]],
                                         [operator + "," + expected])
                        self.assertEqual(native_skipped, {f"{name}:{operator}": 1 for name in
                                                          ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")})
                        self.assert_counts(native)
                        surge, skipped = self.outputs(operator + "," + expression + ",REJECT", no_resolve=mode)
                        converted = generated_payload(surge["fin.yaml"].splitlines()[2][4:])
                        self.assertIn("(DOMAIN-REGEX,", converted)
                        self.assertNotIn("(SRC-IP-CIDR,198.51.100.0/24,no-resolve)", converted)
                        self.assertEqual(",no-resolve" in converted, mode != "strip" and operator != "NOT")
                        self.assertNotIn(f"fin.yaml:{operator}", skipped)
                        self.assert_counts(surge)

    def test_regex_whitelist_uses_existing_dns_portability_and_skip_counts(self):
        whitelist = [Rule("DOMAIN-REGEX", "ad"),
                     Rule("DOMAIN-REGEX", r"^api\-.*\.example\.com\.?$"),
                     Rule("DOMAIN-REGEX", r"^api\-[0-9]\.example\.com\.?$"),
                     Rule("DOMAIN-REGEX", r"^(?=ads)ads\.example\.com$"),
                     Rule("DOMAIN-REGEX", r"^a{1001}$")]
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode):
                out, skipped = render_configured("group", [Rule("DOMAIN", "keep.example.org")],
                                                 purpose="block", no_resolve=mode, whitelist=whitelist)
                self.assertEqual(set(out["fin-adb.txt"].splitlines()[7:]),
                                 {"0.0.0.0 keep.example.org", "@@/ad/", r"@@/^api\-.*\.example\.com\.?$/",
                                  r"@@/^api\-[0-9]\.example\.com\.?$/"})
                self.assertEqual(skipped, {"fin-adb.txt:DOMAIN-REGEX": 2})
                self.assert_counts(out)
                for name in ("fin.txt", "fin-surge.txt", "fin.yaml", "fin-qx.txt", "fin-surge-ds.txt"):
                    if name == "fin.yaml":
                        self.assertEqual([generated_payload(line[4:]) for line in out[name].splitlines()[2:]],
                                         [expected_domain("DOMAIN", "keep.example.org")])
                    else:
                        self.assertNotIn("DOMAIN-REGEX", out[name], name)
        out, skipped = render_configured("group", [], purpose="proxy", no_resolve="keep",
                                         whitelist=whitelist)
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
        self.assertEqual(skipped, {})

    def test_en1_remote_rule_omits_only_interface_and_counts_it(self):
        out, skipped = self.outputs("HOST-SUFFIX,example.com,REJECT,via-interface=en1")
        self.assertEqual(out["fin-qx.txt"], "# group rules: 1\nHOST-SUFFIX,example.com,LIST\n")
        self.assertEqual(skipped, {"fin-qx.txt:DOMAIN-SUFFIX:interface-option": 1})
        self.assertNotIn("via-interface", "".join(generated_texts(out).values()))
        self.assert_counts(out)


class SurgeEscapedFieldFormatTests(unittest.TestCase):
    def test_shared_fields_encode_literal_quotes_and_backslashes_exactly(self):
        from rules import parse

        cases = (
            ("Game\\", '"Game\\\\"'),
            ("'Game\\\\", '"\'Game\\\\\\\\"'),
            ('"Game\'Inc"', '"\\"Game\'Inc\\""'),
            ("'Game\"Inc'", '"\'Game\\"Inc\'"'),
            ('"Game\\', '"\\"Game\\\\"'),
            ("'Game\\", '"\'Game\\\\"'),
            ("Game\\\\\\", '"Game\\\\\\\\\\\\"'),
        )
        for kind in ("PROCESS-NAME", "DEVICE-NAME", "USER-AGENT", "URL-REGEX"):
            for value, field in cases:
                if kind == "URL-REGEX" and (len(value) - len(value.rstrip("\\"))) % 2:
                    continue
                with self.subTest(kind=kind, value=value):
                    source = Rule(kind, value)
                    out, skipped = render_configured("group", [source], purpose="proxy", no_resolve="keep")
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], f"# group rules: 1\n{kind},{field}\n")
                        self.assertEqual(parse(out[name], purpose="proxy"), ([source], []))
                        self.assertNotIn(f"{name}:{kind}", skipped)

    def test_native_and_mixed_logic_encode_fields_without_losing_ip_options(self):
        from rules import parse

        values = ("Game\\", "Game\\\\", "Game\\\\\\", "'Game\\\\", '"Game\'Inc"', "'Game\"Inc'", '"Game\\', "'Game\\")
        for leaf in ("PROCESS-NAME", "PROCESS-PATH"):
            for value in values:
                payload = "/Applications/" + value if leaf == "PROCESS-PATH" else value
                field = '"' + payload.replace("\\", "\\\\").replace('"', '\\"') + '"'
                for operator in ("AND", "OR", "NOT"):
                    expression = (f"(({leaf},{payload}))" if operator == "NOT" else
                                  f"(({leaf},{payload}),(IP-CIDR,192.0.2.0/24,no-resolve),"
                                  "(SRC-IP-CIDR,198.51.100.0/24))")
                    native, messages = parse("payload:\n  - " + json.dumps(f"{operator},{expression}"), purpose="proxy")
                    self.assertEqual(messages, [])
                    mixed = f"{operator}," + expression.replace(f"{leaf},{payload}", f"{leaf},{field}") + ",PROXY"
                    for source in (native, parse(mixed, purpose="proxy")[0]):
                        for mode in ("keep", "add", "strip"):
                            with self.subTest(leaf=leaf, value=value, operator=operator, mode=mode, native=source == native):
                                self.assertEqual(len(source), 1)
                                out, skipped = render_configured("group", source, purpose="proxy", no_resolve=mode)
                                expected = expression.replace(",no-resolve", "") if mode == "strip" else expression
                                if leaf == "PROCESS-NAME" and not source[0].literal_process:
                                    expected = expected.replace(f"{leaf},{field}", expected_process(payload)).replace(
                                        f"{leaf},{payload}", expected_process(payload))
                                yaml = [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]]
                                self.assertEqual(yaml, [f"{operator},{expected}"])
                                for name in ("fin.txt", "fin-surge.txt"):
                                    if source[0].literal_process or leaf == "PROCESS-PATH":
                                        self.assertEqual(out[name], "# group rules: 0\n")
                                        self.assertEqual(skipped[f"{name}:{operator}"], 1)
                                        continue
                                    self.assertIn(f"(PROCESS-NAME,", out[name])
                                    self.assertNotIn(f"{name}:{operator}", skipped)
                                    reparsed, warnings = parse(out[name], purpose="proxy")
                                    self.assertEqual(warnings, [])
                                    rerendered, _ = render_configured("next", reparsed, purpose="proxy", no_resolve=mode)
                                    self.assertEqual([generated_payload(line[4:]) for line in rerendered["fin.yaml"].splitlines()[2:]],
                                                     [f"{operator},{expected}"])


class LiteralQuoteFieldFormatTests(unittest.TestCase):
    def test_literal_quote_fields_preserve_matchers_in_surge_outputs(self):
        from rules import parse

        cases = (
            ('"Game"', '\'"Game"\''),
            ("'Game'", '"\'Game\'"'),
            ('"Game', '\'"Game\''),
            ("'Game", '"\'Game"'),
            (r'"Game\wInc"', '\'"Game\\wInc"\''),
            (r"'Game\wInc'", '"\'Game\\\\wInc\'"'),
            (r'"Game\"Inc"', r"""'"Game\"Inc"'"""),
            (r"'Game\'Inc'", r'''"'Game\\'Inc'"'''),
            ('Game"Inc', 'Game"Inc'),
            ("Game'Inc", "Game'Inc"),
            ('Game\'"Inc', 'Game\'"Inc'),
            ('"Game,Inc"', '\'"Game,Inc"\''),
        )
        for kind in ("PROCESS-NAME", "DEVICE-NAME", "USER-AGENT", "URL-REGEX"):
            for value, field in cases:
                with self.subTest(kind=kind, value=value):
                    source = Rule(kind, value)
                    out, skipped = render_configured("group", [source], purpose="proxy", no_resolve="keep")
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], f"# group rules: 1\n{kind},{field}\n")
                        self.assertEqual(parse(out[name], purpose="proxy"), ([source], []))
                        self.assertNotIn(f"{name}:{kind}", skipped)
                    if kind == "PROCESS-NAME":
                        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                         [expected_process(value)])

    def test_mixed_logic_quote_roles_and_regexp2_matchers_remain_exact(self):
        from rules import parse

        cases = (
            ('AND,((PROCESS-NAME,"Game"),(DOMAIN,x.example.com)),PROXY',
             'AND,((PROCESS-NAME,Game),(DOMAIN,x.example.com))',
             'AND,((PROCESS-NAME,Game),(DOMAIN,x.example.com))'),
            ('AND,((PROCESS-NAME,\'"Game"\'),(DOMAIN,x.example.com)),PROXY',
             'AND,((PROCESS-NAME,\'"Game"\'),(DOMAIN,x.example.com))',
             'AND,((PROCESS-NAME,"Game"),(DOMAIN,x.example.com))'),
            ('OR,((PROCESS-NAME,"\'Game\'"),(DOMAIN,x.example.com)),PROXY',
             'OR,((PROCESS-NAME,"\'Game\'"),(DOMAIN,x.example.com))',
             "OR,((PROCESS-NAME,'Game'),(DOMAIN,x.example.com))"),
            ('NOT,((URL-REGEX,\'"Game\\w,Inc"\')),PROXY',
             'NOT,((URL-REGEX,\'"Game\\w,Inc"\'))', None),
        )
        for source, surge, yaml in cases:
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(messages, [])
                self.assertEqual(len(parsed), 1)
                self.assertFalse(parsed[0].native_fields)
                out, skipped = render_configured("group", parsed, purpose="proxy", no_resolve="keep")
                for name in ("fin.txt", "fin-surge.txt"):
                    self.assertEqual(out[name], f"# group rules: 1\n{surge}\n")
                    reparsed, warnings = parse(out[name], purpose="proxy")
                    self.assertEqual(warnings, [])
                    rendered, _ = render_configured("next", reparsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual(rendered[name], f"# next rules: 1\n{surge}\n")
                    self.assertNotIn(f"{name}:{parsed[0].kind}", skipped)
                if yaml is not None:
                    value = "Game" if source == cases[0][0] else '"Game"' if source == cases[1][0] else "'Game'"
                    yaml = f"{parsed[0].kind},(({expected_process(value)}),({expected_domain('DOMAIN', 'x.example.com')}))"
                self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                 [yaml] if yaml is not None else [])
                self.assertEqual(skipped.get(f"fin.yaml:{parsed[0].kind}", 0), int(yaml is None))
        for kind in ("DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"):
            for native in (False, True):
                value = '"Game\\w,Inc"'
                field = value if native else '\'' + value + '\''
                expression = f"(({kind},{field}),(DOMAIN,x.example.com))"
                source = ("payload:\n  - " + json.dumps("AND," + expression)
                          if native else "AND," + expression + ",PROXY")
                with self.subTest(kind=kind, native=native):
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual(messages, [])
                    out, skipped = render_configured("group", parsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                     [f'AND,(({kind},"Game\\w,Inc"),(DOMAIN,x.example.com))' if native else
                                      f'AND,(({kind},"Game\\w,Inc"),({expected_domain("DOMAIN", "x.example.com")}))'])
                    self.assertNotIn("fin.yaml:AND", skipped)

    def test_unrepresentable_quote_fields_skip_whole_surge_rule_and_keep_native_rule(self):
        from rules import parse

        # 字面 * 仍无法保留到 Surge；引号和反斜杠自身的可表达值由上面的回归测试覆盖。
        values = ('"Game\'Inc*"', "'Game\"Inc*'", '"Game*\\', "'Game*\\")
        for value in values:
            cases = [("PROCESS-NAME", value)] + [
                (kind, f"((PROCESS-NAME,{value}),(DOMAIN,x.example.com))")
                for kind in ("AND", "OR")
            ] + [("NOT", f"((PROCESS-NAME,{value}))"),
                 ("AND", f"((OR,((PROCESS-NAME,{value}),(DOMAIN,x.example.com))),"
                         "(DOMAIN,other.example.com))")]
            for kind, matcher in cases:
                with self.subTest(value=value, kind=kind, matcher=matcher):
                    document = "payload:\n  - " + json.dumps(f"{kind},{matcher}")
                    parsed, messages = parse(document, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(parsed, [Rule(kind, matcher, literal_process=True,
                                                  native_fields=kind != "PROCESS-NAME",
                                                  domain_source="mihomo" if "(DOMAIN," in matcher else "surge")])
                    out, skipped = render_configured("group", parsed + [Rule("DOMAIN-KEYWORD", "keep")],
                                                     purpose="proxy", no_resolve="keep")
                    for name in ("fin.txt", "fin-surge.txt"):
                        self.assertEqual(out[name], "# group rules: 1\nDOMAIN-KEYWORD,keep\n")
                        self.assertEqual(skipped[f"{name}:{kind}"], 1)
                    self.assertEqual({generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
                                     {f"{kind},{matcher}", "DOMAIN-REGEX,keep"})
                    self.assertNotIn(f"fin.yaml:{kind}", skipped)
        for value in ('"Game\\\\', '"Game\\\\\\\\'):
            with self.subTest(even_backslashes=value):
                out, skipped = render_configured("group", [Rule("PROCESS-NAME", value)],
                                                 purpose="proxy", no_resolve="keep")
                for name in ("fin.txt", "fin-surge.txt"):
                    self.assertEqual(parse(out[name], purpose="proxy"), ([Rule("PROCESS-NAME", value)], []))
                    self.assertNotIn(f"{name}:PROCESS-NAME", skipped)


class NativeFieldFix8FormatTests(unittest.TestCase):
    def test_native_logic_inner_quotes_and_comma_have_exact_decoded_payload(self):
        from rules import normalize, parse

        expression = '((DOMAIN-REGEX,"*ads"),(PROCESS-NAME-REGEX,^Game,Inc$))'
        parsed, messages = parse("payload:\n  - 'AND," + expression + "'", purpose="proxy")
        self.assertEqual(messages, [])
        for mode in ("keep", "add", "strip"):
            with self.subTest(mode=mode):
                out, skipped = render_configured("group", normalize(parsed), purpose="proxy", no_resolve=mode)
                self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                 ["AND," + expression])
                self.assertNotIn("fin.yaml:AND", skipped)
                self.assertEqual(out["fin-qx.txt"], "# group rules: 0\n")
                self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_same_logic_text_with_different_source_quotes_is_not_merged(self):
        from rules import normalize, parse

        expression = '((DOMAIN-REGEX,"^ads$"),(DOMAIN,x.example.com))'
        native = parse("payload:\n  - 'AND," + expression + "'", purpose="proxy")[0]
        mixed = parse("AND," + expression + ",PROXY", purpose="proxy")[0]
        out, _ = render_configured("group", normalize(native + mixed), purpose="proxy", no_resolve="strip")
        self.assertEqual({generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
                         {"AND," + expression, "AND,((DOMAIN-REGEX,^ads$),(" + expected_domain("DOMAIN", "x.example.com") + "))"})


class SourceFieldContinuationFormatTests(unittest.TestCase):
    def test_source_regex_markers_round_trip_in_surge_outputs(self):
        from rules import parse

        for value in ("^foo #bar$", "^foo ;bar$", "^foo //bar$", "(?x)^foo # ignored,PROXY"):
            with self.subTest(value=value):
                expected = Rule("URL-REGEX", value)
                out, skipped = render_configured("group", [expected], purpose="proxy", no_resolve="keep")
                for name in ("fin.txt", "fin-surge.txt"):
                    self.assertEqual(parse(out[name], purpose="proxy"), ([expected], []))
                    self.assertNotIn(f"{name}:URL-REGEX", skipped)

    def test_rule_rebuilds_keep_native_fields(self):
        from rules import normalize, parse_whitelist

        source = Rule("IP-CIDR", "192.0.2.0/25", ("force-cellular", "no-resolve"), native_fields=True)
        for mode in ("add", "strip", "keep"):
            with self.subTest(mode=mode), patch("formats.Rule", wraps=Rule) as clone:
                render_configured("group", [source], purpose="proxy", no_resolve=mode)
                self.assertTrue(clone.called)
                for call in clone.call_args_list:
                    self.assertTrue(call.args[5])
        collapsed = normalize([Rule("IP-CIDR", "192.0.2.0/25", native_fields=True),
                               Rule("IP-CIDR", "192.0.2.128/25", native_fields=True)])
        self.assertEqual(collapsed, [Rule("IP-CIDR", "192.0.2.0/24", native_fields=True)])
        with patch("rules.parse", return_value=(collapsed, [])):
            self.assertEqual(parse_whitelist("ignored"), [Rule("IP-CIDR", "192.0.2.0/24", native_fields=True)])


class FormatTests(unittest.TestCase):
    def test_wildcard_survives_compatible_targets(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-*.example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.txt"])
        self.assertIn("HOST-WILDCARD,api-*.example.com,LIST", out["fin-qx.txt"])
        self.assertIn(r"DOMAIN-REGEX,^api\-.*\.example\.com\.?$",
                      [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])
        self.assertNotIn("api-*.example.com", out["fin-surge-ds.txt"])

    def test_wildcard_does_not_remove_exact_domain_from_surge_domain_set(self):
        out, _ = render("a3", [
            Rule("DOMAIN-WILDCARD", "api-*.example.org"), Rule("DOMAIN", "api-v2.example.org"),
        ])
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 1\napi-v2.example.org\n")
        self.assertIn("HOST-WILDCARD,api-*.example.org,LIST\n", out["fin-qx.txt"])
        self.assertIn("HOST,api-v2.example.org,LIST\n", out["fin-qx.txt"])
        self.assertIn(r"DOMAIN-REGEX,^api\-.*\.example\.org\.?$",
                      [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])
        self.assertIn(expected_ordinary_text('  - "DOMAIN,api-v2.example.org"\n'), generated_text(out["fin.yaml"]))

    def test_surge_character_class_wildcard_is_converted_for_mihomo_but_not_qx(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-[0-9].example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin.txt"])
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [r"DOMAIN-REGEX,^api\-[0-9]\.example\.com\.?$"])
        self.assertEqual(skipped["fin-qx.txt:DOMAIN-WILDCARD"], 1)
        self.assertNotIn("fin.yaml:DOMAIN-WILDCARD", skipped)
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 1", r"/^api\-[0-9]\.example\.com$/"])

    def test_character_class_wildcard_preserves_digit_only_scope_for_mihomo_and_dns(self):
        source = Rule("DOMAIN-WILDCARD", "api-[0-9].example.com")
        for allow in (False, True):
            with self.subTest(allow=allow):
                out, skipped = render("a3", [Rule(source.kind, source.value, allow=allow)])
                if not allow:
                    self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin.txt"])
                    self.assertIn("DOMAIN-WILDCARD,api-[0-9].example.com\n", out["fin-surge.txt"])
                    self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                     [r"DOMAIN-REGEX,^api\-[0-9]\.example\.com\.?$"])
                    self.assertNotIn("fin.yaml:DOMAIN-WILDCARD", skipped)
                expected_dns = ("@@" if allow else "") + r"/^api\-[0-9]\.example\.com$/"
                self.assertIn(expected_dns, out["fin-adb.txt"].splitlines()[7:])
                dns_rule = out["fin-adb.txt"].splitlines()[7]
                expression = re.compile(dns_rule.removeprefix("@@")[1:-1])
                self.assertIsNotNone(expression.fullmatch("api-7.example.com"))
                for domain in ("api-a.example.com", "api-7.exampleXcom", "api-7.example.com.evil"):
                    self.assertIsNone(expression.fullmatch(domain))
                self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

    def test_portable_domain_regex_emits_dns_block_and_allow_only(self):
        value = r"^api[0-9]\.example\.com$"
        out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                     Rule("DOMAIN-REGEX", value, allow=True)])
        self.assertEqual(out["fin-adb.txt"].splitlines()[7:],
                         [f"@@/{value}/", f"/{value}/"])
        self.assertEqual(generated_payload(out["fin.yaml"].splitlines()[2][4:]),
                         f"DOMAIN-REGEX,{value}")
        self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)
        expression = re.compile(value)
        self.assertIsNotNone(expression.fullmatch("api7.example.com"))
        self.assertIsNone(expression.fullmatch("apia.example.com"))

    def test_go_portable_domain_regex_emits_literal_dns_block_and_allow(self):
        cases = (
            (r"^ads\.example\.com\z", r"/^ads\.example\.com\z/", r"@@/^ads\.example\.com\z/"),
            (r"^api\d\.example\.com$", r"/^api\p{Nd}\.example\.com$/", r"@@/^api\p{Nd}\.example\.com$/"),
            (r"^(?:ads|track)\.example\.com$", r"/^(?:ads|track)\.example\.com$/", r"@@/^(?:ads|track)\.example\.com$/"),
            (r"^(?<name>ads)\.example\.com$", r"/^(?<name>ads)\.example\.com$/", r"@@/^(?<name>ads)\.example\.com$/"),
        )
        for value, block, allow in cases:
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 2", allow, block])
                self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)

    def test_adguard_portable_capture_flags_and_property_emit_block_and_allow(self):
        cases = (
            (r"^(?<n>ad)(?<n>s)\.example\.com$",
             r"/^(?<n>ad)(?<n>s)\.example\.com$/",
             r"@@/^(?<n>ad)(?<n>s)\.example\.com$/"),
            (r"^(?i:ads)\.example\.com$",
             r"/^(?i:ads)\.example\.com$/",
             r"@@/^(?i:ads)\.example\.com$/"),
            (r"^\p{L}+\.example\.com$",
             r"/^\p{L}+\.example\.com$/",
             r"@@/^\p{L}+\.example\.com$/"),
        )
        for value, block, allow in cases:
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 2", allow, block])
                self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)

    def test_regexp2_zero_padded_repetition_keeps_its_count_in_dns(self):
        cases = (
            (r"^a{01}\.example\.com$", r"/^a{1}\.example\.com$/",
             r"@@/^a{1}\.example\.com$/"),
            (r"^a{00,01}\.example\.com$", r"/^a{0,1}\.example\.com$/",
             r"@@/^a{0,1}\.example\.com$/"),
            (r"^a{0001,}\.example\.com$", r"/^a{1,}\.example\.com$/",
             r"@@/^a{1,}\.example\.com$/"),
        )
        for value, block, allow in cases:
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 2", allow, block])
                self.assertIn(f"DOMAIN-REGEX,{value}",
                              [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])
                self.assertNotIn("fin-adb.txt:DOMAIN-REGEX", skipped)

    def test_go_invalid_property_range_stays_out_of_dns(self):
        value = r"^[a-\p{L}]+\.example\.com$"
        out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                     Rule("DOMAIN-REGEX", value, allow=True)])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 2)
        self.assertIn(f"DOMAIN-REGEX,{value}",
                      [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])

    def test_go_valid_property_class_followed_by_literal_hyphen_emits_dns(self):
        value = r"^[\p{L}-a]+\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def _assert_domain_regex_dns(self, value, dns_value):
        from rules import parse

        parsed, messages = parse(f"DOMAIN-REGEX,{value},REJECT", purpose="block")
        self.assertEqual(messages, [])
        self.assertEqual(parsed, [Rule("DOMAIN-REGEX", value)])
        out, skipped = render("a3", parsed + [Rule("DOMAIN-REGEX", value, allow=True)])
        expected_dns = (["! Total count: 0"] if dns_value is None else
                        ["! Total count: 2", f"@@/{dns_value}/", f"/{dns_value}/"])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], expected_dns)
        self.assertEqual(generated_text(out["fin.yaml"]), '# a3 rules: 1\npayload:\n  - ' +
                         json.dumps(f"DOMAIN-REGEX,{value}", ensure_ascii=False) + "\n")
        expected_skipped = {"fin.yaml:DOMAIN-REGEX": 1}
        for name in ("fin.txt", "fin-qx.txt", "fin-surge.txt", "fin-surge-ds.txt"):
            self.assertEqual(out[name], "# a3 rules: 0\n")
            expected_skipped[f"{name}:DOMAIN-REGEX"] = 2
        if dns_value is None:
            expected_skipped["fin-adb.txt:DOMAIN-REGEX"] = 2
        self.assertEqual(skipped, expected_skipped)
        for allow in (False, True):
            single, single_skipped = render("a3", [Rule("DOMAIN-REGEX", value, allow=allow)])
            expected_single = (["! Total count: 0"] if dns_value is None else
                               ["! Total count: 1", ("@@" if allow else "") + f"/{dns_value}/"])
            self.assertEqual(single["fin-adb.txt"].splitlines()[6:], expected_single)
            self.assertEqual(single_skipped.get("fin-adb.txt:DOMAIN-REGEX", 0),
                             1 if dns_value is None else 0)

    def test_posix_looking_classes_stay_out_of_dns(self):
        for value in (r"^[[:alpha:]-a]+\.example\.com$", r"^[[:alpha:]]+\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_posix_class_literal_braces_are_preserved_in_yaml_and_skipped_in_dns(self):
        self._assert_domain_regex_dns(r"^[[:alpha:]{01}]+\.example\.com$", None)

    def test_regexp2_class_subtraction_stays_out_of_dns(self):
        self._assert_domain_regex_dns(r"^[a-z-[aeiou]]+\.example\.com$", None)

    def test_unicode_decimal_digit_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^\d+\.example\.com$", r"^\p{Nd}+\.example\.com$")

    def test_unicode_decimal_digit_class_combination_stays_out_of_dns(self):
        self._assert_domain_regex_dns(r"^[a\d]+\.example\.com$", None)

    def test_literal_backslash_digit_is_not_translated_for_dns(self):
        value = r"^\\d\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_character_class_literal_braces_are_not_rewritten_as_quantifiers(self):
        value = r"^[a{01}]+\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_absolute_anchors_are_preserved_for_dns(self):
        value = r"\Aads\.example\.com\z"
        self._assert_domain_regex_dns(value, value)

    def test_braced_hex_atom_is_preserved_for_dns(self):
        value = r"^\x{61}ds\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unproved_nonascii_hex_casefold_stays_out_of_dns(self):
        self._assert_domain_regex_dns(r"^\x{130}\.example\.com$", None)

    def test_nested_counted_repetition_respects_go_combined_limit(self):
        self._assert_domain_regex_dns(r"^(?:\w{500}){3}\.example\.com$", None)
        self._assert_domain_regex_dns(r"^(?:\w{500}){2}\.example\.com$",
                                      r"^(?:[\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]{500}){2}\.example\.com$")
        value = r"^(?:a{500}){0,1}\.example\.com$"
        self._assert_domain_regex_dns(value, value)
        value = r"^(?:(?:a{500}){0}){3}\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_zero_minimum_unbounded_repeat_preserves_inner_go_budget(self):
        for atom in (r"\d{500}", "a{500}", "a{0500}"):
            for repeat in ("{0,}", "{00,}"):
                value = rf"^(?:(?:{atom}|b){repeat}){{3}}\.example\.com$"
                with self.subTest(value=value):
                    self._assert_domain_regex_dns(value, None)
        for value in (r"^(?:(?:a{500}){0,}|b){3}\.example\.com$",
                      r"^((a{500}|b){00,}){03}\.example\.com$",
                      r"^(?:(?:(?:a{250}|b){0,}){2}){3}\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_zero_minimum_repeat_keeps_valid_go_boundaries(self):
        for repeat, normalized in (("{0,}", "{0,}"), ("{00,}", "{0,}"),
                                   ("*", "*"), ("+", "+"), ("?", "?"),
                                   ("{1,}", "{1,}"), ("{0001,}", "{1,}"),
                                   ("{0,1}", "{0,1}"), ("{00,01}", "{0,1}")):
            value = rf"^(?:(?:a{{500}}|b){repeat}){{2}}\.example\.com$"
            dns_value = rf"^(?:(?:a{{500}}|b){normalized}){{2}}\.example\.com$"
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, dns_value)
        for repeat, normalized in (("{0}", "{0}"), ("{0,0}", "{0,0}"),
                                   ("{00}", "{0}"), ("{00,00}", "{0,0}")):
            value = rf"^(?:(?:a{{500}}){repeat}|b){{3}}\.example\.com$"
            dns_value = rf"^(?:(?:a{{500}}){normalized}|b){{3}}\.example\.com$"
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, dns_value)
        value = r"^(?:(?:\d{0500}|b){00,}){02}\.example\.com$"
        self._assert_domain_regex_dns(value, r"^(?:(?:\p{Nd}{500}|b){0,}){2}\.example\.com$")
        value = r"^(?:(?:a{250}|b){0,2}){2}\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unicode_nd_property_is_preserved_for_dns(self):
        value = r"^\p{Nd}\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unicode_nondigit_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^ad\Dtrack\.example\.com$",
                                      r"^ad\P{Nd}track\.example\.com$")

    def test_unicode_word_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^\w+\.example\.com$",
                                      r"^[\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]+\.example\.com$")

    def test_unicode_nonword_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^ad\Wtrack\.example\.com$",
                                      r"^ad[^\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]track\.example\.com$")

    def test_unicode_space_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^ads\s?\.example\.com$",
                                      r"^ads[\x09-\x0D\x{85}\p{Z}]?\.example\.com$")

    def test_unicode_nonspace_atom_is_translated_for_dns(self):
        self._assert_domain_regex_dns(r"^\S+\.example\.com$",
                                      r"^[^\x09-\x0D\x{85}\p{Z}]+\.example\.com$")

    def test_unproved_unicode_class_combinations_stay_out_of_dns(self):
        for atom in (r"\d", r"\D", r"\w", r"\W", r"\s", r"\S", r"\p{Nd}"):
            for value in (rf"^[a{atom}]+\.example\.com$", rf"^[]{atom}]+\.example\.com$",
                          rf"^[^]{atom}]+\.example\.com$"):
                with self.subTest(value=value):
                    self._assert_domain_regex_dns(value, None)

    def test_unicode_boundary_and_ignorecase_lowercase_property_stay_out_of_dns(self):
        for value in (r"^\bads\.example\.com$", r"^\p{Ll}\.example\.com$",
                      r"^(?i:\p{Ll})\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_literal_backslashes_before_unicode_atoms_are_preserved(self):
        for atom in ("d", "D", "w", "W", "s", "S", "b", "p{Nd}", "x{61}", "A", "z"):
            value = rf"^\\{atom}\.example\.com$"
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, value)
        self._assert_domain_regex_dns(r"^\\\d\.example\.com$", r"^\\\p{Nd}\.example\.com$")
        value = r"^[a\\d]+\.example\.com$"
        self._assert_domain_regex_dns(value, value)

    def test_unsupported_regex_constructs_keep_yaml_and_dns_skip_counts(self):
        for value in (r"^ads/track\.example\.com$", r"^ads\/track\.example\.com$",
                      r"^ads{01001}\.example\.com$", r"^(ads)\1\.example\.com$",
                      r"^(?<name>ads)\k<name>\.example\.com$", r"^ads(?=track)\.example\.com$"):
            with self.subTest(value=value):
                self._assert_domain_regex_dns(value, None)

    def test_go_invalid_repetition_is_not_emitted_or_counted_in_dns(self):
        value = r"^ads{0,1001}\.example\.com$"
        out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                     Rule("DOMAIN-REGEX", value, allow=True)])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 2)
        self.assertIn(f"DOMAIN-REGEX,{value}",
                      [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])

    def test_regexp2_only_domain_regex_stays_out_of_dns(self):
        for value in (r"^(ads)\1\.example\.com$", r"^ads(?=track)\.example\.com$",
                      r"^(?<name>ads)\k<name>\.example\.com$"):
            with self.subTest(value=value):
                out, skipped = render("a3", [Rule("DOMAIN-REGEX", value),
                                             Rule("DOMAIN-REGEX", value, allow=True)])
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
                self.assertIn(f"DOMAIN-REGEX,{value}",
                              [generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]])
                self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], 2)

    def test_client_accepted_regexp2_rules_keep_go_portable_property_in_dns(self):
        from rules import parse

        values = [r"^\p{L}+\.example\.com$", r"^\x{61}ds\.example\.com$",
                  r"^\Gads\.example\.com$", r"^a+(?<=a+)ds\.example\.com$"]
        source = "\n".join(f"DOMAIN-REGEX,{value},REJECT" for value in values)
        parsed, messages = parse(source + "\nPROCESS-NAME-REGEX,^[(?P]$,REJECT", purpose="block")
        self.assertEqual(messages, [])
        out, skipped = render("a3", parsed)
        self.assertEqual({generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
                         {f"DOMAIN-REGEX,{value}" for value in values} |
                         {"PROCESS-NAME-REGEX,^[(?P]$"})
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 2", r"/^\p{L}+\.example\.com$/",
                          r"/^\x{61}ds\.example\.com$/"])
        self.assertEqual(skipped["fin-adb.txt:DOMAIN-REGEX"], len(values) - 2)
        self.assertEqual(skipped["fin-adb.txt:PROCESS-NAME-REGEX"], 1)

    def test_six_files_are_ordered_and_count_actual_lines(self):
        high = Rule("DOMAIN-WILDCARD", "z-*.example.com")
        low = Rule("DOMAIN-WILDCARD", "a-*.example.com")
        with patch("formats.datetime") as clock:
            clock.now.side_effect = lambda tz: datetime(2026, 9, 29, tzinfo=timezone.utc).astimezone(tz)
            out, _ = render("a3", iter([high, low]))
            reordered, _ = render("a3", iter([low, high]))
        self.assertEqual(set(out), {
            "fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt",
            "fin-surge.txt", "fin-surge-ds.txt",
        })
        self.assertEqual(out, reordered)
        self.assertEqual(out["fin.txt"],
                         "# a3 rules: 2\nDOMAIN-WILDCARD,a-*.example.com\nDOMAIN-WILDCARD,z-*.example.com\n")
        self.assertTrue(all(body.endswith("\n") and "\r" not in body for body in out.values()))

    def test_render_sorts_each_output_type_by_final_line_length_then_text(self):
        out, _ = render("a3", [
            Rule("NETWORK", "udp"), Rule("DOMAIN-SUFFIX", "q.org"),
            Rule("DOMAIN", "long.example.org"), Rule("DOMAIN", "z.org"),
            Rule("DOMAIN-KEYWORD", "ad"), Rule("DOMAIN-SUFFIX", "b.org"),
            Rule("DOMAIN", "a.org"),
        ])
        adb = out.pop("fin-adb.txt")
        self.assertEqual(adb.splitlines()[6:], ["! Total count: 6", "||b.org^", "||q.org^", "/^.*ad.*$/", "0.0.0.0 a.org", "0.0.0.0 z.org", "0.0.0.0 long.example.org"])
        expected = {
            "fin.txt": "# a3 rules: 7\nDOMAIN,a.org\nDOMAIN,z.org\nDOMAIN,long.example.org\nDOMAIN-KEYWORD,ad\nDOMAIN-SUFFIX,b.org\nDOMAIN-SUFFIX,q.org\nPROTOCOL,UDP\n",
            "fin-qx.txt": "# a3 rules: 6\nHOST,a.org,LIST\nHOST,z.org,LIST\nHOST,long.example.org,LIST\nHOST-KEYWORD,ad,LIST\nHOST-SUFFIX,b.org,LIST\nHOST-SUFFIX,q.org,LIST\n",
            "fin.yaml": '# a3 rules: 7\npayload:\n  - "DOMAIN,a.org"\n  - "DOMAIN,z.org"\n  - "DOMAIN,long.example.org"\n  - "DOMAIN-REGEX,ad"\n  - "DOMAIN-SUFFIX,b.org"\n  - "DOMAIN-SUFFIX,q.org"\n  - "NETWORK,udp"\n',
            "fin-surge.txt": "# a3 rules: 2\nDOMAIN-KEYWORD,ad\nPROTOCOL,UDP\n",
            "fin-surge-ds.txt": "# a3 rules: 5\na.org\nz.org\n.b.org\n.q.org\nlong.example.org\n",
        }
        expected["fin.yaml"] = expected_ordinary_text(expected["fin.yaml"])
        self.assertEqual(generated_texts(out), expected)

    def test_ip_types_follow_other_types_and_split_same_type_by_address_family(self):
        out, _ = render("a3", [
            Rule("SRC-IP-CIDR", "2001:db8::/32"), Rule("IP-CIDR", "2001:db8::/32"),
            Rule("IP-ASN", "64500"), Rule("GEOIP", "CN"),
            Rule("SRC-IP-CIDR", "192.0.2.0/24"), Rule("IP-CIDR", "192.0.2.0/24"),
            Rule("NETWORK", "udp"), Rule("DOMAIN", "a.org"),
        ])
        self.assertEqual(out["fin.txt"].splitlines()[1:], [
            "DOMAIN,a.org", "PROTOCOL,UDP", "GEOIP,CN,no-resolve", "IP-ASN,64500,no-resolve",
            "IP-CIDR,192.0.2.0/24,no-resolve", "SRC-IP,192.0.2.0/24",
            "IP-CIDR6,2001:db8::/32,no-resolve", "SRC-IP,2001:db8::/32",
        ])
        self.assertEqual(out["fin-qx.txt"].splitlines()[1:], [
            "HOST,a.org,LIST", "GEOIP,CN,LIST,no-resolve", "IP-ASN,64500,LIST,no-resolve",
            "IP-CIDR,192.0.2.0/24,LIST,no-resolve", "IP6-CIDR,2001:db8::/32,LIST,no-resolve",
        ])
        self.assertEqual(generated_text(out["fin.yaml"]).splitlines()[2:], [expected_ordinary_text(entry) for entry in ([
            '  - "DOMAIN,a.org"', '  - "NETWORK,udp"', '  - "GEOIP,CN,no-resolve"',
            '  - "IP-ASN,64500,no-resolve"', '  - "IP-CIDR,192.0.2.0/24,no-resolve"',
            '  - "SRC-IP-CIDR,192.0.2.0/24"', '  - "IP-CIDR,2001:db8::/32,no-resolve"',
            '  - "SRC-IP-CIDR,2001:db8::/32"',
        ])])
        self.assertEqual(out["fin-surge.txt"].splitlines()[1:], [
            "PROTOCOL,UDP", "GEOIP,CN,no-resolve", "IP-ASN,64500,no-resolve",
            "IP-CIDR,192.0.2.0/24,no-resolve", "SRC-IP,192.0.2.0/24",
            "IP-CIDR6,2001:db8::/32,no-resolve", "SRC-IP,2001:db8::/32",
        ])

    def test_adblock_exceptions_precede_shorter_blocks_and_duplicates_are_removed(self):
        with patch("formats.datetime") as clock:
            clock.now.side_effect = lambda tz: datetime(2026, 9, 28, 16, 45, tzinfo=timezone.utc).astimezone(tz)
            out, _ = render("a3", [
                Rule("DOMAIN", "a.org"), Rule("DOMAIN", "b.org"),
                Rule("DOMAIN-SUFFIX", "example.org"), Rule("DOMAIN", "b.org", allow=True),
            ], whitelist=[
                Rule("DOMAIN", "z.org"), Rule("DOMAIN", "a.org"),
                Rule("DOMAIN", "a.org"), Rule("DOMAIN-SUFFIX", "example.org"),
            ])
        self.assertEqual(out["fin-adb.txt"],
                         "[Adblock Plus 2.0]\n! Title: a3\n! Homepage: https://github.com/DoingDog/rconvert\n"
                         "! Expires: 1 day\n! License: Inherits upstream licenses\n"
                         "! Version: 202609290045\n! Total count: 7\n"
                         "@@|a.org|\n@@|b.org|\n@@|z.org|\n@@||example.org^\n0.0.0.0 a.org\n0.0.0.0 b.org\n||example.org^\n")

    def test_newlines_in_rule_values_cannot_insert_extra_rules(self):
        out, skipped = render("a3", [Rule("DOMAIN-SUFFIX", "safe.example.com\r\nEVIL,host")])
        self.assertTrue(all("EVIL" not in body and "\r" not in body for body in out.values()))
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)

    def test_exact_domain_does_not_expand_into_adblock_subdomains(self):
        out, skipped = render("a3", [Rule("DOMAIN", "exact.example.com")])
        self.assertIn("DOMAIN,exact.example.com\n", out["fin.txt"])
        self.assertIn("HOST,exact.example.com,LIST\n", out["fin-qx.txt"])
        self.assertIn(expected_ordinary_text('  - "DOMAIN,exact.example.com"\n'), generated_text(out["fin.yaml"]))
        self.assertIn("\nexact.example.com\n", out["fin-surge-ds.txt"])
        self.assertNotIn("exact.example.com", out["fin-surge.txt"])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 1", "0.0.0.0 exact.example.com"])
        self.assertNotIn("fin-adb.txt:DOMAIN", skipped)

    def test_suffix_is_shared_by_domain_set_and_adblock(self):
        out, skipped = render("a3", [Rule("DOMAIN-SUFFIX", "ads.example.com")])
        self.assertIn("DOMAIN-SUFFIX,ads.example.com\n", out["fin.txt"])
        self.assertIn("HOST-SUFFIX,ads.example.com,LIST\n", out["fin-qx.txt"])
        self.assertIn(expected_ordinary_text('  - "DOMAIN-SUFFIX,ads.example.com"\n'), generated_text(out["fin.yaml"]))
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 1\n.ads.example.com\n")
        self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 1", "||ads.example.com^"])
        self.assertNotIn("fin-adb.txt:DOMAIN-SUFFIX", skipped)

    def test_keyword_with_dot_is_literal_in_dns_regex(self):
        out, skipped = render("a3", [Rule("DOMAIN-KEYWORD", "ad.track")])
        self.assertGreater(len(out["fin-adb.txt"].splitlines()), 7)
        line = out["fin-adb.txt"].splitlines()[7]
        self.assertTrue(line.startswith("/^") and line.endswith("$/"))
        expression = re.compile(line[1:-1])
        self.assertIsNotNone(expression.fullmatch("cdn.ad.track.example.org"))
        self.assertIsNone(expression.fullmatch("cdn.adXtrack.example.org"))
        self.assertNotIn("fin-adb.txt:DOMAIN-KEYWORD", skipped)

    def test_safe_wildcard_is_anchored_in_dns_regex(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-*.example.org")])
        self.assertGreater(len(out["fin-adb.txt"].splitlines()), 7)
        line = out["fin-adb.txt"].splitlines()[7]
        self.assertTrue(line.startswith("/^") and line.endswith("$/"))
        expression = re.compile(line[1:-1])
        self.assertIsNotNone(expression.fullmatch("api-v2.example.org"))
        for domain in ("other-api-v2.example.org", "api-v2.example.org.evil", "api-v2.exampleXorg"):
            with self.subTest(domain=domain):
                self.assertIsNone(expression.fullmatch(domain))
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

    def test_source_cidr_keeps_direction_for_ipv4_and_ipv6(self):
        out, skipped = render("a3", [
            Rule("SRC-IP-CIDR", "2001:db8::/32"),
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
        ])
        self.assertIn("SRC-IP,192.0.2.0/24\n", out["fin.txt"])
        self.assertIn("SRC-IP,2001:db8::/32\n", out["fin-surge.txt"])
        self.assertIn('  - "SRC-IP-CIDR,2001:db8::/32"\n', generated_text(out["fin.yaml"]))
        self.assertNotIn("IP-CIDR6,2001:db8::/32", generated_text(out["fin.yaml"]))
        self.assertEqual(skipped["fin-qx.txt:SRC-IP-CIDR"], 2)
        self.assertEqual(skipped["fin-adb.txt:SRC-IP-CIDR"], 2)
        self.assertEqual(skipped["fin-surge-ds.txt:SRC-IP-CIDR"], 2)
        self.assertNotIn("2001:db8", out["fin-qx.txt"])

    def test_source_ip_family_keeps_direction_per_target(self):
        out, skipped = render("a3", [
            Rule("SRC-IP-CIDR", "192.0.2.0/24"),
            Rule("SRC-IP-SUFFIX", "8.8.8.8/24"),
            Rule("SRC-GEOIP", "CN"), Rule("SRC-IP-ASN", "64512"),
        ])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("SRC-IP,192.0.2.0/24\n", out[name])
            self.assertNotIn("IP-CIDR,192.0.2.0/24", out[name])
        self.assertIn('  - "SRC-IP-CIDR,192.0.2.0/24"\n', generated_text(out["fin.yaml"]))
        for entry in ("SRC-IP-SUFFIX,8.8.8.8/24", "SRC-GEOIP,CN", "SRC-IP-ASN,64512"):
            self.assertIn(f'  - "{entry}"\n', generated_text(out["fin.yaml"]))
            self.assertNotIn(entry, out["fin.txt"])
            self.assertNotIn(entry, out["fin-surge.txt"])
            self.assertNotIn(entry, out["fin-qx.txt"])
        self.assertNotIn("192.0.2.0/24", out["fin-qx.txt"])
        self.assertEqual(skipped["fin-qx.txt:SRC-IP-CIDR"], 1)
        self.assertEqual(skipped["fin-qx.txt:SRC-IP-SUFFIX"], 1)

    def test_ip_suffix_no_resolve_is_mihomo_only(self):
        out, skipped = render("a3", [
            Rule("IP-SUFFIX", "8.8.8.8/24", ("no-resolve", "NO-RESOLVE")),
        ])
        self.assertEqual(generated_text(out["fin.yaml"]), '# a3 rules: 1\npayload:\n  - "IP-SUFFIX,8.8.8.8/24,no-resolve"\n')
        for name in ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-surge-ds.txt"):
            self.assertNotIn("8.8.8.8/24", out[name])
            self.assertEqual(skipped[f"{name}:IP-SUFFIX"], 1)

    def test_destination_cidr_uses_native_ipv6_names(self):
        out, skipped = render("a3", [
            Rule("IP-CIDR", "192.0.2.0/24"),
            Rule("IP-CIDR6", "2001:db8::/32"),
        ])
        self.assertIn("IP-CIDR,192.0.2.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR,192.0.2.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn("IP6-CIDR,2001:db8::/32,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('  - "IP-CIDR6,2001:db8::/32,no-resolve"\n', generated_text(out["fin.yaml"]))
        self.assertEqual(skipped["fin-adb.txt:IP-CIDR"], 1)

    def test_ipv6_address_in_generic_cidr_uses_ipv6_target_types(self):
        out, _ = render("a3", [Rule("IP-CIDR", "2001:db8::/32")])
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve\n", out["fin.txt"])
        self.assertIn("IP6-CIDR,2001:db8::/32,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('  - "IP-CIDR,2001:db8::/32,no-resolve"\n', generated_text(out["fin.yaml"]))

    def test_surge_port_names_keep_source_and_destination_distinct(self):
        out, skipped = render("a3", [Rule("SRC-PORT", "5353"), Rule("DST-PORT", "443")])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("SRC-PORT,5353\n", out[name])
            self.assertIn("DEST-PORT,443\n", out[name])
        self.assertIn('  - "SRC-PORT,5353"\n', generated_text(out["fin.yaml"]))
        self.assertIn('  - "DST-PORT,443"\n', generated_text(out["fin.yaml"]))
        self.assertEqual(skipped["fin-qx.txt:DST-PORT"], 1)
        self.assertEqual(skipped["fin-qx.txt:SRC-PORT"], 1)

    def test_surge_destination_port_maps_to_mihomo_dst_port(self):
        out, _ = render("a3", [Rule("DEST-PORT", "443")])
        self.assertIn('  - "DST-PORT,443"\n', generated_text(out["fin.yaml"]))

    def test_single_source_ip_maps_to_mihomo_source_cidr(self):
        out, _ = render("a3", [
            Rule("SRC-IP", "192.0.2.1"), Rule("SRC-IP", "2001:db8::1"),
        ])
        self.assertIn('"SRC-IP-CIDR,192.0.2.1/32"', generated_text(out["fin.yaml"]))
        self.assertIn('"SRC-IP-CIDR,2001:db8::1/128"', generated_text(out["fin.yaml"]))
        self.assertNotIn("no-resolve", generated_text(out["fin.yaml"]))

    def test_equivalent_port_aliases_render_once_per_target(self):
        out, _ = render("a3", [Rule("DST-PORT", "443"), Rule("DEST-PORT", "443")])
        self.assertEqual(out["fin.txt"].count("DEST-PORT,443\n"), 1)
        self.assertEqual(out["fin-surge.txt"].count("DEST-PORT,443\n"), 1)
        self.assertEqual(generated_text(out["fin.yaml"]).count('"DST-PORT,443"\n'), 1)

    def test_mihomo_udp_network_maps_to_surge_protocol(self):
        out, _ = render("a3", [Rule("NETWORK", "udp")])
        self.assertIn("PROTOCOL,UDP\n", out["fin.txt"])
        self.assertIn("PROTOCOL,UDP\n", out["fin-surge.txt"])
        self.assertIn('"NETWORK,udp"', generated_text(out["fin.yaml"]))

    def test_surge_udp_protocol_maps_to_mihomo_network(self):
        out, _ = render("a3", [Rule("PROTOCOL", "UDP")])
        self.assertIn('"NETWORK,udp"', generated_text(out["fin.yaml"]))
        self.assertIn("PROTOCOL,UDP\n", out["fin.txt"])

    def test_process_name_regex_quantifier_comma_survives_mihomo_top_level_and_logic(self):
        from rules import parse

        for source, expected in (
            ("PROCESS-NAME-REGEX,^Foo{1,2}Bar$,PROXY",
             "PROCESS-NAME-REGEX,^Foo{1,2}Bar$"),
            ("AND,((PROCESS-NAME-REGEX,^Foo{1,2}Bar$),(DOMAIN,a.example.com)),PROXY",
             "AND,((PROCESS-NAME-REGEX,^Foo{1,2}Bar$),(DOMAIN,a.example.com))"),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(messages, [])
                self.assertEqual(len(parsed), 1)
                out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# cdn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n'))
                self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
                self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
                self.assertEqual(skipped, {
                    f"{name}:{parsed[0].kind}": 1 for name in
                    ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                })

    def test_surge_absolute_process_names_keep_exact_and_glob_path_scope_in_mihomo(self):
        from rules import parse

        for path, mihomo_kind in (("/usr/bin/ssh", "PROCESS-PATH"),
                                  ("/usr/*/ssh", "PROCESS-PATH-WILDCARD")):
            for source, surge_rule, mihomo_rule in (
                (f"PROCESS-NAME,{path},PROXY", f"PROCESS-NAME,{path}",
                 expected_process(path) if "*" not in path else None),
                (f"AND,((PROCESS-NAME,{path}),(DOMAIN,a.example.com)),PROXY",
                 f"AND,((PROCESS-NAME,{path}),(DOMAIN,a.example.com))",
                 f"AND,(({expected_process(path)}),(DOMAIN,a.example.com))" if "*" not in path else None),
            ):
                with self.subTest(source=source):
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual(messages, [])
                    self.assertEqual(len(parsed), 1)
                    out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual(out["fin.txt"], f"# cdn rules: 1\n{surge_rule}\n")
                    self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
                    self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                                     [expected_ordinary_payload(entry) for entry in ([mihomo_rule] if mihomo_rule else [])])
                    self.assertEqual(skipped, {
                        f"{name}:{parsed[0].kind}": 1 for name in
                        ("fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt") + (("fin.yaml",) if mihomo_rule is None else ())
                    })

    def test_mihomo_literal_process_name_absolute_path_remains_name(self):
        from rules import parse

        for source, expected in (
            ('payload:\n  - "PROCESS-NAME,/usr/bin/ssh"', "PROCESS-NAME,/usr/bin/ssh"),
            ('payload:\n  - "AND,((PROCESS-NAME,/usr/bin/ssh),(DOMAIN,a.example.com))"',
             "AND,((PROCESS-NAME,/usr/bin/ssh),(DOMAIN,a.example.com))"),
        ):
            with self.subTest(source=source):
                parsed, messages = parse(source, purpose="proxy")
                self.assertEqual(messages, [])
                out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
                self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
                self.assertEqual(skipped, {
                    f"{name}:{parsed[0].kind}": 1 for name in
                    ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                })

    def test_mihomo_literal_process_path_metacharacters_do_not_become_surge_globs(self):
        from rules import parse

        for path in ("/Applications/Foo*Bar", "/Applications/Foo?Bar"):
            for source, expected in (
                (f'payload:\n  - "PROCESS-PATH,{path}"', f"PROCESS-PATH,{path}"),
                (f'payload:\n  - "AND,((PROCESS-PATH,{path}),(DOMAIN,a.example.com))"',
                 f"AND,((PROCESS-PATH,{path}),(DOMAIN,a.example.com))"),
            ):
                with self.subTest(source=source):
                    parsed, messages = parse(source, purpose="proxy")
                    self.assertEqual(messages, [])
                    out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
                    self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n  - ' + json.dumps(expected) + '\n')
                    self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
                    self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
                    self.assertEqual(skipped, {
                        f"{name}:{parsed[0].kind}": 1 for name in
                        ("fin.txt", "fin-surge.txt", "fin-qx.txt", "fin-adb.txt", "fin-surge-ds.txt")
                    })

    def test_surge_process_name_glob_keeps_wildcard_semantics_in_mihomo(self):
        out, skipped = render("dirt", [
            Rule("PROCESS-NAME", "qbittorrent*"), Rule("PROCESS-NAME", "FooApp"),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"].splitlines()[1:], [
            "PROCESS-NAME,FooApp", "PROCESS-NAME,qbittorrent*",
        ])
        self.assertEqual(out["fin-surge.txt"].splitlines()[1:], [
            "PROCESS-NAME,FooApp", "PROCESS-NAME,qbittorrent*",
        ])
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [expected_process("FooApp")])
        self.assertEqual(skipped["fin.yaml:PROCESS-NAME"], 1)
        self.assertEqual(out["fin-qx.txt"], "# dirt rules: 0\n")
        self.assertEqual(skipped["fin-qx.txt:PROCESS-NAME"], 2)

    def test_mihomo_literal_process_wildcard_is_not_widened_for_surge(self):
        out, skipped = render_configured(
            "cdn", [Rule("PROCESS-NAME", "Foo*Bar", literal_process=True)],
            purpose="proxy", no_resolve="strip",
        )
        self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n  - "PROCESS-NAME,Foo*Bar"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped["fin.txt:PROCESS-NAME"], 1)
        self.assertEqual(skipped["fin-surge.txt:PROCESS-NAME"], 1)

    def test_mixed_process_source_intents_render_both_mihomo_matchers(self):
        from rules import normalize, parse

        literal, _ = parse('payload:\n  - "PROCESS-NAME,Foo*Bar"\n', purpose="proxy")
        glob, _ = parse("PROCESS-NAME,Foo*Bar,PROXY", purpose="proxy")
        for ordered in (literal + glob, glob + literal):
            with self.subTest(first_is_literal=ordered[0].literal_process):
                out, skipped = render_configured(
                    "cdn", normalize(ordered), purpose="proxy", no_resolve="keep",
                )
                self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n'
                                 '  - "PROCESS-NAME,Foo*Bar"\n')
                self.assertEqual(skipped["fin.yaml:PROCESS-NAME"], 1)
                self.assertEqual(out["fin.txt"], "# cdn rules: 1\nPROCESS-NAME,Foo*Bar\n")
                self.assertEqual(skipped["fin.txt:PROCESS-NAME"], 1)

    def test_mihomo_literal_process_child_is_not_widened_in_surge_logic(self):
        from rules import parse

        parsed, warnings = parse(
            'payload:\n  - "AND,((OR,((PROCESS-NAME,Foo?Bar),(DOMAIN,a.example.com))),(DOMAIN,b.example.com))"\n',
            purpose="proxy",
        )
        self.assertEqual(warnings, [])
        out, skipped = render_configured("cdn", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n'
                         '  - "AND,((OR,((PROCESS-NAME,Foo?Bar),(DOMAIN,a.example.com))),(DOMAIN,b.example.com))"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin-surge.txt:AND"], 1)

    def test_qx_interface_options_emit_remote_matcher_and_report_omission(self):
        from rules import parse

        for option in ("force-cellular", "multi-interface", "via-interface=pdp_ip0"):
            with self.subTest(option=option):
                parsed, warnings = parse(
                    f"HOST-SUFFIX,googleapis.com,PROXY,{option}", purpose="proxy",
                )
                self.assertEqual(warnings, [])
                out, skipped = render_configured(
                    "cdn", parsed, purpose="proxy", no_resolve="keep",
                )
                self.assertEqual(out["fin-qx.txt"],
                                 "# cdn rules: 1\nHOST-SUFFIX,googleapis.com,LIST\n")
                self.assertEqual(out["fin.txt"],
                                 "# cdn rules: 1\nDOMAIN-SUFFIX,googleapis.com\n")
                self.assertEqual(generated_text(out["fin.yaml"]),
                                 '# cdn rules: 1\npayload:\n  - "DOMAIN-SUFFIX,googleapis.com"\n')
                self.assertNotIn(option, "".join(generated_texts(out).values()))
                self.assertEqual(skipped["fin-qx.txt:DOMAIN-SUFFIX:interface-option"], 1)

    def test_mihomo_name_wildcard_with_absolute_path_stays_out_of_surge(self):
        from rules import parse

        parsed, warnings = parse('payload:\n  - "PROCESS-NAME-WILDCARD,/usr/*/ssh"', purpose="proxy")
        self.assertEqual(warnings, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n  - "PROCESS-NAME-WILDCARD,/usr/*/ssh"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped, {
            "fin.txt:PROCESS-NAME-WILDCARD": 1, "fin-surge.txt:PROCESS-NAME-WILDCARD": 1,
            "fin-qx.txt:PROCESS-NAME-WILDCARD": 1, "fin-adb.txt:PROCESS-NAME-WILDCARD": 1,
            "fin-surge-ds.txt:PROCESS-NAME-WILDCARD": 1,
        })

    def test_mihomo_name_wildcard_with_absolute_path_stays_out_of_surge_logic(self):
        from rules import parse

        parsed, warnings = parse(
            'payload:\n  - "AND,((PROCESS-NAME-WILDCARD,/usr/*/ssh),(DOMAIN,a.example.com))"',
            purpose="proxy",
        )
        self.assertEqual(warnings, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        self.assertEqual(generated_text(out["fin.yaml"]), '# cdn rules: 1\npayload:\n'
                         '  - "AND,((PROCESS-NAME-WILDCARD,/usr/*/ssh),(DOMAIN,a.example.com))"\n')
        self.assertEqual(out["fin.txt"], "# cdn rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# cdn rules: 0\n")
        self.assertEqual(skipped, {
            "fin.txt:AND": 1, "fin-surge.txt:AND": 1, "fin-qx.txt:AND": 1,
            "fin-adb.txt:AND": 1, "fin-surge-ds.txt:AND": 1,
        })

    def test_process_name_wildcard_maps_to_surge_process_name(self):
        out, skipped = render("a3", [Rule("PROCESS-NAME-WILDCARD", "*telegram*")])
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.txt:PROCESS-NAME-WILDCARD"], 1)
        self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin-surge.txt:PROCESS-NAME-WILDCARD"], 1)
        self.assertIn('"PROCESS-NAME-WILDCARD,*telegram*"', generated_text(out["fin.yaml"]))

    def test_posix_process_path_maps_to_surge_process_name(self):
        path = "/Applications/Foo.app/Contents/MacOS/Foo"
        out, skipped = render("a3", [Rule("PROCESS-PATH", path)])
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.txt:PROCESS-PATH"], 1)
        self.assertIn(f'"PROCESS-PATH,{path}"', generated_text(out["fin.yaml"]))

    def test_posix_process_path_wildcard_maps_to_surge_process_name(self):
        out, skipped = render("a3", [Rule("PROCESS-PATH-WILDCARD", "/Applications/Foo*/bin")])
        expected = "# a3 rules: 0\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(generated_text(out["fin.yaml"]), '# a3 rules: 1\npayload:\n  - "PROCESS-PATH-WILDCARD,/Applications/Foo*/bin"\n')
        self.assertEqual(skipped["fin.txt:PROCESS-PATH-WILDCARD"], 1)

    def test_mihomo_skips_process_names_with_unrepresentable_commas(self):
        out, skipped = render("dirt", [
            Rule("PROCESS-NAME", "Foo,Bar"), Rule("PROCESS-PATH", "/Applications/Foo,Bar"),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"].splitlines()[1:], [
            "PROCESS-NAME,'Foo,Bar'",
        ])
        self.assertEqual(out["fin-surge.txt"].splitlines()[1:], [
            "PROCESS-NAME,'Foo,Bar'",
        ])
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [expected_process("Foo,Bar")])
        self.assertEqual(out["fin-qx.txt"], "# dirt rules: 0\n")
        self.assertNotIn("fin.yaml:PROCESS-NAME", skipped)
        self.assertEqual(skipped["fin.yaml:PROCESS-PATH"], 1)

    def test_process_and_user_agent_only_go_to_confirmed_clients(self):
        out, skipped = render("a3", [Rule("PROCESS-NAME", "FooApp"), Rule("USER-AGENT", "*bot*")])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("PROCESS-NAME,FooApp\n", out[name])
            self.assertIn("USER-AGENT,*bot*\n", out[name])
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [expected_process("FooApp")])
        self.assertNotIn("USER-AGENT", generated_text(out["fin.yaml"]))
        self.assertIn("USER-AGENT,*bot*,LIST\n", out["fin-qx.txt"])
        self.assertNotIn("PROCESS-NAME", out["fin-qx.txt"])
        self.assertEqual(skipped["fin-qx.txt:PROCESS-NAME"], 1)
        self.assertEqual(skipped["fin.yaml:USER-AGENT"], 1)

    def test_ip_asn_geoip_and_keyword_are_not_discarded(self):
        out, skipped = render("a3", [
            Rule("IP-ASN", "13335"), Rule("GEOIP", "CN"),
            Rule("DOMAIN-KEYWORD", "ads"),
        ])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertIn("IP-ASN,13335,no-resolve\n", out[name])
            self.assertIn("GEOIP,CN,no-resolve\n", out[name])
            self.assertIn("DOMAIN-KEYWORD,ads\n", out[name])
        for entry in ("IP-ASN,13335,LIST,no-resolve", "GEOIP,CN,LIST,no-resolve", "HOST-KEYWORD,ads,LIST"):
            self.assertIn(entry + "\n", out["fin-qx.txt"])
        for entry in ("IP-ASN,13335,no-resolve", "GEOIP,CN,no-resolve", "DOMAIN-REGEX,ads"):
            self.assertIn('  - "' + entry + '"\n', generated_text(out["fin.yaml"]))
        self.assertIn("/^.*ads.*$/\n", out["fin-adb.txt"])
        self.assertNotIn("fin-adb.txt:DOMAIN-KEYWORD", skipped)

    def test_mihomo_only_types_are_json_quoted_yaml_scalars(self):
        rules = [
            Rule("DOMAIN-REGEX", '^ad-"promo"\\.example\\.com$'),
            Rule("PROCESS-PATH", "C:\\Program Files\\Foo\\bar.exe"),
            Rule("NETWORK", "udp"), Rule("IN-TYPE", "SOCKS/HTTP"),
        ]
        out, skipped = render("a3", rules)
        self.assertEqual(generated_text(out["fin.yaml"]).splitlines()[0:2], ["# a3 rules: 4", "payload:"])
        self.assertEqual(
            {generated_payload(line.removeprefix("  - ")) for line in out["fin.yaml"].splitlines()[2:]},
            {
                'DOMAIN-REGEX,^ad-"promo"\\.example\\.com$',
                "PROCESS-PATH,C:\\Program Files\\Foo\\bar.exe",
                "NETWORK,udp", "IN-TYPE,SOCKS/HTTP",
            },
        )
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin-qx.txt:DOMAIN-REGEX"], 1)
        self.assertEqual(skipped["fin.txt:PROCESS-PATH"], 1)

    def test_all_mihomo_values_use_json_quoted_yaml_strings(self):
        value = 'Foo"bar\\baz'
        out, _ = render("a3", [Rule("PROCESS-NAME", value, literal_process=True)])
        self.assertIn('\\"', generated_text(out["fin.yaml"]).splitlines()[2])
        self.assertEqual(generated_payload(out["fin.yaml"].splitlines()[2][4:]),
                         'PROCESS-NAME,Foo"bar\\baz')
        self.assertEqual(generated_text(out["fin.yaml"]).splitlines()[0], "# a3 rules: 1")

    def test_mihomo_classical_preserves_documented_types_not_provider_directives(self):
        entries = [
            ("GEOSITE", "youtube"), ("IP-SUFFIX", "8.8.8.8/24"),
            ("SRC-GEOIP", "CN"), ("SRC-IP-ASN", "9808"),
            ("SRC-IP-SUFFIX", "192.0.2.1/8"), ("IN-PORT", "7890"),
            ("IN-USER", "alice"), ("IN-NAME", "socks"),
            ("REMATCH-NAME", "rematch1"), ("PROCESS-PATH-WILDCARD", "/usr/*/wget"),
            ("PROCESS-PATH-REGEX", ".*bin/wget"),
            ("PROCESS-NAME-WILDCARD", "*telegram*"),
            ("PROCESS-NAME-REGEX", "curl$"), ("UID", "1001"), ("DSCP", "4"),
        ]
        out, skipped = render("a3", [Rule(kind, value) for kind, value in entries] + [
            Rule("RULE-SET", "another-provider"), Rule("SUB-RULE", "(NETWORK,tcp)"),
            Rule("MATCH", ""),
        ])
        self.assertEqual(generated_text(out["fin.yaml"]).splitlines()[0], "# a3 rules: 15")
        self.assertEqual(
            {generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]},
            {f"{kind},{value}" + (",no-resolve" if kind == "IP-SUFFIX" else "")
             for kind, value in entries},
        )
        for kind in ("RULE-SET", "SUB-RULE", "MATCH"):
            self.assertEqual(skipped[f"fin.yaml:{kind}"], 1)
        self.assertNotIn("IN-TYPE", out["fin-qx.txt"])

    def test_parsed_single_child_not_is_rendered_with_valid_parentheses(self):
        from rules import parse

        parsed, messages = parse("NOT,(DOMAIN,cdn.example.com),PROXY", purpose="proxy")
        self.assertEqual(messages, [])
        out, _ = render("cdn", parsed)
        self.assertIn("NOT,((DOMAIN,cdn.example.com))\n", out["fin.txt"])
        self.assertIn(expected_ordinary_text('"NOT,((DOMAIN,cdn.example.com))"'), generated_text(out["fin.yaml"]))

    def test_logical_rules_keep_parentheses_only_with_compatible_children(self):
        values = {
            "AND": "((DOMAIN,ads.example.com),(NETWORK,UDP))",
            "OR": "((DOMAIN,ads.example.com),(DOMAIN-SUFFIX,other.example.com))",
            "NOT": "((DOMAIN,safe.example.com))",
        }
        out, skipped = render("a3", [Rule(kind, value) for kind, value in values.items()] + [
            Rule("AND", "((RULE-SET,another-provider),(DOMAIN,ad.example.com))"),
        ])
        for kind, value in values.items():
            self.assertIn(expected_ordinary_text(f'  - "{kind},{value}"\n'), generated_text(out["fin.yaml"]))
            self.assertEqual(skipped[f"fin-qx.txt:{kind}"], 1 if kind != "AND" else 2)
        self.assertIn("OR," + values["OR"] + "\n", out["fin.txt"])
        self.assertIn("NOT," + values["NOT"] + "\n", out["fin-surge.txt"])
        self.assertIn("AND,((DOMAIN,ads.example.com),(PROTOCOL,UDP))\n", out["fin.txt"])
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertNotIn("RULE-SET", generated_text(out["fin.yaml"]))

    def test_logical_network_alias_is_supported_in_both_surge_rulesets(self):
        out, skipped = render("a3", [Rule("AND", "((NETWORK,udp),(DOMAIN,a.example.com))")])
        expected = "# a3 rules: 1\nAND,((PROTOCOL,UDP),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# a3 rules: 1\npayload:\n  - "AND,((NETWORK,udp),(DOMAIN,a.example.com))"\n'))
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:], ["! Total count: 0"])
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped, {
            "fin-qx.txt:AND": 1, "fin-adb.txt:AND": 1, "fin-surge-ds.txt:AND": 1,
        })

    def test_logical_destination_port_alias_is_supported_in_mihomo(self):
        out, skipped = render("a3", [Rule("AND", "((DEST-PORT,443),(DOMAIN,a.example.com))")])
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nAND,((DEST-PORT,443),(DOMAIN,a.example.com))\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# a3 rules: 1\npayload:\n  - "AND,((DST-PORT,443),(DOMAIN,a.example.com))"\n'))
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_source_ip_and_protocol_aliases_keep_match_direction(self):
        source = Rule("AND", "((SRC-IP,192.0.2.1),(PROTOCOL,UDP))")
        out, skipped = render("a3", [source])
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nAND,((SRC-IP,192.0.2.1),(PROTOCOL,UDP))\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(generated_text(out["fin.yaml"]), '# a3 rules: 1\npayload:\n  - "AND,((SRC-IP-CIDR,192.0.2.1/32),(NETWORK,udp))"\n')
        self.assertNotIn("no-resolve", generated_text(out["fin.yaml"]))
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_source_ip_cidr_preserves_ipv4_and_ipv6_ranges_in_mihomo(self):
        from rules import parse

        parsed, messages = parse(
            "AND,((SRC-IP,192.0.2.0/24),(DOMAIN,a.example.com)),REJECT\n"
            "AND,((SRC-IP,2001:db8::/32),(DOMAIN,a.example.com)),REJECT",
            purpose="block",
        )
        self.assertEqual(messages, [])
        out, skipped = render("a3", parsed, no_resolve="add")
        self.assertEqual(generated_text(out["fin.yaml"]).splitlines()[2:], [expected_ordinary_text(entry) for entry in ([
            '  - "AND,((SRC-IP-CIDR,192.0.2.0/24),(DOMAIN,a.example.com))"',
            '  - "AND,((SRC-IP-CIDR,2001:db8::/32),(DOMAIN,a.example.com))"',
        ])])
        self.assertEqual(out["fin.txt"], out["fin-surge.txt"])
        self.assertIn("AND,((SRC-IP,192.0.2.0/24),(DOMAIN,a.example.com))\n", out["fin.txt"])
        self.assertIn("AND,((SRC-IP,2001:db8::/32),(DOMAIN,a.example.com))\n", out["fin.txt"])
        self.assertNotIn("no-resolve", generated_text(out["fin.yaml"]))
        self.assertEqual(skipped["fin-qx.txt:AND"], 2)
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_quoted_process_comma_is_preserved_for_surge_only(self):
        from rules import parse

        parsed, messages = parse('AND,((PROCESS-NAME,"Foo,Bar"),(DOMAIN,a.example.com)),PROXY', purpose="proxy")
        self.assertEqual(messages, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        expected = "# cdn rules: 1\nAND,((PROCESS-NAME,'Foo,Bar'),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [expected_ordinary_payload(entry) for entry in ([f"AND,(({expected_process('Foo,Bar')}),(DOMAIN,a.example.com))"])])
        self.assertEqual(out["fin-surge-ds.txt"], "# cdn rules: 0\n")
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_quoted_url_regex_comma_is_preserved_for_surge_only(self):
        from rules import parse

        parsed, messages = parse(r'OR,((URL-REGEX,"^https://ads\.example/a,b$"),(DOMAIN,a.example.com)),PROXY', purpose="proxy")
        self.assertEqual(messages, [])
        out, skipped = render("cdn", parsed, purpose="proxy", no_resolve="keep")
        expected = "# cdn rules: 1\nOR,((URL-REGEX,'^https://ads\\.example/a,b$'),(DOMAIN,a.example.com))\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(generated_text(out["fin.yaml"]), "# cdn rules: 0\npayload:\n")
        self.assertEqual(skipped["fin.yaml:OR"], 1)

    def test_mihomo_logical_regex_comma_retains_required_quotes(self):
        from rules import parse

        source = 'AND,((DOMAIN-REGEX,"^ads,[0-9]+[.]example$"),(DOMAIN,a.example.com)),REJECT'
        parsed, messages = parse(source, purpose="block")
        self.assertEqual(messages, [])
        out, skipped = render("a3", parsed, no_resolve="keep")
        self.assertEqual(generated_text(out["fin.yaml"]),
                         expected_ordinary_text('# a3 rules: 1\npayload:\n  - "AND,((DOMAIN-REGEX,^ads,[0-9]+[.]example$),(DOMAIN,a.example.com))"\n'))
        round_trip, warnings = parse(out["fin.yaml"], purpose="block")
        self.assertEqual(warnings, [])
        self.assertEqual(round_trip, parsed)
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_logical_no_resolve_add_strip_keep_changes_only_destination_ip_leaves(self):
        source = Rule("OR", "((IP-CIDR,192.0.2.0/24),(GEOIP,CN,no-resolve))")
        for mode, first, second in (
            ("add", "IP-CIDR,192.0.2.0/24,no-resolve", "GEOIP,CN,no-resolve"),
            ("strip", "IP-CIDR,192.0.2.0/24", "GEOIP,CN"),
            ("keep", "IP-CIDR,192.0.2.0/24", "GEOIP,CN,no-resolve"),
        ):
            with self.subTest(mode=mode):
                out, skipped = render("a3", [source], no_resolve=mode)
                expected = f"# a3 rules: 1\nOR,(({first}),({second}))\n"
                self.assertEqual(out["fin.txt"], expected)
                self.assertEqual(out["fin-surge.txt"], expected)
                self.assertEqual(generated_text(out["fin.yaml"]), '# a3 rules: 1\npayload:\n  - ' +
                                 json.dumps(f"OR,(({first}),({second}))") + "\n")
                self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
                self.assertNotIn("fin.txt:OR", skipped)
                self.assertNotIn("fin.yaml:OR", skipped)

    def test_nested_not_no_resolve_does_not_touch_source_ip_or_domain(self):
        source = Rule("AND", "((OR,((SRC-IP-CIDR,192.0.2.0/24),(NOT,((IP-ASN,64500,no-resolve))))),(DOMAIN,a.example.com))")
        out, skipped = render("a3", [source], no_resolve="strip")
        expected = "AND,((OR,((SRC-IP,192.0.2.0/24),(NOT,((IP-ASN,64500))))),(DOMAIN,a.example.com))"
        self.assertEqual(out["fin.txt"], f"# a3 rules: 1\n{expected}\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# a3 rules: 1\npayload:\n  - "AND,((OR,((SRC-IP-CIDR,192.0.2.0/24),(NOT,((IP-ASN,64500))))),(DOMAIN,a.example.com))"\n'))
        self.assertNotIn("no-resolve", out["fin.txt"])
        self.assertNotIn("fin.txt:AND", skipped)

    def test_logical_ip_suffix_no_resolve_is_mihomo_only(self):
        source = Rule("NOT", "((IP-SUFFIX,8.8.8.8/24,no-resolve))")
        for mode, suffix in (("add", ",no-resolve"), ("strip", ""), ("keep", ",no-resolve")):
            with self.subTest(mode=mode):
                out, skipped = render("a3", [source], no_resolve=mode)
                self.assertEqual(generated_text(out["fin.yaml"]),
                                 '# a3 rules: 1\npayload:\n  - "NOT,((IP-SUFFIX,8.8.8.8/24' + suffix + '))"\n')
                self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
                self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
                self.assertEqual(skipped["fin.txt:NOT"], 1)
                self.assertEqual(skipped["fin-surge.txt:NOT"], 1)
                self.assertNotIn("fin.yaml:NOT", skipped)

    def test_logical_duplicate_no_resolve_flags_emit_once(self):
        source = Rule("AND", "((IP-CIDR,192.0.2.0/24,no-resolve,no-resolve),(DOMAIN,a.example.com))")
        out, _ = render("a3", [source], no_resolve="add")
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nAND,((IP-CIDR,192.0.2.0/24,no-resolve),(DOMAIN,a.example.com))\n")
        self.assertEqual(out["fin-surge.txt"], out["fin.txt"])
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# a3 rules: 1\npayload:\n  - "AND,((IP-CIDR,192.0.2.0/24,no-resolve),(DOMAIN,a.example.com))"\n'))

    def test_unsupported_source_ip_child_skips_whole_surge_rule(self):
        source = Rule("AND", "((SRC-GEOIP,CN),(DOMAIN,a.example.com))")
        out, skipped = render("a3", [source])
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-surge.txt"], "# a3 rules: 0\n")
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# a3 rules: 1\npayload:\n  - "AND,((SRC-GEOIP,CN),(DOMAIN,a.example.com))"\n'))
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin-surge.txt:AND"], 1)

    def test_nested_process_path_wildcard_maps_to_surge_process_name(self):
        source = Rule("AND", "((PROCESS-PATH-WILDCARD,/Applications/Foo*/bin),(DOMAIN,a.example.com))")
        out, skipped = render("cdn", [source], purpose="proxy", no_resolve="keep")
        expected = "# cdn rules: 0\n"
        self.assertEqual(out["fin.txt"], expected)
        self.assertEqual(out["fin-surge.txt"], expected)
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text('# cdn rules: 1\npayload:\n  - "AND,((PROCESS-PATH-WILDCARD,/Applications/Foo*/bin),(DOMAIN,a.example.com))"\n'))
        self.assertEqual(skipped["fin.txt:AND"], 1)

    def test_surge_translates_nested_source_cidr_and_destination_port(self):
        value = "((SRC-IP-CIDR,2001:db8::/32),(DST-PORT,443))"
        out, skipped = render("a3", [Rule("AND", value)])
        expected = "AND,((SRC-IP,2001:db8::/32),(DEST-PORT,443))\n"
        self.assertIn(expected, out["fin.txt"])
        self.assertIn(expected, out["fin-surge.txt"])
        self.assertIn('  - "AND,' + value + '"\n', generated_text(out["fin.yaml"]))
        self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_mihomo_converts_surge_process_glob_inside_logic(self):
        value = "((PROCESS-NAME,qbittorrent*),(DOMAIN,ads.example.org))"
        out, skipped = render("dirt", [Rule("AND", value)], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"], f"# dirt rules: 1\nAND,{value}\n")
        self.assertEqual(out["fin-surge.txt"], f"# dirt rules: 1\nAND,{value}\n")
        self.assertEqual(generated_text(out["fin.yaml"]), '# dirt rules: 0\npayload:\n')
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin-qx.txt:AND"], 1)

    def test_surge_ipv6_cidr_inside_logic_uses_ipv6_matcher(self):
        value = "((IP-CIDR,2001:db8::/32),(DOMAIN,ads.example.com))"
        out, _ = render("a3", [Rule("OR", value)])
        self.assertIn("OR,((IP-CIDR6,2001:db8::/32,no-resolve),(DOMAIN,ads.example.com))\n", out["fin.txt"])
        self.assertIn(expected_ordinary_text('  - "OR,((IP-CIDR6,2001:db8::/32,no-resolve),(DOMAIN,ads.example.com))"\n'), generated_text(out["fin.yaml"]))

    def test_mihomo_ipv6_cidr_inside_nested_logic_uses_ipv6_matcher(self):
        from rules import parse

        source = "AND,((OR,((IP-CIDR,2001:db8::/32),(IP-CIDR,192.0.2.0/24))),(DOMAIN,ads.example.com)),REJECT"
        parsed, messages = parse(source, purpose="block")
        self.assertEqual(messages, [])
        self.assertEqual(len(parsed), 1)

        out, _ = render("a3", parsed)
        expected = "AND,((OR,((IP-CIDR6,2001:db8::/32,no-resolve),(IP-CIDR,192.0.2.0/24,no-resolve))),(DOMAIN,ads.example.com))"
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text(f'# a3 rules: 1\npayload:\n  - "{expected}"\n'))
        self.assertEqual(out["fin.txt"], f"# a3 rules: 1\n{expected}\n")
        self.assertEqual(out["fin-surge.txt"], f"# a3 rules: 1\n{expected}\n")

    def test_logical_regex_character_class_parenthesis_is_not_structural(self):
        expression = r"((DOMAIN-REGEX,^[a)b]\.example$),(DOMAIN,ads.example))"
        out, skipped = render("a3", [Rule("AND", expression)])
        expected = r"AND,((DOMAIN-REGEX,^[a\x{29}b]\.example$),(DOMAIN,ads.example))"
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]], [expected_ordinary_payload(entry) for entry in ([expected])])
        from rules import parse
        self.assertEqual(parse(out["fin.yaml"], purpose="block")[1], [])
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_process_name_with_comma_skips_incompatible_logical_rule_as_a_whole(self):
        safe = "((DOMAIN,a.org),(DOMAIN,b.org))"
        out, skipped = render("dirt", [
            Rule("AND", "((PROCESS-NAME,Foo,Bar),(DOMAIN,ads.example.org))"),
            Rule("OR", safe),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"], f"# dirt rules: 1\nOR,{safe}\n")
        self.assertEqual(out["fin-surge.txt"], f"# dirt rules: 1\nOR,{safe}\n")
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text(f'# dirt rules: 1\npayload:\n  - "OR,{safe}"\n'))
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin.yaml:AND"], 1)

    def test_blank_logical_child_skips_entire_rule_without_dropping_valid_logic(self):
        valid = "((DOMAIN,a.org),(DOMAIN,b.org))"
        out, skipped = render("dirt", [
            Rule("AND", "((DOMAIN,ads.example.com),(PROCESS-NAME,   ))"),
            Rule("OR", valid),
        ], purpose="direct", no_resolve="strip")
        self.assertEqual(out["fin.txt"], f"# dirt rules: 1\nOR,{valid}\n")
        self.assertEqual(out["fin-surge.txt"], f"# dirt rules: 1\nOR,{valid}\n")
        self.assertEqual(generated_text(out["fin.yaml"]), expected_ordinary_text(f'# dirt rules: 1\npayload:\n  - "OR,{valid}"\n'))
        self.assertEqual(skipped["fin.txt:AND"], 1)
        self.assertEqual(skipped["fin.yaml:AND"], 1)

    def test_invalid_logical_children_and_parentheses_are_skipped(self):
        out, skipped = render("a3", [
            Rule("AND", "((DOMAIN,valid.example.com),(UNKNOWN,v))"),
            Rule("NOT", "(UNKNOWN,invalid.example.com)"),
        ])
        self.assertEqual(generated_text(out["fin.yaml"]), "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.yaml:NOT"], 1)

    def test_logical_arity_is_valid_for_not_and_and(self):
        out, skipped = render("a3", [
            Rule("AND", "((DOMAIN,ad.example.com))"),
            Rule("NOT", "((DOMAIN,first.example.com),(DOMAIN,second.example.com))"),
        ])
        self.assertEqual(generated_text(out["fin.yaml"]), "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin.yaml:AND"], 1)
        self.assertEqual(skipped["fin.yaml:NOT"], 1)

    def test_logical_children_require_separating_comma(self):
        out, skipped = render("a3", [Rule("AND", "((DOMAIN,one.example.com)(DOMAIN,two.example.com))")])
        self.assertEqual(generated_text(out["fin.yaml"]), "# a3 rules: 0\npayload:\n")
        self.assertEqual(skipped["fin.txt:AND"], 1)

    def test_mihomo_converts_surge_only_wildcard_class_inside_logic(self):
        value = "((DOMAIN-WILDCARD,api-[0-9].example.com),(DOMAIN,ads.example.com))"
        out, skipped = render("a3", [Rule("AND", value)])
        self.assertEqual([generated_payload(line[4:]) for line in out["fin.yaml"].splitlines()[2:]],
                         [expected_ordinary_payload(entry) for entry in ([r"AND,((DOMAIN-REGEX,^api\-[0-9]\.example\.com\.?$),(DOMAIN,ads.example.com))"])])
        self.assertIn("AND," + value + "\n", out["fin.txt"])
        self.assertNotIn("fin.yaml:AND", skipped)

    def test_surge_ruleset_retains_other_documented_types(self):
        entries = [
            ("SRC-IP", "192.0.2.1"), ("URL-REGEX", "^https://ads\\.example/"),
            ("DEVICE-NAME", "Kids-iPad"), ("MAC-ADDRESS", "A4:83:E7:11:22:33"),
            ("PROTOCOL", "UDP"), ("HOSTNAME-TYPE", "IP"),
            ("SUBNET", "TYPE:CELLULAR"), ("CELLULAR-RADIO", "NR"),
            ("CELLULAR-CARRIER", "Carrier"),
        ]
        out, skipped = render("a3", [Rule(kind, value) for kind, value in entries])
        for name in ("fin.txt", "fin-surge.txt"):
            self.assertEqual(out[name].splitlines()[0], "# a3 rules: 9")
            self.assertEqual(set(out[name].splitlines()[1:]),
                             {f"{kind},{value}" for kind, value in entries})
        self.assertEqual(skipped["fin.yaml:URL-REGEX"], 1)
        self.assertEqual(skipped["fin-qx.txt:DEVICE-NAME"], 1)

    def test_surge_quotes_regex_with_comma_in_value(self):
        value = r"^https://ads\.example\.com/promo.{1,2}$"
        out, skipped = render("a3", [Rule("URL-REGEX", value)])
        self.assertIn("URL-REGEX,'" + value + "'\n", out["fin.txt"])
        self.assertIn("URL-REGEX,'" + value + "'\n", out["fin-surge.txt"])
        self.assertEqual(skipped["fin.yaml:URL-REGEX"], 1)

    def test_qx_does_not_split_user_agent_value_containing_comma(self):
        value = "Mozilla/5.0 (Macintosh, Intel Mac OS X)"
        out, skipped = render("a3", [Rule("USER-AGENT", value)])
        self.assertIn("USER-AGENT,'" + value + "'\n", out["fin.txt"])
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(skipped["fin-qx.txt:USER-AGENT"], 1)

    def test_whitelist_keyword_and_wildcard_preserve_dns_match_scope(self):
        out, skipped = render("a3", [], whitelist=[
            Rule("DOMAIN-KEYWORD", "ad.track"),
            Rule("DOMAIN-WILDCARD", "api-*.example.org"),
            Rule("DOMAIN-WILDCARD", "api-[0-9].example.org"),
        ])
        lines = out["fin-adb.txt"].splitlines()[7:]
        self.assertEqual(len(lines), 3)
        expressions = [re.compile(line[3:-1]) for line in lines]
        self.assertTrue(all(line.startswith("@@/^") and line.endswith("$/") for line in lines))
        self.assertEqual([bool(expression.fullmatch("api-v2.example.org")) for expression in expressions],
                         [False, True, False])
        self.assertEqual([bool(expression.fullmatch("api-7.example.org")) for expression in expressions],
                         [False, True, True])
        self.assertEqual([bool(expression.fullmatch("api-a.example.org")) for expression in expressions],
                         [False, True, False])
        self.assertEqual([bool(expression.fullmatch("cdn.ad.track.example.org")) for expression in expressions],
                         [True, False, False])
        self.assertTrue(all(not expression.fullmatch("api-v2.example.org.evil") for expression in expressions))
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)

    def test_custom_block_purpose_emits_dns_and_proxy_group_name_does_not(self):
        custom, _ = render("custom", [Rule("DOMAIN", "ads.example.org")],
                           purpose="block", no_resolve="keep")
        self.assertIn("\n0.0.0.0 ads.example.org\n", custom["fin-adb.txt"])
        proxy, _ = render("a3", [Rule("DOMAIN", "ads.example.org")],
                          purpose="proxy", no_resolve="keep")
        self.assertNotIn("ads.example.org", proxy["fin-adb.txt"])

    def test_group_name_does_not_override_add_or_strip_no_resolve(self):
        rule = Rule("IP-CIDR", "203.0.113.0/24", ("no-resolve",))
        added, _ = render("dirt", [rule], purpose="direct", no_resolve="add")
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", added["fin.txt"])
        stripped, _ = render("a3", [rule], purpose="block", no_resolve="strip")
        self.assertIn("IP-CIDR,203.0.113.0/24\n", stripped["fin.txt"])
        self.assertNotIn("no-resolve", stripped["fin.txt"])

    def test_new_whitelist_uses_exact_and_suffix_dns_exceptions_only_for_block_groups(self):
        whitelist = [
            Rule("DOMAIN", "safe.example.org"), Rule("DOMAIN-SUFFIX", "safe.org"),
            Rule("IP-CIDR", "192.0.2.0/24"),
        ]
        out, _ = render("a3", [Rule("DOMAIN-SUFFIX", "example.org")], whitelist=whitelist)
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 3", "@@||safe.org^", "@@|safe.example.org|", "||example.org^"])
        self.assertEqual(out["fin.txt"], "# a3 rules: 1\nDOMAIN-SUFFIX,example.org\n")
        proxy, _ = render("cdn", [], whitelist=whitelist, purpose="proxy")
        self.assertEqual(proxy["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 0", "! No AdBlock rules for non-advertising group."])

    def test_simple_allow_rule_is_only_emitted_as_adblock_exception(self):
        out, skipped = render("a3", [
            Rule("DOMAIN-SUFFIX", "safe.example.com", allow=True),
            Rule("DOMAIN", "exact.example.com", allow=True),
        ])
        self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                         ["! Total count: 2", "@@|exact.example.com|", "@@||safe.example.com^"])
        self.assertEqual(out["fin.txt"], "# a3 rules: 0\n")
        self.assertEqual(out["fin-qx.txt"], "# a3 rules: 0\n")
        self.assertEqual(generated_text(out["fin.yaml"]), "# a3 rules: 0\npayload:\n")
        self.assertEqual(out["fin-surge-ds.txt"], "# a3 rules: 0\n")
        self.assertNotIn("fin-adb.txt:DOMAIN", skipped)
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)

    def test_unknown_and_wildcard_omissions_are_counted_per_file(self):
        out, skipped = render("a3", [
            Rule("DOMAIN-WILDCARD", "api-*.example.com"), Rule("UNKNOWN-TYPE", "opaque"),
        ])
        self.assertNotIn("fin-adb.txt:DOMAIN-WILDCARD", skipped)
        self.assertIn("/^api\\-.*\\.example\\.com$/\n", out["fin-adb.txt"])
        self.assertEqual(skipped.get("fin-surge-ds.txt:DOMAIN-WILDCARD"), 1)
        self.assertTrue(all(skipped.get(f"{name}:UNKNOWN-TYPE") == 1 for name in out))
        self.assertNotIn("fin-surge.txt:DOMAIN-WILDCARD", skipped)
        self.assertEqual(out["fin.txt"].splitlines()[0], "# a3 rules: 1")

    def test_non_advertising_groups_emit_only_adblock_explanation(self):
        for group in ("cdn", "big-data", "dirt"):
            with self.subTest(group=group):
                out, skipped = render(group, [Rule("DOMAIN-SUFFIX", "legitimate.example.com")], purpose="direct" if group == "dirt" else "proxy")
                self.assertEqual(out["fin-adb.txt"].splitlines()[1], f"! Title: {group}")
                self.assertEqual(out["fin-adb.txt"].splitlines()[6:],
                                 ["! Total count: 0", "! No AdBlock rules for non-advertising group."])
                self.assertIn("DOMAIN-SUFFIX,legitimate.example.com\n", out["fin.txt"])
                self.assertEqual(skipped["fin-adb.txt:DOMAIN-SUFFIX"], 1)

    def test_non_dirt_destination_cidr_adds_no_resolve_on_supported_targets(self):
        rule = Rule("IP-CIDR", "203.0.113.0/24")
        out, _ = render("a3", [rule])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin-surge.txt"])
        self.assertIn("IP-CIDR,203.0.113.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertIn('"IP-CIDR,203.0.113.0/24,no-resolve"', generated_text(out["fin.yaml"]))
        domestic, _ = render("dirt", [rule], purpose="direct", no_resolve="strip")
        self.assertIn("IP-CIDR,203.0.113.0/24\n", domestic["fin.txt"])
        self.assertNotIn("no-resolve", domestic["fin.txt"])

    def test_no_resolve_is_preserved_without_silently_dropping_other_options(self):
        out, skipped = render("a3", [
            Rule("IP-CIDR", "203.0.113.0/24", ("no-resolve",)),
            Rule("DOMAIN-SUFFIX", "unsafe.example.com", ("unverified-flag",)),
        ])
        self.assertIn("IP-CIDR,203.0.113.0/24,no-resolve\n", out["fin.txt"])
        self.assertIn('  - "IP-CIDR,203.0.113.0/24,no-resolve"\n', generated_text(out["fin.yaml"]))
        self.assertIn("IP-CIDR,203.0.113.0/24,LIST,no-resolve\n", out["fin-qx.txt"])
        self.assertEqual(skipped.get("fin-qx.txt:IP-CIDR", 0), 0)
        self.assertTrue(all("unsafe.example.com" not in body for body in out.values()))
        self.assertEqual(skipped["fin.txt:DOMAIN-SUFFIX"], 1)


class GeneratedRecordFormatTests(unittest.TestCase):
    @staticmethod
    def record(rule):
        return [rule.kind, rule.value, list(rule.options), rule.allow, rule.literal_process,
                rule.native_fields, rule.domain_source]

    def test_domain_process_regex_and_qx_interface_collisions_keep_every_identity(self):
        from rules import parse

        domain = Rule('DOMAIN', 'keep.example.org')
        domain_regex = Rule('DOMAIN-REGEX', expected_domain('DOMAIN', domain.value).split(',', 1)[1])
        process = Rule('PROCESS-NAME', 'FooApp')
        process_regex = Rule('PROCESS-NAME-REGEX', expected_process(process.value).split(',', 1)[1])
        qx, messages = parse('HOST,keep.example.org,LIST,via-interface=en1\n', purpose='proxy')
        self.assertEqual(messages, [])
        native = Rule('DOMAIN', 'keep.example.org', domain_source='mihomo')
        originals = [domain, domain_regex, process, process_regex, *qx, native]
        expected = {
            expected_domain('DOMAIN', domain.value): [self.record(domain), self.record(domain_regex)],
            expected_process(process.value): [self.record(process), self.record(process_regex)],
            'DOMAIN,keep.example.org': [self.record(native), self.record(qx[0])],
        }
        output, skipped = render_configured('public', originals * 2, purpose='proxy', no_resolve='keep')
        self.assertEqual(output['fin.yaml'].splitlines()[0], '# public rules: 3')
        for line in output['fin.yaml'].splitlines()[2:]:
            payload = generated_payload(line[4:])
            generated_payload(line[4:], expected[payload])
        restored, messages = parse(output['fin.yaml'], purpose='proxy')
        self.assertEqual(messages, [])
        self.assertEqual(set(restored), set(originals))
        self.assertEqual(len(restored), len(originals))
        repeated, repeated_skips = render_configured('public', restored * 2, purpose='proxy', no_resolve='keep')
        self.assertEqual(repeated, output)
        self.assertEqual(repeated_skips, skipped)

    def test_native_unicode_controls_quotes_backslashes_and_inner_markers_have_exact_records(self):
        from rules import parse

        for value in ('中文', 'ΟΣ', 'οσ', 'ος', 'ΑΟΣ', 'ΟΣΑ', '𠀀🙂', 'a\tb', 'a\0\nb',
                      'a"b', "a'b", 'a\\b', 'a # rconvert-rule-v1 []', 'a\x85b', 'a b', 'a￾b'):
            original = Rule('DOMAIN-KEYWORD', value, domain_source='mihomo')
            for logical in (False, True):
                rule = (Rule('AND', '((DOMAIN-KEYWORD,' + value + '),(NETWORK,tcp))',
                             native_fields=True, domain_source='mihomo') if logical else original)
                with self.subTest(value=value, logical=logical):
                    out, _ = render_configured('public', [rule], purpose='proxy', no_resolve='keep')
                    line, = out['fin.yaml'].split('\n')[2:-1]
                    generated_payload(line[4:], [self.record(rule)])
                    comment = line.partition(' # rconvert-rule-v1 ')[2]
                    self.assertTrue(comment.isascii())
                    self.assertEqual(parse(out['fin.yaml'], purpose='proxy'), ([rule], []))
                    repeated, _ = render_configured('public', [rule], purpose='proxy', no_resolve='keep')
                    self.assertEqual(repeated, out)

    def test_restoration_binding_does_not_authenticate_legal_same_payload_records(self):
        from rules import parse

        native = Rule('DOMAIN', 'keep.example.org', domain_source='mihomo')
        out, _ = render_configured('public', [native], purpose='proxy', no_resolve='keep')
        changed = out['fin.yaml'].replace('"mihomo"', '"qx"')
        self.assertEqual(parse(changed, purpose='proxy'),
                         ([Rule('DOMAIN', 'keep.example.org', domain_source='qx')], []))
        legacy = generated_text(out['fin.yaml'])
        self.assertEqual(parse(legacy, purpose='proxy'), ([native], []))
