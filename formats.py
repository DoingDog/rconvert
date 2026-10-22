import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from functools import cache
from fnmatch import fnmatchcase
from collections import Counter
from collections.abc import Iterable
from bisect import bisect_right

from _unicode15 import _GO15_LOWER, _GO15_ND, _GO15_NONLETTER_WORD
from rules import (Rule, NO_RESOLVE_TYPES, _REGEX, _QX_INTERFACE_OPTIONS, _apply_no_resolve, _capture_number, _delimiters,
                   _field_value, _fields, _has_parent, _hex_codepoint, _logical_children, _REGEXP2_WORD_BOUNDARIES, _valid_deep_regex, _valid_domain,
                   _valid_name_list, _valid_regex, exclude_covered)


FILES = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")
DOMAIN_SET_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
SURGE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN", "USER-AGENT", "URL-REGEX",
    "PROCESS-NAME", "DEST-PORT", "DST-PORT", "SRC-PORT", "IN-PORT",
    "SRC-IP", "SRC-IP-CIDR", "DEVICE-NAME", "MAC-ADDRESS", "PROTOCOL",
    "HOSTNAME-TYPE", "SUBNET", "CELLULAR-RADIO", "CELLULAR-CARRIER",
    "AND", "OR", "NOT",
}
MIHOMO_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX",
    "GEOSITE", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP",
    "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR", "SRC-IP-SUFFIX",
    "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
    "REMATCH-NAME", "PROCESS-PATH", "PROCESS-PATH-WILDCARD", "PROCESS-PATH-REGEX",
    "PROCESS-NAME", "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "UID",
    "NETWORK", "DSCP", "AND", "OR", "NOT",
}
QX_TYPES = {
    "DOMAIN": "HOST", "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD", "DOMAIN-WILDCARD": "HOST-WILDCARD",
    "IP-CIDR": "IP-CIDR", "IP-CIDR6": "IP6-CIDR",
    "USER-AGENT": "USER-AGENT", "IP-ASN": "IP-ASN", "GEOIP": "GEOIP",
}
SURGE_ALIASES = {"SRC-IP-CIDR": "SRC-IP", "DST-PORT": "DEST-PORT", "PROCESS-NAME-WILDCARD": "PROCESS-NAME", "PROCESS-PATH": "PROCESS-NAME", "PROCESS-PATH-WILDCARD": "PROCESS-NAME"}
LOGICAL = {"AND", "OR", "NOT"}
_DNS_LINE_LIMIT = 65536
_DNS_BYTE_TOKEN = r'''(?:[^\\]|\\[. '@;()"\\]|\\[0-9]{3})'''
# regexp2 类外 Unicode 原子在 Go regexp 中的等价集合。
_DNS_UNICODE_ATOMS = {
    "d": r"\p{Nd}", "D": r"\P{Nd}",
    "w": r"[\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]",
    "W": r"[^\p{L}\p{Mn}\p{Nd}\p{Pc}\x{200C}\x{200D}]",
    "s": r"[\x09-\x0D\x{85}\p{Z}]",
    "S": r"[^\x09-\x0D\x{85}\p{Z}]",
}


def _surge_value(value: str, *, source_regex: bool = False, quote_parentheses: bool = False) -> str:
    trailing_escape = (len(value) - len(value.rstrip("\\"))) % 2
    if (value == value.strip() and "," not in value and not value.startswith(("'", '"')) and not trailing_escape and
            not re.search(r"\s(?:[#;]|//)", value) and
            not (quote_parentheses and any(char in value for char in '()'))):
        return value
    if "'" not in value and not trailing_escape:
        return f"'{value}'"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _domain_value(kind: str, value: str, source: str, supported: set[str]) -> tuple[str, str | None]:
    if kind in DOMAIN_SET_TYPES and source == 'mihomo' and supported is SURGE_TYPES:
        return kind, None
    if kind not in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}:
        return kind, value
    if supported is SURGE_TYPES:
        if source == "mihomo":
            if (re.search(r"[a-z]", value, re.I) or
                    kind == "DOMAIN-WILDCARD" and any(c in value for c in "[]") or
                    kind == "DOMAIN-KEYWORD" and value.endswith(".")):
                return kind, None
            if kind == "DOMAIN-WILDCARD":
                # 尾星号仅在最后必要 token 为非点字面字符时吸收 hostname 根点。
                if not value.endswith("*") or value.rstrip("*").endswith((".", "?")):
                    return kind, None
                # 一个 ? 与星号的连续片段只要求非空，UTF-8 byte 与字符匹配等价。
                if any("?" in part and ("*" not in part or part.count("?") != 1)
                       for part in re.findall(r"[?*]+", value)):
                    return kind, None
    elif supported is MIHOMO_TYPES and source == "surge":
        if kind == "DOMAIN-KEYWORD":
            # Surge 忽略 hostname 末尾根点；keyword 的末尾点必须位于 hostname 内部。
            return "DOMAIN-REGEX", re.escape(value.lower()) + (r"(?=.)" if value.endswith(".") else "")
        value = value.lower().removesuffix(".")
        pattern = _wildcard_regex(value)
        # 最后必要的点或 ? 不能依靠 hostname 根点满足。
        boundary = r"(?<!\.)" if value.rstrip("*").endswith((".", "?")) else ""
        return "DOMAIN-REGEX", pattern[:-1] + boundary + r"\.?$" if pattern is not None else None
    return kind, value


# 固定 Go Unicode 15.0.0 的 CaseRanges 与 caseOrbit 非自身映射（含 U+00DF）。
# 区间外 scalar 的 SimpleFold 与 ToLower 均保持自身，不依赖 Python UCD。
_PROCESS_CASE_VARIANTS = re.compile(
    r"["
    r"A-Za-zµÀ-ÖØ-öø-ķĹ-ň"
    r"Ŋ-ƌƎ-ƚƜ-ƩƬ-ƹƼ-ƽƿǄ-ǯ"
    r"Ǳ-ȠȢ-ȳȺ-ɔɖ-ɗəɛ-ɜɠ-ɡɣ"
    r"ɥ-ɦɨ-ɬɯɱ-ɲɵɽʀʂ-ʃʇ-ʌ"
    r"ʒʝ-ʞͅͰ-ͳͶ-ͷͻ-ͽͿΆΈ-Ί"
    r"ΌΎ-ΏΑ-ΡΣ-ία-ϑϕ-ϵϷ-ϻ"
    r"Ͻ-ҁҊ-ԯԱ-Ֆա-ֆႠ-ჅჇჍა-ჺ"
    r"ჽ-ჿᎠ-Ᏽᏸ-ᏽᲀ-ᲈᲐ-ᲺᲽ-Ჿᵹᵽ"
    r"ᶎḀ-ẕẛẞẠ-ἕἘ-Ἕἠ-ὅὈ-Ὅὑ"
    r"ὓὕὗὙὛὝὟ-ώᾀ-ᾱᾳᾸ-ᾼι"
    r"ῃῈ-ῌῐ-ῑῘ-Ίῠ-ῡῥῨ-Ῥῳ"
    r"Ὸ-ῼΩK-ÅℲⅎⅠ-ⅿↃ-ↄⒶ-ⓩ"
    r"Ⰰ-ⱰⱲ-ⱳⱵ-ⱶⱾ-ⳣⳫ-ⳮⳲ-ⳳ"
    r"ⴀ-ⴥⴧⴭꙀ-ꙭꚀ-ꚛꜢ-ꜯꜲ-ꝯꝹ-ꞇ"
    r"Ꞌ-ꞍꞐ-ꞔꞖ-ꞮꞰ-ꟊꟐ-ꟑꟖ-ꟙ"
    r"Ꟶ-ꟶꭓꭰ-ꮿＡ-Ｚａ-ｚ\U00010400-\U0001044f"
    r"\U000104b0-\U000104d3\U000104d8-\U000104fb\U00010570-\U0001057a\U0001057c-\U0001058a"
    r"\U0001058c-\U00010592\U00010594-\U00010595\U00010597-\U000105a1\U000105a3-\U000105b1"
    r"\U000105b3-\U000105b9\U000105bb-\U000105bc\U00010c80-\U00010cb2\U00010cc0-\U00010cf2"
    r"\U000118a0-\U000118df\U00016e40-\U00016e7f\U0001e900-\U0001e943"
    r"]"
)


def _go_lower(value: str) -> str:
    def lower(match):
        point = ord(match[0])
        position = bisect_right(_GO15_LOWER, (point, 0x110000, 0x110000, 0x110000)) - 1
        if position >= 0:
            start, end, stride, delta = _GO15_LOWER[position]
            if point <= end and (point - start) % stride == 0:
                return chr(point + delta)
        return match[0]

    return _PROCESS_CASE_VARIANTS.sub(lower, value)


def _process_value(kind: str, value: str, supported: set[str], literal_process: bool) -> tuple[str, str | None]:
    process_types = {"PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"}
    if kind not in process_types:
        return kind, value
    surge_source = kind == "PROCESS-NAME" and not literal_process
    wildcard = any(char in value for char in "*?")
    if supported is SURGE_TYPES:
        # ToLower 的 U+0131 与 SimpleFold 的两个 I-dot 字符分别保持自身。
        case_value = value.translate({0x131: None} if kind.endswith('-WILDCARD') else {0x130: None, 0x131: None})
        if not surge_source and (wildcard or _PROCESS_CASE_VARIANTS.search(case_value)
                                 or kind.startswith("PROCESS-PATH") and (not value.startswith("/") or value.endswith("/"))
                                 or kind.startswith("PROCESS-NAME") and value.startswith("/")):
            return kind, None
        return "PROCESS-NAME", value
    if surge_source:
        # Surge glob 的字符范围尚未核实；literal exact/prefix 使用 regexp2 严格锚点。
        if wildcard:
            return kind, None
        kind = "PROCESS-PATH-REGEX" if value.startswith("/") else "PROCESS-NAME-REGEX"
        literal = "".join(r"\x{" + f"{ord(char):X}" + "}" for char in value)
        end = "" if value.startswith("/") and value.endswith("/") else r"\z"
        return kind, r"(?-i:\A" + literal + end + ")"
    if value != value.strip(' '):
        return kind, None
    return kind, value


def _yaml_value(value: str) -> str:
    # 保持 JSON 可解码，转义 YAML 的分行/C1/非字符边界，并保留完整 non-BMP scalar。
    return re.sub(r"[\x7f-\x9f\u2028\u2029\ufffe\uffff]",
                  lambda match: f"\\u{ord(match[0]):04x}", json.dumps(value, ensure_ascii=False))


_LINE_UNSAFE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029\ufffe\uffff]")


def _qx_field_supported(kind: str, value: str) -> bool:
    return (kind in QX_TYPES and ',' not in value and
            value == value.strip() and not value.startswith(("'", '"')) and
            not (kind == 'USER-AGENT' and ((len(value) - len(value.rstrip('\\'))) % 2 or
                                          re.search(r'\s(?:[#;]|//)', value))) and
            not (kind == 'DOMAIN-WILDCARD' and any(char in value for char in '[]')))


def _logical_regex_value(value: str, *, logical: bool = True) -> str | None:
    # 复用 lexer 编码会被字段 trim 的字面逗号；逻辑内同时保护字面括号。
    prefix = '(DOMAIN-REGEX,(?:)'
    expression, edits = prefix + value + ')', []
    try:
        list(_delimiters(expression, regex_edits=edits if logical else None, regex_commas=edits))
    except ValueError:
        return None
    parts, cursor = [], len(prefix)
    for start, stop, replacement in sorted(edits):
        parts.extend((expression[cursor:start], replacement))
        cursor = stop
    parts.append(expression[cursor:-1])
    # 空 group 保护字段边缘的 ASCII space，不改变 extended mode 的空格语义。
    return ('(?:)' if value.startswith(' ') else '') + ''.join(parts) + ('(?:)' if value.endswith(' ') else '')


def _logical_value(value: str, operator: str, supported: set[str],
                   literal_process: bool = False, native_fields: bool = False,
                   domain_source: str = "surge") -> str | None:
    expression = f"({operator},{value})"
    groups, commas = {}, {} if native_fields else None
    try:
        list(_delimiters(expression, native_fields=native_fields, groups=groups, commas=commas))
    except ValueError:
        return None
    pending, edits = [(0, len(expression), 0)], []
    trim = ' ' if native_fields else None
    while pending:
        begin, end, depth = pending.pop()
        if expression[begin:begin + 1] != '(' or expression[end - 1:end] != ')':
            return None
        comma = expression.find(',', begin + 1, end - 1)
        if comma < 0:
            return None
        kind = expression[begin + 1:comma].strip(trim).upper()
        if kind in LOGICAL:
            if supported is SURGE_TYPES and depth >= 10:
                return None
            start, stop = comma + 1, end - 1
            while start < stop and (expression[start] == ' ' if native_fields else expression[start].isspace()):
                start += 1
            while stop > start and (expression[stop - 1] == ' ' if native_fields else expression[stop - 1].isspace()):
                stop -= 1
            children = _logical_children(expression, kind, begin, start, stop, groups, commas)
            if children is None or kind not in supported:
                return None
            ranges, wrapped = children
            if supported is SURGE_TYPES and kind != 'NOT' and len(ranges) < 2:
                return None
            if kind == 'NOT' and not wrapped:
                edits.extend(((start, start, '('), (stop, stop, ')')))
            pending.extend((begin, end, depth + 1) for begin, end in reversed(ranges))
            continue
        try:
            fields = _fields(expression[begin + 1:end - 1], native_fields=native_fields)
        except ValueError:
            return None
        if len(fields) < 2:
            return None
        kind, payload, *options = fields
        kind = kind.upper()
        if not native_fields and options and (kind not in NO_RESOLVE_TYPES or
                                              any(option.lower() != 'no-resolve' for option in options)):
            return None
        if not native_fields:
            payload = _field_value(payload)
        if (not _valid_name_list(payload) if kind in {'IN-NAME', 'IN-USER', 'REMATCH-NAME'}
                else not payload.strip(' ' if kind in {'UID', 'DSCP'} else trim)):
            return None
        if kind in {'UID', 'DSCP'}:
            payload = payload.replace(',', '/')
        kind, payload = _domain_value(kind, payload, domain_source, supported)
        if payload is None:
            return None
        kind, payload = _process_value(kind, payload, supported, literal_process)
        if payload is None:
            return None
        if supported is SURGE_TYPES:
            if _LINE_UNSAFE.search(payload):
                return None
            if kind == 'NETWORK' and payload.upper() in {'TCP', 'UDP'}:
                kind, payload = 'PROTOCOL', payload.upper()
            kind = SURGE_ALIASES.get(kind, kind)
            # 条件内的字面括号需要字段引用，防止参与逻辑包装。
            payload = _surge_value(payload, quote_parentheses=True)
        else:
            # Surge UNKNOWN 匹配数据库无结果，Mihomo 的同名 payload 只作字符串比较。
            if kind in {'IP-ASN', 'GEOIP'} and payload.upper() == 'UNKNOWN':
                return None
            if kind == 'DEST-PORT':
                kind = 'DST-PORT'
            elif kind == 'SRC-IP':
                try:
                    network = ipaddress.ip_network(payload, strict=False)
                except ValueError:
                    return None
                kind, payload = 'SRC-IP-CIDR', str(network)
            elif kind == 'PROTOCOL' and payload.upper() in {'TCP', 'UDP'}:
                kind, payload = 'NETWORK', payload.lower()
            if kind in _REGEX and not native_fields:
                payload = _logical_regex_value(payload)
                if payload is None:
                    return None
            if kind not in _REGEX and ',' in payload:
                return None
            if native_fields and kind not in _REGEX and options and any(char in payload for char in '()'):
                payload += ',' + ','.join(options)
            if kind not in _REGEX:
                try:
                    list(_delimiters(payload, native_fields=True))
                except ValueError:
                    return None
        if kind == 'IP-CIDR' and ':' in payload:
            kind = 'IP-CIDR6'
        if kind not in supported:
            return None
        if kind in NO_RESOLVE_TYPES and any(option.lower() == 'no-resolve' for option in options):
            payload += ',no-resolve'
        edits.append((begin, end, f'({kind},{payload})'))
    parts, cursor = [], 0
    for start, stop, text in sorted(edits):
        parts.extend((expression[cursor:start], text))
        cursor = stop
    parts.append(expression[cursor:])
    return ''.join(parts)[len(operator) + 2:-1]


def _wildcard_regex(value: str) -> str | None:
    if not _valid_domain("DOMAIN-WILDCARD", value):
        return None
    parts = re.split(r"(\[[a-z0-9-]+\])", value)
    if any("[" in part or "]" in part for part in parts[::2]):
        return None
    for part in parts[1::2]:
        if "--" in part:
            return None
        try:
            re.compile(part)
        except re.error:
            return None
    return "^" + "".join(
        part if index % 2 else re.escape(part).replace(r"\*", ".*").replace(r"\?", ".")
        for index, part in enumerate(parts)
    ) + "$"


def _dns_join(parts: Iterable[str | None], budget: int, *, separator: str = '') -> str | None:
    values = []
    separator_size = len(separator.encode('utf-8'))
    for part in parts:
        if part is None:
            return None
        budget -= len(part.encode('utf-8')) + (separator_size if values else 0)
        if budget < 0:
            return None
        values.append(part)
    return separator.join(values)


def _dns_literal(value: str, budget: int, *, presentation: bool = False) -> str | None:
    def parts():
        for char in value:
            if not presentation or char == '.':
                yield re.escape(char).replace('=', r'\x{3D}')
                continue
            for byte in char.encode('utf-8'):
                text = chr(byte)
                if text in ''' '@;()"\\''':
                    text = '\\' + text
                elif not 0x21 <= byte <= 0x7E:
                    text = '\\' + f'{byte:03d}'
                yield re.escape(text).replace('=', r'\x{3D}')
    return _dns_join(parts(), budget)


def _native_wildcard_regex(value: str, budget: int) -> str | None:
    prefix, suffix = r'(?s-i:\A', r'\z)'
    body_budget = budget - len(prefix) - len(suffix)
    if value and not value.strip('*'):
        body = _dns_join(('.*',), body_budget)
    else:
        body = _dns_join((_DNS_BYTE_TOKEN + '*' if char == '*' else _DNS_BYTE_TOKEN if char == '?' else
                          _dns_literal(char, body_budget, presentation=True) for char in value), body_budget)
    return _dns_join((prefix, body, suffix), budget)


def _dns_pattern(rule: Rule, *, exception: bool = False) -> str | None:
    if rule.domain_source == 'mihomo':
        if rule.kind in DOMAIN_SET_TYPES:
            return None
        if rule.kind in {'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'}:
            value = _go_lower(rule.value)
            if re.search(r'[A-Za-z]', value):
                return None
            if rule.kind == 'DOMAIN-KEYWORD' and value.endswith('.'):
                return None
            if rule.kind == 'DOMAIN-WILDCARD':
                universal = set(value) <= {'*', '?'} and value.count('?') == 1 and '*' in value
                if (any(char in value for char in '[]') or
                        not universal and (not value.endswith('*') or value.rstrip('*').endswith(('.', '?')))):
                    return None
    budget = _DNS_LINE_LIMIT - 1 - (2 if exception else 0)
    parts = ('|', rule.value, '|') if exception and rule.kind == 'DOMAIN' and '_' not in rule.value else (_dns_body(rule, budget),)
    return _dns_join(parts, budget)


def _dns_body(rule: Rule, budget: int) -> str | None:
    if rule.kind == "DOMAIN":
        if '_' in rule.value:
            return _dns_join((r'/(?s-i:\A', _dns_literal(_go_lower(rule.value), budget), r'\z)/'), budget)
        return _dns_join(('0.0.0.0 ', _go_lower(rule.value)), budget)
    if rule.kind == "DOMAIN-SUFFIX":
        return _dns_join(('||', rule.value, '^'), budget)
    if "/" in rule.value:
        return None
    if rule.kind in {'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'} and rule.domain_source == 'mihomo':
        value = _go_lower(rule.value)
        if rule.kind == 'DOMAIN-KEYWORD':
            prefix, suffix = r'/(?s-i:\A' + _DNS_BYTE_TOKEN + '*', _DNS_BYTE_TOKEN + r'*\z)/'
            return _dns_join((prefix, _dns_literal(value, budget - len(prefix) - len(suffix), presentation=True), suffix), budget)
        if not _valid_domain(rule.kind, value, domain_source=rule.domain_source):
            return None
        return _dns_join(('/', _native_wildcard_regex(value, budget - 2), '/'), budget)
    if rule.kind == "DOMAIN-KEYWORD":
        return _dns_join(('/^.*', _dns_literal(rule.value, budget), '.*$/'), budget)
    if rule.kind == "DOMAIN-WILDCARD":
        if rule.domain_source != "surge" and any(char in rule.value for char in "[]"):
            return None
        pattern = _wildcard_regex(rule.value)
        return f"/{pattern}/" if pattern is not None else None
    if rule.kind == "DOMAIN-REGEX":
        return _dns_regex(rule.value, budget)
    return None


def _dns_regex(value: str, budget: int, *, encoded: bool = False) -> str | None:
    if not encoded and not _valid_regex('DOMAIN-REGEX', value):
        return None
    templates = {}
    if not encoded:
        prefix, groups = '(DOMAIN-REGEX,(?:)', {}
        try:
            list(_delimiters(prefix + value + ')', groups=groups))
        except ValueError:
            return None
        for start, stop in groups.items():
            start, stop = start - len(prefix), stop - len(prefix)
            if start < 0:
                continue
            if value.startswith('(?-i:', start):
                candidate = value[start:stop + 1]
                paired = _paired_domain(Rule('DOMAIN-REGEX', candidate))
                if paired is not None and paired[0] == 'DOMAIN':
                    templates[start] = stop, 'paired', paired[1]
            elif value.startswith(r'(?i:(?:\A|\.)', start):
                candidate = value[start:stop + 1]
                literal = candidate[13:-6].replace(r'\.', '.').replace(r'\-', '-')
                if (literal.isascii() and not literal.endswith('.') and _valid_domain('DOMAIN-SUFFIX', literal) and
                        candidate == r'(?i:(?:\A|\.)' + re.escape(literal) + r'\.?\z)'):
                    templates[start] = stop, 'suffix', literal
    paired_exact = False
    paired_groups = [False]
    translated = []
    replacements = []
    index = 0
    in_class = False
    class_start = 0
    # 节点记录重复次数、高度、operator、FoldCase、前缀摘要、提取后高度、marker、size 和 marker cost。
    repeat_groups = [([], [], [0])]
    # urlfilter 无 match-case modifier 时在表达式前添加 (?i)。
    fold_groups = [not encoded]
    dns_groups = [([], [])]
    dns_sizes = [0]
    repeat_end = -1
    capture_replacements = []
    branch_replacements = []
    max_size = (128 << 20) // 40
    folded_runes = {}

    def literal_identity(char, folded):
        if not folded or char in 'İı' or not _PROCESS_CASE_VARIANTS.fullmatch(char):
            return char
        lower = _go_lower(char)
        fold = char.casefold()
        variants = (char, lower, char.upper(), fold, fold.upper())
        return min([part for part in variants if len(part) == 1] +
                   (['µ'] if fold == 'μ' else ['ͅ'] if fold == 'ι' else ['ᲈ'] if fold == 'ꙋ' else []))

    def class_runes(node):
        if node[2] != 1:
            return None
        char = node[4]
        runes = {char}
        if node[3] and char not in 'İı' and _PROCESS_CASE_VARIANTS.fullmatch(char):
            if char in folded_runes:
                return folded_runes[char]
            # 固定 Go caseOrbit 的额外成员，其余成员由单字符 case mapping 给出。
            variants = (char.lower(), char.upper(), char.title(), char.casefold(),
                        'µ', 'ſ', 'ǅ', 'ǈ', 'ǋ', 'ǲ', 'ͅ', 'ς', 'ϐ', 'ϑ', 'ϕ', 'ϖ', 'ϰ', 'ϱ', 'ϴ', 'ϵ',
                        'ᲀ', 'ᲁ', 'ᲂ', 'ᲃ', 'ᲄ', 'ᲅ', 'ᲆ', 'ᲇ', 'ᲈ', 'ẛ', 'ẞ', 'ι', 'Ω', 'K', 'Å')
            identity = literal_identity(char, True)
            runes.add(identity)
            runes.update(part for part in variants if len(part) == 1 and
                         literal_identity(part, True) == identity)
            folded_runes[char] = frozenset(runes)
        return frozenset(runes)

    def clean_ranges(ranges):
        result = []
        for start, end in sorted(ranges):
            if result and start <= result[-1][1] + 1:
                result[-1] = result[-1][0], max(end, result[-1][1])
            else:
                result.append((start, end))
        return tuple(result)

    def negate_ranges(ranges):
        result, start = [], 0
        for left, right in ranges:
            if start < left:
                result.append((start, left - 1))
            start = right + 1
        if start <= 0x10FFFF:
            result.append((start, 0x10FFFF))
        return tuple(result)

    @cache
    def folding_runes():
        # 固定 Go minFold/maxFold；一次读取现有 case 集合，不随输入的最大码点扫描。
        return _PROCESS_CASE_VARIANTS.findall(''.join(map(chr, range(0x41, 0x1E944))))

    @cache
    def folded_range(start, end):
        if start == end:
            return clean_ranges((ord(char), ord(char)) for char in class_runes((1, 1, 1, True, chr(start))))
        ranges = [(start, end)]
        if end >= 0x41 and start <= 0x1E943 and not (start <= 0x41 and end >= 0x1E943):
            for char in folding_runes():
                if start <= ord(char) <= end:
                    ranges.extend((ord(part), ord(part)) for part in class_runes((1, 1, 1, True, char)))
        return clean_ranges(ranges)

    @cache
    def unicode_ranges(kind):
        if kind == 'w':
            return tuple((start, end - 1) for start, end in zip(_REGEXP2_WORD_BOUNDARIES[::2], _REGEXP2_WORD_BOUNDARIES[1::2]))
        if kind == 's':
            return ((9, 13), (32, 32), (0x85, 0x85), (0xA0, 0xA0), (0x1680, 0x1680),
                    (0x2000, 0x200A), (0x2028, 0x2029), (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000))
        if kind == 'd':
            return tuple((start, end - 1) for start, end in _GO15_ND)
        ranges, position = [], 0
        for start, end in unicode_ranges('w'):
            while position < len(_GO15_NONLETTER_WORD) and _GO15_NONLETTER_WORD[position][1] <= start:
                position += 1
            cursor = start
            while position < len(_GO15_NONLETTER_WORD) and _GO15_NONLETTER_WORD[position][0] <= end:
                left, right = _GO15_NONLETTER_WORD[position]
                if cursor < left:
                    ranges.append((cursor, left - 1))
                cursor = max(cursor, right)
                if right > end:
                    break
                position += 1
            if cursor <= end:
                ranges.append((cursor, end))
        return tuple(ranges)

    def class_node(identity, folded=True):
        ranges = identity[1]
        count = sum(end - start + 1 for start, end in ranges)
        if count == 1:
            return 1, 1, 1, False, chr(ranges[0][0]), 1, (), 1, 0
        if count == 2:
            runes = (chr(ranges[0][0]), chr(ranges[-1][1]))
            if folded and len({literal_identity(char, True) for char in runes}) == 1:
                return 1, 1, 1, True, runes[0], 1, (), 1, 0
        if ranges in (((0, 0x10FFFF),), ((0, 9), (11, 0x10FFFF))):
            folded = None
        return 1, 1, 'class', folded, identity, 1, (), 1, 0

    def class_union(nodes):
        ranges = []
        operator, folded = nodes[0][2:4]
        for position, node in enumerate(nodes):
            if node[2] == 1:
                ranges.extend((ord(char), ord(char)) for char in class_runes(node))
            else:
                ranges.extend(node[4][1])
                # Go merge 保留目标 flags；class 优先于 literal，AnyChar 不比较 FoldCase。
                if operator == 1 or node[3] is None:
                    folded = node[3]
            if position:
                operator = 'class'
        return class_node(('runes', clean_ranges(ranges)), folded)

    # 移除前缀后，单个 alternate 尾节点仍需参与同类分支展开。
    def leading(node):
        if node[2] == 'concat' or node[2] == 'alternate' and node[4] is not None:
            return node[4]
        if node[4] is not None and (isinstance(node[2], int) and node[2] > 0 or
                                   node[2] in {'class', 'class-repeat'}):
            return (((node[2], node[3], node[4], node[1], node[7]),), 0, 0, False)
        return (), node[5], 1, node[2] == 'alternate'

    def suffix_height(prefix, tail):
        count = len(prefix) + tail[1]
        return max([part[3] for part in prefix] + [tail[0]]) + (count > 1) if count else 1

    def group_bounds(group):
        nodes, branches, starts = group
        merged = []
        for part in nodes:
            literal = isinstance(part[2], int) and part[2] > 0
            if (merged and literal and isinstance(merged[-1][2], int) and
                    merged[-1][2] > 0 and part[3] == merged[-1][3]):
                merged[-1][2] += part[2]
                merged[-1][4].append(part[4])
                merged[-1][7] += part[7]
            else:
                merged.append([*part[:4], [part[4]] if literal else part[4], *part[5:]])
        nodes = [(*part[:4], ''.join(part[4]) if isinstance(part[2], int) and part[2] > 0 else part[4],
                  *part[5:]) for part in merged]
        if not nodes:
            node = (1, 1, 0, None, None, 1, (), 1, 0)
        elif len(nodes) == 1:
            node = nodes[0]
        else:
            prefix, tail_factored, tail_count, tail_alternate = [], 0, 0, False
            for part in nodes:
                tokens, factored, count, alternate = leading(part)
                if not tail_count:
                    prefix.extend(tokens)
                    tail_factored, tail_count, tail_alternate = factored, count, alternate
                else:
                    tail_factored = max(tail_factored, part[5] - (
                        part[2] == 'concat' or part[2] == 'alternate' and part[4] is not None))
                    tail_count += len(tokens) + count
                    tail_alternate = False
            node = (max(part[0] for part in nodes),
                    1 + max(part[1] - (part[2] == 'concat') for part in nodes), 'concat', None,
                    (tuple(prefix), tail_factored, tail_count, tail_alternate),
                    1 + max(part[5] - (part[2] == 'concat' or part[2] == 'alternate' and part[4] is not None)
                            for part in nodes),
                    tuple(marker for part in nodes for marker in part[6]),
                    sum(part[7] for part in nodes), sum(part[8] for part in nodes))
        if branches:
            entries = []
            for part, start in [*branches, (node, starts[-1])]:
                if entries and part[2] == entries[-1][0][2] == 0:
                    continue
                entries.append((part, start))
            if len(entries) == 1:
                return entries[0][0]
            nodes = [part for part, _ in entries]
            if all(part[2] == 1 and part[3:5] == nodes[0][3:5] for part in nodes):
                return nodes[0]
            if all(part[2] == 1 or part[2] == 'class' for part in nodes):
                return class_union(nodes)
            markers = []
            height = 1 + max(part[1] - (part[2] == 'alternate') for part in nodes)
            rows = []
            for part, start in entries:
                tokens, *tail = leading(part)
                rows.append((list(tokens), tail, part[7], (start,), part[2] == 'alternate' and part[4] is None))
            result = []
            pending = [('visit', rows, result)]
            # 对完整连续分支组缩短前缀，再处理剩余分支；显式列表保持非递归。
            while pending:
                action, data, destination = pending.pop()
                if action == 'concat':
                    prefix, suffix = data
                    ending = suffix[0]
                    tokens, _, tail_count, _ = ending[4]
                    summary = ((prefix, *tokens), 0, 0, False) if len(tokens) == 1 and not tail_count else (
                        (prefix,), ending[0], 1, ending[2])
                    destination.append((1 + max(prefix[3], ending[0]), prefix[4] + ending[1], False, None, summary))
                    continue
                if action == 'alternate':
                    reduced = []
                    for part in (slot[0] for slot in data):
                        if reduced and part[3] is not None and reduced[-1][3] == part[3]:
                            summary = ((), 0, 0, False)
                            if part[3] == 'class':
                                tokens = [reduced[-1][4][0][0], part[4][0][0]]
                                if tokens[0][:3] == tokens[1][:3]:
                                    token = tokens[0]
                                else:
                                    # Go factor 第三轮选择 operator 和 Rune 数组最复杂的合并目标。
                                    tokens.sort(key=lambda token: (token[0] == 'class', token[1] is None,
                                                                  len(token[2][1]) if token[0] == 'class' else 1), reverse=True)
                                    union = class_union([(1, token[3], *token[:3]) for token in tokens])
                                    token = (*union[2:5], 1, 1)
                                summary = ((token,), 0, 0, False)
                            reduced[-1] = (1, 1, False, part[3], summary)
                        else:
                            reduced.append(part)
                    alternate_height = 1 + max(part[0] - part[2] for part in reduced)
                    destination.append(reduced[0] if len(reduced) == 1 else
                                       (alternate_height, sum(part[1] for part in reduced) + len(reduced) - 1,
                                        True, None, ((), alternate_height, 1, True)))
                    continue
                output, actions, position = [], [], 0
                while position < len(data):
                    tokens, tail, item_size, _, alternate = data[position]
                    first = tokens[0] if tokens else None
                    stop, prefix = position + 1, first
                    while first is not None and stop < len(data) and data[stop][0]:
                        second = data[stop][0][0]
                        if isinstance(first[0], int) and isinstance(second[0], int) and first[1] == second[1]:
                            count = 0
                            while count < min(len(prefix[2]), len(second[2])) and prefix[2][count] == second[2][count]:
                                count += 1
                            if not count:
                                break
                            prefix = (count, first[1], prefix[2][:count], first[3], count)
                        elif first[:3] != second[:3]:
                            break
                        stop += 1
                    slot = []
                    output.append(slot)
                    if stop == position + 1:
                        atom = ('class' if not tail[1] and len(tokens) == 1 and tokens[0][0] in {1, 'class'} else
                                'empty' if not tail[1] and not tokens else None)
                        slot.append((suffix_height(tokens, tail), item_size,
                                     tail[2] if not tokens and tail[1] == 1 else alternate, atom,
                                     (tuple(tokens), *tail)))
                    else:
                        suffix_rows = []
                        for rest, ending, old_size, starts, _ in data[position:stop]:
                            atom, *remaining = rest
                            if isinstance(prefix[0], int) and len(prefix[2]) < len(atom[2]):
                                count = len(prefix[2])
                                remaining.insert(0, (len(atom[2]) - count, atom[1], atom[2][count:], atom[3], atom[4] - count))
                            suffix_rows.append((remaining, ending, max(1, old_size - prefix[4]), starts, False))
                            markers.extend((start, start, '(?:)') for start in starts)
                        suffix = []
                        actions.extend((('visit', suffix_rows, suffix), ('concat', (prefix, suffix), slot)))
                    position = stop
                pending.append(('alternate', output, destination))
                pending.extend(reversed(actions))
            factored, size = result[0][:2]
            markers = tuple(dict.fromkeys(markers)) if factored > height else ()
            savings = sum(part[7] for part in nodes) + len(nodes) - 1 - size
            factored_concat = not result[0][2] and result[0][3] is None
            reduced_concat = factored <= height and factored_concat
            node = (max(part[0] for part in nodes), min(height, factored),
                    'concat' if reduced_concat else 'alternate', None,
                    result[0][4] if factored_concat else None, factored,
                    tuple(marker for part in nodes for marker in part[6]) + markers, size,
                    sum(part[8] for part in nodes) + (savings + len(markers) if markers else 0))
        # 仅当共同前缀提取会越过高度上限时使用零宽组；保留浅层 factoring 的大小归约。
        if node[1] <= 1000 < node[5]:
            branch_replacements.extend(dict.fromkeys(node[6]))
            node = (*node[:4], None if node[2] == 'alternate' else node[4],
                    node[1] if node[6] else node[5], (), node[7] + node[8], 0)
        return node

    def in_ranges(point, ranges):
        position = bisect_right(ranges, (point, 0x110000)) - 1
        return position >= 0 and point <= ranges[position][1]

    def lower_preimage(ranges):
        removed, added = [], []
        for start, end, stride, delta in _GO15_LOWER:
            for point in range(start, end + 1, stride):
                if in_ranges(point, ranges):
                    removed.append((point, point))
                if in_ranges(point + delta, ranges):
                    added.append((point, point))
        excluded = negate_ranges(clean_ranges(removed))
        kept, position = [], 0
        for start, end in ranges:
            while position < len(excluded) and excluded[position][1] < start:
                position += 1
            cursor = position
            while cursor < len(excluded) and excluded[cursor][0] <= end:
                left, right = excluded[cursor]
                kept.append((max(start, left), min(end, right)))
                cursor += 1
        return clean_ranges((*kept, *added))

    def dns_choices(parts):
        parts = list(dict.fromkeys(parts))
        if None in parts:
            return None
        if len(parts) == 1:
            return parts[0]
        return _dns_join(('(?:', _dns_join(parts, budget - 4, separator='|'), ')'), budget)

    def decimal_interval(start, end, width=3):
        if start == end:
            return f'{start:0{width}d}'
        divisor = 10 ** (width - 1)
        first, last = start // divisor, end // divisor
        if first == last:
            return str(first) + decimal_interval(start % divisor, end % divisor, width - 1)
        if start % divisor == 0 and end % divisor == divisor - 1:
            head = str(first) if first == last else '[' + str(first) + '-' + str(last) + ']'
            return head + '[0-9]' * (width - 1)
        parts = [str(first) + decimal_interval(start % divisor, divisor - 1, width - 1)]
        if first + 1 < last:
            parts.append(('[' + str(first + 1) + '-' + str(last - 1) + ']' if first + 2 < last else str(first + 1)) +
                         '[0-9]' * (width - 1))
        parts.append(str(last) + decimal_interval(0, end % divisor, width - 1))
        return dns_choices(parts)

    def byte_interval(start, end):
        parts, literals = [], set()
        for byte in range(max(start, 0x20), min(end, 0x7e) + 1):
            text = chr(byte + 32 if 65 <= byte <= 90 else byte)
            if text in ''' '@;()"\\''':
                parts.append(_dns_literal(text, budget, presentation=True))
            elif text == '.':
                parts.extend((r'\.', r'\\\.'))
            else:
                literals.add(text)
        if literals:
            if len(literals) == 1:
                parts.append(_dns_literal(next(iter(literals)), budget))
            else:
                parts.append('[' + ''.join(re.escape(char).replace('=', r'\x{3D}') for char in sorted(literals)) + ']')
        for left, right in ((start, min(end, 31)), (max(start, 127), end)):
            if left <= right:
                parts.append(_dns_join((r'\\', decimal_interval(left, right)), budget))
        return dns_choices(parts)

    def utf8_interval(first, last):
        if not first:
            return [()]
        if first[0] == last[0]:
            return [((first[0], first[0]), *suffix) for suffix in utf8_interval(first[1:], last[1:])]
        width = len(first) - 1
        parts = [((first[0], first[0]), *suffix) for suffix in
                 utf8_interval(first[1:], bytes([191]) * width)]
        if first[0] + 1 < last[0]:
            parts.append(((first[0] + 1, last[0] - 1), *((128, 191),) * width))
        parts.extend(((last[0], last[0]), *suffix) for suffix in
                     utf8_interval(bytes([128]) * width, last[1:]))
        return parts

    def dns_runes(ranges):
        # D(h) 只含 ASCII presentation；该原子表示空语言，仍可被量词零次跳过。
        if not ranges:
            return r'[^\x{0}-\x{7F}]'
        byte_ranges = []
        for start, end in ranges:
            for left, right in ((0, 127), (128, 2047), (2048, 0xd7ff), (0xe000, 0xffff), (0x10000, 0x10ffff)):
                low, high = max(start, left), min(end, right)
                if low > high:
                    continue
                byte_ranges.extend(utf8_interval(chr(low).encode('utf-8'), chr(high).encode('utf-8')))
        for depth in range(3, -1, -1):
            merged = {}
            for row in byte_ranges:
                key = row[:depth], row[depth + 1:]
                if depth < len(row):
                    merged.setdefault(key, []).append(row[depth])
            if merged:
                byte_ranges = [row for row in byte_ranges if len(row) <= depth]
                byte_ranges.extend((*prefix, interval, *suffix) for (prefix, suffix), items in merged.items()
                                   for interval in clean_ranges(items))
        return dns_choices(_dns_join((byte_interval(start, end) for start, end in row), budget) for row in byte_ranges)

    def literal_ranges(char):
        if ord(char) < 128 and char not in 'iIkK':
            point = ord(char.lower())
            if 97 <= point <= 122 and not paired_exact:
                return ((point - 32, point - 32), (point, point))
            return ((point, point),)
        lowered = ord(_go_lower(char))
        points = {lowered}
        if not paired_exact:
            for start, end, stride, delta in _GO15_LOWER:
                point = lowered - delta
                if start <= point <= end and (point - start) % stride == 0:
                    points.add(point)
        return clean_ranges((point, point) for point in points)

    def dns_literal(char):
        if ord(char) < 128 and char not in 'iIkK':
            return _dns_literal(char.lower(), budget, presentation=True)
        return dns_runes(literal_ranges(char))

    def dns_append(part):
        if part is None:
            return False
        size = budget + 1 if part[0] is None else len(part[0].encode('utf-8'))
        nodes = dns_groups[-1][0]
        # 超预算正文只保留证书，完整 source 扫描后仍可能归约为可空或 universal matcher。
        if dns_sizes[-1] + size > budget and nodes:
            prefix = dns_concat(nodes)
            if prefix is None:
                return False
            nodes[:] = [prefix]
        dns_sizes[-1] = min(budget + 1, dns_sizes[-1] + size)
        nodes.append(part)
        return True

    def dns_set(ranges):
        body = dns_runes(ranges) if dns_sizes[-1] <= budget else None
        universal = ranges in (((0, 0x10ffff),), ((0, 9), (11, 0x10ffff)))
        return dns_append(dns_atom(body, dot=in_ranges(46, ranges), universal=universal, runes=ranges))

    # 证书：target、nullable、末尾可为点、universal-single、Start/End、末尾根点 repeat。
    empty = ('', True, False, False, False, False, None)

    def dns_atom(body, *, dot=False, universal=False, runes=None):
        return body, False, dot, universal, False, False, ('runes', runes, False) if runes is not None else None

    def dns_concat(nodes):
        nodes = [part for part in nodes if part != empty]
        if not nodes:
            return empty
        if len(nodes) == 1:
            return nodes[0]
        if any(part[4] == 'closed' for part in nodes):
            return None
        body, nullable, dot, universal, start, end, tail = empty
        for position, part in enumerate(nodes):
            if end or part[4] and position:
                return None
            if part[5]:
                if position != len(nodes) - 1:
                    return None
                if part[6] is not None and part[6][0] == 'certified':
                    if part[1] and dot:
                        return None
                    body = _dns_join((body, part[0]), budget)
                    nullable = nullable and part[1]
                    dot = part[2] or part[1] and dot
                else:
                    if tail is None or tail[2]:
                        return None
                    if tail[0] == 'optional':
                        body, dot = tail[1], tail[2]
                end = True
                start = start or part[4]
                tail = ('certified', '', False)
                continue
            old_body, old_dot = body, dot
            body = _dns_join((body, part[0]), budget)
            universal = universal and part[1] or part[3] and nullable
            dot = part[2] or part[1] and dot
            nullable = nullable and part[1]
            start = start or part[4]
            tail = ((part[6][0], _dns_join((old_body, part[6][1]), budget),
                     old_dot and part[1] or part[6][2])
                    if part[6] is not None and part[6][0] != 'runes' else None)
        return body, nullable, dot, universal, start, end, tail

    def dns_group(group):
        nodes, branches = group
        part = dns_concat(nodes)
        if part is None:
            return None
        if not branches:
            return part
        entries = [*branches, part]
        if any(entry[4] or entry[5] for entry in entries):
            targets = [dns_complete(entry) for entry in entries]
            if None in targets:
                return None
            body = dns_choices(targets)
            return (body, False, False, False, 'closed', False, None) if body is not None else None
        body = dns_choices(entry[0] for entry in entries)
        runes = (clean_ranges(interval for entry in entries for interval in entry[6][1])
                 if all(entry[6] is not None and entry[6][0] == 'runes' for entry in entries) else None)
        universal = any(entry[3] for entry in entries) or runes in (((0, 0x10ffff),), ((0, 9), (11, 0x10ffff)))
        return (body, any(entry[1] for entry in entries), any(entry[2] for entry in entries),
                universal, False, False, ('runes', runes, False) if runes is not None else None)

    def dns_complete(part):
        if part[4] == 'closed':
            return part[0]
        if part[5] and part[6] is None:
            return None
        if not part[5] and not (part[1] or part[3]) and part[2]:
            return None
        body = '' if not part[5] and (part[1] or part[3]) else part[0]
        return _dns_join((r'\A', '' if part[4] else _DNS_BYTE_TOKEN + '*', body,
                          r'\z' if part[5] else ''), budget)

    def dns_repeat(minimum, maximum):
        if not dns_groups[-1][0]:
            return False
        part = dns_groups[-1][0][-1]
        if part[4] or part[5]:
            return False
        suffix = '*' if (minimum, maximum) == (0, None) else '+' if (minimum, maximum) == (1, None) else (
            '?' if (minimum, maximum) == (0, 1) else '{' + str(minimum) + (
                '' if maximum == minimum else ',' + (str(maximum) if maximum is not None else '')) + '}')
        body = '' if maximum == 0 or part == empty else _dns_join(('(?:', part[0], ')', suffix), budget)
        atom_ranges = part[6][1] if part[6] is not None and part[6][0] == 'runes' else None
        tail = ('optional', '', False) if minimum == 0 and maximum == 1 and atom_ranges == ((46, 46),) else (
            ('star', '', False) if minimum == 0 and maximum is None and part[2] and atom_ranges is not None else None)
        dns_groups[-1][0][-1] = (body, not minimum or part[1], maximum != 0 and part[2],
                                 part[3] and minimum <= 1 and (maximum is None or maximum >= 1), False, False, tail)
        dns_sizes[-1] = min(budget + 1, sum(budget + 1 if node[0] is None else len(node[0].encode('utf-8'))
                                         for node in dns_groups[-1][0]))
        return True

    while index < len(value):
        char = value[index]
        if not in_class:
            nodes, branches, starts = repeat_groups[-1]
            if not encoded:
                if char == '(':
                    paired_groups.append(paired_exact)
                    if index in templates and templates[index][1] == 'paired':
                        paired_exact = True
                    dns_groups.append(([], []))
                    dns_sizes.append(0)
                elif char == ')':
                    if len(dns_groups) == 1:
                        return None
                    group = dns_groups.pop()
                    dns_sizes.pop()
                    body = ((r'(?:' + _DNS_BYTE_TOKEN + r'*\.)?', True, True, False, True, False, None)
                            if index >= 8 and index - 12 in templates and templates[index - 12][1] == 'suffix'
                            else dns_group(group))
                    if not dns_append(body):
                        return None
                    paired_exact = paired_groups.pop()
                elif char == '|':
                    body = dns_group((dns_groups[-1][0], []))
                    if body is None:
                        return None
                    dns_groups[-1][1].append(body)
                    dns_groups[-1][0].clear()
                elif char in '*+?':
                    if index != repeat_end and not dns_repeat(0 if char in '*?' else 1, 1 if char == '?' else None):
                        return None
                elif char in '^$':
                    dns_groups[-1][0].append(('', True, False, False, char == '^', char == '$', None))
                elif char not in r'\.{[':
                    part = dns_literal(char)
                    if part is None:
                        return None
                    if not dns_append(dns_atom(part, runes=literal_ranges(char))):
                        return None
            if char == "(":
                repeat_groups.append(([], [], [index + 1]))
                fold_groups.append(fold_groups[-1])
                if not value.startswith("(?", index):
                    capture_replacements.append((index, index + 1, "(?:"))
            elif char == ")":
                if len(repeat_groups) == 1:
                    return None
                node = group_bounds(repeat_groups.pop())
                fold_groups.pop()
                if node[1] > 1000:
                    return None
                repeat_groups[-1][0].append(node)
            elif char == '|':
                node = group_bounds((nodes, [], starts))
                if node[1] > 1000:
                    return None
                branches.append((node, starts[-1]))
                starts.append(index + 1)
                nodes.clear()
            elif char in '*+?' and index != repeat_end:
                if not nodes or value[index + 1:index + 2] == '+':
                    return None
                count, height = nodes[-1][:2]
                nodes[-1] = (count, height + 1, 'repeat', None, None, nodes[-1][5] + 1, nodes[-1][6],
                             nodes[-1][7] + (2 if char == '*' else 1), nodes[-1][8])
                if height + 1 > 1000:
                    return None
                repeat_end = index + 1
            elif char == '?' and index == repeat_end and nodes and nodes[-1][2] == 'class-repeat':
                previous = nodes[-1]
                nodes[-1] = (*previous[:4], (*previous[4][:-1], True), *previous[5:])
            elif char not in '*+?{':
                escape = value[index + 1:index + 2] if char == '\\' else ''
                operator = ('class' if char in '[.' or escape in _DNS_UNICODE_ATOMS or escape == 'p' else
                            'atom' if char in '^$' or escape in {'A', 'z'} else 1)
                literal = escape or char
                literal = literal_identity(literal, fold_groups[-1])
                identity = literal if operator == 1 else None
                if escape in _DNS_UNICODE_ATOMS:
                    ranges = unicode_ranges(escape.lower())
                    identity = 'runes', negate_ranges(ranges) if escape.isupper() else ranges
                elif char == '.':
                    identity = 'runes', ((0, 9), (11, 0x10FFFF))
                nodes.append((1, 1, operator, fold_groups[-1] if operator in {1, 'class'} and char != '.' else None,
                              identity, 1, (), 1, 0))
                if char == '.' and not encoded:
                    body = dns_runes(((0, 9), (11, 0x10ffff)))
                    if body is None:
                        return None
                    if not dns_append(dns_atom(body, dot=True, universal=True, runes=((0, 9), (11, 0x10ffff)))):
                        return None
        if char == "\\":
            if value.startswith(r"\p{L}", index):
                if not in_class:
                    nodes[-1] = class_node(('runes', unicode_ranges('L')))
                    if not encoded and not dns_set(lower_preimage(unicode_ranges('L'))):
                        return None
                else:
                    class_properties.add(len(translated))
                    class_atoms.append(None)
                translated.append(r"\w")
                index += 5
                continue
            if value.startswith(r"\p{Nd}", index):
                if in_class:
                    return None
                nodes[-1] = class_node(('runes', unicode_ranges('d')))
                if not encoded and not dns_set(lower_preimage(unicode_ranges('d'))):
                    return None
                translated.append(r"\d")
                index += 6
                continue
            if value.startswith(r"\x{", index):
                atom = re.match(r"\\x\{([^}]*)\}", value[index:])
                codepoint = _hex_codepoint(atom[1]) if atom is not None else None
                if codepoint is None or codepoint > 0x7f:
                    return None
                normalized = r"\x{" + f"{codepoint:X}" + "}"
                if normalized != atom[0]:
                    replacements.append((index, index + len(atom[0]), normalized))
                if not in_class:
                    literal = chr(codepoint)
                    nodes[-1] = (1, 1, 1, fold_groups[-1], literal_identity(literal, fold_groups[-1]), 1, (), 1, 0)
                    if not encoded:
                        part = dns_literal(literal)
                        if part is None:
                            return None
                        if not dns_append(dns_atom(part, dot=literal == '.', runes=literal_ranges(literal))):
                            return None
                else:
                    class_atoms.append(codepoint)
                translated.append(re.escape(chr(codepoint)))
                index += len(atom[0])
                continue
            if index + 1 == len(value):
                return None
            escape = value[index + 1]
            if escape in _DNS_UNICODE_ATOMS:
                if in_class:
                    return None
                replacements.append((index, index + 2, _DNS_UNICODE_ATOMS[escape]))
            elif escape not in r"\.*+?{}()[]|^$-Az" and not (encoded and escape in ' #&~') or in_class and escape in "Az":
                return None
            if in_class:
                # regexp2 的 \- 独立加入集合，不参与 pending range。
                if not encoded and escape == '-':
                    class_escaped_hyphens.add(len(class_atoms))
                class_atoms.append(ord(escape))
            elif not encoded:
                if escape in 'Az':
                    dns_groups[-1][0].append(('', True, False, False, escape == 'A', escape == 'z', None))
                elif escape not in _DNS_UNICODE_ATOMS:
                    part = dns_literal(escape)
                    if part is None:
                        return None
                    if not dns_append(dns_atom(part, dot=escape == '.', runes=literal_ranges(escape))):
                        return None
                else:
                    ranges = unicode_ranges(escape.lower())
                    if not dns_set(lower_preimage(negate_ranges(ranges) if escape.isupper() else ranges)):
                        return None
            translated.append(r"\Z" if escape == "z" else value[index:index + 2])
            index += 2
            continue
        if char == "[" and in_class:
            return None
        if char == "[" and not in_class:
            in_class = True
            class_start = index
            class_probe = len(translated)
            class_properties = set()
            class_atoms = []
            class_escaped_hyphens = set()
        elif char == "]" and in_class and index > class_start + 1 + (
                value[class_start + 1:class_start + 2] == "^"):
            in_class = False
            probe = ''.join(part for point, part in enumerate(translated[class_probe:], class_probe)
                            if point not in class_properties) + ']'
            negated = probe.startswith('[^')
            positive = '[' + probe[2:] if negated else probe
            try:
                if positive != '[]':
                    re.compile(positive)
            except re.error:
                return None
            ranges, point = [], 0
            while point < len(class_atoms):
                start = class_atoms[point]
                if start is None:
                    point += 1
                    continue
                start = 45 if start == '-' else start
                if (point + 2 < len(class_atoms) and class_atoms[point + 1] == '-' and
                        class_atoms[point + 2] is not None):
                    if point in class_escaped_hyphens or point + 2 in class_escaped_hyphens:
                        return None
                    end = class_atoms[point + 2]
                    end = 45 if end == '-' else end
                    if start > end:
                        return None
                    point += 3
                else:
                    end = start
                    point += 1
                ranges.append((start, end))
            raw_ranges = clean_ranges(ranges)
            ranges = clean_ranges(part for start, end in raw_ranges for part in (
                ((start, end),) if not fold_groups[-1] else folded_range(start, end)))
            if class_properties:
                ranges = clean_ranges((*ranges, *unicode_ranges('L')))
            # 同一个 Go push 归约用于原始 class 和两个并集合并位置。
            nodes[-1] = class_node(('runes', negate_ranges(ranges) if negated else ranges), fold_groups[-1])
            if not encoded:
                source_ranges = []
                for start, end in raw_ranges:
                    if start == end:
                        point = ord(_go_lower(chr(start)))
                        source_ranges.append((point, point))
                    elif end < 128:
                        source_ranges.append((start, end))
                        if max(start, 65) <= min(end, 90):
                            source_ranges.append((max(start, 65) + 32, min(end, 90) + 32))
                    elif start == 0 and end >= 0x1e943:
                        source_ranges.append((start, end))
                    else:
                        return None
                if class_properties:
                    source_ranges.extend(unicode_ranges('L'))
                source_ranges = clean_ranges(source_ranges)
                if negated:
                    source_ranges = negate_ranges(source_ranges)
                if not dns_set(source_ranges if paired_exact else lower_preimage(source_ranges)):
                    return None
        elif char == "(" and not in_class and value.startswith("(?", index):
            if value.startswith("(?:", index):
                translated.append("(")
                index += 3
                repeat_groups[-1][2][0] = index
                continue
            if (value.startswith("(?i:", index) and value.isascii() or
                    (encoded or index in templates and templates[index][1] == 'paired') and value.startswith("(?-i:", index)):
                translated.append("(")
                fold_groups[-1] = not (encoded or paired_exact)
                index += 5 if value.startswith("(?-i:", index) else 4
                repeat_groups[-1][2][0] = index
                continue
            named = re.match(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", value[index:])
            if named is None:
                return None
            translated.append("(")
            capture_replacements.append((index, index + len(named[0]), "(?:"))
            index += len(named[0])
            repeat_groups[-1][2][0] = index
            continue
        elif char == "{" and not in_class:
            bounds = re.match(r"\{([0-9]+)(?:,([0-9]*))?\}", value[index:])
            if bounds:
                counts = tuple(_capture_number(count) if count else None for count in bounds.groups())
                if (counts[0] is None or bounds[2] and counts[1] is None or
                        any(count > 1000 for count in counts if count is not None) or
                        value[index + len(bounds[0]):].startswith("+")):
                    return None
                if not nodes:
                    return None
                repeat_count = counts[1] if counts[1] is not None else counts[0]
                if bounds[2] == "":
                    repeat_count = max(1, repeat_count)
                previous = nodes[-1]
                count, height = previous[:2]
                fixed_class = previous[2] in {1, 'class'} and (bounds[2] is None or counts[0] == counts[1])
                size = (previous[7] + 2 if not counts[0] else counts[0] * previous[7] + 1) if bounds[2] == '' else (
                    repeat_count * previous[7] + repeat_count - counts[0])
                nodes[-1] = (max(1, count) * repeat_count, height + 1,
                             'class-repeat' if fixed_class else 'repeat', None,
                             (previous[2], previous[3], previous[4], repeat_count, False) if fixed_class else None,
                             previous[5] + 1, previous[6], max(1, size), previous[8] * repeat_count)
                if nodes[-1][0] > 1000 or height + 1 > 1000 or nodes[-1][7] > max_size:
                    return None
                repeat_end = index + len(bounds[0])
                if not encoded and not dns_repeat(counts[0], counts[0] if bounds[2] is None else counts[1]):
                    return None
                normalized = "{" + str(counts[0])
                if bounds[2] is not None:
                    normalized += "," + (str(counts[1]) if counts[1] is not None else "")
                normalized += "}"
                if normalized != bounds[0]:
                    replacements.append((index, index + len(bounds[0]), normalized))
                translated.append(normalized)
                index += len(bounds[0])
                continue
            nodes.append((1, 1, 1, fold_groups[-1], '{', 1, (), 1, 0))
            if not encoded:
                if not dns_append(dns_atom(r'\{', runes=((123, 123),))):
                    return None
        if in_class and char != '[' and not (char == '^' and index == class_start + 1):
            class_atoms.append('-' if char == '-' else ord(char))
        if char == "=":
            replacements.append((index, index + 1, r"\x{3D}"))
        if char == "-" and in_class and translated[-1:] == [r"\w"]:
            translated.append(r"\-")
        else:
            translated.append(r"\{" if char == "{" and not in_class else char)
        index += 1
    if in_class or len(repeat_groups) != 1:
        return None
    bounds = group_bounds(repeat_groups[0])
    if bounds[1] > 1000 or bounds[7] > max_size:
        return None
    try:
        re.compile("".join(translated))
    except RecursionError:
        if not _valid_deep_regex("".join(translated)):
            return None
    except re.error:
        return None
    if not encoded:
        if len(dns_groups) != 1:
            return None
        part = dns_group(dns_groups[0])
        if part is None:
            return None
        target = _dns_join(('(?-i:', dns_complete(part), ')'), budget - 2)
        return _dns_regex(target, budget, encoded=True) if target is not None else None
    # DNS 只消费匹配结果，且上述扫描已拒绝 backreference；非捕获组保留量词绑定。
    replacements.extend(capture_replacements)
    replacements.extend(branch_replacements)
    parts = ['/']
    cursor = 0
    for start, end, normalized in sorted(replacements):
        parts.extend((value[cursor:start], normalized))
        cursor = end
    parts.extend((value[cursor:], '/'))
    return _dns_join(parts, budget)


def _mihomo_rule(rule: Rule) -> Rule | None:
    kind, value = rule.kind, rule.value
    options = tuple(option for option in rule.options if option not in _QX_INTERFACE_OPTIONS)
    if rule.allow or options and (options != ('no-resolve',) or kind not in NO_RESOLVE_TYPES):
        return None
    mihomo_kind, payload = _domain_value(kind, value, rule.domain_source, MIHOMO_TYPES)
    if kind in {'UID', 'DSCP'}:
        payload = value.replace(',', '/')
    if kind == 'DEST-PORT':
        mihomo_kind = 'DST-PORT'
    if kind in {'IP-ASN', 'GEOIP'} and value.upper() == 'UNKNOWN':
        return None
    if payload is not None:
        mihomo_kind, payload = _process_value(mihomo_kind, payload, MIHOMO_TYPES, rule.literal_process)
    if kind in LOGICAL:
        payload = _logical_value(value, kind, MIHOMO_TYPES, rule.literal_process,
                                 rule.native_fields, rule.domain_source)
    elif mihomo_kind in _REGEX and payload is not None and not rule.native_fields:
        payload = _logical_regex_value(payload, logical=False)
    if kind == 'SRC-IP':
        address = ipaddress.ip_address(value)
        mihomo_kind, payload = 'SRC-IP-CIDR', f'{address}/{address.max_prefixlen}'
    if kind == 'PROTOCOL' and value.upper() in {'TCP', 'UDP'}:
        mihomo_kind, payload = 'NETWORK', value.lower()
    if (mihomo_kind not in MIHOMO_TYPES or payload is None or
            ',' in payload and mihomo_kind not in _REGEX and mihomo_kind not in LOGICAL):
        return None
    return Rule(mihomo_kind, payload, options, False, rule.literal_process, True, 'mihomo')


def _paired_domain(rule: Rule) -> tuple[str, str] | None:
    if rule.kind != 'DOMAIN-REGEX' or rule.options:
        return None
    value = rule.value
    if value.startswith(r'(?-i:\A') and value.endswith(r'\.?\z)'):
        kind, literal = 'DOMAIN', value[7:-6]
        literal = re.sub(r'\[([a-z])[A-Z]\]', r'\1', literal)
    elif value.startswith(r'(?-i:(?:\A|\.)'):
        kind, literal = 'DOMAIN-SUFFIX', value[14:].partition(r'\z|')[0]
    else:
        return None
    literal = literal.replace(r'\.', '.').replace(r'\-', '-')
    if (literal.isascii() and literal == literal.lower() and not literal.endswith('.') and
            _valid_domain('DOMAIN-SUFFIX', literal)):
        # raw regex 的结构证书独立于普通域名的输出类型，并严格核对完整模板。
        paired = ''.join('[' + char + char.upper() + ']' if 'a' <= char <= 'z' else re.escape(char)
                         for char in literal)
        expected = (r'(?-i:\A' + paired + r'\.?\z)' if kind == 'DOMAIN' else
                    r'(?-i:(?:\A|\.)' + re.escape(literal) + r'\z|'
                    r'\A(?=[A-Za-z0-9_.-]{1,253}\.?\z)'
                    r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*' + paired + r'\.?\z)')
        if value == expected:
            return kind, literal
    return None


def _route_whitelist(whitelist: list[Rule], target: str) -> tuple[list[Rule], set[tuple[str, str]]]:
    selected, identical = [], set()
    domain_types = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'}
    for entry in whitelist:
        if entry.options and (entry.options != ('no-resolve',) or entry.kind not in NO_RESOLVE_TYPES):
            continue
        source, kind, value = entry.domain_source, entry.kind, entry.value
        if target == 'mihomo':
            if kind in domain_types and (source not in {'surge', 'mihomo'} or source == 'surge' and not value.isascii()):
                continue
            projected = _mihomo_rule(Rule(kind, value, entry.options, literal_process=entry.literal_process,
                                          native_fields=entry.native_fields, domain_source=source))
            if projected is None:
                continue
            # 已证明的 Surge 子集保留来源，另比较真正转换后的 raw regex。
            if source == 'surge':
                selected.append(entry)
            # 最后必要 token 不能用 Host 根点满足；保留原 white 的单向覆盖判断。
            if source == 'surge' and kind == 'DOMAIN-WILDCARD' and value.rstrip('*').endswith(('.', '?')):
                continue
            selected.append(projected)
        elif target == 'surge':
            # native white 的根点与 case 区别不能随 Surge 投影扩大。
            if source != 'surge' and kind in domain_types:
                if source != 'mihomo' or kind in DOMAIN_SET_TYPES or _PROCESS_CASE_VARIANTS.search(value):
                    continue
                kind, value = _domain_value(kind, value, source, SURGE_TYPES)
                if value is None:
                    continue
            elif source == 'mihomo' and kind in {'GEOIP', 'IP-ASN'} and value.upper() == 'UNKNOWN':
                continue
            kind = SURGE_ALIASES.get(kind, kind)
            if kind in SURGE_TYPES and _LINE_UNSAFE.search(value) is None:
                selected.append(Rule(kind, value, domain_source='surge'))
        else:
            if not _qx_field_supported(kind, value) or _LINE_UNSAFE.search(value) is not None:
                continue
            # QX 只复用来源层已有保护，以及未改变 payload 的相同 matcher。
            if source in {'surge', 'qx'}:
                if kind not in domain_types or value.isascii():
                    selected.append(entry)
                if source == 'qx' or value.isascii():
                    identical.add((kind, value))
            elif source == 'mihomo' and kind not in DOMAIN_SET_TYPES:
                _, compatible = _domain_value(kind, value, source, SURGE_TYPES)
                if compatible is not None and (kind not in domain_types or not _PROCESS_CASE_VARIANTS.search(value)):
                    identical.add((kind, value))
    return selected, identical


def render(group: str, rules: Iterable[Rule], *, purpose: str, no_resolve: str,
           whitelist: Iterable[Rule] = (), title: str | None = None) -> tuple[dict[str, str], dict[str, int]]:
    rules, whitelist = [_apply_no_resolve(rule, no_resolve) for rule in rules], list(whitelist)
    routing_white = list(whitelist)
    lines = {name: [] for name in FILES}
    skipped = Counter()
    pending = []
    for rule in sorted(rules, key=lambda item: (item.kind, item.value, item.options, item.allow, item.literal_process, item.native_fields, item.domain_source)):
        effective = rule
        kind, value = rule.kind, rule.value
        interface_options = any(option in _QX_INTERFACE_OPTIONS for option in rule.options)
        if interface_options:
            rule = Rule(kind, value, tuple(option for option in rule.options
                                           if option not in _QX_INTERFACE_OPTIONS),
                        rule.allow, rule.literal_process, rule.native_fields, rule.domain_source)
        line_safe = _LINE_UNSAFE.search(value) is None
        emitted, routed = set(), {}
        logical = kind in LOGICAL
        if rule.allow:
            routing_white.append(rule)
            if not rule.options and purpose == "block" and line_safe:
                dns_pattern = _dns_pattern(rule, exception=True)
                if dns_pattern is not None:
                    lines["fin-adb.txt"].append("@@" + dns_pattern)
                    emitted.add("fin-adb.txt")
        elif rule.options:
            if rule.options == ("no-resolve",) and kind in NO_RESOLVE_TYPES:
                if kind in SURGE_TYPES:
                    surge_kind = "IP-CIDR6" if kind == "IP-CIDR" and ":" in value else kind
                    matcher = Rule(surge_kind, value, (), False, rule.literal_process, rule.native_fields, 'surge')
                    for name in ("fin.txt", "fin-surge.txt"):
                        routed[name] = (f"{surge_kind},{value},no-resolve", matcher)
                if line_safe and _qx_field_supported(kind, value):
                    qx_kind = "IP6-CIDR" if kind == "IP-CIDR" and ":" in value else QX_TYPES[kind]
                    routed["fin-qx.txt"] = (f"{qx_kind},{value},LIST,no-resolve", Rule(kind, value, (), False, rule.literal_process, rule.native_fields, 'qx'))
        else:
            surge_kind, surge_payload = _domain_value(kind, value, rule.domain_source, SURGE_TYPES)
            if surge_payload is not None:
                surge_kind, surge_payload = _process_value(surge_kind, surge_payload, SURGE_TYPES,
                                                          rule.literal_process)
            if kind == "NETWORK" and value.upper() in {"TCP", "UDP"}:
                surge_kind, surge_payload = "PROTOCOL", value.upper()
            surge_kind = SURGE_ALIASES.get(surge_kind, surge_kind)
            surge_value = (_logical_value(value, kind, SURGE_TYPES, rule.literal_process,
                                          rule.native_fields, rule.domain_source) if logical else
                           _surge_value(surge_payload, source_regex=kind == "URL-REGEX")
                           if surge_payload is not None else None)
            if surge_kind in SURGE_TYPES and surge_value is not None and line_safe:
                if kind == "IP-CIDR" and ":" in value:
                    surge_kind = "IP-CIDR6"
                surge_line = f"{surge_kind},{surge_value}"
                matcher = Rule(surge_kind, surge_value if logical else surge_payload, (), False,
                               rule.literal_process, rule.native_fields, 'surge')
                routed["fin.txt"] = (surge_line, matcher)
                if surge_kind in DOMAIN_SET_TYPES:
                    routed["fin-surge-ds.txt"] = (("." if surge_kind == "DOMAIN-SUFFIX" else "") + surge_payload, matcher)
                else:
                    routed["fin-surge.txt"] = (surge_line, matcher)
            if line_safe and _qx_field_supported(kind, value):
                qx_kind = QX_TYPES[kind]
                if kind == "IP-CIDR" and ":" in value:
                    qx_kind = "IP6-CIDR"
                routed["fin-qx.txt"] = (f"{qx_kind},{value},LIST", Rule(kind, value, (), False, rule.literal_process, rule.native_fields, 'qx'))
            if purpose == "block" and line_safe:
                dns_pattern = _dns_pattern(rule)
                if dns_pattern is not None:
                    lines["fin-adb.txt"].append(dns_pattern)
                    emitted.add("fin-adb.txt")
        matcher = _mihomo_rule(effective)
        if matcher is not None:
            payload = f'{matcher.kind},{matcher.value}' + (',no-resolve' if matcher.options else '')
            routed['fin.yaml'] = ('  - ' + _yaml_value(payload), matcher)
        pending.append((rule, effective, emitted, routed, interface_options))
    remaining, identities = {}, {}
    for target, names in (('surge', ('fin.txt', 'fin-surge.txt', 'fin-surge-ds.txt')),
                          ('qx', ('fin-qx.txt',)), ('mihomo', ('fin.yaml',))):
        white, identical = _route_whitelist(routing_white, target)
        projected = [matcher for _, _, _, routed, _ in pending for name, (_, matcher) in routed.items() if name in names]
        kept = set(exclude_covered(projected, white))
        if target == 'mihomo':
            suffixes, keywords, wildcards = set(), set(), set()
            for entry in white:
                paired = _paired_domain(entry)
                if paired is not None and paired[0] == 'DOMAIN-SUFFIX':
                    suffixes.add(paired[1])
                if entry.kind == 'DOMAIN-KEYWORD' and entry.value.isascii():
                    if entry.domain_source == 'surge' or not re.search(r'[A-Za-z]', entry.value):
                        keywords.add(entry.value)
                if (entry.kind == 'DOMAIN-WILDCARD' and entry.domain_source == 'surge' and
                        entry.value.isascii() and _wildcard_regex(entry.value) is not None):
                    wildcards.add(entry.value)
            # 后缀包含分别保持两个 arm；必要 keyword 存在于二者，wildcard 只证明 ASCII exact。
            kept = {matcher for matcher in kept if (paired := _paired_domain(matcher)) is None or not (
                    _has_parent(paired[1], suffixes) or
                    any(keyword and keyword in paired[1] for keyword in keywords) or
                    paired[0] == 'DOMAIN' and any(fnmatchcase(paired[1], pattern) for pattern in wildcards))}
            if wildcards:
                kept = {matcher for matcher in kept if not (
                        matcher.kind == 'DOMAIN' and matcher.value.isascii() and not matcher.value.endswith('.') and
                        _valid_domain('DOMAIN-SUFFIX', matcher.value) and
                        any(fnmatchcase(matcher.value, pattern) for pattern in wildcards))}
        for name in names:
            remaining[name], identities[name] = kept, identical
    complete = set()
    for rule, effective, emitted, routed, interface_options in pending:
        kind = rule.kind
        covered = set()
        for name, (line, matcher) in routed.items():
            value = effective.value if name == 'fin-qx.txt' else matcher.value
            # QX 未证明的 case/root-dot 规范化只能比较实际输出的相同 payload。
            if (value == matcher.value and (name != 'fin-qx.txt' or value.isascii())
                    and matcher not in remaining[name] or (matcher.kind, value) in identities[name]):
                covered.add(name)
                skipped[f'{name}:{kind}:whitelist-covered'] += 1
            else:
                lines[name].append(line)
                emitted.add(name)
        valid_routes = set(routed) & {'fin.txt', 'fin-qx.txt', 'fin-surge.txt', 'fin.yaml'}
        if valid_routes and valid_routes <= covered and effective not in complete:
            skipped[f'whitelist-covered:{kind}'] += 1
            complete.add(effective)
        if interface_options and "fin-qx.txt" in emitted:
            skipped[f"fin-qx.txt:{kind}:interface-option"] += 1
        for name in FILES:
            if name not in emitted | covered and not (name == "fin-surge.txt" and kind in DOMAIN_SET_TYPES
                                                      and not rule.allow and not rule.options):
                skipped[f"{name}:{kind}"] += 1
    if purpose == "block":
        for rule in sorted(whitelist, key=lambda item: (item.kind, item.value)):
            if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX"}:
                pattern = _dns_pattern(rule, exception=True) if _LINE_UNSAFE.search(rule.value) is None else None
                if pattern is None:
                    skipped[f"fin-adb.txt:{rule.kind}"] += 1
                else:
                    lines["fin-adb.txt"].append("@@" + pattern)
    lines = {name: list(dict.fromkeys(body)) for name, body in lines.items()}
    for name, body in lines.items():
        if name == "fin-adb.txt":
            body.sort(key=lambda line: (not line.startswith("@@"), len(line), line))
        elif name == "fin-surge-ds.txt":
            body.sort(key=lambda line: (len(line), line))
        else:
            def sort_key(line):
                kind, _, value = (json.loads(line[4:]) if name == "fin.yaml" else line).partition(",")
                is_ip = kind.startswith(("IP-", "IP6-", "SRC-IP")) or kind in {"GEOIP", "SRC-GEOIP"}
                family = (0 if kind in {"GEOIP", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN"}
                          else 2 if ":" in value else 1)
                return is_ip, family if is_ip else 0, kind, len(line), line

            body.sort(key=sort_key)
    out = {name: (
               "[Adblock Plus 2.0]\n"
               f"! Title: {title if title is not None else group}\n"
               "! Homepage: https://github.com/DoingDog/rconvert\n"
               "! Expires: 1 day\n"
               "! License: Inherits upstream licenses\n"
               f"! Version: {datetime.now(timezone(timedelta(hours=8))):%Y%m%d%H%M}\n"
               f"! Total count: {len(body)}\n"
               if name == "fin-adb.txt" else f"# {group} rules: {len(body)}\n"
           ) + ("payload:\n" if name == "fin.yaml" else "") + "".join(line + "\n" for line in body)
           for name, body in lines.items()}
    if purpose != "block":
        out["fin-adb.txt"] += "! No AdBlock rules for non-advertising group.\n"
    for number, line in enumerate(out["fin-adb.txt"].split("\n")[:-1], 1):
        if len(line.encode("utf-8")) + 1 > _DNS_LINE_LIMIT:
            label = "title" if number == 2 else f"line {number}"
            raise ValueError(f"{group}: fin-adb.txt {label} exceeds {_DNS_LINE_LIMIT}-byte line limit including LF")
    return out, dict(skipped)
