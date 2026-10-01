import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from collections import Counter
from collections.abc import Iterable

from rules import (Rule, _REGEX, _QX_INTERFACE_OPTIONS, _delimiters,
                   _field_value, _fields, _logical_children, _valid_domain)


FILES = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")
DOMAIN_SET_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP"}
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
    if kind not in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}:
        return kind, value
    if supported is SURGE_TYPES:
        if source == "mihomo" and (re.search(r"[a-z]", value, re.I) or
                                    kind == "DOMAIN-WILDCARD" and any(c in value for c in "[]")):
            return kind, None
    elif supported is MIHOMO_TYPES and source == "surge":
        if kind == "DOMAIN-KEYWORD":
            # Surge 忽略 hostname 末尾根点；keyword 的末尾点必须位于 hostname 内部。
            return "DOMAIN-REGEX", re.escape(value.lower()) + (r"(?=.)" if value.endswith(".") else "")
        pattern = _wildcard_regex(value.lower().removesuffix("."))
        return "DOMAIN-REGEX", pattern[:-1] + r"\.?$" if pattern is not None else None
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
    return kind, value


def _yaml_value(value: str) -> str:
    # 保持 JSON 可解码，转义 YAML 的分行/C1/非字符边界，并保留完整 non-BMP scalar。
    return re.sub(r"[\x7f-\x9f\u2028\u2029\ufffe\uffff]",
                  lambda match: f"\\u{ord(match[0]):04x}", json.dumps(value, ensure_ascii=False))


_LINE_UNSAFE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029\ufffe\uffff]")


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


def _logical_value(value: str, operator: str, supported: set[str], no_resolve: str = "keep",
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
        if not payload.strip(trim):
            return None
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
            if kind.startswith('PROCESS-') and ',' in payload and not kind.endswith('-REGEX'):
                return None
            if native_fields and kind not in _REGEX and options and any(char in payload for char in '()'):
                payload += ',' + ','.join(options)
        if kind == 'IP-CIDR' and ':' in payload:
            kind = 'IP-CIDR6'
        if kind not in supported:
            return None
        if kind in NO_RESOLVE_TYPES and (no_resolve == 'add' or no_resolve == 'keep' and
                                        any(option.lower() == 'no-resolve' for option in options)):
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


def _dns_pattern(rule: Rule) -> str | None:
    if rule.kind == "DOMAIN":
        return rule.value
    if rule.kind == "DOMAIN-SUFFIX":
        return f"||{rule.value}^"
    if "/" in rule.value:
        return None
    if rule.kind == "DOMAIN-KEYWORD":
        return f"/^.*{re.escape(rule.value)}.*$/"
    if rule.kind == "DOMAIN-WILDCARD":
        if rule.domain_source != "surge" and any(char in rule.value for char in "[]"):
            return None
        pattern = _wildcard_regex(rule.value)
        return f"/{pattern}/" if pattern is not None else None
    if rule.kind == "DOMAIN-REGEX":
        if re.search(r"[*+?]\+", rule.value):
            return None
        translated = []
        replacements = []
        index = 0
        in_class = False
        class_start = 0
        # Go 对嵌套数值量词检查组合重复次数，上限为 1000。
        repeat_groups = [[]]
        while index < len(rule.value):
            char = rule.value[index]
            if not in_class:
                if char == "(":
                    repeat_groups.append([])
                elif char == ")":
                    if len(repeat_groups) == 1:
                        return None
                    repeat_count = max(repeat_groups.pop(), default=1)
                    repeat_groups[-1].append(repeat_count)
                elif char not in "*+?{":
                    repeat_groups[-1].append(1)
            if char == "\\":
                if rule.value.startswith(r"\p{L}", index):
                    translated.append(r"\w")
                    index += 5
                    continue
                if rule.value.startswith(r"\p{Nd}", index):
                    if in_class:
                        return None
                    translated.append(r"\d")
                    index += 6
                    continue
                if rule.value.startswith(r"\x{", index):
                    atom = re.match(r"\\x\{([0-9a-fA-F]{1,6})\}", rule.value[index:])
                    if atom is None:
                        return None
                    codepoint = int(atom[1], 16)
                    if codepoint > 0x7f:
                        return None
                    translated.append(re.escape(chr(codepoint)))
                    index += len(atom[0])
                    continue
                if index + 1 == len(rule.value):
                    return None
                escape = rule.value[index + 1]
                if escape in _DNS_UNICODE_ATOMS:
                    if in_class:
                        return None
                    replacements.append((index, index + 2, _DNS_UNICODE_ATOMS[escape]))
                elif escape not in r"\.*+?{}()[]|^$-Az" or in_class and escape in "Az":
                    return None
                translated.append(r"\Z" if escape == "z" else rule.value[index:index + 2])
                index += 2
                continue
            if char == "[" and in_class:
                return None
            if char == "[" and not in_class:
                in_class = True
                class_start = index
            elif char == "]" and in_class and index > class_start + 1 + (
                    rule.value[class_start + 1:class_start + 2] == "^"):
                in_class = False
            elif char == "(" and not in_class and rule.value.startswith("(?", index):
                if rule.value.startswith("(?:", index):
                    translated.append("(?:")
                    index += 3
                    continue
                if rule.value.startswith("(?i:", index) and rule.value.isascii():
                    translated.append("(?i:")
                    index += 4
                    continue
                named = re.match(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", rule.value[index:])
                if named is None:
                    return None
                translated.append("(")
                index += len(named[0])
                continue
            elif char == "{" and not in_class:
                bounds = re.match(r"\{([0-9]+)(?:,([0-9]*))?\}", rule.value[index:])
                if bounds:
                    counts = tuple(count.lstrip("0") or "0" if count else count for count in bounds.groups())
                    if any(len(count) > 4 or len(count) == 4 and count > "1000"
                           for count in counts if count) or rule.value[index + len(bounds[0]):].startswith("+"):
                        return None
                    if not repeat_groups[-1]:
                        return None
                    repeat_count = int(counts[1] or counts[0])
                    if counts[1] == "":
                        repeat_count = max(1, repeat_count)
                    repeat_groups[-1][-1] *= repeat_count
                    if repeat_groups[-1][-1] > 1000:
                        return None
                    normalized = "{" + counts[0] + ("," + counts[1] if counts[1] is not None else "") + "}"
                    if normalized != bounds[0]:
                        replacements.append((index, index + len(bounds[0]), normalized))
                    translated.append(normalized)
                    index += len(bounds[0])
                    continue
                repeat_groups[-1].append(1)
            if char == "-" and in_class and translated[-1:] == [r"\w"]:
                translated.append(r"\-")
            else:
                translated.append(char)
            index += 1
        try:
            re.compile("".join(translated))
        except re.error:
            return None
        value = rule.value
        for start, end, normalized in reversed(replacements):
            value = value[:start] + normalized + value[end:]
        return f"/{value}/"
    return None


def render(group: str, rules: Iterable[Rule], *, purpose: str, no_resolve: str,
           whitelist: Iterable[Rule] = (), title: str | None = None) -> tuple[dict[str, str], dict[str, int]]:
    lines = {name: [] for name in FILES}
    skipped = Counter()
    for rule in sorted(rules, key=lambda item: (item.kind, item.value, item.options, item.allow, item.literal_process, item.native_fields, item.domain_source)):
        kind, value = rule.kind, rule.value
        interface_options = any(option in _QX_INTERFACE_OPTIONS for option in rule.options)
        if interface_options:
            rule = Rule(kind, value, tuple(option for option in rule.options
                                           if option not in _QX_INTERFACE_OPTIONS),
                        rule.allow, rule.literal_process, rule.native_fields, rule.domain_source)
        if no_resolve == "strip":
            rule = Rule(kind, value, tuple(option for option in rule.options if option != "no-resolve"),
                        rule.allow, rule.literal_process, rule.native_fields, rule.domain_source)
        elif no_resolve == "add" and not rule.allow and kind in NO_RESOLVE_TYPES:
            rule = Rule(kind, value, rule.options + ("no-resolve",), rule.allow, rule.literal_process, rule.native_fields, rule.domain_source)
        line_safe = _LINE_UNSAFE.search(value) is None
        emitted = set()
        text = f"{kind},{value}"
        logical = kind in LOGICAL
        if rule.allow:
            if not rule.options and purpose == "block" and line_safe:
                dns_pattern = _dns_pattern(rule)
                if dns_pattern is not None:
                    lines["fin-adb.txt"].append("@@" + (f"|{value}|" if kind == "DOMAIN" else dns_pattern))
                    emitted.add("fin-adb.txt")
        elif rule.options:
            if rule.options == ("no-resolve",) and kind in NO_RESOLVE_TYPES:
                if kind in SURGE_TYPES:
                    surge_kind = "IP-CIDR6" if kind == "IP-CIDR" and ":" in value else kind
                    for name in ("fin.txt", "fin-surge.txt"):
                        lines[name].append(f"{surge_kind},{value},no-resolve")
                        emitted.add(name)
                if kind in MIHOMO_TYPES:
                    lines["fin.yaml"].append("  - " + _yaml_value(text + ",no-resolve"))
                    emitted.add("fin.yaml")
                if kind in QX_TYPES:
                    qx_kind = "IP6-CIDR" if kind == "IP-CIDR" and ":" in value else QX_TYPES[kind]
                    lines["fin-qx.txt"].append(f"{qx_kind},{value},LIST,no-resolve")
                    emitted.add("fin-qx.txt")
        else:
            surge_kind, surge_payload = _domain_value(kind, value, rule.domain_source, SURGE_TYPES)
            if surge_payload is not None:
                surge_kind, surge_payload = _process_value(surge_kind, surge_payload, SURGE_TYPES,
                                                          rule.literal_process)
            if kind == "NETWORK" and value.upper() in {"TCP", "UDP"}:
                surge_kind, surge_payload = "PROTOCOL", value.upper()
            surge_kind = SURGE_ALIASES.get(surge_kind, surge_kind)
            surge_value = (_logical_value(value, kind, SURGE_TYPES, no_resolve, rule.literal_process,
                                          rule.native_fields, rule.domain_source) if logical else
                           _surge_value(surge_payload, source_regex=kind == "URL-REGEX")
                           if surge_payload is not None else None)
            if surge_kind in SURGE_TYPES and surge_value is not None and line_safe:
                if kind == "IP-CIDR" and ":" in value:
                    surge_kind = "IP-CIDR6"
                surge_line = f"{surge_kind},{surge_value}"
                lines["fin.txt"].append(surge_line)
                emitted.add("fin.txt")
                if kind not in DOMAIN_SET_TYPES:
                    lines["fin-surge.txt"].append(surge_line)
                    emitted.add("fin-surge.txt")
            if line_safe and kind in QX_TYPES and "," not in value and not (
                kind == "DOMAIN-WILDCARD" and any(c in value for c in "[]")
            ):
                qx_kind = QX_TYPES[kind]
                if kind == "IP-CIDR" and ":" in value:
                    qx_kind = "IP6-CIDR"
                lines["fin-qx.txt"].append(f"{qx_kind},{value},LIST")
                emitted.add("fin-qx.txt")
            mihomo_kind, mihomo_value = _domain_value(kind, value, rule.domain_source, MIHOMO_TYPES)
            if kind == "DEST-PORT":
                mihomo_kind = "DST-PORT"
            if mihomo_value is not None:
                mihomo_kind, mihomo_value = _process_value(mihomo_kind, mihomo_value, MIHOMO_TYPES,
                                                          rule.literal_process)
            if logical:
                mihomo_value = _logical_value(value, kind, MIHOMO_TYPES, no_resolve, rule.literal_process,
                                              rule.native_fields, rule.domain_source)
            elif mihomo_kind in _REGEX and mihomo_value is not None and not rule.native_fields:
                mihomo_value = _logical_regex_value(mihomo_value, logical=False)
            if kind == "SRC-IP":
                address = ipaddress.ip_address(value)
                mihomo_kind, mihomo_value = "SRC-IP-CIDR", f"{address}/{address.max_prefixlen}"
            if kind == "PROTOCOL" and value.upper() in {"TCP", "UDP"}:
                mihomo_kind, mihomo_value = "NETWORK", value.lower()
            if (mihomo_kind in MIHOMO_TYPES and mihomo_value is not None and
                    not (mihomo_kind.startswith("PROCESS-") and "," in mihomo_value and not mihomo_kind.endswith("-REGEX"))):
                lines["fin.yaml"].append("  - " + _yaml_value(f"{mihomo_kind},{mihomo_value}"))
                emitted.add("fin.yaml")
            if purpose == "block" and line_safe:
                dns_pattern = _dns_pattern(rule)
                if dns_pattern is not None:
                    lines["fin-adb.txt"].append(dns_pattern)
                    emitted.add("fin-adb.txt")
            if kind in DOMAIN_SET_TYPES and line_safe:
                lines["fin-surge-ds.txt"].append(("." if kind == "DOMAIN-SUFFIX" else "") + value)
                emitted.add("fin-surge-ds.txt")
        if interface_options and "fin-qx.txt" in emitted:
            skipped[f"fin-qx.txt:{kind}:interface-option"] += 1
        for name in FILES:
            if name not in emitted and not (name == "fin-surge.txt" and kind in DOMAIN_SET_TYPES
                                            and not rule.allow and not rule.options):
                skipped[f"{name}:{kind}"] += 1
    if purpose == "block":
        for rule in sorted(whitelist, key=lambda item: (item.kind, item.value)):
            if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX"}:
                pattern = _dns_pattern(rule) if _LINE_UNSAFE.search(rule.value) is None else None
                if pattern is None:
                    skipped[f"fin-adb.txt:{rule.kind}"] += 1
                else:
                    lines["fin-adb.txt"].append("@@" + (f"|{rule.value}|" if rule.kind == "DOMAIN" else pattern))
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
    return out, dict(skipped)
