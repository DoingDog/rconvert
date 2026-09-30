import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from collections import Counter
from collections.abc import Iterable

from rules import Rule, _QX_INTERFACE_OPTIONS, _fields, _valid_domain


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


def _surge_value(value: str) -> str | None:
    if "," not in value:
        return value
    quote = next((mark for mark in ("'", '"') if mark not in value), None)
    return f"{quote}{value}{quote}" if quote else None


def _logical_value(value: str, operator: str, supported: set[str], no_resolve: str = "keep",
                   literal_process: bool = False) -> str | None:
    if operator == "NOT" and value.startswith("(") and not value.startswith("(("):
        value = f"({value})"
    if not value.startswith("((") or not value.endswith("))"):
        return None
    try:
        children = _fields(value[1:-1])
    except ValueError:
        return None
    if (len(children) != 1 if operator == "NOT" else len(children) < 2):
        return None
    parts = []
    for child in children:
        if not child.startswith("(") or not child.endswith(")"):
            return None
        try:
            fields = _fields(child[1:-1])
        except ValueError:
            return None
        if len(fields) < 2:
            return None
        kind, payload, *options = fields
        if kind in LOGICAL:
            if options:
                return None
            payload = _logical_value(payload, kind, supported, no_resolve, literal_process)
            if payload is None:
                return None
        else:
            if options and (kind not in NO_RESOLVE_TYPES or
                            any(option.lower() != "no-resolve" for option in options)):
                return None
            quote = payload[0] if len(payload) >= 2 and payload[0] in "'\"" and payload[-1] == payload[0] else None
            if quote:
                payload = payload[1:-1]
            if not payload.strip():
                return None
            if supported is SURGE_TYPES:
                if (kind == "PROCESS-NAME" and literal_process and
                        (payload.startswith("/") or any(char in payload for char in "*?")) or
                        kind == "PROCESS-PATH" and any(char in payload for char in "*?") or
                        kind == "PROCESS-NAME-WILDCARD" and payload.startswith("/")):
                    return None
                if kind == "NETWORK" and payload.upper() in {"TCP", "UDP"}:
                    kind, payload = "PROTOCOL", payload.upper()
                elif kind in {"PROCESS-PATH", "PROCESS-PATH-WILDCARD"} and not payload.startswith("/"):
                    return None
                kind = SURGE_ALIASES.get(kind, kind)
                if kind == "IP-CIDR" and ":" in payload:
                    kind = "IP-CIDR6"
                payload = _surge_value(payload)
                if payload is None:
                    return None
            else:
                if kind == "DEST-PORT":
                    kind = "DST-PORT"
                elif kind == "SRC-IP":
                    try:
                        if "/" in payload:
                            payload = str(ipaddress.ip_network(payload, strict=False))
                        else:
                            address = ipaddress.ip_address(payload)
                            payload = f"{address}/{address.max_prefixlen}"
                    except ValueError:
                        return None
                    kind = "SRC-IP-CIDR"
                elif kind == "PROTOCOL" and payload.upper() in {"TCP", "UDP"}:
                    kind, payload = "NETWORK", payload.lower()
                elif kind == "PROCESS-NAME" and not literal_process:
                    if payload.startswith("/"):
                        kind = ("PROCESS-PATH-WILDCARD" if any(char in payload for char in "*?")
                                else "PROCESS-PATH")
                    elif any(char in payload for char in "*?"):
                        kind = "PROCESS-NAME-WILDCARD"
                if kind == "DOMAIN-WILDCARD" and any(char in payload for char in "[]"):
                    payload = _wildcard_regex(payload)
                    if payload is None:
                        return None
                    kind = "DOMAIN-REGEX"
                if kind == "IP-CIDR" and ":" in payload:
                    kind = "IP-CIDR6"
                if kind.startswith("PROCESS-") and "," in payload and not kind.endswith("-REGEX"):
                    return None
            if kind not in supported:
                return None
            if supported is MIHOMO_TYPES and quote and "," in payload:
                payload = f"{quote}{payload}{quote}"
            if kind in NO_RESOLVE_TYPES and (
                no_resolve == "add" or no_resolve == "keep" and options
            ):
                payload += ",no-resolve"
        parts.append(f"({kind},{payload})")
    return "(" + ",".join(parts) + ")"


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
    for rule in sorted(rules, key=lambda item: (item.kind, item.value, item.options, item.allow, item.literal_process)):
        kind, value = rule.kind, rule.value
        interface_options = any(option in _QX_INTERFACE_OPTIONS for option in rule.options)
        if interface_options:
            rule = Rule(kind, value, tuple(option for option in rule.options
                                           if option not in _QX_INTERFACE_OPTIONS),
                        rule.allow, rule.literal_process)
        if no_resolve == "strip":
            rule = Rule(kind, value, tuple(option for option in rule.options if option != "no-resolve"),
                        rule.allow, rule.literal_process)
        elif no_resolve == "add" and not rule.allow and kind in NO_RESOLVE_TYPES:
            rule = Rule(kind, value, rule.options + ("no-resolve",), rule.allow, rule.literal_process)
        if "\r" in value or "\n" in value:
            for name in FILES:
                skipped[f"{name}:{kind}"] += 1
            continue
        emitted = set()
        text = f"{kind},{value}"
        logical = kind in LOGICAL
        if rule.allow:
            if not rule.options and purpose == "block":
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
                    lines["fin.yaml"].append("  - " + json.dumps(text + ",no-resolve", ensure_ascii=False))
                    emitted.add("fin.yaml")
                if kind in QX_TYPES:
                    qx_kind = "IP6-CIDR" if kind == "IP-CIDR" and ":" in value else QX_TYPES[kind]
                    lines["fin-qx.txt"].append(f"{qx_kind},{value},LIST,no-resolve")
                    emitted.add("fin-qx.txt")
        else:
            surge_value = (_logical_value(value, kind, SURGE_TYPES, no_resolve, rule.literal_process)
                           if logical else _surge_value(value))
            if ((kind in SURGE_TYPES or kind == "PROCESS-NAME-WILDCARD" or
                    kind in {"PROCESS-PATH", "PROCESS-PATH-WILDCARD"} and value.startswith('/') or
                    kind == "NETWORK" and value.upper() in {"TCP", "UDP"}) and surge_value is not None
                    and not (kind == "PROCESS-NAME" and rule.literal_process
                             and (value.startswith("/") or any(char in value for char in "*?"))
                             or kind == "PROCESS-PATH" and any(char in value for char in "*?")
                             or kind == "PROCESS-NAME-WILDCARD" and value.startswith("/"))):
                surge_kind = SURGE_ALIASES.get(kind, kind)
                if kind == "NETWORK":
                    surge_kind, surge_value = "PROTOCOL", value.upper()
                if kind == "IP-CIDR" and ":" in value:
                    surge_kind = "IP-CIDR6"
                surge_line = f"{surge_kind},{surge_value}"
                lines["fin.txt"].append(surge_line)
                emitted.add("fin.txt")
                if kind not in DOMAIN_SET_TYPES:
                    lines["fin-surge.txt"].append(surge_line)
                    emitted.add("fin-surge.txt")
            if kind in QX_TYPES and "," not in value and not (
                kind == "DOMAIN-WILDCARD" and any(c in value for c in "[]")
            ):
                qx_kind = QX_TYPES[kind]
                if kind == "IP-CIDR" and ":" in value:
                    qx_kind = "IP6-CIDR"
                lines["fin-qx.txt"].append(f"{qx_kind},{value},LIST")
                emitted.add("fin-qx.txt")
            mihomo_kind = "DST-PORT" if kind == "DEST-PORT" else kind
            if kind == "PROCESS-NAME" and not rule.literal_process:
                if value.startswith("/"):
                    mihomo_kind = ("PROCESS-PATH-WILDCARD" if any(char in value for char in "*?")
                                   else "PROCESS-PATH")
                elif any(char in value for char in "*?"):
                    mihomo_kind = "PROCESS-NAME-WILDCARD"
            mihomo_value = (_logical_value(value, kind, MIHOMO_TYPES, no_resolve, rule.literal_process)
                            if logical else value)
            if kind == "DOMAIN-WILDCARD" and any(char in value for char in "[]"):
                mihomo_kind, mihomo_value = "DOMAIN-REGEX", _wildcard_regex(value)
            if kind == "SRC-IP":
                address = ipaddress.ip_address(value)
                mihomo_kind, mihomo_value = "SRC-IP-CIDR", f"{address}/{address.max_prefixlen}"
            if kind == "PROTOCOL" and value.upper() in {"TCP", "UDP"}:
                mihomo_kind, mihomo_value = "NETWORK", value.lower()
            if (mihomo_kind in MIHOMO_TYPES and mihomo_value is not None and
                    not (kind.startswith("PROCESS-") and "," in value and not kind.endswith("-REGEX"))):
                lines["fin.yaml"].append("  - " + json.dumps(f"{mihomo_kind},{mihomo_value}", ensure_ascii=False))
                emitted.add("fin.yaml")
            if purpose == "block":
                dns_pattern = _dns_pattern(rule)
                if dns_pattern is not None:
                    lines["fin-adb.txt"].append(dns_pattern)
                    emitted.add("fin-adb.txt")
            if kind in DOMAIN_SET_TYPES:
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
            if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}:
                pattern = _dns_pattern(rule) if not any(c in rule.value for c in "\r\n") else None
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
