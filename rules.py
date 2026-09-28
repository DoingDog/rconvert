import ipaddress
import json
import re
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase


@dataclass(frozen=True, slots=True)
class Rule:
    kind: str
    value: str
    options: tuple[str, ...] = ()
    allow: bool = False

    def __post_init__(self):
        kind = self.kind.upper()
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "options", tuple(sorted({option.lower() for option in self.options})))
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
            object.__setattr__(self, "value", self.value.removesuffix(".").lower())
        elif kind == "DOMAIN-KEYWORD":
            object.__setattr__(self, "value", self.value.lower())


_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.I)
_PORTS = {"SRC-PORT", "DEST-PORT", "DST-PORT", "IN-PORT"}
_PROCESS = {"PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD",
            "PROCESS-PATH-WILDCARD", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX",
            "IN-NAME", "REMATCH-NAME", "DEVICE-NAME", "USER-AGENT",
            "DOMAIN-REGEX", "URL-REGEX"}
_REGEX = {"DOMAIN-REGEX", "URL-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"}
_SIMPLE = {"IP-ASN", "SRC-IP-ASN", "GEOIP", "SRC-GEOIP", "GEOSITE",
           "IP-SUFFIX", "SRC-IP-SUFFIX", "SRC-IP", "NETWORK", "PROTOCOL",
           "IN-TYPE", "IN-USER", "UID", "DSCP", "MAC-ADDRESS",
           "HOSTNAME-TYPE", "SUBNET", "CELLULAR-RADIO", "CELLULAR-CARRIER",
           "DOMAIN-KEYWORD"}
_LOGICAL = {"AND", "OR", "NOT"}
_BLOCK_ACTIONS = {"REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF",
                  "REJECT-200", "REJECT-IMG", "REJECT-DICT", "REJECT-ARRAY", "ADBLOCK", "ADVERTISINGLITE", "HIJACKING", "PRIVACY", "ZHIHUADS",
                  "ADGUARDSDNSFILTER", "ADVERTISINGMITV", "BLOCKHTTPDNS", "EASYPRIVACY"}
_KINDS = ({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}
          | _PORTS | _PROCESS | _SIMPLE | _LOGICAL)


def _fields(line: str) -> list[str]:
    fields, start, stack, escaped, quote = [], 0, [], False, None
    closing = {')': '(', ']': '[', '}': '{'}
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"" and not line[start:index].strip():
            quote = char
        elif stack and stack[-1] == '[' and char != ']':
            continue
        elif char in '([{':
            stack.append(char)
        elif char in closing:
            if not stack or stack.pop() != closing[char]:
                raise ValueError("unbalanced delimiters")
        elif char == ',' and not stack:
            fields.append(line[start:index].strip())
            start = index + 1
    if stack or quote:
        raise ValueError("unbalanced delimiters")
    return fields + [line[start:].strip()]


def _valid_domain(kind: str, value: str) -> bool:
    value = value.removesuffix('.')
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    if kind == "DOMAIN-WILDCARD":
        value = re.sub(r"\[[a-z0-9-]+\]", "x", value, flags=re.I)
        if '[' in value or ']' in value:
            return False
        value = value.replace('*', 'x').replace('?', 'x')
    if kind == "DOMAIN-SUFFIX" and '.' not in value:
        return bool(_DOMAIN.fullmatch('x.' + value))
    return bool(_DOMAIN.fullmatch(value))


def _port_comparison(value: str) -> str | None:
    match = re.fullmatch(r"([<>]=?)([0-9]+)", value)
    if not match or len(match[2].lstrip('0')) > 5:
        return None
    number = int(match[2].lstrip('0') or '0')
    lower = number + (match[1] == '>') if match[1].startswith('>') else 1
    upper = number - (match[1] == '<') if match[1].startswith('<') else 65535
    if not 1 <= lower <= upper <= 65535:
        return None
    return str(lower) if lower == upper else f"{lower}-{upper}"


def _valid_port(value: str) -> bool:
    if '/' in value:
        return all(not part.startswith(('<', '>')) and _valid_port(part)
                   for part in value.split('/'))
    if value.startswith(('<', '>')):
        return _port_comparison(value) is not None
    ports = value.split('-')
    numbers = [port.lstrip('0') for port in ports]
    return (1 <= len(ports) <= 2 and
            all(port.isascii() and port.isdecimal() and 0 < len(number) <= 5
                and int(number) <= 65535 for port, number in zip(ports, numbers)) and
            (len(ports) == 1 or int(numbers[0]) <= int(numbers[1])))


def _valid_simple(kind: str, value: str) -> bool:
    if kind in {"IP-ASN", "SRC-IP-ASN"}:
        number = value.lstrip('0')
        return (value.isascii() and value.isdecimal() and 0 < len(number) <= 10
                and int(number) <= 4294967295)
    if kind in {"IP-SUFFIX", "SRC-IP-SUFFIX"}:
        try:
            ipaddress.ip_interface(value)
            return '/' in value
        except ValueError:
            return False
    if kind == "SRC-IP":
        try:
            (ipaddress.ip_network(value, strict=False) if '/' in value
             else ipaddress.ip_address(value))
            return True
        except ValueError:
            return False
    if kind in {"GEOIP", "SRC-GEOIP"}:
        return bool(re.fullmatch(r"[a-z]{2}", value, re.I))
    if kind == "GEOSITE":
        return bool(re.fullmatch(r"[a-z0-9_-]+(?:@[a-z0-9_-]+)?", value, re.I))
    if kind in {"UID", "DSCP"}:
        number = value.lstrip('0')
        return (value.isascii() and value.isdecimal() and len(number) <= 10
                and int(number or '0') <= (63 if kind == "DSCP" else 4294967295))
    if kind == "IN-USER":
        return all(re.fullmatch(r"[^/\s,<>]+", user) for user in value.split('/'))
    if kind == "MAC-ADDRESS":
        return bool(re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value, re.I))
    if kind == "HOSTNAME-TYPE":
        return value in {"IPv4", "IPv6", "DOMAIN", "SIMPLE"}
    if kind == "CELLULAR-RADIO":
        return value in {"GPRS", "Edge", "WCDMA", "HSDPA", "HSUPA", "CDMA1x",
                         "CDMAEVDORev0", "CDMAEVDORevA", "CDMAEVDORevB", "eHRPD",
                         "HRPD", "LTE", "NRNSA", "NR"}
    if kind == "CELLULAR-CARRIER":
        return bool(re.fullmatch(r"[0-9]{5,6}", value))
    if kind == "SUBNET":
        prefix, separator, target = value.partition(':')
        if not separator:
            return bool(value) and not any(c in value for c in '<>\r\n')
        if prefix == "TYPE":
            return target.upper() in {"WIFI", "WIRED", "CELLULAR"}
        if prefix == "ROUTER":
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                return False
        return (prefix in {"SSID", "BSSID"} and bool(target) and '<' not in target and '>' not in target
                or prefix == "MCCMNC" and bool(re.fullmatch(r"[0-9]{5,6}", target)))
    if kind == "NETWORK":
        return value.upper() in {"TCP", "UDP"}
    if kind == "PROTOCOL":
        return value in {"HTTP", "HTTPS", "TCP", "UDP", "QUIC", "STUN", "MTProto",
                         "DOH", "DOH3", "DOQ", "DOT", "DNS"}
    if kind == "IN-TYPE":
        return bool(re.fullmatch(r"[\w-]+(?:/[\w-]+)*", value, re.ASCII))
    return bool(re.fullmatch(r"[a-z0-9._-]+", value, re.I))


def _valid_condition(expression: str) -> bool:
    if not expression.startswith('(') or not expression.endswith(')'):
        return False
    try:
        fields = _fields(expression[1:-1])
    except ValueError:
        return False
    if len(fields) not in (2, 3):
        return False
    kind, value = fields[:2]
    if len(fields) == 3 and not (kind in {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}
                                  and fields[2].lower() == "no-resolve"):
        return False
    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
        return _valid_domain(kind, value) or kind == "DOMAIN" and _valid_domain("DOMAIN-SUFFIX", value)
    if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
            return kind != "IP-CIDR6" or network.version == 6
        except ValueError:
            return False
    if kind in _PORTS:
        return '/' not in value and not value.startswith(('<', '>')) and _valid_port(value)
    if kind in _SIMPLE:
        return _valid_simple(kind, value)
    if kind in _REGEX:
        try:
            re.compile(value)
            return bool(value)
        except re.error:
            return False
    if kind in _PROCESS:
        return bool(value) and not any(char in value for char in '<>\r\n')
    return bool(value) and kind in _KINDS and (
        kind not in _LOGICAL or _valid_logic(kind, value)
    )


def _valid_logic(kind: str, value: str) -> bool:
    if not value.startswith('(') or not value.endswith(')'):
        return False
    if kind == "NOT":
        return _valid_condition(value[1:-1] if value.startswith('((') and value.endswith('))') else value)
    try:
        children = _fields(value[1:-1])
    except ValueError:
        return False
    return len(children) >= 2 and all(_valid_condition(child) for child in children)


def _without_comment(line: str) -> str:
    quote, escaped, in_class = None, False, False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif char in "'\"":
            quote = None if quote == char else char if quote is None else quote
        elif not quote:
            if char == '[':
                in_class = True
            elif char == ']':
                in_class = False
            elif (not in_class and index and line[index - 1].isspace()
                  and (char in '#;' or line.startswith('//', index))):
                return line[:index].rstrip()
    return line


def parse(text: str, *, purpose: str, ignore_policy: bool = False) -> tuple[list[Rule], list[str]]:
    if purpose not in {"block", "direct", "proxy"}:
        raise ValueError(f"invalid purpose: {purpose}")
    opening_tags = {}
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(('#', ';', '//', '!')):
            continue
        line = _without_comment(line)
        if re.search(r"<\s*(?:!doctype\b|/?(?:html|head|body)\b)", line, re.I):
            return [], [f"line {number}: HTML document"]
        for tag in re.finditer(r"<\s*(/?)\s*([a-z][\w:-]*)\b[^>]*>", line, re.I):
            name = tag[2].lower()
            if tag[1] and name in opening_tags:
                return [], [f"line {opening_tags[name]}: HTML document"]
            if not tag[1] and not tag[0].endswith('/>'):
                opening_tags.setdefault(name, number)
    rules, warnings = [], []
    in_payload = False
    for number, source in enumerate(text.splitlines(), 1):
        line = _without_comment(source).strip()
        if not line or line.startswith(('#', ';', '//')):
            continue
        if re.search(r"<\s*(?:/?[a-z][\w:-]*(?:\s[^>]*|/?)>|!doctype\b|!--)", line, re.I):
            warnings.append(f"line {number}: HTML markup")
            continue
        if line == 'payload:':
            in_payload = True
            continue
        if in_payload and not source[0].isspace() and re.match(r"[\w-]+:", line):
            in_payload = False
            continue
        if re.fullmatch(r"\[[\w -]+\]", line):
            continue
        if line.startswith('- '):
            if not in_payload:
                warnings.append(f"line {number}: invalid YAML payload")
                continue
            if line.startswith('- "'):
                try:
                    line = json.loads(line[2:])
                except ValueError:
                    warnings.append(f"line {number}: invalid YAML payload")
                    continue
            else:
                match = re.fullmatch(r"- (?:'((?:[^']|'')*)'|([^'\"#\s].*))", line)
                if not match:
                    warnings.append(f"line {number}: invalid YAML payload")
                    continue
                line = match[1].replace("''", "'") if match[1] is not None else match[2]
        if line.startswith(('||', '@@||')) and '$' in line:
            warnings.append(f"line {number}: conditional ABP rule")
            continue
        host_parts = line.split()
        if host_parts and host_parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            if purpose != "block":
                warnings.append(f"line {number}: hosts entry is block-only")
                continue
            for domain in host_parts[1:]:
                if domain.startswith('#'):
                    break
                if _valid_domain("DOMAIN", domain):
                    rules.append(Rule("DOMAIN", domain))
                else:
                    warnings.append(f"line {number}: invalid hosts domain {domain}")
            continue
        allow = line.startswith('@@')
        options = ()
        abp = re.fullmatch(r"(?:@@)?\|\|([^|^/$]+)\^", line)
        bare_network = None
        if '/' in line and ',' not in line:
            try:
                bare_network = ipaddress.ip_network(line, strict=False)
            except ValueError:
                pass
        if abp:
            kind, value, action = "DOMAIN-SUFFIX", abp[1], ("" if allow else "REJECT")
        elif bare_network is not None:
            kind = "IP-CIDR6" if bare_network.version == 6 else "IP-CIDR"
            value, action = str(bare_network), ""
        elif _valid_domain("DOMAIN", line.removeprefix('.')):
            kind, value, action = ("DOMAIN-SUFFIX" if line.startswith('.') else "DOMAIN"), line.removeprefix('.'), ""
        else:
            try:
                parts = _fields(line)
            except ValueError:
                warnings.append(f"line {number}: unbalanced delimiters")
                continue
            if len(parts) < 2:
                warnings.append(f"line {number}: invalid rule")
                continue
            kind, value = parts[:2]
            if len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]:
                value = value[1:-1]
            kind = {
                "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX",
                "HOST-WILDCARD": "DOMAIN-WILDCARD", "HOST-KEYWORD": "DOMAIN-KEYWORD",
                "IP6-CIDR": "IP-CIDR6",
            }.get(kind.upper(), kind.upper())
            if kind in _PORTS and len(parts) > 3:
                end = 2
                while end < len(parts) - 1 and _valid_port(parts[end]):
                    end += 1
                if end > 2:
                    value = '/'.join(parts[1:end])
                    parts = [parts[0], value, *parts[end:]]
            if any(field.lower() == "extended-matching" for field in parts[2:]):
                warnings.append(f"line {number}: unsupported ruleset option extended-matching")
                continue
            options = tuple(field.lower() for field in parts[2:] if field.lower() == "no-resolve")
            actions = [field.upper() for field in parts[2:] if field.lower() != "no-resolve"]
            if len(actions) > 1:
                warnings.append(f"line {number}: unexpected fields")
                continue
            action = actions[0] if actions else ""
            if action == "LIST":
                action = ""
        if kind not in _KINDS:
            warnings.append(f"line {number}: unknown type {kind}")
            continue
        if kind == "SRC-IP" and '/' in value:
            kind = "SRC-IP-CIDR"
        if options and kind in {"SRC-IP", "SRC-IP-CIDR"}:
            warnings.append(f"line {number}: unsupported no-resolve for {kind}")
            options = ()
        if options and kind not in {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}:
            warnings.append(f"line {number}: unsupported no-resolve for {kind}")
            continue
        if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if kind == "IP-CIDR6" and network.version != 6:
                    raise ValueError("wrong address family")
                value = str(network)
            except ValueError:
                warnings.append(f"line {number}: invalid CIDR {value}")
                continue
        elif kind in _PORTS:
            if not _valid_port(value):
                warnings.append(f"line {number}: invalid port {value}")
                continue
            if '/' in value:
                port_kind = "DST-PORT" if kind == "DEST-PORT" else kind
                value = '(' + ','.join(f"({port_kind},{part})" for part in value.split('/')) + ')'
                kind = "OR"
            elif value.startswith(('<', '>')):
                value = _port_comparison(value)
        elif kind == "SRC-IP":
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                warnings.append(f"line {number}: invalid IP address {value}")
                continue
        elif kind in _SIMPLE:
            if not _valid_simple(kind, value):
                warnings.append(f"line {number}: invalid {kind} {value}")
                continue
        elif kind in _PROCESS:
            if not value or any(char in value for char in '<>\r\n'):
                warnings.append(f"line {number}: invalid value {value}")
                continue
            if kind in _REGEX:
                try:
                    re.compile(value)
                except re.error:
                    warnings.append(f"line {number}: invalid {kind} {value}")
                    continue
        elif kind in _LOGICAL:
            if not _valid_logic(kind, value):
                warnings.append(f"line {number}: invalid logical expression {value}")
                continue
        elif not (_valid_domain(kind, value) or kind == "DOMAIN" and _valid_domain("DOMAIN-SUFFIX", value)):
            warnings.append(f"line {number}: invalid domain {value}")
            continue
        if action and not ignore_policy and not (purpose == "block" and action in _BLOCK_ACTIONS or
                           action == purpose.upper() or
                           purpose in {"direct", "proxy"} and
                           action not in _BLOCK_ACTIONS | {"DIRECT", "PROXY"} and
                           not action.startswith("REJECT")):
            warnings.append(f"line {number}: incompatible action {action}")
        else:
            rules.append(Rule(kind, value, options, allow=allow))
    return rules, warnings


def parse_whitelist(text: str) -> list[Rule]:
    parsed, messages = parse(text, purpose="block", ignore_policy=True)
    supported = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
                 "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP", "IP-ASN", "GEOIP"}
    whitelist = [Rule(rule.kind, rule.value) for rule in parsed if rule.kind in supported]
    if not parsed and not messages:
        raise ValueError("no rules")
    if not whitelist and messages:
        raise ValueError(messages[0])
    for message in messages:
        warnings.warn(message, stacklevel=2)
    return whitelist


def exclude_covered(rules: Iterable[Rule], whitelist: Iterable[Rule]) -> list[Rule]:
    exact, suffixes, keywords, wildcards, typed = set(), set(), set(), set(), set()
    networks = {"src": set(), "dst": set()}
    for entry in whitelist:
        if entry.kind == "DOMAIN":
            exact.add(entry.value)
        elif entry.kind == "DOMAIN-SUFFIX":
            suffixes.add(entry.value)
        elif entry.kind == "DOMAIN-KEYWORD":
            keywords.add(entry.value)
        elif entry.kind == "DOMAIN-WILDCARD":
            wildcards.add(entry.value)
        elif entry.kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP"}:
            direction = "src" if entry.kind.startswith("SRC-") else "dst"
            networks[direction].add(ipaddress.ip_network(entry.value, strict=False))
        elif entry.kind in {"IP-ASN", "GEOIP"}:
            typed.add((entry.kind, entry.value.upper()))
    plain_wildcards = [pattern for pattern in wildcards if '[' not in pattern]
    kept = []
    for rule in rules:
        if rule.allow:
            kept.append(rule)
            continue
        kind, value = rule.kind, rule.value
        if kind == "DOMAIN" or (kind == "DOMAIN-WILDCARD" and not any(c in value for c in "*?[]")):
            covered = (value in exact or _has_parent(value, suffixes) or
                       any(keyword in value for keyword in keywords) or
                       any(fnmatchcase(value, pattern) for pattern in plain_wildcards))
        elif kind == "DOMAIN-SUFFIX":
            covered = _has_parent(value, suffixes) or any(keyword in value for keyword in keywords)
        elif kind == "DOMAIN-KEYWORD":
            covered = any(keyword in value for keyword in keywords)
        elif kind == "DOMAIN-WILDCARD":
            tail = value[max(value.rfind(char) for char in "*?]") + 1:]
            covered = (value in wildcards or
                       tail.startswith('.') and _has_parent(tail[1:], suffixes) or
                       any(keyword in segment for keyword in keywords
                           for segment in re.split(r"\*|\?|\[[a-z0-9-]+\]", value)))
        elif kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP"}:
            direction = "src" if kind.startswith("SRC-") else "dst"
            covered = False
            if networks[direction]:
                network = ipaddress.ip_network(value, strict=False)
                while True:
                    if network in networks[direction]:
                        covered = True
                        break
                    if network.prefixlen == 0:
                        break
                    network = network.supernet()
        else:
            covered = kind in {"IP-ASN", "GEOIP"} and (kind, value.upper()) in typed
        if not covered:
            kept.append(rule)
    return kept


def _has_parent(domain: str, parents: set[str]) -> bool:
    while domain:
        if domain in parents:
            return True
        domain = domain.partition('.')[2]
    return False


def normalize(rules: Iterable[Rule]) -> list[Rule]:
    unique = set(rules)
    suffixes = {}
    for rule in unique:
        if rule.kind == "DOMAIN-SUFFIX":
            suffixes.setdefault((rule.allow, rule.options), set()).add(rule.value)
    keywords = {}
    for rule in unique:
        if rule.kind == "DOMAIN-KEYWORD":
            keywords.setdefault((rule.allow, rule.options), set()).add(rule.value)
    kept = []
    for rule in unique:
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
            candidate = rule.value
            if rule.kind == "DOMAIN-WILDCARD":
                last_wildcard = max(candidate.rfind(char) for char in '*?]')
                tail = candidate[last_wildcard + 1:]
                candidate = tail.partition('.')[2]
            group = suffixes.get((rule.allow, rule.options), set())
            while candidate:
                if candidate in group and (rule.kind != "DOMAIN-SUFFIX" or candidate != rule.value):
                    break
                candidate = candidate.partition('.')[2]
            if candidate:
                continue
        if rule.kind == "DOMAIN-KEYWORD":
            group = keywords[(rule.allow, rule.options)]
            if any(rule.value[start:end] in group
                   for start in range(len(rule.value))
                   for end in range(start + 1, len(rule.value) + 1)
                   if end - start < len(rule.value)):
                continue
        kept.append(rule)
    networks = {}
    others = []
    for rule in kept:
        if rule.kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            network = ipaddress.ip_network(rule.value, strict=False)
            kind = "IP-CIDR6" if rule.kind == "IP-CIDR" and network.version == 6 else rule.kind
            networks.setdefault((kind, network.version, rule.options, rule.allow), []).append(network)
        else:
            others.append(rule)
    for (kind, _, options, allow), group in networks.items():
        others.extend(Rule(kind, str(network), options, allow)
                      for network in ipaddress.collapse_addresses(group))
    return sorted(others, key=lambda rule: (rule.kind, rule.value, rule.options, rule.allow))
