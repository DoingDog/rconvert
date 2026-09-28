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
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}:
            object.__setattr__(self, "value", self.value.removesuffix(".").lower())


_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.I)
_PORTS = {"SRC-PORT", "DEST-PORT", "DST-PORT", "IN-PORT"}
_PROCESS = {"PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD",
            "PROCESS-PATH-WILDCARD", "USER-AGENT", "DOMAIN-REGEX", "URL-REGEX"}
_SIMPLE = {"IP-ASN", "GEOIP", "SRC-IP", "NETWORK", "PROTOCOL", "IN-TYPE", "DOMAIN-KEYWORD"}
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


def _valid_port(value: str) -> bool:
    ports = value.split('-')
    return (1 <= len(ports) <= 2 and
            all(port.isascii() and port.isdecimal() and 1 <= int(port) <= 65535
                for port in ports) and
            (len(ports) == 1 or int(ports[0]) <= int(ports[1])))


def _valid_simple(kind: str, value: str) -> bool:
    if kind == "IP-ASN":
        return value.isascii() and value.isdecimal() and int(value) > 0
    if kind == "SRC-IP":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if kind == "GEOIP":
        return bool(re.fullmatch(r"[a-z]{2}", value, re.I))
    if kind == "NETWORK":
        return value.upper() in {"TCP", "UDP"}
    if kind == "IN-TYPE":
        return bool(re.fullmatch(r"[\w-]+", value, re.ASCII))
    return bool(re.fullmatch(r"[a-z0-9._-]+", value, re.I))


def _valid_condition(expression: str) -> bool:
    if not expression.startswith('(') or not expression.endswith(')'):
        return False
    try:
        kind, value = _fields(expression[1:-1])
    except ValueError:
        return False
    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
        return _valid_domain(kind, value) or kind == "DOMAIN" and _valid_domain("DOMAIN-SUFFIX", value)
    if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
            return kind == "SRC-IP-CIDR" or network.version == (6 if kind == "IP-CIDR6" else 4)
        except ValueError:
            return False
    if kind in _PORTS:
        return _valid_port(value)
    if kind in _SIMPLE:
        return _valid_simple(kind, value)
    if kind in {"DOMAIN-REGEX", "URL-REGEX"}:
        try:
            re.compile(value)
            return bool(value)
        except re.error:
            return False
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


def parse(text: str, *, purpose: str, ignore_policy: bool = False) -> tuple[list[Rule], list[str]]:
    if purpose not in {"block", "direct", "proxy"}:
        raise ValueError(f"invalid purpose: {purpose}")
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(('#', ';', '//', '!')):
            continue
        if re.search(r"<\s*(?:/?[a-z][\w:-]*(?:\s[^>]*|/?)>|!doctype\b|!--)", line, re.I):
            return [], [f"line {number}: HTML document"]
    rules, warnings = [], []
    in_payload = False
    for number, source in enumerate(text.splitlines(), 1):
        line = source.strip()
        if not line or line.startswith(('#', ';', '//')):
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
                match = re.fullmatch(r"- (?:'([^']*)'|([^'\"#\s].*))", line)
                if not match:
                    warnings.append(f"line {number}: invalid YAML payload")
                    continue
                line = match[1] if match[1] is not None else match[2]
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
        if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if kind == "IP-CIDR" and network.version != 4 or kind == "IP-CIDR6" and network.version != 6:
                    raise ValueError("wrong address family")
                value = str(network)
            except ValueError:
                warnings.append(f"line {number}: invalid CIDR {value}")
                continue
        elif kind in _PORTS:
            if not _valid_port(value):
                warnings.append(f"line {number}: invalid port {value}")
                continue
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
            if kind in {"DOMAIN-REGEX", "URL-REGEX"}:
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
    for message in messages:
        warnings.warn(message, stacklevel=2)
    supported = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
                 "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP", "IP-ASN", "GEOIP"}
    return [Rule(rule.kind, rule.value) for rule in parsed if rule.kind in supported]


def _within(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith('.' + suffix)


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


def _wildcard_overlaps_exact(pattern: str, domain: str) -> bool:
    if '[' not in pattern:
        return fnmatchcase(domain, pattern)
    # Surge [] is not a shell glob character class; only an unrelated fixed suffix proves safety.
    last_wildcard = max(pattern.rfind(char) for char in '*?]')
    tail = pattern[last_wildcard + 1:]
    return not tail.startswith('.') or _within(domain, tail[1:])


def normalize(rules: Iterable[Rule], exclusions: Iterable[str] = ()) -> list[Rule]:
    exact, trees, literals, typed = set(), set(), set(), set()
    for exclusion in exclusions:
        value = exclusion.strip()
        if value.upper().startswith("DOMAIN,"):
            exact.add(Rule("DOMAIN", value.split(',', 1)[1].strip()).value)
        elif ',' in value and not value.startswith(','):
            kind, item = value.split(',', 1)
            typed.add((kind.upper(), Rule(kind, item.strip()).value))
        elif value:
            value = value.removeprefix(',').strip()
            if _valid_domain("DOMAIN", value):
                trees.add(Rule("DOMAIN", value).value)
            else:
                literals.add(value)
    unique = {rule for rule in rules if not (
        rule.kind == "DOMAIN" and rule.value in exact or
        (rule.kind, rule.value) in typed or rule.value in literals or
        rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and
        _has_parent(rule.value, trees)
    )}
    allowed = {rule.value for rule in unique if rule.allow and rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}}
    allow_suffixes = {rule.value for rule in unique if rule.allow and rule.kind == "DOMAIN-SUFFIX"}
    unique = {rule for rule in unique if not (
        not rule.allow and rule.kind == "DOMAIN" and
        (rule.value in allowed or _has_parent(rule.value, allow_suffixes))
    )}
    protected = exact | trees | allowed
    protected_trees = trees | allow_suffixes
    tree_ancestors = set()
    for tree in protected_trees:
        while tree:
            tree_ancestors.add(tree)
            tree = tree.partition('.')[2]
    protected_ancestors = set()
    protected_by_suffix = {}
    for domain in protected:
        suffix = domain
        while suffix:
            protected_ancestors.add(suffix)
            protected_by_suffix.setdefault(suffix, []).append(domain)
            suffix = suffix.partition('.')[2]
    for rule in sorted(unique, key=lambda item: (item.kind, item.value, item.options, item.allow)):
        conflicting_suffix = rule.kind == "DOMAIN-SUFFIX" and (
            rule.value in protected_ancestors or _has_parent(rule.value, allow_suffixes)
        )
        conflicting_wildcard = False
        if rule.kind == "DOMAIN-WILDCARD":
            last_wildcard = max(rule.value.rfind(char) for char in '*?]')
            tail = rule.value[last_wildcard + 1:]
            wildcard_candidates = protected_by_suffix.get(tail[1:], ()) if tail.startswith('.') else protected
            conflicting_wildcard = any(
                _wildcard_overlaps_exact(rule.value, excluded) for excluded in wildcard_candidates
            )
            if tail.startswith('.'):
                conflicting_wildcard |= tail[1:] in tree_ancestors or _has_parent(tail[1:], protected_trees)
            else:
                conflicting_wildcard |= bool(protected_trees)
        conflicting_keyword = rule.kind == "DOMAIN-KEYWORD" and (
            bool(trees | allow_suffixes) or any(rule.value in excluded for excluded in protected)
        )
        conflicting_regex = rule.kind == "DOMAIN-REGEX" and bool(protected)
        if not rule.allow and (conflicting_suffix or conflicting_wildcard or conflicting_keyword or conflicting_regex):
            unique.remove(rule)
            warnings.warn(f"excluded conflicting broad rule {rule.kind},{rule.value}", stacklevel=2)
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
            networks.setdefault((rule.kind, network.version, rule.options, rule.allow), []).append(network)
        else:
            others.append(rule)
    for (kind, _, options, allow), group in networks.items():
        others.extend(Rule(kind, str(network), options, allow)
                      for network in ipaddress.collapse_addresses(group))
    return sorted(others, key=lambda rule: (rule.kind, rule.value, rule.options, rule.allow))
