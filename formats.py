import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable

from rules import Rule


FILES = ("fin.txt", "fin-qx.txt", "fin.yaml", "fin-adb.txt", "fin-surge.txt", "fin-surge-ds.txt")
DOMAIN_SET_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
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
SURGE_ALIASES = {"SRC-IP-CIDR": "SRC-IP", "DST-PORT": "DEST-PORT", "PROCESS-NAME-WILDCARD": "PROCESS-NAME", "PROCESS-PATH": "PROCESS-NAME"}
LOGICAL = {"AND", "OR", "NOT"}


def _logical_value(value: str, operator: str, supported: set[str]) -> str | None:
    if operator == "NOT" and value.startswith("(") and not value.startswith("(("):
        value = f"({value})"
    if not value.startswith("((") or not value.endswith("))"):
        return None
    parts = []
    index = 1
    while index < len(value) - 1:
        if value[index] != "(":
            return None
        start = index + 1
        index, depth, in_class, escaped = start, 1, False, False
        while index < len(value) and depth:
            char = value[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "[":
                in_class = True
            elif char == "]" and in_class:
                in_class = False
            elif not in_class:
                depth += (char == "(") - (char == ")")
            index += 1
        if depth or index >= len(value):
            return None
        kind, separator, payload = value[start:index - 1].partition(",")
        if not separator or not payload or kind not in supported:
            return None
        if kind in LOGICAL:
            payload = _logical_value(payload, kind, supported)
            if payload is None:
                return None
        elif supported is MIHOMO_TYPES and kind == "DOMAIN-WILDCARD" and any(c in payload for c in "[]"):
            return None
        if supported is SURGE_TYPES:
            kind = SURGE_ALIASES.get(kind, kind)
            if kind == "IP-CIDR" and ":" in payload:
                kind = "IP-CIDR6"
        parts.append(f"({kind},{payload})")
        if value[index] == ")":
            if index != len(value) - 1:
                return None
            break
        if value[index] != ",":
            return None
        index += 1
    if (len(parts) != 1 if operator == "NOT" else len(parts) < 2):
        return None
    return "(" + ",".join(parts) + ")"


def _dns_pattern(rule: Rule) -> str | None:
    if rule.kind == "DOMAIN":
        return rule.value
    if rule.kind == "DOMAIN-SUFFIX":
        return f"||{rule.value}^"
    if "/" in rule.value:
        return None
    if rule.kind == "DOMAIN-KEYWORD":
        return f"/^.*{re.escape(rule.value)}.*$/"
    if rule.kind == "DOMAIN-WILDCARD" and not any(char in rule.value for char in "[]"):
        pattern = re.escape(rule.value).replace(r"\*", ".*").replace(r"\?", ".")
        return f"/^{pattern}$/"
    return None


def render(group: str, rules: Iterable[Rule], *, purpose: str, no_resolve: str,
           whitelist: Iterable[Rule] = ()) -> tuple[dict[str, str], dict[str, int]]:
    lines = {name: [] for name in FILES}
    skipped = Counter()
    for rule in sorted(rules, key=lambda item: (item.kind, item.value, item.options, item.allow)):
        kind, value = rule.kind, rule.value
        if no_resolve == "strip":
            rule = Rule(kind, value, tuple(option for option in rule.options if option != "no-resolve"), rule.allow)
        elif no_resolve == "add" and not rule.allow and kind in NO_RESOLVE_TYPES:
            rule = Rule(kind, value, rule.options + ("no-resolve",))
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
                surge_kind = "IP-CIDR6" if kind == "IP-CIDR" and ":" in value else kind
                for name in ("fin.txt", "fin-surge.txt"):
                    lines[name].append(f"{surge_kind},{value},no-resolve")
                    emitted.add(name)
                lines["fin.yaml"].append("  - " + json.dumps(text + ",no-resolve", ensure_ascii=False))
                emitted.add("fin.yaml")
                if kind in QX_TYPES:
                    qx_kind = "IP6-CIDR" if kind == "IP-CIDR" and ":" in value else QX_TYPES[kind]
                    lines["fin-qx.txt"].append(f"{qx_kind},{value},LIST,no-resolve")
                    emitted.add("fin-qx.txt")
        else:
            surge_value = _logical_value(value, kind, SURGE_TYPES) if logical else value
            if not logical and "," in value:
                quote = next((mark for mark in ("'", '"') if mark not in value), None)
                surge_value = f"{quote}{value}{quote}" if quote else None
            if (kind in SURGE_TYPES or kind == "PROCESS-NAME-WILDCARD" or
                    kind == "PROCESS-PATH" and value.startswith('/') or
                    kind == "NETWORK" and value.upper() in {"TCP", "UDP"}) and surge_value is not None:
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
            mihomo_value = _logical_value(value, kind, MIHOMO_TYPES) if logical else value
            if kind == "SRC-IP":
                address = ipaddress.ip_address(value)
                mihomo_kind, mihomo_value = "SRC-IP-CIDR", f"{address}/{address.max_prefixlen}"
            if kind == "PROTOCOL" and value.upper() in {"TCP", "UDP"}:
                mihomo_kind, mihomo_value = "NETWORK", value.lower()
            if mihomo_kind in MIHOMO_TYPES and mihomo_value is not None and not (
                kind == "DOMAIN-WILDCARD" and any(c in value for c in "[]")
            ):
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
    out = {name: f"{'!' if name == 'fin-adb.txt' else '#'} {group} rules: {len(body)}\n"
           + ("payload:\n" if name == "fin.yaml" else "") + "".join(line + "\n" for line in body)
           for name, body in lines.items()}
    if purpose != "block":
        out["fin-adb.txt"] += "! No AdBlock rules for non-advertising group.\n"
    return out, dict(skipped)
