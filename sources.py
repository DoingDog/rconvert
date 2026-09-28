import json
import re
from pathlib import Path
from urllib.parse import urlsplit


def resolve_source(root: Path, entry: str) -> str | Path:
    if not isinstance(entry, str) or not entry or entry != entry.strip() or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in entry):
        raise ValueError(f"Invalid source: {entry}")
    try:
        url = urlsplit(entry)
        if url.scheme:
            if url.scheme != "https" or not url.hostname or "\\" in entry or any(char.isspace() for char in entry):
                raise ValueError(f"Invalid HTTPS source: {entry}")
            url.port
            return entry
    except ValueError as exc:
        raise ValueError(f"Invalid HTTPS source: {entry}") from exc
    root = root.resolve()
    relative = Path(entry.replace("\\", "/"))
    if relative.is_absolute():
        raise ValueError(f"Source must be relative to root: {entry}")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError(f"Source escapes root: {entry}")
    return path


def load_config(root: Path) -> list[dict]:
    root = root.resolve()
    groups = json.loads((root / "rulesets.json").read_text(encoding="utf-8-sig"))
    if not isinstance(groups, list) or not groups:
        raise ValueError("rulesets.json must be a nonempty ordered list")
    names = set()
    for group in groups:
        if not isinstance(group, dict) or not {"name", "purpose", "no_resolve", "sources", "whitelist"} <= group.keys():
            raise ValueError(f"Invalid ruleset group: {group}")
        name = group["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) or name in names:
            raise ValueError(f"Invalid or duplicate ruleset group name: {name}")
        names.add(name)
        if group["purpose"] not in ("block", "proxy", "direct") or group["no_resolve"] not in ("add", "strip", "keep"):
            raise ValueError(f"Invalid ruleset options: {name}")
        for key in ("sources", "whitelist"):
            entries = group[key]
            if not isinstance(entries, list) or (key == "sources" and not entries):
                raise ValueError(f"Invalid {key} for {name}")
            for entry in entries:
                resolve_source(root, entry)
    return groups
