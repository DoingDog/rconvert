from pathlib import Path
from urllib.parse import urlsplit


def load_sources(root: Path, group: str) -> list[str | Path]:
    root = root.resolve()
    config = (root / group / "attach" / "rule-list.ini").resolve()
    if not config.is_relative_to(root):
        raise ValueError(f"Group escapes root: {group}")
    sources: list[str | Path] = []
    for line in config.read_text(encoding="utf-8-sig").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        url = urlsplit(entry)
        if url.scheme:
            if url.scheme != "https" or not url.hostname:
                raise ValueError(f"Invalid HTTPS source: {entry}")
            try:
                url.port
            except ValueError as exc:
                raise ValueError(f"Invalid HTTPS source: {entry}") from exc
            sources.append(entry)
        else:
            path = (config.parent / entry.replace("\\", "/")).resolve()
            if not path.is_relative_to(root):
                raise ValueError(f"Source escapes root: {entry}")
            sources.append(path)
    return sources
