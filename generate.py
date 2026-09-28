import argparse
import gzip
import os
import shutil
import sys
import tempfile
import zlib
from io import BytesIO
from http.client import IncompleteRead
from pathlib import Path
from typing import Callable
from urllib import error, request
from urllib.parse import urlsplit

from sources import load_config, resolve_source


MAX_BYTES = 64 * 1024 * 1024


class _UnusableSource(ValueError):
    pass


class _HttpsOnlyRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise ValueError(f"HTTPS redirect required: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_https(url: str) -> bytes:
    if urlsplit(url).scheme != "https":
        raise ValueError(f"HTTPS required: {url}")
    opener = request.build_opener(_HttpsOnlyRedirect())
    opener.addheaders = [("User-Agent", "Mozilla/5.0")]
    try:
        with opener.open(url, timeout=30) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise ValueError(f"HTTPS redirect required: {url}")
            if getattr(response, "status", 200) != 200:
                raise ValueError(f"Unexpected HTTP status {response.status}: {url}")
            if "text/html" in getattr(response, "headers", {}).get("Content-Type", "").lower():
                raise _UnusableSource(f"HTML source rejected: {url}")
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(f"Source exceeds size limit: {url}")
            expected = getattr(response, "headers", {}).get("Content-Length")
            if expected is not None and len(data) != int(expected):
                raise ValueError(f"Incomplete source {url}: {len(data)} of {expected} bytes")
            if getattr(response, "headers", {}).get("Content-Encoding", "").lower() == "gzip":
                try:
                    with gzip.GzipFile(fileobj=BytesIO(data)) as stream:
                        data = stream.read(MAX_BYTES + 1)
                except (EOFError, OSError, zlib.error) as exc:
                    raise RuntimeError(f"Incomplete or invalid gzip source {url}: {exc}") from exc
                if len(data) > MAX_BYTES:
                    raise ValueError(f"Decompressed source exceeds size limit: {url}")
            if not data:
                raise _UnusableSource(f"Source is empty: {url}")
            head = data[:1024].lstrip().removeprefix(b"\xef\xbb\xbf").lstrip().lower()
            if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
                raise _UnusableSource(f"HTML source rejected: {url}")
            return data
    except (error.URLError, TimeoutError, IncompleteRead) as exc:
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc


def publish(outputs: dict[Path, str]) -> None:
    root = Path(__file__).resolve().parent
    if any(not path.resolve().is_relative_to(root) for path in outputs):
        raise ValueError("Output path escapes worktree")
    if any(path.resolve().is_relative_to(root / "static") for path in outputs):
        raise ValueError("Output path targets static")
    staging = root / ".tmp"
    staging.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=staging) as directory:
        staged = []
        for index, (path, text) in enumerate(outputs.items()):
            temporary = Path(directory) / f"{index}.new"
            backup = Path(directory) / f"{index}.old"
            temporary.write_bytes(text.encode("utf-8"))
            if path.exists():
                shutil.copyfile(path, backup)
            staged.append((temporary, path, backup if path.exists() else None))
        replaced = []
        created = []
        try:
            for temporary, path, backup in staged:
                for parent in reversed([parent for parent in (path.parent, *path.parent.parents)
                                        if not parent.exists()]):
                    parent.mkdir()
                    created.append(parent)
                os.replace(temporary, path)
                replaced.append((path, backup))
        except BaseException:
            for path, backup in reversed(replaced):
                if backup is None:
                    path.unlink()
                else:
                    os.replace(backup, path)
            for parent in reversed(created):
                parent.rmdir()
            raise


def generate(root: Path, fetch: Callable[[str], bytes]) -> dict[Path, str]:
    root = root.resolve()
    if not root.is_relative_to(Path(__file__).resolve().parent):
        raise ValueError("Source root escapes worktree")
    from formats import FILES, NO_RESOLVE_TYPES, render
    from rules import Rule, exclude_covered, normalize, parse, parse_whitelist

    configs = load_config(root)
    generated = {root / config["name"] / name for config in configs for name in FILES}
    outputs: dict[Path, str] = {}
    cache: dict[str, bytes | None] = {}
    frozen: set[str] = set()

    def freeze(group: str) -> None:
        for name in FILES:
            path = root / group / name
            if not path.is_file() or not path.stat().st_size:
                raise ValueError(f"Cannot freeze {group}: missing complete old file {path}")
        frozen.add(group)

    def read(source: str | Path) -> str | None:
        if isinstance(source, Path):
            if source in generated and source not in outputs:
                raise ValueError(f"Dependent output not yet generated: {source}")
            data = outputs[source].encode("utf-8") if source in outputs else source.read_bytes()
        else:
            if source not in cache:
                try:
                    cache[source] = fetch(source)
                except RuntimeError as exc:
                    if not isinstance(exc.__cause__, error.HTTPError) or exc.__cause__.code != 404:
                        raise
                    print(f"{source}: HTTP 404; skipped", file=sys.stderr)
                    cache[source] = None
                except _UnusableSource as exc:
                    print(f"{source}: {exc}; skipped", file=sys.stderr)
                    cache[source] = None
            data = cache[source]
            if data is None:
                return None
        if isinstance(source, str):
            text = data.decode("utf-8-sig", errors="surrogateescape")
            lines = []
            bad = 0
            for number, line in enumerate(text.splitlines(keepends=True), 1):
                if any("\udc80" <= char <= "\udcff" for char in line):
                    bad += 1
                    if bad <= 5:
                        print(f"{source}: line {number}: invalid UTF-8; skipped", file=sys.stderr)
                    lines.append("\n")
                else:
                    lines.append(line)
            if bad > 5:
                print(f"{source}: {bad} invalid UTF-8 lines; first five shown", file=sys.stderr)
            return "".join(lines)
        try:
            return data.decode("utf-8-sig")
        except UnicodeError as exc:
            raise UnicodeError(f"Invalid UTF-8 in {source}: {exc}") from exc

    local_whitelists = {}
    for config in configs:
        for entry in config["whitelist"]:
            source = resolve_source(root, entry)
            if isinstance(source, Path) and source not in generated and source not in local_whitelists:
                text = read(source)
                try:
                    local_whitelists[source] = parse_whitelist(text)
                except ValueError as exc:
                    raise ValueError(f"Invalid whitelist {source}: {exc}") from exc

    for config in configs:
        group, purpose, no_resolve = config["name"], config["purpose"], config["no_resolve"]
        if any(isinstance(source := resolve_source(root, entry), Path) and
               source in generated and source.parent.name in frozen
               for entry in config["sources"] + config["whitelist"]):
            freeze(group)
            continue
        rules = []
        for entry in config["sources"]:
            source = resolve_source(root, entry)
            text = read(source)
            if text is None:
                continue
            parsed, source_warnings = parse(text, purpose=purpose)
            for warning in source_warnings[:5]:
                print(f"{source}: {warning}", file=sys.stderr)
            if len(source_warnings) > 5:
                print(f"{source}: {len(source_warnings)} skipped lines; first five shown", file=sys.stderr)
            if not parsed:
                if isinstance(source, Path):
                    raise ValueError(f"No adaptable rules in {source}")
                print(f"{source}: no adaptable rules; skipped", file=sys.stderr)
                continue
            rules.extend(parsed)
        whitelist = []
        for entry in config["whitelist"]:
            source = resolve_source(root, entry)
            if source in local_whitelists:
                whitelist.extend(local_whitelists[source])
                continue
            text = read(source)
            if text is None:
                continue
            try:
                selected = parse_whitelist(text)
                if not selected and isinstance(source, str):
                    print(f"{source}: no supported whitelist rules; skipped", file=sys.stderr)
                whitelist.extend(selected)
            except ValueError as exc:
                if isinstance(source, Path):
                    raise ValueError(f"Invalid whitelist {source}: {exc}") from exc
                print(f"{source}: invalid whitelist ({exc}); skipped", file=sys.stderr)
        if not rules:
            freeze(group)
            continue
        allowed = [rule for rule in rules if rule.allow]
        rules = exclude_covered(rules, whitelist + allowed)
        if no_resolve == "add":
            rules = [Rule(rule.kind, rule.value, rule.options + ("no-resolve",), rule.allow)
                     if not rule.allow and rule.kind in NO_RESOLVE_TYPES else rule for rule in rules]
        elif no_resolve == "strip":
            rules = [Rule(rule.kind, rule.value, tuple(option for option in rule.options if option != "no-resolve"), rule.allow)
                     for rule in rules]
        rendered, skipped = render(group, normalize(rules), purpose=purpose,
                                   whitelist=whitelist, no_resolve=no_resolve)
        if not any(rendered[name].splitlines()[1:] for name in ("fin.txt", "fin-qx.txt", "fin-surge.txt")) and len(rendered["fin.yaml"].splitlines()) <= 2:
            print(f"{group}: no routable rules; frozen", file=sys.stderr)
            freeze(group)
            continue
        for key, count in sorted(skipped.items()):
            print(f"{group} {key}: {count}", file=sys.stderr)
        outputs.update({root / group / name: text for name, text in rendered.items()})
    return outputs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    arguments = parser.parse_args()
    publish(generate(arguments.root, fetch_https))
