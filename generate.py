import argparse
import os
import shutil
import sys
import tempfile
from http.client import IncompleteRead
from pathlib import Path
from typing import Callable
from urllib import error, request
from urllib.parse import urlsplit

from sources import load_config, load_sources, resolve_source


GROUPS = ("a2", "cdn", "a3", "a1", "big-data", "dirt")
PURPOSES = {"a1": "block", "a2": "block", "a3": "block", "cdn": "proxy", "big-data": "proxy", "dirt": "direct"}
MAX_BYTES = 64 * 1024 * 1024


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
                raise ValueError(f"HTML source rejected: {url}")
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(f"Source exceeds size limit: {url}")
            expected = getattr(response, "headers", {}).get("Content-Length")
            if expected is not None and len(data) != int(expected):
                raise ValueError(f"Incomplete source {url}: {len(data)} of {expected} bytes")
            if not data:
                raise ValueError(f"Source is empty: {url}")
            head = data[:1024].lstrip().removeprefix(b"\xef\xbb\xbf").lstrip().lower()
            if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
                raise ValueError(f"HTML source rejected: {url}")
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
        try:
            for temporary, path, backup in staged:
                os.replace(temporary, path)
                replaced.append((path, backup))
        except BaseException:
            for path, backup in reversed(replaced):
                if backup is None:
                    path.unlink()
                else:
                    os.replace(backup, path)
            raise


def generate(root: Path, fetch: Callable[[str], bytes]) -> dict[Path, str]:
    root = root.resolve()
    if not root.is_relative_to(Path(__file__).resolve().parent):
        raise ValueError("Source root escapes worktree")
    from formats import NO_RESOLVE_TYPES, render
    from rules import Rule, normalize, parse

    outputs: dict[Path, str] = {}
    cache: dict[str, bytes] = {}
    configs = load_config(root) if (root / "rulesets.json").exists() else None
    groups = ((item["name"], [resolve_source(root, entry) for entry in item["sources"]], item["purpose"])
              for item in configs) if configs is not None else (
                  (group, load_sources(root, group), PURPOSES[group]) for group in GROUPS)
    for group, sources, purpose in groups:
        rules = []
        for source in sources:
            if isinstance(source, Path):
                data = outputs[source].encode("utf-8") if source in outputs else source.read_bytes()
            else:
                if source not in cache:
                    cache[source] = fetch(source)
                data = cache[source]
            try:
                text = data.decode("utf-8-sig")
            except UnicodeError as exc:
                raise UnicodeError(f"Invalid UTF-8 in {source}: {exc}") from exc
            parsed, source_warnings = parse(text, purpose=purpose)
            for warning in source_warnings[:5]:
                print(f"{source}: {warning}", file=sys.stderr)
            if len(source_warnings) > 5:
                print(f"{source}: {len(source_warnings)} skipped lines; first five shown", file=sys.stderr)
            if not parsed:
                raise ValueError(f"No adaptable rules in {source}")
            rules.extend(parsed)
        exclusions_file = root / group / "attach" / "del.ini"
        exclusions = exclusions_file.read_text(encoding="utf-8-sig").splitlines() if exclusions_file.exists() else []
        if group != "dirt":
            rules = [Rule(rule.kind, rule.value, rule.options + ("no-resolve",), rule.allow)
                     if not rule.allow and rule.kind in NO_RESOLVE_TYPES else rule for rule in rules]
        rendered, skipped = render(group, normalize(rules, exclusions))
        for key, count in sorted(skipped.items()):
            print(f"{group} {key}: {count}", file=sys.stderr)
        if group in {"a1", "a2", "a3"}:
            exact = [item for item in exclusions if item.strip().upper().startswith("DOMAIN,")]
            adb_rules = set(normalize((rule for rule in rules if not rule.allow), exact))
            adb_rules.update(rule for rule in rules if rule.allow)
            for exclusion in exclusions:
                entry = exclusion.strip()
                if entry.startswith(',') or ',' not in entry:
                    parsed, _ = parse(entry.removeprefix(',').strip(), purpose="block")
                    if len(parsed) == 1 and parsed[0].kind == "DOMAIN":
                        adb_rules.add(Rule("DOMAIN-SUFFIX", parsed[0].value, allow=True))
            rendered["fin-adb.txt"] = render(group, adb_rules)[0]["fin-adb.txt"]
        outputs.update({root / group / name: text for name, text in rendered.items()})
    return outputs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    arguments = parser.parse_args()
    publish(generate(arguments.root, fetch_https))
