from pathlib import Path

from formats import FILES
from sources import load_config


START = "<!-- RULE_COUNTS_START -->"
END = "<!-- RULE_COUNTS_END -->"


def update(root: Path) -> None:
    readme = root / "README.md"
    original = readme.read_bytes().decode("utf-8")
    if original.count(START) != 1 or original.count(END) != 1 or original.index(START) > original.index(END):
        raise ValueError("README rule count markers missing or duplicated")
    groups = [group["name"] for group in load_config(root)]
    rows = ["| 格式 | " + " | ".join(f"`{name}`" for name in groups) + " |",
            "| --- | " + " | ".join("---" for _ in groups) + " |"]
    for filename in FILES:
        counts = []
        for group in groups:
            text = (root / group / filename).read_text(encoding="utf-8")
            lines = text.splitlines()
            if filename == "fin-adb.txt" and lines[:1] == ["[Adblock Plus 2.0]"]:
                lines = lines[1:]
            count = sum(bool(line.strip()) and line.strip() != "payload:"
                        and not line.lstrip().startswith(("#", "!"))
                        for line in lines)
            counts.append(str(count))
        rows.append(f"| `{filename}` | " + " | ".join(counts) + " |")
    before, _, remainder = original.partition(START)
    _, _, after = remainder.partition(END)
    newline = "\r\n" if "\r\n" in original else "\n"
    updated = before + START + newline + newline.join(rows) + newline + END + after
    if updated != original:
        readme.write_bytes(updated.encode("utf-8"))


if __name__ == "__main__":
    update(Path(__file__).resolve().parent)
