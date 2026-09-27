from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    kind: str
    value: str
    options: tuple[str, ...] = ()
    allow: bool = False

    def __post_init__(self):
        kind = self.kind.upper()
        object.__setattr__(self, "kind", kind)
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}:
            object.__setattr__(self, "value", self.value.removesuffix(".").lower())
