"""Per-run model and API-key entries (DR-20).

Keys live only in this process's memory. They are excluded from repr(), from every
serialisation helper, and from pickling. RepoAudit never receives a real key: each
RepoAudit entry gets an alias containing "gpt" (RepoAudit routes those to the OpenAI SDK),
and the local model gateway maps the alias to the real provider, model and key.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

PROVIDERS = {"openai": "OpenAI", "anthropic": "Claude (Anthropic)"}
# Development/test only: any OpenAI-compatible endpoint (e.g. a local Ollama server).
# Refused unless PWEXP_DEV=1; never offered in the menu; never allowed in a campaign cycle.
DEV_PROVIDERS = {"local": "OpenAI-compatible endpoint (dev only)"}


def dev_enabled() -> bool:
    return os.environ.get("PWEXP_DEV") == "1"


ROLES = ("repoaudit", "graph_qa")


class ModelEntryError(ValueError):
    pass


@dataclass
class ModelEntry:
    role: str
    provider: str
    model: str
    key: str = field(repr=False, compare=False)
    alias: str = ""
    base_url: str = ""  # only for the dev "local" provider

    def __post_init__(self):
        if self.role not in ROLES:
            raise ModelEntryError(f"role must be one of {ROLES}")
        allowed = {**PROVIDERS, **(DEV_PROVIDERS if dev_enabled() else {})}
        if self.provider not in allowed:
            raise ModelEntryError(f"provider must be one of {tuple(allowed)}")
        if self.provider == "local" and not self.base_url:
            raise ModelEntryError("the local provider needs a base_url")
        if not self.model.strip():
            raise ModelEntryError("model name required")
        if not self.key.strip():
            raise ModelEntryError("API key required for every model entry")

    def __reduce__(self):  # never pickle a key
        raise TypeError("ModelEntry holds a secret and cannot be serialised")

    def public(self) -> dict[str, str]:
        """What may be recorded: never the key."""
        return {"role": self.role, "provider": self.provider, "model": self.model, "alias": self.alias}

    @property
    def masked_key(self) -> str:
        return "●" * 8


class RunModels:
    """The in-memory model list for one run."""

    def __init__(self):
        self._entries: list[ModelEntry] = []

    def add(self, role: str, provider: str, model: str, key: str, base_url: str = "") -> ModelEntry:
        e = ModelEntry(role, provider, model.strip(), key.strip(), base_url=base_url.strip())
        if role == "graph_qa" and any(x.role == "graph_qa" for x in self._entries):
            raise ModelEntryError("only one Graph Q&A model per run; edit or remove the existing one")
        if role == "repoaudit":
            if any(x.role == "repoaudit" and x.provider == e.provider and x.model == e.model for x in self._entries):
                raise ModelEntryError("this RepoAudit model is already in the list")
            n = sum(1 for x in self._entries if x.role == "repoaudit") + 1
            e.alias = f"gpt-pw-m{n}"
        self._entries.append(e)
        return e

    def remove(self, index: int) -> None:
        del self._entries[index]
        for n, e in enumerate([x for x in self._entries if x.role == "repoaudit"], 1):
            e.alias = f"gpt-pw-m{n}"

    def entries(self, role: str | None = None) -> list[ModelEntry]:
        return [e for e in self._entries if role is None or e.role == role]

    def by_alias(self, alias: str) -> ModelEntry | None:
        return next((e for e in self._entries if e.alias == alias), None)

    def public(self) -> list[dict[str, str]]:
        return [e.public() for e in self._entries]

    def matches_protocol(self, declared: list[dict[str, str]]) -> bool:
        """Campaign rule: RepoAudit models must equal the locked declaration (DR-20)."""
        if any(e.provider not in PROVIDERS for e in self._entries):
            return False
        have = sorted((e.provider, e.model) for e in self.entries("repoaudit"))
        want = sorted((d.get("provider"), d.get("model")) for d in declared)
        return have == want

    def clear(self) -> None:
        for e in self._entries:
            e.key = ""
        self._entries.clear()
