"""Preklady konzole. Kazdy text UI je klic do JSON katalogu.

Chybejici klic NIKDY neshodi stranku: spadne se na cestinu a pak na klic
samotny - preklep v sablone je videt, ne 500.
"""
from __future__ import annotations

import json
from functools import cache
from importlib import resources


@cache
def nacti(lang: str) -> dict[str, str]:
    # Cache sdili navraceny slovnik mezi vsemi volajicimi - kdo ho dostane,
    # smi jen cist, NIKDY nemenit na miste (jinak by zmena unikla vsem
    # ostatnim strankam i pozadavkum).
    jazyk = lang if lang in ("cs", "en") else "cs"
    zdroj = resources.files("access_manager.konzole.preklady") / f"{jazyk}.json"
    return json.loads(zdroj.read_text(encoding="utf-8"))


def prelozit(katalog: dict[str, str], klic: str) -> str:
    if klic in katalog:
        return katalog[klic]
    zaloha = nacti("cs")
    return zaloha.get(klic, klic)
