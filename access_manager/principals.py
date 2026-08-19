"""Jmena a zaznamy, ktere nese drat.

Konstanty jsou tu ZNOVU, ne importem z `viewbase`. Access-manager je
samostatna komponenta a viewBase na ni nesmi zaviset opacnym smerem; tohle
jsou jmena PROTOKOLU, jako klice v JSONu - ne sdileny kod. Ven se
neexportuji: dve definice tehoz jmena na drate by se jednou rozesly a byla
by to ticha chyba v pravech, ne pad.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: Kdo neni prihlaseny. Ma ho i prihlaseny clovek: prihlasenim se z verejnych
#: veci nevyvazuje.
PUBLIC = "group:public"

#: Kdo je prihlaseny - kdokoli se jmenem.
USERS = "group:users"

#: Vydavatel ve stitku autentikatoru. Stejna syntaxe jako principal, takze se
#: clovek v telefonu jmenuje stejne jako v pravech.
ISSUER = "viewBase"

#: Jmeno se sklada do cesty i do principalu, takze je to VSTUP a chova se jako
#: vstup: jen pismena, cislice, tecka uvnitr, pomlcka a podtrzitko.
_NAME = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")


def check_name(name: str) -> str:
    """Over jmeno driv, nez se z nej stane cesta nebo principal."""
    text = str(name).strip()
    if not _NAME.match(text):
        raise ValueError(
            f"neplatne jmeno {name!r}: povolena jsou pismena, cislice, '-', '_' "
            f"a tecka uvnitr"
        )
    return text


@dataclass(frozen=True, slots=True)
class User:
    """Kdo to je - PLOCHE, uz rozbalene.

    `principals` je tranzitivni uzaver, ne prime clenstvi: je to nejcastejsi
    dotaz vubec a zaroven presne to, co potrebuje `allowed(principals, acl)`.
    """

    name: str
    subject_id: str
    enabled: bool = True
    principals: frozenset[str] = field(default_factory=frozenset)

    def is_in(self, principal: str) -> bool:
        """Patri clovek pod tenhle principal?

        Je to dotaz nad uzaverem, ktery uz mas v ruce - ne druha cesta po
        siti. Dve mista, kde se pocita prislusnost, znamenaji jedno spatne.
        """
        return principal in self.principals


@dataclass(frozen=True, slots=True)
class Group:
    """Skupina tak, JAK JE NAPSANA - nerozbalena.

    Rozbaluje se az pri dotazu na cloveka. Kdyby se rozbalovalo pri zapisu,
    pridani cloveka do skupiny by nezabralo na ACL, ktera uz existuji.
    """

    name: str
    members: tuple[str, ...] = ()
    includes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Enrolment:
    """Vysledek zavedeni. TAJEMSTVI TU NENI a nebude.

    Repr konci v logu, v tracebacku a v ladicim vypisu - kdyby v nem tajemstvi
    bylo, unikne prvni vyjimkou. Kdo ho potrebuje, precte si soubor.
    """

    name: str
    directory: Path
    label: str

    @property
    def principal(self) -> str:
        return f"user:{self.name}"
