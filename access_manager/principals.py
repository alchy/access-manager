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

#: Vyhrazena jmena skupin - hola, bez prefixu. Kazdy je dostava automaticky
#: (viz `USERS` a `PUBLIC`), takze zalozit je jako obycejne skupiny znamena
#: dve pravdy o temz jmene.
RESERVED_GROUPS = frozenset({"users", "public"})

#: Vydavatel ve stitku autentikatoru. Stejna syntaxe jako principal, takze se
#: clovek v telefonu jmenuje stejne jako v pravech.
ISSUER = "viewBase"

#: Jmeno se sklada do cesty i do principalu, takze je to VSTUP a chova se
#: jako vstup. Vsechna jmena se normalizuji na mala pismena: `Example.com`
#: a `example.com` nesmi byt dva realmy, `Jindrich` a `jindrich` dva lide.
_NAME = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")

#: Lide a spravci smi mit PRAVE JEDEN zavinac - identifikatorem muze byt
#: e-mailova adresa. Skupiny a realmy zavinac nemaji.
_IDENTITY = re.compile(
    r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*(@[a-z0-9_-]+(\.[a-z0-9_-]+)*)?$"
)


def _checked(name: str, vzor: re.Pattern, druh: str) -> str:
    text = str(name).strip().lower()
    if not vzor.match(text):
        raise ValueError(
            f"neplatne jmeno {name!r} ({druh}): povolena jsou mala pismena, "
            f"cislice, '-', '_' a tecka uvnitr"
        )
    return text


def check_name(name: str) -> str:
    """Jmeno skupiny. Over driv, nez se z nej stane cesta nebo principal."""
    return _checked(name, _NAME, "skupina")


def check_identity(name: str) -> str:
    """Jmeno cloveka nebo spravce - navic smi mit jeden zavinac."""
    return _checked(name, _IDENTITY, "identita")


def check_realm(name: str) -> str:
    """Nazev realmu - stejna pravidla jako skupina, FQDN projde."""
    return _checked(name, _NAME, "realm")


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


@dataclass(frozen=True, slots=True)
class Component:
    """Komponenta (aplikace) registrovana v realmu.

    Otisk klice se ulozi, samy klice se neulozuji. Klic se vraci pouze pri
    registraci a nikde se neuklada - ztracenych klicu se nevzpomin, vydaji se
    nove. Otisk klice neni tajemstvi a je viditelny i v repr.
    """

    name: str
    key_id: str
    key_hash: str
    origins: tuple[str, ...] = ()
    detail: bool = False
