"""Jmena, ktera nese drat.

Konstanty jsou tu ZNOVU, ne importem z `viewbase`. Access-manager je
samostatna komponenta a viewBase na ni nesmi zaviset opacnym smerem; tohle
jsou jmena PROTOKOLU, jako klice v JSONu - ne sdileny kod.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Kdo neni prihlaseny. Ma ho i prihlaseny clovek: prihlasenim se z verejnych
#: veci nevyvazuje.
PUBLIC = "group:public"

#: Kdo je prihlaseny - kdokoli se jmenem.
USERS = "group:users"

#: Jmeno se sklada do cesty i do principalu, takze je to VSTUP a chova se jako
#: vstup. Stejne pravidlo jako `viewbase.admin.check_name`.
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
