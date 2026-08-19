"""Ucel dotazu: `login` nebo `unlock:<cil>`.

Anti-replay ma ucel. Tyz kod je legitimne potreba dvakrat behem jednoho
tricetisekundoveho okna (prihlaseni + krok navic) a autentikator mezitim zadny
novy nevyda - spolecny seznam pouzitych kodu napric vsim je chyba 3.6. Cil
u odemykani je tam ze stejneho duvodu o patro niz: kdo si rano odemkne mzdy
a hned nato terminal, narazil by jinak na tutez past.

Access-manager ucelu NEROZUMI. Je to nepruhledny klic prihradky; nekontroluje,
jestli `mzdy` je skutecne okno, o oknech nevi nic. Overuje jen TVAR - aby se
z volneho retezce nedalo udelat "pokazde novy ucel" a anti-replay tim vypnout.

Ucel sklada viewBase, ne divak: klient ho neposila, server ho sestavi z okna,
ktere se odemyka.
"""
from __future__ import annotations

import re

_PURPOSE = re.compile(r"^(login|unlock:[A-Za-z0-9_.:/-]{1,200})$")


def check_purpose(purpose: str) -> str:
    """Over tvar ucelu.

    Vyjimka, ne verdikt: spatny ucel je chyba volajiciho, ne udalost
    uzivatele. Verdikt by ji schoval mezi bezne odmitnuti.
    """
    text = str(purpose)
    if not _PURPOSE.match(text):
        raise ValueError(
            f"neplatny ucel {purpose!r}: cekam `login` nebo `unlock:<cil>`"
        )
    return text
