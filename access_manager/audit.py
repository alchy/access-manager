"""Auditni stopa realmu: JSONL, jeden radek = jedna udalost.

Denni soubory (audit/RRRR-MM-DD.jsonl) delaji z retence proste mazani
souboru a ze cteni rozsahu levnou operaci. Podrobne duvody odmitnuti
patri SEM - na drat jde jen ctverice tvaru. Tajemstvi ani kody se
neloguji nikdy; append je jediny os.write s O_APPEND, takze radky se
neproplitaji ani bez zamku.
"""
from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

ADRESAR = "audit"
MODE = 0o600


def append_event(root, event: dict, retention_days: int) -> None:
    adresar = Path(root) / ADRESAR
    zalozili_jsme = not adresar.exists()
    adresar.mkdir(mode=0o700, exist_ok=True)
    if zalozili_jsme:
        # mode= u mkdir podleha umask; chmod je nezavisly na nem. Cizi
        # (jiz existujici) adresar tim nepresahujeme.
        os.chmod(adresar, 0o700)
    dnes = datetime.now(UTC)
    cil = adresar / f"{dnes:%Y-%m-%d}.jsonl"
    if not cil.exists():
        _prune(adresar, retention_days)
    radek = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
    handle = os.open(cil, os.O_WRONLY | os.O_CREAT | os.O_APPEND, MODE)
    try:
        os.write(handle, radek.encode("utf-8"))
    finally:
        os.close(handle)


def _prune(adresar: Path, retention_days: int) -> None:
    """Smaz denni soubory starsi nez retence. Bezi jen pri zalozeni dne."""
    hranice = time.time() - retention_days * 86400
    for soubor in adresar.glob("*.jsonl"):
        try:
            stari = datetime.strptime(soubor.stem, "%Y-%m-%d")
        except ValueError:
            continue                     # cizi soubor neni nas ukol
        if stari.replace(tzinfo=UTC).timestamp() < hranice:
            soubor.unlink(missing_ok=True)


def recent_by_subject(root, subjects, *, kind=None, limit=5) -> dict[str, list]:
    """Poslednich `limit` udalosti pro kazdy subjekt, NEJNOVEJSI PRVNI.

    Nestavi se to na `read_events` schvalne. Ten precte cely rozsah dni,
    rozparsuje kazdy radek a teprve pak filtruje - pro vypis o stovkach
    identit by to znamenalo projit celou retenci jednou za kazdou z nich.
    Tady se cte od NEJNOVEJSIHO dne a konci se, jakmile ma kazdy hledany
    subjekt dost: u ciloveho pripadu (nedavno prihlaseni lide) staci prvni
    soubor nebo dva.

    Subjekty se predavaji uz hotove (`user:hana`), at tahle funkce nemusi
    vedet nic o tom, jak se skladaji principaly.
    """
    hledane = set(subjects)
    nalezene: dict[str, list] = {subjekt: [] for subjekt in hledane}
    adresar = Path(root) / ADRESAR
    if not hledane or not adresar.is_dir():
        return nalezene

    zbyva = set(hledane)
    for soubor in sorted(adresar.glob("*.jsonl"), reverse=True):
        if not zbyva:
            break
        for radek in reversed(soubor.read_text(encoding="utf-8").splitlines()):
            try:
                udalost = json.loads(radek)
            except json.JSONDecodeError:
                continue                 # viz `read_events` - jeden spatny
                                         # radek nesmi shodit vypis
            subjekt = udalost.get("subject")
            if subjekt not in zbyva:
                continue
            if kind and udalost.get("kind") != kind:
                continue
            nalezene[subjekt].append(udalost)
            if len(nalezene[subjekt]) >= limit:
                zbyva.discard(subjekt)
    return nalezene


def read_events(root, day_from=None, day_to=None, *, subject=None,
                outcome=None, kind=None, who=None, origin=None,
                component=None) -> list[dict]:
    """Precti udalosti s filtrem. Dny jako 'RRRR-MM-DD', vcetne.

    `subject` sedi PRESNE na pole `subject` - to je smlouva pro volajici
    z kodu. `who` je pro cloveka u konzole a je sirsi hned dvakrat: sedi na
    subjekt NEBO aktera (tedy na tyz sloupec, jaky ukazuje konzole - kdo
    filtruje podle toho, co v tabulce vidi, nesmi prijit o radky zapisu jen
    proto, ze u nich je jmeno pod jinym klicem) a porovnava se PODRETEZCEM,
    bez ohledu na velikost pismen.

    Podretezec je tataz uvaha jako u filtru nad vypisem lidi: spravce hleda
    "novak" a chce najit i "jan.novak@example.com". V auditu navic nese
    kazdy subjekt prefix (`user:`, `admin:`), takze presna shoda by ho
    nutila ho opsat - a dve vyhledavaci pole v teze konzoli se nemaji
    chovat ruzne.
    """
    adresar = Path(root) / ADRESAR
    if not adresar.is_dir():
        return []
    vysledek = []
    for soubor in sorted(adresar.glob("*.jsonl")):
        den = soubor.stem
        if day_from and den < day_from:
            continue
        if day_to and den > day_to:
            continue
        for radek in soubor.read_text(encoding="utf-8").splitlines():
            try:
                udalost = json.loads(radek)
            except json.JSONDecodeError:
                # Poskozeny/rucne pripsany radek nesmi shodit konzoli (jedineho
                # ctenare) - jeden spatny radek se jen preskoci, zbytek dne
                # se precte dal.
                continue
            if subject and udalost.get("subject") != subject:
                continue
            if who and not any(
                who in (udalost.get(klic) or "").lower()
                for klic in ("subject", "actor")
            ):
                continue
            if outcome and udalost.get("outcome") != outcome:
                continue
            if kind and udalost.get("kind") != kind:
                continue
            if origin and udalost.get("origin") != origin:
                continue
            if component and udalost.get("component") != component:
                continue
            vysledek.append(udalost)
    return vysledek
