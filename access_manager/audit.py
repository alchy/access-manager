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
    adresar.mkdir(mode=0o700, exist_ok=True)
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


def read_events(root, day_from=None, day_to=None, *, subject=None,
                outcome=None, kind=None) -> list[dict]:
    """Precti udalosti s filtrem. Dny jako 'RRRR-MM-DD', vcetne."""
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
            udalost = json.loads(radek)
            if subject and udalost.get("subject") != subject:
                continue
            if outcome and udalost.get("outcome") != outcome:
                continue
            if kind and udalost.get("kind") != kind:
                continue
            vysledek.append(udalost)
    return vysledek
