"""Provozni log sluzby: jeden JSON objekt na radek.

Tohle NENI auditni stopa (`audit`). Ty dva zaznamy odpovidaji na jinou otazku
a maji proto jineho adresata:

  * `audit` je vecna stopa UVNITR realmu - kdo co udelal, jak dopadlo
    overeni. Lezi v `realm-<x>/audit/`, ma retenci a cte ji konzole.
  * `log` je stopa PROCESU - co odmitl driv, nez vubec vedel, o ktery realm
    jde, a jak se mu vede. Cte ji provozovatel na stroji.

Delici cara neni vkusova: auditni stopa je per-realm (`append_event` zapisuje
do `realm-<x>/`), takze udalost, ktera nastane driv, nez je realm urceny,
NEMA kam byt zapsana. Presne ta patri sem. Co realm zna, patri do auditu -
a nikam jinam, aby se dve mista nemusela drzet v souladu a aby rotace
provozniho logu nezahodila jedinou kopii.

Sdili API i konzole; ze stejneho duvodu jako `origin` to nesmi byt
zduplikovane u kazde aplikace zvlast.

Proud dela triaz
----------------
Bezny provoz jde na **stdout**, potize na **stderr**. Odmitnuty pozadavek
NENI chyba procesu - sluzba se prave zachovala spravne - a na chybovem
proudu nema co delat. Diky tomu znamena `stream` v kontejnerovem logu
konecne neco: `stdout` = provoz, `stderr` = podivej se na to.

Do logu NIKDY nesmi kod, klic ani hlavicka Authorization (spec §3). Podrobny
duvod odmitnuti sem naopak PATRI - ven, k volajicimu, jde porad jen ctverice
tvaru z `verdicts.OUTCOMES`.

Jen stdlib - modul musi jit importovat bez extras.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

#: Jmeno loggeru sluzby. Vse pod nim sdili handlery zapojene v `configure`.
LOGGER_NAME = "access_manager"

#: Strop delky jedne hodnoty. Neni to kosmetika: `name` a `realm` se loguji
#: i tehdy, kdyz NEPROSLY kontrolou tvaru, takze do nich muze prijit
#: libovolne dlouhe pole z formulare. Vzory v `principals` delku neomezuji,
#: takze strop musi byt tady. 256 pohodlne pojme cestu i FQDN - legitimni
#: hodnota se o nej neotre.
MAX_VALUE = 256

#: Klice, ktere si formatovac plni sam - pole udalosti je nesmi prebit.
_RESERVED = frozenset({"t", "level", "event"})

_logger = logging.getLogger(LOGGER_NAME)


def sanitize(value):
    """Ocisti hodnotu, nez se dostane do radku logu.

    Do logu jde i vstup, ktery NEPROSEL kontrolou tvaru - jinak by prave ten
    pokus stopu nemel, a to je ten, ktery provozovatel hleda. JSON sam
    escapuje novy radek, takze podvrzeni ciziho zaznamu tudy nehrozi;
    neomezena delka ano, a tu resi `MAX_VALUE`.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):   # bool je podtrida int - projde tudy
        return value
    if not isinstance(value, str):
        value = str(value)
    if len(value) > MAX_VALUE:
        return value[:MAX_VALUE] + "..."
    return value


class JsonFormatter(logging.Formatter):
    """Jeden JSON objekt na radek, klice v jednom jazyce s auditem.

    Razitko si pise sluzba sama: pod podmanem ho sice doplni log driver a pod
    systemd journald, ale kdo si presmeruje vystup do souboru, nema cas
    odnikud. UTC natvrdo, stejne jako `audit` - dva zaznamy teze udalosti se
    nesmi lisit zonou.
    """

    def format(self, record: logging.LogRecord) -> str:
        line = {
            "t": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="seconds"
            ),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
        }
        line.update(getattr(record, "fields", {}))
        return json.dumps(line, ensure_ascii=False, sort_keys=False)


class TextFormatter(logging.Formatter):
    """Tyz obsah jako `JsonFormatter`, ale ctitelny bez `jq`."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, UTC).isoformat(
            timespec="seconds"
        )
        fields = getattr(record, "fields", {})
        body = " ".join(
            "{}={}".format(key, "-" if value is None else value)
            for key, value in fields.items()
        )
        head = f"{stamp} {record.levelname.lower()} {record.getMessage()}"
        return f"{head}: {body}" if body else head


FORMATS = {"json": JsonFormatter, "text": TextFormatter}


class _LazyStreamHandler(logging.StreamHandler):
    """StreamHandler, ktery si proud najde az pri zapisu.

    `logging.StreamHandler` si `sys.stdout` navaze pri vzniku a drzi ho
    napevno. To je tise rozbite vsude, kde nekdo proudy prehodi POTOM -
    `contextlib.redirect_stdout`, pytestovy `capsys`, supervizor, ktery si
    vystup pretahne jinam: log by dal psal do proudu, ktery uz nikdo necte.
    Rozliseni az v okamziku zapisu to resi a nic nestoji.
    """

    def __init__(self, stream_name: str) -> None:
        self._stream_name = stream_name
        super().__init__()

    @property
    def stream(self):
        return getattr(sys, self._stream_name)

    @stream.setter
    def stream(self, _value) -> None:
        # StreamHandler.__init__ si sem chce ulozit navazany proud; drzime
        # si misto toho jen jeho jmeno, takze zapis zahazujeme.
        pass


class _BelowLevel(logging.Filter):
    """Pusti jen zaznamy POD danou uroven - druhou pulku bere druhy handler."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno < self.limit


def configure(level: str = "info", fmt: str = "json") -> None:
    """Zapoj handlery sluzby. Vola `server.main` hned po nacteni konfigurace.

    Dva handlery delene urovni, ne jeden: `WARNING` a vys jde na stderr,
    zbytek na stdout. Volani je idempotentni - opakovany start (nebo test,
    ktery si tovarnu postavi znovu) nesmi nasypat handlery na sebe a kazdy
    radek vypsat dvakrat.

    Nezname jmeno formatu NEzavira start: log neni duvod nenastartovat
    sluzbu, spadne se na `json`.
    """
    formatter = FORMATS.get(fmt.lower(), JsonFormatter)

    # Handlery se jen odpojuji, NEzaviraji: `close()` na sdilenem proudu by
    # zavrel `sys.stdout` celemu procesu.
    for old in list(_logger.handlers):
        _logger.removeHandler(old)

    routine = _LazyStreamHandler("stdout")
    routine.setFormatter(formatter())
    routine.addFilter(_BelowLevel(logging.WARNING))

    problems = _LazyStreamHandler("stderr")
    problems.setFormatter(formatter())
    problems.setLevel(logging.WARNING)

    _logger.addHandler(routine)
    _logger.addHandler(problems)
    _logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Bez tohohle by radky propadly jeste do korenoveho loggeru a vypsaly se
    # podruhe, kdyby si ho kdokoli (treba knihovna) zapojil.
    _logger.propagate = False

    # `waitress` si loguje pod svym jmenem; bez tohohle by jeho chyby sly
    # pres logging.lastResort na stderr uplne bez formatu.
    waitress = logging.getLogger("waitress")
    waitress.handlers = list(_logger.handlers)
    waitress.propagate = False


def _ensure_configured() -> None:
    """Zapoj vychozi handlery, kdyz `configure` jeste nebezel.

    Bez tohohle by radek propadl na `logging.lastResort`, ktery pousti az
    `WARNING` - a cely provozni log by TISE zmizel vsude, kde se aplikacni
    tovarna pouzije mimo `server.main`: v testech, ve vlastnim WSGI zavedeni,
    pod gunicornem. Tise mizejici log je horsi nez zadny, protoze se na nej
    da spolehnout az do chvile, kdy je potreba.
    """
    if not _logger.handlers:
        configure()


def info(event: str, **fields) -> None:
    """Bezny provoz -> stdout. Napr. odmitnuty pozadavek nebo prenacteni."""
    _ensure_configured()
    _logger.info(event, extra={"fields": _clean(fields)})


def warning(event: str, **fields) -> None:
    """Potiz, kterou ma provozovatel videt -> stderr."""
    _ensure_configured()
    _logger.warning(event, extra={"fields": _clean(fields)})


def _clean(fields: dict) -> dict:
    """Projed hodnoty `sanitize` a nedovol prebit klice formatovace."""
    return {
        key: sanitize(value)
        for key, value in fields.items()
        if key not in _RESERVED
    }
