"""Spec nesmi popisovat endpointy, ktere neexistuji.

Duvod tohohle souboru je konkretni: `docs/design.md` byl navrh psany PRED
implementaci a nikdo ho s ni nesrovnal. Dokumentoval osm zapisovych
endpointu (`POST /v1/users`, `DELETE /v1/users/<jmeno>/credentials/totp`, ...),
ktere sluzba nikdy nemela, a naopak nevedel o `/v1/whoami`, ktery ma.
Kdo to cetl, nevedel, co ta sluzba vlastne dela.

Test proto pripina seznam v §3 na skutecnou `url_map`. Kdyz nekdo pridá
routu a zapomene na spec (nebo naopak), spadne to tady.
"""
import re
from pathlib import Path

from helpers import REALM
from test_config import zapis

from access_manager.config import load_config
from access_manager.server import create_app

SPEC = Path(__file__).resolve().parent.parent / "docs" / "design.md"


def _spec_endpointy() -> set[str]:
    """Cesty vyjmenovane v prehledu v §3 - z bloku za "API je ctecí"."""
    text = SPEC.read_text(encoding="utf-8")
    blok = text.split("**API je čtecí.**", 1)[1].split("```", 2)[1]
    # `<jméno>` je zástupce za konkretni jmeno; ve Flasku je to `<path:name>`.
    return {
        cesta.replace("/<jméno>", "/<>")
        for cesta in re.findall(r"/[a-z0-9/_.<>áéíóúýčďěňřšťůž-]+", blok)
    }


def _skutecne_endpointy(tmp_path) -> set[str]:
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json", {"name": REALM})
    app = create_app(load_config(tmp_path / "conf.d"))
    cesty = {
        re.sub(r"<[^>]+>", "<>", str(pravidlo))
        for pravidlo in app.url_map.iter_rules()
    }
    # `/static/<>` pridava Flask sam; do specu API nepatri.
    return cesty - {"/static/<>"}


def test_the_spec_lists_exactly_the_endpoints_that_exist(tmp_path):
    spec = _spec_endpointy()
    skutecne = _skutecne_endpointy(tmp_path)

    chybi_ve_specu = skutecne - spec
    neexistuji = spec - skutecne
    assert not chybi_ve_specu, f"routa mimo spec: {sorted(chybi_ve_specu)}"
    assert not neexistuji, f"spec slibuje neexistujici: {sorted(neexistuji)}"


def test_the_spec_does_not_promise_a_write_api(tmp_path):
    """Zapisuje se knihovnou nebo konzoli. Kdyby zapis visel na temz klici
    jako cteni, umi kazda aplikace zalozit identitu a vydat ji povereni."""
    zapisove = {
        str(pravidlo)
        for pravidlo in _skutecne_endpointy(tmp_path)
        if pravidlo.startswith("/v1/")
    }
    # Jediny POST, ktery neco meni, je `authenticate` (spotrebuje kod);
    # `principals/check` je dotaz, jen prilis dlouhy na query string.
    assert zapisove == {
        "/v1/authenticate", "/v1/principals/check", "/v1/users", "/v1/users/<>",
        "/v1/groups", "/v1/groups/<>", "/v1/whoami", "/v1/generation",
        "/v1/version",
    }
