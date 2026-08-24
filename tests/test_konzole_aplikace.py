"""Stranka Aplikace: seznam komponent, registrace s jednorazovym klicem
(vysledkova stranka klic.html - PRAVE JEDNOU, nikde jinde), odvolani.
Mirror vzoru z test_konzole_skupiny.py - mutace jsou vzdy POST + CSRF,
neuspesna registrace i odvolani se vraci flashem (Post/Redirect/Get);
uspesna registrace vyjimecne renderuje vysledek primo (viz brief).
"""
import re

import pytest
from helpers import REALM, koren

from access_manager import Admin
from access_manager.files import FileStore

_KLIC_RE = re.compile(r"am_k\d+_[0-9a-f]{64}")


def _zaregistruj(prihlaseny_klient, jmeno, origins="", detail=False):
    klient, csrf = prihlaseny_klient
    data = {"csrf": csrf, "jmeno": jmeno, "origins": origins}
    if detail:
        data["detail"] = "on"
    return klient.post("/aplikace/pridat", data=data)


def _klic_z_odpovedi(odpoved):
    shoda = _KLIC_RE.search(odpoved.get_data(as_text=True))
    assert shoda, "vysledkova stranka neobsahuje klic"
    return shoda.group(0)


def test_registration_shows_the_key_once_and_never_on_the_listing(
    prihlaseny_klient,
):
    odpoved = _zaregistruj(prihlaseny_klient, "core", origins="10.0.0.0/8")
    assert odpoved.status_code == 200
    klic = _klic_z_odpovedi(odpoved)

    klient, _ = prihlaseny_klient
    vypis = klient.get("/aplikace").get_data(as_text=True)
    assert klic not in vypis
    assert "core" in vypis


def test_the_fingerprint_is_shown_shortened_not_in_full(prihlaseny_klient, tmp_path):
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    klic = _klic_z_odpovedi(odpoved)

    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    komponenta = store.component_for_key(klic)
    assert komponenta is not None

    klient, _ = prihlaseny_klient
    vypis = klient.get("/aplikace").get_data(as_text=True)
    assert komponenta.key_hash[:12] in vypis
    assert komponenta.key_hash not in vypis


def test_registering_with_a_duplicate_name_flashes_an_error_and_leaves_state_unchanged(
    prihlaseny_klient,
):
    _zaregistruj(prihlaseny_klient, "core")
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    assert odpoved.status_code == 302

    klient, _ = prihlaseny_klient
    vypis = klient.get("/aplikace").get_data(as_text=True)
    assert "zprava-chyba" in vypis
    assert vypis.count(">core<") == 1


def test_revoking_an_application_removes_it_from_the_listing(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    klient, csrf = prihlaseny_klient

    odpoved = klient.post("/aplikace/core/odvolat", data={"csrf": csrf})
    assert odpoved.status_code == 302

    vypis = klient.get("/aplikace").get_data(as_text=True)
    assert "core" not in vypis


def test_the_registered_key_verifies_against_the_library(prihlaseny_klient, tmp_path):
    odpoved = _zaregistruj(prihlaseny_klient, "core", origins="10.0.0.0/8", detail=True)
    klic = _klic_z_odpovedi(odpoved)

    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    komponenta = store.component_for_key(klic)
    assert komponenta is not None
    assert komponenta.name == "core"
    assert komponenta.detail is True
    assert komponenta.origins == ("10.0.0.0/8",)


def test_every_mutating_route_without_csrf_is_rejected_and_state_unchanged(
    prihlaseny_klient, tmp_path,
):
    _zaregistruj(prihlaseny_klient, "core")
    klient, _ = prihlaseny_klient

    mutace = [
        ("/aplikace/pridat", {"jmeno": "jina"}),
        ("/aplikace/core/odvolat", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    vypis = klient.get("/aplikace").get_data(as_text=True)
    assert "core" in vypis
    assert "jina" not in vypis
    assert len(Admin.local(tmp_path / "data", realm=REALM).components()) == 1


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/aplikace"),
    ("post", "/aplikace/pridat"),
    ("post", "/aplikace/core/odvolat"),
])
def test_every_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    klient, _ = prihlaseny_klient

    vypis = klient.get("/aplikace?lang=en").get_data(as_text=True)
    assert "Applications" in vypis
    assert "Aplikace" not in vypis
