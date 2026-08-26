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


def _zaregistruj(prihlaseny_klient, jmeno, detail=False):
    """Prvni krok: aplikace a klic. Rozsahy registrace UZ NEBERE."""
    klient, csrf = prihlaseny_klient
    data = {"csrf": csrf, "jmeno": jmeno}
    if detail:
        data["detail"] = "on"
    return klient.post("/applications/add", data=data)


def _pridej_rozsah(prihlaseny_klient, jmeno, rozsah):
    """Povoleny rozsah. Jmeno je v CESTE - formular stoji v radku sve
    aplikace, takze cil je dany radkem. Rozsah zustava ve formulari:
    CIDR obsahuje lomitko a v ceste by se rozpadl."""
    klient, csrf = prihlaseny_klient
    return klient.post(
        f"/applications/{jmeno}/ranges/add",
        data={"csrf": csrf, "rozsah": rozsah},
    )


def _odeber_rozsah(prihlaseny_klient, jmeno, rozsah):
    klient, csrf = prihlaseny_klient
    return klient.post(
        f"/applications/{jmeno}/ranges/remove",
        data={"csrf": csrf, "rozsah": rozsah},
    )


def _klic_z_odpovedi(odpoved):
    shoda = _KLIC_RE.search(odpoved.get_data(as_text=True))
    assert shoda, "vysledkova stranka neobsahuje klic"
    return shoda.group(0)


def test_registration_shows_the_key_once_and_never_on_the_listing(
    prihlaseny_klient,
):
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    assert odpoved.status_code == 200
    klic = _klic_z_odpovedi(odpoved)

    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    assert klic not in vypis
    assert "core" in vypis


def test_the_fingerprint_is_shown_shortened_not_in_full(prihlaseny_klient, tmp_path):
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    klic = _klic_z_odpovedi(odpoved)

    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    komponenta = store.component_for_key(klic)
    assert komponenta is not None

    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    assert komponenta.key_hash[:12] in vypis
    assert komponenta.key_hash not in vypis


def test_registering_with_a_duplicate_name_flashes_an_error_and_leaves_state_unchanged(
    prihlaseny_klient,
):
    _zaregistruj(prihlaseny_klient, "core")
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    assert odpoved.status_code == 302

    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    assert "zprava-chyba" in vypis
    # Jmeno je na strance dvakrat: v tabulce a ve vyberu pro rozsahy.
    # Pocita se RADEK TABULKY, tam smi byt jen jeden.
    assert vypis.count('<td class="mono">core</td>') == 1


def test_adding_a_bad_cidr_range_flashes_an_error_and_changes_nothing(
    prihlaseny_klient,
):
    _zaregistruj(prihlaseny_klient, "core")
    odpoved = _pridej_rozsah(prihlaseny_klient, "core", "not-a-cidr")
    assert odpoved.status_code == 302

    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    assert "zprava-chyba" in vypis
    # Aplikace zustava, jen bez rozsahu - preklep nesmi shodit registraci.
    assert "core" in vypis
    # Hlaska chybnou hodnotu cituje (aby bylo videt, co bylo spatne), ale
    # ulozit se nesmela: v tabulce je porad "zadny rozsah".
    assert "zprava-chyba" in vypis
    assert 'class="chip chip-x"' not in vypis


def test_revoking_an_application_removes_it_from_the_listing(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    klient, csrf = prihlaseny_klient

    odpoved = klient.post("/applications/core/revoke", data={"csrf": csrf})
    assert odpoved.status_code == 302

    vypis = klient.get("/applications").get_data(as_text=True)
    assert "core" not in vypis


def test_the_registered_key_verifies_against_the_library(prihlaseny_klient, tmp_path):
    odpoved = _zaregistruj(prihlaseny_klient, "core", detail=True)
    klic = _klic_z_odpovedi(odpoved)
    _pridej_rozsah(prihlaseny_klient, "core", "10.0.0.0/8")

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
        ("/applications/add", {"jmeno": "jina"}),
        ("/applications/core/revoke", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    vypis = klient.get("/applications").get_data(as_text=True)
    assert "core" in vypis
    assert "jina" not in vypis
    assert len(Admin.local(tmp_path / "data", realm=REALM).components()) == 1


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/applications"),
    ("post", "/applications/add"),
    ("post", "/applications/core/revoke"),
])
def test_every_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_key_once_page_has_no_language_switch_link(prihlaseny_klient):
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    telo = odpoved.get_data(as_text=True)
    assert "/lang?to=" not in telo


def test_secret_bearing_pages_send_cache_control_no_store(prihlaseny_klient, tmp_path):
    Admin.local(tmp_path / "data", realm=REALM).add_user("tereza")
    klient, _ = prihlaseny_klient

    qr = klient.get("/users/qr/tereza")
    assert qr.headers.get("Cache-Control") == "no-store"

    klic_odpoved = _zaregistruj(prihlaseny_klient, "core")
    assert klic_odpoved.headers.get("Cache-Control") == "no-store"

    normalni = klient.get("/users")
    assert normalni.headers.get("Cache-Control") != "no-store"


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    klient, _ = prihlaseny_klient

    vypis = klient.get("/applications?lang=en").get_data(as_text=True)
    assert "Applications" in vypis
    assert "Aplikace" not in vypis


# == druhy krok: povolene IP rozsahy =======================================
#
# Registrace uz `origins` nebere. Rozsahy se pridavaji po jednom a jdou
# odebrat, aniz by se menil klic - v konzoli je to chip s krizkem.


def test_an_added_range_shows_up_as_a_chip(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    odpoved = _pridej_rozsah(prihlaseny_klient, "core", "10.42.0.0/16")
    assert odpoved.status_code == 302

    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    assert 'name="rozsah" value="10.42.0.0/16"' in vypis
    assert 'class="chip chip-x"' in vypis


def test_a_component_without_ranges_says_so_instead_of_showing_nothing(
    prihlaseny_klient,
):
    """Prazdny sloupec by vypadal jako 'zatim nevyplneno'. Ve skutecnosti
    to znamena, ze klic neprojde odnikud, a to se ma rict nahlas."""
    _zaregistruj(prihlaseny_klient, "core")
    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    assert "stav-no_credential" in vypis


def test_removing_a_range_takes_it_off_the_listing(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    _pridej_rozsah(prihlaseny_klient, "core", "10.42.0.0/16")
    _pridej_rozsah(prihlaseny_klient, "core", "192.168.1.7")

    odpoved = _odeber_rozsah(prihlaseny_klient, "core", "10.42.0.0/16")
    assert odpoved.status_code == 302

    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)
    # Na holy retezec se ptat nejde: `10.42.0.0/16` je i placeholder pole
    # pro pridani. Hleda se skryte pole formulare, ktery ten chip odebira.
    assert 'name="rozsah" value="10.42.0.0/16"' not in vypis
    assert 'name="rozsah" value="192.168.1.7"' in vypis


def test_the_key_survives_a_range_change(prihlaseny_klient, tmp_path):
    """Cely smysl druheho kroku: menit rozsahy bez vymeny klice."""
    odpoved = _zaregistruj(prihlaseny_klient, "core")
    klic = _klic_z_odpovedi(odpoved)
    _pridej_rozsah(prihlaseny_klient, "core", "10.42.0.0/16")
    _odeber_rozsah(prihlaseny_klient, "core", "10.42.0.0/16")

    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    assert store.component_for_key(klic) is not None


def test_an_empty_range_field_flashes_an_error(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    klient, csrf = prihlaseny_klient
    odpoved = klient.post(
        "/applications/core/ranges/add", data={"csrf": csrf, "rozsah": "  "}
    )
    assert odpoved.status_code == 302
    vypis = klient.get("/applications").get_data(as_text=True)
    assert "zprava-chyba" in vypis


def test_removing_a_range_that_is_not_there_flashes_an_error(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    odpoved = _odeber_rozsah(prihlaseny_klient, "core", "10.0.0.0/8")
    assert odpoved.status_code == 302
    klient, _ = prihlaseny_klient
    assert "zprava-chyba" in klient.get("/applications").get_data(as_text=True)


@pytest.mark.parametrize("cesta", [
    "/applications/core/ranges/add",
    "/applications/core/ranges/remove",
])
def test_range_routes_without_csrf_are_rejected_and_change_nothing(
    prihlaseny_klient, cesta,
):
    _zaregistruj(prihlaseny_klient, "core")
    _pridej_rozsah(prihlaseny_klient, "core", "10.42.0.0/16")
    klient, _ = prihlaseny_klient

    odpoved = klient.post(cesta, data={"rozsah": "10.42.0.0/16"})
    assert odpoved.status_code == 400

    vypis = klient.get("/applications").get_data(as_text=True)
    assert 'name="rozsah" value="10.42.0.0/16"' in vypis


@pytest.mark.parametrize("cesta", [
    "/applications/core/ranges/add",
    "/applications/core/ranges/remove",
])
def test_range_routes_without_a_session_redirect_to_login(prostredi, cesta):
    odpoved = prostredi.post(cesta, data={"rozsah": "10.0.0.0/8"})
    assert odpoved.status_code == 302
    assert "/login" in odpoved.headers["Location"]


# == uprava se dela tam, kde ta vec je ================================


def test_the_detail_flag_can_be_switched_from_the_listing(prihlaseny_klient):
    """Drive se `detail` dal nastavit JEN pri registraci - zmenit ho znamenalo
    odvolat a registrovat znovu, tedy vymenit klic ve vsech instalacich."""
    _zaregistruj(prihlaseny_klient, "core")
    klient, csrf = prihlaseny_klient

    vypis = klient.get("/applications").get_data(as_text=True)
    assert "Zapnout" in vypis

    klient.post("/applications/core/detail", data={"csrf": csrf, "detail": "on"})
    vypis = klient.get("/applications").get_data(as_text=True)
    assert "Vypnout" in vypis

    klient.post("/applications/core/detail", data={"csrf": csrf, "detail": "off"})
    assert "Zapnout" in klient.get("/applications").get_data(as_text=True)


def test_switching_detail_without_csrf_is_rejected(prihlaseny_klient):
    _zaregistruj(prihlaseny_klient, "core")
    klient, _ = prihlaseny_klient
    assert klient.post(
        "/applications/core/detail", data={"detail": "on"}
    ).status_code == 400


def test_the_range_form_lives_in_the_row_of_its_application(prihlaseny_klient):
    """Pridani a odebrani rozsahu drive stalo na dvou ruznych mistech: krizek
    v radku, ale pridani az na konci stranky s vyberem cile ze seznamu."""
    _zaregistruj(prihlaseny_klient, "core")
    _zaregistruj(prihlaseny_klient, "druha")
    klient, _ = prihlaseny_klient
    vypis = klient.get("/applications").get_data(as_text=True)

    # Kazda aplikace ma vlastni formular mirici na SVOU cestu.
    assert 'action="/applications/core/ranges/add"' in vypis
    assert 'action="/applications/druha/ranges/add"' in vypis
    # Zadny vyber cile ze seznamu uz na strance neni.
    assert "<select" not in vypis
