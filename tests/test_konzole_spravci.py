"""Stranka Spravci: vypis se stitkem a stavem parovani, pridani (-> QR
sdilena s lide), odebrani, odvolani tokenu, nove parovani; guard posledniho
spravce. Mirror vzoru z test_konzole_lide.py - mutace jsou vzdy POST + CSRF,
uspech i chyba se vraci flashem (Post/Redirect/Get).
"""
import pytest
from helpers import REALM, admin_kody, koren

from access_manager import Admin
from access_manager.files import FileStore


def _pridej(prihlaseny_klient, jmeno):
    klient, csrf = prihlaseny_klient
    return klient.post("/spravci/pridat", data={"csrf": csrf, "jmeno": jmeno})


def test_adding_an_admin_redirects_to_a_qr_page_without_the_secret(
    prihlaseny_klient, tmp_path,
):
    odpoved = _pridej(prihlaseny_klient, "marie")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/spravci/qr/marie")

    klient, _ = prihlaseny_klient
    stranka = klient.get(odpoved.headers["Location"])
    telo = stranka.get_data(as_text=True)
    assert "<pre" in telo
    assert f"{REALM}-admin-marie" in telo

    tajemstvi = (
        koren(tmp_path / "data") / "admin-marie" / "totp.secret"
    ).read_text(encoding="utf-8").strip()
    assert tajemstvi not in telo

    seznam = klient.get("/spravci").get_data(as_text=True)
    assert tajemstvi not in seznam


def test_listing_shows_waiting_then_paired_then_no_credential_after_revoke(
    prihlaseny_klient, tmp_path,
):
    klient, csrf = prihlaseny_klient
    _pridej(prihlaseny_klient, "marie")

    cekajici = klient.get("/spravci").get_data(as_text=True)
    assert f"{REALM}-admin-marie" in cekajici
    assert "Čeká" in cekajici

    # Prvni skutecne prihlaseni dokoncuje parovani (viz
    # FileStore._complete_pairing) - presne stejny mechanismus, ktery
    # POST /login pouziva uvnitr.
    prvni, druhy = admin_kody(tmp_path / "data", jmeno="marie")
    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    assert store.authenticate_admin("marie", prvni, druhy)

    sparovano = klient.get("/spravci").get_data(as_text=True)
    assert "Spárováno" in sparovano

    klient.post("/spravci/marie/odvolat", data={"csrf": csrf})
    bez_povereni = klient.get("/spravci").get_data(as_text=True)
    assert "Bez pověření" in bez_povereni
    # "Sparovano" uz zbyva jen u jindricha (fixtura ho prihlasi hned na
    # zacatku) - marie po odvolani ne.
    assert bez_povereni.count("Spárováno") == 1


def test_revoke_then_pair_produces_a_new_qr(prihlaseny_klient):
    prvni_odpoved = _pridej(prihlaseny_klient, "marie")
    klient, csrf = prihlaseny_klient
    prvni_qr = klient.get(prvni_odpoved.headers["Location"]).get_data(as_text=True)

    odvolat = klient.post("/spravci/marie/odvolat", data={"csrf": csrf})
    assert odvolat.status_code == 302

    telo = klient.get("/spravci").get_data(as_text=True)
    assert "Bez pověření" in telo

    parovat = klient.post("/spravci/marie/parovat", data={"csrf": csrf})
    assert parovat.status_code == 302
    assert parovat.headers["Location"].endswith("/spravci/qr/marie")

    druhy_qr = klient.get(parovat.headers["Location"]).get_data(as_text=True)
    assert "<pre" in druhy_qr
    assert druhy_qr != prvni_qr


def test_qr_page_rejects_an_invalid_identity_with_404(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    odpoved = klient.get("/spravci/qr/marie!")
    assert odpoved.status_code == 404


def test_the_last_admin_cannot_be_removed_and_state_is_unchanged(
    prihlaseny_klient, tmp_path,
):
    klient, csrf = prihlaseny_klient
    odpoved = klient.post("/spravci/jindrich/odebrat", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/spravci").get_data(as_text=True)
    assert "zprava-chyba" in telo
    assert "posledni spravce" in telo
    assert Admin.local(tmp_path / "data", realm=REALM).admins() == ["jindrich"]


def test_the_last_admins_token_cannot_be_revoked_and_state_is_unchanged(
    prihlaseny_klient, tmp_path,
):
    klient, csrf = prihlaseny_klient
    odpoved = klient.post("/spravci/jindrich/odvolat", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/spravci").get_data(as_text=True)
    assert "zprava-chyba" in telo
    assert "posledni spravce" in telo
    # Odvolani se vubec neprovedlo - tajemstvi zustava netknute.
    assert (
        koren(tmp_path / "data") / "admin-jindrich" / "totp.secret"
    ).is_file()


def test_a_second_admin_can_be_removed(prihlaseny_klient, tmp_path):
    klient, csrf = prihlaseny_klient
    _pridej(prihlaseny_klient, "marie")

    odpoved = klient.post("/spravci/marie/odebrat", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/spravci").get_data(as_text=True)
    assert "marie" not in telo
    assert Admin.local(tmp_path / "data", realm=REALM).admins() == ["jindrich"]


def test_a_newly_added_admin_can_complete_the_full_login_round(
    prihlaseny_klient, tmp_path,
):
    odpoved = _pridej(prihlaseny_klient, "marie")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/spravci/qr/marie")

    prvni, druhy = admin_kody(tmp_path / "data", jmeno="marie")

    klient, _ = prihlaseny_klient
    # Fresh klient nad stejnou aplikaci - "marie" se prihlasuje poprve sama,
    # ne uz prihlaseny "jindrich".
    novy_klient = klient.application.test_client()
    odpoved = novy_klient.post(
        "/login",
        data={"realm": REALM, "jmeno": "marie", "kod1": prvni, "kod2": druhy},
    )
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/")

    with novy_klient.session_transaction() as relace:
        assert relace["admin"] == "marie"

    assert (
        koren(tmp_path / "data") / "admin-marie" / "totp.paired"
    ).is_file()


def test_every_mutating_route_without_csrf_is_rejected_and_state_unchanged(
    prihlaseny_klient, tmp_path,
):
    _pridej(prihlaseny_klient, "marie")
    klient, _ = prihlaseny_klient

    mutace = [
        ("/spravci/pridat", {"jmeno": "petr"}),
        ("/spravci/marie/odvolat", {}),
        ("/spravci/marie/parovat", {}),
        ("/spravci/marie/odebrat", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    telo = klient.get("/spravci").get_data(as_text=True)
    assert "marie" in telo
    assert "petr" not in telo
    assert Admin.local(tmp_path / "data", realm=REALM).admins() == [
        "jindrich", "marie",
    ]


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/spravci"),
    ("get", "/spravci/qr/marie"),
    ("post", "/spravci/pridat"),
    ("post", "/spravci/marie/odebrat"),
    ("post", "/spravci/marie/odvolat"),
    ("post", "/spravci/marie/parovat"),
])
def test_every_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    telo = klient.get("/spravci?lang=en").get_data(as_text=True)
    assert "Admins" in telo
    assert "Správci" not in telo
