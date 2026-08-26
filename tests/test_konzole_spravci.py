"""Stranka Spravci: vypis se stitkem a stavem parovani, pridani (-> QR
sdilena s uzivateli), odebrani, odvolani tokenu, nove parovani; guard posledniho
spravce. Mirror vzoru z test_konzole_uzivatele.py - mutace jsou vzdy POST + CSRF,
uspech i chyba se vraci flashem (Post/Redirect/Get).
"""
import pytest
from helpers import REALM, admin_kody, koren

from access_manager import Admin
from access_manager.files import FileStore


def _pridej(prihlaseny_klient, jmeno):
    klient, csrf = prihlaseny_klient
    return klient.post("/admins/add", data={"csrf": csrf, "jmeno": jmeno})


def test_adding_an_admin_redirects_to_a_qr_page_with_the_credential(
    prihlaseny_klient, tmp_path,
):
    odpoved = _pridej(prihlaseny_klient, "marie")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/admins/qr/marie")

    klient, _ = prihlaseny_klient
    stranka = klient.get(odpoved.headers["Location"])
    telo = stranka.get_data(as_text=True)
    assert "<pre" in telo
    assert f"{REALM}-admin-marie" in telo

    tajemstvi = (
        koren(tmp_path / "data") / "admin-marie" / "totp.secret"
    ).read_text(encoding="utf-8").strip()
    # Sdilena `qr.html` plati pro spravce stejne jako pro cleny: QR i tyz
    # obsah k opsani.
    assert tajemstvi in telo
    assert "otpauth://" in telo

    seznam = klient.get("/admins").get_data(as_text=True)
    assert tajemstvi not in seznam


def test_listing_shows_waiting_then_paired_then_no_credential_after_revoke(
    prihlaseny_klient, tmp_path,
):
    klient, csrf = prihlaseny_klient
    _pridej(prihlaseny_klient, "marie")

    cekajici = klient.get("/admins").get_data(as_text=True)
    assert f"{REALM}-admin-marie" in cekajici
    assert "Nespárováno" in cekajici

    # Prvni skutecne prihlaseni dokoncuje parovani (viz
    # FileStore._complete_pairing) - presne stejny mechanismus, ktery
    # POST /login pouziva uvnitr.
    prvni, druhy = admin_kody(tmp_path / "data", jmeno="marie")
    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    assert store.authenticate_admin("marie", prvni, druhy)

    sparovano = klient.get("/admins").get_data(as_text=True)
    assert "Spárováno" in sparovano

    klient.post("/admins/marie/revoke", data={"csrf": csrf})
    bez_povereni = klient.get("/admins").get_data(as_text=True)
    assert "Bez pověření" in bez_povereni
    # "Sparovano" uz zbyva jen u jindricha (fixtura ho prihlasi hned na
    # zacatku) - marie po odvolani ne.
    assert bez_povereni.count("Spárováno") == 1


def test_revoke_then_pair_produces_a_new_qr(prihlaseny_klient):
    prvni_odpoved = _pridej(prihlaseny_klient, "marie")
    klient, csrf = prihlaseny_klient
    prvni_qr = klient.get(prvni_odpoved.headers["Location"]).get_data(as_text=True)

    odvolat = klient.post("/admins/marie/revoke", data={"csrf": csrf})
    assert odvolat.status_code == 302

    telo = klient.get("/admins").get_data(as_text=True)
    assert "Bez pověření" in telo

    parovat = klient.post("/admins/marie/pair", data={"csrf": csrf})
    assert parovat.status_code == 302
    assert parovat.headers["Location"].endswith("/admins/qr/marie")

    druhy_qr = klient.get(parovat.headers["Location"]).get_data(as_text=True)
    assert "<pre" in druhy_qr
    assert druhy_qr != prvni_qr


def test_qr_page_rejects_an_invalid_identity_with_404(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    odpoved = klient.get("/admins/qr/marie!")
    assert odpoved.status_code == 404


def test_the_last_admin_cannot_be_removed_and_state_is_unchanged(
    prihlaseny_klient, tmp_path,
):
    klient, csrf = prihlaseny_klient
    odpoved = klient.post("/admins/jindrich/remove", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/admins").get_data(as_text=True)
    assert "zprava-chyba" in telo
    assert "posledni spravce" in telo
    assert Admin.local(tmp_path / "data", realm=REALM).admins() == ["jindrich"]


def test_the_last_admins_token_cannot_be_revoked_and_state_is_unchanged(
    prihlaseny_klient, tmp_path,
):
    klient, csrf = prihlaseny_klient
    odpoved = klient.post("/admins/jindrich/revoke", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/admins").get_data(as_text=True)
    assert "zprava-chyba" in telo
    assert "posledni spravce" in telo
    # Odvolani se vubec neprovedlo - tajemstvi zustava netknute.
    assert (
        koren(tmp_path / "data") / "admin-jindrich" / "totp.secret"
    ).is_file()


def test_a_second_admin_can_be_removed(prihlaseny_klient, tmp_path):
    klient, csrf = prihlaseny_klient
    _pridej(prihlaseny_klient, "marie")

    odpoved = klient.post("/admins/marie/remove", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/admins").get_data(as_text=True)
    assert "marie" not in telo
    assert Admin.local(tmp_path / "data", realm=REALM).admins() == ["jindrich"]


def test_a_newly_added_admin_can_complete_the_full_login_round(
    prihlaseny_klient, tmp_path,
):
    odpoved = _pridej(prihlaseny_klient, "marie")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/admins/qr/marie")

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


def test_removing_an_admin_kills_their_live_session(prihlaseny_klient, tmp_path):
    # Kriticky nalez opravneho kola 1: strazce relace (`prihlasen`) drive
    # overoval jen "je v session neco" + "existuje realm", nikdy "existuje
    # ten spravce jeste?" - odebrany spravce si tak drzel plnou pravomoc
    # az do odhlaseni/restartu.
    odpoved = _pridej(prihlaseny_klient, "marie")
    assert odpoved.status_code == 302

    prvni, druhy = admin_kody(tmp_path / "data", jmeno="marie")
    klient, csrf = prihlaseny_klient
    marie_klient = klient.application.test_client()
    prihlaseni = marie_klient.post(
        "/login",
        data={"realm": REALM, "jmeno": "marie", "kod1": prvni, "kod2": druhy},
    )
    assert prihlaseni.status_code == 302

    # marie ma otevrenou relaci a funguje - overeno pred odebranim.
    assert marie_klient.get("/admins").status_code == 200

    odebrani = klient.post("/admins/marie/remove", data={"csrf": csrf})
    assert odebrani.status_code == 302

    dalsi_pozadavek = marie_klient.get("/admins")
    assert dalsi_pozadavek.status_code == 302
    assert dalsi_pozadavek.headers["Location"].endswith("/login")

    with marie_klient.session_transaction() as relace:
        assert "admin" not in relace

    # Prezijici spravce (jindrich) neni zasahem dotcen - jeho relace
    # funguje dal.
    assert klient.get("/admins").status_code == 200


def test_every_mutating_route_without_csrf_is_rejected_and_state_unchanged(
    prihlaseny_klient, tmp_path,
):
    _pridej(prihlaseny_klient, "marie")
    klient, _ = prihlaseny_klient

    mutace = [
        ("/admins/add", {"jmeno": "petr"}),
        ("/admins/marie/revoke", {}),
        ("/admins/marie/pair", {}),
        ("/admins/marie/remove", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    telo = klient.get("/admins").get_data(as_text=True)
    assert "marie" in telo
    assert "petr" not in telo
    assert Admin.local(tmp_path / "data", realm=REALM).admins() == [
        "jindrich", "marie",
    ]


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/admins"),
    ("get", "/admins/qr/marie"),
    ("post", "/admins/add"),
    ("post", "/admins/marie/remove"),
    ("post", "/admins/marie/revoke"),
    ("post", "/admins/marie/pair"),
])
def test_every_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    telo = klient.get("/admins?lang=en").get_data(as_text=True)
    assert "Admins" in telo
    assert "Správci" not in telo
