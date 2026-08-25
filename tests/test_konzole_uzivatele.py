"""Stranka Lide: vypis, zalozeni s QR, vypnuti/zapnuti, smazani, odvolani a
nove parovani. Tohle je VZOR pro dalsi stranky konzole (skupiny/aplikace/
spravci/audit) - mutace jsou vzdy POST + CSRF, uspech i chyba se vraci
flashem zpatky na /users (Post/Redirect/Get).
"""
import pytest
from helpers import REALM, koren

from access_manager import Admin


def _pridej(prihlaseny_klient, jmeno):
    klient, csrf = prihlaseny_klient
    return klient.post("/users/add", data={"csrf": csrf, "jmeno": jmeno})


def test_the_listing_shows_a_created_user_and_their_group(prihlaseny_klient, tmp_path):
    _pridej(prihlaseny_klient, "tereza")
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_group("ucetni")
    spravce.add_member("ucetni", "tereza")

    klient, _ = prihlaseny_klient
    telo = klient.get("/users").get_data(as_text=True)
    assert "tereza" in telo
    assert "ucetni" in telo


def test_adding_a_user_redirects_to_a_qr_page_with_an_ascii_code(
    prihlaseny_klient, tmp_path,
):
    odpoved = _pridej(prihlaseny_klient, "tereza")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/users/qr/tereza")

    klient, _ = prihlaseny_klient
    stranka = klient.get(odpoved.headers["Location"])
    telo = stranka.get_data(as_text=True)
    assert "<pre" in telo
    obrazec = telo.split("<pre", 1)[1].split(">", 1)[1].split("</pre>", 1)[0]
    assert obrazec.count("\n") > 10
    # zadne tajemstvi mimo tenhle ascii QR - ani jako nazev souboru, ani
    # (hlavni test) jako SKUTECNA hodnota tajemstvi nikde na strance.
    assert "totp.secret" not in telo.lower()
    tajemstvi = (
        koren(tmp_path / "data") / "user-tereza" / "totp.secret"
    ).read_text(encoding="utf-8").strip()
    assert tajemstvi not in telo

    seznam = klient.get("/users").get_data(as_text=True)
    assert tajemstvi not in seznam


def test_disabling_changes_the_state_shown_in_the_listing(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    # Cerstve zalozeny clovek jeste nikdy nepouzil sve prvni prihlaseni -
    # ceka na parovani, neni "aktivni" (viz FileStore._complete_pairing).
    ceka = klient.get("/users").get_data(as_text=True)
    assert "Čeká" in ceka

    odpoved = klient.post("/users/tereza/disable", data={"csrf": csrf})
    assert odpoved.status_code == 302

    zakazany = klient.get("/users").get_data(as_text=True)
    assert "Zakázáno" in zakazany


def test_deleting_removes_the_user_from_the_listing(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    odpoved = klient.post("/users/tereza/delete", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/users").get_data(as_text=True)
    assert "tereza" not in telo


def test_revoke_then_pair_produces_a_new_qr(prihlaseny_klient):
    prvni_odpoved = _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient
    prvni_qr = klient.get(prvni_odpoved.headers["Location"]).get_data(as_text=True)

    odvolat = klient.post("/users/tereza/revoke", data={"csrf": csrf})
    assert odvolat.status_code == 302

    parovat = klient.post("/users/tereza/pair", data={"csrf": csrf})
    assert parovat.status_code == 302
    assert parovat.headers["Location"].endswith("/users/qr/tereza")

    druhy_qr = klient.get(parovat.headers["Location"]).get_data(as_text=True)
    assert "<pre" in druhy_qr
    assert druhy_qr != prvni_qr


def test_a_revoked_user_shows_no_credential_before_re_pairing(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    # revoke_credential smaze VSECHNY artefakty (totp.secret i totp.issued),
    # takze tenhle clovek se nemuze prihlasit vubec - a nesmi to vypadat
    # jako "aktivni" (viz kriticky nalez z review kola 1).
    odpoved = klient.post("/users/tereza/revoke", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/users").get_data(as_text=True)
    assert "Bez pověření" in telo
    assert "Aktivní" not in telo

    qr = klient.get("/users/qr/tereza").get_data(as_text=True)
    assert "Bez pověření" in qr
    assert "<pre" not in qr


def test_qr_page_rejects_an_invalid_identity_with_404(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    odpoved = klient.get("/users/qr/tereza!")
    assert odpoved.status_code == 404


def test_every_mutating_route_without_csrf_is_rejected_and_state_unchanged(
    prihlaseny_klient,
):
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient

    mutace = [
        ("/users/add", {"jmeno": "petr"}),
        ("/users/tereza/disable", {}),
        ("/users/tereza/enable", {}),
        ("/users/tereza/revoke", {}),
        ("/users/tereza/pair", {}),
        ("/users/tereza/delete", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    telo = klient.get("/users").get_data(as_text=True)
    assert "tereza" in telo
    assert "Čeká" in telo
    assert "petr" not in telo


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/users"),
    ("get", "/users/qr/tereza"),
    ("post", "/users/add"),
    ("post", "/users/tereza/disable"),
    ("post", "/users/tereza/enable"),
    ("post", "/users/tereza/delete"),
    ("post", "/users/tereza/revoke"),
    ("post", "/users/tereza/pair"),
])
def test_every_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient

    telo = klient.get("/users?lang=en").get_data(as_text=True)
    assert "Users" in telo
    assert "Subject" in telo
    assert "Uživatelé" not in telo
