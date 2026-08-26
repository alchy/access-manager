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
    assert "totp.secret" not in telo.lower()

    tajemstvi = (
        koren(tmp_path / "data") / "user-tereza" / "totp.secret"
    ).read_text(encoding="utf-8").strip()
    # Tajemstvi na TEHLE strance byt smi - je to tataz hodnota, kterou nese
    # QR o kus vys, jen k opsani (kdo sedi u konzole, nema cim skenovat).
    assert tajemstvi in telo
    assert "otpauth://" in telo

    # Ve VYPISU nemá co delat - tam se nikdy nic k opsani nezobrazuje.
    seznam = klient.get("/users").get_data(as_text=True)
    assert tajemstvi not in seznam


def test_pairing_removes_the_typed_secret_together_with_the_qr(
    prihlaseny_klient, tmp_path,
):
    """`_complete_pairing` maze `totp.uri` i `totp.txt`: "mizi jen zobrazitelna
    podoba tajemstvi". String se cte prave z `totp.uri`, takze musi zmizet
    s QR naraz - kdyby se bral z `totp.secret`, prezil by a tim by to
    pravidlo zrusil."""
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient

    adresar = koren(tmp_path / "data") / "user-tereza"
    tajemstvi = (adresar / "totp.secret").read_text(encoding="utf-8").strip()
    assert tajemstvi in klient.get("/users/qr/tereza").get_data(as_text=True)

    # Prvni uspesne prihlaseni = sparovano.
    (adresar / "totp.paired").write_text("1", encoding="utf-8")
    (adresar / "totp.uri").unlink()
    (adresar / "totp.txt").unlink()

    telo = klient.get("/users/qr/tereza").get_data(as_text=True)
    assert tajemstvi not in telo
    assert "otpauth://" not in telo


def test_disabling_changes_the_state_shown_in_the_listing(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    # Cerstve zalozeny clovek jeste nikdy nepouzil sve prvni prihlaseni -
    # ceka na parovani, neni "aktivni" (viz FileStore._complete_pairing).
    ceka = klient.get("/users").get_data(as_text=True)
    assert "Nespárováno" in ceka

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
    assert "Nespárováno" in telo
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
    assert "Username" in telo
    assert "Uživatelé" not in telo


# == vypis o stovkach identit ==============================================
#
# Realm o stovkach lidi se bez filtru necte. Filtr navic setri cteni z disku:
# `_radek_cloveka` sahne kazde identite na disk zvlast, a to az PO filtru.


def _pridej_vic(prihlaseny_klient, jmena):
    for jmeno in jmena:
        _pridej(prihlaseny_klient, jmeno)


def test_the_listing_shows_how_many_identities_there_are(prihlaseny_klient):
    _pridej_vic(prihlaseny_klient, ["hana", "pavel", "tereza"])
    klient, _ = prihlaseny_klient
    telo = klient.get("/users").get_data(as_text=True)
    assert "3 celkem" in telo


def test_a_query_narrows_the_listing_and_reports_both_counts(prihlaseny_klient):
    _pridej_vic(prihlaseny_klient, ["hana.novakova", "pavel.novak", "tereza.mala"])
    klient, _ = prihlaseny_klient
    telo = klient.get("/users?q=novak").get_data(as_text=True)

    assert "hana.novakova" in telo
    assert "pavel.novak" in telo
    assert "tereza.mala" not in telo
    assert "2 z 3" in telo


def test_a_query_matches_anywhere_in_the_name_not_just_the_start(prihlaseny_klient):
    """Spravce hleda 'novak' a chce najit i 'jan.novak@example.com'."""
    _pridej_vic(prihlaseny_klient, ["jan.novak@example.com"])
    klient, _ = prihlaseny_klient
    telo = klient.get("/users?q=novak").get_data(as_text=True)
    assert "jan.novak@example.com" in telo


def test_a_query_that_matches_nothing_says_so(prihlaseny_klient):
    _pridej_vic(prihlaseny_klient, ["hana"])
    klient, _ = prihlaseny_klient
    telo = klient.get("/users?q=nikdo").get_data(as_text=True)
    assert "Filtru neodpovídá nic." in telo
    assert "0 z 1" in telo


def test_an_empty_query_does_not_filter(prihlaseny_klient):
    _pridej_vic(prihlaseny_klient, ["hana", "pavel"])
    klient, _ = prihlaseny_klient
    telo = klient.get("/users?q=%20%20").get_data(as_text=True)
    assert "hana" in telo and "pavel" in telo
    assert "2 celkem" in telo
