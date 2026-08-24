"""Stranka Lide: vypis, zalozeni s QR, vypnuti/zapnuti, smazani, odvolani a
nove parovani. Tohle je VZOR pro dalsi stranky konzole (skupiny/aplikace/
spravci/audit) - mutace jsou vzdy POST + CSRF, uspech i chyba se vraci
flashem zpatky na /lide (Post/Redirect/Get).
"""
from helpers import REALM

from access_manager import Admin


def _pridej(prihlaseny_klient, jmeno):
    klient, csrf = prihlaseny_klient
    return klient.post("/lide/pridat", data={"csrf": csrf, "jmeno": jmeno})


def test_the_listing_shows_a_created_user_and_their_group(prihlaseny_klient, tmp_path):
    _pridej(prihlaseny_klient, "tereza")
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_group("ucetni")
    spravce.add_member("ucetni", "tereza")

    klient, _ = prihlaseny_klient
    telo = klient.get("/lide").get_data(as_text=True)
    assert "tereza" in telo
    assert "ucetni" in telo


def test_adding_a_user_redirects_to_a_qr_page_with_an_ascii_code(prihlaseny_klient):
    odpoved = _pridej(prihlaseny_klient, "tereza")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/lide/qr/tereza")

    klient, _ = prihlaseny_klient
    stranka = klient.get(odpoved.headers["Location"])
    telo = stranka.get_data(as_text=True)
    assert "<pre" in telo
    obrazec = telo.split("<pre", 1)[1].split(">", 1)[1].split("</pre>", 1)[0]
    assert obrazec.count("\n") > 10
    # zadne tajemstvi mimo tenhle ascii QR
    assert "totp.secret" not in telo.lower()


def test_disabling_changes_the_state_shown_in_the_listing(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    # Cerstve zalozeny clovek jeste nikdy nepouzil sve prvni prihlaseni -
    # ceka na parovani, neni "aktivni" (viz FileStore._complete_pairing).
    ceka = klient.get("/lide").get_data(as_text=True)
    assert "Čeká" in ceka

    odpoved = klient.post("/lide/tereza/vypnout", data={"csrf": csrf})
    assert odpoved.status_code == 302

    zakazany = klient.get("/lide").get_data(as_text=True)
    assert "Zakázáno" in zakazany


def test_deleting_removes_the_user_from_the_listing(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    odpoved = klient.post("/lide/tereza/smazat", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/lide").get_data(as_text=True)
    assert "tereza" not in telo


def test_revoke_then_pair_produces_a_new_qr(prihlaseny_klient):
    prvni_odpoved = _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient
    prvni_qr = klient.get(prvni_odpoved.headers["Location"]).get_data(as_text=True)

    odvolat = klient.post("/lide/tereza/odvolat", data={"csrf": csrf})
    assert odvolat.status_code == 302

    parovat = klient.post("/lide/tereza/parovat", data={"csrf": csrf})
    assert parovat.status_code == 302
    assert parovat.headers["Location"].endswith("/lide/qr/tereza")

    druhy_qr = klient.get(parovat.headers["Location"]).get_data(as_text=True)
    assert "<pre" in druhy_qr
    assert druhy_qr != prvni_qr


def test_every_mutating_route_without_csrf_is_rejected_and_state_unchanged(
    prihlaseny_klient,
):
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient

    mutace = [
        ("/lide/pridat", {"jmeno": "petr"}),
        ("/lide/tereza/vypnout", {}),
        ("/lide/tereza/zapnout", {}),
        ("/lide/tereza/odvolat", {}),
        ("/lide/tereza/parovat", {}),
        ("/lide/tereza/smazat", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    telo = klient.get("/lide").get_data(as_text=True)
    assert "tereza" in telo
    assert "Čeká" in telo
    assert "petr" not in telo


def test_an_unauthenticated_get_redirects_to_login(prostredi):
    odpoved = prostredi.get("/lide")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient

    telo = klient.get("/lide?lang=en").get_data(as_text=True)
    assert "People" in telo
    assert "Subject" in telo
    assert "Lidé" not in telo
