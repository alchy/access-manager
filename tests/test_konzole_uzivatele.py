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

    zamceny = klient.get("/users").get_data(as_text=True)
    assert "Zamčeno" in zamceny
    # Zamek je docasny a vratny - radek proto nabizi odemknuti, ne zamknuti.
    assert "Odemknout uživatele" in zamceny


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


# == roletka s poslednimi prihlasenimi ================================


def test_the_listing_shows_the_last_logins_per_person(prihlaseny_klient, tmp_path):
    """Obdoba grepu z auditu primo u cloveka: cas, odkud, kdo pozadal, stav."""
    from helpers import TAJEMSTVI, kod

    from access_manager.files import FileStore

    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient
    # Vlastni tajemstvi, at jde kod spocitat.
    adresar = koren(tmp_path / "data") / "user-tereza"
    (adresar / "totp.secret").write_text(TAJEMSTVI + "\n", encoding="utf-8")

    store = FileStore(koren(tmp_path / "data"), realm=REALM)
    store.authenticate("tereza", {"totp": kod()}, purpose="login",
                       component="workbench", origin="2001:db8::1")
    store.authenticate("tereza", {"totp": "000000"}, purpose="login",
                       component="workbench", origin="10.0.0.9")

    telo = klient.get("/users").get_data(as_text=True)
    assert "<details>" in telo
    assert "2001:db8::1" in telo
    assert "10.0.0.9" in telo
    assert "workbench" in telo
    assert "bad_code" in telo


def test_only_the_last_five_logins_are_shown(prihlaseny_klient, tmp_path):
    from access_manager.audit import append_event

    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient
    for i in range(8):
        append_event(koren(tmp_path / "data"), {
            "t": f"2026-08-26T10:0{i}:00+00:00", "kind": "authenticate",
            "subject": "user:tereza", "outcome": "ok",
            "origin": f"10.0.0.{i}", "component": "workbench",
        }, retention_days=90)

    telo = klient.get("/users").get_data(as_text=True)
    # Nejnovejsich pet, nejnovejsi prvni - starsi tri uz ne.
    for i in (3, 4, 5, 6, 7):
        assert f"10.0.0.{i}" in telo
    for i in (0, 1, 2):
        assert f"10.0.0.{i}" not in telo
    assert telo.index("10.0.0.7") < telo.index("10.0.0.3")


def test_someone_who_never_logged_in_says_so(prihlaseny_klient):
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient
    telo = klient.get("/users").get_data(as_text=True)
    assert "Zatím žádné ověření" in telo


def test_the_login_dropdown_uses_the_same_log_styling_as_the_audit_page(
    prihlaseny_klient, tmp_path,
):
    """Vypis auditu ma vypadat stejne, at ho clovek potka kdekoli - tedy
    tataz trida `log` (a tim i tentyz mensi font) v roletce i na strance
    auditu. A tabulka nesmi zustat smrsknuta vlevo: `.log-posuv` posouva
    jen ji, sama si drzi plnou sirku."""
    from access_manager.audit import append_event

    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient
    # Bez udalosti se roletka vykresli prazdna a tabulka vubec nevznikne.
    append_event(koren(tmp_path / "data"), {
        "t": "2026-08-26T10:00:00+00:00", "kind": "authenticate",
        "subject": "user:tereza", "outcome": "ok", "origin": "10.0.0.1",
    }, retention_days=90)

    telo = klient.get("/users").get_data(as_text=True)
    assert '<table class="tabulka log vnorena">' in telo
    assert '<div class="log-posuv">' in telo
    # `display: block` by z tabulky udelal blok smrsknuty na obsah.
    assert "table.vnorena { margin: 0; border: none" in telo


# == pojmenovani a nabidka akci =======================================


def test_the_row_offers_only_the_action_that_can_work(prihlaseny_klient):
    """`pair` odmita cloveka, ktery uz tajemstvi ma ("prepsani by ho zamklo
    ven"), `revoke` nema co odvolavat, kdyz zadne neni. Tlacitko, ktere muze
    jen spadnout, na radku nema co delat."""
    _pridej(prihlaseny_klient, "tereza")
    klient, csrf = prihlaseny_klient

    # Cerstve zalozeny clovek povereni MA, ale jeste se nesparoval - tlacitko
    # proto mluvi o TOKENU, ne o sparovani, ktere zadne neni.
    telo = klient.get("/users").get_data(as_text=True)
    assert "Zneplatnit párovací token" in telo
    assert "Zneplatnit spárování" not in telo
    assert "Vydat párovací token" not in telo

    klient.post("/users/tereza/revoke", data={"csrf": csrf})

    # Po odvolani je to obracene.
    telo = klient.get("/users").get_data(as_text=True)
    assert "Vydat párovací token" in telo
    assert "Zneplatnit párovací token" not in telo


def test_the_buttons_name_the_thing_they_act_on(prihlaseny_klient):
    """Jedno podstatne jmeno, tri slovesa. "Sparovat" slibovalo spravci ukon,
    ktery provest nemuze - parovani dokoncuje az clovek svym telefonem."""
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient
    telo = klient.get("/users").get_data(as_text=True)
    assert "Zobrazit párovací token" in telo
    assert "Spárovat" not in telo
    assert "Zobrazit QR" not in telo
    # Stav o parovani mluvit SMI - tam se opravdu deje.
    assert "Nespárováno" in telo


def test_the_revoke_button_names_what_actually_exists(prihlaseny_klient, tmp_path):
    """Zneplatneni maze tutez sadu vzdycky, ale rikat "sparovani" nekomu,
    kdo se jeste nesparoval, by byla lez - popisek se ridi stavem radku."""
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient

    telo = klient.get("/users").get_data(as_text=True)
    assert "Zneplatnit párovací token" in telo
    assert "Zneplatnit spárování" not in telo

    # Prvni uspesne prihlaseni => `totp.paired`, stav "aktivni".
    (koren(tmp_path / "data") / "user-tereza" / "totp.paired").write_text("1")

    telo = klient.get("/users").get_data(as_text=True)
    assert "Zneplatnit spárování" in telo
    assert "Zneplatnit párovací token" not in telo


def test_credential_actions_come_before_account_actions(prihlaseny_klient):
    """Akce nad POVERENIM (cim se clovek prokazuje) a nad UCTEM (jestli tu
    vubec je) delaji ruzne veci a maji byt oddelene - tim spis, ze ty druhe
    jsou ucinnejsi."""
    _pridej(prihlaseny_klient, "tereza")
    klient, _ = prihlaseny_klient
    telo = klient.get("/users").get_data(as_text=True)

    povereni = telo.index("Zneplatnit párovací token")
    hranice = telo.index('class="oddelovac"')
    zamek = telo.index("Zamknout uživatele")
    smazat = telo.index("Smazat uživatele")

    assert povereni < hranice < zamek < smazat
