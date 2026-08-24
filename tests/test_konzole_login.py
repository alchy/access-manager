"""Kostra konzole: factory, sdileny layout, prihlasovaci stranka, strazce relace.

Kompletni prihlaseni (POST /login dvema kody) je predmet ukolu 3 - GET /login
(formular + prepinac jazyka) a strazce nechraneneho pristupu jsou z ukolu 2.

Fixtura `prostredi` je sdilena v `conftest.py` - vsechny stranky konzole ji
potrebuji stejnou.
"""
from helpers import REALM, admin_kody


def test_login_page_renders_in_czech_by_default(prostredi):
    odpoved = prostredi.get("/login")
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Přihlášení" in telo


def test_the_language_toggle_switches_to_english(prostredi):
    odpoved = prostredi.get("/login?lang=en")
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Login" in telo
    assert "Přihlášení" not in telo


def test_a_guarded_page_redirects_to_login(prostredi):
    odpoved = prostredi.get("/")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_a_successful_login_sets_the_session_and_redirects(prostredi, tmp_path):
    with prostredi.session_transaction() as relace:
        relace["neco_stareho"] = "melo by zmizet"

    prvni, druhy = admin_kody(tmp_path / "data")
    odpoved = prostredi.post(
        "/login",
        data={"realm": REALM, "jmeno": "jindrich", "kod1": prvni, "kod2": druhy},
    )
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/")

    with prostredi.session_transaction() as relace:
        assert relace["realm"] == REALM
        assert relace["admin"] == "jindrich"
        assert "csrf" in relace
        # Stav pred prihlasenim relaci nepreziva - session.clear() v _prihlasit.
        assert "neco_stareho" not in relace

    # Ukol 4 teprve dodava /lide - overujeme jen cil presmerovani, ne obsah.
    dalsi = prostredi.get("/")
    assert dalsi.status_code == 302
    assert dalsi.headers["Location"].endswith("/lide")


def test_wrong_codes_show_a_single_failure_message(prostredi):
    odpoved = prostredi.post(
        "/login",
        data={"realm": REALM, "jmeno": "jindrich", "kod1": "000000", "kod2": "111111"},
    )
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Přihlášení se nezdařilo" in telo


def test_an_unknown_realm_shows_the_same_failure_message(prostredi):
    odpoved = prostredi.post(
        "/login",
        data={
            "realm": "nezname.example",
            "jmeno": "jindrich",
            "kod1": "000000",
            "kod2": "111111",
        },
    )
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Přihlášení se nezdařilo" in telo


def test_repeated_failures_throttle_and_show_retry_after(prostredi):
    spatne = {"realm": REALM, "jmeno": "jindrich", "kod1": "000000", "kod2": "111111"}
    for _ in range(5):
        prostredi.post("/login", data=spatne)
    odpoved = prostredi.post("/login", data=spatne)
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Příliš mnoho pokusů" in telo


def test_logout_logs_out(prostredi, tmp_path):
    prvni, druhy = admin_kody(tmp_path / "data")
    prostredi.post(
        "/login",
        data={"realm": REALM, "jmeno": "jindrich", "kod1": prvni, "kod2": druhy},
    )
    with prostredi.session_transaction() as relace:
        token = relace["csrf"]

    odpoved = prostredi.post("/logout", data={"csrf": token})
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")

    with prostredi.session_transaction() as relace:
        assert "admin" not in relace


def test_logout_without_csrf_is_rejected(prostredi, tmp_path):
    prvni, druhy = admin_kody(tmp_path / "data")
    prostredi.post(
        "/login",
        data={"realm": REALM, "jmeno": "jindrich", "kod1": prvni, "kod2": druhy},
    )

    odpoved = prostredi.post("/logout", data={})
    assert odpoved.status_code == 400

    with prostredi.session_transaction() as relace:
        assert relace.get("admin") == "jindrich"
