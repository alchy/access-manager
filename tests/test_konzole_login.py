"""Kostra konzole: factory, sdileny layout, prihlasovaci stranka, strazce relace.

Kompletni prihlaseni (POST /login dvema kody) je predmet ukolu 3 - GET /login
(formular + prepinac jazyka) a strazce nechraneneho pristupu jsou z ukolu 2.

Fixtura `prostredi` je sdilena v `conftest.py` - vsechny stranky konzole ji
potrebuji stejnou.
"""
from helpers import REALM, admin_kody
from test_config import zapis

from access_manager import Admin
from access_manager.config import load_config
from access_manager.konzole.app import create_console_app


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

    # Ukol 4 teprve dodava /users - overujeme jen cil presmerovani, ne obsah.
    dalsi = prostredi.get("/")
    assert dalsi.status_code == 302
    assert dalsi.headers["Location"].endswith("/users")


def test_login_with_mismatched_case_and_whitespace_stays_logged_in(prostredi, tmp_path):
    # Kriticky nalez opravneho kola: authenticate_admin normalizuje jmeno
    # pres check_identity uvnitr sebe, ale bez normalizace TADY by se do
    # session ulozilo syrove "Jindrich " - strazce (prihlasen) ho porovnava
    # proti normalizovanym admins() a kazdy DALSI pozadavek by odrazel zpet
    # na /login, i kdyz samotne prihlaseni prave uspelo.
    prvni, druhy = admin_kody(tmp_path / "data")
    odpoved = prostredi.post(
        "/login",
        data={"realm": REALM, "jmeno": "Jindrich ", "kod1": prvni, "kod2": druhy},
    )
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/")

    dalsi = prostredi.get("/users")
    assert dalsi.status_code == 200


def test_login_with_an_uppercase_realm_variant_succeeds(prostredi, tmp_path):
    prvni, druhy = admin_kody(tmp_path / "data")
    odpoved = prostredi.post(
        "/login",
        data={
            "realm": REALM.upper(), "jmeno": "jindrich", "kod1": prvni, "kod2": druhy,
        },
    )
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/")

    dalsi = prostredi.get("/users")
    assert dalsi.status_code == 200


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


def test_console_secure_cookie_config_sets_the_secure_flag(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {
        "data": str(tmp_path / "data"), "console_secure_cookie": True,
    })
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})
    Admin.local(tmp_path / "data", realm=REALM).add_admin("jindrich")

    cfg = load_config(tmp_path / "conf.d")
    app = create_console_app(cfg)
    app.config["TESTING"] = True
    klient = app.test_client()

    prvni, druhy = admin_kody(tmp_path / "data")
    odpoved = klient.post(
        "/login",
        data={"realm": REALM, "jmeno": "jindrich", "kod1": prvni, "kod2": druhy},
    )
    cookies = odpoved.headers.get_all("Set-Cookie")
    assert any("Secure" in c for c in cookies)


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


def test_login_accepts_codes_split_into_per_digit_fields(prostredi, tmp_path):
    """Prihlaseni projde i kdyz kod prijde po cislicich.

    Formular vykresluje policko na kazdou cislici (kod1_1..kod1_6), protoze
    se to lip opisuje z telefonu. Server je slozi zpatky - jedno cele pole
    zustava platne (posilaji ho ostatni testy), tady se overuje ta druha
    cesta.
    """
    prvni, druhy = admin_kody(tmp_path / "data")
    data = {"realm": REALM, "jmeno": "jindrich"}
    for i, znak in enumerate(prvni, start=1):
        data[f"kod1_{i}"] = znak
    for i, znak in enumerate(druhy, start=1):
        data[f"kod2_{i}"] = znak

    odpoved = prostredi.post("/login", data=data)
    assert odpoved.status_code == 302
    with prostredi.session_transaction() as relace:
        assert relace["admin"] == "jindrich"


def test_login_page_renders_one_box_per_digit(prostredi):
    """Formular ma policko na kazdou cislici obou kodu."""
    telo = prostredi.get("/login").get_data(as_text=True)
    for pole in ("kod1", "kod2"):
        for i in range(1, 7):
            assert f'name="{pole}_{i}"' in telo, f"chybi policko {pole}_{i}"
    # Skript je jen pohodli navic - policka musi fungovat i bez nej.
    assert "code.js" in telo


def test_browser_engine_detection_prefers_the_specific_marker():
    """Edge i Opera nesou v UA taky "Chrome", Chrome zase "Safari".

    Poradi zkousenych znacek proto neni libovolne - obecnejsi znacka smi
    prijit az po specificke, jinak se Edge oznaci za Chrome.
    """
    from access_manager.konzole.app import _prohlizec

    edge = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")
    chrome = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    safari = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")
    firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

    assert _prohlizec(edge) == "Edge (Blink)"
    assert _prohlizec(chrome) == "Chrome (Blink)"
    assert _prohlizec(safari) == "Safari (WebKit)"
    assert _prohlizec(firefox) == "Firefox (Gecko)"
    # Nezname UA se nehada - radeji nic nez vymysl.
    assert _prohlizec("neco-uplne-jineho/1.0") == ""
    assert _prohlizec("") == ""


def test_login_page_shows_the_address_the_service_actually_measures(prostredi):
    """Pod formularem je adresa z resolve_origin, ne holy remote_addr.

    Kdyz se tam objevi adresa proxy misto klienta, je spatne nastavene
    trusted_proxies/hops - a je to videt hned pri prihlaseni.
    """
    telo = prostredi.get(
        "/login",
        environ_overrides={"REMOTE_ADDR": "198.51.100.7"},
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
                               "Gecko/20100101 Firefox/121.0"},
    ).get_data(as_text=True)
    assert "198.51.100.7" in telo
    assert "Firefox (Gecko)" in telo
