"""Nalezy z testu na zkusebni instanci pred sestavenim produkcniho obrazu.

Kazdy test tu drzi jednu opravenou chybu, kterou jednotkove testy nevidely,
protoze ji bylo videt az po siti nebo az za proxy:

- `/lang` presmeroval na cizi server pres tabulator v ceste a spadl na konci
  radku (oboji bez prihlaseni);
- jmeno delsi nez unese souborovy system proslo kontrolou tvaru a skoncilo
  chybou 500 - na prihlaseni do konzole i v API;
- tlacitko Kopirovat na strance klice melo inline `onclick`, ktery hlavicka
  `script-src 'self'` z nginx zahodi;
- neosetrena vyjimka se do logu dostala bez casu sluzby (API) nebo bez
  jakehokoli popisu (konzole).
"""
import json
import re
from pathlib import Path
from urllib.parse import quote

import pytest
from helpers import REALM, koren, zaloz
from test_config import zapis

import access_manager
from access_manager import Admin, log
from access_manager.audit import append_event, read_events, recent_by
from access_manager.config import load_config
from access_manager.files import FileStore
from access_manager.principals import (
    MAX_NAME_LENGTH,
    check_identity,
    check_name,
    check_realm,
)
from access_manager.purpose import check_purpose
from access_manager.server import create_app

SABLONY = Path(access_manager.__file__).parent / "konzole" / "templates"
DLOUHE = "x" * 300


# == presmerovani po prepnuti jazyka ======================================


@pytest.mark.parametrize("cil", [
    "//evil.example",                 # schema-relativni adresa
    "/\t/evil.example",               # prohlizec tabulator vypusti -> //evil
    "/\n/evil.example",
    "/users\r\nSet-Cookie: x=1",      # konec radku v hlavicce
    "/\\evil.example",                # zpetne lomitko bere prohlizec jako lomitko
    "/\\/evil.example",
    "\\\\evil.example",
    " //evil.example",
    "/ /evil.example",
    "/users?q=a b",                   # mezera - poctivy cil ji ma zakodovanou
    "https://evil.example/",
    "javascript:alert(1)",
    "evil.example",
    "/\x00",
    "/ž",
])
def test_lang_switch_never_leaves_this_server(prostredi, cil):
    odpoved = prostredi.get(f"/lang?to=cs&next={quote(cil, safe='')}")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"] == "/"


@pytest.mark.parametrize("cil", [
    "/users",
    "/groups?group=ucetni",
    "/audit/apps?obdobi=30&aplikace=wb&detail=0123456789ab",
    "/audit?kdo=admin:jindrich&od=2026-09-01&do=2026-10-01",
    "/audit/users?uzivatel=%C5%BEaneta",     # diakritika, jak ji posle prohlizec
    "/users/qr/hana.novakova@example.com",
])
def test_lang_switch_keeps_every_honest_target(prostredi, cil):
    odpoved = prostredi.get(f"/lang?to=en&next={quote(cil, safe='')}")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"] == cil


# == strop delky jmena ====================================================


@pytest.mark.parametrize("kontrola", [check_identity, check_name, check_realm])
def test_a_name_longer_than_the_filesystem_takes_is_refused(kontrola):
    assert kontrola("a" * MAX_NAME_LENGTH) == "a" * MAX_NAME_LENGTH
    with pytest.raises(ValueError):
        kontrola("a" * (MAX_NAME_LENGTH + 1))
    # Jmeno adresare je `user-<jmeno>` - i s predponou se musi vejit.
    assert len(f"realm-{'a' * MAX_NAME_LENGTH}".encode()) <= 255


def test_a_huge_name_on_the_login_form_is_a_refusal_not_a_crash(prostredi, capsys):
    prostredi.application.config["PROPAGATE_EXCEPTIONS"] = False
    odpoved = prostredi.post("/login", data={
        "realm": REALM, "jmeno": DLOUHE, "kod1": "111111", "kod2": "222222",
    })
    assert odpoved.status_code == 200
    assert "Přihlášení se nezdařilo" in odpoved.get_data(as_text=True)
    zachyceno = capsys.readouterr()
    assert "Exception" not in zachyceno.err
    assert '"reason": "bad_form"' in zachyceno.out


@pytest.fixture
def api(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})
    admin = Admin.local(tmp_path / "data", realm=REALM)
    admin.add_user("hana")
    klic = admin.register_component("app:test")
    app = create_app(load_config(tmp_path / "conf.d"))
    # Jako v provozu: vyjimka se nesmi propsat do testu, ma skoncit 500.
    app.config["PROPAGATE_EXCEPTIONS"] = False
    return app.test_client(), {"Authorization": f"Bearer {klic}"}


def test_a_huge_name_in_the_api_is_a_bad_request_not_a_crash(api):
    klient, hlavicky = api
    assert klient.get(f"/v1/users/{DLOUHE}", headers=hlavicky).status_code == 400
    assert klient.get(f"/v1/groups/{DLOUHE}", headers=hlavicky).status_code == 400
    odpoved = klient.post("/v1/authenticate", headers=hlavicky, json={
        "username": DLOUHE, "credentials": {"totp": "000000"}, "purpose": "login",
    })
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


# == zadny inline skript v sablonach ======================================


def test_no_template_carries_inline_script():
    """Nginx posila `script-src 'self'`: inline `<script>` i obsluhu v atributu
    (`onclick=`) prohlizec zahodi a stranka by v provozu potichu nefungovala.
    """
    for sablona in sorted(SABLONY.glob("*.html")):
        text = sablona.read_text(encoding="utf-8")
        text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)        # komentare Jinja
        for znacka in re.findall(r"<[a-zA-Z][^<>]*>", text):
            assert not re.search(r"\son[a-z]+\s*=", znacka), (sablona.name, znacka)
            if znacka.lower().startswith("<script"):
                assert " src=" in znacka, (sablona.name, znacka)
        assert "javascript:" not in text.lower(), sablona.name


def test_the_pairing_page_copies_through_a_script_file(prihlaseny_klient):
    klient, csrf = prihlaseny_klient
    klient.post("/users/add", data={"csrf": csrf, "jmeno": "tereza"})
    telo = klient.get("/users/qr/tereza").get_data(as_text=True)
    assert 'data-copy-from="totp-secret"' in telo
    assert 'data-copy-from="totp-uri"' in telo
    assert 'src="/static/copy.js"' in telo


def test_the_key_page_copies_through_a_script_file(prihlaseny_klient):
    klient, csrf = prihlaseny_klient
    stranka = klient.post("/applications/add", data={"csrf": csrf, "jmeno": "wb"})
    telo = stranka.get_data(as_text=True)
    assert 'data-copy-from="klic-hodnota"' in telo
    assert 'src="/static/copy.js"' in telo
    skript = klient.get("/static/copy.js")
    assert skript.status_code == 200
    assert "data-copy-from" in skript.get_data(as_text=True)


# == neosetrena vyjimka v logu ============================================


def _radky_chyb(zachyceno):
    return [r for r in zachyceno.err.strip().splitlines() if r.strip()]


def _rozbij_uloziste(monkeypatch):
    def spadni(self, *args, **kwargs):
        raise RuntimeError("uloziste\nneodpovida")
    monkeypatch.setattr(FileStore, "users", spadni)


def test_a_console_crash_is_one_log_line_with_the_service_time(
    prihlaseny_klient, monkeypatch, capsys,
):
    klient, _ = prihlaseny_klient
    klient.application.config["PROPAGATE_EXCEPTIONS"] = False
    _rozbij_uloziste(monkeypatch)
    capsys.readouterr()
    assert klient.get("/users").status_code == 500

    radky = _radky_chyb(capsys.readouterr())
    assert len(radky) == 1, radky              # jeden radek, zadny holy vypis
    zaznam = json.loads(radky[0])
    assert zaznam["t"].endswith("+00:00")      # cas sluzby, v UTC
    assert zaznam["level"] == "error"
    assert zaznam["event"] == "Exception on /users [GET]"
    assert zaznam["exception"] == "RuntimeError: uloziste\nneodpovida"
    assert any("konzole/app.py" in ramec for ramec in zaznam["traceback"])


def test_an_api_crash_is_one_log_line_with_the_service_time(
    api, monkeypatch, capsys,
):
    klient, hlavicky = api
    _rozbij_uloziste(monkeypatch)
    capsys.readouterr()
    assert klient.get("/v1/users", headers=hlavicky).status_code == 500

    radky = _radky_chyb(capsys.readouterr())
    assert len(radky) == 1, radky
    zaznam = json.loads(radky[0])
    assert zaznam["t"].endswith("+00:00")
    assert zaznam["event"] == "Exception on /v1/users [GET]"
    assert zaznam["exception"].startswith("RuntimeError: ")
    assert any("server.py" in ramec for ramec in zaznam["traceback"])


def test_the_text_format_keeps_the_exception_on_the_same_line(capsys):
    log.configure(fmt="text")
    try:
        try:
            raise KeyError("chybi")
        except KeyError:
            log._logger.exception("spadlo to")
        radky = _radky_chyb(capsys.readouterr())
        assert len(radky) == 1
        assert "exception=KeyError: 'chybi'" in radky[0]
        assert "traceback=" in radky[0]
    finally:
        log.configure()


def test_event_fields_cannot_forge_the_exception_keys(capsys):
    log.warning("pokus", exception="podvrh", traceback="podvrh")
    zaznam = json.loads(_radky_chyb(capsys.readouterr())[0])
    assert "exception" not in zaznam and "traceback" not in zaznam



# == audit: radek nejde schovat pred cteckou ==============================


@pytest.mark.parametrize("znak", ["\u2028", "\u2029", "\x85", "\x0b", "\x0c", "\x1c"])
def test_a_unicode_line_separator_cannot_hide_an_audit_line(tmp_path, znak):
    """Kdo znal platny klic, schoval si zamitnuty pokus cestou s U+2028:
    `splitlines()` radek rozdelil a ctecka obe pulky tise preskocila."""
    domov = tmp_path / "realm"
    domov.mkdir()
    append_event(domov, {"t": "2026-10-01T10:00:00+00:00", "kind": "origin_denied",
                         "component": "wb", "path": f"/v1/whoami{znak}x"}, 90)
    append_event(domov, {"t": "2026-10-01T10:00:01+00:00", "kind": "access",
                         "component": "wb", "path": "/v1/whoami"}, 90)
    videne = read_events(domov)
    assert [u["kind"] for u in videne] == ["origin_denied", "access"]
    assert videne[0]["path"] == f"/v1/whoami{znak}x"
    assert len(recent_by(domov, "component", ["wb"])["wb"]) == 2


# == tajemstvi: prazdny soubor neoveruje ==================================


@pytest.mark.parametrize("obsah", ["", "\n", "ABCD"])
def test_an_empty_or_truncated_secret_never_authenticates(tmp_path, obsah):
    """Plny disk nebo pad pri zavadeni necha `totp.secret` prazdny. Kod pro
    prazdne tajemstvi si spocita kdokoli - nesmi to byt platny ucet."""
    import pyotp

    from access_manager import Access
    adresar = zaloz(tmp_path, "hana")
    (adresar / "totp.secret").write_text(obsah, encoding="utf-8")
    kod = pyotp.TOTP(obsah.strip() or "").now() if obsah.strip() == "" else "000000"
    verdikt = Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod}, purpose="login",
    )
    assert verdikt.outcome == "denied"
    assert verdikt.reason == "no_secret"


def test_an_empty_admin_secret_never_opens_the_console(prostredi, tmp_path):
    import pyotp
    tajemstvi = koren(tmp_path / "data") / "admin-jindrich" / "totp.secret"
    tajemstvi.write_text("", encoding="utf-8")
    prazdne = pyotp.TOTP("")
    import time
    ted = time.time()
    odpoved = prostredi.post("/login", data={
        "realm": REALM, "jmeno": "jindrich",
        "kod1": prazdne.at(ted), "kod2": prazdne.at(ted + prazdne.interval),
    })
    assert odpoved.status_code == 200          # zadne presmerovani do konzole
    with prostredi.session_transaction() as relace:
        assert "admin" not in relace


# == ucel: konec radku neni novy ucel =====================================


@pytest.mark.parametrize("ucel", ["login\n", "unlock:mzdy\n", "login\r", " login"])
def test_a_purpose_with_trailing_whitespace_is_refused(ucel):
    with pytest.raises(ValueError):
        check_purpose(ucel)
    assert check_purpose("login") == "login"
    assert check_purpose("unlock:mzdy") == "unlock:mzdy"


# == konzole: drobne pady =================================================


def test_a_non_ascii_csrf_token_is_a_refusal_with_an_audit_line(
    prihlaseny_klient, tmp_path,
):
    klient, _ = prihlaseny_klient
    klient.application.config["PROPAGATE_EXCEPTIONS"] = False
    odpoved = klient.post("/users/add", data={"csrf": "žluť", "jmeno": "tereza"})
    assert odpoved.status_code == 400
    udalosti = read_events(koren(tmp_path / "data"))
    assert any(u.get("op") == "csrf_denied" for u in udalosti)


def test_url_control_parameters_do_not_reach_the_audit_links(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    klient.application.config["PROPAGATE_EXCEPTIONS"] = False
    assert klient.get("/audit/apps?_method=POST").status_code == 200
    telo = klient.get("/audit/apps?_external=1&_scheme=javascript").get_data(
        as_text=True)
    assert 'href="http' not in telo and 'href="javascript' not in telo
