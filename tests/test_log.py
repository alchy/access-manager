"""Provozni log: co do nej patri, na ktery proud, a co do nej NEPATRI.

Delici cara je jedina a nese cely modul `access_manager.log`: kde je znamy
realm, zapisuje se do auditu; kde neni, do provozniho logu. Zadna udalost
nesmi byt v obou - dve kopie by se musely drzet v souladu a jednu z nich by
rotace provozniho logu stejne zahodila.
"""
import json

from helpers import REALM, admin_kody, koren

from access_manager import log
from access_manager.audit import read_events


def radky(zachyceno):
    """Rozeber zachyceny proud na JSON zaznamy."""
    return [
        json.loads(r) for r in zachyceno.strip().splitlines() if r.startswith("{")
    ]


def udalosti(zachyceno, jmeno):
    return [r for r in radky(zachyceno) if r["event"] == jmeno]


# == co do provozniho logu PATRI ======================================


def test_a_deformed_realm_reaches_the_operational_log(prostredi, capsys):
    """Zdeformovany realm konci driv, nez existuje uloziste - do auditu ho
    nema kdo zapsat, takze provozni log je jeho JEDINA stopa."""
    prostredi.post("/login", data={
        "realm": "TOHLE NENI REALM", "jmeno": "jindrich",
        "kod1": "111111", "kod2": "222222",
    })
    zaznamy = udalosti(capsys.readouterr().out, "console_login")
    assert len(zaznamy) == 1
    assert zaznamy[0]["reason"] == "bad_form"
    assert zaznamy[0]["origin"]


def test_an_unknown_realm_reaches_the_operational_log(prostredi, capsys):
    prostredi.post("/login", data={
        "realm": "nikdy.neexistoval", "jmeno": "jindrich",
        "kod1": "111111", "kod2": "222222",
    })
    zaznamy = udalosti(capsys.readouterr().out, "console_login")
    assert len(zaznamy) == 1
    assert zaznamy[0]["reason"] == "unknown_realm"
    assert zaznamy[0]["realm"] == "nikdy.neexistoval"


def test_the_deformed_value_is_logged_as_it_arrived(prostredi, capsys):
    """Normalizovany tvar by nerekl nic - hleda se prave ten rozbity."""
    prostredi.post("/login", data={
        "realm": REALM, "jmeno": "Jindrich Nemec!",
        "kod1": "111111", "kod2": "222222",
    })
    zaznam = udalosti(capsys.readouterr().out, "console_login")[0]
    assert zaznam["name"] == "Jindrich Nemec!"


# == co do provozniho logu NEPATRI ====================================


def test_a_wrong_code_stays_in_the_audit_only(prostredi, tmp_path, capsys):
    """Realm je znamy, takze `authenticate_admin` udalost zauditoval - do
    provozniho logu uz podruhe nejde."""
    prostredi.post("/login", data={
        "realm": REALM, "jmeno": "jindrich", "kod1": "111111", "kod2": "222222",
    })
    assert udalosti(capsys.readouterr().out, "console_login") == []

    stopa = read_events(koren(tmp_path / "data"), kind="authenticate")
    assert [u["outcome"] for u in stopa] == ["denied"]
    assert stopa[0]["reason"] == "bad_code"


def test_a_successful_login_stays_in_the_audit_only(prostredi, tmp_path, capsys):
    prvni, druhy = admin_kody(tmp_path / "data")
    odpoved = prostredi.post("/login", data={
        "realm": REALM, "jmeno": "jindrich", "kod1": prvni, "kod2": druhy,
    })
    assert odpoved.status_code == 302
    assert udalosti(capsys.readouterr().out, "console_login") == []

    stopa = read_events(koren(tmp_path / "data"), kind="authenticate")
    assert [u["outcome"] for u in stopa] == ["ok"]


# == udalosti relace konzole jdou do auditu ===========================


def test_logout_is_audited(prihlaseny_klient, tmp_path):
    klient, token = prihlaseny_klient
    klient.post("/logout", data={"csrf": token})

    stopa = read_events(koren(tmp_path / "data"), kind="session")
    assert [u["op"] for u in stopa] == ["logout"]
    assert stopa[0]["actor"] == "admin:jindrich"


def test_a_missing_csrf_token_is_audited(prihlaseny_klient, tmp_path):
    """Zamitnuta mutace je bezpecnostne zajimava a dosud nemela stopu nikde."""
    klient, _ = prihlaseny_klient
    odpoved = klient.post("/logout", data={"csrf": "podvrzeny"})
    assert odpoved.status_code == 400

    stopa = read_events(koren(tmp_path / "data"), kind="session")
    assert [u["op"] for u in stopa] == ["csrf_denied"]
    assert stopa[0]["path"] == "/logout"


def test_an_evicted_session_is_audited(prihlaseny_klient, tmp_path):
    """Kdyz spravce mezitim zmizi, strazce relaci zabije - a rekne to."""
    import shutil

    klient, _ = prihlaseny_klient
    shutil.rmtree(koren(tmp_path / "data") / "admin-jindrich")

    odpoved = klient.get("/users")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")

    stopa = read_events(koren(tmp_path / "data"), kind="session")
    assert [u["op"] for u in stopa] == ["evicted"]
    assert stopa[0]["reason"] == "admin_removed"


# == proud dela triaz =================================================


def test_routine_events_go_to_stdout_and_problems_to_stderr(capsys):
    log.configure()
    log.info("routine_event", origin="10.0.0.1")
    log.warning("something_broke", error="disk plny")

    zachyceno = capsys.readouterr()
    assert udalosti(zachyceno.out, "routine_event")
    assert udalosti(zachyceno.err, "something_broke")
    # Kazda udalost prave na jednom proudu - jinak by `stream` v logu
    # kontejneru nic nerozlisil.
    assert udalosti(zachyceno.err, "routine_event") == []
    assert udalosti(zachyceno.out, "something_broke") == []


def test_the_operational_log_works_without_configure(capsys):
    """Tovarna pouzita mimo `server.main` (test, vlastni WSGI zavedeni) nesmi
    o log TISE prijit - handlery se doplni samy."""
    import logging

    logging.getLogger(log.LOGGER_NAME).handlers.clear()
    log.info("late_event")
    assert udalosti(capsys.readouterr().out, "late_event")


# == sanitace =========================================================


def test_a_newline_cannot_forge_a_second_record(prostredi, capsys):
    """`name` je pole z formulare. V radkovem logu by novy radek podvrhl cizi
    zaznam; JSON ho escapuje, takze radek zustane jeden."""
    podvrh = 'x\n{"event": "console_login", "outcome": "ok"}'
    prostredi.post("/login", data={
        "realm": REALM, "jmeno": podvrh, "kod1": "1", "kod2": "2",
    })
    zaznamy = radky(capsys.readouterr().out)
    assert len(zaznamy) == 1
    assert zaznamy[0]["outcome"] == "denied"
    assert "\n" in zaznamy[0]["name"]      # obsah zustal, jen neunikl ven


def test_an_unbounded_value_is_truncated():
    """Vzory v `principals` delku neomezuji, takze strop musi byt v logu."""
    orez = log.sanitize("a" * (log.MAX_VALUE + 500))
    assert len(orez) == log.MAX_VALUE + 3
    assert orez.endswith("...")


def test_a_legitimate_path_is_not_truncated():
    cesta = "/var/lib/access-manager/realm-example.com/admin-jindrich/totp.txt"
    assert log.sanitize(cesta) == cesta


def test_fields_cannot_overwrite_the_formatter_keys(capsys):
    log.configure()
    log.info("pokus", level="fatal", t="1970-01-01T00:00:00+00:00", origin="1.2.3.4")
    zaznam = radky(capsys.readouterr().out)[0]
    assert zaznam["level"] == "info"
    assert not zaznam["t"].startswith("1970")
    assert zaznam["origin"] == "1.2.3.4"
