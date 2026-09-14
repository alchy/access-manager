"""Auditni pohledy podle toho, KDO jednal: spravci, uzivatele, aplikace.

Stopa na disku je jedna; pohledy ji jen jinak ctou. Testy zakladaji radky
primo pres `append_event` s razitkem "ted", at nezalezi na hodinach stroje
ani na tom, do ktereho denniho souboru radek padne.
"""
from datetime import UTC, datetime, timedelta

import pytest
from helpers import koren

from access_manager.audit import append_event
from access_manager.konzole import pohledy


def _ted(posun_s=0):
    cas = datetime.now(UTC) + timedelta(seconds=posun_s)
    return cas.isoformat(timespec="seconds")


def _zapis(tmp_path, **pole):
    pole.setdefault("t", _ted())
    append_event(koren(tmp_path / "data"), pole, retention_days=90)


def _t(klic):
    return klic


# == trideni do pohledu ====================================================


def test_each_kind_of_event_lands_in_the_view_of_who_acted():
    prihlaseni_spravce = {"kind": "authenticate", "purpose": "admin",
                          "subject": "admin:j"}
    zapis = {"kind": "write", "op": "add_user", "actor": "admin:j"}
    relace = {"kind": "session", "op": "logout", "actor": "admin:j"}
    overeni_pres_api = {"kind": "authenticate", "purpose": "login",
                        "subject": "user:hana", "component": "wb"}
    overeni_lokalne = {"kind": "authenticate", "purpose": "login",
                       "subject": "user:hana"}
    pozadavek = {"kind": "access", "component": "wb", "path": "/v1/whoami"}
    zamitnuty = {"kind": "origin_denied", "component": "wb"}

    assert pohledy.pocty([prihlaseni_spravce, zapis, relace, overeni_pres_api,
                          overeni_lokalne, pozadavek, zamitnuty]) == {
        "spravci": 3, "uzivatele": 2, "aplikace": 3, "vse": 7,
    }
    # Overeni pres API je v OBOU pohledech - na disku je jednou.
    assert pohledy.je_uzivatel(overeni_pres_api)
    assert pohledy.je_aplikace(overeni_pres_api)
    assert not pohledy.je_aplikace(overeni_lokalne)


# == spravci: relace ======================================================


def _spravci(udalosti, **filtry):
    return pohledy.skupiny_spravcu(udalosti, filtry, _t)


def test_changes_are_grouped_under_the_session_they_were_made_in():
    udalosti = [
        {"t": "2026-09-14T07:29:27+00:00", "kind": "authenticate", "purpose": "admin",
         "subject": "admin:j", "origin": "193.0.231.250", "outcome": "denied",
         "reason": "bad_code"},
        {"t": "2026-09-14T07:31:34+00:00", "kind": "authenticate", "purpose": "admin",
         "subject": "admin:j", "origin": "193.0.231.250", "outcome": "ok"},
        {"t": "2026-09-14T07:31:52+00:00", "kind": "write", "actor": "admin:j",
         "op": "register_component", "name": "soc", "key_id": "k3",
         "origin": "193.0.231.250", "outcome": "ok"},
        {"t": "2026-09-14T07:35:36+00:00", "kind": "write", "actor": "admin:j",
         "op": "add_origin", "name": "soc", "range": "193.0.231.0/24",
         "origin": "193.0.231.250", "outcome": "ok"},
        {"t": "2026-09-14T07:40:00+00:00", "kind": "session", "op": "logout",
         "actor": "admin:j", "origin": "193.0.231.250"},
        {"t": "2026-09-14T07:45:00+00:00", "kind": "write", "actor": "operator",
         "op": "add_admin", "name": "marie", "outcome": "ok"},
    ]
    skupiny = _spravci(udalosti)
    assert [s["druh"] for s in skupiny] == ["mimo", "relace", "neuspech"]
    relace = skupiny[1]
    assert relace["zmen"] == 2
    assert relace["konec"]["op"] == "logout"
    # Nejnovejsi radek skupiny prvni. `_t` nic nepreklada, takze operace bez
    # prekladu spadne na surove jmeno - stejne jako neznama operace v konzoli.
    assert [r["co"] for r in relace["radky"]][:2] == [
        "pohled.op.session.logout", "add_origin",
    ]
    assert relace["radky"][1]["cil"] == "soc  193.0.231.0/24"


def test_a_change_without_a_sign_in_in_the_period_gets_its_own_session():
    skupiny = _spravci([
        {"t": "2026-09-10T13:00:46+00:00", "kind": "write", "actor": "admin:j",
         "op": "register_component", "name": "socupload", "key_id": "k1"},
    ])
    assert [s["druh"] for s in skupiny] == ["bez_zacatku"]


def test_filtering_keeps_the_session_header():
    udalosti = [
        {"t": "2026-09-14T07:31:34+00:00", "kind": "authenticate", "purpose": "admin",
         "subject": "admin:j", "origin": "193.0.231.250", "outcome": "ok"},
        {"t": "2026-09-14T07:31:52+00:00", "kind": "write", "actor": "admin:j",
         "op": "add_user", "name": "hana", "outcome": "ok"},
        {"t": "2026-09-14T07:32:00+00:00", "kind": "write", "actor": "admin:j",
         "op": "add_group", "name": "ucetni", "outcome": "ok"},
    ]
    skupiny = _spravci(udalosti, co="add_group")
    assert len(skupiny) == 1
    assert skupiny[0]["zacatek"]["origin"] == "193.0.231.250"   # hlavicka zustava
    assert [r["cil"] for r in skupiny[0]["radky"]] == ["ucetni"]


def test_an_old_range_write_does_not_pass_the_range_off_as_the_admins_address():
    # Pred `range` nesl zapis rozsahu rozsah v `origin`.
    stary = {"kind": "write", "actor": "admin:j", "op": "add_origin",
             "name": "soc", "origin": "127.0.0.1/32"}
    novy = {**stary, "origin": "193.0.231.250", "range": "127.0.0.1/32"}
    assert pohledy.odkud_aktora(stary) == "—"
    assert pohledy.co_zmenil(stary, _t)[1] == "soc  127.0.0.1/32"
    assert pohledy.odkud_aktora(novy) == "193.0.231.250"
    assert pohledy.co_zmenil(novy, _t)[1] == "soc  127.0.0.1/32"


def test_a_refused_write_reads_as_refused():
    trida, text, _ = pohledy.vysledek(
        {"kind": "write", "op": "remove_admin", "outcome": "denied"}, _t)
    assert (trida, text) == ("vysledek-denied", "pohled.vysledek.write_denied")
    # Starsi zapis bez `outcome` probehl.
    stary = {"kind": "write", "op": "add_user"}
    assert pohledy.vysledek(stary, _t)[0] == "vysledek-write"


# == aplikace: slucovani ==================================================


def _pozadavek(t, cesta="/v1/generation", status=200, **pole):
    return {"t": t, "kind": "access", "component": "wb", "key_id": "k4",
            "origin": "2001:db8::1", "method": "GET", "path": cesta,
            "status": status, "outcome": "ok" if status < 400 else "error", **pole}


def test_consecutive_identical_requests_are_merged_into_one_row():
    udalosti = [
        _pozadavek("2026-09-13T12:00:01+00:00"),
        _pozadavek("2026-09-13T12:01:01+00:00"),
        _pozadavek("2026-09-13T12:02:01+00:00"),
        {"t": "2026-09-13T12:02:30+00:00", "kind": "authenticate", "purpose": "login",
         "subject": "user:hana", "component": "wb", "key_id": "k4",
         "origin": "2001:db8::1", "outcome": "ok"},
        _pozadavek("2026-09-13T12:03:01+00:00"),
        _pozadavek("2026-09-13T12:03:05+00:00", status=404, cesta="/v1/nic"),
    ]
    radky = pohledy.radky_aplikaci(udalosti, {}, _t)
    assert [(r["cesta"], r["pocet"]) for r in radky] == [
        ("/v1/nic", 1), ("/v1/generation", 1), ("/v1/authenticate", 1),
        ("/v1/generation", 3),
    ]
    assert radky[-1]["od"] == pohledy.hodiny(udalosti[0])
    assert radky[2]["subjekt"] == "user:hana"


def test_authentications_and_denied_ranges_are_never_merged():
    denied = {"t": "2026-09-13T12:00:00+00:00", "kind": "origin_denied",
              "component": "wb", "key_id": "k4", "origin": "8.8.8.8"}
    radky = pohledy.radky_aplikaci([denied, dict(denied)], {}, _t)
    assert [r["pocet"] for r in radky] == [1, 1]
    assert radky[0]["vysledek_text"] == "403"


def test_the_request_filter_matches_path_and_user():
    udalosti = [
        _pozadavek("2026-09-13T12:00:01+00:00", cesta="/v1/users/hana"),
        _pozadavek("2026-09-13T12:01:01+00:00", cesta="/v1/whoami"),
    ]
    radky = pohledy.radky_aplikaci(udalosti, {"pozadavek": "hana"}, _t)
    assert [r["cesta"] for r in radky] == ["/v1/users/hana"]


# == uzivatele =============================================================


def test_a_user_row_carries_client_and_server_apart():
    radky = pohledy.radky_uzivatelu([
        {"t": "2026-09-13T12:13:28+00:00", "kind": "authenticate",
         "purpose": "unlock:bf9c11abc031",
         "subject": "user:jindrich", "component": "workbench", "key_id": "k4",
         "origin": "2a01:4f8:1c1b:8c66::1", "client_origin": "193.0.231.250",
         "outcome": "denied", "reason": "bad_code"},
    ], {}, _t)
    r = radky[0]
    assert (r["uzivatel"], r["klient"], r["server"]) == (
        "jindrich", "193.0.231.250", "2a01:4f8:1c1b:8c66::1",
    )
    assert (r["ucel"], r["ucel_doplnek"]) == ("pohled.ucel.unlock", "bf9c11ab…")
    assert (r["vysledek_text"], r["reason"]) == ("pohled.vysledek.denied", "bad_code")


def test_days_are_labelled_today_and_yesterday():
    from datetime import date
    dnes = date(2026, 9, 14)
    katalog = {"pohled.datum": "{den} {d}. {mesic} {rok}", "pohled.dnes": "Dnes",
               "pohled.vcera": "Včera", "pohled.den.0": "pondělí",
               "pohled.den.6": "neděle", "pohled.den.5": "sobota",
               "pohled.mesic.9": "září"}
    t = katalog.get
    assert pohledy.popis_dne(dnes, dnes, t) == "Dnes · pondělí 14. září 2026"
    vcera = pohledy.popis_dne(date(2026, 9, 13), dnes, t)
    assert vcera == "Včera · neděle 13. září 2026"
    assert pohledy.popis_dne(date(2026, 9, 12), dnes, t) == "Sobota 12. září 2026"


# == stranky ==============================================================


@pytest.mark.parametrize("cesta", ["/audit/admins", "/audit/users", "/audit/apps"])
def test_the_views_need_a_session(prostredi, cesta):
    odpoved = prostredi.get(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_sidebar_audit_link_opens_the_admins_view(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    telo = klient.get("/users").get_data(as_text=True)
    assert 'href="/audit/admins"' in telo


def test_the_admins_view_shows_the_session_of_the_signed_in_admin(prihlaseny_klient):
    klient, csrf = prihlaseny_klient
    klient.post("/users/add", data={"csrf": csrf, "jmeno": "tereza"},
                environ_overrides={"REMOTE_ADDR": "192.0.2.44"})
    telo = klient.get("/audit/admins").get_data(as_text=True)
    assert "Relace · jindrich · přihlášen" in telo
    assert "Přihlášení do konzole" in telo
    assert "Přidání uživatele" in telo and "tereza" in telo
    assert "192.0.2.44" in telo
    assert 'class="zalozka aktivni"' in telo


def test_the_tabs_count_each_view_and_keep_the_period(prihlaseny_klient, tmp_path):
    _zapis(tmp_path, kind="access", component="wb", key_id="k1", origin="10.0.0.1",
           method="GET", path="/v1/whoami", status=200, outcome="ok")
    _zapis(tmp_path, kind="authenticate", purpose="login", subject="user:hana",
           component="wb", key_id="k1", origin="10.0.0.1", outcome="ok")
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit/apps?obdobi=30").get_data(as_text=True)
    import re
    vzor = r'(Správci|Uživatelé|Aplikace|Vše)<span class="pocet">(\d+)</span>'
    pocty = dict(re.findall(vzor, telo))
    # Spravce ma aspon prihlaseni z fixtury; overeni je v Uzivatelich i Aplikacich.
    assert pocty["Uživatelé"] == "1"
    assert pocty["Aplikace"] == "2"
    assert int(pocty["Vše"]) == int(pocty["Správci"]) + 2
    assert 'class="aktivni">30 dní' in telo


def test_the_users_view_opens_a_record_detail_with_the_raw_line(
    prihlaseny_klient, tmp_path,
):
    _zapis(tmp_path, kind="authenticate", purpose="login", subject="user:hana",
           component="wb", key_id="k1", origin="2001:db8::1",
           client_origin="193.0.231.250", outcome="denied", reason="bad_code")
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit/users").get_data(as_text=True)
    assert "193.0.231.250" in telo and "2001:db8::1" in telo
    import re
    odkaz = re.search(r'href="(/audit/users\?detail=[0-9a-f]{12})"', telo)
    assert odkaz, "cas radku ma odkazovat na detail"
    detail = klient.get(odkaz.group(1)).get_data(as_text=True)
    assert "Řádek v auditní stopě" in detail
    assert "&#34;client_origin&#34;: &#34;193.0.231.250&#34;" in detail
    assert "Všechny pokusy uživatele hana" in detail
    assert 'data-detail="1"' in detail            # auto-obnova se pozastavi


def test_the_apps_view_merges_polling(prihlaseny_klient, tmp_path):
    for i in range(5):
        _zapis(tmp_path, t=_ted(-300 + i * 60), kind="access", component="wb",
               key_id="k1", origin="10.0.0.1", method="GET", path="/v1/generation",
               status=200, outcome="ok")
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit/apps").get_data(as_text=True)
    assert '<span class="nasobek">5×</span>' in telo
    assert telo.count("/v1/generation") == 1


def test_a_filter_narrows_the_view(prihlaseny_klient, tmp_path):
    _zapis(tmp_path, kind="access", component="wb", key_id="k1", origin="10.0.0.1",
           method="GET", path="/v1/whoami", status=200, outcome="ok")
    _zapis(tmp_path, kind="access", component="soc", key_id="k3", origin="10.0.0.2",
           method="GET", path="/v1/users", status=200, outcome="ok")
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit/apps?aplikace=SOC").get_data(as_text=True)
    assert "/v1/users" in telo
    assert "/v1/whoami" not in telo


def test_the_refresh_link_keeps_the_filters(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit/apps?aplikace=wb&obdobi=30").get_data(as_text=True)
    obnova = telo.split('class="obnova"')[1].split("</div>")[0]
    assert "aplikace=wb" in obnova and "obdobi=30" in obnova
    assert "audit.js" in telo


def test_the_filter_form_sends_what_each_view_reads(prihlaseny_klient):
    import re
    klient, _ = prihlaseny_klient
    ocekavane = {
        "/audit/admins": {"od", "do", "spravce", "odkud", "co", "vysledek"},
        "/audit/users": {"od", "do", "uzivatel", "klient", "aplikace", "ucel",
                         "vysledek"},
        "/audit/apps": {"od", "do", "aplikace", "klic", "odkud", "pozadavek",
                        "vysledek"},
    }
    for cesta, pole in ocekavane.items():
        telo = klient.get(cesta).get_data(as_text=True)
        radek = telo[telo.index('class="filtr-radek"'):telo.index("</thead>")]
        assert set(re.findall(r'name="([a-z_]+)" form="filtr"', radek)) == pole, cesta


def test_the_english_catalogue_renders_the_views(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit/admins?lang=en").get_data(as_text=True)
    assert "What changed" in telo and "Every minute" in telo
    assert "Co změnil" not in telo


def test_a_hand_written_minimal_event_does_not_crash_any_view(
    prihlaseny_klient, tmp_path,
):
    for kus in ({"kind": "write"}, {"kind": "access"}, {"kind": "authenticate"},
                {"kind": "session"}, {"kind": "origin_denied"}, {"kind": "weird"}):
        _zapis(tmp_path, **kus)
    klient, _ = prihlaseny_klient
    for cesta in ("/audit/admins", "/audit/users", "/audit/apps", "/audit"):
        assert klient.get(cesta).status_code == 200, cesta
