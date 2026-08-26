"""Stranka Audit: jediny GET, zadna mutace, zadny CSRF. Filtry (od/do/kdo/
kind/outcome) nad `read_events`. Kazde pole udalosti se cte tolerantne pres
`.get` - rucne pripsany kusy radek nesmi stranku shodit.
"""
import re
from datetime import UTC, datetime

import pytest
from helpers import REALM, koren

from access_manager.audit import append_event


def test_the_admin_login_event_is_visible(prihlaseny_klient):
    # `prihlaseny_klient` uz prihlasil "jindrich" - authenticate_admin tim
    # zapsal auditni udalost driv, nez test vubec zacal.
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit").get_data(as_text=True)
    assert "admin:jindrich" in telo
    assert "authenticate" in telo
    assert "ok" in telo


def test_the_subject_filter_shows_matching_and_hides_others(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    # Druha udalost s jinym subjektem: neznamy spravce -> "denied".
    klient.post(
        "/login",
        data={"realm": REALM, "jmeno": "outsider", "kod1": "000000", "kod2": "000000"},
    )

    jen_jindrich = klient.get("/audit?kdo=admin:jindrich").get_data(as_text=True)
    assert "admin:jindrich" in jen_jindrich
    assert "admin:outsider" not in jen_jindrich

    jen_outsider = klient.get("/audit?kdo=admin:outsider").get_data(as_text=True)
    assert "admin:outsider" in jen_outsider
    assert "admin:jindrich" not in jen_outsider


def _filtracni_pole(telo):
    """Jmena poli filtru v poradi, jak stoji ve sloupcich.

    Pole nestoji uvnitr `<form>` - odkazuji se na nej pres `form="filtr"`,
    aby mohla sedet primo v bunkach tabulky.
    """
    radek = telo[telo.index('class="filtr-radek"'):telo.index("</thead>")]
    return re.findall(r'name="([a-z_]+)" form="filtr"', radek)


def test_the_filter_form_sends_what_the_route_reads(prihlaseny_klient):
    """Formular posilal `od`/`do`/`subjekt`, route cetla `from`/`to`/`subject` -
    tri z peti filtru tise nedelaly nic a testy to nechytily, protoze si
    dotaz skladaly v URL samy. Tenhle test se diva na SKUTECNA pole."""
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit").get_data(as_text=True)
    assert set(_filtracni_pole(telo)) == {
        "od", "do", "kind", "kdo", "odkud", "aplikace", "outcome",
    }

    # A kazde z nich musi na strance opravdu neco delat.
    klient.post(
        "/login",
        data={"realm": REALM, "jmeno": "outsider", "kod1": "000000", "kod2": "000000"},
    )
    for dotaz, ceka_se in (
        ("kdo=admin:jindrich", False),
        ("outcome=ok", False),
        ("kind=write", False),
        ("od=2000-01-01&do=2000-01-02", False),
    ):
        telo = klient.get(f"/audit?{dotaz}").get_data(as_text=True)
        assert ("admin:outsider" in telo) is ceka_se, dotaz


def test_each_filter_sits_under_the_column_it_filters(prihlaseny_klient):
    """Filtr uz nema vlastni popisek - popiskem je ZAHLAVI SLOUPCE nad nim.
    Proto musi porad sedet poradi: n-te pole pod n-tym sloupcem. Drive stalo
    pole "Predmet" nad sloupcem "Kdo" a nesouviselo s nim vubec."""
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit").get_data(as_text=True)

    zahlavi = re.findall(r"<th>(.*?)</th>", telo, flags=re.S)
    zahlavi = [z.strip() for z in zahlavi]
    assert zahlavi == ["Čas", "Událost", "Kdo", "Odkud", "Aplikace", "Výsledek"]

    # Sloupec "Cas" nese dve pole (od-do), ostatni po jednom.
    assert _filtracni_pole(telo) == [
        "od", "do", "kind", "kdo", "odkud", "aplikace", "outcome",
    ]
    assert "Předmět" not in telo


def test_the_new_columns_can_be_filtered(prihlaseny_klient, tmp_path):
    """Sloupec, pod kterym stoji filtr, ho taky musi poslouchat."""
    klient, _ = prihlaseny_klient
    for adresa, aplikace in (("10.0.0.1", "workbench"), ("10.0.0.2", "jina")):
        append_event(koren(tmp_path / "data"), {
            "t": datetime.now(UTC).isoformat(timespec="seconds"),
            "kind": "authenticate", "subject": "user:demo", "outcome": "ok",
            "origin": adresa, "component": aplikace,
        }, retention_days=90)

    jen_prvni = klient.get("/audit?odkud=10.0.0.1").get_data(as_text=True)
    assert "10.0.0.1" in jen_prvni
    assert "10.0.0.2" not in jen_prvni

    jen_workbench = klient.get("/audit?aplikace=workbench").get_data(as_text=True)
    assert "10.0.0.1" in jen_workbench
    assert "10.0.0.2" not in jen_workbench


def test_a_hand_written_minimal_event_does_not_crash_the_page(
    prihlaseny_klient, tmp_path,
):
    kus = {"t": datetime.now(UTC).isoformat(timespec="seconds"), "kind": "weird"}
    append_event(koren(tmp_path / "data"), kus, retention_days=90)

    klient, _ = prihlaseny_klient
    odpoved = klient.get("/audit")
    assert odpoved.status_code == 200
    assert "weird" in odpoved.get_data(as_text=True)


def test_a_malformed_line_does_not_crash_the_page_and_valid_events_still_show(
    prihlaseny_klient, tmp_path,
):
    domov = koren(tmp_path / "data")
    kus = {"t": datetime.now(UTC).isoformat(timespec="seconds"), "kind": "weird2"}
    append_event(domov, kus, retention_days=90)
    soubor = next((domov / "audit").glob("*.jsonl"))
    with soubor.open("a", encoding="utf-8") as f:
        f.write("this is not json\n")

    klient, _ = prihlaseny_klient
    odpoved = klient.get("/audit")
    assert odpoved.status_code == 200
    assert "weird2" in odpoved.get_data(as_text=True)


def test_a_malformed_date_filter_does_not_crash_and_falls_back_to_default(
    prihlaseny_klient,
):
    klient, _ = prihlaseny_klient
    odpoved = klient.get("/audit?from=nedatum&to=takenetohle")
    assert odpoved.status_code == 200
    # Padne na vychozi okno - dnesni prihlaseni tam porad je videt.
    assert "admin:jindrich" in odpoved.get_data(as_text=True)


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/audit"),
])
def test_the_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_filter_texts(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    telo = klient.get("/audit?lang=en").get_data(as_text=True)
    assert "Who" in telo
    assert "Kdo" not in telo


def test_the_who_filter_matches_a_substring_like_the_people_listing(
    prihlaseny_klient,
):
    """Dve vyhledavaci pole v teze konzoli se nemaji chovat ruzne. Filtr nad
    vypisem lidi bere podretezec ("novak" najde "jan.novak@example.com");
    v auditu byla presna shoda, takze prefix `admin:` se musel opsat."""
    klient, _ = prihlaseny_klient
    klient.post(
        "/login",
        data={"realm": REALM, "jmeno": "outsider", "kod1": "000000", "kod2": "000000"},
    )

    # Bez prefixu i jen kus jmena.
    for dotaz in ("jindrich", "JINDRICH", "ndri", "admin:jindrich"):
        telo = klient.get(f"/audit?kdo={dotaz}").get_data(as_text=True)
        assert "admin:jindrich" in telo, dotaz
        assert "admin:outsider" not in telo, dotaz


def test_the_who_filter_still_finds_writes_by_their_actor(prihlaseny_klient):
    """Zapisy nesou jmeno pod `actor`, ne `subject` - bez toho by filtr
    podle toho, co je videt ve sloupci "Kdo", radky zapisu ztratil."""
    klient, csrf = prihlaseny_klient
    klient.post("/users/add", data={"jmeno": "tereza", "csrf": csrf})

    telo = klient.get("/audit?kdo=jindrich").get_data(as_text=True)
    assert "write add_user" in telo
