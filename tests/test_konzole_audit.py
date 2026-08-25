"""Stranka Audit: jediny GET, zadna mutace, zadny CSRF. Filtry (od/do/subjekt/
kind/outcome) nad `read_events`. Kazde pole udalosti se cte tolerantne pres
`.get` - rucne pripsany kusy radek nesmi stranku shodit.
"""
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

    jen_jindrich = klient.get("/audit?subject=admin:jindrich").get_data(as_text=True)
    assert "admin:jindrich" in jen_jindrich
    assert "admin:outsider" not in jen_jindrich

    jen_outsider = klient.get("/audit?subject=admin:outsider").get_data(as_text=True)
    assert "admin:outsider" in jen_outsider
    assert "admin:jindrich" not in jen_outsider


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
