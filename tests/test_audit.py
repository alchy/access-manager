"""Kazdy realm loguje do sveho prostoru; podrobne duvody patri SEM.

Jeden radek = jedna udalost; denni soubory delaji z retence proste mazani.
Tajemstvi ani kody se neloguji nikdy - jen jmena, vysledky, cisla kroku.
"""
import json
import time

from helpers import REALM, kod, koren, zaloz

from access_manager import Access, Admin
from access_manager.audit import read_events
from access_manager.files import FileStore


def test_authentication_lands_in_the_audit_with_its_reason(tmp_path):
    zaloz(tmp_path, "hana")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": "000000"}, purpose="login", component="app:test"
    )
    udalosti = read_events(koren(tmp_path))
    assert len(udalosti) == 1
    u = udalosti[0]
    assert u["kind"] == "authenticate"
    assert u["subject"] == "user:hana"
    assert u["component"] == "app:test"
    assert u["outcome"] == "denied"
    assert u["reason"] == "bad_code"


def test_the_code_itself_is_never_logged(tmp_path):
    zaloz(tmp_path, "hana")
    spravny = kod()
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": spravny}, purpose="login"
    )
    for soubor in (koren(tmp_path) / "audit").glob("*.jsonl"):
        assert spravny not in soubor.read_text(encoding="utf-8")


def test_writes_carry_their_actor(tmp_path):
    Admin.local(tmp_path, realm=REALM, actor="admin:jindrich").add_user("hana")
    zapisy = read_events(koren(tmp_path), kind="write")
    assert zapisy
    assert zapisy[-1]["actor"] == "admin:jindrich"
    assert zapisy[-1]["op"] == "add_user"


def test_the_default_actor_is_the_operator(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_group("ucetni")
    zapisy = read_events(koren(tmp_path), kind="write")
    assert zapisy[-1]["actor"] == "operator"


def test_events_can_be_filtered_by_subject(tmp_path):
    zaloz(tmp_path, "hana")
    zaloz(tmp_path, "petr")
    access = Access.local(tmp_path, realm=REALM)
    access.authenticate("hana", {"totp": "000000"}, purpose="login")
    access.authenticate("petr", {"totp": "000000"}, purpose="login")
    jen_hana = read_events(koren(tmp_path), subject="user:hana")
    assert {u["subject"] for u in jen_hana} == {"user:hana"}


def test_old_daily_files_are_pruned(tmp_path):
    zaloz(tmp_path, "hana")
    adresar = koren(tmp_path) / "audit"
    adresar.mkdir(parents=True, exist_ok=True)
    (adresar / "2020-01-01.jsonl").write_text("{}\n", encoding="utf-8")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": "000000"}, purpose="login"
    )
    assert not (adresar / "2020-01-01.jsonl").exists()


def test_every_line_is_valid_json(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path, realm=REALM).add_group("ucetni")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": "000000"}, purpose="login"
    )
    for soubor in (koren(tmp_path) / "audit").glob("*.jsonl"):
        for radek in soubor.read_text(encoding="utf-8").splitlines():
            json.loads(radek)


def test_a_malformed_line_is_skipped_and_the_rest_still_reads(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_group("ucetni")
    soubor = next((koren(tmp_path) / "audit").glob("*.jsonl"))
    with soubor.open("a", encoding="utf-8") as f:
        f.write("this is not json\n")

    udalosti = read_events(koren(tmp_path))
    assert len(udalosti) == 1               # jen ta platna, poskozeny radek zmizel
    assert udalosti[0]["op"] == "add_group"


# == kdo se ptal, ne jen koho ==========================================


def test_authenticate_records_who_asked_and_from_where(tmp_path):
    """Bez `origin` se z auditu da zjistit jen adresa ODMITNUTEHO pokusu
    (`origin_denied`), ne uspesneho - a to je pri vysetrovani naopak."""
    zaloz(tmp_path, "hana")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login",
        component="workbench", key_id="k3", origin="2001:db8::1",
    )
    udalost = read_events(koren(tmp_path), kind="authenticate")[-1]
    assert udalost["subject"] == "user:hana"       # koho se ptal
    assert udalost["component"] == "workbench"     # kdo se ptal
    assert udalost["key_id"] == "k3"               # kterym klicem
    assert udalost["origin"] == "2001:db8::1"      # odkud


def test_a_local_call_does_not_pretend_to_have_an_address(tmp_path):
    """`Access.local` zadnou adresu ani klic nema. Prazdna hodnota by
    predstirala, ze se merily a nic nevysly - pole se proto NEPISE."""
    zaloz(tmp_path, "hana")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login",
    )
    udalost = read_events(koren(tmp_path), kind="authenticate")[-1]
    assert "origin" not in udalost
    assert "key_id" not in udalost


def test_an_admin_login_records_the_address(tmp_path):
    """Prihlaseni spravce je nejzajimavejsi udalost v realmu a neslo z nej
    poznat, odkud prislo."""
    admin = Admin.local(tmp_path, realm=REALM)
    admin.add_admin("marie")
    tajemstvi = (
        koren(tmp_path) / "admin-marie" / "totp.secret"
    ).read_text(encoding="utf-8").strip()

    store = FileStore(koren(tmp_path), realm=REALM)
    ted = time.time()
    store.authenticate_admin(
        "marie", kod(tajemstvi, at=ted), kod(tajemstvi, at=ted + 30),
        origin="10.89.0.2",
    )
    udalost = read_events(koren(tmp_path), kind="authenticate")[-1]
    assert udalost["subject"] == "admin:marie"
    assert udalost["origin"] == "10.89.0.2"


def test_recent_by_subject_returns_newest_first_and_stops_at_the_limit(tmp_path):
    from access_manager.audit import append_event, recent_by_subject

    koren(tmp_path).mkdir(parents=True, exist_ok=True)
    for i in range(7):
        append_event(koren(tmp_path), {
            "t": f"2026-08-26T10:0{i}:00+00:00", "kind": "authenticate",
            "subject": "user:hana", "outcome": "ok",
        }, retention_days=90)
    append_event(koren(tmp_path), {
        "t": "2026-08-26T11:00:00+00:00", "kind": "write",
        "subject": "user:hana", "op": "add_user",
    }, retention_days=90)

    nalezene = recent_by_subject(
        koren(tmp_path), ["user:hana"], kind="authenticate", limit=5,
    )
    casy = [u["t"] for u in nalezene["user:hana"]]
    assert len(casy) == 5
    assert casy == sorted(casy, reverse=True)      # nejnovejsi prvni
    assert casy[0] == "2026-08-26T10:06:00+00:00"  # `write` se nepocita


def test_recent_by_subject_keeps_subjects_apart(tmp_path):
    from access_manager.audit import append_event, recent_by_subject

    koren(tmp_path).mkdir(parents=True, exist_ok=True)
    for jmeno in ("hana", "petr"):
        append_event(koren(tmp_path), {
            "t": "2026-08-26T10:00:00+00:00", "kind": "authenticate",
            "subject": f"user:{jmeno}", "outcome": "ok",
        }, retention_days=90)

    nalezene = recent_by_subject(
        koren(tmp_path), ["user:hana", "user:petr", "user:nikdo"],
        kind="authenticate",
    )
    assert len(nalezene["user:hana"]) == 1
    assert len(nalezene["user:petr"]) == 1
    assert nalezene["user:nikdo"] == []            # klic je tam i prazdny


def test_recent_by_subject_survives_a_broken_line(tmp_path):
    from access_manager.audit import ADRESAR, append_event, recent_by_subject

    koren(tmp_path).mkdir(parents=True, exist_ok=True)
    append_event(koren(tmp_path), {
        "t": "2026-08-26T10:00:00+00:00", "kind": "authenticate",
        "subject": "user:hana", "outcome": "ok",
    }, retention_days=90)
    soubor = next((koren(tmp_path) / ADRESAR).glob("*.jsonl"))
    with soubor.open("a", encoding="utf-8") as f:
        f.write("tohle neni JSON\n")

    nalezene = recent_by_subject(koren(tmp_path), ["user:hana"])
    assert len(nalezene["user:hana"]) == 1
