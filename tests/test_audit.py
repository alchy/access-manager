"""Kazdy realm loguje do sveho prostoru; podrobne duvody patri SEM.

Jeden radek = jedna udalost; denni soubory delaji z retence proste mazani.
Tajemstvi ani kody se neloguji nikdy - jen jmena, vysledky, cisla kroku.
"""
import json

from helpers import REALM, kod, koren, zaloz

from access_manager import Access, Admin
from access_manager.audit import read_events


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
