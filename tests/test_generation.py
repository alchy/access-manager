"""Generace: nezmenene cislo znamena, ze cache plati dal.

Resi napeti mezi "odvolani je okamzite" a "expiraci si hlida kazdy
komponent sam" (navrh par. 3.4) - jeden trivialni dotaz misto push kanalu.
"""
from helpers import kod, zaloz

from access_manager import Access, Admin


def test_a_fresh_home_is_generation_zero(tmp_path):
    assert Access.local(tmp_path).generation() == 0


def test_every_write_moves_the_generation(tmp_path):
    admin = Admin.local(tmp_path)
    access = Access.local(tmp_path)
    admin.add_user("hana")
    prvni = access.generation()
    admin.add_group("ucetni")
    druha = access.generation()
    admin.add_member("ucetni", "hana")
    treti = access.generation()
    assert 0 < prvni < druha < treti


def test_reading_does_not_move_the_generation(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    pred = access.generation()
    access.user("hana")
    access.users()
    access.groups()
    assert access.generation() == pred


def test_a_verdict_carries_the_generation(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    verdikt = access.authenticate("hana", {"totp": kod()}, purpose="login")
    assert verdikt.gen == access.generation()


def test_a_refusal_carries_the_generation_too(tmp_path):
    # Navrh par. 3.1: gen je pribalene ke KAZDE odpovedi, ne jen k `ok`.
    zaloz(tmp_path, "hana")
    verdikt = Access.local(tmp_path).authenticate(
        "hana", {"totp": "000000"}, purpose="login"
    )
    assert verdikt.gen == Access.local(tmp_path).generation()
