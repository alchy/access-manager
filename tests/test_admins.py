"""Spravce realmu je oddelena identita: neni uzivatel, nema skupiny.

Tentyz clovek jako spravce i clen ma dve tajemstvi a dve polozky
v autentikatoru; odvolani jedne se druhe nedotkne. Posledniho spravce
nejde odebrat ani mu odvolat token - realm nesmi zustat bez spravy.
"""
import pytest
from helpers import REALM, koren

from access_manager import Access, Admin


def admin(tmp_path):
    return Admin.local(tmp_path, realm=REALM)


def test_an_admin_is_not_a_user(tmp_path):
    admin(tmp_path).add_admin("jindrich")
    access = Access.local(tmp_path, realm=REALM)
    assert access.user("jindrich") is None
    assert "jindrich" not in access.users()


def test_an_admin_and_a_user_share_a_name_but_nothing_else(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    a.add_user("jindrich")
    tajemstvi_admin = (koren(tmp_path) / "admin-jindrich" / "totp.secret").read_text()
    tajemstvi_user = (koren(tmp_path) / "user-jindrich" / "totp.secret").read_text()
    assert tajemstvi_admin != tajemstvi_user


def test_the_pairing_label_carries_realm_and_role(tmp_path):
    a = admin(tmp_path)
    zavedeni = a.add_admin("jindrich")
    assert zavedeni.label == f"{REALM}-admin-jindrich"
    zavedeni = a.add_user("hana")
    assert zavedeni.label == f"{REALM}-member-hana"


def test_admins_are_listed_separately(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    a.add_admin("marie")
    assert a.admins() == ["jindrich", "marie"]


def test_the_last_admin_cannot_be_removed(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    with pytest.raises(ValueError):
        a.remove_admin("jindrich")


def test_the_last_admins_token_cannot_be_revoked(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    with pytest.raises(ValueError):
        a.revoke_admin_credential("jindrich")


def test_a_second_admin_can_be_removed(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    a.add_admin("marie")
    a.remove_admin("marie")
    assert a.admins() == ["jindrich"]


def test_admin_lifecycle_moves_the_generation(tmp_path):
    a = admin(tmp_path)
    access = Access.local(tmp_path, realm=REALM)
    a.add_admin("jindrich")
    pred = access.generation()
    a.add_admin("marie")
    assert access.generation() > pred
