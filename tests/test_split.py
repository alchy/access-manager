"""Cteni a zapis jsou dva objekty, ne jeden.

Kdyby zavadeni viselo na tomtez objektu, ktery ma aplikace v ruce, umi kazda
apka se svym klicem zalozit uzivatele a strcit ho do `group:spravci`. Unik
klice jedne apky by byl klic ke vsemu - presne to, cemu meli per-komponentove
klice zabranit.

Tenhle soubor hlida TVAR. Skutecne vynuceni je na sluzbe, ktera se diva na
rozsah klice - tady jde o to, aby to nesel nikdo zavolat omylem.
"""
import pytest
from helpers import REALM

from access_manager import Access, Admin

ZAPISOVE = [
    "add_user",
    "add_group",
    "add_member",
    "include",
    "disable_user",
    "enable_user",
    "remove_member",
    "remove_user",
    "pair_missing",
    "revoke_credential",
    "pair",
    "add_admin",
    "remove_admin",
    "revoke_admin_credential",
    "pair_admin",
    "register_component",
    "revoke_component",
]


@pytest.mark.parametrize("jmeno", ZAPISOVE)
def test_access_cannot_write(tmp_path, jmeno):
    assert not hasattr(Access.local(tmp_path, realm=REALM), jmeno)


@pytest.mark.parametrize("jmeno", ZAPISOVE)
def test_admin_can_write(tmp_path, jmeno):
    assert hasattr(Admin.local(tmp_path, realm=REALM), jmeno)


def test_admin_does_not_authenticate(tmp_path):
    # Spravcovsky nastroj neni prihlasovaci cesta. Kdyby umel `authenticate`,
    # je pokuseni pouzit spravcovsky klic v aplikaci - a ten smi vsechno.
    assert not hasattr(Admin.local(tmp_path, realm=REALM), "authenticate")


def test_neither_facade_has_authenticate_admin(tmp_path):
    # Dvoukodove overeni spravce je vnitrni povrch pro budouci konzoli - ne
    # neco, co by mohla zavolat aplikace nebo spravcovsky nastroj.
    assert not hasattr(Access.local(tmp_path, realm=REALM), "authenticate_admin")
    assert not hasattr(Admin.local(tmp_path, realm=REALM), "authenticate_admin")


def test_admin_has_admins(tmp_path):
    assert hasattr(Admin.local(tmp_path, realm=REALM), "admins")


def test_access_does_not_have_admin_methods(tmp_path):
    access = Access.local(tmp_path, realm=REALM)
    admin_methods = [
        "add_admin",
        "admins",
        "remove_admin",
        "revoke_admin_credential",
        "pair_admin",
    ]
    for metoda in admin_methods:
        assert not hasattr(access, metoda)


def test_access_does_not_have_component_methods(tmp_path):
    access = Access.local(tmp_path, realm=REALM)
    # component_for_key je pro sluzbu - ne pro aplikaci
    assert not hasattr(access, "component_for_key")
    assert not hasattr(access, "register_component")
    assert not hasattr(access, "revoke_component")
    assert not hasattr(access, "components")
