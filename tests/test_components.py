"""Klice aplikaci: vydat jednou, ulozit jen otisk.

Registrace aplikace v realmu = udeleni pristupu k verejnemu API toho
realmu. Klic na serveru nikdy nelezi - ztraceny klic se nevzpomina,
vyda se novy.
"""
import pytest
from helpers import REALM, koren

from access_manager import Access, Admin
from access_manager.files import FileStore


def admin(tmp_path):
    return Admin.local(tmp_path, realm=REALM)


def test_registration_returns_the_key_exactly_once(tmp_path):
    klic = admin(tmp_path).register_component("app:report")
    assert klic.startswith("am_")
    zaznamy = admin(tmp_path).components()
    assert [k.name for k in zaznamy] == ["app:report"]
    assert klic not in repr(zaznamy)          # otisk, nikdy klic


def test_the_key_verifies_against_its_fingerprint(tmp_path):
    klic = admin(tmp_path).register_component(
        "core", origins=("10.0.0.0/8",), detail=True
    )
    store = FileStore(koren(tmp_path), realm=REALM)
    komponenta = store.component_for_key(klic)
    assert komponenta is not None
    assert komponenta.name == "core"
    assert komponenta.detail is True
    assert komponenta.origins == ("10.0.0.0/8",)


def test_a_wrong_key_verifies_as_nothing(tmp_path):
    admin(tmp_path).register_component("core")
    store = FileStore(koren(tmp_path), realm=REALM)
    assert store.component_for_key("am_k1_" + "0" * 64) is None


def test_a_revoked_key_stops_working(tmp_path):
    a = admin(tmp_path)
    klic = a.register_component("core")
    a.revoke_component("core")
    assert FileStore(koren(tmp_path), realm=REALM).component_for_key(klic) is None


def test_an_invalid_cidr_origin_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not-a-cidr"):
        admin(tmp_path).register_component("core", origins=("not-a-cidr",))
    assert admin(tmp_path).components() == []


def test_a_duplicate_component_name_is_refused(tmp_path):
    a = admin(tmp_path)
    a.register_component("core")
    with pytest.raises(ValueError):
        a.register_component("core")


def test_key_ids_grow_and_survive_revocation(tmp_path):
    a = admin(tmp_path)
    k1 = a.register_component("prvni")
    a.revoke_component("prvni")
    k2 = a.register_component("druha")
    id1 = k1.split("_")[1]
    id2 = k2.split("_")[1]
    assert id1 != id2                          # key_id se nikdy nerecykluje


def test_registration_moves_the_generation(tmp_path):
    a = admin(tmp_path)
    access = Access.local(tmp_path, realm=REALM)
    pred = access.generation()
    a.register_component("core")
    assert access.generation() > pred


# == detail jde prepnout bez vymeny klice =============================


def test_detail_can_be_switched_without_replacing_the_key(tmp_path):
    """Tataz uvaha jako u rozsahu: bez tohohle by zmena nazoru na to, kolik
    smi aplikace videt, znamenala odvolat a registrovat znovu - tedy vymenit
    klic ve vsech jejich instalacich."""
    spravce = admin(tmp_path)
    spravce.register_component("app:mzdy")
    otisk = spravce.components()[0].key_hash
    assert spravce.components()[0].detail is False

    spravce.set_detail("app:mzdy", True)
    assert spravce.components()[0].detail is True
    assert spravce.components()[0].key_hash == otisk      # klic se nesahnul

    spravce.set_detail("app:mzdy", False)
    assert spravce.components()[0].detail is False
    assert spravce.components()[0].key_hash == otisk


def test_switching_detail_bumps_the_generation(tmp_path):
    """Generace nese cache klicu ve sluzbe - bez bumpu by zmena zacala platit
    az po restartu."""
    spravce = admin(tmp_path)
    spravce.register_component("app:mzdy")
    pred = Access.local(tmp_path, realm=REALM).generation()
    spravce.set_detail("app:mzdy", True)
    assert Access.local(tmp_path, realm=REALM).generation() > pred


def test_setting_detail_to_the_same_value_is_a_no_op(tmp_path):
    """Bez zmeny se nema bumpnout generace ani zapsat audit - jinak by
    kazde odeslani formulare vyrobilo udalost o nicem."""
    spravce = admin(tmp_path)
    spravce.register_component("app:mzdy")
    spravce.set_detail("app:mzdy", True)
    pred = Access.local(tmp_path, realm=REALM).generation()

    spravce.set_detail("app:mzdy", True)
    assert Access.local(tmp_path, realm=REALM).generation() == pred


def test_setting_detail_on_an_unknown_component_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="neexistuje"):
        admin(tmp_path).set_detail("app:neni", True)


def test_switching_detail_lands_in_the_audit(tmp_path):
    from access_manager.audit import read_events

    spravce = admin(tmp_path)
    spravce.register_component("app:mzdy")
    spravce.set_detail("app:mzdy", True)
    zapisy = [
        u for u in read_events(koren(tmp_path), kind="write")
        if u.get("op") == "set_detail"
    ]
    assert len(zapisy) == 1
    assert zapisy[0]["name"] == "app:mzdy"
    assert zapisy[0]["detail"] is True
