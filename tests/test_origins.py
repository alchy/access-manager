"""Povolene rozsahy komponenty jdou menit, aniz by se sahlo na klic.

Puvodne slo `origins` zadat jen pri registraci. Zmena rozsahu tedy znamenala
odvolat a registrovat znovu - tedy vymenit klic ve VSECH aplikacich jen proto,
ze se presunul server. `add_origin`/`remove_origin` to rozdeluji: klic zustava,
zmena plati hned (bumpne se generace, na ktere stoji cache klicu v serveru).
"""
import pytest
from helpers import REALM, koren

from access_manager import Admin
from access_manager.audit import read_events
from access_manager.files import FileStore


def admin(tmp_path):
    return Admin.local(tmp_path, realm=REALM, actor="operator:test")


def komponenta(tmp_path, jmeno="app:report"):
    for zaznam in admin(tmp_path).components():
        if zaznam.name == jmeno:
            return zaznam
    return None


def test_a_registered_component_starts_with_no_ranges(tmp_path):
    admin(tmp_path).register_component("app:report")
    assert komponenta(tmp_path).origins == ()


def test_adding_a_range_keeps_the_key(tmp_path):
    a = admin(tmp_path)
    klic = a.register_component("app:report")
    a.add_origin("app:report", "10.42.0.0/16")

    store = FileStore(koren(tmp_path), realm=REALM)
    zaznam = store.component_for_key(klic)
    assert zaznam is not None, "klic musi platit i po zmene rozsahu"
    assert zaznam.origins == ("10.42.0.0/16",)


def test_ranges_are_kept_sorted_and_accumulate(tmp_path):
    a = admin(tmp_path)
    a.register_component("app:report")
    a.add_origin("app:report", "192.168.1.7")
    a.add_origin("app:report", "10.42.0.0/16")
    assert komponenta(tmp_path).origins == ("10.42.0.0/16", "192.168.1.7")


def test_ipv6_ranges_are_accepted(tmp_path):
    a = admin(tmp_path)
    a.register_component("app:report")
    a.add_origin("app:report", "2a01:4f8:1c1b::/48")
    assert komponenta(tmp_path).origins == ("2a01:4f8:1c1b::/48",)


def test_removing_a_range_leaves_the_others(tmp_path):
    a = admin(tmp_path)
    a.register_component("app:report")
    a.add_origin("app:report", "10.42.0.0/16")
    a.add_origin("app:report", "192.168.1.7")
    a.remove_origin("app:report", "10.42.0.0/16")
    assert komponenta(tmp_path).origins == ("192.168.1.7",)


def test_removing_the_last_range_is_allowed_and_keeps_the_key(tmp_path):
    """Prazdny seznam = jen smycka. Komponenta se tim fakticky vypne, ale
    klic zustava platny - je to zamer, ne omylem povolena degradace."""
    a = admin(tmp_path)
    klic = a.register_component("app:report")
    a.add_origin("app:report", "10.42.0.0/16")
    a.remove_origin("app:report", "10.42.0.0/16")

    assert komponenta(tmp_path).origins == ()
    store = FileStore(koren(tmp_path), realm=REALM)
    assert store.component_for_key(klic) is not None


def test_the_same_network_in_another_notation_is_not_added_twice(tmp_path):
    """`10.0.0.5` a `10.0.0.5/32` je tataz sit. Ulozit oboji by znamenalo
    dva zaznamy, ze kterych by slo odebrat jen jeden."""
    a = admin(tmp_path)
    a.register_component("app:report")
    a.add_origin("app:report", "10.0.0.5/32")
    a.add_origin("app:report", "10.0.0.5")
    assert komponenta(tmp_path).origins == ("10.0.0.5/32",)


def test_a_range_is_removed_by_network_not_by_string(tmp_path):
    """Kdo v konzoli vidi `10.0.0.5/32`, odebere ho i zapisem `10.0.0.5`."""
    a = admin(tmp_path)
    a.register_component("app:report")
    a.add_origin("app:report", "10.0.0.5/32")
    a.remove_origin("app:report", "10.0.0.5")
    assert komponenta(tmp_path).origins == ()


@pytest.mark.parametrize("rozsah", ["not-a-cidr", "10.0.0.0/99", "", "10.0.0.0 /8"])
def test_a_malformed_range_is_refused_loudly(tmp_path, rozsah):
    """Preklep se NESMI ulozit: `_origin_allowed` nerozpoznanou polozku
    preskakuje, takze by komponenta tise prestala poustet."""
    a = admin(tmp_path)
    a.register_component("app:report")
    with pytest.raises(ValueError):
        a.add_origin("app:report", rozsah)
    assert komponenta(tmp_path).origins == ()


def test_removing_a_range_the_component_does_not_have_is_an_error(tmp_path):
    a = admin(tmp_path)
    a.register_component("app:report")
    with pytest.raises(ValueError):
        a.remove_origin("app:report", "10.0.0.0/8")


def test_an_unknown_component_is_an_error(tmp_path):
    a = admin(tmp_path)
    with pytest.raises(ValueError):
        a.add_origin("app:nikdo", "10.0.0.0/8")
    with pytest.raises(ValueError):
        a.remove_origin("app:nikdo", "10.0.0.0/8")


def test_a_range_change_bumps_the_generation(tmp_path):
    """Na generaci stoji cache klicu ve sluzbe. Bez bumpu by novy rozsah
    zacal platit az po restartu."""
    a = admin(tmp_path)
    a.register_component("app:report")
    store = FileStore(koren(tmp_path), realm=REALM)

    pred = store.generation()
    a.add_origin("app:report", "10.0.0.0/8")
    po_pridani = store.generation()
    assert po_pridani > pred

    a.remove_origin("app:report", "10.0.0.0/8")
    assert store.generation() > po_pridani


def test_range_changes_are_audited_with_actor_and_value(tmp_path):
    a = admin(tmp_path)
    a.register_component("app:report")
    a.add_origin("app:report", "10.0.0.0/8")
    a.remove_origin("app:report", "10.0.0.0/8")

    zapisy = read_events(koren(tmp_path), kind="write")
    operace = [(u["op"], u.get("origin"), u.get("actor")) for u in zapisy]
    assert ("add_origin", "10.0.0.0/8", "operator:test") in operace
    assert ("remove_origin", "10.0.0.0/8", "operator:test") in operace


def test_a_failed_range_change_writes_nothing_to_the_audit(tmp_path):
    a = admin(tmp_path)
    a.register_component("app:report")
    with pytest.raises(ValueError):
        a.add_origin("app:report", "not-a-cidr")
    zapisy = read_events(koren(tmp_path), kind="write")
    assert not [u for u in zapisy if u["op"] == "add_origin"]
