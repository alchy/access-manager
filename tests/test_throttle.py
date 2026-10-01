"""Omezovani pokusu: po N neuspesich prijde `throttled`.

Pocitaji se JEN bad_code/replay existujici identity - neexistujici jmeno
pocitadlo nezveda (jinak si kdokoli necha zamknout cizi jmena) a blokovany
puvod se sem u sluzby vubec nedostane.

Klic je dvojice jmeno a adresa klienta. Zamek se s kazdou dalsi serii
zdvojnasobi a neuspechy se nezapominaji po minute; uspech maze pocitadlo
adresy, ze ktere prisel. Bez adresy klienta plati puvodni pevne okno na
jmeno. Cas testy posouvaji pres `files._now`, necekaji.
"""
import json
import time

import pytest
from helpers import REALM, kod, koren, zaloz

from access_manager import Access, Admin, files
from access_manager.audit import read_events
from access_manager.files import FileStore


class Hodiny:
    def __init__(self):
        self.ted = int(time.time())

    def posun(self, sekund):
        self.ted += sekund


@pytest.fixture
def hodiny(monkeypatch):
    """Cas omezovani pod kontrolou testu. Kody TOTP dal jedou podle
    skutecnych hodin - posouva se jen to, co meri zamky."""
    h = Hodiny()
    monkeypatch.setattr(files, "_now", lambda: h.ted)
    return h


def store_access(tmp_path):
    return Access.local(tmp_path, realm=REALM)


def vycerpej(access, jmeno="hana", pokusu=5):
    for _ in range(pokusu):
        access.authenticate(jmeno, {"totp": "000000"}, purpose="login")


def test_five_failures_throttle_the_identity(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    verdikt = access.authenticate("hana", {"totp": "000000"}, purpose="login")
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after is not None
    assert 0 < verdikt.retry_after <= 60


def test_a_throttled_identity_refuses_even_the_right_code(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    verdikt = access.authenticate("hana", {"totp": kod()}, purpose="login")
    assert verdikt.outcome == "throttled"


def test_success_clears_the_counter(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access, pokusu=4)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")
    vycerpej(access, pokusu=4)
    verdikt = access.authenticate("hana", {"totp": "000000"}, purpose="login")
    assert verdikt.reason == "bad_code"


def test_an_unknown_name_does_not_count(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for _ in range(10):
        access.authenticate("nikdo", {"totp": "000000"}, purpose="login")
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")


def test_an_expired_window_unlocks(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    hodiny.posun(61)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")


def test_without_a_client_address_the_window_does_not_escalate(tmp_path, hodiny):
    """Bez adresy klienta (aplikace ji neposila, lokalni volani) zustava
    pevne okno na jmeno. Stupnovany zamek na jmeno by znamenal, ze pet
    pokusu denne zamkne ciziho cloveka na cely den."""
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for _ in range(4):
        vycerpej(access)
        verdikt = access.authenticate("hana", {"totp": "000000"}, purpose="login")
        assert verdikt.outcome == "throttled" and verdikt.retry_after <= 60
        hodiny.posun(61)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")


def test_non_ascii_codes_count_like_wrong_ones(tmp_path):
    # Driv vyjimka utekla pred `_record_failure` - neomezeny pocet pokusu.
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for _ in range(5):
        access.authenticate("hana", {"totp": "ěščřžý"}, purpose="login")
    verdikt = access.authenticate("hana", {"totp": kod()}, purpose="login")
    assert verdikt.outcome == "throttled"


def test_non_ascii_admin_codes_count_like_wrong_ones(tmp_path):
    from access_manager.files import FileStore
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    store = FileStore(koren(tmp_path), realm=REALM)
    for i in range(5):
        prvni, druhy = ("ěščřžý", "000000") if i % 2 else ("000000", "ěščřžý")
        store.authenticate_admin("jindrich", prvni, druhy)
    verdikt = store.authenticate_admin("jindrich", "000000", "111111")
    assert verdikt.outcome == "throttled"


def test_the_admin_login_is_throttled_too(tmp_path):
    from access_manager.files import FileStore
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    store = FileStore(koren(tmp_path), realm=REALM)
    for _ in range(5):
        store.authenticate_admin("jindrich", "000000", "111111")
    verdikt = store.authenticate_admin("jindrich", "000000", "111111")
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after is not None



# == dvojice jmeno a adresa ===============================================

A, B = "192.0.2.10", "192.0.2.20"


def pokus(access, adresa, totp="000000", jmeno="hana"):
    return access.authenticate(
        jmeno, {"totp": totp}, purpose="login", client_origin=adresa,
    )


def spatne(access, adresa, pocet=5, jmeno="hana"):
    return [pokus(access, adresa, jmeno=jmeno) for _ in range(pocet)]


def test_failures_from_one_address_do_not_lock_the_owner_out(tmp_path, hodiny):
    """Kdo hada z adresy A, zamyka adresu A. Majitel uctu se z B prihlasi."""
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    spatne(access, A)
    assert pokus(access, A, kod()).outcome == "throttled"
    assert pokus(access, B, kod()).outcome == "ok"


def test_the_lock_doubles_with_every_series(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    cekani = []
    for _ in range(4):
        spatne(access, A)
        verdikt = pokus(access, A)
        assert verdikt.outcome == "throttled"
        cekani.append(verdikt.retry_after)
        hodiny.posun(verdikt.retry_after + 1)
    assert cekani == [60, 120, 240, 480]


def test_the_lock_stops_at_the_ceiling(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    store = FileStore(koren(tmp_path), realm=REALM, throttle_max_lock_s=300,
                      throttle_name_attempts=10_000)
    for _ in range(6):
        for _ in range(5):
            store.authenticate("hana", {"totp": "000000"}, purpose="login",
                               client_origin=A)
        verdikt = store.authenticate("hana", {"totp": "000000"}, purpose="login",
                                     client_origin=A)
        hodiny.posun(verdikt.retry_after + 1)
    assert verdikt.retry_after == 300


def test_staying_under_the_limit_no_longer_avoids_the_lock(tmp_path, hodiny):
    """Driv stacilo delat ctyri pokusy za minutu: pocitadlo se po okne
    vynulovalo a omezeni neprislo nikdy - 5760 pokusu denne."""
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    spatne(access, A, pocet=4)
    hodiny.posun(3600)
    assert pokus(access, A).reason == "bad_code"      # paty neuspech zamyka
    assert pokus(access, A, kod()).outcome == "throttled"


def test_a_day_of_quiet_forgets_the_address(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    spatne(access, A, pocet=4)
    hodiny.posun(86400 + 1)
    spatne(access, A, pocet=4)
    assert pokus(access, A).reason == "bad_code"
    # A po zamku: den klidu vrati i uroven zamku na zacatek.
    assert pokus(access, A).outcome == "throttled"
    hodiny.posun(2 * 86400)
    spatne(access, A)
    assert pokus(access, A).retry_after == 60


def test_success_clears_only_its_own_address(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    spatne(access, A, pocet=4)
    spatne(access, B, pocet=4)
    assert pokus(access, B, kod()).outcome == "ok"
    spatne(access, B, pocet=4)
    assert pokus(access, B).reason == "bad_code"      # B zacalo od nuly
    assert pokus(access, A).reason == "bad_code"      # A ne: tohle byl paty
    assert pokus(access, A, kod()).outcome == "throttled"


def test_ipv6_is_keyed_by_its_64_network(tmp_path, hodiny):
    """Jeden pocitac ma v /64 tolik adres, kolik chce. Vsechny jsou jeden klic."""
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for i in range(5):
        pokus(access, f"2001:db8:1:2::{i + 1}")
    assert pokus(access, "2001:db8:1:2:ffff::9", kod()).outcome == "throttled"
    assert pokus(access, "2001:db8:1:3::1", kod()).outcome == "ok"


def test_an_ipv4_mapped_address_is_the_same_ipv4_address(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    spatne(access, f"::ffff:{A}")
    assert pokus(access, A, kod()).outcome == "throttled"


def test_many_addresses_hit_the_slow_counter_of_the_name(tmp_path, hodiny):
    """Kdo strida adresy, ma kazdou zvlast - a s vlastnim rozsahem IPv6 jich
    ma tisice. Nad adresami je proto pomale pocitadlo na jmeno."""
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for i in range(20):
        assert pokus(access, f"198.51.100.{i + 1}").reason == "bad_code"
    verdikt = pokus(access, "203.0.113.200", kod())
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after <= 60
    hodiny.posun(61)
    assert pokus(access, "203.0.113.200", kod()).outcome == "ok"


def test_the_name_lock_is_marked_in_the_audit(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for i in range(20):
        pokus(access, f"198.51.100.{i + 1}")
    radky = [u for u in read_events(koren(tmp_path)) if "lock_scope" in u]
    assert [(u["lock_scope"], u["lock_level"], u["lock_s"]) for u in radky] == [
        ("name", 1, 60),
    ]
    assert radky[0]["client_origin"] == "198.51.100.20"
    assert radky[0]["reason"] == "bad_code"


def test_the_address_lock_is_marked_in_the_audit(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    spatne(access, A)
    hodiny.posun(61)
    spatne(access, A)
    radky = [u for u in read_events(koren(tmp_path)) if "lock_scope" in u]
    assert [(u["lock_scope"], u["lock_level"], u["lock_s"]) for u in radky] == [
        ("address", 1, 60), ("address", 2, 120),
    ]


def test_the_state_file_stays_bounded(tmp_path, hodiny):
    zaloz(tmp_path, "hana")
    store = FileStore(koren(tmp_path), realm=REALM, throttle_name_attempts=10_000)
    for i in range(200):
        store.authenticate("hana", {"totp": "000000"}, purpose="login",
                           client_origin=f"10.{i // 250}.{i % 250}.7")
    stav = json.loads(
        (koren(tmp_path) / "user-hana" / "throttle.json").read_text())
    assert len(stav["addresses"]) == files.MAX_THROTTLE_ADDRESSES


@pytest.mark.parametrize("obsah", [
    '{"od": 1790000000, "pokusu": 5}',        # tvar pred stupnovanym zamkem
    "neni json", "[]", '{"addresses": {"x": {}}}', "",
])
def test_an_unreadable_state_file_never_blocks(tmp_path, hodiny, obsah):
    adresar = zaloz(tmp_path, "hana")
    (adresar / "throttle.json").write_text(obsah, encoding="utf-8")
    access = store_access(tmp_path)
    assert pokus(access, A, kod()).outcome == "ok"


# == spravce: jen adresa, zadne pocitadlo na jmeno ========================


def spravce_store(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    return FileStore(koren(tmp_path), realm=REALM)


def test_an_admin_cannot_be_locked_out_from_other_addresses(tmp_path, hodiny):
    """Dva kody po sobe se uhodnout nedaji, takze zamek na jmeno by u spravce
    slouzil jen k tomu, aby ho nekdo z konzole vyradil."""
    from helpers import admin_kody
    store = spravce_store(tmp_path)
    for i in range(40):
        for _ in range(5):
            store.authenticate_admin("jindrich", "000000", "111111",
                                     origin=f"198.51.100.{i + 1}")
    zamcena = store.authenticate_admin("jindrich", "000000", "111111",
                                       origin="198.51.100.1")
    assert zamcena.outcome == "throttled"
    prvni, druhy = admin_kody(tmp_path)
    assert store.authenticate_admin("jindrich", prvni, druhy, origin="192.0.2.77")


def test_an_admin_origin_that_is_not_an_address_falls_back_to_the_name(tmp_path):
    store = spravce_store(tmp_path)
    for _ in range(5):
        store.authenticate_admin("jindrich", "000000", "111111", origin="neni-adresa")
    verdikt = store.authenticate_admin("jindrich", "000000", "111111",
                                       origin="take-ne")
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after <= 60
