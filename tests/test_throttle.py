"""Omezovani pokusu: po N neuspesich v okne prijde `throttled`.

Pocitaji se JEN bad_code/replay existujici identity - neexistujici jmeno
pocitadlo nezveda (jinak si kdokoli necha zamknout cizi jmena) a blokovany
puvod se sem u sluzby vubec nedostane. Uspech pocitadlo maze.
"""
import json
import time

from helpers import REALM, kod, koren, zaloz

from access_manager import Access, Admin


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


def test_an_expired_window_unlocks(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    cesta = koren(tmp_path) / "user-hana" / "throttle.json"
    data = json.loads(cesta.read_text(encoding="utf-8"))
    data["od"] = int(time.time()) - 120
    cesta.write_text(json.dumps(data), encoding="utf-8")
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")


def test_the_admin_login_is_throttled_too(tmp_path):
    from access_manager.files import FileStore
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    store = FileStore(koren(tmp_path), realm=REALM)
    for _ in range(5):
        store.authenticate_admin("jindrich", "000000", "111111")
    verdikt = store.authenticate_admin("jindrich", "000000", "111111")
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after is not None
