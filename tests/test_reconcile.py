"""Reconcile: deklarace rika CO ma byt, sluzba doplni JEN co chybi.

Restart ve 3 rano nikomu nic nevymeni. Zmizeni z deklarace neni mazani -
sjednocenim nejde nic odebrat.
"""
import time

import pytest
from helpers import REALM

from access_manager import reconcile

DEKLARACE = [{"name": REALM, "admins": ["jindrich"]}]


def test_reconcile_creates_the_realm_and_its_first_admin(tmp_path):
    nova = reconcile(tmp_path, DEKLARACE)
    assert [z.name for z in nova] == ["jindrich"]
    assert (tmp_path / f"realm-{REALM}" / "admin-jindrich" / "totp.txt").is_file()


def test_reconcile_is_idempotent(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    cesta = tmp_path / f"realm-{REALM}" / "admin-jindrich" / "totp.secret"
    tajemstvi = cesta.read_text()
    assert reconcile(tmp_path, DEKLARACE) == []
    assert cesta.read_text() == tajemstvi


def test_reconcile_adds_a_newly_declared_admin(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    nova = reconcile(tmp_path, [{"name": REALM, "admins": ["jindrich", "marie"]}])
    assert [z.name for z in nova] == ["marie"]


def test_an_expired_unpaired_admin_gets_a_fresh_qr(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    adresar = tmp_path / f"realm-{REALM}" / "admin-jindrich"
    stare_tajemstvi = (adresar / "totp.secret").read_text()
    (adresar / "totp.issued").write_text(
        f"{int(time.time()) - 15 * 86400}\n", encoding="utf-8"
    )
    nova = reconcile(tmp_path, DEKLARACE)
    assert [z.name for z in nova] == ["jindrich"]
    assert (adresar / "totp.secret").read_text() != stare_tajemstvi


def test_a_missing_realm_in_the_declaration_is_not_deleted(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    reconcile(tmp_path, [{"name": "jiny", "admins": ["petr"]}])
    assert (tmp_path / f"realm-{REALM}").is_dir()


def test_duplicate_realm_names_close_the_start(tmp_path):
    with pytest.raises(ValueError):
        reconcile(tmp_path, [{"name": "a", "admins": []}, {"name": "A", "admins": []}])


def test_a_declaration_without_a_name_closes_the_start(tmp_path):
    with pytest.raises(ValueError):
        reconcile(tmp_path, [{"admins": ["jindrich"]}])


def test_reconcile_audits_as_the_operator(tmp_path):
    from access_manager.audit import read_events
    reconcile(tmp_path, DEKLARACE)
    zapisy = read_events(tmp_path / f"realm-{REALM}", kind="write")
    assert zapisy
    assert all(z["actor"] == "operator" for z in zapisy)
