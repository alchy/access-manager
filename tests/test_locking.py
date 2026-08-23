"""Dva procesy nad tymz adresarem si nesmi slapat po zapisech.

Anti-replay i clenstvi jsou cteni-uprava-zapis: bez zamku tyz kod projde
dvakrat (kazdy proces si precte prazdny seznam) a pomalejsi zapisujici
prepise rychlejsiho. `_replace` chrani pred poskozenym souborem, ne pred
ztracenym zapisem.
"""
import threading
import time

from access_manager import Access, Admin
from access_manager.files import _locked

from helpers import kod, zaloz


def test_the_lock_is_exclusive(tmp_path):
    poradi = []
    drzim = threading.Event()

    def drzitel():
        with _locked(tmp_path):
            drzim.set()
            time.sleep(0.2)
            poradi.append("drzitel")

    def cekatel():
        assert drzim.wait(timeout=5), "timeout: drzitel nikdy nenapsal event"
        with _locked(tmp_path):
            poradi.append("cekatel")

    vlakna = [threading.Thread(target=drzitel), threading.Thread(target=cekatel)]
    for v in vlakna:
        v.start()
    for v in vlakna:
        v.join(timeout=10)
        assert not v.is_alive(), f"thread {v.name} se neukoncilo"
    assert poradi == ["drzitel", "cekatel"]


def test_a_burst_of_the_same_code_passes_exactly_once(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    stejny = kod()
    zavora = threading.Barrier(8, timeout=5)
    verdikty = []

    def utocnik():
        zavora.wait()
        verdikty.append(
            access.authenticate("hana", {"totp": stejny}, purpose="login")
        )

    vlakna = [threading.Thread(target=utocnik) for _ in range(8)]
    for v in vlakna:
        v.start()
    for v in vlakna:
        v.join(timeout=10)
        assert not v.is_alive(), f"thread {v.name} se neukoncilo"
    assert sum(1 for v in verdikty if v) == 1


def test_two_writers_do_not_lose_each_others_members(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("ucetni")
    admin.add_user("hana")
    admin.add_user("petr")
    zavora = threading.Barrier(2, timeout=5)

    def pridej(jmeno):
        zavora.wait()
        admin.add_member("ucetni", jmeno)

    vlakna = [
        threading.Thread(target=pridej, args=("hana",)),
        threading.Thread(target=pridej, args=("petr",)),
    ]
    for v in vlakna:
        v.start()
    for v in vlakna:
        v.join(timeout=10)
        assert not v.is_alive(), f"thread {v.name} se neukoncilo"
    assert Access.local(tmp_path).group("ucetni").members == ("hana", "petr")
