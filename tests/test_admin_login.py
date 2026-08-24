"""Vstup do konzole: dva kody z po sobe jdoucich oken, v jednom pozadavku.

Jedno odkoukane cislo nestaci - dokazuje se souvisle drzeni autentikatoru.
Druhy kod musi sedet PRESNE na krok s+1; oba kroky se spotrebuji.
"""
import pyotp
from helpers import REALM, koren

from access_manager.files import FileStore


def store(tmp_path):
    from access_manager import Admin
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    return FileStore(koren(tmp_path), realm=REALM)


def dva_kody(tmp_path, offset=0):
    secret = (koren(tmp_path) / "admin-jindrich" / "totp.secret").read_text().strip()
    totp = pyotp.TOTP(secret)
    ted = __import__("time").time() + offset * totp.interval
    return totp.at(ted), totp.at(ted + totp.interval)


def test_two_adjacent_codes_pass(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    verdikt = s.authenticate_admin("jindrich", prvni, druhy)
    assert verdikt
    assert verdikt.subject_id == "admin:jindrich"
    assert verdikt.principals == frozenset()


def test_the_same_code_twice_is_not_adjacent(tmp_path):
    s = store(tmp_path)
    prvni, _ = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", prvni, prvni).reason == "bad_code"


def test_swapped_codes_are_refused(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", druhy, prvni).reason == "bad_code"


def test_replaying_the_pair_is_a_replay(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", prvni, druhy)
    assert s.authenticate_admin("jindrich", prvni, druhy).reason == "replay"


def test_an_unknown_admin_is_refused_by_name(tmp_path):
    s = store(tmp_path)
    assert s.authenticate_admin("nikdo", "000000", "111111").reason == "unknown_user"


def test_a_user_cannot_log_in_as_admin(tmp_path):
    from access_manager import Admin
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    s = FileStore(koren(tmp_path), realm=REALM)
    secret = (koren(tmp_path) / "user-hana" / "totp.secret").read_text().strip()
    totp = pyotp.TOTP(secret)
    ted = __import__("time").time()
    verdikt = s.authenticate_admin("hana", totp.at(ted), totp.at(ted + totp.interval))
    assert verdikt.reason == "unknown_user"


def test_admin_login_completes_the_pairing(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", prvni, druhy)
    assert (koren(tmp_path) / "admin-jindrich" / "totp.paired").is_file()
    assert not (koren(tmp_path) / "admin-jindrich" / "totp.txt").exists()
