"""QR je zobrazene tajemstvi, ne registracni tiket - proto ma platnost.

Dva nezavisle mechanismy: do sparovani (po prvnim uspesnem prihlaseni se
uri/txt smazou) a nejdele N dni (nesparovane zavedeni expiruje - duvod
`expired` tim prestava byt jmenem pro stav, ktery nemuze nastat).
"""
import time

from helpers import REALM, kod, koren

from access_manager import Access, Admin


def test_enrolment_records_when_it_was_issued(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    assert (koren(tmp_path) / "user-hana" / "totp.issued").is_file()


def test_first_successful_login_consumes_the_qr(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    secret = (koren(tmp_path) / "user-hana" / "totp.secret").read_text().strip()
    assert Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod(secret)}, purpose="login"
    )
    directory = koren(tmp_path) / "user-hana"
    assert (directory / "totp.paired").is_file()
    assert not (directory / "totp.txt").exists()
    assert not (directory / "totp.uri").exists()
    assert (directory / "totp.secret").is_file()   # tajemstvi overuje dal


def test_an_unpaired_enrolment_expires_after_ttl(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    stare = int(time.time()) - 15 * 86400
    (directory / "totp.issued").write_text(f"{stare}\n", encoding="utf-8")
    secret = (directory / "totp.secret").read_text().strip()
    verdikt = Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod(secret)}, purpose="login"
    )
    assert verdikt.reason == "expired"


def test_a_paired_identity_never_expires(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    secret = (directory / "totp.secret").read_text().strip()
    access = Access.local(tmp_path, realm=REALM)
    assert access.authenticate("hana", {"totp": kod(secret)}, purpose="login")
    stare = int(time.time()) - 400 * 86400
    (directory / "totp.issued").write_text(f"{stare}\n", encoding="utf-8")
    assert access.authenticate("hana", {"totp": kod(secret)}, purpose="unlock:x")


def test_a_dir_without_issued_never_expires(tmp_path):
    # Rucne zalozeny adresar (napr. testovaci zaloz()) nema issued - nesmi
    # zacit expirovat; TTL plati jen pro zavedeni, ktera vydala knihovna.
    from helpers import zaloz
    zaloz(tmp_path, "hana")
    assert Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )


def test_revoke_and_pair_reset_the_validity(tmp_path):
    admin = Admin.local(tmp_path, realm=REALM)
    admin.add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    stare = int(time.time()) - 15 * 86400
    (directory / "totp.issued").write_text(f"{stare}\n", encoding="utf-8")
    admin.revoke_credential("hana")
    admin.pair("hana")
    hodnota = int((directory / "totp.issued").read_text().strip())
    assert hodnota > stare + 14 * 86400
