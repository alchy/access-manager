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


def test_a_corrupt_issued_file_expires_instead_of_crashing(tmp_path):
    # Pad uprostred zapisu umi nechat prazdny soubor; prihlaseni musi
    # odpovedet verdiktem, ne vyjimkou - a fail-closed znamena expired.
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    (directory / "totp.issued").write_text("", encoding="utf-8")
    secret = (directory / "totp.secret").read_text().strip()
    verdikt = Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod(secret)}, purpose="login"
    )
    assert verdikt.reason == "expired"


def test_completing_a_pairing_after_removal_is_a_quiet_noop(tmp_path):
    # Zavod: mezi overenim a dokoncenim parovani nekdo identitu smazal.
    # _complete_pairing nesmi spadnout ani vyrobit osirely marker.
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    import shutil as _shutil

    from access_manager.files import FileStore
    store = FileStore(koren(tmp_path), realm=REALM)
    _shutil.rmtree(directory)
    directory.mkdir()          # adresar bez tajemstvi (po revoke)
    store._complete_pairing(directory)
    assert not (directory / "totp.paired").exists()


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


# == vyprsele zavedeni se v konzoli uz nezobrazuje =====================


def _vypsi_zavedeni_do_minulosti(adresar, dni):
    """Posun `totp.issued` o `dni` zpatky - TTL se pocita prave z nej."""
    import time
    (adresar / "totp.issued").write_text(
        str(int(time.time()) - dni * 86400), encoding="utf-8"
    )


def test_an_expired_enrolment_hides_the_qr_and_the_typed_secret(
    prihlaseny_klient, tmp_path,
):
    """Po TTL uz `authenticate` hlasi `expired`. Ukazovat k tomu dal QR
    a tajemstvi znamena posilat cloveka opsat neco, co mu neprojde."""
    klient, csrf = prihlaseny_klient
    klient.post("/users/add", data={"jmeno": "tereza", "csrf": csrf})
    adresar = koren(tmp_path / "data") / "user-tereza"
    tajemstvi = (adresar / "totp.secret").read_text(encoding="utf-8").strip()

    # Cerstve zavedeni: obojí je videt.
    telo = klient.get("/users/qr/tereza").get_data(as_text=True)
    assert "<pre" in telo
    assert tajemstvi in telo

    _vypsi_zavedeni_do_minulosti(adresar, 15)      # qr_ttl_days je 14

    telo = klient.get("/users/qr/tereza").get_data(as_text=True)
    assert "<pre" not in telo
    assert tajemstvi not in telo
    assert "otpauth://" not in telo
    # Artefakty na disku zustavaji - skryva se jen jejich zobrazeni.
    assert (adresar / "totp.txt").is_file()
    assert (adresar / "totp.uri").is_file()


def test_an_expired_enrolment_is_not_reported_as_still_waiting(
    prihlaseny_klient, tmp_path,
):
    """Drive spadlo vyprsele zavedeni do "ceka" a `max(0, ...)` ho vypsalo
    jako "plati jeste 0 dni" - tedy jako by na nej slo dal cekat."""
    klient, csrf = prihlaseny_klient
    klient.post("/users/add", data={"jmeno": "tereza", "csrf": csrf})
    _vypsi_zavedeni_do_minulosti(koren(tmp_path / "data") / "user-tereza", 15)

    telo = klient.get("/users").get_data(as_text=True)
    assert 'class="stav stav-expired"' in telo
    assert 'class="stav stav-waiting"' not in telo
    assert "0 dní" not in telo


def test_an_expired_admin_enrolment_is_hidden_too(prihlaseny_klient, tmp_path):
    """`qr.html` i vypis jsou pro spravce tytez - musi se chovat stejne."""
    klient, csrf = prihlaseny_klient
    klient.post("/admins/add", data={"jmeno": "marie", "csrf": csrf})
    adresar = koren(tmp_path / "data") / "admin-marie"
    _vypsi_zavedeni_do_minulosti(adresar, 15)

    telo = klient.get("/admins/qr/marie").get_data(as_text=True)
    assert "<pre" not in telo
    assert "otpauth://" not in telo
    assert 'class="stav stav-expired"' in klient.get("/admins").get_data(as_text=True)
