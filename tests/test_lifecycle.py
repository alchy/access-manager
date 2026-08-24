"""Zivotni cyklus: vypnout, zapnout, odebrat clenstvi, smazat cloveka.

Zablokovat cloveka na tri dny je bezny ukon; smazat ho kvuli tomu znamena
prijit o jeho clenstvi i o auditni stopu (navrh par. 3.1). Proto jsou
disable a remove dva ruzne ukony a oba tu musi byt.
"""
import pytest
from helpers import REALM, kod, koren, skupiny, zaloz

from access_manager import Access, Admin


def test_a_disabled_user_stops_authenticating(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path, realm=REALM).disable_user("hana")
    verdikt = Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )
    assert verdikt.reason == "disabled"


def test_an_enabled_user_authenticates_again(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path, realm=REALM)
    admin.disable_user("hana")
    admin.enable_user("hana")
    assert Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )


def test_disabling_keeps_the_membership(tmp_path):
    # Vypnuty clovek neni smazany clovek: clenstvi i auditni stopa zustavaji.
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"ucetni": {"members": ["hana"]}})
    Admin.local(tmp_path, realm=REALM).disable_user("hana")
    user = Access.local(tmp_path, realm=REALM).user("hana")
    assert not user.enabled
    assert "group:ucetni" in user.principals


def test_disabling_twice_is_harmless(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path, realm=REALM)
    access = Access.local(tmp_path, realm=REALM)
    admin.disable_user("hana")
    gen_after_first = access.generation()
    admin.disable_user("hana")
    assert not Access.local(tmp_path, realm=REALM).user("hana").enabled
    assert access.generation() == gen_after_first


def test_disabling_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path, realm=REALM).disable_user("nikdo")


def test_a_removed_member_loses_the_group(tmp_path):
    admin = Admin.local(tmp_path, realm=REALM)
    admin.add_user("hana")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    admin.remove_member("ucetni", "hana")
    access = Access.local(tmp_path, realm=REALM)
    assert "group:ucetni" not in access.user("hana").principals


def test_removing_an_absent_member_is_harmless(tmp_path):
    # DELETE je idempotentni: "uz tam neni" je splneny cil, ne chyba.
    admin = Admin.local(tmp_path, realm=REALM)
    access = Access.local(tmp_path, realm=REALM)
    admin.add_group("ucetni")
    gen_before = access.generation()
    admin.remove_member("ucetni", "hana")
    assert access.generation() == gen_before


def test_removing_a_member_from_an_unknown_group_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path, realm=REALM).remove_member("neni", "hana")


def test_a_removed_user_is_gone_even_from_member_lists(tmp_path):
    # Smazani je ucinny zasah (navrh par. 3.2) - a po sobe nesmi nechat
    # jmeno v zadnem seznamu clenu.
    admin = Admin.local(tmp_path, realm=REALM)
    admin.add_user("hana")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    admin.remove_user("hana")
    access = Access.local(tmp_path, realm=REALM)
    assert access.user("hana") is None
    assert access.group("ucetni").members == ()
    verdikt = access.authenticate("hana", {"totp": "123456"}, purpose="login")
    assert verdikt.reason == "unknown_user"


def test_removing_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path, realm=REALM).remove_user("nikdo")


def test_lifecycle_writes_move_the_generation(tmp_path):
    admin = Admin.local(tmp_path, realm=REALM)
    access = Access.local(tmp_path, realm=REALM)
    admin.add_user("hana")
    pred = access.generation()
    admin.disable_user("hana")
    assert access.generation() > pred


# ===========================================================================
# Ztraceny telefon: odvolat a znovu sparovat
# ===========================================================================


def test_a_revoked_credential_refuses_as_no_secret(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path, realm=REALM).revoke_credential("hana")
    verdikt = Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )
    assert verdikt.reason == "no_secret"


def test_pairing_never_overwrites_an_existing_secret(tmp_path):
    # Stejne pravidlo jako u add_user: prepsat tajemstvi znamena zamknout
    # cloveka ven. Jedina cesta k novemu je revoke + pair.
    zaloz(tmp_path, "hana")
    with pytest.raises(ValueError):
        Admin.local(tmp_path, realm=REALM).pair("hana")


def test_revoke_and_pair_issue_a_different_secret(tmp_path):
    admin = Admin.local(tmp_path, realm=REALM)
    admin.add_user("hana")
    stare = (koren(tmp_path) / "user-hana" / "totp.secret").read_text()
    admin.revoke_credential("hana")
    admin.pair("hana")
    assert (koren(tmp_path) / "user-hana" / "totp.secret").read_text() != stare


def test_revocation_forgets_the_used_steps_of_the_old_secret(tmp_path):
    # Cisla spotrebovanych kroku patri ke STAREMU tajemstvi. Kdyby prezila,
    # prvni kod z noveho telefonu by v temz okne vypadal jako replay.
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path, realm=REALM)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")
    admin = Admin.local(tmp_path, realm=REALM)
    admin.revoke_credential("hana")
    admin.pair("hana")
    nove = (koren(tmp_path) / "user-hana" / "totp.secret").read_text().strip()
    assert access.authenticate("hana", {"totp": kod(nove)}, purpose="login")


def test_an_unknown_mechanism_cannot_be_revoked(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path, realm=REALM)
    with pytest.raises(ValueError):
        admin.revoke_credential("hana", mechanism="password")


def test_pairing_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path, realm=REALM).pair("nikdo")


def test_revoking_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path, realm=REALM).revoke_credential("nikdo")


def test_pairing_heals_a_dir_with_stale_qr_but_no_secret(tmp_path):
    # Pad uprostred revoke necha uri/txt bez tajemstvi; pair to musi uklidit,
    # ne spadnout na O_EXCL a nechat pulku stareho a pulku noveho.
    directory = koren(tmp_path) / "user-hana"
    directory.mkdir(parents=True)
    (directory / "totp.uri").write_text("stary\n", encoding="utf-8")
    (directory / "totp.txt").write_text("stary qr\n", encoding="utf-8")
    Admin.local(tmp_path, realm=REALM).pair("hana")
    secret_path = koren(tmp_path) / "user-hana" / "totp.secret"
    secret = secret_path.read_text(encoding="utf-8").strip()
    uri = (koren(tmp_path) / "user-hana" / "totp.uri").read_text(encoding="utf-8")
    assert secret in uri   # QR patri k NOVEMU tajemstvi


def test_pair_missing_heals_a_dir_with_stale_qr_but_no_secret(tmp_path):
    # Stejny pad, ale cestou pair_missing() - pouziva se pri startu sluzby.
    directory = koren(tmp_path) / "user-hana"
    directory.mkdir(parents=True)
    (directory / "totp.uri").write_text("stary\n", encoding="utf-8")
    (directory / "totp.txt").write_text("stary qr\n", encoding="utf-8")
    Admin.local(tmp_path, realm=REALM).pair_missing()
    secret_path = koren(tmp_path) / "user-hana" / "totp.secret"
    secret = secret_path.read_text(encoding="utf-8").strip()
    uri = (koren(tmp_path) / "user-hana" / "totp.uri").read_text(encoding="utf-8")
    assert secret in uri   # QR patri k NOVEMU tajemstvi
