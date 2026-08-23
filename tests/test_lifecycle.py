"""Zivotni cyklus: vypnout, zapnout, odebrat clenstvi, smazat cloveka.

Zablokovat cloveka na tri dny je bezny ukon; smazat ho kvuli tomu znamena
prijit o jeho clenstvi i o auditni stopu (navrh par. 3.1). Proto jsou
disable a remove dva ruzne ukony a oba tu musi byt.
"""
import pytest
from helpers import kod, skupiny, zaloz

from access_manager import Access, Admin


def test_a_disabled_user_stops_authenticating(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path).disable_user("hana")
    verdikt = Access.local(tmp_path).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )
    assert verdikt.reason == "disabled"


def test_an_enabled_user_authenticates_again(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path)
    admin.disable_user("hana")
    admin.enable_user("hana")
    assert Access.local(tmp_path).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )


def test_disabling_keeps_the_membership(tmp_path):
    # Vypnuty clovek neni smazany clovek: clenstvi i auditni stopa zustavaji.
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"ucetni": {"members": ["hana"]}})
    Admin.local(tmp_path).disable_user("hana")
    user = Access.local(tmp_path).user("hana")
    assert not user.enabled
    assert "group:ucetni" in user.principals


def test_disabling_twice_is_harmless(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path)
    access = Access.local(tmp_path)
    admin.disable_user("hana")
    gen_after_first = access.generation()
    admin.disable_user("hana")
    assert not Access.local(tmp_path).user("hana").enabled
    assert access.generation() == gen_after_first


def test_disabling_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).disable_user("nikdo")


def test_a_removed_member_loses_the_group(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("hana")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    admin.remove_member("ucetni", "hana")
    assert "group:ucetni" not in Access.local(tmp_path).user("hana").principals


def test_removing_an_absent_member_is_harmless(tmp_path):
    # DELETE je idempotentni: "uz tam neni" je splneny cil, ne chyba.
    admin = Admin.local(tmp_path)
    access = Access.local(tmp_path)
    admin.add_group("ucetni")
    gen_before = access.generation()
    admin.remove_member("ucetni", "hana")
    assert access.generation() == gen_before


def test_removing_a_member_from_an_unknown_group_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).remove_member("neni", "hana")


def test_a_removed_user_is_gone_even_from_member_lists(tmp_path):
    # Smazani je ucinny zasah (navrh par. 3.2) - a po sobe nesmi nechat
    # jmeno v zadnem seznamu clenu.
    admin = Admin.local(tmp_path)
    admin.add_user("hana")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    admin.remove_user("hana")
    access = Access.local(tmp_path)
    assert access.user("hana") is None
    assert access.group("ucetni").members == ()
    verdikt = access.authenticate("hana", {"totp": "123456"}, purpose="login")
    assert verdikt.reason == "unknown_user"


def test_removing_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).remove_user("nikdo")


def test_lifecycle_writes_move_the_generation(tmp_path):
    admin = Admin.local(tmp_path)
    access = Access.local(tmp_path)
    admin.add_user("hana")
    pred = access.generation()
    admin.disable_user("hana")
    assert access.generation() > pred


# ===========================================================================
# Ztraceny telefon: odvolat a znovu sparovat
# ===========================================================================


def test_a_revoked_credential_refuses_as_no_secret(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path).revoke_credential("hana")
    verdikt = Access.local(tmp_path).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )
    assert verdikt.reason == "no_secret"


def test_pairing_never_overwrites_an_existing_secret(tmp_path):
    # Stejne pravidlo jako u add_user: prepsat tajemstvi znamena zamknout
    # cloveka ven. Jedina cesta k novemu je revoke + pair.
    zaloz(tmp_path, "hana")
    with pytest.raises(ValueError):
        Admin.local(tmp_path).pair("hana")


def test_revoke_and_pair_issue_a_different_secret(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("hana")
    stare = (tmp_path / "user-hana" / "totp.secret").read_text()
    admin.revoke_credential("hana")
    admin.pair("hana")
    assert (tmp_path / "user-hana" / "totp.secret").read_text() != stare


def test_revocation_forgets_the_used_steps_of_the_old_secret(tmp_path):
    # Cisla spotrebovanych kroku patri ke STAREMU tajemstvi. Kdyby prezila,
    # prvni kod z noveho telefonu by v temz okne vypadal jako replay.
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")
    admin = Admin.local(tmp_path)
    admin.revoke_credential("hana")
    admin.pair("hana")
    nove = (tmp_path / "user-hana" / "totp.secret").read_text().strip()
    assert access.authenticate("hana", {"totp": kod(nove)}, purpose="login")


def test_an_unknown_mechanism_cannot_be_revoked(tmp_path):
    zaloz(tmp_path, "hana")
    with pytest.raises(ValueError):
        Admin.local(tmp_path).revoke_credential("hana", mechanism="password")
