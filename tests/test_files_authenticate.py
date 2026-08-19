"""Overuje se POVERENI, ne opravneni.

Chyba 3.6 z viewBase2: prihlaseni kod spotrebovalo a anti-replay byl spolecny
pro celeho uzivatele - pritom je tyz kod potreba dvakrat behem jednoho
tricetisekundoveho okna (prihlaseni + krok navic) a autentikator mezitim zadny
novy nevyda. Proto ma kazdy dotaz ucel a seznam pouzitych je PER UCEL.

Poznamka k jednomu testu, ktery tu NENI: konstantni doba overeni u nezname
identity. U TOTP je rozdil v radu mikrosekund a merit ho znamena mit test,
ktery obcas spadne na zatizenem stroji. Az pribude heslo s argon2id, bude ten
rozdil meritelny a test bude mit smysl - do te doby by to bylo divadlo.
"""
import json

import pyotp
import pytest

from access_manager import Files, Verdict

from test_files_identity import skupiny, zaloz

TAJEMSTVI = "JBSWY3DPEHPK3PXP"


def kod(secret=TAJEMSTVI, at=None):
    totp = pyotp.TOTP(secret)
    return totp.now() if at is None else totp.at(at)


# ===========================================================================
# Co projde a co ne
# ===========================================================================


def test_the_right_code_passes(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    assert Files(tmp_path).authenticate("hana", {"totp": kod()}, purpose="login")


def test_a_wrong_code_is_refused(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    verdikt = Files(tmp_path).authenticate("hana", {"totp": "000000"}, purpose="login")
    assert not verdikt
    assert verdikt.outcome == "bad_code"


def test_a_passing_verdict_carries_the_principals(tmp_path):
    # Kdo prosel, ma rovnou i to, co potrebuje `allowed(principals, acl)` -
    # jinak by kazde prihlaseni byla dve kolecka po siti.
    zaloz(tmp_path, "hana", TAJEMSTVI)
    skupiny(tmp_path, {"ucetni": {"members": ["hana"]}})
    verdikt = Files(tmp_path).authenticate("hana", {"totp": kod()}, purpose="login")
    assert verdikt.subject_id == "user:hana"
    assert "group:ucetni" in verdikt.principals


def test_an_unknown_user_is_refused_by_name(tmp_path):
    verdikt = Files(tmp_path).authenticate("nikdo", {"totp": "123456"}, purpose="login")
    assert verdikt.outcome == "unknown_user"


def test_a_user_without_a_secret_is_refused_by_name(tmp_path):
    # Zalozeny adresar bez tajemstvi neni "spatny kod" - je to nedokoncene
    # zavedeni a spravce to ma poznat z auditu.
    (tmp_path / "user-hana").mkdir()
    verdikt = Files(tmp_path).authenticate("hana", {"totp": "123456"}, purpose="login")
    assert verdikt.outcome == "no_secret"


def test_a_disabled_user_is_refused_by_name(tmp_path):
    # Zablokovat cloveka na tri dny je bezny ukon; smazat ho kvuli tomu
    # znamena prijit o jeho clenstvi i o auditni stopu.
    zaloz(tmp_path, "hana", TAJEMSTVI)
    (tmp_path / "user-hana" / "disabled").write_text("dovolena\n", encoding="utf-8")
    verdikt = Files(tmp_path).authenticate("hana", {"totp": kod()}, purpose="login")
    assert verdikt.outcome == "disabled"


# ===========================================================================
# Co je potreba, rozhoduje komponenta
# ===========================================================================


def test_no_credentials_at_all_asks_for_what_is_missing(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    verdikt = Files(tmp_path).authenticate("hana", {}, purpose="login")
    assert verdikt.outcome == "need_second_factor"
    assert "totp" in verdikt.required


def test_an_unknown_mechanism_does_not_count_as_a_factor(tmp_path):
    # Kdyby si klient smel vybrat mechanismus, vybere si ten slabsi. Nezname
    # jmeno se proto chova, jako by nebylo poslane - ne jako by stacilo.
    zaloz(tmp_path, "hana", TAJEMSTVI)
    verdikt = Files(tmp_path).authenticate(
        "hana", {"kouzlo": "abrakadabra"}, purpose="login"
    )
    assert not verdikt
    assert verdikt.outcome == "need_second_factor"


# ===========================================================================
# Anti-replay je PER UCEL (chyba 3.6)
# ===========================================================================


def test_the_same_code_twice_for_the_same_purpose_is_a_replay(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    access = Files(tmp_path)
    stejny = kod()
    assert access.authenticate("hana", {"totp": stejny}, purpose="login")
    assert access.authenticate("hana", {"totp": stejny}, purpose="login").outcome == "replay"


def test_the_same_code_serves_a_different_purpose(tmp_path):
    # TOHLE je chyba 3.6: prihlaseni a krok navic spadnou do tehoz okna
    # a autentikator zadny novy kod nevyda.
    zaloz(tmp_path, "hana", TAJEMSTVI)
    access = Files(tmp_path)
    stejny = kod()
    assert access.authenticate("hana", {"totp": stejny}, purpose="login")
    assert access.authenticate("hana", {"totp": stejny}, purpose="unlock:mzdy")


def test_unlocking_two_windows_in_one_window_of_time(tmp_path):
    # Duvod, proc ma `unlock` cil: bez nej by druhe okno v tychz 30 vterinach
    # narazilo na tutez past, jen o patro niz.
    zaloz(tmp_path, "hana", TAJEMSTVI)
    access = Files(tmp_path)
    stejny = kod()
    assert access.authenticate("hana", {"totp": stejny}, purpose="unlock:mzdy")
    assert access.authenticate("hana", {"totp": stejny}, purpose="unlock:terminal")


def test_one_users_replay_does_not_touch_another(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    zaloz(tmp_path, "petr", TAJEMSTVI)
    access = Files(tmp_path)
    stejny = kod()
    assert access.authenticate("hana", {"totp": stejny}, purpose="login")
    assert access.authenticate("petr", {"totp": stejny}, purpose="login")


# ===========================================================================
# Ucel ma tvar
# ===========================================================================


def test_a_free_form_purpose_is_refused(tmp_path):
    # Kdyby ucel byl volny retezec, staci posilat pokazde jiny a anti-replay
    # je vypnuty. Je to chyba volajiciho, ne udalost uzivatele - proto vyjimka.
    zaloz(tmp_path, "hana", TAJEMSTVI)
    with pytest.raises(ValueError):
        Files(tmp_path).authenticate("hana", {"totp": kod()}, purpose="cokoli")


def test_an_unlock_without_a_target_is_refused(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    with pytest.raises(ValueError):
        Files(tmp_path).authenticate("hana", {"totp": kod()}, purpose="unlock")


def test_login_and_unlock_with_a_target_are_the_two_shapes(tmp_path):
    zaloz(tmp_path, "hana", TAJEMSTVI)
    access = Files(tmp_path)
    access.authenticate("hana", {"totp": "000000"}, purpose="login")
    access.authenticate("hana", {"totp": "000000"}, purpose="unlock:screen.provoz/mzdy")
