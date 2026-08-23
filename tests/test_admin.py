"""Zapisova pulka: zalozit cloveka, skupinu, clenstvi a zretezeni.

Dve pravidla, ktera plati vsude tady a maji stejny duvod:

  * EXISTUJICI TAJEMSTVI SE NIKDY NEPREPISE. Prepsat ho znamena zamknout
    cloveka ven - jeho autentikator dal vydava kody, ktere uz nikam nepatri.
  * DOPLNUJE SE JEN CO CHYBI. Sluzba restartovana ve 3 rano nesmi vyrobit
    novou sadu tajemstvi; smi doplnit tomu, kdo zadne nema.

Parovani je na TEXTOVEM QR: na server se clovek dostane pres ssh, `cat`
vypise kod do terminalu a telefon ho sejme z obrazovky. SVG je hezci, ale
na hlavu bez obrazovky k nicemu.
"""
import stat

import pytest

from access_manager import Access, Admin

from helpers import principaly, zaloz


# ===========================================================================
# Zalozeni cloveka
# ===========================================================================


def test_a_new_user_can_be_found_afterwards(tmp_path):
    Admin.local(tmp_path).add_user("jindrich")
    assert Access.local(tmp_path).user("jindrich") is not None


def test_a_new_user_gets_a_pairing_secret(tmp_path):
    Admin.local(tmp_path).add_user("jindrich")
    assert (tmp_path / "user-jindrich" / "totp.secret").is_file()


def test_a_new_user_gets_a_pairing_qr_as_text(tmp_path):
    # Na hlave bez obrazovky se QR ctě `cat`em.
    Admin.local(tmp_path).add_user("jindrich")
    qr = (tmp_path / "user-jindrich" / "totp.txt").read_text(encoding="utf-8")
    assert qr.count("\n") > 10          # je to obrazec, ne radka


def test_the_enrolment_says_where_things_are_but_not_what_they_are(tmp_path):
    # Repr konci v logu a v tracebacku; kdyby v nem tajemstvi bylo, unikne
    # prvni vyjimkou.
    zavedeni = Admin.local(tmp_path).add_user("jindrich")
    tajemstvi = (tmp_path / "user-jindrich" / "totp.secret").read_text().strip()
    assert tajemstvi not in repr(zavedeni)
    assert "jindrich" in str(zavedeni.directory)


def test_artefacts_are_readable_only_by_their_owner(tmp_path):
    Admin.local(tmp_path).add_user("jindrich")
    directory = tmp_path / "user-jindrich"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "totp.secret").stat().st_mode) == 0o600


def test_an_existing_user_is_never_overwritten(tmp_path):
    # Prepsani tajemstvi cloveka zamkne ven.
    admin = Admin.local(tmp_path)
    admin.add_user("jindrich")
    puvodni = (tmp_path / "user-jindrich" / "totp.secret").read_text()
    with pytest.raises(ValueError):
        admin.add_user("jindrich")
    assert (tmp_path / "user-jindrich" / "totp.secret").read_text() == puvodni


def test_a_name_that_is_a_path_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).add_user("../../etc/passwd")


# ===========================================================================
# Doplneni parovacich kodu tem, kdo je nemaji
# ===========================================================================


def test_a_user_without_a_secret_gets_one(tmp_path):
    (tmp_path / "user-jindrich").mkdir()
    doplneni = Admin.local(tmp_path).pair_missing()
    assert [z.name for z in doplneni] == ["jindrich"]
    assert (tmp_path / "user-jindrich" / "totp.txt").is_file()


def test_an_existing_secret_is_left_alone(tmp_path):
    # Restart ve 3 rano nesmi vymenit tajemstvi tem, kdo uz je maji.
    zaloz(tmp_path, "jindrich", "JBSWY3DPEHPK3PXP")
    assert Admin.local(tmp_path).pair_missing() == []
    assert "JBSWY3DPEHPK3PXP" in (tmp_path / "user-jindrich" / "totp.secret").read_text()


# ===========================================================================
# Skupiny
# ===========================================================================


def test_a_new_group_shows_up(tmp_path):
    Admin.local(tmp_path).add_group("ucetni")
    assert "ucetni" in Access.local(tmp_path).groups()


def test_an_existing_group_is_refused(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("ucetni")
    with pytest.raises(ValueError):
        admin.add_group("ucetni")


@pytest.mark.parametrize("jmeno", ["users", "public"])
def test_a_reserved_group_cannot_be_created(tmp_path, jmeno):
    # `group:users` a `group:public` dostava kazdy automaticky. Zalozit je
    # jako obycejne skupiny znamena dve pravdy o temz jmene.
    with pytest.raises(ValueError):
        Admin.local(tmp_path).add_group(jmeno)


# ===========================================================================
# Clenstvi
# ===========================================================================


def test_a_member_gets_the_group(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("jindrich")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "jindrich")
    assert "group:ucetni" in principaly(tmp_path, "jindrich")


def test_adding_the_same_member_twice_is_harmless(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("jindrich")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "jindrich")
    admin.add_member("ucetni", "jindrich")
    assert Access.local(tmp_path).group("ucetni").members == ("jindrich",)


def test_a_member_of_an_unknown_group_is_refused(tmp_path):
    # Preklep by jinak zalozil skupinu, kterou nikdo nikdy nenapsal do ACL.
    admin = Admin.local(tmp_path)
    admin.add_user("jindrich")
    with pytest.raises(ValueError):
        admin.add_member("ucetni", "jindrich")


def test_an_unknown_member_is_refused(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("ucetni")
    with pytest.raises(ValueError):
        admin.add_member("ucetni", "nikdo")


# ===========================================================================
# Skupina ve skupine
# ===========================================================================


def test_an_included_group_carries_its_members_up(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("jindrich")
    admin.add_group("mzdy")
    admin.add_group("ucetni")
    admin.add_member("mzdy", "jindrich")
    admin.include("ucetni", "mzdy")          # ucetni OBSAHUJE mzdy
    assert {"group:mzdy", "group:ucetni"} <= principaly(tmp_path, "jindrich")


def test_including_a_group_twice_is_harmless(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("mzdy")
    admin.add_group("ucetni")
    admin.include("ucetni", "mzdy")
    admin.include("ucetni", "mzdy")
    assert Access.local(tmp_path).group("ucetni").includes == ("mzdy",)


def test_a_cycle_is_refused_when_it_is_made(tmp_path):
    # Cteni cyklus prezije, ale VYROBIT ho je vzdycky omyl - a v tu chvili
    # jeste vime, kdo ho dela a proc.
    admin = Admin.local(tmp_path)
    admin.add_group("a")
    admin.add_group("b")
    admin.include("a", "b")
    with pytest.raises(ValueError):
        admin.include("b", "a")


def test_a_group_cannot_include_itself(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("a")
    with pytest.raises(ValueError):
        admin.include("a", "a")


def test_including_an_unknown_group_is_refused(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("ucetni")
    with pytest.raises(ValueError):
        admin.include("ucetni", "mzdi")
