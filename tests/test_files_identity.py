"""Souborovy backend: kdo je kdo.

Uloziste je zatim SOUBOR - cte se paralelne, expiraci si hlida kazdy
komponent sam. `Files` neni atrapa pro testy: je to skutecny backend, ktery
si vevnitr drzi i sama sluzba. Diky tomu bezi tytez testy proti obema
zapojenim.

Format navazuje na to, co uz dnes zaklada `python -m viewbase.admin adduser`:

    VIEWBASE_HOME/
      user-hana/totp.secret
      groups.json     {"ucetni": {"members": ["hana"], "includes": ["mzdy"]}}
"""
import pytest
from helpers import PUBLIC, REALM, USERS, koren, skupiny, zaloz

from access_manager import Access

# ===========================================================================
# Existence
# ===========================================================================


def test_an_unknown_user_is_none(tmp_path):
    # "Neznam" neni "vychozi" - chyba 3.5 zacinala presne tady.
    assert Access.local(tmp_path, realm=REALM).user("nikdo") is None


def test_a_known_user_is_found(tmp_path):
    zaloz(tmp_path, "hana")
    assert Access.local(tmp_path, realm=REALM).user("hana") is not None


def test_a_user_carries_their_own_principal(tmp_path):
    zaloz(tmp_path, "hana")
    assert "user:hana" in Access.local(tmp_path, realm=REALM).user("hana").principals


def test_every_user_is_in_users_and_public(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path, realm=REALM)
    assert {USERS, PUBLIC} <= access.user("hana").principals


def test_a_name_cannot_climb_out_of_the_home(tmp_path):
    # Jmeno se sklada do CESTY. Bez kontroly by `../..` cetlo, co si nekdo
    # preje - a jmeno chodi zvenci.
    with pytest.raises(ValueError):
        Access.local(tmp_path, realm=REALM).user("../../etc/passwd")


def test_a_name_with_a_slash_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Access.local(tmp_path, realm=REALM).user("hana/../petr")


# ===========================================================================
# Existuji tyhle principaly? (navrh par. 3.3)
# ===========================================================================


def test_existing_principals_are_not_unknown(tmp_path):
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"ucetni": {"members": []}})
    assert Access.local(tmp_path, realm=REALM).unknown_principals(
        ["user:hana", "group:ucetni", USERS, PUBLIC]
    ) == []


def test_a_typo_in_a_group_is_reported(tmp_path):
    # `default_access` se skupinou, ktera neexistuje, je slib, ktery
    # instance nemuze splnit - dnes to konci prazdnou obrazovkou.
    skupiny(tmp_path, {"ucetni": {"members": []}})
    access = Access.local(tmp_path, realm=REALM)
    assert access.unknown_principals(["group:ucetnii"]) == ["group:ucetnii"]


def test_a_malformed_principal_is_unknown_not_an_error(tmp_path):
    # Kontrola pri startu ma vyjmenovat vsechno spatne, ne spadnout na
    # prvnim preklepu.
    access = Access.local(tmp_path, realm=REALM)
    assert access.unknown_principals(["group:../x", "cokoli"]) == [
        "cokoli",
        "group:../x",
    ]


# ===========================================================================
# Pripravenost uloziste (zrcadlo /readyz, navrh par. 3.4)
# ===========================================================================


def test_an_existing_home_is_ready(tmp_path):
    koren(tmp_path).mkdir(parents=True)
    assert Access.local(tmp_path, realm=REALM).ready() is None


def test_a_missing_home_is_not_ready(tmp_path):
    # Neexistujici domov je spatne pripojeny svazek, ne cerstva instalace.
    assert Access.local(tmp_path / "nikde", realm=REALM).ready() is not None


def test_a_corrupt_groups_file_is_not_ready(tmp_path):
    koren(tmp_path).mkdir(parents=True)
    (koren(tmp_path) / "groups.json").write_text("{zlomeno", encoding="utf-8")
    assert "groups.json" in Access.local(tmp_path, realm=REALM).ready()


def test_names_are_normalized_to_lowercase(tmp_path):
    zaloz(tmp_path, "hana")
    assert Access.local(tmp_path, realm=REALM).user("Hana") is not None


def test_an_email_is_a_valid_user_name(tmp_path):
    zaloz(tmp_path, "jindrich.nemec@yahoo.com")
    user = Access.local(tmp_path, realm=REALM).user("jindrich.nemec@yahoo.com")
    assert user is not None
    assert user.subject_id == "user:jindrich.nemec@yahoo.com"


def test_two_ats_are_refused(tmp_path):
    with pytest.raises(ValueError):
        Access.local(tmp_path, realm=REALM).user("a@b@c")
