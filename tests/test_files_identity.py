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
import json

import pytest

from access_manager import Access

PUBLIC = "group:public"
USERS = "group:users"


def zaloz(home, name, secret="JBSWY3DPEHPK3PXP"):
    directory = home / f"user-{name}"
    directory.mkdir(parents=True)
    (directory / "totp.secret").write_text(secret + "\n", encoding="utf-8")
    return directory


def skupiny(home, table):
    (home / "groups.json").write_text(json.dumps(table), encoding="utf-8")


# ===========================================================================
# Existence
# ===========================================================================


def test_an_unknown_user_is_none(tmp_path):
    # "Neznam" neni "vychozi" - chyba 3.5 zacinala presne tady.
    assert Access.local(tmp_path).user("nikdo") is None


def test_a_known_user_is_found(tmp_path):
    zaloz(tmp_path, "hana")
    assert Access.local(tmp_path).user("hana") is not None


def test_a_user_carries_their_own_principal(tmp_path):
    zaloz(tmp_path, "hana")
    assert "user:hana" in Access.local(tmp_path).user("hana").principals


def test_every_user_is_in_users_and_public(tmp_path):
    zaloz(tmp_path, "hana")
    assert {USERS, PUBLIC} <= Access.local(tmp_path).user("hana").principals


def test_a_name_cannot_climb_out_of_the_home(tmp_path):
    # Jmeno se sklada do CESTY. Bez kontroly by `../..` cetlo, co si nekdo
    # preje - a jmeno chodi zvenci.
    with pytest.raises(ValueError):
        Access.local(tmp_path).user("../../etc/passwd")


def test_a_name_with_a_slash_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Access.local(tmp_path).user("hana/../petr")
