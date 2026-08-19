"""Zretezeni skupin rozbaluje KOMPONENTA a vraci plochy uzaver.

Kdyby graf dostavalo viewBase a rozbalovalo si ho samo, prestane byt cela
autorizace jednou funkci `allowed(principals, acl)` a pribude druhe misto,
kde se pocita prislusnost. Detekce cyklu patri sem, jednou - ne do kazdeho
volajiciho.

Smer: `ucetni.includes = ["mzdy"]` znamena "ucetni OBSAHUJE mzdy", takze kdo
je v mzdach, je i v ucetni. Opacne ne. Kdyby se smer prohodil, vetsina testu
nize by porad prochazela - proto je tu
`test_membership_does_not_flow_downwards`.
"""
import json

import pytest

from access_manager import Access

from test_files_identity import skupiny, zaloz


def principaly(home, name):
    return Access.local(home).user(name).principals


# ===========================================================================
# Prime clenstvi
# ===========================================================================


def test_a_direct_member_gets_the_group(tmp_path):
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"ucetni": {"members": ["hana"]}})
    assert "group:ucetni" in principaly(tmp_path, "hana")


def test_someone_elses_group_is_not_yours(tmp_path):
    zaloz(tmp_path, "hana")
    zaloz(tmp_path, "petr")
    skupiny(tmp_path, {"ucetni": {"members": ["petr"]}})
    assert "group:ucetni" not in principaly(tmp_path, "hana")


def test_no_groups_file_is_not_an_error(tmp_path):
    # Cerstva instalace: uzivatel existuje, skupiny jeste nikdo nezalozil.
    zaloz(tmp_path, "hana")
    assert "user:hana" in principaly(tmp_path, "hana")


# ===========================================================================
# Zretezeni
# ===========================================================================


def test_a_chained_group_is_included(tmp_path):
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {
        "mzdy": {"members": ["hana"]},
        "ucetni": {"includes": ["mzdy"]},
    })
    assert {"group:mzdy", "group:ucetni"} <= principaly(tmp_path, "hana")


def test_a_chain_of_three_is_followed_all_the_way(tmp_path):
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {
        "a": {"members": ["hana"]},
        "b": {"includes": ["a"]},
        "c": {"includes": ["b"]},
    })
    assert {"group:a", "group:b", "group:c"} <= principaly(tmp_path, "hana")


def test_membership_does_not_flow_downwards(tmp_path):
    # TENHLE test drzi SMER. Bez nej projde i obracene zapojene rozbaleni -
    # a to by kazdemu ucetnimu tise pridalo prava mzdove agendy.
    zaloz(tmp_path, "petr")
    skupiny(tmp_path, {
        "ucetni": {"members": ["petr"], "includes": ["mzdy"]},
        "mzdy": {"members": []},
    })
    assert "group:mzdy" not in principaly(tmp_path, "petr")


# ===========================================================================
# Co graf umi udelat spatne
# ===========================================================================


def test_a_cycle_does_not_hang(tmp_path):
    # Dva spravci, kazdy prida jedno zretezeni, a nikdo nevidi cely graf.
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {
        "a": {"members": ["hana"], "includes": ["b"]},
        "b": {"includes": ["a"]},
    })
    assert {"group:a", "group:b"} <= principaly(tmp_path, "hana")


def test_a_group_that_includes_itself_is_harmless(tmp_path):
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"a": {"members": ["hana"], "includes": ["a"]}})
    assert "group:a" in principaly(tmp_path, "hana")


def test_an_unknown_group_in_includes_is_ignored(tmp_path):
    # Preklep ve zretezeni nesmi shodit prihlaseni vsem.
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {
        "mzdy": {"members": ["hana"]},
        "ucetni": {"includes": ["mzdi"]},
    })
    assert "group:mzdy" in principaly(tmp_path, "hana")
