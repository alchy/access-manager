"""Stranka Skupiny: vypis s pocty, detail (prime cleny, zretezeni, kdo patri
jen pres retezec), zalozeni, smazani, pridani/odebrani clena, zretezeni.
Mirror vzoru z test_konzole_uzivatele.py - mutace jsou vzdy POST + CSRF, uspech
i chyba se vraci flashem (Post/Redirect/Get).
"""
import pytest
from helpers import REALM, principaly

from access_manager import Admin


def _pridej_skupinu(prihlaseny_klient, nazev):
    klient, csrf = prihlaseny_klient
    return klient.post("/groups/add", data={"csrf": csrf, "nazev": nazev})


def test_the_listing_shows_a_created_group_and_its_member_count(
    prihlaseny_klient, tmp_path,
):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_user("tereza")
    spravce.add_group("ucetni")
    spravce.add_member("ucetni", "tereza")

    klient, _ = prihlaseny_klient
    telo = klient.get("/groups").get_data(as_text=True)
    assert "ucetni" in telo


def test_adding_a_group_redirects_to_its_detail(prihlaseny_klient):
    odpoved = _pridej_skupinu(prihlaseny_klient, "ucetni")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/groups?group=ucetni")


def test_the_detail_shows_direct_members_and_includes(prihlaseny_klient, tmp_path):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_user("tereza")
    spravce.add_group("mzdy")
    spravce.add_group("ucetni")
    spravce.add_member("mzdy", "tereza")
    spravce.include("ucetni", "mzdy")

    klient, _ = prihlaseny_klient
    telo = klient.get("/groups?group=mzdy").get_data(as_text=True)
    assert "tereza" in telo

    telo = klient.get("/groups?group=ucetni").get_data(as_text=True)
    assert "mzdy" in telo


@pytest.mark.parametrize("skupina", ["neexistuje", "Neplatne Jmeno!"])
def test_a_missing_or_malformed_group_query_shows_the_listing_without_a_crash(
    prihlaseny_klient, skupina,
):
    # Nonexistujici jmeno (validni syntax) i zdeformovany dotaz (neprojde
    # check_name) nesmi stranku shodit - detail proste zmizi.
    klient, _ = prihlaseny_klient
    odpoved = klient.get(f"/groups?group={skupina}")
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    # Detailova sekce (nazev skupiny, cleny, zretezeni) se vubec
    # nerenderuje - zustava jen holy vypis.
    assert "<h3" not in telo
    assert '<h2 class="mono">' not in telo


def test_membership_added_via_the_console_shows_up_in_the_users_closure(
    prihlaseny_klient, tmp_path,
):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_user("tereza")
    spravce.add_group("ucetni")

    klient, csrf = prihlaseny_klient
    odpoved = klient.post(
        "/groups/ucetni/member", data={"csrf": csrf, "clen": "tereza"},
    )
    assert odpoved.status_code == 302

    assert "group:ucetni" in principaly(tmp_path / "data", "tereza")


def test_removing_a_member_drops_the_group_from_the_users_closure(
    prihlaseny_klient, tmp_path,
):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_user("tereza")
    spravce.add_group("ucetni")
    spravce.add_member("ucetni", "tereza")

    klient, csrf = prihlaseny_klient
    odpoved = klient.post(
        "/groups/ucetni/member/tereza/remove", data={"csrf": csrf},
    )
    assert odpoved.status_code == 302

    assert "group:ucetni" not in principaly(tmp_path / "data", "tereza")


def test_belonging_via_chaining_is_shown_separately_from_direct_members(
    prihlaseny_klient, tmp_path,
):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_user("tereza")
    spravce.add_group("mzdy")
    spravce.add_group("ucetni")
    spravce.add_member("mzdy", "tereza")
    spravce.include("ucetni", "mzdy")          # ucetni OBSAHUJE mzdy

    klient, _ = prihlaseny_klient
    telo = klient.get("/groups?group=ucetni").get_data(as_text=True)
    # tereza je clenem "ucetni" jen pres zretezeni, ne primo - v tabulce
    # primych clenu nesmi byt, ale v seznamu "pres retezec" ano.
    assert '<td class="mono">tereza</td>' not in telo
    assert '<span class="chip">tereza</span>' in telo


def test_a_cycle_flashes_the_library_error_and_leaves_the_chain_unchanged(
    prihlaseny_klient, tmp_path,
):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_group("a")
    spravce.add_group("b")
    spravce.include("a", "b")                  # a OBSAHUJE b

    klient, csrf = prihlaseny_klient
    odpoved = klient.post(
        "/groups/b/chain", data={"csrf": csrf, "zahrnuti": "a"},
    )
    assert odpoved.status_code == 302

    from access_manager import Access
    skupina_b = Access.local(tmp_path / "data", realm=REALM).group("b")
    assert skupina_b.includes == ()


def test_a_reserved_group_is_refused_and_state_unchanged(prihlaseny_klient):
    klient, csrf = prihlaseny_klient
    odpoved = klient.post(
        "/groups/add", data={"csrf": csrf, "nazev": "users"},
    )
    assert odpoved.status_code == 302

    telo = klient.get("/groups").get_data(as_text=True)
    assert "zprava-chyba" in telo
    assert ">users<" not in telo


def test_deleting_a_group_removes_it_from_the_listing(prihlaseny_klient):
    _pridej_skupinu(prihlaseny_klient, "ucetni")
    klient, csrf = prihlaseny_klient

    odpoved = klient.post("/groups/ucetni/delete", data={"csrf": csrf})
    assert odpoved.status_code == 302

    telo = klient.get("/groups").get_data(as_text=True)
    assert "ucetni" not in telo


def test_every_mutating_route_without_csrf_is_rejected_and_state_unchanged(
    prihlaseny_klient, tmp_path,
):
    spravce = Admin.local(tmp_path / "data", realm=REALM)
    spravce.add_user("tereza")
    _pridej_skupinu(prihlaseny_klient, "ucetni")
    klient, _ = prihlaseny_klient

    mutace = [
        ("/groups/add", {"nazev": "mzdy"}),
        ("/groups/ucetni/member", {"clen": "tereza"}),
        ("/groups/ucetni/member/tereza/remove", {}),
        ("/groups/ucetni/chain", {"zahrnuti": "ucetni"}),
        ("/groups/ucetni/delete", {}),
    ]
    for cesta, data in mutace:
        odpoved = klient.post(cesta, data=data)
        assert odpoved.status_code == 400, cesta

    telo = klient.get("/groups").get_data(as_text=True)
    assert "ucetni" in telo
    assert "mzdy" not in telo
    assert "group:ucetni" not in principaly(tmp_path / "data", "tereza")


@pytest.mark.parametrize("metoda,cesta", [
    ("get", "/groups"),
    ("post", "/groups/add"),
    ("post", "/groups/ucetni/delete"),
    ("post", "/groups/ucetni/member"),
    ("post", "/groups/ucetni/member/tereza/remove"),
    ("post", "/groups/ucetni/chain"),
])
def test_every_route_without_a_session_redirects_to_login(prostredi, metoda, cesta):
    odpoved = getattr(prostredi, metoda)(cesta)
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")


def test_the_english_language_switches_table_texts(prihlaseny_klient):
    _pridej_skupinu(prihlaseny_klient, "ucetni")
    klient, _ = prihlaseny_klient

    telo = klient.get("/groups?lang=en").get_data(as_text=True)
    assert "Groups" in telo
    assert "Skupiny" not in telo
