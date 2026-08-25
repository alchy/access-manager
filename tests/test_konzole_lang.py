"""Stranka-agnosticky prepinac jazyka: GET /lang uklada jazyk do session a
presmeruje zpet na `next`, s ochranou proti open redirectu. Puvodni
mechanismus `?lang=cs|en` (pres before_request) zustava funkcni dal - `/lang`
je jen dalsi, PRG-bezpecna cesta pro POST-vyrenderovane stranky (napr.
klic.html), kde holy `?lang=` skonci 405 (jina metoda) nebo ztrati dotaz
(filtrovany /audit, /groups?group=...).
"""
from urllib.parse import quote


def test_lang_switch_preserves_a_filtered_audit_query(prihlaseny_klient):
    klient, _ = prihlaseny_klient
    cesta = "/audit?subject=admin:jindrich&kind=authenticate"
    odpoved = klient.get(f"/lang?to=en&next={quote(cesta, safe='')}")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith(cesta)

    with klient.session_transaction() as relace:
        assert relace["lang"] == "en"


def test_lang_switch_with_an_open_redirect_next_falls_back_to_root(prostredi):
    odpoved = prostredi.get("/lang?to=en&next=//evil.example")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/")
    assert "evil.example" not in odpoved.headers["Location"]


def test_lang_switch_without_a_next_falls_back_to_root(prostredi):
    odpoved = prostredi.get("/lang?to=cs")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/")


def test_lang_switch_with_an_invalid_to_value_is_ignored(prostredi):
    with prostredi.session_transaction() as relace:
        relace["lang"] = "cs"

    odpoved = prostredi.get("/lang?to=xx&next=/login")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")

    with prostredi.session_transaction() as relace:
        assert relace["lang"] == "cs"
