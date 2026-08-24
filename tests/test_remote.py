"""RemoteStore: TLS vynucene mimo loopback, overeni verze/totoznosti, retry.

Zadny test tady neotevira soket - `httpx.WSGITransport` vola aplikaci
primo v pameti, stejne jako `app.test_client()` na serverove strane.
"""
import httpx
import pytest
from helpers import REALM, TAJEMSTVI, kod, koren, zaloz
from test_config import zapis  # helper na zapis fragmentu

from access_manager import Access, Admin
from access_manager.config import load_config
from access_manager.remote import RemoteStore
from access_manager.server import create_app


@pytest.fixture
def sluzba(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})
    admin = Admin.local(tmp_path / "data", realm=REALM)
    klic = admin.register_component("app:test")   # prazdne origins = jen loopback
    cfg = load_config(tmp_path / "conf.d")
    return create_app(cfg), klic


def test_remote_construction_checks_version_and_realm(sluzba):
    app, klic = sluzba
    remote = RemoteStore(
        "http://127.0.0.1", klic, realm=REALM,
        transport=httpx.WSGITransport(app=app),
    )
    assert remote.component == "app:test"
    assert remote.realm_name == REALM
    assert remote.key_id


def test_a_realm_mismatch_fails_loudly(sluzba):
    app, klic = sluzba
    with pytest.raises(RuntimeError, match="realm"):
        RemoteStore(
            "http://127.0.0.1", klic, realm="jiny-realm",
            transport=httpx.WSGITransport(app=app),
        )


def test_http_outside_loopback_is_refused():
    # Zadny transport netreba - selhat to ma driv, nez padne prvni pozadavek.
    with pytest.raises(ValueError, match="https"):
        RemoteStore("http://example.com", "am_k1_" + "0" * 64)


def test_http_on_loopback_is_allowed_for_dev(sluzba):
    app, klic = sluzba
    remote = RemoteStore(
        "http://localhost", klic,
        transport=httpx.WSGITransport(app=app),
    )
    assert remote.realm_name == REALM


def test_retries_survive_a_flaky_5xx(sluzba):
    app, klic = sluzba

    class VadnaSit:
        """WSGI obalka: prvni dve volani spadnou na 500, pak pusti dal."""

        def __init__(self, cilova_app):
            self._cilova_app = cilova_app
            self.volani = 0

        def __call__(self, environ, start_response):
            self.volani += 1
            if self.volani <= 2:
                start_response(
                    "500 Internal Server Error",
                    [("Content-Type", "text/plain")],
                )
                return [b"vypadek"]
            return self._cilova_app(environ, start_response)

    obalka = VadnaSit(app)
    remote = RemoteStore(
        "http://127.0.0.1", klic,
        transport=httpx.WSGITransport(app=obalka),
    )
    assert remote.realm_name == REALM
    assert obalka.volani >= 3


def test_the_key_never_appears_in_errors(sluzba):
    app, _ = sluzba
    spatny_klic = "am_k1_" + "9" * 64
    with pytest.raises(RuntimeError) as vyjimka:
        RemoteStore(
            "http://127.0.0.1", spatny_klic,
            transport=httpx.WSGITransport(app=app),
        )
    assert spatny_klic not in str(vyjimka.value)


def test_ca_refuses_a_bool_killswitch():
    # ca=False by v httpx vypnulo overeni certifikatu - vypinac neexistuje.
    # Selhat to ma driv, nez padne prvni pozadavek - zadny transport netreba.
    with pytest.raises(TypeError):
        Access.remote("https://example.com", "am_k1_" + "0" * 64, ca=False)
    with pytest.raises(TypeError):
        Access.remote("https://example.com", "am_k1_" + "0" * 64, ca=True)


# ===========================================================================
# Datove metody a cache podle generace (ukol 8)
# ===========================================================================


@pytest.fixture
def sluzba_s_daty(tmp_path):
    """Sluzba s uzivatelem hana (clen ucetni) a dvema komponentami - tichou
    (detail=False) a hlucnou (detail=True). Stejny DATA adresar jako
    `Access.local`, aby testy mohly porovnavat vzdaleny a mistni pohled."""
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})

    zaloz(tmp_path / "data", "hana", TAJEMSTVI)
    admin = Admin.local(tmp_path / "data", realm=REALM)
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    tichy = admin.register_component("app:quiet")            # detail=False
    hlucny = admin.register_component("app:loud", detail=True)

    cfg = load_config(tmp_path / "conf.d")
    app = create_app(cfg)
    return app, tichy, hlucny, admin, tmp_path / "data"


def _remote(app, klic):
    return RemoteStore(
        "http://127.0.0.1", klic, transport=httpx.WSGITransport(app=app),
    )


def test_remote_authenticate_matches_local_shapes(sluzba_s_daty):
    app, tichy, _, _, data = sluzba_s_daty
    remote = _remote(app, tichy)
    mistni = Access.local(data, realm=REALM)

    verdikt = remote.authenticate("hana", {"totp": kod()}, purpose="login")

    assert verdikt.outcome == "ok"
    assert verdikt.subject_id == "user:hana"
    assert verdikt.principals == mistni.user("hana").principals
    assert verdikt.gen is not None


def test_remote_replay_is_denied(sluzba_s_daty):
    app, tichy, _, _, _ = sluzba_s_daty
    remote = _remote(app, tichy)
    stejny = kod()
    telo = {"totp": stejny}

    prvni = remote.authenticate("hana", telo, purpose="login")
    druhy = remote.authenticate("hana", telo, purpose="login")

    assert prvni.outcome == "ok"
    assert druhy.outcome == "denied"
    assert druhy.reason is None            # tichy komponent nema detail


def test_a_detail_component_gets_the_reason_remotely(sluzba_s_daty):
    app, _, hlucny, _, _ = sluzba_s_daty
    remote = _remote(app, hlucny)

    verdikt = remote.authenticate("hana", {"totp": "000000"}, purpose="login")

    assert verdikt.outcome == "denied"
    assert verdikt.reason == "bad_code"


def test_remote_user_returns_the_flat_closure(sluzba_s_daty):
    app, tichy, _, _, _ = sluzba_s_daty
    remote = _remote(app, tichy)

    hana = remote.user("hana")
    assert hana is not None
    assert hana.subject_id == "user:hana"
    assert hana.enabled is True
    assert "group:ucetni" in hana.principals
    assert "user:hana" in hana.principals

    assert remote.user("nikdo") is None


def test_the_user_cache_is_invalidated_by_gen(sluzba_s_daty):
    app, tichy, _, admin, _ = sluzba_s_daty
    remote = _remote(app, tichy)
    admin.add_group("mzdy")

    pred = remote.user("hana")
    assert "group:mzdy" not in pred.principals

    admin.add_member("mzdy", "hana")           # zvedne generaci na disku
    remote.generation()                        # vzdaleny klient generaci pozoruje
    po = remote.user("hana")

    assert "group:mzdy" in po.principals        # stara cache se NEPOUZILA


def test_remote_group_mirrors_the_wire_prefix(sluzba_s_daty):
    app, tichy, _, admin, data = sluzba_s_daty
    admin.add_group("mzdy")
    admin.include("ucetni", "mzdy")
    remote = _remote(app, tichy)
    mistni = Access.local(data, realm=REALM)

    dalkove = remote.group("ucetni")
    domaci = mistni.group("ucetni")

    assert dalkove is not None
    assert dalkove.includes == domaci.includes == ("mzdy",)   # bez "group:" prefixu
    assert dalkove.members == domaci.members
    assert remote.group("neexistuje") is None


def test_remote_users_groups_and_unknown_principals(sluzba_s_daty):
    app, tichy, _, admin, _ = sluzba_s_daty
    remote = _remote(app, tichy)

    assert remote.users() == ["hana"]
    assert remote.groups() == ["ucetni"]
    assert remote.unknown_principals(
        ["user:hana", "group:ucetni", "group:neni"]
    ) == ["group:neni"]


def test_remote_ready_and_generation(sluzba_s_daty):
    app, tichy, _, _, data = sluzba_s_daty
    remote = _remote(app, tichy)

    assert remote.ready() is None

    pred = remote.generation()
    Admin.local(data, realm=REALM).add_group("mzdy")
    po = remote.generation()
    assert po > pred

    (koren(data) / "groups.json").write_text("{zlomeno", encoding="utf-8")
    assert "groups.json" in remote.ready()


def test_remote_throttled_carries_retry_after(sluzba_s_daty):
    app, tichy, _, _, _ = sluzba_s_daty
    remote = _remote(app, tichy)
    telo = {"totp": "000000"}

    for _ in range(5):
        remote.authenticate("hana", telo, purpose="login")
    verdikt = remote.authenticate("hana", telo, purpose="login")

    assert verdikt.outcome == "throttled"
    assert 0 < verdikt.retry_after <= 60


def test_remote_authenticate_raises_on_a_bad_request(sluzba_s_daty):
    # Spatny tvar ucelu je chyba VOLAJICIHO (nase chyba), ne verdikt - server
    # odpovi 400 a klient to ma nahlasit jako chybu programatora, ne ticho
    # vratit nejaky verdikt.
    app, tichy, _, _, _ = sluzba_s_daty
    remote = _remote(app, tichy)
    with pytest.raises(RuntimeError):
        remote.authenticate("hana", {"totp": kod()}, purpose="cokoli")
