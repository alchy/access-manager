"""RemoteStore: TLS vynucene mimo loopback, overeni verze/totoznosti, retry.

Zadny test tady neotevira soket - `httpx.WSGITransport` vola aplikaci
primo v pameti, stejne jako `app.test_client()` na serverove strane.
"""
import httpx
import pytest
from helpers import REALM
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
