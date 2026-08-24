"""Kostra konzole: factory, sdileny layout, prihlasovaci stranka, strazce relace.

Kompletni prihlaseni (POST /login dvema kody) prijde az v ukolu 3 - tady jen
GET /login (formular + prepinac jazyka) a strazce nechraneneho pristupu.
"""
import pytest
from helpers import REALM
from test_config import zapis

from access_manager import Admin
from access_manager.config import load_config
from access_manager.konzole.app import create_console_app


@pytest.fixture
def prostredi(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})
    Admin.local(tmp_path / "data", realm=REALM).add_admin("jindrich")

    cfg = load_config(tmp_path / "conf.d")
    app = create_console_app(cfg)
    app.config["TESTING"] = True
    return app.test_client()


def test_login_page_renders_in_czech_by_default(prostredi):
    odpoved = prostredi.get("/login")
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Přihlášení" in telo


def test_the_language_toggle_switches_to_english(prostredi):
    odpoved = prostredi.get("/login?lang=en")
    assert odpoved.status_code == 200
    telo = odpoved.get_data(as_text=True)
    assert "Login" in telo
    assert "Přihlášení" not in telo


def test_a_guarded_page_redirects_to_login(prostredi):
    odpoved = prostredi.get("/")
    assert odpoved.status_code == 302
    assert odpoved.headers["Location"].endswith("/login")
