"""Sdilene fixtury pro testy konzole: cerstve prostredi a uz prihlaseny klient.

`test_konzole_login.py` si drzi vlastni `prostredi` (testuje samotne
prihlaseni), ale kazda dalsi stranka uz prihlaseni jen predpoklada - proto
tenhle spolecny zaklad, aby se choreografie "zapis admina, nacti config,
prihlas se dvema kody" nekopirovala do kazdeho souboru zvlast.
"""
import pytest
from helpers import REALM, admin_kody
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


@pytest.fixture
def prihlaseny_klient(prostredi, tmp_path):
    """Klient uz prihlaseny jako spravce `jindrich` - vraci (klient, csrf)."""
    prvni, druhy = admin_kody(tmp_path / "data")
    prostredi.post(
        "/login",
        data={"realm": REALM, "jmeno": "jindrich", "kod1": prvni, "kod2": druhy},
    )
    with prostredi.session_transaction() as relace:
        token = relace["csrf"]
    return prostredi, token
