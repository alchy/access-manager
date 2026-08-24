"""`POST /v1/authenticate`: vzdy 200, `reason` jen duveryhodnym komponentam.

Ctyri tvary verdiktu na drate (`verdict_to_wire`); chyba volajiciho
(chybejici pole, spatny tvar ucelu) je 400, ne verdikt - viz test_wire.py
pro samotne tvary a test_throttle.py pro pocitani pokusu.
"""
import pytest
from helpers import REALM, TAJEMSTVI, kod, koren, zaloz
from test_config import zapis

from access_manager import Admin
from access_manager.audit import read_events
from access_manager.config import load_config
from access_manager.server import create_app


def hlavicky(klic):
    return {"Authorization": f"Bearer {klic}"}


@pytest.fixture
def prostredi(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})

    zaloz(tmp_path / "data", "hana", TAJEMSTVI)
    admin = Admin.local(tmp_path / "data", realm=REALM)
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    tichy = admin.register_component("app:quiet")            # detail=False (vychozi)
    hlucny = admin.register_component("app:loud", detail=True)

    cfg = load_config(tmp_path / "conf.d")
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client(), tichy, hlucny, tmp_path / "data"


def test_ok_returns_sorted_principals_and_gen(prostredi):
    client, tichy, _, _ = prostredi
    odpoved = client.post(
        "/v1/authenticate", headers=hlavicky(tichy),
        json={"username": "hana", "credentials": {"totp": kod()}, "purpose": "login"},
    )
    assert odpoved.status_code == 200
    telo = odpoved.get_json()
    assert telo["outcome"] == "ok"
    assert telo["principals"] == [
        "group:public", "group:ucetni", "group:users", "user:hana",
    ]
    assert "gen" in telo


def test_denied_hides_reason_without_detail(prostredi):
    client, tichy, _, _ = prostredi
    odpoved = client.post(
        "/v1/authenticate", headers=hlavicky(tichy),
        json={
            "username": "hana", "credentials": {"totp": "000000"}, "purpose": "login",
        },
    )
    assert odpoved.status_code == 200
    telo = odpoved.get_json()
    assert telo["outcome"] == "denied"
    assert "reason" not in telo


def test_denied_shows_reason_with_detail(prostredi):
    client, _, hlucny, _ = prostredi
    odpoved = client.post(
        "/v1/authenticate", headers=hlavicky(hlucny),
        json={
            "username": "hana", "credentials": {"totp": "000000"}, "purpose": "login",
        },
    )
    assert odpoved.status_code == 200
    telo = odpoved.get_json()
    assert telo["outcome"] == "denied"
    assert telo["reason"] == "bad_code"


def test_need_factor_lists_required(prostredi):
    client, tichy, _, _ = prostredi
    odpoved = client.post(
        "/v1/authenticate", headers=hlavicky(tichy),
        json={"username": "hana", "credentials": {}, "purpose": "login"},
    )
    assert odpoved.status_code == 200
    telo = odpoved.get_json()
    assert telo["outcome"] == "need_factor"
    assert telo["required"] == ["totp"]


def test_replay_is_denied(prostredi):
    client, _, hlucny, _ = prostredi
    stejny = kod()
    telo = {"username": "hana", "credentials": {"totp": stejny}, "purpose": "login"}
    prvni = client.post("/v1/authenticate", headers=hlavicky(hlucny), json=telo)
    druhy = client.post("/v1/authenticate", headers=hlavicky(hlucny), json=telo)
    assert prvni.get_json()["outcome"] == "ok"
    assert druhy.status_code == 200
    assert druhy.get_json()["outcome"] == "denied"
    assert druhy.get_json()["reason"] == "replay"


def test_throttled_reports_retry_after(prostredi):
    client, tichy, _, _ = prostredi
    telo = {"username": "hana", "credentials": {"totp": "000000"}, "purpose": "login"}
    for _ in range(5):
        client.post("/v1/authenticate", headers=hlavicky(tichy), json=telo)
    odpoved = client.post("/v1/authenticate", headers=hlavicky(tichy), json=telo)
    assert odpoved.status_code == 200
    vysledek = odpoved.get_json()
    assert vysledek["outcome"] == "throttled"
    assert 0 < vysledek["retry_after"] <= 60


def test_bad_purpose_shape_is_400(prostredi):
    client, tichy, _, _ = prostredi
    odpoved = client.post(
        "/v1/authenticate", headers=hlavicky(tichy),
        json={"username": "hana", "credentials": {"totp": kod()}, "purpose": "cokoli"},
    )
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


def test_missing_username_is_400(prostredi):
    client, tichy, _, _ = prostredi
    odpoved = client.post(
        "/v1/authenticate", headers=hlavicky(tichy),
        json={"credentials": {"totp": kod()}, "purpose": "login"},
    )
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


def test_audit_carries_the_component_name(prostredi):
    client, tichy, _, data = prostredi
    client.post(
        "/v1/authenticate", headers=hlavicky(tichy),
        json={"username": "hana", "credentials": {"totp": kod()}, "purpose": "login"},
    )
    udalosti = read_events(koren(data), kind="authenticate")
    assert len(udalosti) == 1
    assert udalosti[0]["component"] == "app:quiet"
