"""Bezpecnostni pater sluzby: puvod -> klic -> origin ACL -> dal.

401 bez rozdilu (neexistujici a nepovoleny vypadaji stejne); 403 za puvod
pada driv, nez se cokoli cte; prazdne origins znamena jen smycku.
"""
import pytest
from helpers import REALM
from test_config import zapis  # helper na zapis fragmentu

from access_manager import Admin
from access_manager.config import load_config
from access_manager.server import create_app


@pytest.fixture
def prostredi(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {
        "data": str(tmp_path / "data"),
        "trusted_proxies": ["10.0.0.1"],
    })
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})
    admin = Admin.local(tmp_path / "data", realm=REALM)
    klic = admin.register_component("app:test", origins=("10.42.0.0/16",))
    loopback = admin.register_component("app:local")      # prazdne origins
    cfg = load_config(tmp_path / "conf.d")
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client(), klic, loopback


def test_health_needs_no_key(prostredi):
    client, _, _ = prostredi
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/version").get_json()["api"] == "1"


def test_no_key_is_401_everywhere_else(prostredi):
    client, _, _ = prostredi
    assert client.get("/v1/users").status_code == 401


def test_a_wrong_key_is_the_same_401(prostredi):
    client, _, _ = prostredi
    hlavicka = {"Authorization": "Bearer am_k1_" + "0" * 64}
    odpoved = client.get("/v1/users", headers=hlavicka)
    assert odpoved.status_code == 401


def test_a_valid_key_from_a_wrong_origin_is_403(prostredi):
    client, klic, _ = prostredi
    odpoved = client.get(
        "/v1/users", headers={"Authorization": f"Bearer {klic}"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.9"},
    )
    assert odpoved.status_code == 403


def test_a_valid_key_from_its_cidr_passes(prostredi):
    client, klic, _ = prostredi
    odpoved = client.get(
        "/v1/users", headers={"Authorization": f"Bearer {klic}"},
        environ_overrides={"REMOTE_ADDR": "10.42.3.7"},
    )
    assert odpoved.status_code == 200


def test_empty_origins_means_loopback_only(prostredi):
    client, _, loopback = prostredi
    doma = client.get("/v1/users", headers={"Authorization": f"Bearer {loopback}"},
                      environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    venku = client.get("/v1/users", headers={"Authorization": f"Bearer {loopback}"},
                       environ_overrides={"REMOTE_ADDR": "10.42.3.7"})
    assert doma.status_code == 200
    assert venku.status_code == 403


def test_forwarded_for_counts_only_from_a_trusted_proxy(prostredi):
    client, klic, _ = prostredi
    pres_proxy = client.get(
        "/v1/users", headers={"Authorization": f"Bearer {klic}",
                              "X-Forwarded-For": "1.2.3.4, 10.42.3.7"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
    )
    primo = client.get(
        "/v1/users", headers={"Authorization": f"Bearer {klic}",
                              "X-Forwarded-For": "10.42.3.7"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.9"},
    )
    assert pres_proxy.status_code == 200      # hops=1: bere se pravy prvek
    assert primo.status_code == 403           # nepoveryhodny peer: XFF se ignoruje


def test_readyz_reports_unready_realms(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", "alfa.json", {"name": "alfa", "admins": []})
    cfg = load_config(tmp_path / "conf.d")
    app = create_app(cfg)
    odpoved = app.test_client().get("/readyz")
    assert odpoved.status_code == 503          # realm jeste nema uloziste
