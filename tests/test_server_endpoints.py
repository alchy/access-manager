"""Cteci endpointy sluzby: vzdy jen v realmu klice, nikdy krizem.

Fixture zaklada DVA realmy (REALM a beta), kazdy s vlastnim loopback klicem.
V REALMu je hana clenem mzdy a ucetni obsahuje mzdy zretezenim - uzaver tak
uz obsahuje group:ucetni, i kdyz je hana clenem jen primo mzdy.
"""
import pytest
from helpers import REALM, koren
from test_config import zapis

from access_manager import Admin
from access_manager.audit import read_events
from access_manager.config import load_config
from access_manager.server import create_app

BETA = "beta"


def hlavicky(klic):
    return {"Authorization": f"Bearer {klic}"}


@pytest.fixture
def prostredi(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    zapis(tmp_path / "conf.d" / "realms", f"{REALM}.json",
          {"name": REALM, "admins": ["jindrich"]})
    zapis(tmp_path / "conf.d" / "realms", f"{BETA}.json",
          {"name": BETA, "admins": ["jindrich"]})

    admin = Admin.local(tmp_path / "data", realm=REALM)
    admin.add_user("hana")
    admin.add_group("mzdy")
    admin.add_group("ucetni")
    admin.add_member("mzdy", "hana")
    admin.include("ucetni", "mzdy")           # ucetni OBSAHUJE mzdy
    klic = admin.register_component("app:test")           # prazdne origins

    beta_admin = Admin.local(tmp_path / "data", realm=BETA)
    beta_klic = beta_admin.register_component("app:beta")  # prazdne origins

    cfg = load_config(tmp_path / "conf.d")
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client(), klic, beta_klic


def test_who_is_who_returns_the_flat_closure(prostredi):
    client, klic, _ = prostredi
    telo = client.get("/v1/users/hana", headers=hlavicky(klic)).get_json()
    assert telo["exists"] is True
    assert "group:ucetni" in telo["principals"]


def test_an_unknown_user_is_exists_false(prostredi):
    client, klic, _ = prostredi
    odpoved = client.get("/v1/users/nikdo", headers=hlavicky(klic))
    assert odpoved.status_code == 200
    assert odpoved.get_json() == {"exists": False}


def test_listings_and_group_shape(prostredi):
    client, klic, _ = prostredi
    users = client.get("/v1/users", headers=hlavicky(klic)).get_json()
    assert users == {"users": ["hana"]}

    groups = client.get("/v1/groups", headers=hlavicky(klic)).get_json()
    assert groups == {"groups": ["mzdy", "ucetni"]}

    ucetni = client.get("/v1/groups/ucetni", headers=hlavicky(klic)).get_json()
    assert ucetni["exists"] is True
    assert ucetni["members"] == []
    assert ucetni["includes"] == ["group:mzdy"]


def test_principals_check_reports_the_unknown(prostredi):
    client, klic, _ = prostredi
    odpoved = client.post(
        "/v1/principals/check", headers=hlavicky(klic),
        json={"principals": ["user:hana", "group:ucetni", "group:neni"]},
    )
    assert odpoved.status_code == 200
    assert odpoved.get_json() == {"unknown": ["group:neni"]}


def test_principals_check_needs_the_field(prostredi):
    client, klic, _ = prostredi
    odpoved = client.post(
        "/v1/principals/check", headers=hlavicky(klic), json={},
    )
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


def test_principals_check_rejects_malformed_json(prostredi):
    client, klic, _ = prostredi
    odpoved = client.post(
        "/v1/principals/check", headers=hlavicky(klic),
        data="neni to json", content_type="application/json",
    )
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


def test_principals_check_rejects_a_scalar(prostredi):
    # "principals" musi byt seznam - retezec by se tise iteroval po znacich.
    client, klic, _ = prostredi
    odpoved = client.post(
        "/v1/principals/check", headers=hlavicky(klic),
        json={"principals": "group:x"},
    )
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


def test_whoami_names_the_key(prostredi):
    client, klic, _ = prostredi
    telo = client.get("/v1/whoami", headers=hlavicky(klic)).get_json()
    assert telo["component"] == "app:test"
    assert telo["realm"] == REALM
    assert "key_id" in telo


def test_generation_is_the_realms_generation(prostredi, tmp_path):
    client, klic, _ = prostredi
    pred = client.get("/v1/generation", headers=hlavicky(klic)).get_json()["gen"]
    Admin.local(tmp_path / "data", realm=REALM).add_user("nova")
    po = client.get("/v1/generation", headers=hlavicky(klic)).get_json()["gen"]
    assert po > pred


def test_a_second_realm_is_invisible(prostredi):
    client, klic, beta_klic = prostredi
    z_realmu = client.get("/v1/users", headers=hlavicky(klic)).get_json()
    z_bety = client.get("/v1/users", headers=hlavicky(beta_klic)).get_json()
    assert z_realmu == {"users": ["hana"]}
    assert z_bety == {"users": []}

    # klic bety nevidi hanu, i kdyz se zepta primo na jeji jmeno
    cizi_pohled = client.get("/v1/users/hana", headers=hlavicky(beta_klic))
    assert cizi_pohled.get_json() == {"exists": False}


def test_a_malformed_name_is_400(prostredi):
    client, klic, _ = prostredi
    odpoved = client.get("/v1/users/..%2F..", headers=hlavicky(klic))
    assert odpoved.status_code == 400
    assert odpoved.get_json() == {"error": "bad_request"}


def test_an_unknown_v1_path_is_404(prostredi):
    client, klic, _ = prostredi
    odpoved = client.get("/v1/nesmysl", headers=hlavicky(klic))
    assert odpoved.status_code == 404


def test_authenticate_audits_the_asking_component_key_and_origin(prostredi, tmp_path):
    """Cely retezec "kdo se ptal" az do auditu: sluzba adresu uz spocitala
    pro origin ACL, tak ji ma predat dal."""
    client, klic, _ = prostredi
    client.post(
        "/v1/authenticate",
        json={"username": "hana", "credentials": {"totp": "000000"},
              "purpose": "login"},
        headers={"Authorization": f"Bearer {klic}"},
    )
    udalost = read_events(koren(tmp_path / "data"), kind="authenticate")[-1]
    assert udalost["subject"] == "user:hana"
    assert udalost["component"]
    assert udalost["key_id"]
    assert udalost["origin"]
