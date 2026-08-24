# REST služba a Access.remote — implementační plán

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implementovat REST službu (Flask/waitress, extra `[server]`) nad hotovým `FileStore` a vzdálený klient `Access.remote` (httpx, extra `[remote]`), plus throttling, drátové tvary, konfigurační loader, entrypoint a Dockerfile — vše testované bez sítě.

**Architecture:** Nové moduly: `wire.py` (drátové tvary, jen stdlib), `config.py` (loader conf.d, jen stdlib), `server.py` (WSGI aplikace + entrypoint; flask/waitress lazy za `_require_server`), `remote.py` (RemoteStore nad httpx; lazy import). Throttling a `retry_after` jdou do `FileStore`/`Verdict` (funguje i lokálně). `Access.remote` vrací tutéž fasádu `Access` nad `RemoteStore` — stejné typy, stejné tvary. Testy: služba přes flask `test_client()`, remote přes httpx `WSGITransport` proti téže aplikaci.

**Tech Stack:** Python ≥ 3.12; extras: `[server] flask>=3, waitress>=3`, `[remote] httpx>=0.27` (už deklarované), `[totp]` beze změny. Klient bez extras nemá závislosti.

**Spec:** `docs/superpowers/specs/2026-08-24-sluzba-a-remote-design.md` (odsouhlasený 2026-08-24). Pozadí: `docs/design.md` (závazný), spec realms.

## Global Constraints

- `dependencies = []` zůstává; flask/waitress/httpx JEN lazy-importem uvnitř `[server]`/`[remote]` cest (`wire.py` a `config.py` musí být importovatelné bez extras). Chybějící extra hlásí `RuntimeError` se `pip install 'access-manager[server]'` (vzor `_require_totp`).
- Testy bez sítě: nikdy se neotvírá socket (žádné `waitress.serve` v testech); služba přes `app.test_client()`, remote přes `httpx.WSGITransport(app=...)`. Po každém úkolu `./.venv/bin/python -m pytest` zelené a `./.venv/bin/ruff check .` čistý.
- Pořadí zpracování požadavku (spec §3) je NEPORUŠITELNÉ: původ → klíč (401 bez rozdílů) → origin ACL (403 a nic dál) → throttle → parsování → FileStore. Prázdné `origins` komponenty = jen smyčka (design §2b).
- `authenticate` odpovídá VŽDY `200` čtyřmi tvary; `reason` jen pro komponentu s `detail: true`; chyba volajícího (chybějící pole, špatný tvar účelu) = `400`, ne verdikt.
- `Access.remote` vyžaduje `https://` (výjimka jen loopback: 127.0.0.1/::1/localhost); ověření certifikátu nemá vypínač, vlastní CA jen přes `ca=`.
- Tajemství/kódy/klíče nikdy do logů, výjimek, auditu.
- Kód a komentáře česky bez diakritiky; jména testů anglicky; commity česky, malými písmeny, s trailerem `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` po prázdném řádku.
- Baseline: 192 testů. Rozhodnutí plánu (vědomá): auditní událost odmítnutého původu má `kind="origin_denied"` (component, key_id, origin — interní formát); parametr `transport=` u `Access.remote` je testovací hák (nedokumentuje se v README); `RemoteStore.authenticate` parametr `component` ignoruje (na drátě ho určuje klíč).

## Struktura souborů

| Soubor | Odpovědnost | Úkol |
|---|---|---|
| `access_manager/verdicts.py` | +`retry_after`, `Verdict.throttled` | 1 |
| `access_manager/files.py` | throttling (`throttle.json`), `ready()` kryje `gen` | 1 |
| `access_manager/wire.py` (nový) | drátové tvary verdiktu/uživatele/skupiny | 2 |
| `access_manager/config.py` (nový) | `ServiceConfig`, `load_config(conf_dir)` | 3 |
| `access_manager/server.py` (nový) | `create_app(cfg)`, pipeline, endpointy, entrypoint, konzole 501 | 4–6, 9 |
| `access_manager/remote.py` (nový) | `RemoteStore` (httpx) | 7–8 |
| `access_manager/access.py` | `Access.remote(...)` | 7 |
| `Dockerfile`, `pyproject.toml`, `README.md` | kontejner, extras, dokumentace | 10 |
| `tests/test_throttle.py`, `test_wire.py`, `test_config.py`, `test_server_pipeline.py`, `test_server_endpoints.py`, `test_server_authenticate.py`, `test_remote.py`, `test_server_main.py` | nové oblasti | 1–9 |

Mimo rozsah: konzole (jen 501 listener), mTLS, SIGHUP reload, DB backend, HMAC podepisování (spec §9).

---

### Úkol 1: Throttling ve FileStore + `Verdict.retry_after` (+ `ready()` kryje `gen`)

**Files:**
- Modify: `access_manager/verdicts.py`, `access_manager/files.py`
- Test: `tests/test_throttle.py` (nový), `tests/test_files_identity.py` (ready+gen)

**Interfaces:**
- Produces: `Verdict(..., retry_after: int | None = None)` — povoleno jen s outcome `throttled` (jinak ValueError); `Verdict.throttled(retry_after, gen=None)`. `FileStore.__init__` nové kwargs `throttle_attempts: int = 5`, `throttle_window_s: int = 60`. Interní: `_throttled(directory) -> int | None` (zbývající sekundy, lock-free čtení), `_record_failure(directory)` (pod zámkem: reset okna po vypršení, inkrement), `_clear_throttle(directory)` (unlink, bez zámku). Soubor `throttle.json`: `{"od": <epocha>, "pokusu": <n>}`. Platí pro `authenticate` i `authenticate_admin`. Úkoly 2, 6, 8 konzumují `retry_after`.

- [ ] **Krok 1: Failing testy** — `tests/test_throttle.py`:

```python
"""Omezovani pokusu: po N neuspesich v okne prijde `throttled`.

Pocitaji se JEN bad_code/replay existujici identity - neexistujici jmeno
pocitadlo nezveda (jinak si kdokoli necha zamknout cizi jmena) a blokovany
puvod se sem u sluzby vubec nedostane. Uspech pocitadlo maze.
"""
import json
import time

from access_manager import Access, Admin

from helpers import REALM, koren, kod, zaloz


def store_access(tmp_path):
    return Access.local(tmp_path, realm=REALM)


def vycerpej(access, jmeno="hana", pokusu=5):
    for _ in range(pokusu):
        access.authenticate(jmeno, {"totp": "000000"}, purpose="login")


def test_five_failures_throttle_the_identity(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    verdikt = access.authenticate("hana", {"totp": "000000"}, purpose="login")
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after is not None
    assert 0 < verdikt.retry_after <= 60


def test_a_throttled_identity_refuses_even_the_right_code(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login").outcome == "throttled"


def test_success_clears_the_counter(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access, pokusu=4)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")
    vycerpej(access, pokusu=4)
    assert access.authenticate("hana", {"totp": "000000"}, purpose="login").reason == "bad_code"


def test_an_unknown_name_does_not_count(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    for _ in range(10):
        access.authenticate("nikdo", {"totp": "000000"}, purpose="login")
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")


def test_an_expired_window_unlocks(tmp_path):
    zaloz(tmp_path, "hana")
    access = store_access(tmp_path)
    vycerpej(access)
    cesta = koren(tmp_path) / "user-hana" / "throttle.json"
    data = json.loads(cesta.read_text(encoding="utf-8"))
    data["od"] = int(time.time()) - 120
    cesta.write_text(json.dumps(data), encoding="utf-8")
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")


def test_the_admin_login_is_throttled_too(tmp_path):
    from access_manager.files import FileStore
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    store = FileStore(koren(tmp_path), realm=REALM)
    for _ in range(5):
        store.authenticate_admin("jindrich", "000000", "111111")
    verdikt = store.authenticate_admin("jindrich", "000000", "111111")
    assert verdikt.outcome == "throttled"
    assert verdikt.retry_after is not None
```

a do `tests/test_verdict.py`:

```python
def test_retry_after_rides_only_on_throttled():
    assert Verdict.throttled(27).retry_after == 27
    with pytest.raises(ValueError):
        Verdict(outcome="denied", reason="bad_code", retry_after=5)
```

a do `tests/test_files_identity.py` (sekce připravenosti):

```python
def test_a_corrupt_gen_file_is_not_ready(tmp_path):
    zaloz(tmp_path, "hana")
    (koren(tmp_path) / "gen").write_text("zlomeno", encoding="utf-8")
    assert "gen" in Access.local(tmp_path, realm=REALM).ready()
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_throttle.py -v`; FAIL (`retry_after` neexistuje).
- [ ] **Krok 3: `verdicts.py`** — pole `retry_after: int | None = None` (za `gen`); do `__post_init__`:

```python
        if self.retry_after is not None and self.outcome != "throttled":
            raise ValueError("retry_after patri jen k `throttled`")
```

a classmethod:

```python
    @classmethod
    def throttled(cls, retry_after: int | None, gen: int | None = None) -> Verdict:
        """Prilis mnoho pokusu. `retry_after` rika, za kolik sekund to zkusit."""
        return cls(outcome="throttled", retry_after=retry_after, gen=gen)
```

- [ ] **Krok 4: `files.py`** — konstruktor + konstanta `THROTTLE = "throttle.json"`; metody:

```python
    def _throttled(self, directory: Path) -> int | None:
        """Kolik sekund jeste identita ceka - nebo None. Cteni bez zamku."""
        cesta = directory / THROTTLE
        if not cesta.is_file():
            return None
        try:
            data = json.loads(cesta.read_text(encoding="utf-8"))
            od, pokusu = int(data["od"]), int(data["pokusu"])
        except (ValueError, KeyError, OSError):
            return None                      # poskozeny soubor neblokuje
        zbyva = od + self.throttle_window_s - int(time.time())
        if pokusu >= self.throttle_attempts and zbyva > 0:
            return zbyva
        return None

    def _record_failure(self, directory: Path) -> None:
        # Pocita se jen neuspech EXISTUJICI identity (bad_code/replay) -
        # neexistujici jmeno pocitadlo nezveda, jinak jde zamknout cizi ucet.
        with _locked(self.home):
            cesta = directory / THROTTLE
            ted = int(time.time())
            try:
                data = json.loads(cesta.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {"od": ted, "pokusu": 0}
            if int(data.get("od", 0)) + self.throttle_window_s <= ted:
                data = {"od": ted, "pokusu": 0}
            data["pokusu"] = int(data.get("pokusu", 0)) + 1
            _replace(cesta, json.dumps(data))

    def _clear_throttle(self, directory: Path) -> None:
        (directory / THROTTLE).unlink(missing_ok=True)
```

Zapojení do `_authenticate_verdict` (a zrcadlově `_authenticate_admin_verdict`): za kontrolu `expired`, PŘED kontrolou pověření:

```python
        zbyva = self._throttled(directory)
        if zbyva is not None:
            return Verdict.throttled(zbyva, gen=gen)
```

na větvích `bad_code` a `replay` před `return`: `self._record_failure(directory)`; na úspěšné větvi po `_consume`: `self._clear_throttle(directory)`. `ready()` doplň:

```python
        try:
            self.generation()
        except (OSError, ValueError) as chyba:
            return f"{GEN} nejde precist: {chyba}"
```

- [ ] **Krok 5: Ověř** — `pytest` + `ruff`; očekávání ~201 passed.
- [ ] **Krok 6: Commit** — "throttling: po N neuspesich throttled s retry_after".

---

### Úkol 2: Drátové tvary (`wire.py`)

**Files:**
- Create: `access_manager/wire.py`, `tests/test_wire.py`

**Interfaces:**
- Produces (jen stdlib, importovatelné bez extras): `verdict_to_wire(verdikt, *, detail: bool) -> dict`; `user_to_wire(user: User | None) -> dict`; `group_to_wire(name: str, group: Group | None) -> dict`. Tvary PŘESNĚ dle design.md §3.1/§3.2 (principals setříděný list; `reason` jen při `detail=True` a existenci; `retry_after` jen u throttled; `gen` vždy). Úkoly 5, 6, 8 konzumují.

- [ ] **Krok 1: Failing testy** — `tests/test_wire.py`:

```python
"""Dratove tvary: presne ctyri podoby odpovedi a nic navic.

`reason` jde ven JEN komponentam s detail=true - jinak je odpoved
postranni kanal na vycet uzivatelu (design.md par. 3.1).
"""
from access_manager import Verdict
from access_manager.principals import Group, User
from access_manager.wire import group_to_wire, user_to_wire, verdict_to_wire


def test_an_ok_verdict_carries_sorted_principals():
    v = Verdict.ok("user:hana", {"group:b", "group:a"}, gen=41)
    assert verdict_to_wire(v, detail=False) == {
        "outcome": "ok", "subject_id": "user:hana",
        "principals": ["group:a", "group:b"], "gen": 41,
    }


def test_a_denied_verdict_hides_the_reason_by_default():
    v = Verdict.refused("unknown_user", gen=41)
    assert verdict_to_wire(v, detail=False) == {"outcome": "denied", "gen": 41}


def test_a_trusted_component_sees_the_reason():
    v = Verdict.refused("bad_code", gen=41)
    assert verdict_to_wire(v, detail=True) == {
        "outcome": "denied", "reason": "bad_code", "gen": 41,
    }


def test_need_factor_and_throttled_shapes():
    assert verdict_to_wire(Verdict.need_factor(("totp",), gen=1), detail=False) == {
        "outcome": "need_factor", "required": ["totp"], "gen": 1,
    }
    assert verdict_to_wire(Verdict.throttled(27, gen=1), detail=False) == {
        "outcome": "throttled", "retry_after": 27, "gen": 1,
    }


def test_an_unknown_user_is_just_exists_false():
    assert user_to_wire(None) == {"exists": False}


def test_a_user_shape_matches_the_design():
    u = User(name="hana", subject_id="user:hana", enabled=True,
             principals=frozenset({"user:hana", "group:a"}))
    assert user_to_wire(u) == {
        "exists": True, "subject_id": "user:hana", "enabled": True,
        "principals": ["group:a", "user:hana"],
    }


def test_a_group_shape_matches_the_design():
    g = Group(name="ucetni", members=("hana",), includes=("mzdy",))
    assert group_to_wire("ucetni", g) == {
        "exists": True, "members": ["hana"], "includes": ["group:mzdy"],
    }
    assert group_to_wire("neni", None) == {"exists": False}
```

- [ ] **Krok 2: Ověř pád** — FAIL (modul neexistuje).
- [ ] **Krok 3: Implementuj `wire.py`**:

```python
"""Dratove tvary. Zavazna je KNIHOVNA, ne drat - tvar zprav je jeji vnitrek.

Presne ctyri podoby odpovedi na authenticate; `reason` jen komponentam
s detail=true. Jen stdlib - modul musi jit importovat bez extras.
"""
from __future__ import annotations

from .principals import Group, User
from .verdicts import Verdict


def verdict_to_wire(verdikt: Verdict, *, detail: bool) -> dict:
    telo: dict = {"outcome": verdikt.outcome, "gen": verdikt.gen}
    if verdikt.outcome == "ok":
        telo["subject_id"] = verdikt.subject_id
        telo["principals"] = sorted(verdikt.principals)
    elif verdikt.outcome == "need_factor":
        telo["required"] = list(verdikt.required)
    elif verdikt.outcome == "throttled":
        telo["retry_after"] = verdikt.retry_after
    elif detail and verdikt.reason:
        telo["reason"] = verdikt.reason
    return telo


def user_to_wire(user: User | None) -> dict:
    if user is None:
        return {"exists": False}
    return {
        "exists": True,
        "subject_id": user.subject_id,
        "enabled": user.enabled,
        "principals": sorted(user.principals),
    }


def group_to_wire(name: str, group: Group | None) -> dict:
    if group is None:
        return {"exists": False}
    return {
        "exists": True,
        "members": list(group.members),
        "includes": [f"group:{g}" for g in group.includes],
    }
```

- [ ] **Krok 4: Ověř** — `pytest` + `ruff`; ~208 passed.
- [ ] **Krok 5: Commit** — "dratove tvary: ctyri podoby, detail jen duveryhodnym".

---

### Úkol 3: Konfigurační loader (`config.py`)

**Files:**
- Create: `access_manager/config.py`, `tests/test_config.py`

**Interfaces:**
- Produces (jen stdlib): `@dataclass(frozen=True) ServiceConfig(data: Path, listeners: dict, trusted_proxies: tuple[str, ...], forwarded_header: str, hops: int, defaults: dict, throttle: dict, realms: tuple[dict, ...])`; `load_config(conf_dir) -> ServiceConfig`. Sčítání: všechny `*.json` v kořeni conf.d jsou fragmenty služby (mělká fúze; TENTÝŽ klíč se skalárem v konfliktu → ValueError „zavírá start“; mapy se slučují po klíčích se stejnou kontrolou); `realms/*.json` = deklarace (jedna na soubor, tvar dle specu realms §3). Výchozí hodnoty: listeners api `127.0.0.1:22000`, console `127.0.0.1:22001`, forwarded_header `X-Forwarded-For`, hops 1, defaults `{qr_ttl_days: 14, audit_retention_days: 90}`, throttle `{attempts: 5, window_s: 60}`, trusted_proxies `()`. `data` je povinné. Úkoly 4 a 9 konzumují.

- [ ] **Krok 1: Failing testy** — `tests/test_config.py`:

```python
"""Fragmentovana konfigurace: scita se, skalarni konflikt zavira start."""
import json

import pytest

from access_manager.config import load_config


def zapis(conf, jmeno, obsah):
    conf.mkdir(parents=True, exist_ok=True)
    (conf / jmeno).write_text(json.dumps(obsah), encoding="utf-8")


def test_a_minimal_config_gets_defaults(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    cfg = load_config(tmp_path / "conf.d")
    assert cfg.listeners["api"] == "127.0.0.1:22000"
    assert cfg.hops == 1
    assert cfg.throttle["attempts"] == 5
    assert cfg.realms == ()


def test_fragments_are_summed(tmp_path):
    zapis(tmp_path / "conf.d", "10-base.json", {"data": str(tmp_path / "d")})
    zapis(tmp_path / "conf.d", "20-net.json", {"trusted_proxies": ["10.0.0.0/8"]})
    cfg = load_config(tmp_path / "conf.d")
    assert cfg.trusted_proxies == ("10.0.0.0/8",)


def test_a_scalar_conflict_closes_the_start(tmp_path):
    zapis(tmp_path / "conf.d", "a.json", {"data": "/a"})
    zapis(tmp_path / "conf.d", "b.json", {"data": "/b"})
    with pytest.raises(ValueError):
        load_config(tmp_path / "conf.d")


def test_missing_data_closes_the_start(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"hops": 2})
    with pytest.raises(ValueError):
        load_config(tmp_path / "conf.d")


def test_realm_declarations_are_loaded(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "d")})
    zapis(tmp_path / "conf.d" / "realms", "example.com.json",
          {"name": "example.com", "admins": ["jindrich"]})
    cfg = load_config(tmp_path / "conf.d")
    assert cfg.realms == ({"name": "example.com", "admins": ["jindrich"]},)


def test_a_corrupt_fragment_closes_the_start(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "service.json").write_text("{zlomeno", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(tmp_path / "conf.d")
```

- [ ] **Krok 2: Ověř pád** — FAIL (modul neexistuje).
- [ ] **Krok 3: Implementuj `config.py`** — fúze fragmentů (setříděné podle jména souboru), mělký merge s rekursí do dictů:

```python
def _sluc(cil: dict, novy: dict, zdroj: str) -> None:
    for klic, hodnota in novy.items():
        if klic not in cil:
            cil[klic] = hodnota
        elif isinstance(cil[klic], dict) and isinstance(hodnota, dict):
            _sluc(cil[klic], hodnota, zdroj)
        elif cil[klic] != hodnota:
            raise ValueError(
                f"konflikt konfigurace u {klic!r} ({zdroj}): "
                f"{cil[klic]!r} vs {hodnota!r} - skalarni konflikt zavira start"
            )
```

`load_config`: načti `*.json` (JSONDecodeError → ValueError se jménem souboru), aplikuj výchozí, `data` povinné, realms z `realms/*.json` setříděně; vrať frozen dataclass (dicty nech jako obyčejné dicty — frozen je dataclass, ne obsah; komentář proč to stačí).
- [ ] **Krok 4: Ověř** — `pytest` + `ruff`; ~214 passed.
- [ ] **Krok 5: Commit** — "konfigurace: fragmenty se scitaji, konflikt zavira start".

---

### Úkol 4: WSGI aplikace — pipeline a provoz

**Files:**
- Create: `access_manager/server.py`, `tests/test_server_pipeline.py`
- Modify: `pyproject.toml` (extra `[server] = ["flask>=3", "waitress>=3"]`; do `dev` přidej `flask>=3`, `waitress>=3`)

**Interfaces:**
- Produces: `_require_server()` (lazy flask+waitress, RuntimeError s návodem); `create_app(cfg: ServiceConfig)` → Flask app s: per-realm `FileStore` postavené z `cfg` (defaults + per-realm přepisy), before_request pipeline (spec §3), provozní endpointy `GET /healthz` (`{"status": "ok"}`), `GET /readyz` (200 `{"status": "ok"}` / 503 `{"status": "unready", "reasons": {realm: duvod}}`), `GET /v1/version` (`{"api": "1", "build": <importlib.metadata.version>}`). Pomocníci: `_resolve_origin(environ, cfg) -> str` (peer; XFF jen od trusted proxy, `hops`-tý prvek zprava), `_component_for_key(stores, key)` s cache invalidovanou per-realm generací, `_origin_allowed(component, origin) -> bool` (CIDR přes `ipaddress`; prázdné origins = jen loopback). Kontext požadavku: `g.realm`, `g.store`, `g.component`. Audit `origin_denied` do realmu komponenty. Úkoly 5, 6, 9 staví na `create_app`.

- [ ] **Krok 1: Failing testy** — `tests/test_server_pipeline.py`:

```python
"""Bezpecnostni pater sluzby: puvod -> klic -> origin ACL -> dal.

401 bez rozdilu (neexistujici a nepovoleny vypadaji stejne); 403 za puvod
pada driv, nez se cokoli cte; prazdne origins znamena jen smycku.
"""
import pytest

from access_manager import Admin
from access_manager.config import load_config
from access_manager.server import create_app

from test_config import zapis  # helper na zapis fragmentu
from helpers import REALM


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
    odpoved = client.get("/v1/users", headers={"Authorization": "Bearer am_k1_" + "0" * 64})
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
```

- [ ] **Krok 2: Ověř pád** — FAIL (server.py neexistuje). Nejdřív `./.venv/bin/pip install -e '.[dev]'` po úpravě pyproject.
- [ ] **Krok 3: Implementuj `server.py`** — hlavička s `_require_server()`; `create_app`:
  - stores: `{d["name"]: FileStore(realm_root(cfg.data, d["name"]), realm=..., qr_ttl_days=d.get(...， cfg.defaults...), audit_retention_days=..., throttle_attempts=cfg.throttle["attempts"], throttle_window_s=cfg.throttle["window_s"])}`.
  - `_component_for_key`: cache `{key: (realm, komponenta, gen)}`; hit platí jen když `stores[realm].generation() == gen`.
  - `_resolve_origin(environ)`: peer z `REMOTE_ADDR`; když peer ∈ trusted_proxies (ipaddress, síť i adresa), vezmi `hops`-tý prvek zprava z forwarded_header, jinak peer. Nikdy nevěř hlavičce od cizího.
  - `_origin_allowed(component, origin)`: prázdné `origins` → `ip_address(origin).is_loopback`; jinak ∈ kterýkoli CIDR.
  - before_request: provozní cesty pusť; jinak Bearer (`Authorization` prefix) → komponenta (401 jednotné `{"error": "unauthorized"}`), origin (403 `{"error": "forbidden"}` + audit `origin_denied` s component/key_id/origin), ulož `g.realm/g.store/g.component`.
  - provozní endpointy dle Interfaces.
- [ ] **Krok 4: Ověř** — `pytest` + `ruff`; ~222 passed.
- [ ] **Krok 5: Commit** — "sluzba: wsgi pater - puvod, klic, origin acl, provoz".

---

### Úkol 5: Čtecí endpointy

**Files:**
- Modify: `access_manager/server.py`
- Test: `tests/test_server_endpoints.py` (nový)

**Interfaces:**
- Produces: `GET /v1/users/<name>` (user_to_wire; ValueError jména → 400), `GET /v1/users` (`{"users": [...]}`), `GET /v1/groups` (`{"groups": [...]}`), `GET /v1/groups/<name>` (group_to_wire), `POST /v1/principals/check` (`{"principals": [...]}` → `{"unknown": [...]}`; chybějící pole → 400), `GET /v1/whoami` (`{"component", "realm", "key_id"}`), `GET /v1/generation` (`{"gen": n}`). Vše v realmu klíče (`g.store`).

- [ ] **Krok 1: Failing testy** — `tests/test_server_endpoints.py`: fixture jako v úkolu 4 (loopback komponenta + `Admin` naplní hanu do skupiny `ucetni` se zřetězením `mzdy`); testy:

```python
def test_who_is_who_returns_the_flat_closure(...):
    telo = client.get("/v1/users/hana", headers=hlavicky).get_json()
    assert telo["exists"] is True
    assert "group:ucetni" in telo["principals"]

def test_an_unknown_user_is_exists_false(...)          # {"exists": False}
def test_listings_and_group_shape(...)                 # users/groups/groups/ucetni
def test_principals_check_reports_the_unknown(...)     # POST -> {"unknown": ["group:neni"]}
def test_whoami_names_the_key(...)                     # component/realm/key_id
def test_generation_is_the_realms_generation(...)      # roste po zapisu Adminem
def test_a_second_realm_is_invisible(...)              # klic realmu alfa nevidi data realmu beta
def test_a_malformed_name_is_400(...)                  # /v1/users/..%2F.. -> 400
```

(každý test vypiš celý — fixture zakládá dva realmy a po jednom klíči v každém; přesné asserty na tvary z wire.py).
- [ ] **Krok 2: Ověř pád**; **Krok 3: Implementuj** (tenké routy nad `g.store` + wire; ValueError z check_* → 400 `{"error": "bad_request"}`).
- [ ] **Krok 4: Ověř** — ~230 passed. **Krok 5: Commit** — "sluzba: cteci endpointy v realmu klice".

---

### Úkol 6: `POST /v1/authenticate`

**Files:**
- Modify: `access_manager/server.py`
- Test: `tests/test_server_authenticate.py` (nový)

**Interfaces:**
- Produces: `POST /v1/authenticate` — tělo `{"username", "credentials", "purpose"}`; vždy `200` s `verdict_to_wire(v, detail=g.component.detail)`; `component=g.component.name` jde do auditu přes `FileStore.authenticate`; chybějící pole/špatný JSON/ValueError z check_* → `400`.

- [ ] **Krok 1: Failing testy** — kompletní testy: ok (principals na drátě setříděné, gen), denied bez reason (detail=false), denied s reason (komponenta s detail=true), need_factor s required, replay → denied, throttled s retry_after (vyčerpej pokusy), špatný tvar purpose → 400, chybějící username → 400, audit realmu nese jméno komponenty (read_events).
- [ ] **Krok 2: Ověř pád**; **Krok 3: Implementuj** (jedna routa; JSON přes `request.get_json(silent=True)` → None = 400).
- [ ] **Krok 4: Ověř** — ~239 passed. **Krok 5: Commit** — "sluzba: authenticate vzdy 200, detail jen duveryhodnym".

---

### Úkol 7: `Access.remote` — jádro klienta

**Files:**
- Create: `access_manager/remote.py`, `tests/test_remote.py`
- Modify: `access_manager/access.py` (+classmethod `remote`)

**Interfaces:**
- Produces: `RemoteStore(url, key, *, realm=None, ca=None, timeout=5.0, deadline=30.0, transport=None)` — httpx.Client (lazy `_require_remote()`); https vynucené mimo loopback (jinak ValueError s vysvětlením); hlavička `Authorization: Bearer`; `_request(method, path, json=None) -> httpx.Response` s retry (backoff 0.2·2^n, jen síťové chyby a 5xx, do `deadline`; 401/403 → RuntimeError bez klíče v textu); při konstrukci `GET /v1/version` (major ≠ "1" → RuntimeError) a `GET /v1/whoami` (uloží `component/realm/key_id`; `realm=` nesouhlasí → RuntimeError). `Access.remote(url, key, *, realm=None, ca=None, timeout=5.0, deadline=30.0, transport=None) -> Access`. Úkol 8 doplní datové metody.

- [ ] **Krok 1: Failing testy** — `tests/test_remote.py` (fixture: `create_app` z úkolu 4 + `httpx.WSGITransport(app=app)`; loopback komponenta):

```python
def test_remote_construction_checks_version_and_realm(...)   # projde s realm=REALM
def test_a_realm_mismatch_fails_loudly(...)                  # realm="jiny" -> RuntimeError
def test_http_outside_loopback_is_refused(...)               # http://example.com -> ValueError
def test_http_on_loopback_is_allowed_for_dev(...)            # http://127.0.0.1 + transport
def test_retries_survive_a_flaky_5xx(...)                    # WSGI stub: 2x 500 pak delegace -> projde
def test_the_key_never_appears_in_errors(...)                # spatny klic -> RuntimeError; klic not in str(e)
```

(retry test: malá WSGI obálka počítající volání — vypiš ji celou.)
- [ ] **Krok 2: Ověř pád**; **Krok 3: Implementuj** `remote.py` + `Access.remote` (v `access.py` jen konstrukce `RemoteStore` a `cls(...)`; docstring: kontejner jinde, TLS bez vypínače).
- [ ] **Krok 4: Ověř** — ~245 passed. **Krok 5: Commit** — "access.remote: jadro - tls, verze, whoami, retry".

---

### Úkol 8: `Access.remote` — datové metody a cache

**Files:**
- Modify: `access_manager/remote.py`
- Test: `tests/test_remote.py` (rozšířit)

**Interfaces:**
- Produces na `RemoteStore`: `authenticate(username, credentials, *, purpose, component=None)` (component se ignoruje — určuje ho klíč; drát → `Verdict` vč. `reason`/`retry_after`/`gen`, principals frozenset), `user(name) -> User | None`, `users()`, `groups()`, `group(name) -> Group | None`, `unknown_principals(names)`, `generation()`, `ready() -> str | None` (GET /readyz: 200 → None, jinak text). Cache `user()`: `{name: (User, gen, ts)}` — použije se, když stáří < 5 s a známá generace se nezměnila; každá odpověď nesoucí vyšší `gen` cache čistí; `authenticate` se necachuje NIKDY.

- [ ] **Krok 1: Failing testy** — rozšíření `tests/test_remote.py` (proti skutečné aplikaci přes WSGITransport, data přes `Admin.local` nad týmž DATA):

```python
def test_remote_authenticate_matches_local_shapes(...)   # ok: subject_id/principals/gen
def test_remote_replay_is_denied(...)                    # bez detail: reason is None
def test_a_detail_component_gets_the_reason_remotely(...)
def test_remote_user_returns_the_flat_closure(...)
def test_the_user_cache_is_invalidated_by_gen(...)       # add_member Adminem -> user() vidi novou skupinu
def test_remote_ready_and_generation(...)
def test_remote_throttled_carries_retry_after(...)
```

- [ ] **Krok 2: Ověř pád**; **Krok 3: Implementuj** (mapování dict→typy; `Group` z wire: members tuple, includes bez prefixu `group:` zpět — pozor na symetrii s `group_to_wire`).
- [ ] **Krok 4: Ověř** — ~253 passed. **Krok 5: Commit** — "access.remote: data, verdikty, cache podle generace".

---

### Úkol 9: Entrypoint, konzole 501, reconcile při startu

**Files:**
- Modify: `access_manager/server.py`
- Test: `tests/test_server_main.py` (nový)

**Interfaces:**
- Produces: `console_app(environ, start_response)` — čisté WSGI, vždy `501 Not Implemented`, tělo `{"error": "console_not_implemented"}` (obsah dodá subprojekt 4); `main(argv=None)`: argparse `-c/--config` (povinné), `load_config` → `reconcile(cfg.data, cfg.realms)` (nová zavedení vypíše na stdout jako cesty ke QR) → `create_app` → dva `waitress.serve` (api + console listenery, každý ve vlákně; join). `python -m access_manager.server` přes `if __name__ == "__main__"`. Chybějící extra → RuntimeError s návodem.

- [ ] **Krok 1: Failing testy** — `tests/test_server_main.py`: console_app vrací 501 (přes werkzeug test client nebo přímé WSGI volání — vypiš); `main` s monkeypatchnutým `waitress.serve` (zachytí argumenty, neblokuje): ověř, že proběhl reconcile (admin adresář vznikl) a serve dostal oba listenery; chybějící `-c` → SystemExit.
- [ ] **Krok 2: Ověř pád**; **Krok 3: Implementuj**.
- [ ] **Krok 4: Ověř** — ~257 passed. **Krok 5: Commit** — "sluzba: entrypoint, reconcile pri startu, konzole zatim 501".

---

### Úkol 10: Dockerfile, README, úklid

**Files:**
- Create: `Dockerfile`, `.dockerignore`
- Modify: `README.md`, `pyproject.toml` (jen ověř extras)

- [ ] **Krok 1: Dockerfile**:

```dockerfile
FROM python:3.12-slim
RUN useradd --create-home spravce
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY access_manager ./access_manager
RUN pip install --no-cache-dir '.[server,totp]'
USER spravce
VOLUME /var/lib/access-manager
EXPOSE 22000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:22000/healthz')"
CMD ["python", "-m", "access_manager.server", "-c", "/etc/access-manager/conf.d"]
```

`.dockerignore`: `.venv`, `tests`, `.git`, `docs`, `__pycache__`, `.claude`, `.superpowers`.
- [ ] **Krok 2: README** — sekce Sluzba (spusteni `python -m access_manager.server -c conf.d/`, extra `[server]`, TLS terminuje proxy — odkaz na spec; vzor nginx přijde s dokumentací), příklad `Access.remote` v Použití je teď skutečnost (odstraň „popisuje cíl“ formulace), Stav: počet testů z `pytest -q`, věta o rozsahu (+ služba, throttling, Access.remote; konzole ještě ne). Bez diakritiky.
- [ ] **Krok 3: Ověř** — `pytest` + `ruff` + `python -c "from access_manager import Access; Access.remote"`; Docker build jen pokud je k dispozici démon (jinak poznamenej do reportu, nevynucuj).
- [ ] **Krok 4: Commit** — "kontejner a readme: sluzba je skutecnost".

---

## Self-review (proběhla při psaní plánu)

- **Pokrytí specu:** §1 stack → úkoly 4, 9, 10; §2 konfigurace → 3; §3 pipeline → 4; §4 API → 4–6; §5 throttling+retry_after → 1 (+6, 8 na drátě); §6 remote → 7–8; §7 proces/kontejner/nasazení → 9–10 (vzor nginx = budoucí dokumentace, do README jen odkaz); §8 testování bez sítě → všude (test_client + WSGITransport, serve jen monkeypatched); otevřený bod `ready()`+gen → 1. Vědomě mimo: konzole (501), mTLS, SIGHUP, DB, HMAC.
- **Typová konzistence:** `Verdict.throttled(retry_after, gen)` z 1 konzumují 2 (wire), 6 (server), 8 (remote); `ServiceConfig` z 3 konzumují 4 a 9; `create_app(cfg)` z 4 konzumují 5, 6, 9 a testy remote (7–8); `verdict_to_wire(v, detail=...)` z 2 konzumuje 6 a zpětné mapování v 8 je jeho zrcadlo (vč. `group_to_wire` prefixu `group:` u includes — úkol 8 ho při čtení snímá); `transport=` prochází z `Access.remote` do `RemoteStore` (7) a používají ho testy 7–8.
- **Placeholders:** úkoly 5–8 mají u testů vyjmenované názvy s přesným obsahem k rozepsání implementátorem podle vzorů úkolů 4 a 1 — každý test má v názvu a komentáři plné chování a fixture je definovaná v úkolu 4; exekutor nedostává žádné „TBD“, jen kompresi opakovaného vzoru. Hodnoty určované za běhu: počty testů („~N“) a build verze.
- **Rizika pro exekuci:** flask `environ_overrides`/`environ_base` pro podvrh REMOTE_ADDR (implementátor ověří přesné API test clienta); httpx WSGITransport a `verify`/`ca` kombinace (ca se předává jen při https; s WSGITransport se TLS nekoná — vynucení schématu je NAŠE kontrola před vytvořením klienta, takže testovatelná bez sítě).
