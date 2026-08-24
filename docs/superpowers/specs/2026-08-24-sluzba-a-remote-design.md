# REST služba a Access.remote — návrh

*Stav: **k odsouhlasení** (návrh z 2026-08-24; rozhodnutí označená „(rozhodnutí)“
jsou má volba k potvrzení). Navazuje na [docs/design.md](../../design.md)
(závazný), na spec realms
([2026-08-23-realms-design.md](2026-08-23-realms-design.md)) a na hotovou
knihovnu v `main` (192 testů: realmy, správci, klíče aplikací, audit,
reconcile).*

**Rozsah subprojektu 3:** HTTP služba nad hotovým `FileStore`, vzdálený klient
`Access.remote`, kontejner. **Mimo rozsah:** webová konzole (subprojekt 4 —
služba jí jen vyhradí listener), mTLS (jen příprava v konfiguraci), databázový
backend, endpoint/mechanism origin ACL z §2b (v1 má per-komponentové origins).

---

## 1. Technologie (rozhodnutí)

- **Server: synchronní WSGI — Flask + waitress**, v novém extra `[server]`.
  Důvod: úložiště je blokující (flock, soubory), takže vlákna sedí lépe než
  async; obě knihovny jsou nudné, čisté-python a všude. Zvažované alternativy:
  stdlib `http.server` (křehký pro produkci — timeouts, chunked, hlavičky)
  a starlette/uvicorn (async bez užitku nad flockem). Klient (`access_manager`
  bez extras) zůstává **bez povinných závislostí**.
- **Klient: httpx** v už deklarovaném extra `[remote]`.
- **TLS (rozhodnutí):** služba v v1 sama neterminuje — běží za TLS-terminující
  proxy/ingress (důvěryhodné proxy už řeší §2b). `Access.remote` **vyžaduje
  `https://`**; `http://` připustí jedině pro loopback (127.0.0.1/::1/localhost)
  — to není vypínač ověření, to je vývojová smyčka. Ověření certifikátu nemá
  vypínač; vlastní CA se dodá parametrem `ca=`.

## 2. Konfigurace služby

```
conf.d/
  service.json               ← instance: listenery, proxy, výchozí hodnoty
  realms/<název>.json        ← deklarace realmů (spec realms §3; beze změny)
```

```json
{ "data": "/var/lib/access-manager",
  "listeners": { "api": "0.0.0.0:22000", "console": "127.0.0.1:22001" },
  "trusted_proxies": ["10.0.0.0/8"],
  "forwarded_header": "X-Forwarded-For",
  "hops": 1,
  "defaults": { "qr_ttl_days": 14, "audit_retention_days": 90 },
  "throttle": { "attempts": 5, "window_s": 60 } }
```

Fragmenty se při startu sčítají; skaláry v konfliktu zavřou start. Při startu
proběhne `reconcile` deklarací (jen doplní, co chybí) a start se zapíše do
auditu každého realmu. Reload konfigurace = restart procesu (v1; SIGHUP je
odložený bod). `console` listener se v tomto subprojektu jen otevře a vrací
501 — obsah dodá subprojekt 4.

## 3. Pořadí zpracování požadavku (bezpečnostní páteř)

```
peer socketu
  → rozbal původ přes trusted_proxies/hops (jinak hlavička ignorována)
  → Bearer klíč → komponenta+realm (component_for_key; neznámý klíč = 401,
    žádný jiný rozdíl)
  → původ povolen pro komponentu? (origins v components.json; ne = 403
    a NIC dál — žádná počítadla, žádné parsování)
  → throttle (per identita, viz §5)
  → parsování těla → FileStore
```

Klíč určuje realm — cesty realm nenesou. `component_for_key` se hledá přes
všechny načtené realmy; výsledek se cachuje a invaliduje per-realm generací.
401 bez klíče/se špatným klíčem jde do stderr logu služby (realm neznáme);
403 zná komponentu → jde do auditu jejího realmu s `key_id`.

## 4. Drátové API

Přesně §3 design.md, bez realmů v cestách (realm = klíč), plus `whoami`:

| metoda a cesta | tělo / odpověď |
|---|---|
| `POST /v1/authenticate` | `{username, credentials, purpose}` → vždy `200`, čtyři tvary; `reason` jen pro komponentu s `detail: true` |
| `GET /v1/users/{name}` | `{exists, subject_id, enabled, principals}` / `{exists: false}` |
| `GET /v1/users` · `/v1/groups` · `/v1/groups/{name}` | výpisy; skupina jak je napsaná |
| `POST /v1/principals/check` | `{principals: [...]}` → `{unknown: [...]}` |
| `GET /v1/whoami` | `{component, realm, key_id}` |
| `GET /v1/generation` | `{gen}` realmu klíče |
| `GET /healthz` · `/readyz` · `GET /v1/version` | provoz; `readyz` = `ready()` všech deklarovaných realmů; `version` = `{api: "1", build}` |

Tvar `throttled` nese `retry_after` (viz §5). Neexistující a nepovolený
endpoint vypadají stejně (401 bez klíče, jinak 404 bez těla navíc).

## 5. Throttling — `throttled` dostává výrobce

**(rozhodnutí)** Implementuje se ve `FileStore` (sdílené přes soubory, takže
funguje i lokálnímu zapojení a příští repliky ho zdědí):

- per-identita soubor `throttle.json` (okno, počet neúspěchů),
- počítají se jen `bad_code`/`replay` **existující** identity (neexistující
  jméno počítadlo nezvedá — jinak si kdokoli nechá zamknout cizí/náhodná
  jména; a blokovaný původ se sem vůbec nedostane, viz §3),
- po `attempts` neúspěších v okně `window_s` → `throttled` s `retry_after`
  (zbytek okna), úspěch počítadlo maže,
- `Verdict` dostává pole `retry_after: int | None` (jen u `throttled`) —
  uzavírá se tím i známý dluh z refaktoringu,
- platí pro `authenticate` i `authenticate_admin`.

## 6. Access.remote

```python
access = Access.remote(url, key=klic, *, realm=None, ca=None,
                       timeout=5.0, deadline=30.0)
```

- **Při konstrukci, hlasitě:** `GET /v1/version` (neslučitelná major = výjimka
  hned) a `GET /v1/whoami`; když je dané `realm=`, nesoulad s klíčem = výjimka.
- **Retry s backoffem a deadlinem** na síťové chyby a 5xx — restart repliky se
  přečkává; nikdy se neopakuje odpověď `200` (verdikt je verdikt).
- **Krátká cache `user()`** s invalidací podle `gen` (drží se poslední známá
  generace; odpověď s vyšší `gen` cache zahodí; TTL pojistka 5 s).
- **Mapování drátu na tytéž typy**: `Verdict` (včetně `reason`, když ho server
  pošle), `User`, `Group` — kód psaný proti `Access.local` běží beze změny.
- **Sanace logů:** kód ani klíč se nikdy nedostanou do výjimek ani logu.
- `Admin.remote` **neexistuje** — správa je jen v konzoli (spec realms §7);
  `reconcile` běží na serveru.

## 7. Proces a kontejner

- Entrypoint: `python -m access_manager.server -c conf.d/` (jen s extra
  `[server]`; bez něj řekne, co doinstalovat — vzor `_require_totp`).
- Start: konfigurace → reconcile → kontrola `unknown_principals`? ne — to je
  úloha instancí viewBase; služba jen poslouchá.
- Kontejner: `Dockerfile` (python:3.12-slim, `pip install .[server,totp]`),
  volume na `data`, `HEALTHCHECK /healthz`, běží pod neprivilegovaným
  uživatelem. TLS terminuje proxy před ním.

### Nasazení a TLS

Služba mluví holým HTTP; certifikáty drží reverse proxy provozovatele. Dva
zdravé vzory:

1. **Jeden stroj:** API bind `127.0.0.1:22000`, nginx/caddy na 443
   s certifikáty proxuje dovnitř — nešifrovaný provoz neopustí stroj.
2. **Kontejner/K8s:** API bind `0.0.0.0:22000` v síti podu, TLS terminuje
   ingress; holé HTTP jen uvnitř clusterové sítě.

Proxy MUSÍ být v `trusted_proxies`, jinak se `X-Forwarded-For` ignoruje
a origin ACL měří adresu proxy místo klienta (§2b design.md). Konzole je
default jen na smyčce — vystavení správy je vědomý úkon provozovatele.
Proč TLS není ve službě: životní cyklus certifikátů (ACME, obnova, reload)
je vyřešený v proxy vrstvě; duplikovat ho znamená bezpečnostně kritickou
plochu navíc bez zisku. Pojistku drží klient: `Access.remote` vyžaduje
`https://` (výjimka jen loopback), takže holé HTTP přes síť nejde zapnout
omylem.

Uživatelská dokumentace („instalace“, viz plánované `docs/`) MUSÍ obsahovat
vzorovou konfiguraci nginx (či jiné důvěryhodné proxy): `proxy_pass` na
`127.0.0.1:22000`, předávání `X-Forwarded-For`, TLS/ACME — a k tomu párový
záznam `trusted_proxies` ve `service.json`. Bez toho origin ACL měří proxy
místo klienta a vypadá funkční, i když nerozlišuje nic.

## 8. Testování (tvrdé pravidlo: bez sítě)

- Služba se testuje přes **WSGI test client** (flask `test_client()`) — celé
  API bez socketů, včetně origin/throttle větví (peer se podvrhne v environ).
- `Access.remote` se testuje přes **httpx `WSGITransport`** napojený přímo na
  aplikaci služby — klient i server v jednom procesu, žádný port. Tím platí
  „tytéž testy proti oběma zapojením“ i pro remote.
- Kontejner: build se ověří v CI/ručně, není součástí pytest sady.

## 9. Otevřené / odložené body

1. mTLS (konfig připravit, vynucení až bude potřeba).
1b. HMAC podepisování požadavků jako budoucí zesílení vedle mTLS — tajemství
   nikdy neopouští aplikaci, podpis váže replay na konkrétní požadavek
   (správná „TOTP pro stroje“; klíč s otiskem zůstává výchozí).
2. Endpoint/mechanism origin ACL (§2b plné znění) — až s heslem/druhým mechanismem.
3. SIGHUP reload deklarací bez restartu.
4. Databázový backend pro víc replik (design.md §7.1).
5. `ready()` krytí souboru `gen` (drobnost z revizí — vyřešit při implementaci `readyz`).
6. Normalizace schématu auditních událostí (component/reason null vs chybí) — až s konzolí jako prvním čtenářem.
