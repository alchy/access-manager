# REST API

*Drátové rozhraní služby. Závazná je knihovna (`Access`), ne drát — tvar
zpráv je její vnitřek; tady je popsaný pro provozovatele a ladění.*

## Autentizace požadavků a pořadí kontrol

Každý požadavek (mimo provozní cesty) nese klíč komponenty:

```http
Authorization: Bearer am_k1_9f3c…
```

Klíč vydává správce realmu v registraci aplikace; **klíč určuje realm** —
cesty proto realm nenesou a aplikace o realmech nemusí vědět. Server drží
jen sha256 otisk klíče.

Kontroly běží v neporušitelném pořadí:

1. **Původ** — pravdu drží peer socketu; `X-Forwarded-For` se čte jen od
   adres v `trusted_proxies` (`hops`-tý prvek zprava).
2. **Klíč** → komponenta+realm. Chybějící i špatný klíč = **`401`
   a žádný jiný rozdíl** (do stderr logu služby jde původ a cesta).
3. **Origin ACL** — původ mimo `origins` komponenty = **`403` a nic dál**
   (žádná počítadla, žádné parsování); jde do auditu realmu s `key_id`.
   Prázdné `origins` = jen smyčka.
4. Omezování pokusů, parsování, úložiště.

## Endpointy

| metoda a cesta | co vrací |
|---|---|
| `POST /v1/authenticate` | vždy `200`, jeden ze čtyř tvarů (níže) |
| `GET /v1/users/{name}` | `{"exists": true, "subject_id", "enabled", "principals": [plochý uzávěr]}` / `{"exists": false}` |
| `GET /v1/users` · `/v1/groups` | `{"users": [...]}` · `{"groups": [...]}` |
| `GET /v1/groups/{name}` | `{"exists": true, "members": [...], "includes": ["group:mzdy"]}` |
| `POST /v1/principals/check` | `{"principals": [...]}` → `{"unknown": [...]}` |
| `GET /v1/whoami` | `{"component", "realm", "key_id"}` — čí je tento klíč |
| `GET /v1/generation` | `{"gen": n}` realmu klíče |
| `GET /healthz` · `/readyz` · `/v1/version` | provoz (bez klíče); readyz `503` s důvody per realm |

Veřejné API **nemá jediný zapisovací endpoint** — veškerá správa patří
konzoli (zatím 501) a knihovně na serveru. Neznámá cesta pod `/v1/` je
`404` (s platným klíčem), chybný tvar požadavku `400 {"error": "bad_request"}`.

## Čtyři tvary odpovědi na `authenticate`

```http
POST /v1/authenticate
{ "username": "hana", "credentials": { "totp": "123456" }, "purpose": "login" }

200 { "outcome": "ok", "subject_id": "user:hana",
      "principals": ["group:public", "group:ucetni", "group:users", "user:hana"],
      "gen": 41 }
200 { "outcome": "denied", "gen": 41 }
200 { "outcome": "need_factor", "required": ["totp"], "gen": 41 }
200 { "outcome": "throttled", "retry_after": 27, "gen": 41 }
```

To jsou **všechny** tvary; odpověď je vždy `200`, aby stavový kód nebyl
postranní kanál. `principals` je setříděné (jinak nejde porovnat ani
cachovat), `gen` je přibalená generace pro invalidaci cache. Komponenta
s `detail: true` v registraci dostane u `denied` navíc
`"reason": "bad_code" | "replay" | "unknown_user" | ...` — výchozí stav je
bez důvodu, protože kdo rozliší `unknown_user` od `bad_code`, umí si vypsat
uživatele. Pověření je mapa `mechanismus → hodnota` (dnes jediný
mechanismus: `totp`); `purpose` má tvar `login` nebo `unlock:<cíl>`.

## Model důvěry

| směr | mechanismus |
|---|---|
| aplikace → služba | klíč komponenty (otisk na serveru) + původ (CIDR) jako druhý nezávislý faktor; kdo chce víc než filtr adres, chce mTLS |
| služba → aplikace | TLS terminovaná proxy před službou; klient vyžaduje `https://` a ověření certifikátu nemá vypínač (vlastní CA přes `ca=`); kontrola verze a `whoami` při startu |

Aplikace při přihlášení vidí a přeposílá TOTP kód — model vědomě počítá
s tím, že je důvěryhodná pro sběr pověření; škodu omezuje jednorázovost
kódu, anti-replay per účel a omezování pokusů. Služba aplikaci nikdy nevydá
tajemství — jen verdikt a principály.

Podrobné zdůvodnění návrhu: [design.md](design.md).
