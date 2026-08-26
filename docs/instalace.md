# Instalace a provoz

*Jak nainstalovat knihovnu, spustit službu, postavit před ni důvěryhodnou proxy
a nechat ji běžet pod systemd.*

## Požadavky

| | |
|---|---|
| Python | **3.12 nebo novější** |
| systém | Linux/POSIX pro provoz služby (přenačtení stojí na `SIGHUP`) |
| závislosti | **žádné povinné** — extras podle role, viz níže |
| TLS | terminuje reverzní proxy provozovatele, služba mluví holým HTTP |

Klientská knihovna běží kdekoli, kde běží Python 3.12; omezení na POSIX se týká
jen běžící služby.

## Instalace knihovny

```bash
pip install git+https://github.com/alchy/access-manager
```

Balíček nemá žádné povinné závislosti. Podle role si přidáte extra:

| extra | pro koho | přitáhne |
|---|---|---|
| *(nic)* | aplikace s lokálním zapojením | — |
| `[remote]` | aplikace připojené k službě | httpx |
| `[totp]` | zakládání identit (párovací token) | pyotp, qrcode |
| `[server]` | provoz služby | flask, waitress |
| `[dev]` | vývoj a testy | vše výše + pytest, ruff |

Hranaté závorky si bash i zsh vykládají po svém — extras patří do apostrofů:

```bash
pip install 'access-manager[server,totp]'
```

Pro provoz na serveru je na místě vlastní virtualenv, ne systémový Python:

```bash
python3 -m venv /opt/access-manager/.venv
/opt/access-manager/.venv/bin/pip install 'access-manager[server,totp] @ git+https://github.com/alchy/access-manager'
```

Kdo chce sahat do kódu, instaluje editovatelně z klonu (`pip install -e
'.[dev]'`) — po úpravě zdroje pak stačí restart služby, ne přeinstalace.

## Spuštění služby

```bash
pip install 'access-manager[server,totp]'
python -m access_manager.server -c conf.d/
```

Přepínač `-c` (`--config`) je **povinný** a ukazuje na adresář, ne na soubor.

Při startu služba načte konfiguraci, provede **reconcile** deklarovaných realmů
(doplní jen to, co chybí — nové párovací tokeny vypíše jako cesty k `totp.txt`)
a začne poslouchat: **API na portu 22000**, správcovská webová konzole na
portu 22001 (přihlášení a správu realmů popisuje [admin.md](admin.md)).
Co služba zaznamenává a kam, popisuje [Provozní log](#provozní-log) níže.

Obojí se ve výchozím stavu váže na **smyčku** — zvenčí se k tomu nikdo
nedostane, dokud před to nepostavíte proxy (níže) nebo si neuděláte ssh tunel:

```bash
ssh -L 22001:127.0.0.1:22001 server    # konzole na http://127.0.0.1:22001
```

## Konfigurace (`conf.d/`)

Adresář má dvě patra a každé se čte jinak:

| co | jak se to čte |
|---|---|
| `conf.d/*.json` | fragmenty **jednoho** dokumentu; sčítají se v pořadí podle jména |
| `conf.d/realms/*.json` | **jeden soubor = jedna deklarace realmu**, nesčítá se |

Fragmenty existují proto, aby šlo držet zvlášť to, co se liší mezi stroji
(`listeners`, `trusted_proxies`), a co je společné. **Skalární konflikt zavírá
start** — dva fragmenty, které témuž klíči přiřazují různou hodnotu, nejsou
překryv, ale spor, a služba nebude hádat, který vyhrál. Podadresáře se
neprocházejí do hloubky a `realms/` je jediný, na který se služba dívá.

`conf.d/service.json`:

```json
{ "data": "/var/lib/access-manager",
  "listeners": { "api": "127.0.0.1:22000", "console": "127.0.0.1:22001" },
  "trusted_proxies": ["127.0.0.1"],
  "forwarded_header": "X-Forwarded-For",
  "hops": 1,
  "console_secure_cookie": true,
  "defaults": { "qr_ttl_days": 14, "audit_retention_days": 90 },
  "throttle": { "attempts": 5, "window_s": 60 },
  "log": { "level": "info", "format": "json" } }
```

`conf.d/realms/example.com.json` — deklarace realmu:

```json
{ "name": "example.com",
  "admins": ["jindrich"] }
```

Je to JSON, ne JSON5: **komentáře ani čárka za posledním prvkem neprojdou**
a rozbitý soubor zavře start hláškou `neplatny JSON v service.json`.

`data` je povinné (úložiště instance); vše ostatní má výchozí hodnoty uvedené
výše — `console_secure_cookie` je jediné, jehož výchozí hodnota je `false`
(proč, viz TLS níže). Deklarace realmu smí přebít
`qr_ttl_days`/`audit_retention_days`, instanční `defaults` ji nepřebijí nikdy.
Dvakrát deklarovaný realm (i lišící se jen velikostí písmen — jména se
normalizují na malá) zavírá start. Zmizení realmu z deklarace **není mazání** —
služba ho přestane obsluhovat, data zůstávají; fyzické smazání je výslovný úkon
provozovatele na serveru.

### Datový adresář

Uvnitř `data` vznikne podadresář `realm-<název>/` na každý deklarovaný realm
a v něm identity, skupiny, klíče a audit. Leží tam **párovací tajemství**, takže
si úložiště práva hlídá samo: adresáře `0700`, soubory `0600`, a to už při
vzniku souboru, ne až po zápisu.

Jedna výjimka stojí za pozornost: **kořen `data` si služba přechmodí jen
tehdy, když ho zakládá sama.** Cizí adresář nechává být — což je správně u
domovského adresáře člověka, ale znamená to, že adresář předpřipravený
instalátorem nebo systemd si nechá práva, se kterými vznikl. Kdo `data`
zakládá ručně, ať si je nastaví taky:

```bash
install -d -o access-manager -g access-manager -m 0700 /var/lib/access-manager
```

## Ověření po instalaci

Provozní cesty jdou **bez klíče** — jinak by si orchestrátor nemohl ověřit
životnost, aniž by znal tajemství:

```bash
curl -s localhost:22000/healthz      # {"status":"ok"}          - proces žije
curl -s localhost:22000/readyz       # {"status":"ok"}          - úložiště jsou v pořádku
curl -s localhost:22000/v1/version   # {"api":"1","build":"…"}  - verze API a buildu
```

`readyz` vrací `503` a `reasons` po jednotlivých realmech, když je některé
úložiště nepoužitelné — to je ta odpověď, na kterou se má dívat load balancer.
Cokoli pod `/v1/` mimo tenhle výčet vrátí bez klíče `401`; to není porucha.

První správce se přihlásí párovacím QR, které reconcile vypsal:

```bash
cat /var/lib/access-manager/realm-example.com/admin-jindrich/totp.txt
```

QR je uložené jako **text**, takže `cat` přes ssh stačí i na stroji bez
obrazovky. Přihlášení do konzole chce realm, jméno správce a **dva kódy ze
dvou po sobě jdoucích oken** — podrobně v [admin.md](admin.md).

## Provozní log

Služba píše **jeden JSON objekt na řádek**. Není to auditní stopa — ty dva
záznamy odpovídají na jinou otázku a čte je někdo jiný:

| | provozní log | auditní stopa |
|---|---|---|
| kde | `stdout`/`stderr` procesu | `data/realm-<název>/audit/RRRR-MM-DD.jsonl` |
| rozsah | celý proces | jeden realm |
| čte | provozovatel na stroji | konzole na webu |
| retence | co si nechá systemd/podman | `audit_retention_days` (90 dní) |

**Dělicí čára není libovolná.** Auditní stopa je per-realm, takže událost,
která nastane dřív, než je realm určený, nemá kam být zapsána — a právě ta
patří do provozního logu. Co realm zná, patří do auditu a nikam jinam: dvě
kopie by se musely držet v souladu a jednu z nich by rotace stejně zahodila.

Do provozního logu jde tedy:

- **neplatný nebo chybějící klíč API** (`unauthorized`) — bez komponenty není
  realm,
- **přihlášení do konzole odmítnuté dřív, než je úložiště** (`console_login`
  s důvodem `bad_form` nebo `unknown_realm`) — zdeformovaný nebo neexistující
  realm,
- **události procesu** — přenačtení konfigurace, vydané párovací tokeny.

Všechno ostatní — úspěšné i neúspěšné ověření, zápisy, odepřený původ,
odhlášení, zamítnutý CSRF token — má realm známý a najdete to v auditu.

### Proud dělá triáž

Běžný provoz jde na **`stdout`**, potíže na **`stderr`**. Odmítnutý požadavek
není chyba procesu — služba se právě zachovala správně — a na chybovém proudu
nemá co dělat. Pod systemd to znamená, že `journalctl -p warning` ukáže právě
to, co chce pozornost:

```
{"t":"2026-08-26T03:55:09+00:00","level":"info","event":"unauthorized","origin":"2a01:4f8::1","path":"/v1/whoami"}
{"t":"2026-08-26T04:04:50+00:00","level":"warning","event":"config_reload_failed","reason":"bezi dal ta stara konfigurace","error":"neplatny JSON v service.json"}
```

Razítko `t` je vždy v **UTC**, stejně jako audit — dva záznamy téže události
se nesmí lišit zónou.

### Nastavení

```json
{ "log": { "level": "info", "format": "json" } }
```

`format` přijímá `json` (výchozí) a `text` — tytéž údaje čitelně bez `jq`.
Neznámý název formátu **start nezavře**, spadne se na `json`: log není důvod
nenastartovat službu. Úroveň ani formát se **nemění SIGHUPem** — přehazovat
handlery pod běžícími vlákny je víc rizika než užitku, chce to restart.

Kód, klíč ani hlavička `Authorization` se do logu nedostanou nikdy. Hodnoty,
které přišly z formuláře (`realm`, `name` u `console_login`), se logují **tak,
jak přišly** — i zdeformované, protože právě ten tvar provozovatel hledá —
ale zkrácené na 256 znaků.

## Služba pod systemd

Unit je v repozitáři — `deploy/access-manager.service`. Není to šablona z hlavy,
ale unit z referenčního nasazení; hlavička souboru popisuje layout, se kterým
počítá, a čtyři řádky, které se přepisují jinde.

```bash
install -m 0644 deploy/access-manager.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now access-manager
journalctl -u access-manager -f
```

Podstatné je v něm tohle:

| řádek | proč tam je |
|---|---|
| `ExecReload=/bin/kill -HUP $MAINPID` | bez něj `systemctl reload` nefunguje a zbývá jen restart |
| `Restart=on-failure` | rozbitá konfigurace start zavře; restartovat donekonečna nemá smysl |
| `ProtectSystem=full`, `ProtectHome=yes` | `/usr`, `/boot`, `/etc` a domovské adresáře jen pro čtení |
| `ReadWritePaths=` na datový adresář | výjimka z předchozího řádku — sem služba **musí** zapisovat |

Datový adresář si můžete nechat založit systemd, pokud sedí v `/var/lib`;
`ReadWritePaths` pak není potřeba:

```ini
StateDirectory=access-manager
StateDirectoryMode=0700
```

To znamená `/var/lib/access-manager` — tam pak musí ukazovat `data`
v `service.json`. `StateDirectoryMode` stojí za vypsání: výchozí je `0755`
a služba si kořen `data` přechmoduje jen tehdy, když ho zakládá sama (viz
Datový adresář výše).

Komentáře v unit souboru patří **na vlastní řádek**; `Klic=hodnota  # pozn.`
systemd jako komentář nechápe a načte ho do hodnoty. Výsledek si po každé
úpravě ověřte:

```bash
systemd-analyze verify /etc/systemd/system/access-manager.service
```

## TLS a důvěryhodná proxy (nginx)

Služba mluví holým HTTP; **TLS terminuje reverse proxy provozovatele**.
Klient (`Access.remote`) vyžaduje `https://` (výjimkou je jen loopback pro
vývoj), takže holé HTTP přes síť nejde zapnout omylem.

API a konzole jsou **dva různé porty a patří jim dvě různá jména** — API je
strojové rozhraní pro aplikace, konzole je správcovské rozhraní pro lidi
a nemá důvod poslouchat na téže adrese.

### API (port 22000)

```nginx
limit_req_zone $binary_remote_addr zone=am_auth:10m   rate=30r/m;
limit_req_zone $binary_remote_addr zone=am_global:10m rate=300r/m;

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;

    # API, ne web - nic z toho se nevykresluje v prohlížeči.
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY"    always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy   "default-src 'none'; frame-ancestors 'none'" always;

    proxy_http_version 1.1;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout  5s;
    proxy_read_timeout    30s;

    # Ověřování je nejcitlivější místo - přísnější limit. Služba má vlastní
    # throttle (5 pokusů / 60 s na identitu); tohle je vrstva navíc, na adresu.
    location /v1/authenticate {
        limit_req zone=am_auth burst=10 nodelay;
        proxy_pass http://127.0.0.1:22000;
    }

    location / {
        limit_req zone=am_global burst=50 nodelay;
        proxy_pass http://127.0.0.1:22000;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com;
    location /.well-known/acme-challenge/ { root /var/www/letsencrypt; allow all; }
    location / { return 301 https://$host$request_uri; }
}
```

### Konzole (port 22001)

Totéž s vlastním jménem a certifikátem, `proxy_pass` na `127.0.0.1:22001`
a dvěma rozdíly:

```nginx
    # Konzole zobrazuje párovací token jako QR v data: URI - bez `img-src data:`
    # by se správci nezobrazil kód, který má opsat do telefonu.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" always;
    add_header Referrer-Policy         "no-referrer" always;

    location = /login {
        limit_req zone=ama_login burst=5 nodelay;   # vlastní zóna, ~20r/m
        proxy_pass http://127.0.0.1:22001;
    }
```

Konzole má vlastní přihlášení (dva po sobě jdoucí TOTP kódy), CSRF na každé
mutaci a relace umírající s restartem služby — ale pořád je to správcovské
rozhraní. Kdo ho nepotřebuje mít v internetu, ať ho tam nedává a chodí ssh
tunelem.

**Za TLS proxy zapněte `console_secure_cookie`** (výchozí `false`) — cookie
relace pak ponese příznak `Secure` a neopustí šifrované spojení. Výchozí
`false` má důvod: `Secure` cookie bez TLS prohlížeč zahodí rovnou a do konzole
by se nepřihlásil nikdo, tedy ani ten, kdo ji poprvé zkouší na smyčce.

### Párový zápis v `service.json`

**Adresa proxy musí být v `trusted_proxies`**, jinak služba hlavičku
`X-Forwarded-For` ignoruje a origin ACL i audit měří adresu proxy místo
skutečného klienta (a vypadá to funkčně, i když to nerozlišuje nic):

```json
{ "trusted_proxies": ["127.0.0.1"], "hops": 1 }
```

`hops` říká, kolikátý prvek **zprava** v hlavičce je pravda — klient si totiž
může poslat vlastní `X-Forwarded-For` a proxy svůj údaj připojuje zprava.
Jedna proxy na témže stroji = `hops: 1`. Přijímá se i CIDR, takže celý blok
proxy se vejde na jednu položku.

Selhání je **tiché a vypadá stejně jako úspěch**: chybějící, zdeformovaná
nebo na `hops` prvků příliš krátká hlavička spadne zpátky na adresu peera.
Když tedy `hops` neodpovídá skutečnému počtu proxy, služba nic neohlásí — jen
bude v auditu u každého požadavku stát adresa proxy. Stojí za to se po
nasazení podívat do auditu, jestli tam jsou adresy klientů, a ne pořád jedna
a tatáž.

## Přenačtení za běhu (SIGHUP)

Služba reaguje na **SIGHUP**: znovu načte `conf.d/`, dojede reconcile
deklarovaných realmů a vymění obě aplikace za běhu.

```bash
systemctl reload access-manager     # ExecReload=/bin/kill -HUP $MAINPID
kill -HUP <pid>                     # bez systemd
```

Sokety zůstávají navázané, takže **nevypadne žádné spojení** a rozdělané
požadavky doběhnou. Přihlášené relace konzole reload **přežijí** — to je
záměrný rozdíl oproti restartu, který je dál smete (`create_console_app` si
jinak generuje nový podpisový klíč). Kdo chce čistou tabulku, má restart.

Co se přenačte:

| | |
|---|---|
| deklarace realmů, `defaults`, `throttle` | ano |
| `trusted_proxies`, `forwarded_header`, `hops` | ano |
| `console_secure_cookie` | ano |
| `data` | ano (nová úložiště) |
| **`listeners`** | **ne** — sokety už jsou navázané, chce to restart |
| **kód** | **ne** — nová verze balíčku chce restart, viz Aktualizace |

Změnu `listeners` služba **řekne do logu** a jinak ji ignoruje — aby se
nikdo nedivil, proč se nic nestalo.

**Rozbitá konfigurace službu neshodí.** Nové aplikace se staví dřív, než se
cokoli vymění, takže výjimka spadne ještě před zásahem a běží dál ta stará:

```
SIGHUP: prenacteni SELHALO, bezi dal ta stara konfigurace: realm 'x' je deklarovany dvakrat
```

Pozor: `systemctl reload` skončí **úspěchem i když přenačtení selhalo** —
systemd ví jen to, že signál odeslal, ne co s ním aplikace udělala. Výsledek
se čte z logu:

```bash
systemctl reload access-manager && journalctl -u access-manager -n 5 | grep SIGHUP
```

## Aktualizace

Nový kód SIGHUP nepřinese — přenačtení čte konfiguraci, ne balíček. Aktualizace
je tedy instalace a **restart**:

```bash
/opt/access-manager/.venv/bin/pip install --upgrade \
    'access-manager[server,totp] @ git+https://github.com/alchy/access-manager'
systemctl restart access-manager
```

Restart **odhlásí všechny správce** z konzole (relace žijí jen v paměti
procesu) a na pár set milisekund zavře porty. Data zůstávají; při startu
proběhne reconcile, který existujícího nic nemění. Ověření po restartu je
`/v1/version` — vrací `build`, tedy verzi nainstalovaného balíčku.

## Kontejner

Provoz v kontejneru (podman, rootless, start s systémem, reverzní proxy před
publikovanými porty) má vlastní dokument: **[install-container.md](install-container.md)**.
Je to cílený způsob nasazení; tenhle dokument popisuje nativní instalaci, která
zůstává podporovanou variantou.

Zkrácene:

```bash
deploy/container-build.sh          # postavi obraz
sudo deploy/install-container.sh   # uzivatel, subuid/subgid, linger, unit
sudo systemctl enable --now access-manager-container
```

Tři věci, které se v kontejneru dělají jinak než tady:

1. **Cesty v konfiguraci jsou cesty uvnitř kontejneru** — `data` je
   `/var/lib/access-manager`, ne cesta na hostiteli.
2. **`listeners` musí být `0.0.0.0`**, jinak by se poslouchalo na smyčce
   kontejneru; ven vede jen to, co podman publikuje (a to je `127.0.0.1`).
3. **`trusted_proxies` je jiné** — proxy k službě nedorazí z `127.0.0.1`, ale
   z adresy kontejneru.

## Kudy dál

- Provoz v kontejneru: [install-container.md](install-container.md)
- Správa realmů, správců a klíčů aplikací: [admin.md](admin.md)
- Připojení aplikace: [aplikace.md](aplikace.md)
- REST API a provozní endpointy: [api.md](api.md)
- Normativní návrh a zdůvodnění rozhodnutí: [design.md](design.md)
