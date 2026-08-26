# Provoz v kontejneru (podman)

*Jak postavit obraz, spustit službu jako neprivilegovaný kontejner, nechat ji
startovat s systémem a postavit před ni reverzní proxy.*

Nativní instalace do virtualenvu je popsaná v [instalace.md](instalace.md)
a zůstává funkční variantou. Tenhle dokument popisuje **cílený způsob
nasazení**: uživatel si z gitu stáhne repozitář, postaví obraz a spustí ho
s parametry.

## Co je uvnitř a co venku

| | kde | na hostiteli | v kontejneru |
|---|---|---|---|
| kód a závislosti | **v obrazu** | — | `/app` |
| konfigurace (`conf.d/`) | **mimo**, jen pro čtení | `~/conf.d` | `/etc/access-manager/conf.d` |
| data (identity, skupiny, klíče, audit) | **mimo** | `~/.access-manager` | `/var/lib/access-manager` |
| log služby | **mimo** | `~/logs/service.log` | — (píše ho podman, ne služba) |
| TLS a certifikáty | **mimo** | reverzní proxy | — |

`~` je domovský adresář uživatele, pod kterým kontejner běží — u zdejšího
nasazení `/www/access-manager`. **Všechny tři cesty jsou parametry** (`--conf`,
`--data`, `--log`, resp. `AM_CONF`/`AM_DATA`/`AM_LOG`); výchozí hodnoty se
odvozují od domova a datový adresář drží konvenci projektu `~/.access-manager`.

Pozor na dvojkolejnost, která mate: **`/var/lib/access-manager` na hostiteli
neexistuje.** Je to přípojný bod uvnitř kontejneru, kam se `~/.access-manager`
montuje. Tytéž soubory jsou uvnitř vlastněné uživatelem `spravce`, venku
uživatelem `access-manager` — o to se stará `keep-id`, viz níže.

Z kontejneru tedy nezmizí nic, co má přežít. Obraz je zaměnitelný kus; smazat
ho a postavit znovu nic nestojí.

## Porty: jen localhost, proxy je povinná

**Kontejner publikuje porty výhradně na `127.0.0.1`.** Zvenčí stroje na ně
nevede nic:

```
127.0.0.1:22000  ->  kontejner :22000   REST API
127.0.0.1:22001  ->  kontejner :22001   správcovská konzole
```

To není opomenutí, které by se mělo „dodělat" publikováním na `0.0.0.0`.
Služba mluví **holým HTTP** a klient (`Access.remote`) odmítá cokoli jiného
než `https://`. Mezi ni a svět tedy **musí** přijít reverzní proxy, která
terminuje TLS — nginx, caddy, cokoli. Bez ní služba není použitelná odjinud
než z toho jednoho stroje.

Vzorová konfigurace nginx (dva vhosty, security headers, limity, ACME) je
v [instalace.md](instalace.md), oddíl *TLS a důvěryhodná proxy*. Proti nativní
instalaci se **nemění ani řádek** — proxy pořád mluví na `127.0.0.1:22000`
a `127.0.0.1:22001`, jen na druhém konci sedí kontejner místo lokálního
procesu.

Co se změnit **musí**, je `trusted_proxies` — viz *Původ požadavku* níže.
Přeskočit ten oddíl znamená rozbitý audit, který vypadá funkčně.

## Požadavky

| | |
|---|---|
| podman | 4.3+ (kvůli `--userns=keep-id:uid=…`); ověřeno na 5.8 |
| jádro | user namespaces zapnuté (`user.max_user_namespaces` > 0) |
| uživatel | systémový, **nemusí mít shell ani heslo** |

Kontejner **neběží jako root** — ani na hostiteli, ani (po namapování) uvnitř.

## Rychlý start

```bash
git clone https://github.com/alchy/access-manager
cd access-manager
deploy/container-build.sh
podman run --rm -p 127.0.0.1:22000:22000 -p 127.0.0.1:22001:22001 \
           localhost/access-manager:latest
```

Bez namontované konfigurace kontejner **nespadne** — vyrobí si dummy defaults
(realm `example.local`, správce `admin`, naslouchání na `0.0.0.0`, prázdné
`trusted_proxies`) a nahlas do logu řekne, že jsou dummy. Je to na osahání,
ne do provozu.

Obraz stavějte **jako uživatel, pod kterým pak poběží**: rootless podman drží
úložiště obrazů v jeho domovském adresáři, takže obraz postavený rootem by
`podman run` toho uživatele vůbec nenašel.

## Instalace jako služba

```bash
sudo deploy/install-container.sh
```

Skript je idempotentní a udělá čtyři věci:

1. založí systémového uživatele `access-manager` (nologin) a adresáře
   `conf.d/`, `.access-manager/`, `logs/` s právy `0700`;
2. **deleguje mu subuid/subgid** — bez nich rootless podman nenastartuje;
3. **zapne linger** — bez něj po bootu neexistuje `/run/user/<uid>` a kontejner
   nemá co spustit;
4. nainstaluje `container-run.sh` jako `/usr/local/bin/access-manager-container`
   a systemd unit.

Pak konfigurace, obraz a start:

```bash
# konfigurace do ~access-manager/conf.d (viz nize)
sudo -u access-manager -H XDG_RUNTIME_DIR=/run/user/$(id -u access-manager) \
     deploy/container-build.sh
sudo systemctl enable --now access-manager-container
```

Unit volá `container-run.sh`, ne podman přímo — parametry provozu a ručního
spuštění se tak nemůžou rozejít. Přebíjejí se v `/etc/sysconfig/access-manager-container`
(`AM_CONF`, `AM_DATA`, `AM_API_PORT`, `AM_BIND`, …); úplný výčet vypíše
`access-manager-container --help`.

## Konfigurace

Konfigurace je **jediná věc, která v obrazu není**. Montuje se jen pro čtení:

```
-v /www/access-manager/conf.d:/etc/access-manager/conf.d:ro
```

Formát je stejný jako u nativní instalace ([instalace.md](instalace.md)), ale
pozor na jednu věc, na kterou se naletí spolehlivě:

> **Cesty v konfiguraci jsou cesty UVNITŘ kontejneru.** Konfiguraci čte proces
> v kontejneru, ne na hostiteli.

Takže `data` je `/var/lib/access-manager` (kam se svazek montuje), **ne**
`/www/access-manager/data` (kde leží na hostiteli). Kdo tam nechá hostitelskou
cestu, dostane při startu:

```
PermissionError: [Errno 13] Permission denied: '/www'
```

Naslouchání musí být na `0.0.0.0` — na `127.0.0.1` by se poslouchalo na
smyčce *kontejneru* a publikované porty by nevedly nikam:

```json
{ "data": "/var/lib/access-manager",
  "listeners": { "api": "0.0.0.0:22000", "console": "0.0.0.0:22001" },
  "trusted_proxies": ["10.89.0.2"],
  "hops": 1,
  "console_secure_cookie": true }
```

To, že služba poslouchá na `0.0.0.0`, ji nevystavuje — ven z kontejneru vede
jen to, co podman publikuje, a to je `127.0.0.1`.

## Původ požadavku (`trusted_proxies`)

Tohle je nejzrádnější místo celého nasazení.

Nativní služba viděla nginx přicházet z `127.0.0.1`. **Kontejner ho z `127.0.0.1`
nevidí.** Publikované porty procházejí překladem adres, takže služba uvnitř
vidí jako zdroj adresu kontejneru — u zdejšího nasazení `10.89.0.2`.

Důsledek nesprávného `trusted_proxies`: služba přestane věřit hlavičce
`X-Forwarded-For`, origin ACL i audit začnou u **každého** požadavku měřit
adresu kontejneru — a nic to neohlásí. Vypadá to funkčně, jen to nerozlišuje
nic.

Proto `container-run.sh` kontejneru přiděluje **pevnou adresu** (`--ip`,
výchozí `10.89.0.2`) ve vlastní síti `am-net`. Kdyby se nechala plavat,
`trusted_proxies` by po každém restartu mohlo ukazovat jinam.

Ověření po nasazení — pošlete požadavek bez klíče a přečtěte si, jaký původ
služba zaznamenala:

```bash
curl -s -o /dev/null https://auth.example.com/v1/whoami
grep '401 unauthorized' ~/logs/service.log | tail -1
```

```
401 unauthorized: puvod=2a01:4f8:1c1b:8c66::1 cesta=/v1/whoami
```

Musí tam být **adresa klienta**. Když tam vidíte `10.89.0.2` (nebo veřejnou IP
stroje), hlavička se nevěří a `trusted_proxies` je špatně.

## Události kontejneru

Služba reaguje na signály stejně jako v nativním nasazení — unit je jen posílá
dovnitř kontejneru:

| příkaz | co se stane |
|---|---|
| `systemctl reload access-manager-container` | `podman kill --signal HUP` → přenačte `conf.d`, reconcile, výměna aplikací; **spojení nevypadnou, relace konzole přežijí** |
| `systemctl restart access-manager-container` | kontejner se zastaví a spustí znovu; relace konzole se smetou (záměr) |
| `systemctl stop …` | SIGTERM dovnitř, po 15 s SIGKILL |

Reload čte konfiguraci z namontovaného `conf.d` — **nové vydání obrazu tím
nenaběhne**, na to je `restart` (viz *Aktualizace*).

Kontejner běží s `--init`, a to není kosmetika. Bez něj je Python procesem
číslo 1 a jádro procesu s PID 1 zahazuje signály, na které nemá handler:
`podman stop` by čekal celých 10 sekund a pak poslal SIGKILL. S `--init` sedí
na PID 1 catatonit, signály předává dál a zastavení trvá **1 sekundu**.

## Správa a ověření provozu

Primární cesta ke správě je pořád **webová konzole** (port 22001, přes proxy).
Knihovna `Admin`, kterou [admin.md](admin.md) popisuje jako cestu provozovatele
přes ssh, je v kontejnerovém nasazení o `podman exec` dál — cesta k úložišti je
`/var/lib/access-manager`, tedy cesta **uvnitř** kontejneru:

```bash
podman exec -i access-manager python -c "
from access_manager import Admin
a = Admin.local('/var/lib/access-manager', realm='example.com', actor='operator')
z = a.add_user('hana')
print(z.directory)"          # tam lezi totp.txt s parovacim QR
```

Ověření, že nasazení opravdu funguje — od klíče po verdikt:

```bash
# 1. klic aplikace (zobrazi se PRAVE JEDNOU)
podman exec -i access-manager python -c "
from access_manager import Admin
a = Admin.local('/var/lib/access-manager', realm='example.com', actor='operator')
print(a.register_component('app:test', origins=('10.89.0.2/32',), detail=True))"

# 2. cte API klic?
curl -s -H "Authorization: Bearer $KLIC" http://127.0.0.1:22000/v1/whoami
# {"component":"app:test","key_id":"k1","realm":"example.com"}

# 3. overi kod?
curl -s -H "Authorization: Bearer $KLIC" -H 'Content-Type: application/json' \
     -d '{"username":"hana","credentials":{"totp":"123456"},"purpose":"login"}' \
     http://127.0.0.1:22000/v1/authenticate
# {"outcome":"ok","subject_id":"user:hana","principals":[...],"gen":5}

# 4. zapsalo se to do auditu?
tail -1 ~/.access-manager/realm-example.com/audit/$(date +%F).jsonl
```

Po zkoušce nezapomeňte uklidit: `revoke_component`, `remove_user`. Odvolání
klíče platí okamžitě, bez restartu.

### Klíče aplikací a `origins` v kontejneru

Past, která navazuje na *Původ požadavku*. Prázdné `origins` u komponenty
znamenají **„jen smyčka"** — jenže služba v kontejneru žádný požadavek jako
smyčkový nevidí. I volání z téhož stroje na `127.0.0.1:22000` k ní dorazí
s původem `10.89.0.2`.

Komponenta s prázdnými `origins` je tedy v kontejnerovém nasazení odmítnuta
`403`. `origins` musí obsahovat:

- **adresu kontejneru** (`10.89.0.2/32`) pro volání, která jdou přímo na
  publikovaný port bez proxy;
- **rozsah skutečných klientů** pro volání, která jdou přes proxy — tam už
  původ vychází z `X-Forwarded-For`.

## Data a logy

**Data** (identity, skupiny, klíče, audit) jsou v montovaném svazku na
hostiteli. Kontejner je zaměnitelný, data zůstávají. Auditní stopa je pořád
tam, kde byla: `data/realm-<název>/audit/RRRR-MM-DD.jsonl`.

**Log služby** píše podman do souboru na hostiteli:

```
~/logs/service.log
```

Rotuje se po 10 MB (`--log-opt max-size`). Formát má na začátku řádku časové
razítko a proud, vlastní hláška je za `stderr F`:

```
2026-08-26T05:55:09+02:00 stderr F 401 unauthorized: puvod=… cesta=/v1/whoami
```

Totéž jde přes `podman logs access-manager` nebo — protože kontejner běží
v popředí pod systemd — přes `journalctl -u access-manager-container`.

### Časová zóna

Kontejner běží ve výchozím stavu v **UTC**, ať má hostitel jakoukoli zónu.
Na auditní stopu to ale **nemá žádný vliv**: `audit.py` si razítka i jména
denních souborů počítá z `datetime.now(UTC)` napevno, takže audit je v UTC
i v nativním provozu na stroji nastaveném do CEST. Přechod do kontejneru tedy
v auditu nezpůsobí žádnou nespojitost a `audit_retention_days` se počítá
pořád stejně.

Zóna se dá přesto nastavit — ovlivní hodiny uvnitř kontejneru a cokoli, co
by se v budoucnu dívalo na místní čas:

```
AM_TZ=Europe/Prague        # v /etc/sysconfig/access-manager-container
```

Časová razítka v `service.log` píše podman, ne služba, takže ta jsou v zóně
hostitele bez ohledu na `AM_TZ`.

### Vlastnictví souborů a `keep-id`

Kontejner běží uvnitř jako `spravce` (uid 1000), na hostiteli jsou data
uživatele `access-manager` (jiné uid). Spojuje to `--userns=keep-id:uid=1000,gid=1000`:
hostitelský uživatel se dovnitř namapuje **právě na 1000**, takže namontovaná
data sedí a soubory zůstávají na hostiteli vlastněné `access-manager`em.

Proto má `Dockerfile` uid natvrdo (`useradd --uid 1000`). Kdyby se posunulo,
práva na svazku přestanou sedět.

## Aktualizace

```bash
git -C /www/access-manager/repo pull
sudo -u access-manager -H XDG_RUNTIME_DIR=/run/user/$(id -u access-manager) \
     /www/access-manager/repo/deploy/container-build.sh
sudo systemctl restart access-manager-container
```

`reload` na tohle nestačí — přenačítá konfiguraci, ne obraz. Restart odhlásí
správce z konzole (relace žijí jen v paměti procesu) a na dvě sekundy zavře
porty. Ověření je `/v1/version`, které vrací `build`.

## Rootless: proč to potřebuje, co potřebuje

Čtyři věci, bez kterých to nejede, a z hlášek to není poznat:

**subuid/subgid.** Kontejner potřebuje celý blok UID, které smí mapovat
dovnitř — uvnitř obrazu existuje root (0), `spravce` (1000) i `nobody`
(65534), venku je jen jedno UID uživatele. Jádro mu proto deleguje rozsah
(`200000–265535`). Kdyby proces z kontejneru utekl, je venku uid `200000+`,
které nikomu nepatří a nesmí nic.

**Linger.** Rootless podman potřebuje `/run/user/<uid>` a uživatelský systemd.
Bez lingeru vznikají až přihlášením — a služba startující při bootu se nikam
nepřihlašuje. `loginctl enable-linger` je přesně to „povolení běhu bez
terminálu".

**`--cgroup-manager=cgroupfs`.** Systémový unit běží v system slice, takže
uživatelský systemd mu cgroup scope vyrobit nemůže. Start skončí na:

```
crun: error `creating` systemd unit `libpod-….scope`: got `failed`
```

cgroupfs ten krok obchází a zakládá cgroupy přímo v delegované skupině — proto
je v unitu `Delegate=yes`.

**`DBUS_SESSION_BUS_ADDRESS`.** Ze systémového unitu není uživatelská sběrnice
vidět; unit ji proto ukazuje explicitně na `/run/user/<uid>/bus`.

Instalátor tohle nastaví všechno; tenhle oddíl je pro toho, kdo bude ladit,
proč to na jiném stroji nejede.

## Řešení potíží

| hláška | příčina |
|---|---|
| `crun: error creating systemd unit ... got failed` | chybí `--cgroup-manager=cgroupfs` nebo `Delegate=yes` |
| `PermissionError: ... '/www'` | `data` v konfiguraci je hostitelská cesta místo cesty v kontejneru |
| kontejner běží, port nereaguje | `listeners` v konfiguraci je `127.0.0.1` místo `0.0.0.0` |
| v auditu je pořád jedna adresa | `trusted_proxies` neodpovídá adrese kontejneru |
| `podman stop` trvá 10 s | chybí `--init` |
| `HEALTHCHECK is not supported for OCI image format` | build bez `--format docker` |
| po reloadu se nic nezměnilo | reload čte konfiguraci, ne obraz — chce to `restart` |

## Návrat k nativnímu provozu

`deploy/access-manager.service` v repozitáři pořád platí. Vrátit se znamená
zastavit kontejner, nainstalovat ten unit a **vrátit v konfiguraci cesty
hostitele** — `data` zpět na hostitelskou cestu (`~/.access-manager`), `listeners` na
`127.0.0.1` a `trusted_proxies` na `127.0.0.1`. Postup nativní instalace je
v [instalace.md](instalace.md).

## Kudy dál

- Nativní instalace a nginx: [instalace.md](instalace.md)
- Správa realmů, správců a klíčů: [admin.md](admin.md)
- Připojení aplikace: [aplikace.md](aplikace.md)
- REST API: [api.md](api.md)
- Normativní návrh: [design.md](design.md)
