# Instalace a provoz

*Jak nainstalovat knihovnu, spustit službu a postavit před ni důvěryhodnou proxy.*

## Instalace knihovny

```bash
pip install git+https://github.com/alchy/access-manager
```

Balíček nemá žádné povinné závislosti. Podle role si přidáte extra:

| extra | pro koho | přitáhne |
|---|---|---|
| *(nic)* | aplikace s lokálním zapojením | — |
| `[remote]` | aplikace připojené k službě | httpx |
| `[totp]` | zakládání identit (párovací QR) | pyotp, qrcode |
| `[server]` | provoz služby | flask, waitress |
| `[dev]` | vývoj a testy | vše výše + pytest, ruff |

## Spuštění služby

```bash
pip install 'access-manager[server,totp]'
python -m access_manager.server -c conf.d/
```

Při startu služba načte konfiguraci, provede **reconcile** deklarovaných realmů
(doplní jen to, co chybí — nová párovací QR vypíše na stdout jako cesty
k `totp.txt`) a začne poslouchat: **API na portu 22000**, správcovská webová
konzole na portu 22001 (přihlášení a správu realmů popisuje
[admin.md](admin.md)). Neautorizované pokusy (401) se logují na stderr.

## Konfigurace (`conf.d/`)

Fragmenty se při startu sčítají; **skalární konflikt zavírá start**.

```json
// conf.d/service.json
{ "data": "/var/lib/access-manager",
  "listeners": { "api": "127.0.0.1:22000", "console": "127.0.0.1:22001" },
  "trusted_proxies": ["10.0.0.0/8"],
  "forwarded_header": "X-Forwarded-For",
  "hops": 1,
  "defaults": { "qr_ttl_days": 14, "audit_retention_days": 90 },
  "throttle": { "attempts": 5, "window_s": 60 } }
```

```json
// conf.d/realms/example.com.json  — deklarace realmu
{ "name": "example.com",
  "admins": ["jindrich"] }
```

`data` je povinné (úložiště instance); vše ostatní má výchozí hodnoty uvedené
výše. Deklarace realmu smí přebít `qr_ttl_days`/`audit_retention_days`.
Zmizení realmu z deklarace **není mazání** — služba ho přestane obsluhovat,
data zůstávají; fyzické smazání je výslovný úkon provozovatele na serveru.

## TLS a důvěryhodná proxy (nginx)

Služba mluví holým HTTP; **TLS terminuje reverse proxy provozovatele**.
Klient (`Access.remote`) vyžaduje `https://` (výjimkou je jen loopback pro
vývoj), takže holé HTTP přes síť nejde zapnout omylem.

Vzorová konfigurace nginx na témže stroji:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:22000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Párový zápis ve `service.json` je povinný** — adresa proxy musí být
v `trusted_proxies`, jinak služba hlavičku `X-Forwarded-For` ignoruje
a origin ACL měří adresu proxy místo skutečného klienta (a vypadá funkčně,
i když nerozlišuje nic):

```json
{ "trusted_proxies": ["127.0.0.1"], "hops": 1 }
```

`hops` říká, kolikátý prvek **zprava** v hlavičce je pravda — klient si totiž
může poslat vlastní `X-Forwarded-For` a proxy svůj údaj připojuje zprava.

## Kontejner

`Dockerfile` je v kořeni repozitáře:

```bash
docker build -t access-manager .
docker run -v am-data:/var/lib/access-manager \
           -v ./conf.d:/etc/access-manager/conf.d:ro \
           -p 22000:22000 access-manager
```

Dvě věci, na které se v kontejneru zapomíná:

1. `listeners.api` nastavte na `0.0.0.0:22000` — `EXPOSE` sám nestačí.
2. Healthcheck kontejneru počítá s výchozím listenerem `127.0.0.1:22000`;
   kdo listener převáže, musí převázat i healthcheck.

## Kudy dál

- Správa realmů, správců a klíčů aplikací: [admin.md](admin.md)
- Připojení aplikace: [aplikace.md](aplikace.md)
- REST API: [api.md](api.md)
- Normativní návrh a zdůvodnění rozhodnutí: [design.md](design.md)
