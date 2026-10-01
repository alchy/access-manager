# HANDOVER — stav a zbytek práce

Rozcestník pro další session. **Není to dokumentace** — ta je v [`docs/`](docs/) a v
[`README.md`](README.md) a je zdrojem pravdy o tom, jak služba funguje. Tady je jen to, co
v dokumentaci být nemá: stav nasazení, otevřená rozhodnutí, co zbývá a zvláštnosti tohohle stroje.

> **Všude jen současný stav.** Soubor se přepisuje, ne dopisuje; historie je v gitu.
> **Před prací ověř tvrzení o stavu proti kódu, sysconfigu a logu** — handover zastará první.

Jazyk: identifikátory v kódu anglicky, komentáře česky bez diakritiky, dokumentace česky
s diakritikou. V testech smí být cokoli pojmenováno česky.

---

## Stav k 1. 10. 2026

**Produkce** běží z obrazu `localhost/access-manager:latest` sestaveného 1. 10. 2026 z `main`
(commit `3406cb9`; pozdější commity v `main` mění jen tento soubor). Nasazeno 1. 10. 2026
v 18:45 UTC; restart trval půl minuty. Obsah obrazu je ověřený proti repozitáři soubor po
souboru. Ten den proběhla dvě nasazení: v 18:02 UTC commit `086d6e1`, v 18:45 UTC `3406cb9`.

Co nasazená verze nese proti obrazu z 16. 9. (commit `76bed4d`):

| oblast | co se změnilo |
|---|---|
| časy v konzoli | všude UTC s označením (`16:12:05 UTC`, `2026-10-01 16:12:05 UTC`), dny a období v UTC |
| názvy | `konzole/pohledy.py` → `audit_views.py`, anglické identifikátory v něm, v `konzole/app.py` a v šablonách; šablony přejmenované (`users.html`, `groups.html`, …) |
| formuláře | panel Přidat přes celou šířku, detail skupiny ve dvou sloupcích pod výpisem |
| akce | u Uživatelů a Správců dva sloupce s pevnou mřížkou a krátkými popisky |
| opravy z revizí | viz „Opraveno“ níže |
| panely Přidat | stejné rozložení, příklad a vysvětlení bez předpony, bez číslovky u aplikace |
| omezování pokusů | klíčem je jméno a adresa klienta, zámek roste (bod 1 níže) |

Testů **620** zelených, `ruff check .` čistý. `AM_TZ=Europe/Prague`
v `/etc/sysconfig/access-manager-container` zůstává; hodiny kontejneru jsou v pražském čase,
zobrazení v konzoli to neovlivňuje.

**Návrat k předchozí verzi.** Starší obrazy jsou označené:

| značka | commit | co v něm chybí |
|---|---|---|
| `rollback-20261001` | `086d6e1` | nové omezování pokusů a úprava panelů Přidat |
| `rollback-20260916` | `76bed4d` | všechno z 1. 10. 2026 |

Formát dat se nezměnil, návrat je jen výměna obrazu (jako `access-manager`, viz Zvláštnosti
stroje). Starší verze čte nový `throttle.json` jako prázdný, zámky tím zaniknou.

    podman tag localhost/access-manager:rollback-20261001 localhost/access-manager:latest
    systemctl restart access-manager-container.service        # jako root

Na `origin` i v tomto repozitáři je jen `main`; sloučené větve jsou smazané.

Git proti `origin` jde jen přes klíč uživatele `tech` spuštěný jako root, potom
`chown -R access-manager: .git`.

**Nasazení další verze:** zkouška na zkušební instanci (níže), `deploy/container-build-access-manager.sh`,
restart `access-manager-container.service`. Restart odhlásí všechny správce a API je asi
půl minuty nedostupné, tedy i přihlášení do Workbenche a SOC portálu.

## Zkouška před sestavením produkčního obrazu

`/www/access-manager/mock-e2e/` (mimo repozitář) — 225 kontrol po síti proti kontejneru
`am-test` z obrazu `:test`, na vlastních portech, síti a datech. Viz tamní `README.md`.

    sudo /www/access-manager/mock-e2e/run.sh up      # sestaví, spustí, otestuje
    sudo /www/access-manager/mock-e2e/run.sh down    # uklidí

Nasazená verze touto zkouškou prošla celá. Zkušební kontejner neběží; `run.sh up` ho postaví znovu.

## Opraveno a nasazeno 1. 10. 2026

Všechno má test v `tests/test_hardening.py` nebo u příslušné stránky.

- **Přesměrování na cizí server** přes `/lang?next=/%09/evil.example`, bez přihlášení. Cíl musí
  být cesta na tomto serveru z tisknutelných znaků ASCII (`_LOCAL_PATH` v `konzole/app.py`).
- **Chyba 500 na dlouhém jménu** na přihlášení do konzole i v API. Jména mají strop
  `MAX_NAME_LENGTH = 128` (`principals.py`).
- **Tlačítko Kopírovat** u klíče a párovacího kódu mělo obsluhu v atributu, kterou CSP z nginx
  zahodí. Obsluha je v `static/copy.js`; test hlídá, že žádná šablona nemá inline skript.
- **Neošetřená výjimka v logu** je jeden řádek JSON s časem služby, typem a zásobníkem
  (`log.py`, `log.adopt`). Dřív šla u API mimo formát a u konzole bez popisu.
- **Řádek auditu šel schovat** znakem U+2028 v cestě: čtečka dělila i na oddělovačích řádků
  z Unicode (`audit._radky`).
- **Prázdný `totp.secret` ověřoval.** Soubor kratší než 16 znaků se bere jako chybějící
  (`files._usable_secret`). Zápis tajemství pořád není atomický, viz níže.
- **Účel s koncem řádku** (`"login\n"`) byl vlastní přihrádka anti-replay (`purpose.py`).
- **Token CSRF s ne-ASCII znakem** a **`?_method=POST` na stránce auditu** končily chybou 500.
- Chyba po zápisu do skupiny se přesměruje bez kotvy, aby hláška zůstala vidět.
  `?od=2026-1-5` se převede na kanonický den.

## Otevřená rozhodnutí

Nic z toho není opravené. Řazeno podle závažnosti.

### Vysoká

1. **Omezování pokusů a hádání kódu.** Nasazeno 1. 10. 2026: klíčem je dvojice jméno a adresa klienta, zámek roste (minuta, dvojnásobky, nejvýš den)
   a neúspěchy se nezapomínají po minutě. U uživatele je nad adresami pomalé počítadlo na
   jméno (20 neúspěchů, zámek nejvýš hodinu). Konzole dává při zámku stejnou hlášku jako při
   špatném kódu. Pravidla jsou v `docs/admin.md`. **Co zbývá:**
   - **Workbench `client_origin` posílá od 1. 10. 2026, 19:42 UTC** (jeho commit `5cd75b6`),
     SOC portál už dřív. Brána Workbenche bere poslední prvek `X-Forwarded-For`, tedy ten od
     nginx. Ověřeno v auditu: přihlášení na neexistující jméno nese adresu, ze které
     požadavek opravdu přišel, a podvržená hlavička se neuplatnila. Bez adresy klienta tak
     zůstávají jen lokální volání.
   - **Hádání z mnoha adres** brzdí u uživatele jen pomalé počítadlo na jméno, zhruba 500
     pokusů denně (0,15 %). Stejným počítadlem jde uživatele z několika adres zamknout až
     na hodinu. Vyřeší to až další krok: po opakovaných chybách chtít dva kódy po sobě místo
     zámku. Je to změna rozhraní, kterou musí umět Workbench i SOC portál.
   - Řádky auditu se zámkem (`lock_scope`) nemají v konzoli filtr ani štítek; jsou vidět
     v detailu záznamu.
2. **Před konzolí není seznam povolených adres.** Zámek správce z jedné adresy už ostatní
   adresy nezasáhne, ale přihlašovací stránka je v internetu.

### Střední

3. **Důvěryhodná proxy je každý místní proces.** Služba vidí všechna spojení z adresy
   kontejneru (`trusted_proxies`), takže proces na hostiteli podvrhne `X-Forwarded-For`,
   a tím původ pro povolené rozsahy i pro audit, a obejde limity nginx. SOC na tom stojí:
   posílá adresu klienta do `/v1/whoami`. Návrh po krocích: ověřit prvek hlavičky jako adresu;
   omezit přístup na porty 22000 a 22001 podle uživatele (nftables); sdílené tajemství mezi
   nginx a službou.
4. **Odhlášení neruší relaci na serveru.** Relace je podepsaná cookie; stará kopie po
   odhlášení dál čte i zapisuje, až do restartu služby nebo 31 dní. Nečinná konzole se
   neodhlásí nikdy. `docs/admin.md` („relace žije jen v paměti procesu“) je zavádějící.
   Návrh: registr relací v paměti, nečinnost 15 minut, strop 8 hodin.
5. **`/v1/authenticate` prozradí existenci účtu** i bez `detail`: prázdné `credentials` vrátí
   `need_factor` jen existujícímu uživateli, a to bez omezení pokusů.
6. **Audit nese 75 tisíc řádků `whoami` z 29. 9. – 1. 10.** Workbench po restartu serveru
   spouštěl dvě sady jednotek zároveň a padající služba identity volala `/v1/whoami` při
   každém startu, každé 2,7 s. Opraveno ve Workbenchi 1. 10. v 19:03 UTC (jeho commit
   `684efa9`); od té doby je audit klidný. Staré řádky zůstanou do konce retence a stránka
   auditu je za ty tři dny pomalejší. Stránka čte celé období při každém zobrazení, takže
   podobná záplava ji zpomalí znovu; služba sama se proti ní nebrání.
7. **Zápis `totp.secret` není atomický** (soubor se založí a pak plní). Prázdný soubor už
   neověřuje, ale `pair()` ho neopraví („už tajemství má“). Návrh: dočasný soubor a `os.link`.

### Nízká

8. **nginx** (`/etc/nginx/conf.d/autumnpartials-access-manager*.conf`):
   - `limit_req` vrací 503 s HTML; klientská knihovna 5xx opakuje. Nastavit 429 a JSON.
   - `/readyz` a `/v1/version` jsou veřejné; `/readyz` při potíži vrací cesty úložiště.
   - `client_max_body_size 4m` je pro obě služby zbytečně moc, stačí desítky kB.
   - CSP konzole: `img-src data:` je zbytečné (QR je text); `style-src 'unsafe-inline'` drží
     jen blok `<style>` v `layout.html`.
   - `gzip` u konzole s tokenem CSRF a odraženými filtry má tvar pro BREACH; vypnout tam.
   - Konzole je v internetu bez seznamu povolených adres.
9. **API**: 404, 405 a 500 jsou HTML, ne JSON. `/v1/principals/check` nemá strop počtu položek
   (10 000 položek drží vlákno 0,9 s, vlákna jsou čtyři). Chybí `MAX_CONTENT_LENGTH`.
   Poškozený `used.json`, `gen` nebo `components.json` dává 500; `/readyz` to nepozná.
10. **Jméno aplikace** je skoro bez kontroly: s lomítkem ji z konzole nejde odvolat.
11. **Obraz**: `python:3.12-slim` bez digestu a závislosti bez zámku. Sestavení 1. 10. tak
    tiše zvedlo Werkzeug z 3.1.8 na 3.1.9. `container-run.sh` nemá `--pids-limit` ani `--memory`.
12. **Stránky konzole** kromě QR a klíče nemají `Cache-Control: no-store`.
13. **Provozní log ve formátu `text`** neescapuje řídicí znaky; produkce má `json`.
14. **Poslední správce**: stráž počítá i nespárované správce, takže jediný spárovaný smí
    odebrat sám sebe a realm zůstane bez přístupu do konzole.
15. **Nové přihlášení do minuty** po předchozím skončí jako `replay` a počítá se do omezení
    pokusů: přihlášení správce spotřebuje dva časové kroky. Plyne to z návrhu dvou kódů, není
    to chyba; jen to má být v `docs/admin.md`.
16. **Den záznamu a den souboru** se mohou o půlnoci UTC lišit (dvě volání hodin). Konzole se
    řídí jménem souboru; takový záznam stojí pod hlavičkou jiného dne.
17. **Pád `/v1/whoami` 30. 9. 2026 21:26 UTC** v zápisu auditu po odpovědi: výpis je v logu
    useknutý, příčina neznámá. Nové logování ji příště zachytí celou.

### Názvy a zadání

18. **Česky zůstalo záměrně**, protože je to vnější rozhraní nebo data: názvy parametrů v URL
    a formulářích (`od`, `do`, `obdobi`, `jmeno`, …), překladové klíče, třídy CSS, hodnoty
    v datech (pohledy `spravci`/`uzivatele`/`aplikace`/`vse`, druhy skupin v auditu), balíčky
    `konzole` a `preklady`, ostatní moduly (`audit.py`, `files.py`, `server.py`, …). Nové
    překladové klíče `actions.*` jsou anglicky; ostatní nové drží české jmenné prostory.
19. Nepoužité překladové klíče: `aplikace.register`, `audit.kind`.
20. **Zadání k časům** dorazilo useknuté u slov „platnost pá“. Pokryto: řádky přehledu, hlavičky
    dnů, období a filtr od–do, „aktualizováno“, „sloučeno od“, roletky posledních přihlášení,
    razítka vydání a spárování. „Platnost“ se ukazuje jen jako počet dní, bez času.

## Zvláštnosti stroje

- Repozitář patří uživateli `access-manager`. Úpravy a testy pouštět jako on
  (`sudo -u access-manager …`), jinak v repozitáři vzniknou soubory roota.
- Rootless podman: `sudo -u access-manager env HOME=/www/access-manager
  XDG_RUNTIME_DIR=/run/user/980 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/980/bus podman …`.
- V relaci roota jsou `cp` a `rm` aliasy na `cp -i` a `rm -i`. Ve skriptu čekají na odpověď,
  nic neudělají a vrátí úspěch; psát `command cp -f` a `command rm -f` a výsledek ověřit.
- Řádek provozního logu začíná razítkem podmana v místním čase hostitele. Čas služby je pole
  `t` uvnitř JSON, vždy v UTC.
