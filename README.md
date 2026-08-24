# access-manager

**Autentikator a adresar skupin.** Odpovi na jednu otazku a rovnou k ni
prida, kam ten clovek patri:

    "jsi to ty?"  ->  ok, user:jindrich, [group:mzdy, group:ucetni, ...]

Dnes je mechanismus jediny: autentikator v telefonu (TOTP).

Na otazku *"smi to?"* **neodpovida zamerne** - a od te otazky uz nedrzi ani
zadna ACL. Prava patri tomu, kdo sve objekty zna; access-manager je nezna
a znat je nema. Duvod je v [docs/design.md](docs/design.md), par. 5.

Zretezeni skupin rozbaluje SERVER a vraci plochy uzaver. Klasicka bolest
LDAPu je prave tohle - zanorene clenstvi se necha dopocitat klientovi
a pulka klientu to udela spatne.

Ma vlastni proces a vlastni REST API, protoze ho pouziva **jak jadro, tak
aplikace** - nemuze tedy bydlet uvnitr ani jednoho. Muze bezet v jinem
kontejneru nez oba.

## Pouziti

### Lokalne

Aplikace, ktera jen prihlasuje lidi, potrebuje tohle a nic vic:

```python
from access_manager import Access

access = Access.local("~/.access-manager", realm="example.com")

verdikt = access.authenticate("jindrich", {"totp": kod}, purpose="login")

if verdikt.outcome == "need_factor":
    ...                                   # co chybi, rekla komponenta
if not verdikt:
    ...                                   # ven JEDNA hlaska, do logu duvod

verdikt.subject_id     # "user:jindrich"
verdikt.principals     # {"user:jindrich", "group:users", "group:public"}
```

### Vzdalenosti (REST)

Chces-li se pripojit k bezici sluzbe:

```python
from access_manager import Access

access = Access.remote(
    url="https://auth.example.com:22000",
    key="tajny-klic-aplikace",
    realm="example.com"
)

verdikt = access.authenticate("jindrich", {"totp": kod}, purpose="login")
```

### Obecne

Dve veci, ktere je treba vedet predem:

1. **Nedostanete relaci, dostanete verdikt.** Access-manager nedrzi
   prihlasene lidi - kdyby ano, jeho restart ve 3 rano odhlasi vsechny.
   Drzet cloveka prihlaseneho je prace volajiciho.
2. **`group:users` a `group:public` jsou vyhrazene.** Znamenaji "kdokoli
   overeny" a "kdokoli"; clovek je dostane tak jako tak a nejdou mu odebrat.
3. **Realm je povinny.** Kazdy uzivatel a kazda skupina zije jen v ramci sveho
   realmu; clovek z jednoho se nikdy nesetka s druhym.

## Realmy

Realm je subadresar a jmenny prostor. Instance je vzdy per-realm: vsichni
uzivatele jedne instance patri do stejneho realmu. Vznik deklaraci (kdo patri
kam) se resi externim systemem, access-manager jen splni `reconcile`, tj.
doplni z uloziste jen to, co chybi. Spravci jsou oddelene identity se stitkem
`<realm>-<role>-<jmeno>` a maji dvoukodovy vstup do budouci provozovatelske
konzole. Klice aplikaci se vydavaji jednou, na serveru si drzi jen otisk.
Audit je per-realm.

## Instalace

```bash
pip install access-manager          # klient
pip install access-manager[totp]    # + zakladani TOTP identit
```

Klient nema zadne povinne zavislosti. HTTP vrstva a TOTP jsou volitelne
extra, takze apka, ktera jen vola `authenticate`, si netahne nic.

## Sprava

Zakladani a clenstvi jsou na samostatnem objektu, se samostatnym klicem:

```python
from access_manager import Admin

admin = Admin.local("~/.access-manager", realm="example.com")

admin.add_user("jindrich")            # + tajemstvi, URI a QR JAKO TEXT
admin.pair_missing()                  # doplni jen tem, kdo parovaci kod nemaji

admin.add_group("mzdy")
admin.add_member("mzdy", "jindrich")
admin.include("ucetni", "mzdy")       # ucetni OBSAHUJE mzdy; cyklus odmitne
```

`Access` zapisove operace **nema** a `Admin` neumi `authenticate`. Kdyby
zavadeni viselo na tomtez objektu, umi kazda apka se svym klicem zalozit
uzivatele a strcit ho do `group:spravci`.

QR se zaklada jako text (`totp.txt`): na server se clovek dostane pres ssh,
`cat` vypise kod do terminalu a telefon ho sejme z obrazovky. Obrazek je na
hlave bez obrazovky k nicemu.

## Sluzba

Spusteni vlastni instance sluzby:

```bash
pip install 'access-manager[server]'
python -m access_manager.server -c conf.d/
```

Sluzba vyposlouchava na portu 22000 (REST API). Vicemene casu se bude zdat,
ze veci nefunguje - vice v konzoli (port 22001), zatim ale vraci 501.

TLS terminuje reverse proxy pred sluzbou (vzorova konfigurace nginx prijde
s dokumentaci). Detaily jsou v
[docs/superpowers/specs/2026-08-24-sluzba-a-remote-design.md](docs/superpowers/specs/2026-08-24-sluzba-a-remote-design.md).

Kontejnerizace: priklad Dockerfile je v koreni repa; zazehni vse
potrebne a spusti sluzbu jako uzivatel `spravce`.

Poznamka: healthcheck kontejneru pocita s vychozim api listenerem
127.0.0.1:22000 - kdo listener prevaze, musi prevazit i healthcheck.

## Stav

Hotova je souborova vrstva (overeni, rozbaleni skupin, anti-replay, cela
zapisova pulka vcetne zivotniho cyklu: disable, remove, revoke + nove
parovani, generace a kontroly principalu), realmy (spravci, platnost QR,
klice aplikaci, audit, reconcile), REST sluzba (flask/waitress za proxy),
throttling, a Access.remote (271 testu, bezi bez site). Konzole jeste ne
(listener vraci 501).

Navrh REST API je v [docs/design.md](docs/design.md) a plati jako zavazny -
knihovna se pise podle nej, ne naopak.

## Licence

Apache 2.0, viz [LICENSE](LICENSE).
